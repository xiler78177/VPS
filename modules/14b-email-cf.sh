# modules/14b-email-cf.sh - Cloudflare API 封装（jq 解析、统一错误处理）
# 调用前需要：export CF_API_TOKEN / CF_ACCOUNT_ID
#
# 所有 _email_cf_* 函数约定：
#   stdout = 业务数据（id / 域名等）或完整响应
#   exit   = 0 成功；1 业务失败；2 网络失败
#   错误细节进 EMAIL_LOG_FILE，不打印到终端（由调用方决定是否打印）

_email_cf_api() {
    # $1: method  $2: path (不带前导 /)  $3: 可选 JSON body
    local method="$1" path="$2" body="${3:-}"
    [[ -n "${CF_API_TOKEN:-}" ]] || { email_log "CF API token missing"; return 1; }
    local url="https://api.cloudflare.com/client/v4/$path"
    local -a args=(-sS --max-time 30 -X "$method"
                   -H "Authorization: Bearer $CF_API_TOKEN"
                   -H "Content-Type: application/json")
    [[ -n "$body" ]] && args+=(-d "$body")
    local resp
    resp=$(curl "${args[@]}" "$url" 2>>"$EMAIL_LOG_FILE") || {
        email_log "CF API network failure: $method $path"
        return 2
    }
    local ok
    ok=$(echo "$resp" | jq -r '.success // false' 2>/dev/null)
    if [[ "$ok" != "true" ]]; then
        local err safe_body
        err=$(echo "$resp" | jq -r '.errors // [] | map("\(.code): \(.message)") | join("; ")' 2>/dev/null)
        # ── secret 路径脱敏 ──
        # /secrets 路径的 body 包含 ADMIN_PASSWORDS / RESEND_TOKEN 等明文，绝不入日志
        if [[ "$path" == *"/secrets"* ]]; then
            safe_body="<redacted: secret payload>"
        else
            safe_body="${body:-<none>}"
        fi
        email_log "CF API ${method} ${path} failed: ${err:-<empty>} body=${safe_body}"
        return 1
    fi
    printf '%s' "$resp"
}

# DELETE 请求，将 HTTP 404（资源已不存在）视为幂等成功。
# 卸载流程在部分失败后会保留 state 供重跑；若重跑时已删除的资源返回 404 仍被判失败，
# 会导致 state 永远无法清除（死锁）。此 helper 让重复删除变为幂等。
# 返回: 0 = 删除成功或资源本就不存在; 1 = token 缺失或确定性失败; 2 = 网络错误
_email_cf_api_delete() {
    # $1: path (不带前导 /)
    local path="$1"
    [[ -n "${CF_API_TOKEN:-}" ]] || { email_log "CF API token missing"; return 1; }
    local url="https://api.cloudflare.com/client/v4/$path"
    local out http resp ok
    out=$(curl -sS --max-time 30 -w '\n%{http_code}' -X DELETE \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        "$url" 2>>"$EMAIL_LOG_FILE") || {
        email_log "CF API network failure: DELETE $path"
        return 2
    }
    http="${out##*$'\n'}"
    resp="${out%$'\n'*}"
    ok=$(echo "$resp" | jq -r '.success // false' 2>/dev/null)
    [[ "$ok" == "true" ]] && return 0
    if [[ "$http" == "404" ]]; then
        email_log "CF API DELETE $path: 404 already gone, treated as success"
        return 0
    fi
    local err
    err=$(echo "$resp" | jq -r '.errors // [] | map("\(.code): \(.message)") | join("; ")' 2>/dev/null)
    email_log "CF API DELETE $path failed: http=${http:-unknown} ${err:-<empty>}"
    return 1
}

_email_cf_token_verify() {
    _email_cf_api GET "user/tokens/verify" >/dev/null
}

# URL-encode 单个字符串（用 jq 的 @uri 滤镜，无 jq 时回退裸值）
# 适用于把用户输入或派生字段安全嵌入 query string
_email_cf_urlencode() {
    if command_exists jq; then
        jq -rn --arg v "${1:-}" '$v | @uri'
    else
        printf '%s' "${1:-}"
    fi
}

# 列出当前 Token 可见的 accounts，用于自动选择
_email_cf_accounts_list() {
    local resp
    resp=$(_email_cf_api GET "accounts?per_page=50") || return 1
    echo "$resp" | jq -r '.result[] | "\(.id)\t\(.name)"'
}

_email_cf_account_first_id() {
    local resp
    resp=$(_email_cf_api GET "accounts?page=1&per_page=1") || return 1
    echo "$resp" | jq -r '.result[0].id // empty'
}

_email_cf_zone_id_by_name() {
    local domain="$1" enc resp
    enc=$(_email_cf_urlencode "$domain")
    resp=$(_email_cf_api GET "zones?name=$enc") || return 1
    local zid
    zid=$(echo "$resp" | jq -r '.result[0].id // empty')
    [[ -n "$zid" ]] || return 1
    printf '%s' "$zid"
}

# ── DNS ──
# 用法: _email_cf_dns_create <zone_id> <type> <name> <content> [priority] [proxied:true|false]
# 返回: record_id（成功时 stdout）
_email_cf_dns_create() {
    local zid="$1" type="$2" name="$3" content="$4" priority="${5:-}" proxied="${6:-}"
    local body
    body=$(jq -nc \
        --arg type "$type" --arg name "$name" --arg content "$content" \
        --argjson priority "${priority:-null}" \
        --argjson proxied "${proxied:-null}" \
        '{type:$type, name:$name, content:$content}
         + (if $priority != null then {priority:$priority} else {} end)
         + (if $proxied != null then {proxied:$proxied} else {} end)')
    local resp
    resp=$(_email_cf_api POST "zones/$zid/dns_records" "$body") || return 1
    echo "$resp" | jq -r '.result.id'
}

_email_cf_dns_delete() {
    local zid="$1" rid="$2"
    [[ -z "$rid" || "$rid" == "null" ]] && return 0
    _email_cf_api_delete "zones/$zid/dns_records/$rid" >/dev/null
}

# 按 type+name 查找（用于清理脏数据 / 防重复添加）
# 返回: 多行 record_id
_email_cf_dns_find_ids() {
    local zid="$1" type="$2" name="$3"
    local enc_type enc_name resp page=1 per_page=50 total_pages count
    enc_type=$(_email_cf_urlencode "$type")
    enc_name=$(_email_cf_urlencode "$name")
    while true; do
        resp=$(_email_cf_api GET "zones/$zid/dns_records?type=$enc_type&name=$enc_name&per_page=$per_page&page=$page") || return 1
        echo "$resp" | jq -r '.result[].id'
        total_pages=$(echo "$resp" | jq -r '.result_info.total_pages // empty' 2>/dev/null)
        count=$(echo "$resp" | jq -r '.result | length' 2>/dev/null)
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
}

# 删除 zone 下所有匹配 type+name 的记录（idempotent 清理）
_email_cf_dns_purge() {
    local zid="$1" type="$2" name="$3" ids id failed=0
    ids=$(_email_cf_dns_find_ids "$zid" "$type" "$name") || return 1
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        _email_cf_dns_delete "$zid" "$id" || failed=1
    done <<< "$ids"
    return "$failed"
}

# ── Pages ──
_email_cf_pages_project_create() {
    local name="$1"
    local body
    body=$(jq -nc --arg n "$name" \
        '{name:$n, production_branch:"production"}')
    _email_cf_api POST "accounts/$CF_ACCOUNT_ID/pages/projects" "$body" >/dev/null
}

_email_cf_pages_project_delete() {
    local name="$1"
    _email_cf_api_delete "accounts/$CF_ACCOUNT_ID/pages/projects/$name" >/dev/null
}

_email_cf_pages_get_subdomain() {
    local project="$1"
    local resp
    resp=$(_email_cf_api GET "accounts/$CF_ACCOUNT_ID/pages/projects/$project") || return 1
    echo "$resp" | jq -r '.result.subdomain // empty'
}

_email_cf_pages_attach_domain() {
    local project="$1" domain="$2"
    local body
    body=$(jq -nc --arg d "$domain" '{name:$d}')
    _email_cf_api POST "accounts/$CF_ACCOUNT_ID/pages/projects/$project/domains" "$body" >/dev/null
}

# ── Workers / D1 ──
_email_cf_worker_exists() {
    local name="$1"
    [[ -n "${CF_API_TOKEN:-}" && -n "${CF_ACCOUNT_ID:-}" ]] || {
        email_log "Worker exists check missing token/account: $name"
        return 2
    }
    command_exists jq || {
        email_log "Worker exists check requires jq: $name"
        return 2
    }

    local enc_name url out resp http ok err
    enc_name=$(_email_cf_urlencode "$name")
    url="https://api.cloudflare.com/client/v4/accounts/$CF_ACCOUNT_ID/workers/scripts/$enc_name"
    out=$(curl -sS --max-time 30 -w '\n%{http_code}' -X GET \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        "$url" 2>>"$EMAIL_LOG_FILE") || {
        email_log "Worker exists check network failure: $name"
        return 2
    }
    http="${out##*$'\n'}"
    resp="${out%$'\n'*}"
    ok=$(jq -r '.success // false' 2>/dev/null <<< "$resp")
    if [[ "$ok" == "true" ]]; then
        return 0
    fi
    if [[ "$http" == "404" ]]; then
        email_log "Worker not found: $name"
        return 1
    fi
    err=$(jq -r '.errors // [] | map("\(.code): \(.message)") | join("; ")' 2>/dev/null <<< "$resp")
    email_log "Worker exists check indeterminate: name=$name http=${http:-unknown} errors=${err:-<empty>}"
    return 2
}

_email_cf_pages_project_exists() {
    local name="$1"
    _email_cf_api GET "accounts/$CF_ACCOUNT_ID/pages/projects/$name" >/dev/null 2>&1
}

_email_cf_worker_delete() {
    local name="$1"
    _email_cf_api_delete "accounts/$CF_ACCOUNT_ID/workers/scripts/$name" >/dev/null
}

_email_cf_worker_secret_put() {
    # 用 API 直接写 secret，避免 wrangler 交互问题
    local script="$1" key="$2" value="$3"
    local body
    body=$(jq -nc --arg n "$key" --arg t "secret_text" --arg v "$value" \
        '{name:$n, type:$t, text:$v}')
    _email_cf_api PUT "accounts/$CF_ACCOUNT_ID/workers/scripts/$script/secrets" "$body" >/dev/null
}

_email_cf_d1_delete() {
    local d1_id="$1"
    [[ -n "$d1_id" ]] || return 0
    _email_cf_api_delete "accounts/$CF_ACCOUNT_ID/d1/database/$d1_id" >/dev/null
}

# ── Email Routing ──
_email_cf_email_routing_status() {
    local zid="$1"
    local resp
    resp=$(_email_cf_api GET "zones/$zid/email/routing") || return 1
    echo "$resp" | jq -r '.result.enabled // false'
}

_email_cf_email_routing_enable() {
    local zid="$1"
    local status
    status=$(_email_cf_email_routing_status "$zid") || return 1
    if [[ "$status" != "true" ]]; then
        _email_cf_api POST "zones/$zid/email/routing/enable" "" >/dev/null || return 1
    fi
    return 0
}

# catch-all: 全部邮件转发到 worker
_email_cf_catch_all_to_worker() {
    local zid="$1" worker_name="$2"
    local body
    body=$(jq -nc --arg w "$worker_name" \
        '{matchers:[{type:"all"}],
          actions:[{type:"worker", value:[$w]}],
          enabled:true,
          name:"catch_all_to_worker"}')
    _email_cf_api PUT "zones/$zid/email/routing/rules/catch_all" "$body" >/dev/null
}

_email_cf_catch_all_disable() {
    local zid="$1"
    local body='{"enabled":false,"matchers":[{"type":"all"}],"actions":[{"type":"drop"}]}'
    _email_cf_api PUT "zones/$zid/email/routing/rules/catch_all" "$body" >/dev/null
}

# ── 高层封装：add-and-record ──
# 用法: _email_cf_dns_create_record_into <state_var> <zone_id> <type> <name> <content> [priority] [proxied]
# 成功时：把返回的 record_id 写入指定 state 变量名（如 EMAIL_DNS_MX1_ID）；失败时变量保留旧值
_email_cf_dns_create_record_into() {
    local var_name="$1"; shift
    local rid
    rid=$(_email_cf_dns_create "$@") || return 1
    [[ -n "$rid" && "$rid" != "null" ]] || return 1
    printf -v "$var_name" '%s' "$rid"
    return 0
}
