#!/usr/bin/env bash
# scripts/cdn-preferip/lib.sh
# B/C 共享：配置加载、日志、节点串拼装、Cloudflare DNS 同步。
# 不进 v4-built.sh；在【国内机】独立运行。

set -u

CDN_PREFERIP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDN_PREFERIP_CONF="${CDN_PREFERIP_CONF:-$CDN_PREFERIP_DIR/cdn-preferip.conf}"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"; }

load_conf() {
    [[ -f "$CDN_PREFERIP_CONF" ]] || die "配置文件不存在: $CDN_PREFERIP_CONF（请 cp cdn-preferip.conf.example cdn-preferip.conf 后填写）"
    # shellcheck disable=SC1090
    source "$CDN_PREFERIP_CONF"
    # CDN_UUID/DOMAIN/WS_PATH 仅旧「单节点」模式需要;新「多节点」(nodes.txt)模式从链接里读,故改可选
    CDN_UUID="${CDN_UUID:-}"; CDN_DOMAIN="${CDN_DOMAIN:-}"; CDN_WS_PATH="${CDN_WS_PATH:-}"
    CDN_NODE_NAME="${CDN_NODE_NAME:-cdn-${CDN_DOMAIN%%.*}}"
    PREFERIP_OUTPUT_FILE="${PREFERIP_OUTPUT_FILE:-$CDN_PREFERIP_DIR/preferip.rendered.txt}"
    CFST_TOP_N="${CFST_TOP_N:-1}"
    [[ "$CFST_TOP_N" =~ ^[0-9]+$ && "$CFST_TOP_N" -ge 1 ]] || die "CFST_TOP_N 必须是 >=1 的整数"
    DEFAULT_CF_COLO="${DEFAULT_CF_COLO:-}"
    DEFAULT_CF_IP_VERSION="${DEFAULT_CF_IP_VERSION:-}"
    if [[ -n "$DEFAULT_CF_IP_VERSION" ]]; then
        DEFAULT_CF_IP_VERSION="$(normalize_ip_version "$DEFAULT_CF_IP_VERSION")" || die "DEFAULT_CF_IP_VERSION 只能是 ipv4 / ipv6 / auto"
    fi
    CFST_COLO_MODE="${CFST_COLO_MODE:-auto}"  # auto=nodes.txt 有地区码就按地区优选; off=全局优选
    CFST_COLO_MODE="${CFST_COLO_MODE,,}"
    case "$CFST_COLO_MODE" in
        auto|off) ;;
        *) die "CFST_COLO_MODE 只能是 auto / off" ;;
    esac
    # 某节点所需地区没有结果时：
    #   keep   = 保留 nodes.txt 原链接里的 server，仅更新有结果的节点（推荐）
    #   abort  = 中止整次生成，完全保留上次输出文件
    #   global = 回退到全局优选 IP（仅在明确接受跨地区覆盖时使用）
    MISSING_COLO_POLICY="${MISSING_COLO_POLICY:-keep}"
    MISSING_COLO_POLICY="${MISSING_COLO_POLICY,,}"
    case "$MISSING_COLO_POLICY" in
        keep|abort|global) ;;
        *) die "MISSING_COLO_POLICY 只能是 keep / abort / global" ;;
    esac
    KEEP_ON_EMPTY="${KEEP_ON_EMPTY:-true}"
    # 优选结果分配/稳态切换（主要由 preferip-push.sh 使用）
    PREFERIP_ASSIGN_MODE="${PREFERIP_ASSIGN_MODE:-round_robin}"
    PREFERIP_ASSIGN_MODE="${PREFERIP_ASSIGN_MODE,,}"
    case "$PREFERIP_ASSIGN_MODE" in
        first|round_robin) ;;
        *) die "PREFERIP_ASSIGN_MODE 只能是 first / round_robin" ;;
    esac
    PREFERIP_STICKY="${PREFERIP_STICKY:-true}"
    PREFERIP_SWITCH_MIN_SPEED_GAIN_PERCENT="${PREFERIP_SWITCH_MIN_SPEED_GAIN_PERCENT:-20}"
    PREFERIP_SWITCH_MIN_LATENCY_GAIN_MS="${PREFERIP_SWITCH_MIN_LATENCY_GAIN_MS:-20}"
    PREFERIP_STICKY_MIN_SPEED="${PREFERIP_STICKY_MIN_SPEED:-0}"
    PREFERIP_STICKY_MAX_LATENCY="${PREFERIP_STICKY_MAX_LATENCY:-999999}"
    PREFERIP_PROBE_ENABLE="${PREFERIP_PROBE_ENABLE:-false}"
    PREFERIP_PROBE_TIMEOUT="${PREFERIP_PROBE_TIMEOUT:-6}"
    PREFERIP_PROBE_ACCEPT_CODES="${PREFERIP_PROBE_ACCEPT_CODES:-200,204,301,302,400,401,403,404,426}"
    PREFERIP_BAD_TTL_HOURS="${PREFERIP_BAD_TTL_HOURS:-24}"
    PREFERIP_STATE_FILE="${PREFERIP_STATE_FILE:-$CDN_PREFERIP_DIR/preferip.state.tsv}"
    PREFERIP_HISTORY_FILE="${PREFERIP_HISTORY_FILE:-$CDN_PREFERIP_DIR/preferip.history.csv}"
    PREFERIP_BAD_FILE="${PREFERIP_BAD_FILE:-$CDN_PREFERIP_DIR/bad-ip.txt}"
    PREFERIP_LOCK_FILE="${PREFERIP_LOCK_FILE:-$CDN_PREFERIP_DIR/preferip.lock}"
    PREFERIP_SERVER_MODE="${PREFERIP_SERVER_MODE:-ip}"
    PREFERIP_SERVER_MODE="${PREFERIP_SERVER_MODE,,}"
    case "$PREFERIP_SERVER_MODE" in
        ip|dns|auto) ;;
        *) die "PREFERIP_SERVER_MODE 只能是 ip / dns / auto" ;;
    esac
    PREFERIP_DNS_TTL="${PREFERIP_DNS_TTL:-1}"
    [[ "$PREFERIP_DNS_TTL" =~ ^[0-9]+$ && "$PREFERIP_DNS_TTL" -ge 1 ]] || die "PREFERIP_DNS_TTL 必须是 >=1 的整数"
    PREFERIP_CF_API_TOKEN="${PREFERIP_CF_API_TOKEN:-${CF_API_TOKEN:-${CLOUDFLARE_API_TOKEN:-}}}"
    PREFERIP_CF_ZONE_ID="${PREFERIP_CF_ZONE_ID:-}"
    PREFERIP_DNS_PROXIED="${PREFERIP_DNS_PROXIED:-false}"
    PREFERIP_DNS_PROXIED="${PREFERIP_DNS_PROXIED,,}"
    case "$PREFERIP_DNS_PROXIED" in
        true|false) ;;
        *) die "PREFERIP_DNS_PROXIED 只能是 true / false" ;;
    esac
    PREFERIP_DNS_DELETE_STALE="${PREFERIP_DNS_DELETE_STALE:-true}"
    if [[ "$PREFERIP_SERVER_MODE" == "dns" && -z "$PREFERIP_CF_API_TOKEN" ]]; then
        die "PREFERIP_SERVER_MODE=dns 需要配置 Cloudflare API Token（PREFERIP_CF_API_TOKEN / CF_API_TOKEN / CLOUDFLARE_API_TOKEN）"
    fi
}

trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

normalize_colo_key() {
    # 支持 HKG / NRT,KIX 这类 CF colo/IATA 码；去空白并转大写。
    local key="${1:-}"
    key="${key//[[:space:]]/}"
    key="${key^^}"
    [[ "$key" =~ ^[A-Z0-9]+(,[A-Z0-9]+)*$ ]] || return 1
    printf '%s' "$key"
}

normalize_ip_version() {
    local v="${1:-}"
    v="$(trim "$v")"
    v="${v,,}"
    case "$v" in
        ""|auto|default) printf '' ;;
        4|v4|ip4|ipv4) printf 'ipv4' ;;
        6|v6|ip6|ipv6) printf 'ipv6' ;;
        *) return 1 ;;
    esac
}

split_colo_version() {
    # 支持 HKG@ipv6 这种紧凑写法，也支持单独字段写 ipv6。
    local raw="${1:-}" base ver
    base="$raw"
    ver=""
    if [[ "$raw" == *@* ]]; then
        base="${raw%@*}"
        ver="${raw##*@}"
    fi
    base="$(normalize_colo_key "$base")" || return 1
    ver="$(normalize_ip_version "$ver")" || return 1
    printf '%s|%s' "$base" "$ver"
}

result_key_for_colo() {
    local colo="${1:-}" key=""
    if [[ -n "$colo" ]] && key=$(normalize_colo_key "$colo" 2>/dev/null); then
        printf '%s' "$key"
    else
        printf 'GLOBAL'
    fi
}

result_key_for_node() {
    local colo="${1:-}" ip_version="${2:-}" base ver
    base="$(result_key_for_colo "$colo")"
    ver="$(normalize_ip_version "$ip_version")" || return 1
    if [[ -n "$ver" ]]; then
        printf '%s@%s' "$base" "${ver^^}"
    else
        printf '%s' "$base"
    fi
}

normalize_result_key() {
    local raw="${1:-}" base ver
    raw="$(trim "$raw")"
    if [[ "$raw" == *@* ]]; then
        base="${raw%@*}"
        ver="${raw##*@}"
        result_key_for_node "$base" "$ver"
    else
        result_key_for_node "$raw" ""
    fi
}

result_key_colo() {
    local key="${1:-}"
    key="${key%@*}"
    [[ "$key" == "GLOBAL" ]] && { printf 'GLOBAL'; return 0; }
    normalize_colo_key "$key"
}

result_key_ip_version() {
    local key="${1:-}"
    if [[ "$key" == *@* ]]; then
        normalize_ip_version "${key##*@}"
    else
        printf ''
    fi
}

NODE_NOTE=""; NODE_COLO=""; NODE_IP_VERSION=""; NODE_LINK=""
NODE_ENTRY_DOMAIN=""
validate_dns_name() {
    local name="${1:-}"
    [[ "$name" =~ ^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

parse_node_line() {
    # 兼容格式：
    #   旧: 备注|vless链接
    #   新: 备注|CF地区码|vless链接       例如: 香港-01|HKG|vless://...
    #   混合池: 备注|CF地区码|ipv6|vless链接 或 备注|HKG@ipv6|vless://...
    #   DNS入口: 备注|CF地区码|entry=prefer.example.com|vless://...
    #            备注|CF地区码|ipv6|entry=prefer6.example.com|vless://...
    # 地区码可填多个逗号分隔候选，例如: 日本-01|NRT,KIX|vless://...
    local raw="${1:-}" trimmed cv i link_idx=-1 token token_l value
    local -a fields=()
    NODE_NOTE=""; NODE_COLO=""; NODE_IP_VERSION=""; NODE_LINK=""; NODE_ENTRY_DOMAIN=""
    [[ -n "${raw//[[:space:]]/}" ]] || return 1
    trimmed="$(trim "$raw")"
    [[ "$trimmed" == \#* ]] && return 1
    IFS='|' read -ra fields <<< "$raw"
    [[ ${#fields[@]} -ge 2 ]] || return 1
    NODE_NOTE="$(trim "${fields[0]}")"
    for ((i=1; i<${#fields[@]}; i++)); do
        token="$(trim "${fields[$i]}")"
        if [[ "$token" == vless://* ]]; then
            NODE_LINK="$token"
            link_idx="$i"
            break
        fi
    done
    [[ "$link_idx" -gt 0 ]] || return 1
    [[ -n "$NODE_NOTE" && "$NODE_LINK" == vless://* ]] || return 1

    NODE_COLO="${DEFAULT_CF_COLO:-}"
    NODE_IP_VERSION="${DEFAULT_CF_IP_VERSION:-}"
    for ((i=1; i<link_idx; i++)); do
        token="$(trim "${fields[$i]}")"
        [[ -n "$token" ]] || continue
        token_l="${token,,}"
        case "$token_l" in
            ipv4|v4|ip4|ipv6|v6|ip6)
                NODE_IP_VERSION="$(normalize_ip_version "$token")" || return 1
                ;;
            entry=*|dns=*|server=*)
                value="${token#*=}"
                value="$(trim "$value")"
                [[ -n "$value" ]] && NODE_ENTRY_DOMAIN="$value"
                ;;
            *.*)
                if [[ -z "$NODE_ENTRY_DOMAIN" && "$token" != *":"* && "$token" != *"/"* ]]; then
                    NODE_ENTRY_DOMAIN="$token"
                else
                    return 1
                fi
                ;;
            *)
                cv="$(split_colo_version "$token")" || return 1
                NODE_COLO="${cv%%|*}"
                value="${cv#*|}"
                [[ -n "$value" && "$value" != "$cv" ]] && NODE_IP_VERSION="$value"
                ;;
        esac
    done
    if [[ -n "$NODE_ENTRY_DOMAIN" ]]; then
        NODE_ENTRY_DOMAIN="${NODE_ENTRY_DOMAIN,,}"
        validate_dns_name "$NODE_ENTRY_DOMAIN" || return 1
    fi
    if [[ -n "$NODE_IP_VERSION" ]]; then
        NODE_IP_VERSION="$(normalize_ip_version "$NODE_IP_VERSION")" || return 1
    fi
    return 0
}

uri_host() {
    local host="${1:-}"
    if [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

is_ip_literal() {
    local ip="${1:-}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || ( "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ ) ]]
}

vless_hostport() {
    local link="${1:-}" body after hostport
    [[ "$link" == vless://* && "$link" == *"@"* ]] || return 1
    body="${link#vless://}"
    body="${body%%#*}"
    after="${body#*@}"
    hostport="${after%%\?*}"
    [[ -n "$hostport" ]] || return 1
    printf '%s' "$hostport"
}

vless_server() {
    local hostport
    hostport="$(vless_hostport "$1")" || return 1
    if [[ "$hostport" =~ ^\[([^]]+)\](:[0-9]+)?$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    elif [[ "$hostport" =~ ^([^:]+):[0-9]+$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        # 无端口域名 / IPv4 / 未加括号 IPv6（兼容旧数据）
        printf '%s' "$hostport"
    fi
}

vless_port() {
    local hostport
    hostport="$(vless_hostport "$1")" || return 1
    if [[ "$hostport" =~ ^\[[^]]+\]:([0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    elif [[ "$hostport" =~ ^[^:]+:([0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf '443'
    fi
}

# URL-encode（用于 ws path 等）
urlencode() {
    local s="$1" out="" i c
    local LC_ALL=C   # 关键:按字节处理,正确编码中文等多字节 UTF-8(否则会编成 Unicode 码点)
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v c '%%%02X' "'${c}"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

urldecode() {
    local s="${1:-}"
    s="${s//+/ }"
    printf '%b' "${s//%/\\x}"
}

vless_query_string() {
    local link="${1:-}" body after query
    [[ "$link" == vless://* ]] || return 1
    body="${link#vless://}"
    body="${body%%#*}"
    after="${body#*@}"
    [[ "$after" == *\?* ]] || return 1
    query="${after#*\?}"
    printf '%s' "$query"
}

vless_query_param() {
    local link="${1:-}" key="${2:-}" query pair k v
    local -a _pairs
    query="$(vless_query_string "$link")" || return 1
    IFS='&' read -ra _pairs <<< "$query"
    for pair in "${_pairs[@]}"; do
        k="${pair%%=*}"
        v=""
        [[ "$pair" == *=* ]] && v="${pair#*=}"
        if [[ "$k" == "$key" ]]; then
            urldecode "$v"
            return 0
        fi
    done
    return 1
}

cf_api() {
    local method="$1" path="$2" token="$3"; shift 3
    local url="https://api.cloudflare.com/client/v4${path}"
    curl -fsS --max-time 30 -X "$method" "$url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" "$@"
}

cf_api_ok() { [[ "$(jq -r '.success // false' 2>/dev/null <<< "$1")" == "true" ]]; }
cf_api_err() { jq -r '.errors[0].message // "未知错误"' 2>/dev/null <<< "$1" || echo "未知错误"; }

cf_list_zones() {
    local token="$1" query="${2:-}" per_page="${3:-50}"
    local page=1 resp all='[]' total_pages count endpoint
    while true; do
        endpoint="/zones?per_page=${per_page}&page=${page}"
        [[ -n "$query" ]] && endpoint="${endpoint}&${query}"
        resp="$(cf_api GET "$endpoint" "$token")" || return 1
        if ! cf_api_ok "$resp"; then
            echo "$resp"
            return 1
        fi
        all="$(jq -c --argjson acc "$all" '$acc + (.result // [])' <<< "$resp" 2>/dev/null)" || {
            echo '{"success":false,"errors":[{"message":"解析 Zone 分页响应失败"}]}'
            return 1
        }
        total_pages="$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)"
        count="$(jq -r '.result | length' <<< "$resp" 2>/dev/null)"
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
    jq -n --argjson result "$all" '{success:true, errors:[], messages:[], result:$result}'
}

cf_get_zone_id() {
    local domain="$1" token="$2" current resp zid try
    current="$domain"
    while [[ "$current" == *"."* ]]; do
        resp="$(cf_api GET "/zones?name=$current" "$token")" || return 1
        if cf_api_ok "$resp"; then
            zid="$(jq -r '.result[0].id // empty' <<< "$resp")"
            [[ -n "$zid" ]] && { printf '%s' "$zid"; return 0; }
        fi
        current="${current#*.}"
    done
    resp="$(cf_list_zones "$token")" || return 1
    if cf_api_ok "$resp"; then
        try="$domain"
        while [[ "$try" == *"."* ]]; do
            zid="$(jq -r --arg d "$try" '.result[] | select(.name == $d) | .id' <<< "$resp" | head -n1)"
            [[ -n "$zid" ]] && { printf '%s' "$zid"; return 0; }
            try="${try#*.}"
        done
    fi
    return 1
}

cf_dns_upsert_record() {
    local zone_id="$1" token="$2" type="$3" name="$4" content="$5" proxied="${6:-false}"
    local records record_id count data resp extra_ids
    records="$(cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")" || return 1
    if ! cf_api_ok "$records"; then
        log "读取 $type DNS 记录失败: $(cf_api_err "$records")"
        return 1
    fi
    record_id="$(jq -r '.result[0].id // empty' <<< "$records")"
    count="$(jq -r '.result | length' <<< "$records")"
    if [[ "$count" -gt 1 ]]; then
        log "警告: 存在 ${count} 条 $type 记录，将保留第一条并清理多余记录。"
        extra_ids="$(jq -r '.result[1:][] | .id // empty' <<< "$records")"
    else
        extra_ids=""
    fi
    data="$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --argjson proxied "$proxied" --argjson ttl "${PREFERIP_DNS_TTL:-1}" \
        '{type:$type, name:$name, content:$content, ttl:$ttl, proxied:$proxied}')"
    if [[ -n "$record_id" ]]; then
        resp="$(cf_api PUT "/zones/$zone_id/dns_records/$record_id" "$token" --data "$data")" || return 1
    else
        resp="$(cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$data")" || return 1
    fi
    if cf_api_ok "$resp"; then
        while IFS= read -r extra_id; do
            [[ -n "$extra_id" ]] || continue
            resp="$(cf_api DELETE "/zones/$zone_id/dns_records/$extra_id" "$token")" || return 1
            if ! cf_api_ok "$resp"; then
                log "删除多余 $type DNS 记录失败: $(cf_api_err "$resp")"
                return 1
            fi
        done <<< "$extra_ids"
        printf '%s' "$resp"
        return 0
    fi
    log "DNS 记录 ${name} ${type} 更新失败: $(cf_api_err "$resp")"
    return 1
}

cf_dns_delete_records() {
    local zone_id="$1" token="$2" type="$3" name="$4"
    local records ids id resp
    records="$(cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")" || return 1
    if ! cf_api_ok "$records"; then
        log "读取待清理 $type DNS 记录失败: $(cf_api_err "$records")"
        return 1
    fi
    ids="$(jq -r '.result[].id // empty' <<< "$records")"
    [[ -n "$ids" ]] || return 0
    while IFS= read -r id; do
        [[ -n "$id" ]] || continue
        resp="$(cf_api DELETE "/zones/$zone_id/dns_records/$id" "$token")" || return 1
        if ! cf_api_ok "$resp"; then
            log "删除 stale DNS 记录失败: $(cf_api_err "$resp")"
            return 1
        fi
    done <<< "$ids"
}

cf_ip_family() {
    local ip="${1:-}"
    if [[ "$ip" == *:* ]]; then
        printf 'AAAA'
    else
        printf 'A'
    fi
}

cf_dns_sync_entry_domain() {
    local domain="$1" ip="$2" token="${3:-$PREFERIP_CF_API_TOKEN}" zone_id="${4:-$PREFERIP_CF_ZONE_ID}" delete_stale_override="${5:-}" family delete_stale proxied
    [[ -n "$domain" && -n "$ip" ]] || return 1
    is_ip_literal "$ip" || return 1
    [[ -n "$token" ]] || die "DNS 模式需要 Cloudflare API Token（PREFERIP_CF_API_TOKEN / CF_API_TOKEN / CLOUDFLARE_API_TOKEN）"
    family="$(cf_ip_family "$ip")"
    delete_stale="${delete_stale_override:-${PREFERIP_DNS_DELETE_STALE:-true}}"
    proxied="${PREFERIP_DNS_PROXIED:-false}"
    [[ "$proxied" == "true" || "$proxied" == "false" ]] || proxied="false"
    if [[ -z "$zone_id" ]]; then
        zone_id="$(cf_get_zone_id "$domain" "$token")" || return 1
        [[ -n "$zone_id" ]] || return 1
    fi
    cf_dns_upsert_record "$zone_id" "$token" "$family" "$domain" "$ip" "$proxied" >/dev/null || return 1
    if [[ "$delete_stale" == "true" ]]; then
        case "$family" in
            A) cf_dns_delete_records "$zone_id" "$token" AAAA "$domain" || return 1 ;;
            AAAA) cf_dns_delete_records "$zone_id" "$token" A "$domain" || return 1 ;;
        esac
    fi
    printf '%s|%s|%s' "$zone_id" "$family" "$ip"
}

# 拼一条 CDN 客户端 vless 链接：server=优选IP，host/sni=真实域名。
# 与落地机 reality_cdn_build_link 完全一致的格式。
build_cdn_link() {
    local server="$1" name="${2:-$CDN_NODE_NAME}"
    printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#%s' \
        "$CDN_UUID" "$(uri_host "$server")" "$CDN_DOMAIN" "$CDN_DOMAIN" "$(urlencode "$CDN_WS_PATH")" "$(urlencode "$name")"
}

# 多节点模式:把一条现成 vless 链接的 server 换成优选IP、备注换成指定名,其余(uuid/port/host/sni/path)原样保留。
# 用法: rewrite_vless "<原链接>" "<优选IP>" "<新备注名>"  →  stdout 新链接
rewrite_vless() {
    local link="$1" newip="$2" newname="$3"
    [[ "$link" == vless://* ]] || return 1
    local body="${link#vless://}"
    body="${body%%#*}"                          # 去掉原 #备注
    local uuid="${body%%@*}"                     # UUID(@前)
    local after="${body#*@}"                     # HOST:PORT?QUERY
    local query=""; [[ "$after" == *\?* ]] && query="${after#*\?}"
    local port; port="$(vless_port "$link")" || port="443"
    local out="vless://${uuid}@$(uri_host "$newip"):${port}"
    [[ -n "$query" ]] && out="${out}?${query}"
    printf '%s#%s' "$out" "$(urlencode "$newname")"
}
