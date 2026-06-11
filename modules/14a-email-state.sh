# modules/14a-email-state.sh - 临时邮箱 state 持久化、Token 输入、日志包装
readonly EMAIL_STATE_DIR="/etc/server-manage/email"
readonly EMAIL_STATE_FILE="${EMAIL_STATE_DIR}/state.conf"
readonly EMAIL_ADMIN_FILE="/root/.email-admin.txt"
readonly EMAIL_LOG_FILE="/var/log/server-manage-email.log"
readonly EMAIL_INSTALL_DIR="/root/cloudflare_temp_email"

# 默认 state 字段（每次 load 前必须重置，防上轮残值污染）
_email_state_reset_vars() {
    EMAIL_INSTALLED=0
    EMAIL_INSTALL_VERSION=""
    EMAIL_INSTALL_DATE=""
    EMAIL_DOMAIN=""
    EMAIL_ZONE_ID=""
    EMAIL_CF_ACCOUNT_ID=""
    EMAIL_API_PREFIX=""
    EMAIL_API_DOMAIN=""
    EMAIL_FRONTEND_PREFIX=""
    EMAIL_FRONTEND_DOMAIN=""
    EMAIL_ADDRESS_PREFIX=""
    EMAIL_WORKER_NAME=""
    EMAIL_PAGES_PROJECT=""
    EMAIL_PAGES_DOMAIN=""
    EMAIL_D1_NAME=""
    EMAIL_D1_ID=""
    EMAIL_RESEND_ENABLED=0
    EMAIL_RESEND_SEND_DOMAIN=""
    EMAIL_DNS_FRONTEND_ID=""
    EMAIL_DNS_MX1_ID=""
    EMAIL_DNS_MX2_ID=""
    EMAIL_DNS_MX3_ID=""
    EMAIL_DNS_DKIM_ID=""
    EMAIL_DNS_SPF_ID=""
    EMAIL_DNS_SEND_MX_ID=""
    EMAIL_DNS_DMARC_ID=""
    EMAIL_CATCH_ALL_ENABLED=0
    EMAIL_PATCHES_APPLIED=""
}

# value 转义：与 reality_state_quote 同款，确保通过新版 validate_conf_file
_email_state_quote() {
    local s="${1:-}"
    s=${s//$'\r'/ }
    s=${s//$'\n'/ }
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//\$/\\\$}
    s=${s//\`/\\\`}
    printf '"%s"' "$s"
}

email_state_init_dirs() {
    mkdir -p "$EMAIL_STATE_DIR"
    chown root:root "$EMAIL_STATE_DIR"
    chmod 700 "$EMAIL_STATE_DIR"
    [[ -f "$EMAIL_LOG_FILE" ]] || { touch "$EMAIL_LOG_FILE"; chmod 600 "$EMAIL_LOG_FILE"; }
}

email_state_write() {
    email_state_init_dirs
    local tmp
    tmp=$(mktemp "$EMAIL_STATE_DIR/.state.XXXXXX") || return 1
    {
        echo "# server-manage email state — 由脚本管理，请勿手动编辑"
        echo "EMAIL_INSTALLED=${EMAIL_INSTALLED:-0}"
        echo "EMAIL_RESEND_ENABLED=${EMAIL_RESEND_ENABLED:-0}"
        echo "EMAIL_CATCH_ALL_ENABLED=${EMAIL_CATCH_ALL_ENABLED:-0}"
        echo "EMAIL_INSTALL_VERSION=$(_email_state_quote "${EMAIL_INSTALL_VERSION:-}")"
        echo "EMAIL_INSTALL_DATE=$(_email_state_quote "${EMAIL_INSTALL_DATE:-}")"
        echo "EMAIL_DOMAIN=$(_email_state_quote "${EMAIL_DOMAIN:-}")"
        echo "EMAIL_ZONE_ID=$(_email_state_quote "${EMAIL_ZONE_ID:-}")"
        echo "EMAIL_CF_ACCOUNT_ID=$(_email_state_quote "${EMAIL_CF_ACCOUNT_ID:-}")"
        echo "EMAIL_API_PREFIX=$(_email_state_quote "${EMAIL_API_PREFIX:-}")"
        echo "EMAIL_API_DOMAIN=$(_email_state_quote "${EMAIL_API_DOMAIN:-}")"
        echo "EMAIL_FRONTEND_PREFIX=$(_email_state_quote "${EMAIL_FRONTEND_PREFIX:-}")"
        echo "EMAIL_FRONTEND_DOMAIN=$(_email_state_quote "${EMAIL_FRONTEND_DOMAIN:-}")"
        echo "EMAIL_ADDRESS_PREFIX=$(_email_state_quote "${EMAIL_ADDRESS_PREFIX:-}")"
        echo "EMAIL_WORKER_NAME=$(_email_state_quote "${EMAIL_WORKER_NAME:-}")"
        echo "EMAIL_PAGES_PROJECT=$(_email_state_quote "${EMAIL_PAGES_PROJECT:-}")"
        echo "EMAIL_PAGES_DOMAIN=$(_email_state_quote "${EMAIL_PAGES_DOMAIN:-}")"
        echo "EMAIL_D1_NAME=$(_email_state_quote "${EMAIL_D1_NAME:-}")"
        echo "EMAIL_D1_ID=$(_email_state_quote "${EMAIL_D1_ID:-}")"
        echo "EMAIL_RESEND_SEND_DOMAIN=$(_email_state_quote "${EMAIL_RESEND_SEND_DOMAIN:-}")"
        echo "EMAIL_DNS_FRONTEND_ID=$(_email_state_quote "${EMAIL_DNS_FRONTEND_ID:-}")"
        echo "EMAIL_DNS_MX1_ID=$(_email_state_quote "${EMAIL_DNS_MX1_ID:-}")"
        echo "EMAIL_DNS_MX2_ID=$(_email_state_quote "${EMAIL_DNS_MX2_ID:-}")"
        echo "EMAIL_DNS_MX3_ID=$(_email_state_quote "${EMAIL_DNS_MX3_ID:-}")"
        echo "EMAIL_DNS_DKIM_ID=$(_email_state_quote "${EMAIL_DNS_DKIM_ID:-}")"
        echo "EMAIL_DNS_SPF_ID=$(_email_state_quote "${EMAIL_DNS_SPF_ID:-}")"
        echo "EMAIL_DNS_SEND_MX_ID=$(_email_state_quote "${EMAIL_DNS_SEND_MX_ID:-}")"
        echo "EMAIL_DNS_DMARC_ID=$(_email_state_quote "${EMAIL_DNS_DMARC_ID:-}")"
        echo "EMAIL_PATCHES_APPLIED=$(_email_state_quote "${EMAIL_PATCHES_APPLIED:-}")"
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp"
    chown root:root "$tmp"
    mv -f "$tmp" "$EMAIL_STATE_FILE"
}

email_state_load() {
    _email_state_reset_vars
    [[ -f "$EMAIL_STATE_FILE" ]] || return 1
    if ! validate_conf_file "$EMAIL_STATE_FILE"; then
        print_error "邮箱 state 校验失败，已忽略: $EMAIL_STATE_FILE"
        return 1
    fi
    # shellcheck disable=SC1090
    source "$EMAIL_STATE_FILE"
    [[ "${EMAIL_INSTALLED:-0}" == "1" ]]
}

email_state_clear() {
    rm -f "$EMAIL_STATE_FILE"
    _email_state_reset_vars
}

# 把当前 state 文件备份为 .bak.<timestamp>；返回备份文件路径
# 用于 partial → 重新部署 / upgrade 等"会覆盖 state"的操作前防丢失
email_state_backup() {
    [[ -f "$EMAIL_STATE_FILE" ]] || { echo ""; return 0; }
    local bak="${EMAIL_STATE_FILE}.bak.$(date +%Y%m%d-%H%M%S)"
    if cp -a "$EMAIL_STATE_FILE" "$bak" 2>/dev/null; then
        chmod 600 "$bak"
        echo "$bak"
        return 0
    fi
    return 1
}

# ── Token / 敏感输入 ──
# 用法: email_read_secret "Cloudflare API Token" CF_API_TOKEN
email_read_secret() {
    local prompt="$1" var_name="$2" t=""
    [[ -t 0 ]] || { print_error "非交互终端无法读取 ${prompt}"; return 1; }
    read -r -s -p "$(echo -e "${C_YELLOW}${prompt}: ${C_RESET}")" t
    echo ""
    printf -v "$var_name" '%s' "$t"
    [[ -n "$t" ]]
}

email_mask_token() {
    local t="${1:-}" len=${#1}
    if (( len <= 8 )); then
        printf '****'
    else
        printf '%s****%s' "${t:0:4}" "${t: -4}"
    fi
}

# 同步 export Wrangler 推荐的新版环境变量（CF_* 在 Wrangler 4.x 已 deprecated）
# 调用前确保 CF_API_TOKEN / CF_ACCOUNT_ID 已就位
_email_export_wrangler_env() {
    export CF_API_TOKEN CF_ACCOUNT_ID
    export CLOUDFLARE_API_TOKEN="${CF_API_TOKEN:-}"
    export CLOUDFLARE_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
}

# 统一调用上游项目本地 Wrangler。
# Cloudflare 官方推荐 Wrangler 作为项目依赖安装；cloudflare_temp_email 的 worker/frontend/pages
# package.json 也都把 wrangler 放在 devDependencies，避免全局 wrangler 与项目锁定版本漂移。
_email_wrangler() {
    local candidate
    for candidate in \
        "./node_modules/.bin/wrangler" \
        "$EMAIL_INSTALL_DIR/worker/node_modules/.bin/wrangler" \
        "$EMAIL_INSTALL_DIR/frontend/node_modules/.bin/wrangler" \
        "$EMAIL_INSTALL_DIR/pages/node_modules/.bin/wrangler"; do
        if [[ -x "$candidate" ]]; then
            "$candidate" "$@"
            return $?
        fi
    done
    print_error "未找到项目本地 Wrangler，请先安装对应子项目依赖。"
    return 127
}

email_save_admin_password() {
    local pw="$1"
    (
        umask 077
        {
            echo "# Cloudflare Temp Email 管理员密码"
            echo "# 自动生成于 $(date '+%Y-%m-%d %H:%M:%S')"
            echo "# 该文件仅 root 可读 (mode 600)"
            echo ""
            printf 'admin_password=%s\n' "$pw"
        } > "$EMAIL_ADMIN_FILE"
    )
    chmod 600 "$EMAIL_ADMIN_FILE"
    chown root:root "$EMAIL_ADMIN_FILE"
}

# ── 日志包装 ──
email_log() {
    email_state_init_dirs
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$EMAIL_LOG_FILE"
}

# 用法: email_run "构建前端" pnpm build:pages
# 默认安静运行，失败时自动打印日志尾部
email_run() {
    local label="$1"; shift
    email_state_init_dirs
    email_log "===== $label ====="
    printf '%b' "${C_BLUE}[..]${C_RESET} $label..."
    if "$@" >> "$EMAIL_LOG_FILE" 2>&1; then
        printf '\r%b\n' "${C_GREEN}[✓]${C_RESET} $label                                                  "
        return 0
    fi
    local rc=$?
    printf '\r%b\n' "${C_RED}[✗]${C_RESET} $label (exit=$rc)                                            "
    echo -e "${C_GRAY}最近日志 (${EMAIL_LOG_FILE} 末 30 行，敏感字段已脱敏)：${C_RESET}"
    # tail 时过滤可能出现的 secret 明文（curl --data 的 secret_text、wrangler 输出 TOKEN 等）
    tail -n 30 "$EMAIL_LOG_FILE" 2>/dev/null | _email_redact_secrets | sed 's/^/  /'
    return "$rc"
}

# 行级脱敏：替换日志中可能出现的 secret 明文
# 覆盖 CF API JSON 中的 "text":"..."、wrangler 输出的 TOKEN=xxx 形式
_email_redact_secrets() {
    sed -E \
        -e 's/("text"[[:space:]]*:[[:space:]]*)"[^"]*"/\1"<redacted>"/g' \
        -e 's/(ADMIN_PASSWORDS|RESEND_TOKEN|CLOUDFLARE_API_TOKEN|CF_API_TOKEN)([[:space:]]*=[[:space:]]*|:[[:space:]]*)["'"'"']?[^[:space:]"'"'"']+["'"'"']?/\1\2<redacted>/g' \
        -e 's/(Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1<redacted>/g'
}

# 同步 pages/wrangler.toml 中 [[services]] service 字段为当前 Worker 名
# 幂等：已是正确值则 noop；无 services section 也 noop（不视为错误）
# 调用方：14c 首次部署、14d 升级、14d 重新部署 — 三处复用，避免自定义 Worker 名后 Pages Functions 仍指向 cloudflare_temp_email
_email_patch_pages_service_binding() {
    local pages_dir="${1:-$EMAIL_INSTALL_DIR/pages}"
    local pages_toml="$pages_dir/wrangler.toml"
    [[ -f "$pages_toml" ]] || { email_log "pages toml 不存在: $pages_toml"; return 1; }
    if ! grep -qE '^[[:space:]]*service[[:space:]]*=' "$pages_toml"; then
        email_log "pages toml 未包含 service 行，无需 patch"
        return 0
    fi
    if grep -qE "^[[:space:]]*service[[:space:]]*=[[:space:]]*\"${EMAIL_WORKER_NAME}\"" "$pages_toml"; then
        email_log "pages service binding 已是 ${EMAIL_WORKER_NAME}，跳过"
        return 0
    fi
    sed -i.bak -E "s|^([[:space:]]*service[[:space:]]*=[[:space:]]*\")[^\"]+(\".*)$|\1${EMAIL_WORKER_NAME}\2|" "$pages_toml"
    rm -f "${pages_toml}.bak"
    email_log "Patched pages/wrangler.toml service binding → ${EMAIL_WORKER_NAME}"
    return 0
}
