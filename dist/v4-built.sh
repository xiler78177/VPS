#!/bin/bash

readonly VERSION="v14.5"
readonly SCRIPT_NAME="server-manage"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
readonly WG_SHARED_DB_DIR="/etc/wireguard/db"
readonly WG_SHARED_DB_FILE="${WG_SHARED_DB_DIR}/wg-data.json"
readonly WG_SHARED_ROLE_FILE="/etc/wireguard/.role"
readonly WG_SHARED_ROUTE_STATE_FILE="${WG_SHARED_DB_DIR}/managed-routes.state"
readonly WG_DEFAULT_PORT=50000
readonly WG_MTU_DIRECT=1420
PLATFORM="debian"

detect_platform() {
    if [[ -f /etc/openwrt_release ]]; then
        PLATFORM="openwrt"
    elif [[ -f /etc/os-release ]]; then
        local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$os_id" in
            ubuntu|debian) PLATFORM="debian" ;;
            *) command -v opkg &>/dev/null && PLATFORM="openwrt" ;;
        esac
    elif command -v opkg &>/dev/null; then
        PLATFORM="openwrt"
fi
}
detect_platform

if [[ "$PLATFORM" == "openwrt" ]]; then
    readonly LOG_FILE="/root/.server-manage/log/${SCRIPT_NAME}.log"
else
    readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
fi

feature_blocked() {
    echo -e "${C_YELLOW}[!] 功能不可用: $1${C_RESET}"
    echo -e "${C_YELLOW}    当前系统: OpenWrt (仅支持 Web/DNS/DDNS/BBR/基础信息)${C_RESET}"
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_GRAY='\033[0;90m'
readonly C_DIM='\033[2m'

CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com"
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
DEFAULT_SSH_PORT=22
SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
DOCKER_PROXY_DIR="/etc/systemd/system/docker.service.d"
DOCKER_PROXY_CONF="${DOCKER_PROXY_DIR}/http-proxy.conf"

# 注意：$CONFIG_FILE 的安全加载在 01-utils.sh 末尾完成（需依赖 validate_conf_file）

CURRENT_SSH_PORT=""
CURRENT_SSH_PORTS=""
APT_UPDATED=0

CACHED_IPV4=""
CACHED_IPV6=""
CACHED_ISP=""
CACHED_LOCATION=""
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
DDNS_UPDATE_SCRIPT="${DDNS_UPDATE_SCRIPT:-/usr/local/bin/ddns-update.sh}"
SAAS_CONFIG_DIR="/etc/saas-cdn"
SAAS_PREFERRED_DOMAINS="saas.sin.fan cdn.anycast.eu.org cdn-all.xn--b6gac.eu.org www.freedidi.com"
REALITY_CONFIG_DIR="/etc/server-manage/reality"
REALITY_STATE_FILE="${REALITY_CONFIG_DIR}/state.conf"
REALITY_LINK_FILE="${REALITY_CONFIG_DIR}/client-link.txt"
REALITY_CLIENT_JSON="${REALITY_CONFIG_DIR}/client.json"
REALITY_LINK_FILE_V4="${REALITY_CONFIG_DIR}/client-link-v4.txt"
REALITY_LINK_FILE_V6="${REALITY_CONFIG_DIR}/client-link-v6.txt"
REALITY_CLIENT_JSON_V4="${REALITY_CONFIG_DIR}/client-v4.json"
REALITY_CLIENT_JSON_V6="${REALITY_CONFIG_DIR}/client-v6.json"
REALITY_BACKUP_DIR="${REALITY_CONFIG_DIR}/backups"
REALITY_RELAY_DIR="${REALITY_CONFIG_DIR}/relays"
# CDN 链路（VLESS+WS+TLS 橙云 + 优选 IP）状态/产物。与 Reality 直连链路并存：
# Reality 仍绑 0.0.0.0:443 灰云直连；CDN 的 WS 入站只绑 127.0.0.1:<内部端口>，
# 由 nginx 在独立回源端口(REALITY_CDN_ORIGIN_PORT)做 TLS 终止 + 反代，CF 橙云回源。
REALITY_CDN_STATE_FILE="${REALITY_CONFIG_DIR}/cdn.conf"
REALITY_CDN_LINK_FILE="${REALITY_CONFIG_DIR}/cdn-link.txt"
REALITY_CDN_CLIENT_JSON="${REALITY_CONFIG_DIR}/cdn-client.json"
REALITY_CDN_ORIGIN_PORT="${REALITY_CDN_ORIGIN_PORT:-8443}"
# 443 共存模式（nginx stream + ssl_preread 分流）：443 由 nginx stream 独占，
# 按 SNI 分流——真站域名(白名单) → REALITY_WEB_INNER_PORT；default(借用SNI/未知/无SNI)
# → REALITY_COEXIST_INNER_PORT(sing-box reality 入站)。所有后端仅绑 127.0.0.1，外部不可见。
# reality 内部端口选 18443，明确避开 CDN 回源用的 8443（CF 橙云支持端口，不可改）。
REALITY_COEXIST_STATE_FILE="${REALITY_CONFIG_DIR}/coexist.conf"
REALITY_COEXIST_INNER_PORT="${REALITY_COEXIST_INNER_PORT:-18443}"
REALITY_WEB_INNER_PORT="${REALITY_WEB_INNER_PORT:-12443}"
REALITY_STREAM_ENABLED_DIR="/etc/nginx/stream-enabled"
REALITY_STREAM_CONF="${REALITY_STREAM_ENABLED_DIR}/reality-coexist.conf"
REALITY_SINGBOX_CONFIG="/etc/sing-box/config.json"
REALITY_REALM_CONFIG="/etc/realm/config.toml"
REALITY_PORT_MIN=20000
REALITY_PORT_MAX=60000
fix_terminal() {
    [[ -t 0 ]] || return 0
    stty erase '^?' intr '^C' susp '^Z' icanon echo 2>/dev/null || true
    export TERM="${TERM:-xterm-256color}"
}
fix_terminal

draw_line() {
    printf "%$(tput cols 2>/dev/null || echo 80)s\n" | tr " " "-"
}

print_title() {
    clear || true
    local title=" $1 "
    local width=$(tput cols 2>/dev/null || echo 80)
    local padding=$(( (width - ${#title}) / 2 ))
    [[ $padding -lt 0 ]] && padding=0
    echo -e "${C_CYAN}"
    printf "%${width}s\n" | tr " " "="
    printf "%${padding}s%s\n" "" "$title"
    printf "%${width}s\n" | tr " " "="
    echo -e "${C_RESET}"
}

print_info() { echo -e "${C_BLUE}[i]${C_RESET} $1"; }
print_guide() { echo -e "${C_GREEN}>>${C_RESET} $1"; }
print_success() { echo -e "${C_GREEN}[✓]${C_RESET} $1"; }
print_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1" >&2; }
print_error() { echo -e "${C_RED}[✗]${C_RESET} $1" >&2; }
log_action() {
    local log_dir
    log_dir=$(dirname "$LOG_FILE")
    [[ -d "$log_dir" ]] || mkdir -p "$log_dir" 2>/dev/null || return 0
    # 日志轮转: 超过 5MB 自动归档
    if [[ -f "$LOG_FILE" ]]; then
        local log_size
        log_size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ "$log_size" -gt 5242880 ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.1"
            : > "$LOG_FILE"
            chmod 600 "$LOG_FILE"
        fi
    fi
    if command_exists jq; then
        jq -n --arg t "$(date '+%Y-%m-%d %H:%M:%S')" \
              --arg l "${2:-INFO}" \
              --arg m "$1" \
              '{time:$t,level:$l,msg:$m}' >> "$LOG_FILE" 2>/dev/null || true
    else
        # 安全转义：先处理反斜杠，再处理双引号
        local msg="$1"
        msg="${msg//\\/\\\\}"
        msg="${msg//\"/\\\"}"
        echo "{\"time\":\"$(date '+%Y-%m-%d %H:%M:%S')\",\"level\":\"${2:-INFO}\",\"msg\":\"$msg\"}" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

pause() {
    [[ -t 0 ]] || return 0
    echo ""
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

SERVER_MANAGE_TMPFILES=()

_tmp_register() {
    local tmpfile="${1:-}"
    [[ -n "$tmpfile" ]] || return 0
    SERVER_MANAGE_TMPFILES+=("$tmpfile")
}

_tmp_unregister() {
    local remove="${1:-}" tmpfile
    local kept=()
    [[ -n "$remove" ]] || return 0
    for tmpfile in "${SERVER_MANAGE_TMPFILES[@]}"; do
        [[ "$tmpfile" == "$remove" ]] || kept+=("$tmpfile")
    done
    SERVER_MANAGE_TMPFILES=("${kept[@]}")
}

_cleanup_tmpfiles() {
    local tmpfile
    for tmpfile in "${SERVER_MANAGE_TMPFILES[@]}"; do
        # 仅清理本脚本登记过、且文件名符合本脚本临时文件模式的路径。
        case "$tmpfile" in
            */.tmp.server-manage.*|*/.bak.server-manage.*|/etc/resolv.conf.tmp.*)
                rm -f -- "$tmpfile" 2>/dev/null || true
                ;;
        esac
    done
    SERVER_MANAGE_TMPFILES=()
    # 兼容旧版本可能残留在 /etc 下的同名前缀临时文件。
    rm -f /etc/.tmp.server-manage.* 2>/dev/null || true
}

write_file_atomic() {
    local filepath="$1" content="$2" tmpfile dir
    dir="$(dirname "$filepath")"
    mkdir -p "$dir" || return 1
    tmpfile=$(mktemp "${dir}/.tmp.server-manage.XXXXXX") || return 1
    _tmp_register "$tmpfile"
    if ! printf "%s\n" "$content" > "$tmpfile"; then
        rm -f -- "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    if [[ -f "$filepath" ]]; then
        chmod --reference="$filepath" "$tmpfile" 2>/dev/null || true
        chown --reference="$filepath" "$tmpfile" 2>/dev/null || true
    fi
    if ! mv "$tmpfile" "$filepath"; then
        rm -f -- "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    _tmp_unregister "$tmpfile"
    return 0
}

write_private_file_atomic() {
    local filepath="$1" content="$2" tmpfile dir old_umask rc
    dir="$(dirname "$filepath")"
    mkdir -p "$dir" || return 1
    old_umask=$(umask)
    umask 077
    tmpfile=$(mktemp "${dir}/.tmp.server-manage.private.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ $rc -eq 0 ]] || return 1
    _tmp_register "$tmpfile"
    if ! printf "%s\n" "$content" > "$tmpfile"; then
        rm -f -- "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    chmod 600 "$tmpfile" 2>/dev/null || true
    chown root:root "$tmpfile" 2>/dev/null || true
    if ! mv "$tmpfile" "$filepath"; then
        rm -f -- "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    _tmp_unregister "$tmpfile"
    return 0
}

copy_cert_pair_atomic() {
    local src_fullchain="$1" src_privkey="$2" dest_dir="$3"
    local dest_full dest_key full_tmp key_tmp old_umask rc bak_full="" bak_key=""
    _copy_cert_pair_restore_local() {
        local _dest_full="$1" _dest_key="$2" _bak_full="${3:-}" _bak_key="${4:-}" _full_tmp="${5:-}" _key_tmp="${6:-}"
        rm -f -- "$_dest_full" "$_dest_key" "$_full_tmp" "$_key_tmp" 2>/dev/null || true
        [[ -n "$_bak_full" && -f "$_bak_full" ]] && mv "$_bak_full" "$_dest_full" 2>/dev/null || true
        [[ -n "$_bak_key" && -f "$_bak_key" ]] && mv "$_bak_key" "$_dest_key" 2>/dev/null || true
    }
    [[ -f "$src_fullchain" && -f "$src_privkey" && -n "$dest_dir" ]] || return 1
    mkdir -p "$dest_dir" || return 1
    dest_full="${dest_dir}/fullchain.pem"
    dest_key="${dest_dir}/privkey.pem"
    old_umask=$(umask)
    umask 077
    full_tmp=$(mktemp "${dest_dir}/.tmp.server-manage.fullchain.XXXXXX")
    rc=$?
    if [[ "$rc" -eq 0 ]]; then
        key_tmp=$(mktemp "${dest_dir}/.tmp.server-manage.privkey.XXXXXX")
        rc=$?
    fi
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || { rm -f -- "${full_tmp:-}" "${key_tmp:-}" 2>/dev/null || true; return 1; }
    declare -F _tmp_register >/dev/null 2>&1 && _tmp_register "$full_tmp"
    declare -F _tmp_register >/dev/null 2>&1 && _tmp_register "$key_tmp"
    if ! cp -L "$src_fullchain" "$full_tmp" || ! cp -L "$src_privkey" "$key_tmp"; then
        rm -f -- "$full_tmp" "$key_tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
        return 1
    fi
    chmod 644 "$full_tmp" 2>/dev/null || true
    chmod 600 "$key_tmp" 2>/dev/null || true
    chown root:root "$full_tmp" "$key_tmp" 2>/dev/null || true
    if [[ -e "$dest_full" ]]; then
        bak_full=$(mktemp "${dest_dir}/.bak.server-manage.fullchain.XXXXXX") || {
            rm -f -- "$full_tmp" "$key_tmp" 2>/dev/null || true
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
            return 1
        }
        rm -f -- "$bak_full"
        mv "$dest_full" "$bak_full" || {
            rm -f -- "$full_tmp" "$key_tmp" "$bak_full" 2>/dev/null || true
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
            return 1
        }
    fi
    if [[ -e "$dest_key" ]]; then
        bak_key=$(mktemp "${dest_dir}/.bak.server-manage.privkey.XXXXXX") || {
            _copy_cert_pair_restore_local "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
            return 1
        }
        rm -f -- "$bak_key"
        mv "$dest_key" "$bak_key" || {
            _copy_cert_pair_restore_local "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
            declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
            return 1
        }
    fi
    if ! mv "$full_tmp" "$dest_full"; then
        _copy_cert_pair_restore_local "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
        return 1
    fi
    declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$full_tmp"
    if ! mv "$key_tmp" "$dest_key"; then
        _copy_cert_pair_restore_local "$dest_full" "$dest_key" "$bak_full" "$bak_key" "" "$key_tmp"
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
        return 1
    fi
    declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$key_tmp"
    rm -f -- "$bak_full" "$bak_key" 2>/dev/null || true
    return 0
}

render_cert_pair_hook_helper() {
    cat <<'HOOK_CERT_PAIR_HELPER'
copy_cert_pair_restore() {
    local dest_full="$1" dest_key="$2" bak_full="${3:-}" bak_key="${4:-}" full_tmp="${5:-}" key_tmp="${6:-}"
    rm -f -- "$dest_full" "$dest_key" "$full_tmp" "$key_tmp" 2>/dev/null || true
    [[ -n "$bak_full" && -f "$bak_full" ]] && mv "$bak_full" "$dest_full" 2>/dev/null || true
    [[ -n "$bak_key" && -f "$bak_key" ]] && mv "$bak_key" "$dest_key" 2>/dev/null || true
}

copy_cert_pair_atomic() {
    local src_fullchain="$1" src_privkey="$2" dest_dir="$3"
    local dest_full dest_key full_tmp key_tmp old_umask rc bak_full="" bak_key=""
    [[ -f "$src_fullchain" && -f "$src_privkey" && -n "$dest_dir" ]] || return 1
    mkdir -p "$dest_dir" || return 1
    dest_full="${dest_dir}/fullchain.pem"
    dest_key="${dest_dir}/privkey.pem"
    old_umask=$(umask)
    umask 077
    full_tmp=$(mktemp "${dest_dir}/.tmp.server-manage.fullchain.XXXXXX")
    rc=$?
    if [[ "$rc" -eq 0 ]]; then
        key_tmp=$(mktemp "${dest_dir}/.tmp.server-manage.privkey.XXXXXX")
        rc=$?
    fi
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || { rm -f -- "${full_tmp:-}" "${key_tmp:-}" 2>/dev/null || true; return 1; }
    if ! cp -L "$src_fullchain" "$full_tmp" || ! cp -L "$src_privkey" "$key_tmp"; then
        rm -f -- "$full_tmp" "$key_tmp" 2>/dev/null || true
        return 1
    fi
    chmod 644 "$full_tmp" 2>/dev/null || true
    chmod 600 "$key_tmp" 2>/dev/null || true
    chown root:root "$full_tmp" "$key_tmp" 2>/dev/null || true
    if [[ -e "$dest_full" ]]; then
        bak_full=$(mktemp "${dest_dir}/.bak.server-manage.fullchain.XXXXXX") || {
            rm -f -- "$full_tmp" "$key_tmp" 2>/dev/null || true
            return 1
        }
        rm -f -- "$bak_full"
        mv "$dest_full" "$bak_full" || {
            rm -f -- "$full_tmp" "$key_tmp" "$bak_full" 2>/dev/null || true
            return 1
        }
    fi
    if [[ -e "$dest_key" ]]; then
        bak_key=$(mktemp "${dest_dir}/.bak.server-manage.privkey.XXXXXX") || {
            copy_cert_pair_restore "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
            return 1
        }
        rm -f -- "$bak_key"
        mv "$dest_key" "$bak_key" || {
            copy_cert_pair_restore "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
            return 1
        }
    fi
    if ! mv "$full_tmp" "$dest_full"; then
        copy_cert_pair_restore "$dest_full" "$dest_key" "$bak_full" "$bak_key" "$full_tmp" "$key_tmp"
        return 1
    fi
    if ! mv "$key_tmp" "$dest_key"; then
        copy_cert_pair_restore "$dest_full" "$dest_key" "$bak_full" "$bak_key" "" "$key_tmp"
        return 1
    fi
    rm -f -- "$bak_full" "$bak_key" 2>/dev/null || true
    return 0
}
HOOK_CERT_PAIR_HELPER
}

handle_interrupt() {
    _cleanup_tmpfiles
    echo ""
    print_warn "操作已取消 (用户中断)。"
    exit 130
}

trap 'handle_interrupt' SIGINT SIGTERM

check_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        print_error "请使用 root 权限运行 (sudo)。"
        exit 2
    fi
}

check_os() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "检测到 OpenWrt 系统，将以精简模式运行。"
        print_info "可用功能: 系统信息 / Web服务(DNS+DDNS+证书) / BBR / 主机名 / 时区 / 日志"
        print_info "不可用: UFW / Fail2ban / Docker / Swap / iPerf3 / SSH完整管理 / apt依赖安装"
        sleep 2
        return 0
    fi
    if [[ ! -f /etc/os-release ]]; then
        print_error "不支持的操作系统。"
        exit 1
    fi
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ "$os_id" != "ubuntu" && "$os_id" != "debian" ]]; then
        print_warn "脚本主要针对 Ubuntu/Debian 优化，其他系统可能存在兼容性问题。"
        if ! confirm "是否继续？"; then
            exit 0
        fi
    fi
}

command_exists() { 
    command -v "$1" >/dev/null 2>&1
}

# 通用前置检查：要求某命令存在，否则报错并返回
_require_cmd() {
    local cmd="$1" name="${2:-$1}"
    if ! command_exists "$cmd"; then
        print_error "${name} 未安装。"
        pause; return 1
    fi
    return 0
}

# 统一重启 sshd 的工具函数（兼容 sshd/ssh 两种服务名）
_restart_sshd() {
    if is_systemd; then
        # Ubuntu 22.10+ 可能由 ssh.socket/sshd.socket 做 socket activation，重启服务本身不会改监听端口。
        local socket_unit
        if socket_unit=$(_ssh_socket_unit); then
            systemctl restart "$socket_unit" 2>/dev/null || return 1
            systemctl try-restart sshd 2>/dev/null || systemctl try-restart ssh 2>/dev/null || true
            return 0
        fi
        systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
        return $?
    fi
    return 1
}

is_systemd() {
    command_exists systemctl || return 1
    [[ -d /run/systemd/system ]] || return 1
    [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]] || return 1
    return 0
}

_ssh_socket_unit() {
    is_systemd || return 1
    local unit
    # 只认 is-active：真正在做 socket activation 的系统，其 ssh.socket 必然 active。
    # 绝不能用 is-enabled —— 大量 Debian/Ubuntu 镜像上 ssh.socket 是 enabled-but-inactive，
    # 实际监听 22 的是传统 ssh.service。误判为 socket activation 会写 socket drop-in 改端口，
    # 与 ssh.service 冲突，导致改回原端口也连不上、只能重装系统（已发生生产事故）。
    for unit in ssh.socket sshd.socket; do
        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            # 二次确认：该 socket 确实在监听 SSH（有 ListenStream），排除空壳 active。
            if systemctl show "$unit" -p Listen 2>/dev/null | grep -q 'Stream'; then
                echo "$unit"
                return 0
            fi
        fi
    done
    return 1
}

_ssh_socket_activation_active() {
    _ssh_socket_unit >/dev/null
}

_ssh_port_is_listening() {
    local port="$1"
    validate_port "$port" || return 1
    if command_exists ss; then
        ss -H -tlpn 2>/dev/null | awk -v p="$port" '
            { addr=$4; if (addr ~ (":" p "$")) found=1 }
            END { exit found ? 0 : 1 }
        '
        return $?
    fi
    if command_exists netstat; then
        netstat -tlpn 2>/dev/null | awk -v p="$port" '
            NR > 2 { addr=$4; if (addr ~ (":" p "$")) found=1 }
            END { exit found ? 0 : 1 }
        '
        return $?
    fi
    return 1
}

_sshd_effective_value() {
    local key="${1,,}"
    command_exists sshd || return 1
    sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k {print tolower($2); exit}'
}

_ssh_authorized_keys_file_has_key() {
    local file="$1"
    [[ -f "$file" && -s "$file" ]] || return 1
    grep -Eq '^[[:space:]]*(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256))[[:space:]]+[A-Za-z0-9+/=]+' "$file" 2>/dev/null
}

_ssh_authorized_keys_available() {
    local root_home="${SSH_ROOT_HOME:-/root}"
    local passwd_file="${SSH_PASSWD_FILE:-/etc/passwd}"
    _ssh_authorized_keys_file_has_key "${root_home}/.ssh/authorized_keys" && return 0
    [[ -f "$passwd_file" ]] || return 1
    local user _x uid gid gecos home shell
    while IFS=: read -r user _x uid gid gecos home shell; do
        [[ -z "$user" || "$user" == "root" ]] && continue
        [[ -z "$home" || "$shell" =~ (nologin|false)$ ]] && continue
        _ssh_authorized_keys_file_has_key "${home}/.ssh/authorized_keys" && return 0
    done < "$passwd_file"
    return 1
}

_ssh_authorized_keys_append() {
    local ak="$1" key="$2" owner="${3:-}" dir tmp old_umask rc last_byte
    [[ -n "$ak" && -n "$key" ]] || return 1
    dir="$(dirname "$ak")"
    mkdir -p "$dir" || return 1
    if [[ -f "$ak" ]] && grep -Fxq -- "$key" "$ak" 2>/dev/null; then
        return 0
    fi
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/.tmp.server-manage.authorized-keys.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    _tmp_register "$tmp"
    if [[ -f "$ak" ]]; then
        cat "$ak" > "$tmp" || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
        if [[ -s "$tmp" ]]; then
            last_byte=$(tail -c 1 "$tmp" 2>/dev/null | od -An -tx1 | tr -d ' \n')
            if [[ "$last_byte" != "0a" ]]; then
                printf '\n' >> "$tmp" || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
            fi
        fi
    fi
    printf '%s\n' "$key" >> "$tmp" || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true
    [[ -n "$owner" ]] && chown "$owner" "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$ak"; then
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi
    _tmp_unregister "$tmp"
    chmod 600 "$ak" 2>/dev/null || true
    [[ -n "$owner" ]] && chown "$owner" "$ak" 2>/dev/null || true
    return 0
}

_ssh_authorized_keys_remove() {
    local ak="$1" key="$2" owner="${3:-}" dir tmp old_umask rc grep_rc
    [[ -n "$ak" && -n "$key" && -f "$ak" ]] || return 1
    dir="$(dirname "$ak")"
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/.tmp.server-manage.authorized-keys.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    _tmp_register "$tmp"
    grep -Fvx -- "$key" "$ak" > "$tmp"
    grep_rc=$?
    if [[ $grep_rc -gt 1 ]]; then
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    [[ -n "$owner" ]] && chown "$owner" "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$ak"; then
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi
    _tmp_unregister "$tmp"
    chmod 600 "$ak" 2>/dev/null || true
    [[ -n "$owner" ]] && chown "$owner" "$ak" 2>/dev/null || true
    return 0
}

_ssh_non_root_sudo_available() {
    local passwd_file="${SSH_PASSWD_FILE:-/etc/passwd}"
    local group_file="${SSH_GROUP_FILE:-/etc/group}"
    [[ -f "$passwd_file" && -f "$group_file" ]] || return 1
    local sudo_users=" " sudo_gids=" " group _x gid members member
    while IFS=: read -r group _x gid members; do
        case "$group" in
            sudo|wheel)
                sudo_gids+="${gid} "
                IFS=',' read -ra _sudo_member_arr <<< "$members"
                for member in "${_sudo_member_arr[@]}"; do
                    [[ -n "$member" ]] && sudo_users+="${member} "
                done
                ;;
        esac
    done < "$group_file"
    local user uid gecos home shell
    while IFS=: read -r user _x uid gid gecos home shell; do
        [[ -z "$user" || "$user" == "root" ]] && continue
        [[ -z "$shell" || "$shell" =~ (nologin|false)$ ]] && continue
        if [[ "$sudo_users" == *" ${user} "* || "$sudo_gids" == *" ${gid} "* ]]; then
            return 0
        fi
    done < "$passwd_file"
    return 1
}

ufw_is_active() {
    command_exists ufw || return 1
    LANG=C ufw status 2>/dev/null | grep -qi 'Status: active'
}

# 统一设置 sshd_config 的某个 directive：命中则替换，未命中则插入到首个 Match 块之前
# 用法: _sshd_set_directive <Key> <Value> [file] [skip_dropin_check]
_sshd_set_directive() {
    local key="$1" value="$2" file="${3:-$SSHD_CONFIG}" skip_dropin_check="${4:-0}"
    [[ -f "$file" ]] || return 1
    # 检查 drop-in 是否已配置同名 directive（OpenSSH 默认 drop-in 优先生效）
    if [[ "$skip_dropin_check" != "1" && -d /etc/ssh/sshd_config.d ]]; then
        local overrides
        overrides=$(grep -lE "^[[:space:]]*${key}[[:space:]]+" /etc/ssh/sshd_config.d/*.conf 2>/dev/null || true)
        if [[ -n "$overrides" ]]; then
            print_warn "${key} 已在 drop-in 中配置（OpenSSH 优先生效）："
            echo "$overrides" | sed 's/^/  - /'
            confirm "继续修改 ${file}（drop-in 可能覆盖此设置）?" || return 1
        fi
    fi

    local tmpfile
    tmpfile=$(mktemp "$(dirname "$file")/.tmp.server-manage.sshd-directive.XXXXXX") || return 1
    _tmp_register "$tmpfile"
    awk -v key="$key" -v value="$value" '
        BEGIN { done=0; inserted=0; key_l=tolower(key) }
        /^[[:space:]]*Match([[:space:]]|$)/ {
            if (!done && !inserted) {
                print key " " value
                done=1
                inserted=1
            }
            print
            in_match=1
            next
        }
        !in_match && tolower($0) ~ "^[[:space:]]*#?[[:space:]]*" key_l "[[:space:]]+" {
            if (!done) {
                print key " " value
                done=1
            }
            next
        }
        { print }
        END {
            if (!done) {
                print ""
                print "# server-manage: appended " key
                print key " " value
            }
        }
    ' "$file" > "$tmpfile" || { rm -f "$tmpfile"; _tmp_unregister "$tmpfile"; return 1; }
    chmod --reference="$file" "$tmpfile" 2>/dev/null || true
    chown --reference="$file" "$tmpfile" 2>/dev/null || true
    if ! mv "$tmpfile" "$file"; then
        rm -f "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    _tmp_unregister "$tmpfile"
}

refresh_ssh_port() {
    local p="" ports=() seen=" "
    # 优先用 sshd -T 解析有效配置（覆盖 /etc/ssh/sshd_config + sshd_config.d/*.conf 全部 drop-in）
    if command_exists sshd; then
        while IFS= read -r p; do
            if validate_port "$p" && [[ "$seen" != *" $p "* ]]; then
                ports+=("$p")
                seen+="$p "
            fi
        done < <(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2}')
    fi
    # 回退：grep 主配 + drop-in（按字母序，后者优先）
    if [[ ${#ports[@]} -eq 0 ]]; then
        local files=("$SSHD_CONFIG") f
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            while IFS= read -r f; do
                files+=("$f")
            done < <(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sort)
        fi
        for f in "${files[@]}"; do
            [[ -f "$f" ]] || continue
            local cand
            while IFS= read -r cand; do
                if validate_port "$cand" && [[ "$seen" != *" $cand "* ]]; then
                    ports+=("$cand")
                    seen+="$cand "
                fi
            done < <(grep -iE "^\s*Port\s+" "$f" 2>/dev/null | awk '{print $2}')
        done
    fi
    if [[ ${#ports[@]} -gt 0 ]]; then
        CURRENT_SSH_PORT="${ports[0]}"
        CURRENT_SSH_PORTS="${ports[*]}"
    else
        CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
        CURRENT_SSH_PORTS=$DEFAULT_SSH_PORT
    fi
}

confirm() {
    local prompt="$1"
    local reply
    if [[ ! -t 0 ]]; then
        print_warn "非交互终端无法确认: ${prompt}"
        return 1
    fi
    while true; do
        read -e -r -p "$(echo -e "${C_YELLOW}${prompt} [Y/n]:${C_RESET} ")" reply
        case "${reply,,}" in
            y|yes|"") return 0 ;;
            n|no) return 1 ;;
            *) print_warn "请输入 y 或 n" ;;
        esac
    done
}

validate_port() {
    local port=$1
    [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_dns_label() {
    local label="${1:-}"
    [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

validate_host() {
    local host="${1:-}"
    [[ -n "$host" && ${#host} -le 253 ]] || return 1
    validate_ip "$host" && return 0
    [[ "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$ ]]
}

validate_ip() {
    local ip=$1
    # IPv4 验证
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a octets
        read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            [[ "$octet" =~ ^[0-9]+$ ]] || return 1
            [ "$octet" -le 255 ] || return 1
        done
        return 0
    fi
    # IPv6 验证：必须包含冒号，仅允许十六进制和冒号，长度合理；最多允许一个 :: 压缩段
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]; then
        [[ ${#ip} -le 39 ]] || return 1
        [[ ! "$ip" == *:::* ]] || return 1
        local double_colon_count
        double_colon_count=$(grep -o '::' <<< "$ip" | wc -l | tr -d ' ')
        [[ "$double_colon_count" -le 1 ]] || return 1
        IFS=':' read -ra _ipv6_parts <<< "$ip"
        local part nonempty=0
        for part in "${_ipv6_parts[@]}"; do
            [[ -z "$part" ]] && continue
            [[ ${#part} -le 4 ]] || return 1
            ((nonempty++)) || true
        done
        if [[ "$double_colon_count" -eq 1 ]]; then
            [[ "$nonempty" -le 7 ]] || return 1
        else
            [[ "$nonempty" -eq 8 ]] || return 1
        fi
        return 0
    fi
    return 1
}

validate_cidr() {
    local cidr="${1:-}" ip prefix
    [[ "$cidr" == */* ]] || return 1
    ip="${cidr%/*}"
    prefix="${cidr##*/}"
    [[ -n "$ip" && "$prefix" =~ ^[0-9]+$ ]] || return 1
    validate_ip "$ip" || return 1
    if [[ "$ip" == *:* ]]; then
        (( prefix >= 0 && prefix <= 128 ))
    else
        (( prefix >= 0 && prefix <= 32 ))
    fi
}

nft_addr_family_for_cidr() {
    case "${1:-}" in
        *:*) printf 'ip6' ;;
        *)   printf 'ip' ;;
    esac
}

validate_cidr_list() {
    local list="${1:-}" item
    [[ -n "$list" && "$list" != "null" ]] || return 0
    local IFS=','
    local -a _cidr_items
    read -ra _cidr_items <<< "$list"
    for item in "${_cidr_items[@]}"; do
        item=$(echo "$item" | xargs)
        [[ -n "$item" ]] || return 1
        validate_cidr "$item" || return 1
    done
    return 0
}

validate_wg_allowed_ips() {
    local list="${1:-}" item
    [[ -n "$list" && "$list" != "null" ]] || return 1
    local IFS=','
    local -a _allowed_items
    read -ra _allowed_items <<< "$list"
    for item in "${_allowed_items[@]}"; do
        item=$(echo "$item" | xargs)
        [[ -n "$item" ]] || return 1
        if [[ "$item" == */* ]]; then
            validate_cidr "$item" || return 1
        else
            validate_ip "$item" || return 1
        fi
    done
    return 0
}

validate_wg_key() {
    local key="${1:-}"
    [[ "$key" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

validate_domain() {
    local domain=$1
    # 域名至少需要包含一个点号
    [[ "$domain" == *"."* ]] || return 1
    [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]
}

validate_conf_file() {
    local conf="$1"
    [[ -f "$conf" ]] || return 1

    # ── 文件权限 / owner 检查 ──
    # 必须由 root 拥有，且 group/other 不可写，否则任何低权限进程都能写入再触发 source 注入
    if [[ "$PLATFORM" != "openwrt" ]] && command_exists stat; then
        local fown fmode
        fown=$(stat -c '%U' "$conf" 2>/dev/null || echo "")
        fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
        if [[ -n "$fown" && "$fown" != "root" ]]; then
            print_error "配置文件 owner 非 root，已拒绝: $conf (owner=$fown)"
            log_action "Rejected config (owner=$fown): $conf" "WARN" 2>/dev/null || true
            return 1
        fi
        if [[ -n "$fmode" && "$fmode" =~ ^[0-7]+$ ]]; then
            if (( 8#${fmode} & 022 )); then
                print_error "配置文件权限过宽，已拒绝: $conf (mode=$fmode，需 group/other 不可写)"
                log_action "Rejected config (mode=$fmode): $conf" "WARN" 2>/dev/null || true
                return 1
            fi
        fi
    fi

    # ── 行级语法 / value 安全性校验 ──
    # 仅接受以下三种合法 value 形式，源自最小信任原则：
    #   1) 单引号包裹（最安全：bash 不做任何扩展）
    #   2) 双引号包裹，且不含未转义的 $( / ${ / `  （这三个会触发命令替换/变量扩展）
    #   3) 裸字面量，字符集限定 [A-Za-z0-9_./@:+-]
    local lineno=0 reason=""
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((lineno++)) || true
        line="${line%$'\r'}"
        # 跳过空白行 / 注释
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue

        # 必须形如 KEY=...
        if [[ ! "$line" =~ ^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*= ]]; then
            reason="行${lineno}: 非 KEY=value 形式"
            break
        fi

        local value="${line#*=}"
        [[ -z "$value" ]] && continue

        # 形式 1：单引号
        if [[ "$value" =~ ^\'[^\']*\'$ ]]; then
            continue
        fi

        # 形式 2：双引号
        if [[ "$value" =~ ^\".*\"$ ]]; then
            # 先消除所有已转义的元字符，再判断剩余串是否仍含命令替换/变量扩展
            local stripped="${value//\\\\/}"
            stripped="${stripped//\\\$/}"
            stripped="${stripped//\\\`/}"
            stripped="${stripped//\\\"/}"
            if [[ "$stripped" == *'$('* || "$stripped" == *'${'* || "$stripped" == *'`'* ]]; then
                reason="行${lineno}: value 含命令替换/变量扩展（不安全）"
                break
            fi
            continue
        fi

        # 形式 3：裸字面量
        if [[ "$value" =~ ^[A-Za-z0-9_./@:+-]+$ ]]; then
            continue
        fi

        reason="行${lineno}: value 非合法字面量（需用单/双引号包裹）"
        break
    done < "$conf"

    if [[ -n "$reason" ]]; then
        print_error "配置文件格式异常，已跳过: $conf ($reason)"
        log_action "Rejected config file: $conf reason=$reason" "WARN" 2>/dev/null || true
        return 1
    fi
    return 0
}

cron_remove_job() {
    local pattern="$1"
    local cron_tmp
    cron_tmp=$(_cron_tmp_create) || return 1
    crontab -l 2>/dev/null | grep -Fv -- "$pattern" > "$cron_tmp" || true
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        _cron_tmp_cleanup "$cron_tmp"
        return 1
    fi
    _cron_tmp_cleanup "$cron_tmp"
}

_cron_tmp_create() {
    local tmp_dir tmp_file old_umask rc
    old_umask=$(umask)
    umask 077
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME:-server-manage}-cron.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    tmp_file="$tmp_dir/crontab"
    : > "$tmp_file" || { rm -rf -- "$tmp_dir" 2>/dev/null || true; return 1; }
    chmod 600 "$tmp_file" 2>/dev/null || true
    printf '%s\n' "$tmp_file"
}

_cron_tmp_cleanup() {
    local cron_tmp="${1:-}" tmp_dir base
    [[ -n "$cron_tmp" ]] || return 0
    tmp_dir="$(dirname "$cron_tmp")"
    base="$(basename "$tmp_dir")"
    case "$base" in
        "${SCRIPT_NAME:-server-manage}-cron."*) rm -rf -- "$tmp_dir" 2>/dev/null || true ;;
        *) rm -f -- "$cron_tmp" 2>/dev/null || true ;;
    esac
}

cron_has_job_command() {
    local command_path="$1"
    crontab -l 2>/dev/null | awk -v cmd="$command_path" 'NF >= 6 && $6 == cmd { found=1 } END { exit(found ? 0 : 1) }'
}

cron_remove_job_command() {
    local command_path="$1"
    local cron_tmp
    cron_tmp=$(_cron_tmp_create) || return 1
    crontab -l 2>/dev/null | awk -v cmd="$command_path" '!(NF >= 6 && $6 == cmd)' > "$cron_tmp" || true
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        _cron_tmp_cleanup "$cron_tmp"
        return 1
    fi
    _cron_tmp_cleanup "$cron_tmp"
}

cron_add_job_command() {
    local command_path="$1" line="$2"
    local cron_tmp
    cron_tmp=$(_cron_tmp_create) || return 1
    crontab -l 2>/dev/null | awk -v cmd="$command_path" '!(NF >= 6 && $6 == cmd)' > "$cron_tmp" || true
    echo "$line" >> "$cron_tmp"
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        _cron_tmp_cleanup "$cron_tmp"
        return 1
    fi
    _cron_tmp_cleanup "$cron_tmp"
}

cron_add_job() {
    local pattern="$1" line="$2"
    local cron_tmp
    cron_tmp=$(_cron_tmp_create) || return 1
    crontab -l 2>/dev/null | grep -Fv -- "$pattern" > "$cron_tmp" || true
    echo "$line" >> "$cron_tmp"
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        _cron_tmp_cleanup "$cron_tmp"
        return 1
    fi
    _cron_tmp_cleanup "$cron_tmp"
}

init_environment() {
    mkdir -p "$CACHE_DIR" "$(dirname "$LOG_FILE")"
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE"
        chmod 600 "$LOG_FILE"
    fi
    refresh_ssh_port
        if [[ "$PLATFORM" == "openwrt" ]]; then
        for p in curl jq openssl-util ca-bundle; do
            if ! opkg list-installed 2>/dev/null | grep -q "^${p} "; then
                opkg update >/dev/null 2>&1
                opkg install "$p" >/dev/null 2>&1 || true
            fi
        done
    else
        auto_deps
    fi
    log_action "Script initialized (platform=$PLATFORM)" "INFO"
}

# ── 主配置安全加载 ──
# 必须放在 validate_conf_file 定义之后；任何校验失败仅警告并跳过 source，
# 不让格式异常或被篡改的配置文件触发 source 注入。
if [[ -f "$CONFIG_FILE" ]]; then
    if validate_conf_file "$CONFIG_FILE"; then
        source "$CONFIG_FILE"
    else
        print_warn "主配置已忽略，本次使用默认值: $CONFIG_FILE"
    fi
fi
_extract_ipv4_from_text() {
    local raw="$1" ip="" octet _o1 _o2 _o3 _o4 _extra
    [[ -z "$raw" ]] && return 1
    while IFS= read -r ip; do
        local valid=1
        IFS='.' read -r _o1 _o2 _o3 _o4 _extra <<< "$ip"
        [[ -z "${_extra:-}" ]] || continue
        for octet in "$_o1" "$_o2" "$_o3" "$_o4"; do
            [[ "$octet" =~ ^[0-9]+$ ]] && [ "$octet" -le 255 ] || { valid=0; break; }
        done
        [[ "$valid" -eq 1 ]] || continue
        echo "$ip"
        return 0
    done < <(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    return 1
}

_ipv4_is_public() {
    local ip="${1:-}" o1 o2 o3 o4 extra n1 n2 n3 n4 octet
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
    n1=$((10#$o1)); n2=$((10#$o2)); n3=$((10#$o3)); n4=$((10#$o4))

    (( n1 == 0 || n1 == 10 || n1 == 127 || n1 >= 224 )) && return 1
    (( n1 == 100 && n2 >= 64 && n2 <= 127 )) && return 1
    (( n1 == 169 && n2 == 254 )) && return 1
    (( n1 == 172 && n2 >= 16 && n2 <= 31 )) && return 1
    (( n1 == 192 && n2 == 168 )) && return 1
    (( n1 == 198 && (n2 == 18 || n2 == 19) )) && return 1
    (( n1 == 192 && n2 == 0 && (n3 == 0 || n3 == 2) )) && return 1
    (( n1 == 198 && n2 == 51 && n3 == 100 )) && return 1
    (( n1 == 203 && n2 == 0 && n3 == 113 )) && return 1
    (( n1 == 255 && n2 == 255 && n3 == 255 && n4 == 255 )) && return 1
    return 0
}

_get_ipv4_from_device() {
    local dev="${1:-}" ip
    [[ -n "$dev" ]] || return 1
    while IFS= read -r ip; do
        ip="${ip%%/*}"
        _ipv4_is_public "$ip" || continue
        echo "$ip"
        return 0
    done < <(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}')
    return 1
}

get_openwrt_public_ipv4() {
    local iface="${1:-wan}" device="${2:-}" ip dev candidates=""
    if command -v ifstatus >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -n "$ip" && "$ip" != "null" ]] || continue
            if _ipv4_is_public "$ip"; then
                echo "$ip"
                return 0
            fi
        done < <(ifstatus "$iface" 2>/dev/null | jq -r '."ipv4-address"[]?.address // empty' 2>/dev/null)
        candidates=$(ifstatus "$iface" 2>/dev/null | jq -r '.l3_device // empty, .device // empty' 2>/dev/null | awk 'NF && !seen[$0]++')
    fi

    [[ -n "$device" ]] && candidates=$(printf '%s\n%s\n' "$device" "$candidates" | awk 'NF && !seen[$0]++')
    if command -v uci >/dev/null 2>&1; then
        for dev in "$(uci -q get "network.${iface}.device" 2>/dev/null)" "$(uci -q get "network.${iface}.ifname" 2>/dev/null)"; do
            [[ -n "$dev" ]] && candidates=$(printf '%s\n%s\n' "$candidates" "$dev" | awk 'NF && !seen[$0]++')
        done
    fi

    while IFS= read -r dev; do
        [[ -n "$dev" ]] || continue
        if ip=$(_get_ipv4_from_device "$dev"); then
            echo "$ip"
            return 0
        fi
    done <<< "$candidates"
    return 1
}

# 统一公网 IP 获取函数：OpenWrt 优先读取 WAN 接口，失败后回退到国内可达的 API。
get_public_ipv4() {
    local source="${1:-auto}" iface="${2:-wan}" device="${3:-}" raw="" ip="" url=""
    case "$source" in
        auto|interface|api) ;;
        *) source="auto" ;;
    esac
    if [[ "$source" == "auto" || "$source" == "interface" ]]; then
        if ip=$(get_openwrt_public_ipv4 "$iface" "$device") && [[ -n "$ip" ]]; then
            echo "$ip"
            return 0
        fi
        [[ "$source" == "interface" ]] && return 1
    fi
    local endpoints=(
        "https://4.ipw.cn"
        "https://myip.ipip.net/ip"
        "https://ip.3322.net"
        "https://ifconfig.me/ip"
        "https://4.ident.me"
    )
    for url in "${endpoints[@]}"; do
        raw=$(curl -4 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
        ip=$(_extract_ipv4_from_text "$raw") || continue
        echo "$ip"
        return 0
    done
    return 1
}

get_public_ipv6() {
    local ip=""
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://6.ipw.cn 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://v6.ident.me 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://ifconfig.me 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    return 1
}

ddns_rebuild_cron() {
    cron_remove_job "ddns-update.sh"
    if [[ -d "$DDNS_CONFIG_DIR" ]] && ls "$DDNS_CONFIG_DIR"/*.conf &>/dev/null 2>&1; then
        # cron 的 */59 语义是每小时第 0/59 分钟触发（中间会出现 1 分钟间隔），
        # 因此统一每分钟唤醒，再由 ddns-update.sh 按每份配置的 DDNS_INTERVAL 节流。
        cron_add_job "ddns-update.sh" "* * * * * $DDNS_UPDATE_SCRIPT >/dev/null 2>&1"
        ddns_install_hotplug >/dev/null 2>&1 || true
    elif [[ "$PLATFORM" == "openwrt" ]]; then
        rm -f /etc/hotplug.d/iface/95-server-manage-ddns 2>/dev/null || true
    fi
}

ddns_install_hotplug() {
    [[ "$PLATFORM" == "openwrt" ]] || return 0
    local hotplug_file="/etc/hotplug.d/iface/95-server-manage-ddns"
    local content="#!/bin/sh
[ \"\${ACTION:-}\" = \"ifup\" ] || exit 0
[ -x \"$DDNS_UPDATE_SCRIPT\" ] || exit 0
case \"\${INTERFACE:-}\" in \"\"|loopback|lan) exit 0 ;; esac
match=0
for conf in \"$DDNS_CONFIG_DIR\"/*.conf; do
    [ -f \"\$conf\" ] || continue
    if grep -q \"^DDNS_INTERFACE=\\\"\${INTERFACE}\\\"\$\" \"\$conf\" 2>/dev/null; then
        match=1
        break
    fi
    if [ \"\${INTERFACE}\" = \"wan\" ] && ! grep -q '^DDNS_INTERFACE=' \"\$conf\" 2>/dev/null; then
        match=1
        break
    fi
done
[ \"\$match\" = \"1\" ] || exit 0
DDNS_FORCE=1 \"$DDNS_UPDATE_SCRIPT\" --force >/dev/null 2>&1 &
exit 0"
    write_private_file_atomic "$hotplug_file" "$content" || return 1
    chmod 0755 "$hotplug_file" 2>/dev/null || true
    return 0
}

ddns_create_script() {
    mkdir -p "$DDNS_CONFIG_DIR"
    chmod 700 "$DDNS_CONFIG_DIR" 2>/dev/null || true
    mkdir -p "$(dirname "$DDNS_UPDATE_SCRIPT")"
    local ddns_script_tmp
    ddns_script_tmp=$(mktemp "$(dirname "$DDNS_UPDATE_SCRIPT")/.tmp.server-manage.ddns-update.XXXXXX") || return 1
    _tmp_register "$ddns_script_tmp"
if ! cat > "$ddns_script_tmp" << 'EOF'
#!/bin/bash
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
DDNS_RUNTIME_DIR="/var/lib/server-manage/ddns"
DDNS_STAMP_DIR="$DDNS_RUNTIME_DIR/stamps"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$DDNS_LOG"; }
mkdir -p "$DDNS_RUNTIME_DIR" "$DDNS_STAMP_DIR" 2>/dev/null || {
    log "无法创建 DDNS 状态目录: $DDNS_RUNTIME_DIR"
    exit 1
}
chmod 700 /var/lib/server-manage "$DDNS_RUNTIME_DIR" "$DDNS_STAMP_DIR" 2>/dev/null || true
if command -v flock >/dev/null 2>&1; then
    exec 200>"$DDNS_RUNTIME_DIR/update.lock"
    flock -n 200 || exit 0
else
    mkdir "$DDNS_RUNTIME_DIR/update.lock.d" 2>/dev/null || exit 0
    trap 'rmdir "$DDNS_RUNTIME_DIR/update.lock.d" 2>/dev/null' EXIT
fi

extract_ipv4() {
    local raw="$1" ip="" octet _o1 _o2 _o3 _o4 _extra
    [[ -z "$raw" ]] && return 1
    while IFS= read -r ip; do
        local valid=1
        IFS='.' read -r _o1 _o2 _o3 _o4 _extra <<< "$ip"
        [[ -z "${_extra:-}" ]] || continue
        for octet in "$_o1" "$_o2" "$_o3" "$_o4"; do
            [[ "$octet" =~ ^[0-9]+$ ]] && [ "$octet" -le 255 ] || { valid=0; break; }
        done
        [[ "$valid" -eq 1 ]] || continue
        echo "$ip"
        return 0
    done < <(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    return 1
}

ipv4_is_public() {
    local ip="${1:-}" o1 o2 o3 o4 extra n1 n2 n3 n4 octet
    IFS='.' read -r o1 o2 o3 o4 extra <<< "$ip"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$o1" "$o2" "$o3" "$o4"; do
        [[ "$octet" =~ ^[0-9]+$ ]] || return 1
        (( 10#$octet <= 255 )) || return 1
    done
    n1=$((10#$o1)); n2=$((10#$o2)); n3=$((10#$o3)); n4=$((10#$o4))
    (( n1 == 0 || n1 == 10 || n1 == 127 || n1 >= 224 )) && return 1
    (( n1 == 100 && n2 >= 64 && n2 <= 127 )) && return 1
    (( n1 == 169 && n2 == 254 )) && return 1
    (( n1 == 172 && n2 >= 16 && n2 <= 31 )) && return 1
    (( n1 == 192 && n2 == 168 )) && return 1
    (( n1 == 198 && (n2 == 18 || n2 == 19) )) && return 1
    (( n1 == 192 && n2 == 0 && (n3 == 0 || n3 == 2) )) && return 1
    (( n1 == 198 && n2 == 51 && n3 == 100 )) && return 1
    (( n1 == 203 && n2 == 0 && n3 == 113 )) && return 1
    (( n1 == 255 && n2 == 255 && n3 == 255 && n4 == 255 )) && return 1
    return 0
}

get_ipv4_from_device() {
    local dev="${1:-}" ip
    [[ -n "$dev" ]] || return 1
    while IFS= read -r ip; do
        ip="${ip%%/*}"
        ipv4_is_public "$ip" || continue
        echo "$ip"
        return 0
    done < <(ip -4 -o addr show dev "$dev" scope global 2>/dev/null | awk '{print $4}')
    return 1
}

get_openwrt_public_ipv4() {
    local iface="${1:-wan}" device="${2:-}" ip dev candidates=""
    if command -v ifstatus >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
        while IFS= read -r ip; do
            [[ -n "$ip" && "$ip" != "null" ]] || continue
            if ipv4_is_public "$ip"; then
                echo "$ip"
                return 0
            fi
        done < <(ifstatus "$iface" 2>/dev/null | jq -r '."ipv4-address"[]?.address // empty' 2>/dev/null)
        candidates=$(ifstatus "$iface" 2>/dev/null | jq -r '.l3_device // empty, .device // empty' 2>/dev/null | awk 'NF && !seen[$0]++')
    fi
    [[ -n "$device" ]] && candidates=$(printf '%s\n%s\n' "$device" "$candidates" | awk 'NF && !seen[$0]++')
    if command -v uci >/dev/null 2>&1; then
        for dev in "$(uci -q get "network.${iface}.device" 2>/dev/null)" "$(uci -q get "network.${iface}.ifname" 2>/dev/null)"; do
            [[ -n "$dev" ]] && candidates=$(printf '%s\n%s\n' "$candidates" "$dev" | awk 'NF && !seen[$0]++')
        done
    fi
    while IFS= read -r dev; do
        [[ -n "$dev" ]] || continue
        if ip=$(get_ipv4_from_device "$dev"); then
            echo "$ip"
            return 0
        fi
    done <<< "$candidates"
    return 1
}

get_ip() {
    local family="${1:-4}" source="${2:-auto}" iface="${3:-wan}" device="${4:-}" raw="" ip="" url=""
    case "$source" in
        auto|interface|api) ;;
        *) source="auto" ;;
    esac
    if [[ "$family" == "4" ]]; then
        if [[ "$source" == "auto" || "$source" == "interface" ]]; then
            if ip=$(get_openwrt_public_ipv4 "$iface" "$device") && [[ -n "$ip" ]]; then
                echo "$ip"
                return 0
            fi
            [[ "$source" == "interface" ]] && return 1
        fi
        for url in \
            https://4.ipw.cn \
            https://myip.ipip.net/ip \
            https://ip.3322.net \
            https://ifconfig.me/ip \
            https://4.ident.me
        do
            raw=$(curl -4 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
            ip=$(extract_ipv4 "$raw") || continue
            echo "$ip"
            return 0
        done
        return 1
    else
        for url in \
            https://6.ipw.cn \
            https://v6.ident.me \
            https://ifconfig.me/ip
        do
            raw=$(curl -6 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
            [[ "$raw" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$raw" == *:* ]] && { echo "$raw"; return 0; }
        done
        return 1
    fi
}

update_cf() {
    local domain=$1 rt=$2 ip=$3 token=$4 zone=$5 proxied=${6:-false}
    [[ "$proxied" == "true" || "$proxied" == "false" ]] || proxied="false"
    local resp=$(curl -s --connect-timeout 10 --max-time 30 "https://api.cloudflare.com/client/v4/zones/$zone/dns_records?type=$rt&name=$domain" \
        -H "Authorization: Bearer $token" -H "Content-Type: application/json")
    if [[ "$(echo "$resp" | jq -r ".success // false" 2>/dev/null)" != "true" ]]; then
        log "[$domain] $rt lookup failed"
        return 1
    fi
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    local dns_ip=$(echo "$resp" | jq -r '.result[0].content // empty')
    [[ "$ip" == "$dns_ip" ]] && return 0
    
    local method="POST" url="https://api.cloudflare.com/client/v4/zones/$zone/dns_records"
    [[ -n "$rid" ]] && { method="PUT"; url="$url/$rid"; }
    
    resp=$(curl -s --connect-timeout 10 --max-time 30 -X "$method" "$url" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        --data "{\"type\":\"$rt\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
    [[ "$(echo "$resp" | jq -r '.success')" == "true" ]] && { log "[$domain] $rt: $dns_ip -> $ip"; return 0; }
    log "[$domain] $rt update failed"; return 1
}

# 安全解析 conf：不 source，避免恶意命令替换 / 变量扩展执行
# 仅接受白名单 KEY，value 必须是双引号包裹的简单字面量
parse_ddns_conf() {
    local conf="$1" line key val
    local fown fmode meta perm uid
    if command -v stat >/dev/null 2>&1 && fown=$(stat -c '%U' "$conf" 2>/dev/null); then
        fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
        if [[ "$fown" != "root" && "$fown" != "0" ]]; then
            log "owner 非 root，跳过: $conf (owner=$fown)"
            return 1
        fi
        if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
            log "权限过宽，跳过: $conf (mode=$fmode)"
            return 1
        fi
    else
        meta=$(ls -ldn "$conf" 2>/dev/null || echo "")
        perm=$(printf '%s\n' "$meta" | awk '{print $1}')
        uid=$(printf '%s\n' "$meta" | awk '{print $3}')
        if [[ "$uid" != "0" ]]; then
            log "owner 非 root，跳过: $conf (uid=$uid)"
            return 1
        fi
        if [[ "${perm:5:1}" == "w" || "${perm:8:1}" == "w" ]]; then
            log "权限过宽，跳过: $conf (perm=$perm)"
            return 1
        fi
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    DDNS_IP_SOURCE="" DDNS_INTERFACE="" DDNS_DEVICE=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL|DDNS_IP_SOURCE|DDNS_INTERFACE|DDNS_DEVICE)=\"([^\"\$\`\\]*)\"$ ]]; then
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            case "$key" in
                DDNS_DOMAIN)   DDNS_DOMAIN="$val" ;;
                DDNS_TOKEN)    DDNS_TOKEN="$val" ;;
                DDNS_ZONE_ID)  DDNS_ZONE_ID="$val" ;;
                DDNS_IPV4)     DDNS_IPV4="$val" ;;
                DDNS_IPV6)     DDNS_IPV6="$val" ;;
                DDNS_PROXIED)  DDNS_PROXIED="$val" ;;
                DDNS_INTERVAL) DDNS_INTERVAL="$val" ;;
                DDNS_IP_SOURCE) DDNS_IP_SOURCE="$val" ;;
                DDNS_INTERFACE) DDNS_INTERFACE="$val" ;;
                DDNS_DEVICE)   DDNS_DEVICE="$val" ;;
            esac
        else
            log "格式异常行，跳过: $conf"
            return 1
        fi
    done < "$conf"
    [[ -n "$DDNS_DOMAIN" && -n "$DDNS_TOKEN" && -n "$DDNS_ZONE_ID" ]] || {
        log "必填字段缺失，跳过: $conf"
        return 1
    }
    DDNS_IPV4=${DDNS_IPV4:-false}
    DDNS_IPV6=${DDNS_IPV6:-false}
    DDNS_PROXIED=${DDNS_PROXIED:-false}
    DDNS_IP_SOURCE=${DDNS_IP_SOURCE:-auto}
    DDNS_INTERFACE=${DDNS_INTERFACE:-wan}
    DDNS_DEVICE=${DDNS_DEVICE:-}
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    [[ "$DDNS_IP_SOURCE" == "auto" || "$DDNS_IP_SOURCE" == "interface" || "$DDNS_IP_SOURCE" == "api" ]] || DDNS_IP_SOURCE="auto"
    [[ "$DDNS_INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]] || DDNS_INTERFACE="wan"
    [[ -z "$DDNS_DEVICE" || "$DDNS_DEVICE" =~ ^[A-Za-z0-9_.:-]+$ ]] || DDNS_DEVICE=""
    return 0
}

ddns_should_run() {
    local conf="$1" interval="${DDNS_INTERVAL:-5}" now last="" stamp_name stamp
    [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 1 && "$interval" -le 59 ]] || interval=5
    stamp_name=$(basename "$conf" | sed 's/[^A-Za-z0-9_.-]/_/g')
    stamp="$DDNS_STAMP_DIR/${stamp_name}.stamp"
    now=$(date +%s)
    if [[ "${DDNS_FORCE:-0}" == "1" || "${DDNS_FORCE:-0}" == "true" ]]; then
        printf '%s\n' "$now" > "$stamp" 2>/dev/null || true
        return 0
    fi
    [[ -f "$stamp" ]] && read -r last < "$stamp" || true
    if [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < interval * 60 )); then
        return 1
    fi
    printf '%s\n' "$now" > "$stamp" 2>/dev/null || true
    return 0
}

failed=0
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    [[ "${1:-}" == "--force" ]] && DDNS_FORCE=1
    failed=0
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [ -f "$conf" ] || continue
        parse_ddns_conf "$conf" || continue
        ddns_should_run "$conf" || continue
        if [[ "$DDNS_IPV4" == "true" ]]; then
            if ip=$(get_ip 4 "$DDNS_IP_SOURCE" "$DDNS_INTERFACE" "$DDNS_DEVICE") && [[ -n "$ip" ]]; then
                update_cf "$DDNS_DOMAIN" A "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED" || failed=1
            else
                log "[$DDNS_DOMAIN] A 获取公网 IPv4 失败"
                failed=1
            fi
        fi
        if [[ "$DDNS_IPV6" == "true" ]]; then
            if ip=$(get_ip 6) && [[ -n "$ip" ]]; then
                update_cf "$DDNS_DOMAIN" AAAA "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED" || failed=1
            else
                log "[$DDNS_DOMAIN] AAAA 获取公网 IPv6 失败"
                failed=1
            fi
        fi
    done
    exit "$failed"
fi
EOF
    then
        rm -f -- "$ddns_script_tmp" 2>/dev/null || true
        _tmp_unregister "$ddns_script_tmp"
        return 1
    fi
    chmod 0755 "$ddns_script_tmp" 2>/dev/null || true
    if ! mv "$ddns_script_tmp" "$DDNS_UPDATE_SCRIPT"; then
        rm -f -- "$ddns_script_tmp" 2>/dev/null || true
        _tmp_unregister "$ddns_script_tmp"
        return 1
    fi
    _tmp_unregister "$ddns_script_tmp"
}

ddns_setup() {
    local domain=$1 token=$2 zone_id=$3 ipv4=$4 ipv6=$5 proxied=$6
    echo -e "${C_CYAN}[DDNS 动态解析配置]${C_RESET}"
    if ! confirm "是否启用 DDNS 自动更新 (IP 变化时自动更新 DNS)?"; then
        return 0
    fi
        read -e -r -p "检测间隔(分钟, 1-59) [5]: " interval
    interval=${interval:-5}
    if [[ ! "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 || "$interval" -gt 59 ]]; then
        print_warn "间隔必须为 1-59，使用默认值 5"
        interval=5
    fi
    mkdir -p "$DDNS_CONFIG_DIR"
    chmod 700 "$DDNS_CONFIG_DIR" 2>/dev/null || true
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\"
DDNS_IP_SOURCE=\"auto\"
DDNS_INTERFACE=\"wan\"
DDNS_DEVICE=\"\""
    write_private_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    ddns_create_script || { print_error "DDNS 更新脚本生成失败"; return 1; }
    ddns_rebuild_cron || { print_error "DDNS cron 更新失败"; return 1; }
    print_success "DDNS 已启用 (每 ${interval} 分钟检测)"
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

ddns_setup_noninteractive() {
    local domain=$1 token=$2 zone_id=$3 ipv4=${4:-true} ipv6=${5:-false} proxied=${6:-false} interval=${7:-5}
    local ip_source="${8:-auto}" iface="${9:-wan}" device="${10:-}"
    [[ -z "$domain" || -z "$token" || -z "$zone_id" ]] && return 1
    if [[ ! "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 || "$interval" -gt 59 ]]; then
        interval=5
    fi
    [[ "$ip_source" == "auto" || "$ip_source" == "interface" || "$ip_source" == "api" ]] || ip_source="auto"
    [[ "$iface" =~ ^[A-Za-z0-9_.:-]+$ ]] || iface="wan"
    [[ -z "$device" || "$device" =~ ^[A-Za-z0-9_.:-]+$ ]] || device=""
    mkdir -p "$DDNS_CONFIG_DIR"
    chmod 700 "$DDNS_CONFIG_DIR" 2>/dev/null || true
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\"
DDNS_IP_SOURCE=\"$ip_source\"
DDNS_INTERFACE=\"$iface\"
DDNS_DEVICE=\"$device\""
    write_private_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    ddns_create_script || { print_error "DDNS 更新脚本生成失败"; return 1; }
    ddns_rebuild_cron || { print_error "DDNS cron 更新失败"; return 1; }
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

# 顶层（交互菜单）安全解析 conf：与生成脚本 ddns-update.sh 内嵌的同名解析器逻辑一致，
# 但诊断走顶层的 log_action（heredoc 里的 log 仅存在于生成脚本中）。
# ddns_list / ddns_delete 复用本函数——与本文件 get_public_ipv4(顶层)/get_ip(生成脚本) 的双份模式一致。
parse_ddns_conf() {
    local conf="$1" line key val
    local fown fmode meta perm uid
    if command -v stat >/dev/null 2>&1 && fown=$(stat -c '%U' "$conf" 2>/dev/null); then
        fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
        if [[ "$fown" != "root" && "$fown" != "0" ]]; then
            log_action "DDNS 解析跳过：owner 非 root: $conf (owner=$fown)"
            return 1
        fi
        if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
            log_action "DDNS 解析跳过：权限过宽: $conf (mode=$fmode)"
            return 1
        fi
    else
        meta=$(ls -ldn "$conf" 2>/dev/null || echo "")
        perm=$(printf '%s\n' "$meta" | awk '{print $1}')
        uid=$(printf '%s\n' "$meta" | awk '{print $3}')
        if [[ "$uid" != "0" ]]; then
            log_action "DDNS 解析跳过：owner 非 root: $conf (uid=$uid)"
            return 1
        fi
        if [[ "${perm:5:1}" == "w" || "${perm:8:1}" == "w" ]]; then
            log_action "DDNS 解析跳过：权限过宽: $conf (perm=$perm)"
            return 1
        fi
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    DDNS_IP_SOURCE="" DDNS_INTERFACE="" DDNS_DEVICE=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL|DDNS_IP_SOURCE|DDNS_INTERFACE|DDNS_DEVICE)=\"([^\"\$\`\\]*)\"$ ]]; then
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            case "$key" in
                DDNS_DOMAIN)   DDNS_DOMAIN="$val" ;;
                DDNS_TOKEN)    DDNS_TOKEN="$val" ;;
                DDNS_ZONE_ID)  DDNS_ZONE_ID="$val" ;;
                DDNS_IPV4)     DDNS_IPV4="$val" ;;
                DDNS_IPV6)     DDNS_IPV6="$val" ;;
                DDNS_PROXIED)  DDNS_PROXIED="$val" ;;
                DDNS_INTERVAL) DDNS_INTERVAL="$val" ;;
                DDNS_IP_SOURCE) DDNS_IP_SOURCE="$val" ;;
                DDNS_INTERFACE) DDNS_INTERFACE="$val" ;;
                DDNS_DEVICE)   DDNS_DEVICE="$val" ;;
            esac
        else
            log_action "DDNS 解析跳过：格式异常行: $conf"
            return 1
        fi
    done < "$conf"
    [[ -n "$DDNS_DOMAIN" && -n "$DDNS_TOKEN" && -n "$DDNS_ZONE_ID" ]] || {
        log_action "DDNS 解析跳过：必填字段缺失: $conf"
        return 1
    }
    DDNS_IPV4=${DDNS_IPV4:-false}
    DDNS_IPV6=${DDNS_IPV6:-false}
    DDNS_PROXIED=${DDNS_PROXIED:-false}
    DDNS_IP_SOURCE=${DDNS_IP_SOURCE:-auto}
    DDNS_INTERFACE=${DDNS_INTERFACE:-wan}
    DDNS_DEVICE=${DDNS_DEVICE:-}
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    [[ "$DDNS_IP_SOURCE" == "auto" || "$DDNS_IP_SOURCE" == "interface" || "$DDNS_IP_SOURCE" == "api" ]] || DDNS_IP_SOURCE="auto"
    [[ "$DDNS_INTERFACE" =~ ^[A-Za-z0-9_.:-]+$ ]] || DDNS_INTERFACE="wan"
    [[ -z "$DDNS_DEVICE" || "$DDNS_DEVICE" =~ ^[A-Za-z0-9_.:-]+$ ]] || DDNS_DEVICE=""
    return 0
}

ddns_list() {
    print_title "DDNS 配置列表"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无 DDNS 配置"; pause; return; }
    printf "${C_CYAN}%-30s %-6s %-6s %-8s %-8s %s${C_RESET}\n" "域名" "IPv4" "IPv6" "代理" "来源" "间隔"
    draw_line
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID="" DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
        parse_ddns_conf "$conf" || continue
        printf "%-30s %-6s %-6s %-8s %-8s %s\n" "$DDNS_DOMAIN" \
            "$([[ "$DDNS_IPV4" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_IPV6" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_PROXIED" == "true" ]] && echo "开启" || echo "关闭")" \
            "${DDNS_IP_SOURCE:-auto}" \
            "${DDNS_INTERVAL}分钟"
    done
    local ip4=$(get_public_ipv4)
    local ip6=$(get_public_ipv6)
    echo -e "${C_CYAN}当前IP:${C_RESET} IPv4=${ip4:-N/A} IPv6=${ip6:-N/A}"
    pause
}
ddns_delete() {
    print_title "删除 DDNS 配置"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无配置"; pause; return; }
    local i=1 domains=() files=()
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID="" DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
        parse_ddns_conf "$conf" || continue
        domains+=("$DDNS_DOMAIN"); files+=("$conf")
        echo "$i. $DDNS_DOMAIN"; ((i++))
    done
    echo "0. 返回"
    read -e -r -p "选择: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    [[ "$idx" =~ ^[0-9]+$ && "$idx" -le ${#domains[@]} ]] || { print_error "无效"; pause; return; }
    confirm "删除 ${domains[$((idx-1))]} 的 DDNS?" && {
        rm -f "${files[$((idx-1))]}"
        if [[ -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]]; then
            cron_remove_job "ddns-update.sh"
            rm -f "$DDNS_UPDATE_SCRIPT"
            [[ "$PLATFORM" == "openwrt" ]] && rm -f /etc/hotplug.d/iface/95-server-manage-ddns 2>/dev/null || true
        else
            ddns_rebuild_cron
        fi
        print_success "已删除"; log_action "DDNS deleted: ${domains[$((idx-1))]}"
    }
    pause
}
ddns_force_update() {
    if [[ -x "$DDNS_UPDATE_SCRIPT" ]]; then
        print_info "正在更新..."
        if DDNS_FORCE=1 "$DDNS_UPDATE_SCRIPT"; then
            print_success "更新完成"
        else
            local rc=$?
            print_error "DDNS 更新失败 (rc=$rc)，请查看日志"
            tail -n 10 "$DDNS_LOG" 2>/dev/null || echo "暂无日志"
            pause
            return "$rc"
        fi
        tail -n 10 "$DDNS_LOG" 2>/dev/null || echo "暂无日志"
    else
        print_warn "DDNS 未配置"
    fi
    pause
}
load_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        local file_mtime
        file_mtime=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)
        local cache_age=$(($(date +%s) - file_mtime))
        if [[ $cache_age -lt $CACHE_TTL ]]; then
            # 安全检查：仅允许合法的变量赋值格式
            if validate_conf_file "$CACHE_FILE" 2>/dev/null; then
                source "$CACHE_FILE" 2>/dev/null || return 1
                return 0
            fi
            return 1
        fi
    fi
    return 1
}

_sysinfo_conf_escape() {
    local value="${1:-}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//\$/\\$}"
    value="${value//\`/\\\`}"
    printf '%s' "$value"
}

_network_cache_defaults() {
    CACHED_IPV4="${CACHED_IPV4:-N/A}"
    CACHED_IPV6="${CACHED_IPV6:-未配置}"
    CACHED_ISP="${CACHED_ISP:-N/A}"
    CACHED_LOCATION="${CACHED_LOCATION:-N/A}"
}

load_cache_stale() {
    [[ -f "$CACHE_FILE" ]] || return 1
    validate_conf_file "$CACHE_FILE" 2>/dev/null || return 1
    source "$CACHE_FILE" 2>/dev/null || return 1
    _network_cache_defaults
    return 0
}

_network_cache_refresh_background() {
    mkdir -p "$CACHE_DIR" 2>/dev/null || return 0
    local lock_file="${CACHE_DIR}/sysinfo.refresh.lock"
    if command_exists flock; then
        (
            exec 201>"$lock_file" || exit 0
            flock -n 201 || exit 0
            refresh_network_cache
        ) >/dev/null 2>&1 &
    else
        (
            mkdir "${lock_file}.d" 2>/dev/null || exit 0
            trap 'rmdir "${lock_file}.d" 2>/dev/null || true' EXIT
            refresh_network_cache
        ) >/dev/null 2>&1 &
    fi
}

ensure_network_cache_async() {
    if load_cache; then
        return 0
    fi
    if load_cache_stale; then
        _network_cache_refresh_background
        return 0
    fi
    _network_cache_defaults
    _network_cache_refresh_background
    return 0
}

refresh_network_cache() {
    CACHED_IPV4=$(get_public_ipv4 || echo "N/A")
    CACHED_IPV6=$(get_public_ipv6 || echo "")
    [[ -z "$CACHED_IPV6" ]] && CACHED_IPV6="未配置"
    local ipinfo=$(curl -s --connect-timeout 3 --max-time 5 https://ipinfo.io/json 2>/dev/null || echo "{}")
    CACHED_ISP=$(echo "$ipinfo" | grep -o '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    [[ -z "$CACHED_ISP" ]] && CACHED_ISP="N/A"
    local country=$(echo "$ipinfo" | grep -o '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local city=$(echo "$ipinfo" | grep -o '"city"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    CACHED_LOCATION="${country:-N/A} ${city:-}"
    mkdir -p "$CACHE_DIR"
    local cache_content
    cache_content=$(cat << EOF
CACHED_IPV4="$(_sysinfo_conf_escape "$CACHED_IPV4")"
CACHED_IPV6="$(_sysinfo_conf_escape "$CACHED_IPV6")"
CACHED_ISP="$(_sysinfo_conf_escape "$CACHED_ISP")"
CACHED_LOCATION="$(_sysinfo_conf_escape "$CACHED_LOCATION")"
EOF
)
    write_file_atomic "$CACHE_FILE" "$cache_content" || return 1
    chmod 600 "$CACHE_FILE" 2>/dev/null || true
}
get_ip_location() {
    local ip="$1"
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|fe80:|::1|fc00:|fd00:) ]]; then
        echo "本地网络"
        return
    fi
    local result
    if command_exists timeout; then
        result=$(timeout 3 curl -s "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    else
        result=$(curl -s --max-time 3 "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    fi
    if [[ -n "$result" ]] && echo "$result" | grep -q '"status":"success"'; then
        local country=$(echo "$result" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        local region=$(echo "$result" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
        local city=$(echo "$result" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        local isp=$(echo "$result" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        local location=""
        [[ -n "$country" ]] && location="$country"
        [[ -n "$region" && "$region" != "$country" ]] && location="${location} ${region}"
        [[ -n "$city" && "$city" != "$region" ]] && location="${location} ${city}"
        [[ -n "$isp" ]] && location="${location} (${isp})"
        echo "${location:-未知}"
        return
    fi
    echo "查询失败"
}

_ip_location_cache_path() {
    local ip="$1" safe_ip
    safe_ip=$(printf '%s' "$ip" | tr -c 'A-Za-z0-9_.-' '_')
    printf '%s/ip-location-%s.cache' "$CACHE_DIR" "$safe_ip"
}

_ip_location_refresh_background() {
    local ip="$1" cache_file="$2" lock_file
    lock_file="${cache_file}.lock"
    mkdir -p "$CACHE_DIR" 2>/dev/null || return 0
    if command_exists flock; then
        (
            exec 202>"$lock_file" || exit 0
            flock -n 202 || exit 0
            local location
            location=$(get_ip_location "$ip")
            [[ -n "$location" ]] || location="查询失败"
            write_file_atomic "$cache_file" "$location"
        ) >/dev/null 2>&1 &
    else
        (
            mkdir "${lock_file}.d" 2>/dev/null || exit 0
            trap 'rmdir "${lock_file}.d" 2>/dev/null || true' EXIT
            local location
            location=$(get_ip_location "$ip")
            [[ -n "$location" ]] || location="查询失败"
            write_file_atomic "$cache_file" "$location"
        ) >/dev/null 2>&1 &
    fi
}

get_ip_location_cached() {
    local ip="$1" cache_file file_mtime cache_age
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|fe80:|::1|fc00:|fd00:) ]]; then
        echo "本地网络"
        return 0
    fi
    cache_file=$(_ip_location_cache_path "$ip")
    if [[ -s "$cache_file" ]]; then
        file_mtime=$(stat -c %Y "$cache_file" 2>/dev/null || stat -f %m "$cache_file" 2>/dev/null || echo 0)
        cache_age=$(($(date +%s) - file_mtime))
        if [[ "$cache_age" -lt 86400 ]]; then
            head -n 1 "$cache_file"
            return 0
        fi
    fi
    _ip_location_refresh_background "$ip" "$cache_file"
    echo "待查询"
}

show_dual_column_sysinfo() {
    ensure_network_cache_async
    local hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown")
    local os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -c 35)
    local kernel=$(uname -r | head -c 20)
    local arch=$(uname -m)
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs | head -c 25)
    local cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "1")
    local cpu_freq=$(awk '/MHz/ {printf "%.1fGHz", $4/1000; exit}' /proc/cpuinfo 2>/dev/null || echo "N/A")

    # 使用 /proc/stat 计算 CPU 使用率（比 top -bn1 快 5-10 倍）
    local cpu_usage="0%"
    if [[ -f /proc/stat ]]; then
        local c1 c2
        c1=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
        sleep 0.2
        c2=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
        cpu_usage=$(awk -v a="$c1" -v b="$c2" 'BEGIN{
            split(a,x," "); split(b,y," ");
            dt=y[1]-x[1]; di=y[2]-x[2];
            if(dt>0) printf "%.0f%%", 100*(1-di/dt); else print "0%"}')
    fi
    local load_avg=$(awk '{printf "%.2f %.2f %.2f", $1, $2, $3}' /proc/loadavg 2>/dev/null)
    local tcp_conn=0 udp_conn=0
    if command -v ss >/dev/null 2>&1; then
        tcp_conn=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
        udp_conn=$(ss -un 2>/dev/null | tail -n +2 | wc -l)
    elif [[ -f /proc/net/tcp ]]; then
        tcp_conn=$(awk 'NR>1 && $4=="01"{n++}END{print n+0}' /proc/net/tcp 2>/dev/null)
        udp_conn=$(awk 'NR>1{n++}END{print n+0}' /proc/net/udp 2>/dev/null)
    fi
    local mem_info swap_info
    if command -v free >/dev/null 2>&1; then
        mem_info=$(free -m | awk '/^Mem:/ {printf "%d/%dM %.0f%%", $3, $2, ($2>0)?$3/$2*100:0}')
        swap_info=$(free -m | awk '/^Swap:/ {if($2>0) printf "%d/%dM %.0f%%", $3, $2, $3/$2*100; else print "未启用"}')
    else
        local mt=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
        local mf=$(awk '/^MemAvailable/{print int($2/1024)}' /proc/meminfo)
        local mu=$((mt - mf))
        mem_info="${mu}/${mt}M $(( mt>0 ? mu*100/mt : 0 ))%"
        swap_info="未启用"
    fi
    local disk_info=$(df -h / | awk 'NR==2 {printf "%s/%s %s", $3, $2, $5}')
    local main_if=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
    local rx_total="0B" tx_total="0B"
    if [[ -n "$main_if" ]]; then
        read -r rx_total tx_total <<< "$(awk -v iface="$main_if:" '
            function fmt(b) {
                if(b>=1073741824) return sprintf("%.2fG",b/1073741824)
                if(b>=1048576) return sprintf("%.0fM",b/1048576)
                if(b>=1024) return sprintf("%.0fK",b/1024)
                return sprintf("%dB",b)
            }
            $1==iface {print fmt($2), fmt($10)}
        ' /proc/net/dev 2>/dev/null)"
        rx_total=${rx_total:-0B}; tx_total=${tx_total:-0B}
    fi
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    local uptime_str=$(awk '{d=int($1/86400);h=int($1%86400/3600);m=int($1%3600/60);
        if(d>0)printf "%d天%d时%d分",d,h,m;else if(h>0)printf "%d时%d分",h,m;else printf "%d分",m}' /proc/uptime)
    local sys_time=$(date "+%m-%d %H:%M")
    local timezone=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' || echo "UTC")
    refresh_ssh_port
    local ssh_port="${CURRENT_SSH_PORTS:-${CURRENT_SSH_PORT:-22}}"
    local ufw_st="○"; command -v ufw &>/dev/null && ufw_is_active && ufw_st="●"
    local f2b_st="○"; systemctl is-active fail2ban &>/dev/null && f2b_st="●"
    local nginx_st="○"; systemctl is-active nginx &>/dev/null && nginx_st="●"
    local docker_st="○"; systemctl is-active docker &>/dev/null && docker_st="●"
    local wg_st="○"; ip link show wg0 &>/dev/null && wg_st="●"
    local W=76  # 总宽度
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "主机:" "$hostname" "IPv4:" "$CACHED_IPV4"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "系统:" "${os_info:0:17}" "IPv6:" "${CACHED_IPV6:0:20}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "内核:" "$kernel" "运营商:" "${CACHED_ISP:0:18}"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "CPU:" "${cpu_model:0:17}" "内存:" "$mem_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "核心:" "${cpu_cores}核 @ $cpu_freq" "交换:" "$swap_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "负载:" "$load_avg" "硬盘:" "$disk_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "占用:" "$cpu_usage 连接:${tcp_conn}t/${udp_conn}u" "流量:" "↓${rx_total} ↑${tx_total}"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "算法:" "$tcp_cc + $qdisc" "位置:" "${CACHED_LOCATION:0:18}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "运行:" "$uptime_str" "时区:" "$timezone"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s | ${C_CYAN}%-8s${C_RESET}%s\n" \
        "SSH:" "端口 $ssh_port" "时间:" "$sys_time"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " 服务: UFW[${C_GREEN}%s${C_RESET}] F2B[${C_GREEN}%s${C_RESET}] Nginx[${C_GREEN}%s${C_RESET}] Docker[${C_GREEN}%s${C_RESET}] WG[${C_GREEN}%s${C_RESET}]\n" \
        "$ufw_st" "$f2b_st" "$nginx_st" "$docker_st" "$wg_st"

    # 展示最近 3 条登录记录
    local login_count=0
    if command -v last >/dev/null 2>&1; then
        local login_lines
        login_lines=$(last -n 20 -a -w 2>/dev/null | grep -E "^[a-zA-Z]" | grep -v -E "wtmp begins|^reboot" | head -3)
        if [[ -n "$login_lines" ]]; then
            printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
            while IFS= read -r login_line; do
                [[ -z "$login_line" ]] && continue
                login_count=$((login_count + 1))
                local login_user=$(echo "$login_line" | awk '{print $1}')
                local login_ip=$(echo "$login_line" | awk '{print $NF}')
                local login_time=$(echo "$login_line" | awk '{print $4, $5, $6}')
                local login_display=""
                if [[ -n "$login_ip" && "$login_ip" =~ ^[0-9a-f.:]+$ ]]; then
                    local ip_loc=$(get_ip_location_cached "$login_ip")
                    login_display="${login_user}@${login_ip} (${ip_loc}) ${login_time}"
                else
                    login_display="${login_user} ${login_time}"
                fi
                printf " ${C_CYAN}%-8s${C_RESET}%s\n" "登录${login_count}:" "${login_display:0:65}"
            done <<< "$login_lines"
        fi
    fi
    if [[ "$login_count" -eq 0 ]]; then
        printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
        printf " ${C_CYAN}%-8s${C_RESET}%s\n" "登录:" "无记录"
    fi
}
_ufw_validate_current_ssh_ports() {
    local _ssh_port found=0
    for _ssh_port in $CURRENT_SSH_PORTS; do
        found=1
        validate_port "$_ssh_port" || {
            print_error "无法确认当前 SSH 端口，拒绝操作 UFW"
            return 1
        }
    done
    if [[ "$found" -eq 0 ]]; then
        print_error "无法确认当前 SSH 端口，拒绝操作 UFW"
        return 1
    fi
    return 0
}

_ufw_apply_default_ssh_rules() {
    local _ssh_port
    _ufw_validate_current_ssh_ports || return 1
    print_info "配置默认规则..."
    if ! ufw default deny incoming >/dev/null; then
        print_error "设置 UFW 默认入站拒绝失败。"
        return 1
    fi
    if ! ufw default allow outgoing >/dev/null; then
        print_error "设置 UFW 默认出站允许失败。"
        return 1
    fi
    for _ssh_port in $CURRENT_SSH_PORTS; do
        if ! ufw allow "$_ssh_port/tcp" comment "SSH-Access" >/dev/null; then
            print_error "放行 SSH 端口 ${_ssh_port}/tcp 失败，拒绝继续启用 UFW。"
            return 1
        fi
    done
    return 0
}

ufw_setup() {
    install_package "ufw" || { print_error "UFW 安装失败。"; pause; return 1; }
    _require_cmd ufw "UFW" || return
    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行，请先禁用它。"
        pause; return 1
    fi
    refresh_ssh_port
    _ufw_apply_default_ssh_rules || { pause; return 1; }
    if confirm "启用 UFW 可能导致 SSH 断开(若端口配置错误)，确认启用?"; then
        if ! echo "y" | ufw enable >/dev/null; then
            print_error "UFW 启用失败。"
            pause; return 1
        fi
        print_success "UFW 已启用。"
        log_action "UFW enabled with SSH ports $CURRENT_SSH_PORTS"
    fi
    pause
}

ufw_del() {
    _require_cmd ufw "UFW" || return
    print_title "删除 UFW 规则"
    echo -e "${C_CYAN}当前放行的端口 (已过滤 Fail2ban 规则):${C_RESET}"
    ufw status | grep "ALLOW" | grep -viE 'fail2ban|f2b' | awk '{print $1}' | sort -t'/' -k1,1n -u
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时删除 tcp 和 udp${C_RESET}"
    read -e -r -p "要删除的规则: " rules
    [[ -z "$rules" ]] && return
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            if ! validate_port "$port"; then
                print_error "端口无效: $port"
                continue
            fi
            if [[ -n "$proto" ]]; then
                ufw delete allow "${port}${proto}" 2>/dev/null && print_success "已删除: ${port}${proto}" || print_warn "${port}${proto} 不存在"
            else
                ufw delete allow "${port}/tcp" 2>/dev/null && print_success "已删除: ${port}/tcp" || print_warn "${port}/tcp 不存在"
                ufw delete allow "${port}/udp" 2>/dev/null && print_success "已删除: ${port}/udp" || true
            fi
        else
            print_error "无效格式: $rule"
        fi
    done
    log_action "UFW rules deleted: $rules"
    pause
}

ufw_safe_reset() {
    _require_cmd ufw "UFW" || return
    if confirm "这将重置所有规则！脚本会尝试保留当前 SSH 端口，确定吗？"; then
        print_info "正在重置..."
        refresh_ssh_port
        _ufw_validate_current_ssh_ports || { pause; return 1; }
        if ! echo "y" | ufw disable >/dev/null; then
            print_error "UFW 禁用失败，已中止重置。"
            pause; return 1
        fi
        if ! echo "y" | ufw reset >/dev/null; then
            print_error "UFW 重置失败。"
            pause; return 1
        fi
        _ufw_apply_default_ssh_rules || { pause; return 1; }
        if ! echo "y" | ufw enable >/dev/null; then
            print_error "UFW 重新启用失败，请手动检查当前防火墙状态。"
            pause; return 1
        fi
        print_success "重置完成。SSH 端口 ${CURRENT_SSH_PORTS} 已放行。"
        log_action "UFW reset completed"
    fi
    pause
}

ufw_add() {
    _require_cmd ufw "UFW" || return
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时放行 tcp 和 udp${C_RESET}"
    read -e -r -p "要放行的规则: " rules
    [[ -z "$rules" ]] && return
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            if validate_port "$port"; then
                if [[ -n "$proto" ]]; then
                    ufw allow "${port}${proto}" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}${proto}" || \
                        print_error "添加失败: ${port}${proto}"
                else
                    ufw allow "${port}/tcp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/tcp" || \
                        print_error "添加失败: ${port}/tcp"
                    ufw allow "${port}/udp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/udp" || \
                        print_error "添加失败: ${port}/udp"
                fi
                log_action "UFW allowed ${port}${proto:-/tcp+udp}"
            else
                print_error "端口无效: $port"
            fi
        else
            print_error "无效格式: $rule"
        fi
    done
    pause
}

FIREWALL_SSH_OPEN_BACKENDS=""
FIREWALL_UDP_OPEN_BACKENDS=""

_firewall_iptables_input_restrictive() {
    local bin="$1"
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk '
        $1=="-P" && $2=="INPUT" && ($3=="DROP" || $3=="REJECT") { found=1 }
        $1=="-A" && $2=="INPUT" && $0 ~ / -j (DROP|REJECT)( |$)/ { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_has_tcp_accept() {
    local bin="$1" port="$2"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk -v p="$port" '
        $1=="-A" && $2=="INPUT" &&
        $0 ~ / -j ACCEPT( |$)/ &&
        $0 ~ /(^| )-p tcp( |$)/ &&
        $0 ~ ("(^| )--dport " p "($| )") { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_insert_tcp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage SSH}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    _firewall_iptables_has_tcp_accept "$bin" "$port" && return 0

    "$bin" -I INPUT 1 -p tcp -m state --state NEW -m tcp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -I INPUT 1 -p tcp -m tcp --dport "$port" -j ACCEPT
}

_firewall_iptables_delete_tcp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage SSH}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 0
    "$bin" -D INPUT -p tcp -m state --state NEW -m tcp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -D INPUT -p tcp -m tcp --dport "$port" -j ACCEPT 2>/dev/null || true
}

_firewall_iptables_has_udp_accept() {
    local bin="$1" port="$2"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk -v p="$port" '
        $1=="-A" && $2=="INPUT" &&
        $0 ~ / -j ACCEPT( |$)/ &&
        $0 ~ /(^| )-p udp( |$)/ &&
        $0 ~ ("(^| )--dport " p "($| )") { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_insert_udp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage UDP}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    _firewall_iptables_has_udp_accept "$bin" "$port" && return 0

    "$bin" -I INPUT 1 -p udp -m udp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -I INPUT 1 -p udp -m udp --dport "$port" -j ACCEPT
}

_firewall_iptables_delete_udp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage UDP}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 0
    "$bin" -D INPUT -p udp -m udp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -D INPUT -p udp -m udp --dport "$port" -j ACCEPT 2>/dev/null || true
}

_firewall_iptables_save_rules() {
    local save_bin="$1" rules_file="$2" tmpfile
    [[ -f "$rules_file" ]] || return 2
    command_exists "$save_bin" || return 2
    tmpfile=$(mktemp "$(dirname "$rules_file")/.tmp.server-manage.iptables.XXXXXX") || return 1
    _tmp_register "$tmpfile"
    if ! "$save_bin" > "$tmpfile"; then
        rm -f "$tmpfile"
        _tmp_unregister "$tmpfile"
        return 1
    fi
    chmod --reference="$rules_file" "$tmpfile" 2>/dev/null || true
    chown --reference="$rules_file" "$tmpfile" 2>/dev/null || true
    if ! mv "$tmpfile" "$rules_file"; then
        rm -f "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    _tmp_unregister "$tmpfile"
    return 0
}

_firewall_save_after_iptables_change() {
    local backend="$1" rc
    case "$backend" in
        iptables)
            if _firewall_iptables_save_rules iptables-save /etc/iptables/rules.v4; then rc=0; else rc=$?; fi
            case "$rc" in
                0) print_info "已同步持久化 /etc/iptables/rules.v4" ;;
                1) print_warn "IPv4 运行时规则已更新，但持久化 /etc/iptables/rules.v4 失败，请手动检查。" ;;
                2) print_warn "IPv4 运行时规则已更新，但未检测到 /etc/iptables/rules.v4；重启后可能丢失。" ;;
            esac
            ;;
        ip6tables)
            if _firewall_iptables_save_rules ip6tables-save /etc/iptables/rules.v6; then rc=0; else rc=$?; fi
            case "$rc" in
                0) print_info "已同步持久化 /etc/iptables/rules.v6" ;;
                1) print_warn "IPv6 运行时规则已更新，但持久化 /etc/iptables/rules.v6 失败，请手动检查。" ;;
                2) print_warn "IPv6 运行时规则已更新，但未检测到 /etc/iptables/rules.v6；重启后可能丢失。" ;;
            esac
            ;;
    esac
}

# firewall_prepare_non_ufw_ssh_port <port> [comment]
# 在 UFW 未启用时，为 SSH 改端口场景处理常见的本地防火墙：
# - firewalld: 运行时 + permanent 放行
# - iptables/ip6tables(nft backend 也兼容): INPUT 存在 DROP/REJECT 时插入新端口 ACCEPT，并在已存在
#   /etc/iptables/rules.v4/v6 时同步持久化
#
# 返回值:
#   0 = 已确保或未检测到本地阻断
#   1 = 自动放行失败
#   2 = 检测到可能阻断但用户取消/无法自动确认
firewall_prepare_non_ufw_ssh_port() {
    local port="$1" comment="${2:-SSH-New}"
    FIREWALL_SSH_OPEN_BACKENDS=""
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    [[ "$PLATFORM" == "openwrt" ]] && return 0

    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行；SSH 新端口必须同步放行。"
        if ! command_exists firewall-cmd; then
            print_error "firewalld 活跃但 firewall-cmd 不可用，拒绝继续修改 SSH 端口。"
            return 1
        fi
        if ! confirm "是否通过 firewalld 放行 ${port}/tcp（运行时 + permanent）？"; then
            return 2
        fi
        firewall-cmd --add-port="${port}/tcp" >/dev/null || return 1
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || \
            print_warn "firewalld permanent 规则写入失败；本次运行时已放行，但重启后可能丢失。"
        FIREWALL_SSH_OPEN_BACKENDS+=" firewalld"
        print_success "firewalld 已放行 ${port}/tcp。"
        return 0
    fi

    local restrictive=0 changed=0 backend
    for backend in iptables ip6tables; do
        command_exists "$backend" || continue
        _firewall_iptables_input_restrictive "$backend" || continue
        restrictive=1
        if _firewall_iptables_has_tcp_accept "$backend" "$port"; then
            print_info "${backend} 已存在 ${port}/tcp 放行规则。"
            continue
        fi
        print_warn "检测到 ${backend} INPUT 链存在 DROP/REJECT，且未放行新 SSH 端口 ${port}/tcp。"
        if ! confirm "是否自动插入 ${backend} 放行规则并尽量持久化？"; then
            [[ -n "$FIREWALL_SSH_OPEN_BACKENDS" ]] && firewall_rollback_ssh_port "$port" "$FIREWALL_SSH_OPEN_BACKENDS" "$comment"
            return 2
        fi
        if ! _firewall_iptables_insert_tcp_accept "$backend" "$port" "$comment"; then
            print_error "${backend} 插入 ${port}/tcp 放行规则失败。"
            [[ -n "$FIREWALL_SSH_OPEN_BACKENDS" ]] && firewall_rollback_ssh_port "$port" "$FIREWALL_SSH_OPEN_BACKENDS" "$comment"
            return 1
        fi
        FIREWALL_SSH_OPEN_BACKENDS+=" ${backend}"
        changed=1
        print_success "${backend} 已放行 ${port}/tcp。"
        _firewall_save_after_iptables_change "$backend"
    done

    if [[ $restrictive -eq 0 ]]; then
        print_info "未检测到 UFW 以外的本地 INPUT DROP/REJECT；仍请确认云安全组已放行 ${port}/tcp。"
    elif [[ $changed -eq 0 ]]; then
        print_info "检测到本地防火墙限制，但新端口已有放行规则。"
    fi
    return 0
}

firewall_rollback_ssh_port() {
    local port="$1" backends="${2:-}" comment="${3:-SSH-New}" backend
    validate_port "$port" || return 0
    for backend in $backends; do
        case "$backend" in
            iptables|ip6tables)
                _firewall_iptables_delete_tcp_accept "$backend" "$port" "$comment"
                _firewall_save_after_iptables_change "$backend"
                ;;
            firewalld)
                if command_exists firewall-cmd; then
                    firewall-cmd --remove-port="${port}/tcp" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done
}

# firewall_prepare_non_ufw_udp_port <port> [comment]
# UFW 未启用/不存在时，为必须可入站的 UDP 服务处理常见本机防火墙。
# 返回值同 firewall_prepare_non_ufw_ssh_port。
firewall_prepare_non_ufw_udp_port() {
    local port="$1" comment="${2:-Managed-UDP}"
    FIREWALL_UDP_OPEN_BACKENDS=""
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    [[ "$PLATFORM" == "openwrt" ]] && return 0

    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行；UDP 端口 ${port} 必须同步放行。"
        if ! command_exists firewall-cmd; then
            print_error "firewalld 活跃但 firewall-cmd 不可用，拒绝继续。"
            return 1
        fi
        if ! confirm "是否通过 firewalld 放行 ${port}/udp（运行时 + permanent）？"; then
            return 2
        fi
        firewall-cmd --add-port="${port}/udp" >/dev/null || return 1
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || \
            print_warn "firewalld permanent 规则写入失败；本次运行时已放行，但重启后可能丢失。"
        FIREWALL_UDP_OPEN_BACKENDS+=" firewalld"
        print_success "firewalld 已放行 ${port}/udp。"
        return 0
    fi

    local restrictive=0 changed=0 backend
    for backend in iptables ip6tables; do
        command_exists "$backend" || continue
        _firewall_iptables_input_restrictive "$backend" || continue
        restrictive=1
        if _firewall_iptables_has_udp_accept "$backend" "$port"; then
            print_info "${backend} 已存在 ${port}/udp 放行规则。"
            continue
        fi
        print_warn "检测到 ${backend} INPUT 链存在 DROP/REJECT，且未放行 ${port}/udp。"
        if ! confirm "是否自动插入 ${backend} 放行规则并尽量持久化？"; then
            [[ -n "$FIREWALL_UDP_OPEN_BACKENDS" ]] && firewall_rollback_udp_port "$port" "$FIREWALL_UDP_OPEN_BACKENDS" "$comment"
            return 2
        fi
        if ! _firewall_iptables_insert_udp_accept "$backend" "$port" "$comment"; then
            print_error "${backend} 插入 ${port}/udp 放行规则失败。"
            [[ -n "$FIREWALL_UDP_OPEN_BACKENDS" ]] && firewall_rollback_udp_port "$port" "$FIREWALL_UDP_OPEN_BACKENDS" "$comment"
            return 1
        fi
        FIREWALL_UDP_OPEN_BACKENDS+=" ${backend}"
        changed=1
        print_success "${backend} 已放行 ${port}/udp。"
        _firewall_save_after_iptables_change "$backend"
    done

    if [[ $restrictive -eq 0 ]]; then
        print_info "未检测到 UFW 以外的本地 INPUT DROP/REJECT；仍请确认云安全组已放行 ${port}/udp。"
    elif [[ $changed -eq 0 ]]; then
        print_info "检测到本地防火墙限制，但 ${port}/udp 已有放行规则。"
    fi
    return 0
}

firewall_rollback_udp_port() {
    local port="$1" backends="${2:-}" comment="${3:-Managed-UDP}" backend
    validate_port "$port" || return 0
    for backend in $backends; do
        case "$backend" in
            iptables|ip6tables)
                _firewall_iptables_delete_udp_accept "$backend" "$port" "$comment"
                _firewall_save_after_iptables_change "$backend"
                ;;
            firewalld)
                if command_exists firewall-cmd; then
                    firewall-cmd --remove-port="${port}/udp" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done
}

# firewall_allow_tcp_port <port> [comment]
# 返回值:
#   0 = 已成功放行
#   1 = 真实错误（参数无效 / ufw 命令失败）
#   2 = UFW 不可用（未安装 / 未启用）—— 业务流程应仅警告，不要中断；启用 UFW 由用户主动进防火墙菜单完成
#
# 设计原则：业务模块（Reality/Realm/Email 等）不在自动流程里启用或重置 UFW，
# 以免与云安全组、用户已有规则、SSH 端口产生冲突。需要启用 UFW 的请走【防火墙模块】。
firewall_allow_tcp_port() {
    local port="$1" comment="${2:-Managed-TCP}"
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "OpenWrt 防火墙请在 LuCI/fw4 中放行 ${port}/tcp"
        return 0
    fi

    if ! command_exists ufw; then
        print_warn "未检测到 UFW — 本脚本不会自动安装。"
        print_info "如需本地防火墙，请进入【防火墙管理】菜单完成 UFW 安装与启用；"
        print_info "或在云厂商安全组放行 ${port}/tcp。"
        log_action "UFW absent during firewall_allow_tcp_port port=${port}" "INFO"
        return 2
    fi

    if ! ufw_is_active; then
        print_warn "UFW 已安装但未启用 — 本脚本不会在业务流程里自动启用 UFW。"
        print_info "如需本地防火墙保护，请进入【防火墙管理】→ 安装并启用 UFW；"
        print_info "或在云厂商安全组放行 ${port}/tcp。"
        log_action "UFW inactive during firewall_allow_tcp_port port=${port}" "INFO"
        return 2
    fi

    # UFW 已启用 — 仅追加规则
    if ufw allow "${port}/tcp" comment "$comment" >/dev/null 2>&1; then
        log_action "UFW allowed ${port}/tcp comment=${comment}"
        return 0
    fi
    print_error "UFW 添加规则失败: ${port}/tcp"
    return 1
}

# firewall_allow_udp_port <port> [comment]
# 返回值同 firewall_allow_tcp_port；业务模块只追加规则，不自动启用/重置 UFW。
firewall_allow_udp_port() {
    local port="$1" comment="${2:-Managed-UDP}"
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "OpenWrt 防火墙请在 LuCI/fw4 中放行 ${port}/udp"
        return 0
    fi

    if ! command_exists ufw; then
        print_warn "未检测到 UFW — 本脚本不会自动安装。"
        print_info "如需本地防火墙，请进入【防火墙管理】菜单完成 UFW 安装与启用；"
        print_info "或在云厂商安全组放行 ${port}/udp。"
        log_action "UFW absent during firewall_allow_udp_port port=${port}" "INFO"
        return 2
    fi

    if ! ufw_is_active; then
        print_warn "UFW 已安装但未启用 — 本脚本不会在业务流程里自动启用 UFW。"
        print_info "如需本地防火墙保护，请进入【防火墙管理】→ 安装并启用 UFW；"
        print_info "或在云厂商安全组放行 ${port}/udp。"
        log_action "UFW inactive during firewall_allow_udp_port port=${port}" "INFO"
        return 2
    fi

    # UFW 已启用 — 仅追加规则
    if ufw allow "${port}/udp" comment "$comment" >/dev/null 2>&1; then
        log_action "UFW allowed ${port}/udp comment=${comment}"
        return 0
    fi
    print_error "UFW 添加规则失败: ${port}/udp"
    return 1
}

firewall_apply_reality_port() {
    local port="$1"
    firewall_allow_tcp_port "$port" "SingBox-Reality"
}

firewall_apply_realm_port() {
    local port="$1"
    firewall_allow_tcp_port "$port" "Realm-Relay"
}

# ── GeoIP 国家级 IP 白/黑名单 ──
readonly GEOIP_CONF_DIR="/etc/server-manage"
readonly GEOIP_CONF="${GEOIP_CONF_DIR}/geoip.conf"
readonly GEOIP_DATA_DIR="${GEOIP_CONF_DIR}/geoip-data"
readonly GEOIP_CHAIN="GEOIP_FILTER"
readonly GEOIP6_CHAIN="GEOIP6_FILTER"
readonly GEOIP_URL="https://www.ipdeny.com/ipblocks/data/aggregated"
readonly GEOIP6_URL="https://www.ipdeny.com/ipv6/ipaddresses/aggregated"

_geoip_country_name() {
    case "${1^^}" in
        CN) echo "中国" ;; JP) echo "日本" ;; US) echo "美国" ;; KR) echo "韩国" ;;
        SG) echo "新加坡" ;; HK) echo "香港" ;; TW) echo "台湾" ;; DE) echo "德国" ;;
        GB) echo "英国" ;; FR) echo "法国" ;; RU) echo "俄罗斯" ;; AU) echo "澳大利亚" ;;
        CA) echo "加拿大" ;; IN) echo "印度" ;; NL) echo "荷兰" ;; BR) echo "巴西" ;;
        *) echo "${1^^}" ;;
    esac
}

_geoip_load_conf() {
    local line key value mode="" countries="" last_update="" cc
    GEOIP_MODE="" GEOIP_COUNTRIES="" GEOIP_LAST_UPDATE=""
    [[ -f "$GEOIP_CONF" ]] || return 1
    validate_conf_file "$GEOIP_CONF" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
        key="${line%%=*}"
        key="${key//[[:space:]]/}"
        value="${line#*=}"
        case "$key" in
            GEOIP_MODE|GEOIP_COUNTRIES|GEOIP_LAST_UPDATE) ;;
            *) return 1 ;;
        esac
        if [[ "$value" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ "$value" =~ ^\'([^\']*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi
        case "$key" in
            GEOIP_MODE) mode="$value" ;;
            GEOIP_COUNTRIES) countries="$value" ;;
            GEOIP_LAST_UPDATE) last_update="$value" ;;
        esac
    done < "$GEOIP_CONF"
    [[ -z "$mode" || "$mode" =~ ^(whitelist|blacklist)$ ]] || return 1
    for cc in $countries; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || return 1
    done
    GEOIP_MODE="$mode"
    GEOIP_COUNTRIES="$countries"
    GEOIP_LAST_UPDATE="$last_update"
    return 0
}

_geoip_service_file_path() {
    printf '%s' "${GEOIP_SERVICE_FILE:-/etc/systemd/system/geoip-firewall.service}"
}

_geoip_apply_script_path() {
    printf '%s' "${GEOIP_APPLY_SCRIPT:-/usr/local/bin/geoip-apply.sh}"
}

_geoip_update_script_path() {
    printf '%s' "${GEOIP_UPDATE_SCRIPT:-/usr/local/bin/geoip-update.sh}"
}

_geoip_render_conf() {
    local mode="$1" countries="$2" last_update="$3" cc
    [[ "$mode" =~ ^(whitelist|blacklist)$ ]] || return 1
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    for cc in $countries; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || return 1
    done
    printf 'GEOIP_MODE="%s"\n' "$mode"
    printf 'GEOIP_COUNTRIES="%s"\n' "$countries"
    printf 'GEOIP_LAST_UPDATE="%s"\n' "$last_update"
}

_geoip_write_conf() {
    local mode="$1" countries="$2" last_update="$3" content
    content="$(_geoip_render_conf "$mode" "$countries" "$last_update")" || return 1
    write_private_file_atomic "$GEOIP_CONF" "$content"
}

_geoip_render_conf_last_update() {
    local conf_file="$1" last_update="$2"
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    if [[ -f "$conf_file" ]]; then
        awk -v last_update="$last_update" '
            BEGIN { done=0 }
            /^[[:space:]]*GEOIP_LAST_UPDATE[[:space:]]*=/ {
                if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
                done=1
                next
            }
            { print }
            END {
                if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
            }
        ' "$conf_file"
    else
        printf 'GEOIP_LAST_UPDATE="%s"\n' "$last_update"
    fi
}

_geoip_update_last_update() {
    local conf_file="$1" last_update="${2:-$(date +%Y-%m-%d)}" content
    validate_conf_file "$conf_file" || return 1
    content="$(_geoip_render_conf_last_update "$conf_file" "$last_update")" || return 1
    write_private_file_atomic "$conf_file" "$content"
}

_geoip_render_service_unit() {
    local apply_script="${1:-/usr/local/bin/geoip-apply.sh}"
    cat <<SVC_EOF
[Unit]
Description=GeoIP Firewall Rules
After=network.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=${apply_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
}

_geoip_install_service_unit() {
    local service_file content
    service_file="$(_geoip_service_file_path)"
    content="$(_geoip_render_service_unit "$(_geoip_apply_script_path)")" || return 1
    write_file_atomic "$service_file" "$content" || return 1
    chmod 644 "$service_file" 2>/dev/null || true
}

_geoip_download() {
    local countries="$1"
    mkdir -p "$GEOIP_DATA_DIR"
    local ok=0 fail=0
    for cc in $countries; do
        cc="${cc,,}"
        local url="${GEOIP_URL}/${cc}-aggregated.zone"
        local url6="${GEOIP6_URL}/${cc}-aggregated.zone"
        local dest="${GEOIP_DATA_DIR}/${cc}.zone"
        local dest6="${GEOIP_DATA_DIR}/${cc}.zone6"
        local tmp tmp6 count count6
        tmp=$(mktemp "${GEOIP_DATA_DIR}/.${cc}.zone.XXXXXX") || { print_error "${cc^^}: 创建临时文件失败"; ((fail++)) || true; continue; }
        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp" "$url" 2>/dev/null; then
            count=$(grep -c '^[0-9]' "$tmp" 2>/dev/null)
            if [[ "$count" -gt 0 ]]; then
                mv "$tmp" "$dest"
                echo -e "  ${C_GREEN}✓${C_RESET} ${cc^^} ($(_geoip_country_name "$cc")) IPv4: ${count} 条 IP 段"
                ((ok++)) || true
            else
                print_warn "${cc^^}: 文件为空或格式异常，保留旧数据"
                rm -f "$tmp"
                ((fail++)) || true
            fi
        else
            print_error "${cc^^}: 下载失败，保留旧数据"
            rm -f "$tmp"
            ((fail++)) || true
        fi
        tmp6=$(mktemp "${GEOIP_DATA_DIR}/.${cc}.zone6.XXXXXX") || { print_error "${cc^^}: 创建 IPv6 临时文件失败"; ((fail++)) || true; continue; }
        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp6" "$url6" 2>/dev/null; then
            count6=$(grep -c ':' "$tmp6" 2>/dev/null)
            if [[ "$count6" -gt 0 ]]; then
                mv "$tmp6" "$dest6"
                echo -e "  ${C_GREEN}✓${C_RESET} ${cc^^} ($(_geoip_country_name "$cc")) IPv6: ${count6} 条 IP 段"
            else
                print_warn "${cc^^}: IPv6 文件为空或格式异常，保留旧数据"
                rm -f "$tmp6"
                ((fail++)) || true
            fi
        else
            print_error "${cc^^}: IPv6 下载失败，保留旧数据"
            rm -f "$tmp6"
            ((fail++)) || true
        fi
    done
    [[ $fail -eq 0 ]] && [[ $ok -gt 0 ]]
}

_geoip_apply() {
    local mode="$1" countries="$2"
    local set_name="geoip_${mode}"
    local tmp_set="${set_name}_tmp"
    local set6_name="geoip_${mode}6"
    local tmp6_set="${set6_name}_tmp"
    local total_entries=0 total6_entries=0 use_ip6tables=0 swapped4=0
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        if [[ -f "$f" ]]; then
            local count
            count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
            total_entries=$((total_entries + count))
        fi
        local f6="${GEOIP_DATA_DIR}/${cc,,}.zone6"
        if [[ -f "$f6" ]]; then
            local count6
            count6=$(grep -c ':' "$f6" 2>/dev/null)
            total6_entries=$((total6_entries + count6))
        fi
    done
    if [[ "$total_entries" -le 0 ]]; then
        print_error "GeoIP 有效 IP 段为空，拒绝应用规则以避免清空集合。"
        return 1
    fi
    if [[ -e /proc/net/if_inet6 ]] && ! command_exists ip6tables; then
        print_error "检测到 IPv6 栈但缺少 ip6tables，拒绝应用 GeoIP 以避免 IPv6 绕过。"
        return 1
    fi
    command_exists ip6tables && use_ip6tables=1
    # Bulk load into temp set
    ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set" || return 1
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] || continue
        if ! sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null; then
            print_error "GeoIP 写入 ipset 失败: ${cc}"
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
    done

    if [[ "$use_ip6tables" -eq 1 ]]; then
        if ! ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null && ! ipset flush "$tmp6_set"; then
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
        for cc in $countries; do
            local f6="${GEOIP_DATA_DIR}/${cc,,}.zone6"
            [[ -f "$f6" ]] || continue
            if ! sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null; then
                print_error "GeoIP 写入 IPv6 ipset 失败: ${cc}"
                ipset destroy "$tmp6_set" 2>/dev/null || true
                ipset destroy "$tmp_set" 2>/dev/null || true
                return 1
            fi
        done
    fi

    # Swap only after both families have been populated. If IPv6 swap fails after
    # IPv4 has moved, swap IPv4 back so an update failure does not half-commit.
    ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
    if ! ipset swap "$tmp_set" "$set_name"; then
        print_error "GeoIP ipset swap 失败，保留旧集合。"
        ipset destroy "$tmp_set" 2>/dev/null || true
        [[ "$use_ip6tables" -eq 1 ]] && ipset destroy "$tmp6_set" 2>/dev/null || true
        return 1
    fi
    swapped4=1
    if [[ "$use_ip6tables" -eq 1 ]]; then
        ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
        if ! ipset swap "$tmp6_set" "$set6_name"; then
            print_error "GeoIP IPv6 ipset swap 失败，保留旧集合。"
            if [[ "$swapped4" -eq 1 ]]; then
                ipset swap "$tmp_set" "$set_name" 2>/dev/null || \
                    print_warn "GeoIP IPv4 集合回滚失败，请手动检查 ipset: ${set_name}/${tmp_set}"
            fi
            ipset destroy "$tmp6_set" 2>/dev/null || true
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
        ipset destroy "$tmp6_set" 2>/dev/null || true
        if [[ "$total6_entries" -le 0 ]]; then
            print_warn "GeoIP IPv6 数据为空；白名单模式将默认拦截公网 IPv6。"
        fi
    fi
    ipset destroy "$tmp_set" 2>/dev/null || true
    # Build iptables chain
    iptables -N "$GEOIP_CHAIN" 2>/dev/null || iptables -F "$GEOIP_CHAIN" || return 1
    iptables -A "$GEOIP_CHAIN" -i lo -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 127.0.0.0/8 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 10.0.0.0/8 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 172.16.0.0/12 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 192.168.0.0/16 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
    if [[ "$mode" == "whitelist" ]]; then
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j RETURN || return 1
        iptables -A "$GEOIP_CHAIN" -j DROP || return 1
    else
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j DROP || return 1
    fi
    # Insert into INPUT chain at position 1 (before UFW)
    iptables -C INPUT -j "$GEOIP_CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$GEOIP_CHAIN" || return 1
    if command_exists ip6tables; then
        ip6tables -N "$GEOIP6_CHAIN" 2>/dev/null || ip6tables -F "$GEOIP6_CHAIN" || return 1
        ip6tables -A "$GEOIP6_CHAIN" -i lo -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s ::1/128 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s fc00::/7 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s fe80::/10 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
        if [[ "$mode" == "whitelist" ]]; then
            ip6tables -A "$GEOIP6_CHAIN" -m set --match-set "$set6_name" src -j RETURN || return 1
            ip6tables -A "$GEOIP6_CHAIN" -j DROP || return 1
        else
            ip6tables -A "$GEOIP6_CHAIN" -m set --match-set "$set6_name" src -j DROP || return 1
        fi
        ip6tables -C INPUT -j "$GEOIP6_CHAIN" 2>/dev/null || ip6tables -I INPUT 1 -j "$GEOIP6_CHAIN" || return 1
    fi
}

_geoip_clear() {
    iptables -D INPUT -j "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -F "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -X "$GEOIP_CHAIN" 2>/dev/null || true
    ip6tables -D INPUT -j "$GEOIP6_CHAIN" 2>/dev/null || true
    ip6tables -F "$GEOIP6_CHAIN" 2>/dev/null || true
    ip6tables -X "$GEOIP6_CHAIN" 2>/dev/null || true
    ipset destroy geoip_whitelist 2>/dev/null || true
    ipset destroy geoip_blacklist 2>/dev/null || true
    ipset destroy geoip_whitelist6 2>/dev/null || true
    ipset destroy geoip_blacklist6 2>/dev/null || true
}

_geoip_install_persistence() {
    local apply_script update_script apply_content update_content
    apply_script="$(_geoip_apply_script_path)"
    update_script="$(_geoip_update_script_path)"
    # Apply script (runs on boot)
    apply_content="$(cat << 'APPLY_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
CHAIN="GEOIP_FILTER"
CHAIN6="GEOIP6_FILTER"
[ -f "$CONF" ] || exit 0

# 安全解析：拒绝 source，避免被替换为恶意 conf 触发 root 命令执行
fown=$(stat -c '%U' "$CONF" 2>/dev/null || echo "")
fmode=$(stat -c '%a' "$CONF" 2>/dev/null || echo "")
[ "$fown" = "root" ] || exit 0
if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then exit 0; fi
GEOIP_MODE="" GEOIP_COUNTRIES=""
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^(GEOIP_MODE|GEOIP_COUNTRIES|GEOIP_LAST_UPDATE)=\"([A-Za-z0-9\ _.-]*)\"$ ]]; then
        case "${BASH_REMATCH[1]}" in
            GEOIP_MODE)        GEOIP_MODE="${BASH_REMATCH[2]}" ;;
            GEOIP_COUNTRIES)   GEOIP_COUNTRIES="${BASH_REMATCH[2]}" ;;
            GEOIP_LAST_UPDATE) : ;;
        esac
    else
        exit 0
    fi
done < "$CONF"

[ -z "$GEOIP_MODE" ] && exit 0
[[ "$GEOIP_MODE" =~ ^(whitelist|blacklist)$ ]] || exit 0
set_name="geoip_${GEOIP_MODE}"
tmp_set="${set_name}_tmp"
set6_name="geoip_${GEOIP_MODE}6"
tmp6_set="${set6_name}_tmp"
total_entries=0
total6_entries=0
use_ip6tables=0
swapped4=0
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
    total_entries=$((total_entries + count))
    f6="${DATA}/${cc,,}.zone6"
    [ -f "$f6" ] || continue
    count6=$(grep -c ':' "$f6" 2>/dev/null)
    total6_entries=$((total6_entries + count6))
done
[ "$total_entries" -gt 0 ] || exit 1
[ -e /proc/net/if_inet6 ] && ! command -v ip6tables >/dev/null 2>&1 && exit 1
command -v ip6tables >/dev/null 2>&1 && use_ip6tables=1
ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set" || exit 1
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
done
if [ "$use_ip6tables" -eq 1 ]; then
    if ! ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null && ! ipset flush "$tmp6_set"; then
        ipset destroy "$tmp_set" 2>/dev/null || true
        exit 1
    fi
    for cc in $GEOIP_COUNTRIES; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
        f6="${DATA}/${cc,,}.zone6"
        [ -f "$f6" ] || continue
        sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp6_set" 2>/dev/null || true; ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
    done
fi
ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
ipset swap "$tmp_set" "$set_name" || { ipset destroy "$tmp_set" 2>/dev/null || true; [ "$use_ip6tables" -eq 1 ] && ipset destroy "$tmp6_set" 2>/dev/null || true; exit 1; }
swapped4=1
if [ "$use_ip6tables" -eq 1 ]; then
    ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
    if ! ipset swap "$tmp6_set" "$set6_name"; then
        [ "$swapped4" -eq 1 ] && ipset swap "$tmp_set" "$set_name" 2>/dev/null || true
        ipset destroy "$tmp6_set" 2>/dev/null || true
        ipset destroy "$tmp_set" 2>/dev/null || true
        exit 1
    fi
    ipset destroy "$tmp6_set" 2>/dev/null || true
fi
ipset destroy "$tmp_set" 2>/dev/null || true
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN" || exit 1
iptables -A "$CHAIN" -i lo -j RETURN || exit 1
iptables -A "$CHAIN" -s 127.0.0.0/8 -j RETURN || exit 1
iptables -A "$CHAIN" -s 10.0.0.0/8 -j RETURN || exit 1
iptables -A "$CHAIN" -s 172.16.0.0/12 -j RETURN || exit 1
iptables -A "$CHAIN" -s 192.168.0.0/16 -j RETURN || exit 1
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || exit 1
if [ "$GEOIP_MODE" = "whitelist" ]; then
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j RETURN || exit 1
    iptables -A "$CHAIN" -j DROP || exit 1
else
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j DROP || exit 1
fi
iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN" || exit 1
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N "$CHAIN6" 2>/dev/null || ip6tables -F "$CHAIN6" || exit 1
    ip6tables -A "$CHAIN6" -i lo -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s ::1/128 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s fc00::/7 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s fe80::/10 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || exit 1
    if [ "$GEOIP_MODE" = "whitelist" ]; then
        ip6tables -A "$CHAIN6" -m set --match-set "$set6_name" src -j RETURN || exit 1
        ip6tables -A "$CHAIN6" -j DROP || exit 1
    else
        ip6tables -A "$CHAIN6" -m set --match-set "$set6_name" src -j DROP || exit 1
    fi
    ip6tables -C INPUT -j "$CHAIN6" 2>/dev/null || ip6tables -I INPUT 1 -j "$CHAIN6" || exit 1
fi
APPLY_EOF
)"
    write_file_atomic "$apply_script" "$apply_content" || return 1
    chmod 700 "$apply_script"
    # Update script (cron weekly)
    update_content="$(cat << 'UPDATE_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
URL="https://www.ipdeny.com/ipblocks/data/aggregated"
URL6="https://www.ipdeny.com/ipv6/ipaddresses/aggregated"
[ -f "$CONF" ] || exit 0

# 安全解析（同 apply 脚本）
fown=$(stat -c '%U' "$CONF" 2>/dev/null || echo "")
fmode=$(stat -c '%a' "$CONF" 2>/dev/null || echo "")
[ "$fown" = "root" ] || exit 0
if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then exit 0; fi
GEOIP_COUNTRIES=""
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^GEOIP_COUNTRIES=\"([A-Za-z0-9\ _.-]*)\"$ ]]; then
        GEOIP_COUNTRIES="${BASH_REMATCH[1]}"
    fi
done < "$CONF"
[ -z "$GEOIP_COUNTRIES" ] && exit 0

mkdir -p "$DATA"
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    cc="${cc,,}"
    tmp=$(mktemp "${DATA}/.${cc}.zone.XXXXXX") || exit 1
    tmp6=$(mktemp "${DATA}/.${cc}.zone6.XXXXXX") || { rm -f "$tmp"; exit 1; }
    if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp" "${URL}/${cc}-aggregated.zone" 2>/dev/null; then
        count=$(grep -c '^[0-9]' "$tmp" 2>/dev/null)
        if [ "$count" -gt 0 ]; then
            mv "$tmp" "${DATA}/${cc}.zone" || { rm -f "$tmp"; exit 1; }
        else
            rm -f "$tmp" "$tmp6"
            exit 1
        fi
    else
        rm -f "$tmp" "$tmp6"
        exit 1
    fi
    if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp6" "${URL6}/${cc}-aggregated.zone" 2>/dev/null; then
        count6=$(grep -c ':' "$tmp6" 2>/dev/null)
        if [ "$count6" -gt 0 ]; then
            mv "$tmp6" "${DATA}/${cc}.zone6" || { rm -f "$tmp6"; exit 1; }
        else
            rm -f "$tmp6"
            exit 1
        fi
    else
        rm -f "$tmp6"
        exit 1
    fi
done
/usr/local/bin/geoip-apply.sh || exit 1
update_last_update() {
    last_update="$(date +%Y-%m-%d)"
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || exit 1
    dir="$(dirname "$CONF")"
    tmp="$(mktemp "${dir}/.tmp.server-manage.geoip.XXXXXX")" || exit 1
    if awk -v last_update="$last_update" '
        BEGIN { done=0 }
        /^[[:space:]]*GEOIP_LAST_UPDATE[[:space:]]*=/ {
            if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
            done=1
            next
        }
        { print }
        END {
            if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
        }
    ' "$CONF" > "$tmp"; then
        chmod 600 "$tmp" 2>/dev/null || true
        chown root:root "$tmp" 2>/dev/null || true
        mv "$tmp" "$CONF" || { rm -f "$tmp"; exit 1; }
    else
        rm -f "$tmp"
        exit 1
    fi
}
update_last_update
UPDATE_EOF
)"
    write_file_atomic "$update_script" "$update_content" || return 1
    chmod 700 "$update_script"
    # Systemd boot service
    if is_systemd; then
        _geoip_install_service_unit || return 1
        systemctl daemon-reload || return 1
        systemctl enable geoip-firewall >/dev/null 2>&1 || return 1
    fi
    # Weekly cron (Sunday 04:00)
    cron_add_job "$(basename "$update_script")" "0 4 * * 0 ${update_script} >/dev/null 2>&1"
}

geoip_setup() {
    print_title "GeoIP 国家级 IP 白/黑名单"
    if ! command_exists ipset; then
        install_package "ipset"
        if ! command_exists ipset; then
            print_error "ipset 安装失败。"; pause; return
        fi
    fi
    if ! command_exists iptables; then
        print_error "iptables 未安装。"; pause; return
    fi
    _geoip_load_conf
    if [[ -n "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 已配置: 模式=${GEOIP_MODE} 国家=${GEOIP_COUNTRIES}"
        if ! confirm "重新配置将覆盖现有规则，继续?"; then
            pause; return
        fi
        _geoip_clear
    fi
    echo -e "${C_CYAN}选择模式:${C_RESET}"
    echo "  1. 白名单 (仅允许指定国家访问，其他全部拦截)"
    echo "  2. 黑名单 (仅封禁指定国家，其他正常放行)"
    read -e -r -p "选择 [1]: " mode_choice
    local mode="whitelist"
    [[ "$mode_choice" == "2" ]] && mode="blacklist"
    if [[ "$mode" == "whitelist" ]]; then
        echo -e "${C_YELLOW}[!] 白名单模式: 非白名单国家的所有入站连接将被直接丢弃${C_RESET}"
        echo -e "${C_YELLOW}    请确保你的访问来源国家都已加入白名单${C_RESET}"
    fi
    echo ""
    echo -e "${C_CYAN}常用国家代码:${C_RESET}"
    echo "  CN 中国    JP 日本    US 美国    KR 韩国    SG 新加坡"
    echo "  HK 香港    TW 台湾    DE 德国    GB 英国    FR 法国"
    echo "  RU 俄罗斯  AU 澳大利亚  CA 加拿大  NL 荷兰    IN 印度"
    echo ""
    read -e -r -p "输入国家代码 (空格分隔): " countries_input
    [[ -z "$countries_input" ]] && { print_warn "已取消"; pause; return; }
    local countries=""
    for cc in $countries_input; do
        cc="${cc^^}"
        if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then
            print_error "无效国家代码: $cc (需要2位字母)"; pause; return
        fi
        countries="$countries $cc"
    done
    countries=$(echo "$countries" | xargs)
    # SSH safety check (whitelist mode)
    if [[ "$mode" == "whitelist" ]]; then
        local ssh_ip="${SSH_CLIENT%% *}"
        if [[ -n "$ssh_ip" ]]; then
            print_info "当前 SSH 来源: $ssh_ip"
            echo -e "${C_RED}[安全提示] 请确认你的 IP 所在国家已在白名单中！${C_RESET}"
            if ! confirm "确认继续? (设置错误将导致 SSH 断开)"; then
                pause; return
            fi
        fi
    fi
    draw_line
    echo -e "${C_CYAN}配置摘要:${C_RESET}"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单 (仅允许)" || echo "黑名单 (仅封禁)")"
    echo "  国家: $countries"
    draw_line
    if ! confirm "确认应用?"; then
        print_warn "已取消"; pause; return
    fi
    print_info "正在下载 IP 数据..."
    if ! _geoip_download "$countries"; then
        print_error "所有国家数据下载失败"; pause; return
    fi
    print_info "正在应用防火墙规则..."
    if ! _geoip_apply "$mode" "$countries"; then
        print_error "GeoIP 规则应用失败，未写入持久化配置。"
        pause; return
    fi
    local total=0
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] && total=$((total + $(grep -c '^[0-9]' "$f" 2>/dev/null)))
    done
    if ! _geoip_write_conf "$mode" "$countries" "$(date +%Y-%m-%d)"; then
        print_error "GeoIP 配置写入失败，未安装持久化任务。"
        pause; return 1
    fi
    local persistence_ok=1
    if ! _geoip_install_persistence; then
        persistence_ok=0
        print_warn "GeoIP 当前规则已生效，但持久化/自动更新任务安装失败。"
        print_warn "请检查文件权限、crontab 或 systemd 状态；重启后规则可能不会自动恢复。"
    fi
    print_success "GeoIP 当前规则已生效！"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单" || echo "黑名单")"
    echo "  国家: $countries"
    echo "  IP段: ${total} 条"
    if [[ "$persistence_ok" -eq 1 ]]; then
        echo "  自动更新: 每周日 04:00"
        log_action "GeoIP configured: mode=$mode countries=$countries entries=$total"
    else
        echo "  自动更新: 未安装成功"
        log_action "GeoIP configured without persistence: mode=$mode countries=$countries entries=$total"
        pause
        return 1
    fi
    pause
}

geoip_status() {
    print_title "GeoIP 状态"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    local set_name="geoip_${GEOIP_MODE}"
    echo -e "${C_CYAN}模式:${C_RESET} $([[ "$GEOIP_MODE" == "whitelist" ]] && echo "白名单 (仅允许)" || echo "黑名单 (仅封禁)")"
    echo -e "${C_CYAN}国家:${C_RESET} $GEOIP_COUNTRIES"
    echo -e "${C_CYAN}更新:${C_RESET} ${GEOIP_LAST_UPDATE:-未知}"
    echo ""
    echo -e "${C_CYAN}[IP 段统计]${C_RESET}"
    local total=0
    for cc in $GEOIP_COUNTRIES; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        if [[ -f "$f" ]]; then
            local count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
            printf "  %-4s %-10s %s 条\n" "${cc}" "$(_geoip_country_name "$cc")" "$count"
            total=$((total + count))
        fi
    done
    echo "  总计: ${total} 条"
    echo ""
    echo -e "${C_CYAN}[iptables 命中统计]${C_RESET}"
    iptables -L "$GEOIP_CHAIN" -n -v 2>/dev/null | head -20 || \
        print_warn "iptables 规则不存在"
    echo ""
    echo -e "${C_CYAN}[ipset 集合]${C_RESET}"
    if ipset list "$set_name" 2>/dev/null | head -5; then
        local entries=$(ipset list "$set_name" 2>/dev/null | grep -c '^[0-9]')
        echo "  已加载条目: ${entries}"
    else
        print_warn "ipset 集合不存在"
    fi
    pause
}

geoip_update() {
    print_title "更新 GeoIP 数据"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    print_info "正在更新 IP 数据 (${GEOIP_COUNTRIES})..."
    if _geoip_download "$GEOIP_COUNTRIES"; then
        print_info "正在重新加载规则..."
        if ! _geoip_apply "$GEOIP_MODE" "$GEOIP_COUNTRIES"; then
            print_error "GeoIP 规则重新加载失败，已保留旧规则"
            pause; return 1
        fi
        if ! _geoip_update_last_update "$GEOIP_CONF"; then
            print_error "GeoIP 更新时间写入失败"
            pause; return 1
        fi
        print_success "更新完成"
        log_action "GeoIP data updated: $GEOIP_COUNTRIES"
    else
        print_error "更新失败"
    fi
    pause
}

geoip_disable() {
    print_title "禁用 GeoIP"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    if ! confirm "确认禁用 GeoIP 规则? (将移除所有国家限制)"; then return; fi
    _geoip_clear
    rm -f "$GEOIP_CONF"
    rm -rf "$GEOIP_DATA_DIR"
    rm -f "$(_geoip_apply_script_path)" "$(_geoip_update_script_path)"
    cron_remove_job "$(basename "$(_geoip_update_script_path)")"
    if is_systemd; then
        systemctl disable geoip-firewall 2>/dev/null || true
        rm -f "$(_geoip_service_file_path)"
        systemctl daemon-reload
    fi
    print_success "GeoIP 已禁用，所有规则已清除。"
    log_action "GeoIP disabled and cleaned up"
    pause
}

menu_geoip() {
    fix_terminal
    while true; do
        print_title "GeoIP 国家级 IP 白/黑名单"
        _geoip_load_conf
        if [[ -n "$GEOIP_MODE" ]]; then
            echo -e "${C_GREEN}状态: 已启用${C_RESET}"
            echo -e "模式: $([[ "$GEOIP_MODE" == "whitelist" ]] && echo "白名单" || echo "黑名单") | 国家: ${GEOIP_COUNTRIES} | 更新: ${GEOIP_LAST_UPDATE:-未知}"
        else
            echo -e "${C_YELLOW}状态: 未配置${C_RESET}"
        fi
        echo ""
        echo "1. 配置 GeoIP 规则
2. 查看当前状态
3. 手动更新 IP 数据库
4. 禁用 GeoIP
0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) geoip_setup ;;
            2) geoip_status ;;
            3) geoip_update ;;
            4) geoip_disable ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

menu_ufw() {
    fix_terminal
    while true; do
        print_title "UFW 防火墙管理"
        if command_exists ufw; then
            local ufw_status=$(ufw status 2>/dev/null | head -n 1 || echo "未运行")
            echo -e "${C_CYAN}当前状态:${C_RESET} $ufw_status"
        else
            echo -e "${C_YELLOW}UFW 未安装${C_RESET}"
        fi
        echo "1. 安装并启用 UFW
2. 查看本机监听端口
3. 添加放行端口
4. 查看当前规则
5. 删除规则
6. 禁用 UFW
7. 重置默认规则 (安全模式)
8. GeoIP 国家级 IP 白/黑名单
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) ufw_setup ;;
            2) check_port_usage ;;
            3) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_add
                fi
                ;;
            4) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    print_title "当前防火墙规则"
                    ufw status numbered
                    pause
                fi
                ;;
            5) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_del
                fi
                ;;
            6)
                if ! command_exists ufw; then
                    print_error "UFW 未安装。"
                    pause
                elif confirm "确认禁用 UFW？"; then
                    echo "y" | ufw disable
                    print_success "UFW 已禁用。"
                    log_action "UFW disabled"
                    pause
                fi
                ;;
            7) ufw_safe_reset ;;
            8) menu_geoip ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
_f2b_rollback_jail_local() {
    local target="${1:-}" backup="${2:-}" had_target="${3:-0}"
    if [[ "$had_target" -eq 1 && -n "$backup" && -f "$backup" ]]; then
        mv "$backup" "$target" 2>/dev/null || true
    else
        rm -f -- "$target" 2>/dev/null || true
    fi
    [[ -n "$backup" ]] && _tmp_unregister "$backup"
}

_f2b_apply_jail_local() {
    local conf_content="${1:-}" banaction="${2:-}"
    local target="${FAIL2BAN_JAIL_LOCAL}" backup="" had_target=0
    [[ -n "$target" && -n "$conf_content" ]] || return 1
    if [[ -f "$target" ]]; then
        had_target=1
        backup=$(mktemp "$(dirname "$target")/.bak.server-manage.fail2ban.XXXXXX") || return 1
        _tmp_register "$backup"
        if ! cp -a "$target" "$backup"; then
            rm -f -- "$backup" 2>/dev/null || true
            _tmp_unregister "$backup"
            return 1
        fi
    fi
    if ! write_file_atomic "$target" "$conf_content"; then
        _f2b_rollback_jail_local "$target" "$backup" "$had_target"
        return 1
    fi
    if command_exists fail2ban-client && ! fail2ban-client -d >/dev/null 2>&1; then
        _f2b_rollback_jail_local "$target" "$backup" "$had_target"
        return 1
    fi
    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        if ! systemctl restart fail2ban; then
            _f2b_rollback_jail_local "$target" "$backup" "$had_target"
            return 1
        fi
    fi
    rm -f -- "$backup" 2>/dev/null || true
    [[ -n "$backup" ]] && _tmp_unregister "$backup"
    print_success "配置已写入: $target (banaction=$banaction)"
    command_exists fail2ban-client && print_success "配置校验通过"
    is_systemd && print_success "Fail2ban 已启动 (banaction=$banaction)。"
    return 0
}

f2b_setup() {
    print_title "Fail2ban 安装与配置"
    install_package "fail2ban" "silent"
    install_package "rsyslog" "silent"
    local backend="auto"
    if is_systemd; then
        systemctl enable rsyslog >/dev/null 2>&1 || true
        systemctl restart rsyslog || true
        backend="systemd"
    fi

    # Fail2ban 本身只负责监控日志和判定，实际封禁 IP 需要底层防火墙工具
    # 支持链路: nftables > iptables+ipset > iptables-multiport > 不可用
    print_info "正在检测封禁后端..."
    local banaction=""
    local ban_backend_info=""
    
    # 优先级 1: nftables (Debian 11+/Ubuntu 22.04+ 默认)
    if command_exists nft && nft list ruleset &>/dev/null 2>&1; then
        banaction="nftables-allports"
        ban_backend_info="nftables (原生内核防火墙)"
        print_success "检测到 nftables - 使用 nftables-allports"
    fi
    
    # 优先级 2: iptables + ipset (传统方案，高性能)
    if [[ -z "$banaction" ]] && command_exists iptables; then
        # iptables 存在，尝试安装 ipset 配合使用
        if ! command_exists ipset; then
            print_info "正在安装 ipset (高性能封禁集合)..."
            install_package "ipset" "silent"
        fi
        if command_exists ipset; then
            # 验证 ipset 能否正常创建/销毁测试集合
            if ipset create _f2b_test hash:ip timeout 1 &>/dev/null; then
                ipset destroy _f2b_test &>/dev/null
                banaction="iptables-ipset-proto6-allports"
                ban_backend_info="iptables + ipset (高性能集合)"
                print_success "检测到 iptables + ipset"
            else
                # ipset 命令存在但无法使用 (可能是内核模块问题)
                print_warn "ipset 命令存在但无法正常工作，回退到 iptables-multiport"
                banaction="iptables-multiport"
                ban_backend_info="iptables-multiport (逐条规则)"
            fi
        else
            # ipset 安装失败，使用 iptables 基础模式
            banaction="iptables-multiport"
            ban_backend_info="iptables-multiport (逐条规则，无 ipset)"
            print_warn "ipset 不可用，回退到 iptables-multiport"
        fi
    fi
    
    # 优先级 3: 如果 iptables 也不存在，尝试安装
    if [[ -z "$banaction" ]]; then
        print_warn "未检测到 nftables 或 iptables!"
        print_info "尝试安装 iptables..."
        install_package "iptables" "silent"
        if command_exists iptables; then
            install_package "ipset" "silent"
            if command_exists ipset && ipset create _f2b_test hash:ip timeout 1 &>/dev/null 2>&1; then
                ipset destroy _f2b_test &>/dev/null
                banaction="iptables-ipset-proto6-allports"
                ban_backend_info="iptables + ipset (新安装)"
            else
                banaction="iptables-multiport"
                ban_backend_info="iptables-multiport (新安装)"
            fi
            print_success "iptables 安装成功"
        else
            # 全部失败 - 中止
            echo ""
            print_error "无法找到或安装任何可用的封禁后端!"
            echo -e "  Fail2ban 需要以下工具之一来执行 IP 封禁:"
            echo -e "  ${C_CYAN}1.${C_RESET} nftables    (Debian 11+/Ubuntu 22.04+ 推荐)"
            echo -e "  ${C_CYAN}2.${C_RESET} iptables    (传统方案，搭配 ipset 更佳)"
            echo -e "  请手动安装后重试: ${C_GREEN}apt install -y iptables ipset${C_RESET}"
            echo -e "  或: ${C_GREEN}apt install -y nftables${C_RESET}"
            pause; return 1
        fi
    fi
    read -e -r -p "监控 SSH 端口 [$CURRENT_SSH_PORT]: " port
    port=${port:-$CURRENT_SSH_PORT}
    if ! validate_port "$port"; then
        print_error "端口无效，使用默认值 $CURRENT_SSH_PORT"
        port=$CURRENT_SSH_PORT
    fi
    read -e -r -p "最大重试次数 (登录失败几次后封禁) [5]: " maxretry
    maxretry=${maxretry:-5}
    if ! [[ "$maxretry" =~ ^[0-9]+$ ]] || [ "$maxretry" -lt 1 ]; then
        print_warn "无效输入，使用默认值 5"
        maxretry=5
    fi
    echo "封禁时间选项:
  1) 10分钟 (10m)
  2) 30分钟 (30m)
  3) 1小时 (1h)
  4) 6小时 (6h)
  5) 24小时 (24h)
  6) 7天 (7d)
  7) 永久封禁
  8) 自定义"
    read -e -r -p "选择封禁时间 [5]: " bantime_choice
    local bantime="24h"
    case $bantime_choice in
        1) bantime="10m" ;;
        2) bantime="30m" ;;
        3) bantime="1h" ;;
        4) bantime="6h" ;;
        5|"") bantime="24h" ;;
        6) bantime="7d" ;;
        7) bantime="-1" ;;
        8)
            read -e -r -p "输入封禁时间 (如 10m, 1h, 24h, 7d, -1为永久): " custom_bantime
            if [[ "$custom_bantime" =~ ^-?[0-9]+[smhd]?$ ]]; then
                bantime="$custom_bantime"
            else
                print_warn "格式无效，使用默认值 24h"
                bantime="24h"
            fi
            ;;
        *) 
            print_warn "无效选择，使用默认值 24h"
            bantime="24h"
            ;;
    esac
    echo "检测时间窗口 (在此时间内达到最大重试次数则封禁):
  1) 10分钟 (10m) - 默认
  2) 30分钟 (30m)
  3) 1小时 (1h)
  4) 自定义"
    read -e -r -p "选择检测窗口 [1]: " findtime_choice
    local findtime="10m"
    case $findtime_choice in
        1|"") findtime="10m" ;;
        2) findtime="30m" ;;
        3) findtime="1h" ;;
        4)
            read -e -r -p "输入检测窗口 (如 10m, 1h): " custom_findtime
            if [[ "$custom_findtime" =~ ^[0-9]+[smhd]?$ ]]; then
                findtime="$custom_findtime"
            else
                print_warn "格式无效，使用默认值 10m"
                findtime="10m"
            fi
            ;;
        *) findtime="10m" ;;
    esac
    # ignoreip 白名单
    local default_ignore="127.0.0.1/8 ::1 10.0.0.0/8"
    echo ""
    echo -e "${C_CYAN}[ignoreip 白名单]${C_RESET}"
    echo -e "  白名单中的 IP 永远不会被封禁 (防止误封自己)"
    echo -e "  默认值: ${C_GREEN}${default_ignore}${C_RESET}"
    echo -e "  可追加你的固定 IP、WireGuard 网段等 (空格分隔)"
    read -e -r -p "ignoreip [回车使用默认]: " custom_ignore
    local ignoreip="${custom_ignore:-$default_ignore}"
    # Nginx jail detection
    local nginx_jail=0
    if command_exists nginx && [[ -d /var/log/nginx ]]; then
        echo ""
        echo -e "${C_CYAN}[Nginx 防护]${C_RESET}"
        echo -e "  检测到 Nginx 已安装，可同时启用 Web 防爆破 jail:"
        echo -e "  ${C_GREEN}nginx-http-auth${C_RESET}  — 监控 HTTP 401 认证失败 (密码爆破)"
        echo -e "  ${C_GREEN}nginx-botsearch${C_RESET}  — 监控 404 扫描探测 (.env/wp-admin 等)"
        if confirm "是否启用 Nginx 防护?"; then
            nginx_jail=1
        fi
    fi
    draw_line
    echo -e "${C_CYAN}配置摘要:${C_RESET}"
    echo "  SSH 端口:     $port"
    echo "  最大重试:     $maxretry 次"
    echo "  检测窗口:     $findtime"
    echo "  封禁时间:     $bantime"
    echo "  封禁方式:     $ban_backend_info"
    echo "  白名单:       $ignoreip"
    [[ $nginx_jail -eq 1 ]] && echo -e "  Nginx 防护:   ${C_GREEN}启用${C_RESET} (http-auth + botsearch)"
    [[ "$bantime" == "-1" ]] && echo -e "  ${C_YELLOW}提示: 永久封禁建议定期检查规则数量${C_RESET}"
    draw_line
    if ! confirm "确认应用此配置?"; then
        print_warn "已取消配置。"
        pause
        return
    fi

    # 迁移：清理旧的 UFW 封禁规则
    if ufw_is_active; then
        local old_f2b_rules
        old_f2b_rules=$(ufw status numbered 2>/dev/null | grep -ciE "f2b|fail2ban")
        if [[ "$old_f2b_rules" -gt 0 ]]; then
            print_warn "检测到 UFW 中有 ${old_f2b_rules} 条 Fail2ban 旧规则"
            print_info "新配置使用 ipset 替代 UFW 封禁，旧规则已无用且拖慢系统"
            if confirm "是否清理这些旧规则? (强烈建议)"; then
                f2b_migrate_ufw_to_ipset
            fi
        fi
    fi
    local conf_content="[DEFAULT]
bantime = $bantime
findtime = $findtime
banaction = $banaction
banaction_allports = $banaction
ignoreip = $ignoreip
[sshd]
enabled = true
port = $port
maxretry = $maxretry
backend = $backend
logpath = %(sshd_log)s"
    # Append Nginx jails if enabled
    if [[ $nginx_jail -eq 1 ]]; then
        conf_content="${conf_content}

[nginx-http-auth]
enabled = true
port = http,https
maxretry = $maxretry
logpath = /var/log/nginx/error.log

[nginx-botsearch]
enabled = true
port = http,https
maxretry = 5
logpath = /var/log/nginx/access.log"
    fi
    if _f2b_apply_jail_local "$conf_content" "$banaction"; then
        log_action "Fail2ban configured: port=$port, maxretry=$maxretry, bantime=$bantime, banaction=$banaction"
    else
        print_error "Fail2ban 配置应用失败，已回滚。"
        echo "运行 fail2ban-client -d 或 journalctl -u fail2ban -n 20 查看详情"
        log_action "Fail2ban configuration failed and rolled back" "ERROR"
        pause
        return 1
    fi
    pause
}

f2b_migrate_ufw_to_ipset() {
    print_info "正在清理 UFW 中的 Fail2ban 旧规则..."
    systemctl stop fail2ban 2>/dev/null || true
    if ! command_exists ufw; then
        print_warn "UFW 未安装，跳过旧规则清理"
        return 0
    fi
    local rule_numbers=() line rule_no i total_removed=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[[[:space:]]*([0-9]+)\] ]]; then
            rule_no="${BASH_REMATCH[1]}"
            if [[ "$line" =~ f2b- || "$line" =~ [Ff]ail2ban ]]; then
                rule_numbers+=("$rule_no")
            fi
        fi
    done < <(ufw status numbered 2>/dev/null)
    if [[ ${#rule_numbers[@]} -eq 0 ]]; then
        print_info "无需清理"
        return 0
    fi
    for ((i=${#rule_numbers[@]}-1; i>=0; i--)); do
        if printf 'y\n' | ufw delete "${rule_numbers[$i]}" >/dev/null 2>&1; then
            ((total_removed++)) || true
        else
            print_warn "UFW 规则 #${rule_numbers[$i]} 删除失败"
        fi
    done
    if ! ufw reload >/dev/null 2>&1; then
        print_error "UFW reload 失败，请检查规则状态"
        return 1
    fi
    if [[ $total_removed -gt 0 ]]; then
        print_success "已清理 ${total_removed} 条 UFW 旧规则"
        log_action "Migrated fail2ban: deleted $total_removed UFW rules, switched to ipset"
    else
        print_warn "未能删除任何 UFW 旧规则"
    fi
}

_f2b_active_jails() {
    fail2ban-client status 2>/dev/null | awk -F: '/Jail list/ {gsub(/[[:space:]]/, "", $2); gsub(/,/, " ", $2); print $2; exit}'
}

_f2b_banned_ips_for_jail() {
    local jail="$1"
    fail2ban-client status "$jail" 2>/dev/null | sed -n 's/^[[:space:]|`-]*Banned IP list:[[:space:]]*//p' | xargs
}

f2b_status() {
    print_title "Fail2ban 状态"
    if ! command_exists fail2ban-client; then
        print_error "Fail2ban 未安装。"
        pause
        return
    fi
    echo -e "${C_CYAN}[服务状态]${C_RESET}"
    if is_systemd; then
        systemctl status fail2ban --no-pager -l 2>/dev/null | head -n 5 || echo "服务未运行"
    fi
    # Show all active jails
    local jails
    jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ')
    if [[ -z "$jails" ]]; then
        print_warn "没有活跃的 jail"
        pause; return
    fi
    echo -e "${C_CYAN}[活跃 Jail]${C_RESET} $jails"
    echo ""
    local IFS=','
    for jail in $jails; do
        unset IFS
        echo -e "${C_CYAN}[$jail]${C_RESET}"
        local status_out cur_banned total_banned banned_ips
        status_out=$(fail2ban-client status "$jail" 2>/dev/null)
        cur_banned=$(echo "$status_out" | grep "Currently banned" | awk '{print $NF}')
        total_banned=$(echo "$status_out" | grep "Total banned" | awk '{print $NF}')
        banned_ips=$(echo "$status_out" | sed -n 's/^[[:space:]|`-]*Banned IP list:[[:space:]]*//p' | xargs)
        echo "  当前封禁: ${cur_banned:-0} | 累计封禁: ${total_banned:-0}"
        if [[ -n "$banned_ips" && "$banned_ips" != " " ]]; then
            echo "  封禁 IP: $banned_ips"
        fi
    done
    unset IFS
    # Show ignoreip if configured
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        local ignore
        ignore=$(grep '^ignoreip' "$FAIL2BAN_JAIL_LOCAL" | cut -d= -f2 | xargs)
        [[ -n "$ignore" ]] && echo -e "\n${C_CYAN}[白名单]${C_RESET} $ignore"
    fi
    pause
}

f2b_unban() {
    print_title "解封 IP 地址"
    if ! command_exists fail2ban-client; then
        print_error "Fail2ban 未安装。"
        pause
        return
    fi
    echo -e "${C_CYAN}当前封禁的 IP:${C_RESET}"
    local jails jail ip ips total=0
    jails=$(_f2b_active_jails)
    if [[ -z "$jails" ]]; then
        print_warn "没有活跃的 jail。"
        pause
        return
    fi
    for jail in $jails; do
        ips=$(_f2b_banned_ips_for_jail "$jail")
        for ip in $ips; do
            [[ -z "$ip" || "$ip" == "0" ]] && continue
            total=$((total + 1))
            printf "%2d. [%s] %s\n" "$total" "$jail" "$ip"
        done
    done
    if [[ "$total" -eq 0 ]]; then
        print_warn "当前没有被封禁的 IP。"
        pause
        return
    fi
    echo ""
    echo "输入选项:
  - 输入 IP 地址解封单个
  - 输入 'all' 解封所有
  - 输入 '0' 取消"
    read -e -r -p "请输入: " input
    if [[ "$input" == "0" || -z "$input" ]]; then
        return
    elif [[ "$input" == "all" ]]; then
        if confirm "确认解封所有 IP?"; then
            for jail in $jails; do
                ips=$(_f2b_banned_ips_for_jail "$jail")
                for ip in $ips; do
                    [[ -z "$ip" || "$ip" == "0" ]] && continue
                    fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null && \
                        print_success "已解封: $ip (jail=$jail)" || \
                        print_error "解封失败: $ip (jail=$jail)"
                done
            done
            log_action "Fail2ban: unbanned all IPs"
        fi
    else
        if ! validate_ip "$input"; then
            print_error "无效的 IP 地址格式。"
            pause; return
        fi
        local ok=0
        for jail in $jails; do
            ips=$(_f2b_banned_ips_for_jail "$jail")
            [[ " $ips " == *" $input "* ]] || continue
            if fail2ban-client set "$jail" unbanip "$input" 2>/dev/null; then
                print_success "已解封: $input (jail=$jail)"
                ok=1
            else
                print_error "解封失败: $input (jail=$jail)"
            fi
        done
        if [[ "$ok" -eq 1 ]]; then
            log_action "Fail2ban: unbanned $input"
        else
            print_error "解封失败，请检查 IP 是否仍在任一 jail 中。"
        fi
    fi
    pause
}

f2b_ban() {
    print_title "手动封禁 IP"
    if ! command_exists fail2ban-client; then
        print_error "Fail2ban 未安装。"
        pause; return
    fi
    # List active jails for selection
    local jails_raw
    jails_raw=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ')
    if [[ -z "$jails_raw" ]]; then
        print_warn "没有活跃的 jail"; pause; return
    fi
    local IFS=',' jail_arr=()
    for j in $jails_raw; do jail_arr+=("$j"); done
    unset IFS
    local target_jail="sshd"
    if [[ ${#jail_arr[@]} -gt 1 ]]; then
        echo "选择要封禁到哪个 jail:"
        local i=1
        for j in "${jail_arr[@]}"; do
            echo "  $i. $j"
            ((i++))
        done
        read -e -r -p "选择 [1]: " jidx
        jidx=${jidx:-1}
        if [[ "$jidx" =~ ^[0-9]+$ ]] && [[ "$jidx" -ge 1 && "$jidx" -le ${#jail_arr[@]} ]]; then
            target_jail="${jail_arr[$((jidx-1))]}"
        fi
    fi
    echo -e "目标 jail: ${C_CYAN}${target_jail}${C_RESET}"
    read -e -r -p "输入要封禁的 IP 地址 (空格分隔多个): " ip_input
    [[ -z "$ip_input" ]] && return
    for ip in $ip_input; do
        if ! validate_ip "$ip"; then
            print_error "无效 IP: $ip"; continue
        fi
        if fail2ban-client set "$target_jail" banip "$ip" 2>/dev/null; then
            print_success "已封禁: $ip (jail=$target_jail)"
            log_action "Fail2ban: manually banned $ip in $target_jail"
        else
            print_error "封禁失败: $ip"
        fi
    done
    pause
}

f2b_view_config() {
    print_title "当前 Fail2ban 配置"
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        echo -e "${C_CYAN}配置文件: $FAIL2BAN_JAIL_LOCAL${C_RESET}"
        draw_line
        cat "$FAIL2BAN_JAIL_LOCAL"
        draw_line
    else
        print_warn "配置文件不存在，使用系统默认配置。"
        echo "默认配置位置: /etc/fail2ban/jail.conf"
    fi
    pause
}

f2b_logs() {
    print_title "Fail2ban 日志"
    echo "1. 查看最近 50 条日志
2. 实时跟踪日志 (Ctrl+C 退出)
3. 查看封禁历史
0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            if [[ -f /var/log/fail2ban.log ]]; then
                tail -n 50 /var/log/fail2ban.log
            else
                journalctl -u fail2ban -n 50 --no-pager 2>/dev/null || echo "日志不可用"
            fi
            ;;
        2)
            print_info "按 Ctrl+C 退出..."
            if [[ -f /var/log/fail2ban.log ]]; then
                tail -f /var/log/fail2ban.log
            else
                journalctl -u fail2ban -f 2>/dev/null || echo "日志不可用"
            fi
            ;;
        3)
            echo -e "${C_CYAN}最近的封禁记录:${C_RESET}"
            if [[ -f /var/log/fail2ban.log ]]; then
                grep -E "Ban|Unban" /var/log/fail2ban.log | tail -n 30
            else
                journalctl -u fail2ban --no-pager 2>/dev/null | grep -E "Ban|Unban" | tail -n 30
            fi
            ;;
        0|"") return ;;
    esac
    pause
}

menu_f2b() {
    fix_terminal
    while true; do
        print_title "Fail2ban 入侵防御"
        if command_exists fail2ban-client; then
            if systemctl is-active fail2ban &>/dev/null; then
                local banned_count
                banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
                echo -e "${C_GREEN}状态: 运行中${C_RESET} | 当前封禁: ${banned_count:-0} 个 IP"
            else
                echo -e "${C_YELLOW}状态: 已安装但未运行${C_RESET}"
            fi
        else
            echo -e "${C_RED}状态: 未安装${C_RESET}"
        fi
        echo "1. 安装/重新配置 Fail2ban
2. 查看状态和封禁列表
3. 解封 IP 地址
4. 手动封禁 IP
5. 查看当前配置
6. 查看日志
7. 启动/停止服务
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) f2b_setup ;;
            2) f2b_status ;;
            3) f2b_unban ;;
            4) f2b_ban ;;
            5) f2b_view_config ;;
            6) f2b_logs ;;
            7)
                if ! command_exists fail2ban-client; then
                    print_error "Fail2ban 未安装。"
                    pause
                    continue
                fi
                echo "1. 启动"
                echo "2. 停止"
                echo "3. 重启"
                echo "0. 返回上一级"
                read -e -r -p "选择: " sc
                case $sc in
                    1) systemctl start fail2ban && print_success "已启动" || print_error "启动失败" ;;
                    2) systemctl stop fail2ban && print_success "已停止" || print_error "停止失败" ;;
                    3) systemctl restart fail2ban && print_success "已重启" || print_error "重启失败" ;;
                    0|q|Q|"") ;;
                    *) print_error "无效选项" ;;
                esac
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
# 仅更新 Fail2ban [sshd] jail 的 port，避免误改 nginx/http 等其他 jail。
_fail2ban_set_sshd_port() {
    local jail_file="$1" port="$2"
    [[ -f "$jail_file" ]] || return 1
    validate_port "$port" || return 1
    local tmpfile
    tmpfile=$(mktemp "$(dirname "$jail_file")/.tmp.fail2ban-sshd.XXXXXX") || return 1
    awk -v port="$port" '
        BEGIN { seen_sshd=0 }
        /^\[[^]]+\]/ {
            if (in_sshd && !done) { print "port = " port; done=1 }
            in_sshd=($0 == "[sshd]")
            if (in_sshd) seen_sshd=1
            print
            next
        }
        in_sshd && /^[[:space:]]*port[[:space:]]*=/ {
            print "port = " port
            done=1
            next
        }
        { print }
        END {
            if (in_sshd && !done) print "port = " port
            if (!seen_sshd) exit 2
        }
    ' "$jail_file" > "$tmpfile" || { rm -f "$tmpfile"; return 1; }
    chmod --reference="$jail_file" "$tmpfile" 2>/dev/null || true
    chown --reference="$jail_file" "$tmpfile" 2>/dev/null || true
    mv "$tmpfile" "$jail_file"
}

_ssh_socket_dropin_path() {
    local socket_unit="$1"
    printf '/etc/systemd/system/%s.d/server-manage-port.conf' "$socket_unit"
}

_ssh_socket_dropin_rollback() {
    local socket_dropin="${1:-}" socket_backup="${2:-}" socket_created="${3:-0}"
    [[ -n "$socket_dropin" ]] || return 0
    if [[ -n "$socket_backup" && -f "$socket_backup" ]]; then
        mv "$socket_backup" "$socket_dropin" 2>/dev/null || true
    elif [[ "$socket_created" -eq 1 ]]; then
        rm -f "$socket_dropin" 2>/dev/null || true
    fi
    systemctl daemon-reload 2>/dev/null || true
}

ssh_change_port() {
    print_title "修改 SSH 端口"
    refresh_ssh_port
    echo -e "${C_GRAY}当前生效端口 (sshd -T 解析): ${CURRENT_SSH_PORT}${C_RESET}"
    read -e -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    if ! validate_port "$port"; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi
    if [[ "$port" == "$CURRENT_SSH_PORT" ]]; then
        print_warn "新端口与当前端口相同，无需修改。"
        pause; return
    fi

    # 检查 drop-in 是否设置了 Port — 若设置了，sed 改主配是无效的
    local dropin_port_file=""
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        dropin_port_file=$(grep -lE "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1)
    fi
    local target_conf="$SSHD_CONFIG"
    if [[ -n "$dropin_port_file" ]]; then
        print_warn "Port 已在 drop-in 中配置（OpenSSH 优先生效）："
        echo "  - $dropin_port_file"
        echo ""
        echo "  1. 修改 drop-in 文件 (推荐)"
        echo "  2. 修改主配置 $SSHD_CONFIG（drop-in 仍会覆盖，可能无效）"
        echo "  0. 取消"
        read -e -r -p "选择 [1]: " dch
        case "${dch:-1}" in
            1) target_conf="$dropin_port_file" ;;
            2) target_conf="$SSHD_CONFIG" ;;
            *) print_warn "已取消"; pause; return ;;
        esac
    fi

    local socket_unit="" socket_dropin="" socket_backup="" socket_created=0
    if _ssh_socket_activation_active; then
        socket_unit=$(_ssh_socket_unit)
        print_warn "检测到 systemd ${socket_unit} socket activation。"
        print_warn "仅修改 sshd_config 不会改变真实监听端口，必须同步修改 ${socket_unit}。"
        if ! confirm "是否同步修改 ${socket_unit} 监听端口为 ${port}？"; then
            pause; return
        fi
    fi

    # 检查端口是否已被其他服务占用
    if command_exists ss && ss -tlpn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"; then
        local occupier=$(ss -tlpn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $NF}' | head -1)
        print_error "端口 $port 已被占用: $occupier"
        if ! confirm "是否强制继续修改？(可能导致冲突)"; then
            pause; return
        fi
    fi

    local backup_file="${target_conf}.bak.$(date +%s)"
    cp "$target_conf" "$backup_file"

    if [[ -n "$socket_unit" ]]; then
        socket_dropin=$(_ssh_socket_dropin_path "$socket_unit")
        local socket_dropin_dir
        socket_dropin_dir=$(dirname "$socket_dropin")
        mkdir -p "$socket_dropin_dir"
        if [[ -f "$socket_dropin" ]]; then
            socket_backup="${socket_dropin}.bak.$(date +%s)"
            cp "$socket_dropin" "$socket_backup"
        else
            socket_created=1
        fi
        local socket_tmp
        socket_tmp=$(mktemp "${socket_dropin_dir}/.tmp.server-manage.ssh-socket.XXXXXX") || {
            print_error "创建 SSH socket drop-in 临时文件失败，已回滚。"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        }
        _tmp_register "$socket_tmp"
        if ! cat > "$socket_tmp" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${port}
ListenStream=[::]:${port}
EOF
        then
            print_error "写入 SSH socket drop-in 失败，已回滚。"
            rm -f "$socket_tmp" 2>/dev/null || true
            _tmp_unregister "$socket_tmp"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        fi
        chmod 0644 "$socket_tmp" 2>/dev/null || true
        if ! mv "$socket_tmp" "$socket_dropin"; then
            print_error "安装 SSH socket drop-in 失败，已回滚。"
            rm -f "$socket_tmp" 2>/dev/null || true
            _tmp_unregister "$socket_tmp"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        fi
        _tmp_unregister "$socket_tmp"
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 先放行新端口（防止改完连不上）
    local ufw_opened=0 firewall_opened_backends=""
    if ufw_is_active; then
        if ! ufw allow "$port/tcp" comment "SSH-New" >/dev/null; then
            print_error "UFW 放行新 SSH 端口失败，已中止修改。"
            [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
            rm -f "$backup_file"
            pause; return 1
        fi
        ufw_opened=1
        print_success "UFW 已放行新端口 $port。"
    else
        if declare -F firewall_prepare_non_ufw_ssh_port >/dev/null; then
            if ! firewall_prepare_non_ufw_ssh_port "$port" "SSH-New"; then
                print_error "无法确认本地防火墙已放行新 SSH 端口，拒绝继续修改以避免失联。"
                print_info "请先手动放行 ${port}/tcp（云安全组 + 本机防火墙），再重试。"
                [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
                rm -f "$backup_file"
                pause; return 1
            fi
            firewall_opened_backends="$FIREWALL_SSH_OPEN_BACKENDS"
        else
            print_warn "未找到非 UFW 防火墙检测 helper；请确认云安全组/iptables/nftables 已放行 ${port}/tcp。"
            if ! confirm "仍要继续修改 SSH 端口？"; then
                pause; return
            fi
        fi
    fi

    # 写入端口配置。必须插入到首个 Match 块之前，否则只会作用于匹配块并导致 sshd -t 失败/配置无效。
    if ! _sshd_set_directive "Port" "$port" "$target_conf" 1; then
        print_error "写入 SSH 端口配置失败，已回滚。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        pause; return
    fi

    # 校验配置语法
    if ! sshd -t 2>/dev/null; then
        print_error "sshd 配置校验失败！已回滚。"
        mv "$backup_file" "$target_conf"
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        pause; return
    fi

    if ! _restart_sshd; then
        print_error "重启失败！已回滚配置。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        _restart_sshd || true
        pause; return
    fi

    local listen_ok=0 _try
    for _try in 1 2 3 4 5; do
        if _ssh_port_is_listening "$port"; then
            listen_ok=1
            break
        fi
        sleep 1
    done
    if [[ $listen_ok -ne 1 ]]; then
        print_error "重启后未检测到 SSH 在新端口 ${port}/tcp 监听，已回滚配置。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        _restart_sshd || true
        pause; return
    fi

    # 非 socket activation 模式下，再用 sshd -T 校验配置解析端口；socket 模式以真实监听为准。
    if [[ -z "$socket_unit" ]]; then
        local effective_port
        effective_port=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')
        if [[ "$effective_port" != "$port" ]]; then
            print_error "重启后 sshd -T 解析端口仍为 ${effective_port:-未知}，与目标 $port 不一致。"
            print_error "可能仍被其他 drop-in 文件覆盖。已回滚配置和本次新增防火墙规则。"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
            [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
            _restart_sshd || true
            pause; return
        fi
    fi

    print_success "SSH 重启成功，已确认新端口真实监听: $port"
    if [[ $ufw_opened -eq 1 ]]; then
        ufw delete allow "$CURRENT_SSH_PORT/tcp" 2>/dev/null || true
    fi
    # 同步更新 Fail2ban jail 端口
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        if _fail2ban_set_sshd_port "$FAIL2BAN_JAIL_LOCAL" "$port"; then
            systemctl restart fail2ban 2>/dev/null || true
            print_info "Fail2ban [sshd] 已同步新端口 $port"
        else
            print_warn "Fail2ban [sshd] 端口同步失败，请手动检查 $FAIL2BAN_JAIL_LOCAL"
        fi
    fi
    CURRENT_SSH_PORT=$port
    log_action "SSH port changed to $port (file=$target_conf socket=${socket_unit:-none})"
    rm -f "$backup_file" "$socket_backup"
    pause
}


ssh_keys() {
    print_title "SSH 密钥管理"
    echo "1. 导入公钥
2. 查看已部署的公钥
3. 删除指定公钥
4. 生成服务器密钥对
5. 禁用密码登录
0. 返回"
    read -e -r -p "选择: " c
    case $c in
    1)
        read -e -r -p "用户名: " user
        if ! id "$user" >/dev/null 2>&1; then 
            print_error "用户不存在"
            pause; return
        fi
        read -e -r -p "粘贴公钥: " key
        [[ -z "$key" ]] && return
        if [[ ! "$key" =~ ^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256))\ [A-Za-z0-9+/=]+ ]]; then
            print_error "公钥格式无效 (应以 ssh-rsa/ssh-ed25519/ecdsa-sha2 等开头)"
            pause; return
        fi
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        mkdir -p "$dir"
        if grep -qF "$key" "$dir/authorized_keys" 2>/dev/null; then
            print_warn "该公钥已存在，无需重复添加。"
            pause; return
        fi
        chmod 700 "$dir" 2>/dev/null || true
        chown "$user:$user" "$dir" 2>/dev/null || true
        _ssh_authorized_keys_append "$dir/authorized_keys" "$key" "$user:$user" || {
            print_error "公钥写入失败"
            pause; return
        }
        print_success "公钥已添加。"
        log_action "SSH key added for user $user"
        ;;
    2)
        read -e -r -p "用户名 [root]: " user
        user=${user:-root}
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        local ak="$dir/authorized_keys"
        if [[ ! -f "$ak" ]] || [[ ! -s "$ak" ]]; then
            print_warn "该用户没有部署任何公钥。"
            pause; return
        fi
        echo -e "${C_CYAN}[$user 的公钥列表]${C_RESET}"
        local idx=1
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            local fp=$(echo "$line" | ssh-keygen -l -f - 2>/dev/null)
            if [[ -n "$fp" ]]; then
                local bits=$(echo "$fp" | awk '{print $1}')
                local hash=$(echo "$fp" | awk '{print $2}')
                local comment=$(echo "$line" | awk '{print $NF}')
                local ktype=$(echo "$line" | awk '{print $1}')
                printf "  ${C_GREEN}%d.${C_RESET} %-12s %s位  %s  ${C_GRAY}%s${C_RESET}\n" "$idx" "$ktype" "$bits" "$hash" "$comment"
            else
                printf "  ${C_GREEN}%d.${C_RESET} %s\n" "$idx" "${line:0:80}"
            fi
            ((idx++)) || true
        done < "$ak"
        [[ $idx -eq 1 ]] && print_warn "无有效公钥"
        ;;
    3)
        read -e -r -p "用户名 [root]: " user
        user=${user:-root}
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        local ak="$dir/authorized_keys"
        if [[ ! -f "$ak" ]] || [[ ! -s "$ak" ]]; then
            print_warn "该用户没有部署任何公钥。"; pause; return
        fi
        # Show keys with index
        local keys=() idx=1
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            keys+=("$line")
            local comment=$(echo "$line" | awk '{print $NF}')
            local ktype=$(echo "$line" | awk '{print $1}')
            printf "  %d. %-12s %s\n" "$idx" "$ktype" "$comment"
            ((idx++)) || true
        done < "$ak"
        [[ ${#keys[@]} -eq 0 ]] && { print_warn "无公钥"; pause; return; }
        read -e -r -p "输入要删除的序号: " didx
        if [[ "$didx" =~ ^[0-9]+$ ]] && [[ "$didx" -ge 1 && "$didx" -le ${#keys[@]} ]]; then
            local target_key="${keys[$((didx-1))]}"
            if confirm "确认删除第 ${didx} 个公钥?"; then
                _ssh_authorized_keys_remove "$ak" "$target_key" "$user:$user" || { print_error "写入失败"; pause; return; }
                print_success "已删除。"
                log_action "SSH key deleted for user $user (index=$didx)"
            fi
        else
            print_error "无效序号"
        fi
        ;;
    4)
        echo -e "${C_CYAN}生成 Ed25519 密钥对 (用于服务器主动连接其他主机)${C_RESET}"
        read -e -r -p "备注信息 [留空跳过]: " comment
        local key_file="/root/.ssh/id_ed25519_server"
        if [[ -f "$key_file" ]]; then
            print_warn "密钥已存在: $key_file"
            if ! confirm "覆盖现有密钥?"; then pause; return; fi
        fi
        local args=(ssh-keygen -t ed25519 -f "$key_file" -N "")
        [[ -n "$comment" ]] && args+=(-C "$comment")
        "${args[@]}"
        echo ""
        print_success "密钥对已生成。"
        echo -e "${C_CYAN}私钥:${C_RESET} $key_file"
        echo -e "${C_CYAN}公钥:${C_RESET} ${key_file}.pub"
        echo ""
        echo -e "${C_CYAN}公钥内容 (复制到目标服务器的 authorized_keys):${C_RESET}"
        cat "${key_file}.pub"
        log_action "SSH keypair generated: $key_file"
        echo ""
        if confirm "是否将公钥导入本服务器的 authorized_keys?"; then
            read -e -r -p "导入到哪个用户 [root]: " imp_user
            imp_user=${imp_user:-root}
            if ! id "$imp_user" >/dev/null 2>&1; then
                print_error "用户不存在"; pause; return
            fi
            local imp_dir="/home/$imp_user/.ssh"
            [[ "$imp_user" == "root" ]] && imp_dir="/root/.ssh"
            mkdir -p "$imp_dir"
            local pub_key
            pub_key=$(cat "${key_file}.pub")
            if grep -qF "$pub_key" "$imp_dir/authorized_keys" 2>/dev/null; then
                print_warn "该公钥已存在，无需重复添加。"
            else
                chmod 700 "$imp_dir" 2>/dev/null || true
                chown "$imp_user:$imp_user" "$imp_dir" 2>/dev/null || true
                _ssh_authorized_keys_append "$imp_dir/authorized_keys" "$pub_key" "$imp_user:$imp_user" || {
                    print_error "公钥导入失败"
                    pause; return
                }
                print_success "公钥已导入 ${imp_user} 的 authorized_keys。"
                log_action "SSH pubkey auto-imported for user $imp_user from $key_file"
            fi
        fi
        ;;
    5)
        if ! _ssh_authorized_keys_available; then
            print_error "未检测到任何可登录用户的 authorized_keys，禁止关闭密码登录以避免锁外。"
            print_info "请先通过 [导入公钥] 部署并测试密钥登录。"
            pause; return
        fi
        if confirm "确认已测试密钥登录成功？"; then
            local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
            cp "$SSHD_CONFIG" "$backup_file"
            _sshd_set_directive "PasswordAuthentication" "no" "$SSHD_CONFIG" || { mv "$backup_file" "$SSHD_CONFIG"; pause; return; }
            if ! sshd -t 2>/dev/null; then
                print_error "sshd 配置校验失败！已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                pause; return
            fi
            local effective_password_auth
            effective_password_auth=$(_sshd_effective_value "passwordauthentication")
            if [[ "$effective_password_auth" != "no" ]]; then
                print_error "sshd -T 复验失败：PasswordAuthentication 实际为 ${effective_password_auth:-未知}，未生效。"
                print_error "可能被 /etc/ssh/sshd_config.d/*.conf 覆盖，已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                pause; return
            fi
            if ! _restart_sshd; then
                print_error "SSH 重启失败，已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                _restart_sshd || true
                pause; return
            fi
            rm -f "$backup_file"
            print_success "密码登录已禁用，并已通过 sshd -T 复验。"
            log_action "SSH password authentication disabled"
        fi
        ;;
    0|q) return ;;
    esac
    pause
}

menu_ssh() {
    fix_terminal
    while true; do
        print_title "SSH 安全管理 (当前端口: $CURRENT_SSH_PORT)"
        echo "1. 修改 SSH 端口
2. 创建 Sudo 用户
3. 禁用 Root 远程登录
4. 密钥管理 (导入/查看/删除/生成)
5. 修改用户密码
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) ssh_change_port ;;
            2) 
                read -e -r -p "新用户名: " u
                if [[ -n "$u" ]]; then
                    adduser "$u" && usermod -aG sudo "$u" && \
                    print_success "用户创建成功。" && \
                    log_action "Created sudo user: $u"
                fi
                pause ;;
            3)
                if ! _ssh_non_root_sudo_available; then
                    print_error "未检测到非 root sudo 用户，禁止禁用 Root 登录以避免锁外。"
                    print_info "请先通过 [创建 Sudo 用户] 创建并测试可登录用户。"
                    pause; continue
                fi
                if confirm "禁用 Root 登录？"; then
                    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
                    cp "$SSHD_CONFIG" "$backup_file"
                    _sshd_set_directive "PermitRootLogin" "no" "$SSHD_CONFIG" || { mv "$backup_file" "$SSHD_CONFIG"; pause; continue; }
                    if ! sshd -t 2>/dev/null; then
                        print_error "sshd 配置校验失败！已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        pause; continue
                    fi
                    local effective_root_login
                    effective_root_login=$(_sshd_effective_value "permitrootlogin")
                    if [[ "$effective_root_login" != "no" ]]; then
                        print_error "sshd -T 复验失败：PermitRootLogin 实际为 ${effective_root_login:-未知}，未生效。"
                        print_error "可能被 /etc/ssh/sshd_config.d/*.conf 覆盖，已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        pause; continue
                    fi
                    if ! _restart_sshd; then
                        print_error "SSH 重启失败，已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        _restart_sshd || true
                        pause; continue
                    fi
                    rm -f "$backup_file"
                    print_success "Root 登录已禁用，并已通过 sshd -T 复验。"
                    log_action "SSH root login disabled"
                fi
                pause ;;
            4) ssh_keys ;;
            5) 
                read -e -r -p "用户名 [root]: " u
                u=${u:-root}
                passwd "$u"
                pause ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
        refresh_ssh_port
    done
}
menu_update() {
    print_title "依赖检查与修复"
    print_info "强制重新检查所有依赖包..."
    local FULL_DEPS="curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iproute2 net-tools procps"
    local ufw_was_active=0
    local f2b_was_active=0
    if ufw_is_active; then
        ufw_was_active=1
    fi
    if systemctl is-active fail2ban &>/dev/null; then
        f2b_was_active=1
    fi
    print_info "1/2 更新软件源..."
    if apt-get update >/dev/null 2>&1; then
        print_success "软件源更新完成"
    else
        print_warn "软件源更新失败，但继续检查"
    fi
    print_info "2/2 检查并修复依赖包..."
    local installed=0
    local failed=0
    local ok_count=0
    local f2b_newly_installed=0
    for pkg in $FULL_DEPS; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo -e "  ${C_GREEN}✓${C_RESET} $pkg (正常)"
            ((ok_count++)) || true
        else
            echo -n "  → 正在安装 $pkg ... "
            if (DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1); then
                echo -e "${C_GREEN}成功${C_RESET}"
                ((installed++)) || true
                [[ "$pkg" == "fail2ban" ]] && f2b_newly_installed=1
            else
                echo -e "${C_RED}失败${C_RESET}"
                ((failed++)) || true
            fi
        fi
    done
    echo "================================================================================"
    print_success "依赖检查完成"
    echo "  正常: $ok_count 个 | 新安装: $installed 个"
    [[ $failed -gt 0 ]] && echo -e "  ${C_RED}失败: $failed 个${C_RESET}"
    # 更新状态文件
    _deps_save_state "$FULL_DEPS"
    # 恢复之前的服务状态
    if [[ $ufw_was_active -eq 1 ]]; then
        ufw --force enable >/dev/null 2>&1 || true
    fi
    if [[ $f2b_was_active -eq 1 ]]; then
        systemctl start fail2ban >/dev/null 2>&1 || true
    elif [[ $f2b_newly_installed -eq 1 ]]; then
        # Debian/Ubuntu 安装 fail2ban 后可能立即启动默认 sshd jail。
        # 自动依赖检查只负责安装，不应静默启用封禁策略。
        systemctl disable --now fail2ban >/dev/null 2>&1 || systemctl stop fail2ban >/dev/null 2>&1 || true
    fi
    echo "================================================================================"
    log_action "Dependencies checked/repaired manually"
    pause
}

_deps_save_state() {
    local deps="$1"
    local state_dir="/etc/server-manage"
    mkdir -p "$state_dir"
    # 记录包列表签名和时间
    local pkg_hash
    pkg_hash=$(echo "$deps" | md5sum | awk '{print $1}')
    echo "checked=$(date '+%Y-%m-%d %H:%M:%S')|hash=$pkg_hash" > "$state_dir/.deps-ok"
    chmod 600 "$state_dir/.deps-ok"
}

auto_deps() {
    local FULL_DEPS="curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iproute2 net-tools procps"
    local state_file="/etc/server-manage/.deps-ok"

    # 快速路径: 状态文件存在时只做轻量级验证
    if [[ -f "$state_file" ]]; then
        local missing=0
        for pkg in $FULL_DEPS; do
            if ! dpkg -s "$pkg" &>/dev/null; then
                missing=1
                break
            fi
        done
        [[ $missing -eq 0 ]] && return 0
        # 有缺失则进入修复流程
        print_warn "检测到依赖缺失，正在自动修复..."
    fi

    # 完整安装/修复流程
    print_info "正在检查并安装基础依赖..."
    local ufw_was_active=0
    local f2b_was_active=0
    if ufw_is_active; then
        ufw_was_active=1
    fi
    if systemctl is-active fail2ban &>/dev/null; then
        f2b_was_active=1
    fi
    apt-get update >/dev/null 2>&1 || true
    local installed=0
    local failed=0
    local ufw_newly_installed=0
    local f2b_newly_installed=0
    for pkg in $FULL_DEPS; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo "  ✓ $pkg (已安装)"
        else
            echo -n "  → 正在安装 $pkg ... "
            if (DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1); then
                echo -e "${C_GREEN}成功${C_RESET}"
                ((installed++)) || true
                [[ "$pkg" == "ufw" ]] && ufw_newly_installed=1
                [[ "$pkg" == "fail2ban" ]] && f2b_newly_installed=1
            else
                echo -e "${C_RED}失败${C_RESET}"
                ((failed++)) || true
            fi
        fi
    done
    if [[ $installed -gt 0 || $failed -gt 0 ]]; then
        print_success "依赖安装完成 (新安装: $installed 个)"
        [[ $failed -gt 0 ]] && print_warn "失败: $failed 个"
        # 只有当 ufw/fail2ban 是本次新安装且之前未运行时才提示
        local hints=()
        if [[ $ufw_newly_installed -eq 1 && $ufw_was_active -eq 0 ]]; then
            hints+=("菜单 [2] 配置 UFW")
        fi
        if [[ $f2b_newly_installed -eq 1 && $f2b_was_active -eq 0 ]]; then
            hints+=("菜单 [3] 配置 Fail2ban")
        fi
        if [[ ${#hints[@]} -gt 0 ]]; then
            echo -e "${C_YELLOW}提示:${C_RESET} 安全服务已安装但未自动启用"
            echo "  请通过 $(IFS='、'; echo "${hints[*]}")"
        fi
    fi
    # 恢复之前的服务状态
    if [[ $ufw_was_active -eq 1 ]]; then
        ufw --force enable >/dev/null 2>&1 || true
    fi
    if [[ $f2b_was_active -eq 1 ]]; then
        systemctl start fail2ban >/dev/null 2>&1 || true
    elif [[ $f2b_newly_installed -eq 1 ]]; then
        # apt 安装 fail2ban 后可能立即启动默认 sshd jail；自动依赖检查不启用策略。
        systemctl disable --now fail2ban >/dev/null 2>&1 || systemctl stop fail2ban >/dev/null 2>&1 || true
    fi
    # 保存状态
    _deps_save_state "$FULL_DEPS"
    log_action "Dependencies auto-checked (installed=$installed failed=$failed)"
}

update_apt_cache() {
    if [[ $APT_UPDATED -eq 0 ]]; then
        print_info "更新软件源缓存..."
        apt-get update >/dev/null 2>&1
        APT_UPDATED=1
    fi
}

install_package() {
    local pkg="$1"
    local silent="${2:-}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        if opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
            [[ "$silent" != "silent" ]] && print_warn "$pkg 已安装，跳过。"
            return 0
        fi
        [[ "$silent" != "silent" ]] && print_info "正在安装 $pkg (opkg)..."
        opkg update >/dev/null 2>&1
        if opkg install "$pkg" >/dev/null 2>&1; then
            [[ "$silent" != "silent" ]] && print_success "$pkg 安装成功。"
            log_action "Installed package (opkg): $pkg"
            return 0
        else
            print_error "安装 $pkg 失败 (opkg)。"
            return 1
        fi
    fi
    if dpkg -s "$pkg" &> /dev/null; then
        [[ "$silent" != "silent" ]] && print_warn "$pkg 已安装，跳过。"
        return 0
    fi
    [[ "$silent" != "silent" ]] && print_info "正在安装 $pkg ..."
    update_apt_cache
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
        print_warn "首次安装失败，尝试修复依赖..."
        apt-get install -f -y >/dev/null 2>&1
        if ! apt-get install -y "$pkg" >/dev/null 2>&1; then
            print_error "安装 $pkg 失败。"
            return 1
        fi
    fi
    [[ "$silent" != "silent" ]] && print_success "$pkg 安装成功。"
    log_action "Installed package: $pkg"
    return 0
}

check_port_usage() {
    print_title "本机端口监听状态"
    command_exists ss || command_exists netstat || install_package "iproute2"
    local awk_logic='
    function get_purpose(p) {
        if(p==21)return "FTP"; if(p==22)return "SSH"; if(p==25)return "SMTP";
        if(p==53)return "DNS"; if(p==80)return "HTTP"; if(p==443)return "HTTPS";
        if(p==3128)return "Squid"; if(p==3306)return "MySQL"; if(p==5201)return "iPerf3"; 
        if(p==5432)return "PostgreSQL"; if(p==6379)return "Redis"; if(p==8080)return "Web Alt";
        return "Unknown";
    }
    '
    printf "${C_BLUE}%-6s | %-6s | %-16s | %s${C_RESET}\n" "Proto" "Port" "Purpose" "Process"
    draw_line
    if command_exists ss; then
        ss -tulpn | awk "$awk_logic"' 
        $2~/LISTEN|UNCONN/ {
            proto=$1
            split($5,a,":"); port=a[length(a)]
            split($NF,b,"\""); name=(length(b)>=2)?b[2]:"Unknown"
            printf "%-6s | %-6s | %-16s | %s\n", proto, port, get_purpose(port), name
        }' | sort -u -t'|' -k2,2n || true
    elif command_exists netstat; then
        netstat -tulpn | awk "$awk_logic"'
        /LISTEN|udp/ {
            proto=$1
            split($4,a,":"); port=a[length(a)]
            split($7,b,"/"); name=(b[2]=="")?"Unknown":b[2]
            printf "%-6s | %-6s | %-16s | %s\n", proto, port, get_purpose(port), name
        }' | sort -u -t'|' -k2,2n || true
    fi
    pause
}


opt_cleanup() {
    print_title "系统清理"
    print_info "正在清理..."
    apt-get autoremove -y >/dev/null 2>&1 || true
    apt-get autoclean -y >/dev/null 2>&1 || true
    apt-get clean >/dev/null 2>&1 || true
    journalctl --vacuum-time=7d >/dev/null 2>&1 || true
    print_success "清理完成。"
    log_action "System cleanup completed"
    pause
}

_hostname_file_path() {
    printf '%s' "/etc/hostname"
}

_hosts_file_path() {
    printf '%s' "/etc/hosts"
}

_hostname_write_file() {
    local new_name="$1"
    write_file_atomic "$(_hostname_file_path)" "$new_name"
}

_hostname_render_hosts_conf() {
    local hosts_file="$1" old_name="$2" new_name="$3"
    awk -v old="$old_name" -v new="$new_name" '
        function first_field(text, fields, count, i) {
            count = split(text, fields, /[[:space:]]+/)
            for (i = 1; i <= count; i++) {
                if (fields[i] != "") return fields[i]
            }
            return ""
        }
        function render_line(line, add_new,   hash, head, comment, leading, rest, count, i, token, out, seen, has_new) {
            hash = index(line, "#")
            if (hash) {
                head = substr(line, 1, hash - 1)
                comment = substr(line, hash)
            } else {
                head = line
                comment = ""
            }
            if (head ~ /^[[:space:]]*$/) return line
            match(head, /^[[:space:]]*/)
            leading = substr(head, RSTART, RLENGTH)
            rest = substr(head, length(leading) + 1)
            count = split(rest, fields, /[[:space:]]+/)
            if (count < 1 || fields[1] == "") return line
            out = leading fields[1]
            has_new = 0
            delete seen
            for (i = 2; i <= count; i++) {
                token = fields[i]
                if (token == "") continue
                if (old != "" && old != new && token == old) token = new
                if (token == new) has_new = 1
                if (!(token in seen)) {
                    out = out " " token
                    seen[token] = 1
                }
            }
            if (add_new && fields[1] == "127.0.0.1" && !has_new) {
                out = out " " new
                has_new = 1
            }
            if (has_new) saw_new = 1
            return out (comment != "" ? " " comment : "")
        }
        { rendered[NR] = render_line($0, 0) }
        END {
            target = 0
            if (!saw_new) {
                for (i = 1; i <= NR; i++) {
                    hash = index(rendered[i], "#")
                    head = hash ? substr(rendered[i], 1, hash - 1) : rendered[i]
                    if (first_field(head) == "127.0.0.1") {
                        target = i
                        break
                    }
                }
            }
            for (i = 1; i <= NR; i++) {
                if (i == target) print render_line(rendered[i], 1)
                else print rendered[i]
            }
            if (!saw_new && target == 0) {
                print "127.0.0.1 localhost " new
            }
        }
    ' "$hosts_file" 2>/dev/null || {
        printf '127.0.0.1 localhost %s\n' "$new_name"
    }
}

_hostname_update_hosts() {
    local old_name="$1" new_name="$2" hosts_file content
    hosts_file="$(_hosts_file_path)"
    content="$(_hostname_render_hosts_conf "$hosts_file" "$old_name" "$new_name")" || return 1
    write_file_atomic "$hosts_file" "$content"
}

opt_hostname() {
    print_title "修改主机名"
    echo "当前: $(hostname)"
    read -e -r -p "请输入新主机名: " new_name
    [[ -z "$new_name" ]] && return
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
        print_error "主机名格式无效。"
        pause; return
    fi
    # 先保存旧主机名，再执行修改
    local old_name
    old_name=$(hostname 2>/dev/null || true)
    if [[ "$PLATFORM" == "openwrt" ]]; then
        if ! command_exists uci; then
            print_error "OpenWrt 缺少 uci，无法持久化主机名。"
            pause; return 1
        fi
        if ! uci set system.@system[0].hostname="$new_name" || ! uci commit system; then
            print_error "OpenWrt 主机名写入 uci 失败。"
            pause; return 1
        fi
        hostname "$new_name" 2>/dev/null || true
        /etc/init.d/system reload >/dev/null 2>&1 || true
    elif command_exists hostnamectl; then
        hostnamectl set-hostname "$new_name" || { print_error "hostnamectl 设置失败。"; pause; return 1; }
    else
        local hostname_file old_hostname_file had_hostname_file=0
        hostname_file="$(_hostname_file_path)"
        if [[ -f "$hostname_file" ]]; then
            old_hostname_file=$(cat "$hostname_file")
            had_hostname_file=1
        else
            old_hostname_file=""
        fi
        _hostname_write_file "$new_name" || { print_error "/etc/hostname 写入失败。"; pause; return 1; }
        if ! hostname "$new_name"; then
            if [[ "$had_hostname_file" -eq 1 ]]; then
                write_file_atomic "$hostname_file" "$old_hostname_file" >/dev/null 2>&1 || true
            else
                rm -f "$hostname_file" 2>/dev/null || true
            fi
            print_error "临时主机名设置失败。"
            pause; return 1
        fi
    fi

    if ! _hostname_update_hosts "$old_name" "$new_name"; then
        print_warn "主机名已设置，但 /etc/hosts 更新失败，请手动检查。"
        pause; return 1
    fi
    print_success "主机名已修改为: $new_name"
    log_action "Hostname changed to $new_name"
    pause
}

_swap_file_path() {
    printf '%s' "/swapfile"
}

_swap_fstab_path() {
    printf '%s' "/etc/fstab"
}

_swap_fstab_has_swapfile() {
    local swap_file="$(_swap_file_path)" fstab="$(_swap_fstab_path)"
    [[ -f "$fstab" ]] || return 1
    awk -v sf="$swap_file" '$1 == sf && $3 == "swap" { found=1 } END { exit(found ? 0 : 1) }' "$fstab"
}

_swap_fstab_add_swapfile() {
    local swap_file="$(_swap_file_path)" fstab="$(_swap_fstab_path)" fstab_dir tmp
    _swap_fstab_has_swapfile && return 0
    fstab_dir="$(dirname "$fstab")"
    mkdir -p "$fstab_dir" || return 1
    tmp=$(mktemp "${fstab_dir}/.tmp.server-manage.fstab.XXXXXX") || return 1
    _tmp_register "$tmp"
    if [[ -f "$fstab" ]]; then
        awk -v sf="$swap_file" '
            { print; if ($1 == sf && $3 == "swap") found=1 }
            END { if (!found) printf "%s none swap sw 0 0\n", sf }
        ' "$fstab" > "$tmp" || {
            rm -f "$tmp"
            _tmp_unregister "$tmp"
            return 1
        }
        chmod --reference="$fstab" "$tmp" 2>/dev/null || true
        chown --reference="$fstab" "$tmp" 2>/dev/null || true
    else
        printf '%s none swap sw 0 0\n' "$swap_file" > "$tmp" || {
            rm -f "$tmp"
            _tmp_unregister "$tmp"
            return 1
        }
        chmod 644 "$tmp" 2>/dev/null || true
    fi
    if ! mv "$tmp" "$fstab"; then
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi
    _tmp_unregister "$tmp"
}

_swap_fstab_remove_swapfile() {
    local swap_file="$(_swap_file_path)" fstab="$(_swap_fstab_path)" tmp
    [[ -f "$fstab" ]] || return 0
    tmp=$(mktemp "$(dirname "$fstab")/.tmp.server-manage.fstab.XXXXXX") || return 1
    _tmp_register "$tmp"
    awk -v sf="$swap_file" '!($1 == sf && $3 == "swap")' "$fstab" > "$tmp" || {
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    }
    chmod --reference="$fstab" "$tmp" 2>/dev/null || true
    chown --reference="$fstab" "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$fstab"; then
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi
    _tmp_unregister "$tmp"
}

opt_swap() {
    print_title "Swap 管理"
    local size=$(free -m | awk '/Swap/ {print $2}')
    local swap_file="$(_swap_file_path)"
    echo "当前 Swap: ${size}MB"
    echo ""
    echo "1. 开启/修改 Swap
2. 关闭/删除 Swap
0. 返回"
    read -e -r -p "选择: " c
    if [[ "$c" == "1" ]]; then
        read -e -r -p "大小 (MB): " s
        if [[ ! "$s" =~ ^[0-9]+$ ]] || [ "$s" -lt 128 ]; then
            print_error "大小无效 (最小 128MB)。"
            pause; return
        fi
        print_info "正在设置 ${s}MB Swap..."
        swapoff "$swap_file" 2>/dev/null || true
        rm -f "$swap_file"
        # 检测文件系统类型，btrfs 不支持 fallocate 创建 swap
        local fs_type=$(df -T / 2>/dev/null | awk 'NR==2{print $2}')
        if [[ "$fs_type" == "btrfs" ]]; then
            truncate -s 0 "$swap_file"
            chattr +C "$swap_file" 2>/dev/null || true
            if ! dd if=/dev/zero of="$swap_file" bs=1M count="$s" status=progress; then
                print_error "创建 Swap 文件失败 (磁盘空间不足?)"; rm -f "$swap_file"; pause; return
            fi
        elif ! fallocate -l "${s}M" "$swap_file" 2>/dev/null; then
            if ! dd if=/dev/zero of="$swap_file" bs=1M count="$s" status=progress; then
                print_error "创建 Swap 文件失败 (磁盘空间不足?)"; rm -f "$swap_file"; pause; return
            fi
        fi
        chmod 600 "$swap_file"
        if ! mkswap "$swap_file" >/dev/null; then
            print_error "mkswap 失败"; rm -f "$swap_file"; pause; return
        fi
        if ! swapon "$swap_file"; then
            print_error "swapon 失败"; rm -f "$swap_file"; pause; return
        fi
        _swap_fstab_add_swapfile || { print_error "写入 fstab 失败"; pause; return; }
        print_success "Swap 设置成功。"
        log_action "Swap configured: ${s}MB"
    elif [[ "$c" == "2" ]]; then
        if confirm "确认删除 Swap？"; then
            swapoff "$swap_file" 2>/dev/null || true
            rm -f "$swap_file"
            _swap_fstab_remove_swapfile || { print_error "更新 fstab 失败"; pause; return; }
            print_success "Swap 已删除。"
            log_action "Swap removed"
        fi
    fi
    pause
}

opt_bbr() {
    print_title "BBR 加速"
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
    local available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
    echo "当前配置:"
    echo "  拥塞控制: $current_cc"
    echo "  队列算法: $current_qdisc"
    if [[ "$current_cc" == "bbr" && "$current_qdisc" == "fq" ]]; then
        print_success "BBR + fq 已启用。"
        pause; return
    fi
    if [[ " $available_cc " != *" bbr "* ]]; then
        print_error "当前内核未暴露 bbr 拥塞控制算法。"
        pause; return 1
    fi
    if [[ "$current_cc" == "bbr" && "$current_qdisc" != "fq" ]]; then
        print_warn "BBR 已启用，但队列算法不是 fq，建议一并修正。"
    fi
    if confirm "写入 BBR + fq 到托管 sysctl.d 配置？"; then
        local params
        params="$(_sysctl_render_bbr_conf "$(_sysctl_tuning_conf_path)" "fq" "bbr")"
        _sysctl_commit_tuning "$params" "bbr" "not-applicable" "BBR acceleration" || {
            pause; return 1
        }
        log_action "BBR enabled via sysctl.d"
    fi
    pause
}

select_timezone() {
    echo "1.上海 2.香港 3.东京 4.纽约 5.伦敦 6.UTC"
    read -e -r -p "选择: " t
    local z tz
    case $t in
        1) z="Asia/Shanghai"; tz="CST-8" ;;
        2) z="Asia/Hong_Kong"; tz="HKT-8" ;;
        3) z="Asia/Tokyo"; tz="JST-9" ;;
        4) z="America/New_York"; tz="EST5EDT,M3.2.0,M11.1.0" ;;
        5) z="Europe/London"; tz="GMT0BST,M3.5.0/1,M10.5.0" ;;
        6) z="UTC"; tz="UTC0" ;;
        *) print_error "无效选择"; return 1 ;;
    esac
    if [[ "$PLATFORM" == "openwrt" ]]; then
        if ! command_exists uci; then
            print_error "OpenWrt 缺少 uci，无法持久化时区。"
            return 1
        fi
        if ! uci set system.@system[0].zonename="$z" || \
           ! uci set system.@system[0].timezone="$tz" || \
           ! uci commit system; then
            print_error "OpenWrt 时区写入 uci 失败。"
            return 1
        fi
        /etc/init.d/system reload >/dev/null 2>&1 || true
    elif command_exists timedatectl; then
        timedatectl set-timezone "$z" || { print_error "timedatectl 设置时区失败。"; return 1; }
    else
        [[ -f "/usr/share/zoneinfo/$z" ]] || { print_error "zoneinfo 不存在: /usr/share/zoneinfo/$z"; return 1; }
        ln -sf "/usr/share/zoneinfo/$z" /etc/localtime || { print_error "写入 /etc/localtime 失败。"; return 1; }
    fi
    print_success "时区已设为 $z"
    log_action "Timezone changed to $z"
}

_sysctl_conf_path() {
    printf '%s' "${SERVER_MANAGE_SYSCTL_CONF:-/etc/sysctl.conf}"
}

_sysctl_d_dir_path() {
    if [[ -n "${SERVER_MANAGE_SYSCTL_D_DIR:-}" ]]; then
        printf '%s' "$SERVER_MANAGE_SYSCTL_D_DIR"
        return
    fi
    if [[ "$(_sysctl_conf_path)" != "/etc/sysctl.conf" ]]; then
        printf '%s/sysctl.d' "$(dirname "$(_sysctl_conf_path)")"
        return
    fi
    printf '%s' "/etc/sysctl.d"
}

_sysctl_tuning_conf_path() {
    printf '%s/99zz-server-manage-tuning.conf' "$(_sysctl_d_dir_path)"
}

_sysctl_tuning_profile_path() {
    printf '%s/99zz-server-manage-tuning.profile.md' "$(_sysctl_d_dir_path)"
}

_sysctl_backup_dir_path() {
    if [[ -n "${SERVER_MANAGE_SYSCTL_BACKUP_DIR:-}" ]]; then
        printf '%s' "$SERVER_MANAGE_SYSCTL_BACKUP_DIR"
        return
    fi
    if [[ "$(_sysctl_conf_path)" != "/etc/sysctl.conf" ]]; then
        printf '%s/sysctl-backups' "$(dirname "$(_sysctl_conf_path)")"
        return
    fi
    printf '%s' "/etc/server-manage/sysctl-backups"
}

_sysctl_rollback_path() {
    if [[ -n "${SERVER_MANAGE_SYSCTL_ROLLBACK:-}" ]]; then
        printf '%s' "$SERVER_MANAGE_SYSCTL_ROLLBACK"
        return
    fi
    if [[ "$(_sysctl_conf_path)" != "/etc/sysctl.conf" ]]; then
        printf '%s/server-manage-sysctl.rollback.conf' "$(dirname "$(_sysctl_conf_path)")"
        return
    fi
    printf '%s' "/etc/server-manage/sysctl-tuning.rollback.conf"
}

_sysctl_latest_snapshot_path() {
    if [[ -n "${SERVER_MANAGE_SYSCTL_LATEST_SNAPSHOT:-}" ]]; then
        printf '%s' "$SERVER_MANAGE_SYSCTL_LATEST_SNAPSHOT"
        return
    fi
    if [[ "$(_sysctl_conf_path)" != "/etc/sysctl.conf" ]]; then
        printf '%s/server-manage-sysctl.latest-snapshot' "$(dirname "$(_sysctl_conf_path)")"
        return
    fi
    printf '%s' "/etc/server-manage/sysctl-tuning.latest-snapshot"
}

_sysctl_backup_path() {
    printf '%s.pre-tuning' "$(_sysctl_conf_path)"
}

_sysctl_bbr_backup_path() {
    printf '%s.bak' "$(_sysctl_conf_path)"
}

_sysctl_render_tuned_conf() {
    local conf_file="$1" params="$2"
    if [[ -f "$conf_file" ]]; then
        awk '
            /^# BEGIN server-manage sysctl tuning/ { in_new=1; next }
            in_new {
                if (/^# END server-manage sysctl tuning/) in_new=0
                next
            }
            /^# server-manage sysctl tuning/ { in_legacy=1; next }
            in_legacy {
                if ($0 == "") in_legacy=0
                next
            }
            { print }
        ' "$conf_file"
    fi
    printf '\n%s\n' "$params"
}

_sysctl_normalize_value() {
    awk '{$1=$1; print}' <<< "${1:-}"
}

_sysctl_read_value() {
    local key="$1"
    sysctl -n "$key" 2>/dev/null || printf 'N/A'
}

_sysctl_main_iface() {
    local iface=""
    if command_exists ip; then
        iface=$(ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}')
        [[ -n "$iface" ]] || iface=$(ip route 2>/dev/null | awk '/^default/ {print $5; exit}')
    fi
    printf '%s' "$iface"
}

_sysctl_extract_keys_from_params() {
    local params="$1"
    awk -F= '
        /^[[:space:]]*[A-Za-z0-9_.-]+[[:space:]]*=/ {
            key=$1
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key != "") print key
        }
    ' <<< "$params" | awk '!seen[$0]++'
}

_sysctl_render_runtime_rollback_conf() {
    local params="$1" label="${2:-manual}" key value
    printf '# server-manage runtime rollback for %s\n' "$label"
    printf '# captured_at = %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    while IFS= read -r key; do
        [[ -n "$key" ]] || continue
        value=$(sysctl -n "$key" 2>/dev/null || true)
        [[ -n "$value" ]] || continue
        printf '%s = %s\n' "$key" "$value"
    done < <(_sysctl_extract_keys_from_params "$params")
}

_sysctl_render_conf_without_keys() {
    local conf_file="$1" keys="$2"
    [[ -f "$conf_file" ]] || return 0
    awk -v keys="$keys" '
        BEGIN {
            n = split(keys, k, /\n/)
            for (i = 1; i <= n; i++) if (k[i] != "") skip[k[i]] = 1
        }
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { print; next }
        {
            line = $0
            sub(/[[:space:]]*#.*/, "", line)
            split(line, parts, "=")
            key = parts[1]
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
            if (key in skip) {
                print "# server-manage moved to sysctl.d: " $0
                next
            }
            print
        }
    ' "$conf_file"
}

_sysctl_snapshot_create() {
    local ts="${1:-$(date '+%Y%m%d-%H%M%S')}" backup_parent backup_root conf_file sysctl_d f i=0
    backup_parent="$(_sysctl_backup_dir_path)"
    backup_root="${backup_parent}/$ts"
    conf_file="$(_sysctl_conf_path)"
    sysctl_d="$(_sysctl_d_dir_path)"
    mkdir -p "$backup_parent" || return 1
    while ! mkdir "$backup_root" 2>/dev/null; do
        [[ -e "$backup_root" ]] || return 1
        i=$((i + 1))
        backup_root="${backup_parent}/${ts}-${i}"
    done
    mkdir -p "${backup_root}/sysctl.d" || return 1
    if [[ -f "$conf_file" ]]; then
        cp -a "$conf_file" "${backup_root}/sysctl.conf" || return 1
    else
        : > "${backup_root}/sysctl.conf.missing" || return 1
    fi
    if [[ -d "$sysctl_d" ]]; then
        for f in "$sysctl_d"/*.conf; do
            [[ -e "$f" ]] || continue
            cp -a "$f" "${backup_root}/sysctl.d/" || return 1
        done
    else
        : > "${backup_root}/sysctl.d.missing" || return 1
    fi
    printf '%s' "$backup_root"
}

_sysctl_restore_managed_snapshot() {
    local backup_root="$1" conf_file tuning_conf tuning_base ts
    [[ -n "$backup_root" && -d "$backup_root" ]] || return 1
    conf_file="$(_sysctl_conf_path)"
    tuning_conf="$(_sysctl_tuning_conf_path)"
    tuning_base="$(basename "$tuning_conf")"
    ts=$(date '+%Y%m%d-%H%M%S')
    if [[ -f "${backup_root}/sysctl.conf" ]]; then
        cp -a "${backup_root}/sysctl.conf" "$conf_file" 2>/dev/null || return 1
    elif [[ -f "${backup_root}/sysctl.conf.missing" ]]; then
        rm -f "$conf_file" 2>/dev/null || true
    fi
    if [[ -f "${backup_root}/sysctl.d/${tuning_base}" ]]; then
        mkdir -p "$(dirname "$tuning_conf")" || return 1
        cp -a "${backup_root}/sysctl.d/${tuning_base}" "$tuning_conf" || return 1
    elif [[ -f "$tuning_conf" ]]; then
        mv "$tuning_conf" "${tuning_conf}.failed-${ts}" 2>/dev/null || return 1
    fi
}

_sysctl_read_latest_snapshot() {
    local latest_file snapshot backup_dir
    latest_file="$(_sysctl_latest_snapshot_path)"
    [[ -f "$latest_file" ]] || return 1
    snapshot=$(head -n 1 "$latest_file" 2>/dev/null || true)
    backup_dir="$(_sysctl_backup_dir_path)"
    case "$snapshot" in
        "$backup_dir"/*)
            [[ -d "$snapshot" ]] || return 1
            printf '%s' "$snapshot"
            ;;
        *)
            return 1
            ;;
    esac
}

_sysctl_cleanup_registered_paths() {
    local path
    for path in "$@"; do
        [[ -n "${path:-}" ]] || continue
        rm -f -- "$path" 2>/dev/null || true
        _tmp_unregister "$path"
    done
}

_sysctl_restore_metadata_backups() {
    local rollback_path="$1" rollback_backup="$2" rollback_existed="$3"
    local latest_path="$4" latest_backup="$5" latest_existed="$6"
    if [[ "$rollback_existed" == "1" && -n "$rollback_backup" && -f "$rollback_backup" ]]; then
        cp -a "$rollback_backup" "$rollback_path" 2>/dev/null || true
    else
        rm -f "$rollback_path" 2>/dev/null || true
    fi
    if [[ "$latest_existed" == "1" && -n "$latest_backup" && -f "$latest_backup" ]]; then
        cp -a "$latest_backup" "$latest_path" 2>/dev/null || true
    else
        rm -f "$latest_path" 2>/dev/null || true
    fi
}

_sysctl_apply_runtime_file() {
    local conf_file="$1"
    sysctl -p "$conf_file" >/dev/null 2>&1
}

_sysctl_apply_system_with_fallback() {
    local conf_file="$1"
    if sysctl --system >/dev/null 2>&1; then
        return 0
    fi
    print_warn "sysctl --system 执行失败，尝试只应用托管配置。"
    _sysctl_apply_runtime_file "$conf_file"
}

_sysctl_persistent_ip_forward_enabled() {
    local file
    if [[ -d "$(_sysctl_d_dir_path)" ]]; then
        for file in "$(_sysctl_d_dir_path)"/*.conf; do
            [[ -f "$file" ]] || continue
            grep -Eq '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*1([[:space:]]*(#.*)?)?$' "$file" && return 0
        done
    fi
    return 1
}

_sysctl_verify_effective_params() {
    local params="$1" line key expected actual failed=0
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"
        expected="$(_sysctl_normalize_value "${BASH_REMATCH[2]}")"
        actual="$(_sysctl_normalize_value "$(sysctl -n "$key" 2>/dev/null || true)")"
        if [[ "$actual" != "$expected" ]]; then
            print_warn "读回不一致: $key 期望 [$expected] 实际 [$actual]"
            failed=1
        fi
    done <<< "$params"
    return "$failed"
}

_sysctl_detect_cc_for_tuning() {
    local available
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    if [[ " $available " == *" bbr3 "* ]]; then
        printf '%s' "bbr3"
    elif [[ " $available " == *" bbr "* ]]; then
        printf '%s' "bbr"
    fi
}

_sysctl_buffer_bytes_for_class() {
    case "${1:-2}" in
        1) printf '%s' "16777216" ;;   # 16 MB: 100M/小内存/保守
        2) printf '%s' "67108864" ;;   # 64 MB: 常见 1G VPS
        3) printf '%s' "134217728" ;;  # 128 MB: 高带宽/高 RTT，仍不默认上 256 MB
        *) printf '%s' "33554432" ;;   # 32 MB: 未知环境
    esac
}

_sysctl_build_role_params() {
    local role="$1" bw_class="$2" buf cc block_start block_end include_forward=0
    buf="$(_sysctl_buffer_bytes_for_class "$bw_class")"
    cc="$(_sysctl_detect_cc_for_tuning)"
    block_start="# BEGIN server-manage sysctl tuning: ${role}"
    block_end="# END server-manage sysctl tuning"

    case "$role" in
        kernel-relay)
            include_forward=1
            ;;
    esac

    {
        printf '%s\n' "$block_start"
        [[ -n "$cc" ]] && {
            printf 'net.core.default_qdisc = fq\n'
            printf 'net.ipv4.tcp_congestion_control = %s\n' "$cc"
        }
        case "$role" in
            relay)
                printf 'fs.file-max = 1048576\n'
                printf 'net.core.somaxconn = 4096\n'
                printf 'net.core.netdev_max_backlog = 4096\n'
                printf 'net.core.rmem_max = %s\n' "$buf"
                printf 'net.core.wmem_max = %s\n' "$buf"
                printf 'net.ipv4.tcp_max_syn_backlog = 4096\n'
                printf 'net.ipv4.tcp_tw_reuse = 1\n'
                printf 'net.ipv4.tcp_fin_timeout = 15\n'
                printf 'net.ipv4.tcp_keepalive_time = 600\n'
                printf 'net.ipv4.tcp_keepalive_intvl = 15\n'
                printf 'net.ipv4.tcp_keepalive_probes = 5\n'
                printf 'net.ipv4.tcp_max_tw_buckets = 32768\n'
                printf 'net.ipv4.tcp_syncookies = 1\n'
                printf 'net.ipv4.tcp_mtu_probing = 1\n'
                printf 'net.ipv4.tcp_notsent_lowat = 131072\n'
                printf 'net.ipv4.tcp_rmem = 4096 87380 %s\n' "$buf"
                printf 'net.ipv4.tcp_wmem = 4096 65536 %s\n' "$buf"
                ;;
            kernel-relay)
                printf 'fs.file-max = 1048576\n'
                printf 'net.core.somaxconn = 4096\n'
                printf 'net.core.netdev_max_backlog = 4096\n'
                printf 'net.core.rmem_max = %s\n' "$buf"
                printf 'net.core.wmem_max = %s\n' "$buf"
                printf 'net.ipv4.tcp_max_syn_backlog = 4096\n'
                printf 'net.ipv4.tcp_tw_reuse = 1\n'
                printf 'net.ipv4.tcp_fin_timeout = 15\n'
                printf 'net.ipv4.tcp_keepalive_time = 600\n'
                printf 'net.ipv4.tcp_keepalive_intvl = 15\n'
                printf 'net.ipv4.tcp_keepalive_probes = 5\n'
                printf 'net.ipv4.tcp_max_tw_buckets = 32768\n'
                printf 'net.ipv4.tcp_syncookies = 1\n'
                printf 'net.ipv4.tcp_mtu_probing = 1\n'
                printf 'net.ipv4.tcp_rmem = 4096 87380 %s\n' "$buf"
                printf 'net.ipv4.tcp_wmem = 4096 65536 %s\n' "$buf"
                [[ "$include_forward" -eq 1 ]] && printf 'net.ipv4.ip_forward = 1\n'
                ;;
            landing)
                printf 'fs.file-max = 1048576\n'
                printf 'net.core.somaxconn = 8192\n'
                printf 'net.core.netdev_max_backlog = 8192\n'
                printf 'net.core.rmem_max = %s\n' "$buf"
                printf 'net.core.wmem_max = %s\n' "$buf"
                printf 'net.ipv4.tcp_max_syn_backlog = 8192\n'
                printf 'net.ipv4.tcp_tw_reuse = 1\n'
                printf 'net.ipv4.tcp_fin_timeout = 10\n'
                printf 'net.ipv4.tcp_keepalive_time = 300\n'
                printf 'net.ipv4.tcp_keepalive_intvl = 10\n'
                printf 'net.ipv4.tcp_keepalive_probes = 3\n'
                printf 'net.ipv4.tcp_syncookies = 1\n'
                printf 'net.ipv4.tcp_max_tw_buckets = 65536\n'
                printf 'net.ipv4.tcp_mtu_probing = 1\n'
                printf 'net.ipv4.tcp_notsent_lowat = 131072\n'
                printf 'net.ipv4.tcp_rmem = 4096 87380 %s\n' "$buf"
                printf 'net.ipv4.tcp_wmem = 4096 65536 %s\n' "$buf"
                ;;
            conservative|*)
                printf 'fs.file-max = 262144\n'
                printf 'net.core.somaxconn = 2048\n'
                printf 'net.ipv4.tcp_max_syn_backlog = 2048\n'
                printf 'net.ipv4.tcp_tw_reuse = 1\n'
                printf 'net.ipv4.tcp_syncookies = 1\n'
                printf 'net.ipv4.tcp_fin_timeout = 30\n'
                ;;
        esac
        printf '%s\n' "$block_end"
    }
}

_sysctl_render_profile() {
    local role="$1" bw_label="$2" goal="$3" backup_root="$4" rollback_file="$5" tuning_conf="$6" params="$7"
    cat <<EOF
# server-manage sysctl tuning profile

- created_at: $(date '+%Y-%m-%d %H:%M:%S')
- role: ${role}
- bandwidth_hint: ${bw_label}
- user_goal: ${goal:-not specified}
- tuning_file: ${tuning_conf}
- rollback_file: ${rollback_file}
- backup_snapshot: ${backup_root}

## Reasoning

This profile follows an evidence-first tuning policy: keep MTU/TBF unchanged unless PMTU,
qdisc drops/backlog, retransmission deltas, or real application tests justify them.
The active change is limited to Linux sysctl values and is stored in sysctl.d.

## Applied Values

\`\`\`
${params}
\`\`\`

## Caveats

- TCP buffer ceilings are selected from the bandwidth hint, not from a full BDP calculation.
- Run PMTU and iperf3 tests from the tuning menu for path-specific validation.
- UDP/QUIC protocols such as HY2/TUIC are not proven by TCP iperf3 alone.
EOF
}

_sysctl_commit_tuning() {
    local params="$1" role="$2" bw_label="$3" goal="$4"
    local tuning_conf profile_path rollback_path latest_path conf_file sysctl_d conf_dir ts
    local tmp_tuning="" tmp_rollback="" tmp_latest="" tmp_conf="" keys rollback_content backup_root profile_content
    local rollback_backup="" latest_backup="" rollback_existed=0 latest_existed=0
    tuning_conf="$(_sysctl_tuning_conf_path)"
    profile_path="$(_sysctl_tuning_profile_path)"
    rollback_path="$(_sysctl_rollback_path)"
    latest_path="$(_sysctl_latest_snapshot_path)"
    conf_file="$(_sysctl_conf_path)"
    sysctl_d="$(_sysctl_d_dir_path)"
    conf_dir="$(dirname "$conf_file")"
    ts=$(date '+%Y%m%d-%H%M%S')
    keys="$(_sysctl_extract_keys_from_params "$params")"
    rollback_content="$(_sysctl_render_runtime_rollback_conf "$params" "$role")"

    mkdir -p "$sysctl_d" "$conf_dir" "$(dirname "$rollback_path")" "$(dirname "$latest_path")" || {
        print_error "创建 sysctl 配置目录失败"
        return 1
    }
    backup_root="$(_sysctl_snapshot_create "$ts")" || {
        print_error "备份 sysctl 配置失败"
        return 1
    }

    if [[ -f "$rollback_path" ]]; then
        rollback_backup=$(mktemp "$(dirname "$rollback_path")/.bak.server-manage.rollback.XXXXXX") || return 1
        _tmp_register "$rollback_backup"
        if ! cp -a "$rollback_path" "$rollback_backup"; then
            print_error "备份现有回滚配置失败"
            _sysctl_cleanup_registered_paths "$rollback_backup"
            return 1
        fi
        rollback_existed=1
    fi
    if [[ -f "$latest_path" ]]; then
        latest_backup=$(mktemp "$(dirname "$latest_path")/.bak.server-manage.latest.XXXXXX") || {
            _sysctl_cleanup_registered_paths "$rollback_backup"
            return 1
        }
        _tmp_register "$latest_backup"
        if ! cp -a "$latest_path" "$latest_backup"; then
            print_error "备份最近快照指针失败"
            _sysctl_cleanup_registered_paths "$rollback_backup" "$latest_backup"
            return 1
        fi
        latest_existed=1
    fi

    tmp_tuning=$(mktemp "${sysctl_d}/.tmp.server-manage.sysctl.XXXXXX") || {
        _sysctl_cleanup_registered_paths "$rollback_backup" "$latest_backup"
        return 1
    }
    _tmp_register "$tmp_tuning"
    tmp_rollback=$(mktemp "$(dirname "$rollback_path")/.tmp.server-manage.rollback.XXXXXX") || {
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$rollback_backup" "$latest_backup"; return 1
    }
    _tmp_register "$tmp_rollback"
    tmp_latest=$(mktemp "$(dirname "$latest_path")/.tmp.server-manage.latest.XXXXXX") || {
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$rollback_backup" "$latest_backup"; return 1
    }
    _tmp_register "$tmp_latest"
    printf '%s\n' "$params" > "$tmp_tuning" || {
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"; return 1
    }
    printf '%s\n' "$rollback_content" > "$tmp_rollback" || {
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"; return 1
    }
    printf '%s\n' "$backup_root" > "$tmp_latest" || {
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"; return 1
    }
    chmod 644 "$tmp_tuning" "$tmp_rollback" "$tmp_latest" 2>/dev/null || true

    if ! _sysctl_apply_runtime_file "$tmp_tuning"; then
        _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"
        print_error "sysctl -p 校验失败，未写入正式配置。"
        log_action "Sysctl tuning failed before commit: role=$role" "ERROR"
        return 1
    fi

    if [[ -f "$conf_file" && -n "$keys" ]]; then
        tmp_conf=$(mktemp "${conf_dir}/.tmp.server-manage.sysctl-conf.XXXXXX") || {
            _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
            _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"; return 1
        }
        _tmp_register "$tmp_conf"
        _sysctl_render_conf_without_keys "$conf_file" "$keys" > "$tmp_conf" || {
            _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
            _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$tmp_conf" "$rollback_backup" "$latest_backup"
            print_error "生成 sysctl.conf 去冲突配置失败"
            return 1
        }
        chmod --reference="$conf_file" "$tmp_conf" 2>/dev/null || chmod 644 "$tmp_conf" 2>/dev/null || true
        chown --reference="$conf_file" "$tmp_conf" 2>/dev/null || true
        if ! mv "$tmp_conf" "$conf_file"; then
            _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
            _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$tmp_conf" "$rollback_backup" "$latest_backup"
            print_error "写入 $conf_file 失败"
            return 1
        fi
        _tmp_unregister "$tmp_conf"
    fi

    if ! mv "$tmp_tuning" "$tuning_conf"; then
        _sysctl_restore_managed_snapshot "$backup_root" >/dev/null 2>&1 || true
        _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
        _sysctl_cleanup_registered_paths "$tmp_tuning" "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"
        print_error "写入 $tuning_conf 失败"
        return 1
    fi
    _tmp_unregister "$tmp_tuning"

    if ! _sysctl_apply_system_with_fallback "$tuning_conf" || ! _sysctl_verify_effective_params "$params"; then
        _sysctl_restore_managed_snapshot "$backup_root" >/dev/null 2>&1 || true
        _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
        _sysctl_restore_metadata_backups "$rollback_path" "$rollback_backup" "$rollback_existed" "$latest_path" "$latest_backup" "$latest_existed"
        _sysctl_cleanup_registered_paths "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"
        print_error "应用后读回校验失败，已尝试回滚运行态。"
        log_action "Sysctl tuning failed after commit: role=$role" "ERROR"
        return 1
    fi

    if ! mv "$tmp_rollback" "$rollback_path"; then
        _sysctl_restore_managed_snapshot "$backup_root" >/dev/null 2>&1 || true
        _sysctl_apply_runtime_file "$tmp_rollback" >/dev/null 2>&1 || true
        _sysctl_restore_metadata_backups "$rollback_path" "$rollback_backup" "$rollback_existed" "$latest_path" "$latest_backup" "$latest_existed"
        _sysctl_cleanup_registered_paths "$tmp_rollback" "$tmp_latest" "$rollback_backup" "$latest_backup"
        print_error "写入回滚配置失败"
        return 1
    fi
    _tmp_unregister "$tmp_rollback"

    if ! mv "$tmp_latest" "$latest_path"; then
        _sysctl_restore_managed_snapshot "$backup_root" >/dev/null 2>&1 || true
        _sysctl_apply_runtime_file "$rollback_path" >/dev/null 2>&1 || true
        _sysctl_restore_metadata_backups "$rollback_path" "$rollback_backup" "$rollback_existed" "$latest_path" "$latest_backup" "$latest_existed"
        _sysctl_cleanup_registered_paths "$tmp_latest" "$rollback_backup" "$latest_backup"
        print_error "写入最近快照指针失败，已回滚本次调优。"
        return 1
    fi
    _tmp_unregister "$tmp_latest"
    _sysctl_cleanup_registered_paths "$rollback_backup" "$latest_backup"

    profile_content="$(_sysctl_render_profile "$role" "$bw_label" "$goal" "$backup_root" "$rollback_path" "$tuning_conf" "$params")"
    write_file_atomic "$profile_path" "$profile_content" || {
        print_warn "调优已写入，但 profile 写入失败: $profile_path"
    }

    print_success "内核参数已应用并读回确认。"
    echo "  配置: $tuning_conf"
    echo "  说明: $profile_path"
    echo "  回滚: $rollback_path"
    echo "  备份: $backup_root"
    log_action "Sysctl tuning applied: role=$role backup=$backup_root"
}

_sysctl_render_bbr_conf() {
    local conf_file="$1" qdisc="${2:-fq}" cc="${3:-bbr}"
    if [[ -f "$conf_file" ]]; then
        awk '
            /^# BEGIN server-manage bbr/ { in_bbr=1; next }
            in_bbr {
                if (/^# END server-manage bbr/) in_bbr=0
                next
            }
            /^[[:space:]]*net\.core\.default_qdisc[[:space:]=]/ { next }
            /^[[:space:]]*net\.ipv4\.tcp_congestion_control[[:space:]=]/ { next }
            { print }
        ' "$conf_file"
    fi
    printf '\n# BEGIN server-manage bbr\n'
    printf 'net.core.default_qdisc = %s\n' "$qdisc"
    printf 'net.ipv4.tcp_congestion_control = %s\n' "$cc"
    printf '# END server-manage bbr\n'
}

_sysctl_render_wireguard_forward_conf() {
    local conf_file="$1" value="${2:-1}"
    if [[ -f "$conf_file" ]]; then
        awk '
            /^# BEGIN server-manage wireguard ip-forward/ { in_wg=1; next }
            in_wg {
                if (/^# END server-manage wireguard ip-forward/) in_wg=0
                next
            }
            { print }
        ' "$conf_file"
    fi
    if [[ "$value" == "1" ]]; then
        printf '\n# BEGIN server-manage wireguard ip-forward\n'
        printf 'net.ipv4.ip_forward = 1\n'
        printf '# END server-manage wireguard ip-forward\n'
    fi
}

_sysctl_commit_candidate() {
    local tmp_candidate="$1" target_conf="$2" err_prefix="$3"
    if ! sysctl -p "$tmp_candidate" >/dev/null 2>&1; then
        print_error "${err_prefix}: sysctl -p 校验失败"
        return 1
    fi
    if ! mv "$tmp_candidate" "$target_conf"; then
        sysctl -p "$target_conf" >/dev/null 2>&1 || true
        print_error "${err_prefix}: 写入 $target_conf 失败"
        return 1
    fi
}

_sysctl_apply_wireguard_forward() {
    local value="${1:-1}" sysctl_conf sysctl_dir tmp_candidate
    sysctl_conf="$(_sysctl_conf_path)"
    sysctl_dir="$(dirname "$sysctl_conf")"
    mkdir -p "$sysctl_dir" || { print_error "创建 sysctl 配置目录失败"; return 1; }
    tmp_candidate=$(mktemp "${sysctl_dir}/.tmp.server-manage.wg-forward.XXXXXX") || {
        print_error "创建临时 sysctl 配置失败"
        return 1
    }
    _tmp_register "$tmp_candidate"
    if ! _sysctl_render_wireguard_forward_conf "$sysctl_conf" "$value" > "$tmp_candidate"; then
        rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
        print_error "生成 WireGuard IP 转发配置失败"
        return 1
    fi
    if [[ -f "$sysctl_conf" ]]; then
        chmod --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
        chown --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
    else
        chmod 644 "$tmp_candidate" 2>/dev/null || true
    fi
    if ! _sysctl_commit_candidate "$tmp_candidate" "$sysctl_conf" "WireGuard IP 转发配置"; then
        rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
        return 1
    fi
    _tmp_unregister "$tmp_candidate"
}

_sysctl_enable_wireguard_forward() {
    _sysctl_apply_wireguard_forward 1
}

_sysctl_disable_wireguard_forward() {
    local sysctl_conf tmp_check
    sysctl_conf="$(_sysctl_conf_path)"
    _sysctl_apply_wireguard_forward 0 || return 1
    tmp_check=$(mktemp) || return 0
    _tmp_register "$tmp_check"
    _sysctl_render_wireguard_forward_conf "$sysctl_conf" 0 > "$tmp_check" || {
        rm -f "$tmp_check"; _tmp_unregister "$tmp_check"
        return 0
    }
    if ! grep -q '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]=]' "$tmp_check" \
       && ! _sysctl_persistent_ip_forward_enabled; then
        sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    fi
    rm -f "$tmp_check"; _tmp_unregister "$tmp_check"
}

_sysctl_print_inspection() {
    print_title "内核参数调优 - 只读检查"
    local iface os_info mem_total mem_avail swap_total cc qdisc route
    iface="$(_sysctl_main_iface)"
    os_info=$(grep '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"' || uname -s)
    mem_total=$(awk '/^MemTotal:/ {print int($2/1024) "M"}' /proc/meminfo 2>/dev/null)
    mem_avail=$(awk '/^MemAvailable:/ {print int($2/1024) "M"}' /proc/meminfo 2>/dev/null)
    swap_total=$(awk '/^SwapTotal:/ {print int($2/1024) "M"}' /proc/meminfo 2>/dev/null)
    cc="$(_sysctl_read_value net.ipv4.tcp_congestion_control)"
    qdisc="$(_sysctl_read_value net.core.default_qdisc)"
    route=$(ip route get 1.1.1.1 2>/dev/null | head -1 || true)

    echo -e "${C_CYAN}基础信息:${C_RESET}"
    printf "  %-18s %s\n" "主机名:" "$(hostname 2>/dev/null || echo unknown)"
    printf "  %-18s %s\n" "系统:" "$os_info"
    printf "  %-18s %s\n" "内核:" "$(uname -r)"
    printf "  %-18s %s\n" "内存/可用:" "${mem_total:-N/A}/${mem_avail:-N/A}"
    printf "  %-18s %s\n" "Swap:" "${swap_total:-N/A}"
    printf "  %-18s %s\n" "主接口:" "${iface:-N/A}"
    if [[ -n "$iface" && -d "/sys/class/net/$iface" ]]; then
        printf "  %-18s %s\n" "MTU:" "$(cat "/sys/class/net/$iface/mtu" 2>/dev/null || echo N/A)"
    fi
    printf "  %-18s %s\n" "默认路由:" "${route:-N/A}"
    printf "  %-18s %s\n" "TCP算法:" "${cc} + ${qdisc}"
    echo ""

    echo -e "${C_CYAN}关键 sysctl:${C_RESET}"
    local key
    for key in \
        net.ipv4.tcp_available_congestion_control \
        net.ipv4.tcp_congestion_control \
        net.core.default_qdisc \
        net.core.rmem_max \
        net.core.wmem_max \
        net.ipv4.tcp_rmem \
        net.ipv4.tcp_wmem \
        net.core.somaxconn \
        net.ipv4.tcp_max_syn_backlog \
        net.core.netdev_max_backlog \
        net.ipv4.tcp_notsent_lowat \
        net.ipv4.ip_forward \
        net.ipv6.conf.all.forwarding \
        net.ipv4.tcp_fastopen \
        net.ipv4.tcp_ecn \
        net.ipv4.tcp_syncookies \
        net.ipv4.tcp_mtu_probing; do
        printf "  %-42s %s\n" "$key" "$(_sysctl_read_value "$key")"
    done
    echo ""

    echo -e "${C_CYAN}套接字摘要:${C_RESET}"
    if command_exists ss; then
        ss -s 2>/dev/null | sed 's/^/  /'
    else
        echo "  ss 未安装"
    fi
    echo ""

    echo -e "${C_CYAN}qdisc 状态:${C_RESET}"
    if [[ -n "$iface" ]] && command_exists tc; then
        tc -s qdisc show dev "$iface" 2>/dev/null | sed 's/^/  /'
    else
        echo "  tc 不可用或未识别主接口"
    fi
    echo ""

    echo -e "${C_CYAN}进程角色线索:${C_RESET}"
    if command_exists ps; then
        ps -eo comm,args 2>/dev/null | grep -Ei 'sing-box|xray|realm|gost|nodepass|hysteria|tuic|nginx|caddy|apache|iperf3|qos-agent' | grep -v grep | sed 's/^/  /' || echo "  未发现常见代理/Web/测速进程"
    else
        echo "  ps 不可用"
    fi
    echo ""

    echo -e "${C_CYAN}相关配置文件:${C_RESET}"
    echo "  主配置: $(_sysctl_conf_path)"
    echo "  托管配置: $(_sysctl_tuning_conf_path)"
    echo "  Profile: $(_sysctl_tuning_profile_path)"
    if [[ -d "$(_sysctl_d_dir_path)" ]]; then
        ls -1 "$(_sysctl_d_dir_path)"/*.conf 2>/dev/null | sed 's/^/  /' || true
    fi
    log_action "Sysctl tuning inspection completed"
    pause
}

_sysctl_pmtu_test() {
    print_title "PMTU 路径测试"
    local target s mtu
    read -e -r -p "目标 IP/域名: " target
    [[ -z "$target" ]] && return
    if ! validate_host "$target"; then
        print_error "目标主机格式无效。"
        pause; return 1
    fi
    if [[ "$target" == *:* ]]; then
        print_warn "当前 PMTU 阶梯测试主要面向 IPv4；IPv6 请优先看 tracepath 输出。"
    fi
    if command_exists tracepath; then
        echo -e "${C_CYAN}tracepath:${C_RESET}"
        tracepath -n "$target" 2>/dev/null || true
        echo ""
    else
        print_warn "tracepath 未安装，跳过。"
    fi
    echo -e "${C_CYAN}IPv4 DF ping ladder:${C_RESET}"
    for s in 1472 1452 1432 1412 1392 1352 1332 1312 1292; do
        mtu=$((s + 28))
        if ping -M do -s "$s" -c 2 -W 1 "$target" >/dev/null 2>&1; then
            echo "  payload=$s mtu=$mtu OK"
        else
            echo "  payload=$s mtu=$mtu FAIL"
        fi
    done
    log_action "PMTU test completed target=$target"
    pause
}

_sysctl_iperf3_direction_test() {
    print_title "iPerf3 关键方向测试"
    if ! command_exists iperf3; then
        if ! confirm "iperf3 未安装，是否现在安装？"; then
            print_warn "已取消 iPerf3 测试。"
            pause; return 1
        fi
        install_package "iperf3" "silent"
    fi
    if ! command_exists iperf3; then
        print_error "iperf3 安装失败或命令不可用。"
        pause; return 1
    fi
    local peer port duration iface qdisc_before qdisc_after fail_count=0
    read -e -r -p "peer IP/域名: " peer
    [[ -z "$peer" ]] && return
    if ! validate_host "$peer"; then
        print_error "peer 格式无效。"
        pause; return 1
    fi
    read -e -r -p "iperf3 端口 [25201]: " port
    port=${port:-25201}
    validate_port "$port" || { print_error "端口无效。"; pause; return 1; }
    read -e -r -p "单项测试时长秒数 [8]: " duration
    duration=${duration:-8}
    [[ "$duration" =~ ^[0-9]+$ && "$duration" -ge 3 && "$duration" -le 120 ]] || {
        print_error "时长需为 3-120 秒。"; pause; return 1
    }
    iface="$(_sysctl_main_iface)"
    if [[ -n "$iface" ]] && command_exists tc; then
        qdisc_before=$(tc -s qdisc show dev "$iface" 2>/dev/null)
    fi
    echo -e "${C_CYAN}target -> peer, P1:${C_RESET}"
    iperf3 -c "$peer" -p "$port" -t "$duration" -P 1 || ((fail_count++)) || true
    echo -e "${C_CYAN}target -> peer, P4:${C_RESET}"
    iperf3 -c "$peer" -p "$port" -t "$duration" -P 4 || ((fail_count++)) || true
    echo -e "${C_CYAN}peer -> target (-R), P1:${C_RESET}"
    iperf3 -c "$peer" -p "$port" -t "$duration" -P 1 -R || ((fail_count++)) || true
    echo -e "${C_CYAN}peer -> target (-R), P4:${C_RESET}"
    iperf3 -c "$peer" -p "$port" -t "$duration" -P 4 -R || ((fail_count++)) || true
    if [[ -n "$iface" ]] && command_exists tc; then
        qdisc_after=$(tc -s qdisc show dev "$iface" 2>/dev/null)
        echo -e "${C_CYAN}qdisc 测试前:${C_RESET}"
        printf '%s\n' "$qdisc_before" | sed 's/^/  /'
        echo -e "${C_CYAN}qdisc 测试后:${C_RESET}"
        printf '%s\n' "$qdisc_after" | sed 's/^/  /'
    fi
    if [[ "$fail_count" -gt 0 ]]; then
        print_warn "iPerf3 测试完成，但有 ${fail_count} 项失败，请按输出判断是否为 peer/端口/防火墙问题。"
        log_action "iPerf3 direction test completed with failures peer=$peer port=$port duration=$duration failures=$fail_count" "WARN"
    else
        print_success "iPerf3 四个方向测试均已完成。"
        log_action "iPerf3 direction test completed peer=$peer port=$port duration=$duration"
    fi
    pause
}

_sysctl_apply_role_preset() {
    print_title "应用角色化 sysctl 调优"
    echo "这一步只修改 sysctl，不自动修改 MTU、TBF/HTB 或 qos-agent。"
    echo "建议先完成只读检查、PMTU 和关键方向 iPerf3 测试。"
    echo ""
    echo "选择机器角色:"
    echo "  1. 用户态代理/中转 (sing-box/xray/realm/gost 等，不开启 ip_forward)"
    echo "  2. 内核转发/WireGuard 中转 (需要 IPv4 forwarding)"
    echo "  3. 落地机/Web 出口 (TCP 终点或重新发起方)"
    echo "  4. 保守方案 (小内存/未知链路)"
    echo "  0. 返回"
    local r role role_label bw bw_label goal params ok
    read -e -r -p "选择: " r
    case "$r" in
        1) role="relay"; role_label="userspace relay" ;;
        2) role="kernel-relay"; role_label="kernel relay / WireGuard" ;;
        3) role="landing"; role_label="landing / web exit" ;;
        4) role="conservative"; role_label="conservative" ;;
        0|q|"") return ;;
        *) print_error "无效选择"; pause; return 1 ;;
    esac
    echo ""
    echo "带宽/BDP 提示:"
    echo "  1. 100M 或小内存"
    echo "  2. 1G 常规 VPS"
    echo "  3. 高带宽/高 RTT，已有测试依据"
    echo "  4. 未知，偏保守"
    read -e -r -p "选择 [2]: " bw
    bw=${bw:-2}
    case "$bw" in
        1) bw_label="100M/small-memory" ;;
        2) bw_label="1G/common" ;;
        3) bw_label="high-bandwidth/high-rtt" ;;
        4) bw_label="unknown/conservative" ;;
        *) print_error "无效选择"; pause; return 1 ;;
    esac
    read -e -r -p "优化目标备注 (可空): " goal
    params="$(_sysctl_build_role_params "$role" "$bw")"
    echo ""
    echo -e "${C_CYAN}即将写入的托管配置:${C_RESET}"
    printf '%s\n' "$params" | sed 's/^/  /'
    echo ""
    print_warn "不会根据单个异常 peer 推导 MTU/TBF；如需限速或改 MTU，请先用测试证据确认。"
    read -e -r -p "输入 APPLY 确认写入: " ok
    [[ "$ok" == "APPLY" ]] || { print_warn "已取消。"; pause; return 0; }
    _sysctl_commit_tuning "$params" "$role_label" "$bw_label" "$goal"
    pause
}

_sysctl_rollback_tuning() {
    print_title "回滚 sysctl 调优"
    local tuning_conf rollback_path legacy_backup snapshot latest_path
    tuning_conf="$(_sysctl_tuning_conf_path)"
    rollback_path="$(_sysctl_rollback_path)"
    legacy_backup="$(_sysctl_backup_path)"
    latest_path="$(_sysctl_latest_snapshot_path)"
    snapshot="$(_sysctl_read_latest_snapshot 2>/dev/null || true)"

    if [[ -n "$snapshot" ]]; then
        if ! _sysctl_restore_managed_snapshot "$snapshot"; then
            print_error "恢复持久化快照失败: $snapshot"
            pause; return 1
        fi
        if [[ -f "$rollback_path" ]]; then
            _sysctl_apply_runtime_file "$rollback_path" >/dev/null 2>&1 || true
        else
            sysctl --system >/dev/null 2>&1 || true
        fi
        rm -f "$latest_path" 2>/dev/null || true
        print_success "已恢复调优前的持久化配置。"
        echo "  快照: $snapshot"
        log_action "Sysctl tuning rolled back via snapshot $snapshot"
    elif [[ -f "$rollback_path" ]]; then
        if [[ -f "$tuning_conf" ]]; then
            mv "$tuning_conf" "${tuning_conf}.disabled-$(date '+%Y%m%d-%H%M%S')" || {
                print_error "停用托管配置失败"
                pause; return 1
            }
        fi
        if _sysctl_apply_runtime_file "$rollback_path"; then
            print_success "已按运行态回滚配置恢复。"
            log_action "Sysctl tuning rolled back via $rollback_path"
        else
            print_error "运行态回滚失败，请检查 $rollback_path"
            pause; return 1
        fi
    elif [[ -f "$legacy_backup" ]]; then
        cp "$legacy_backup" "$(_sysctl_conf_path)"
        sysctl -p "$(_sysctl_conf_path)" >/dev/null 2>&1 || true
        print_success "已回滚到旧版调优前的 sysctl.conf。"
        log_action "Sysctl tuning rolled back via legacy backup"
    else
        print_warn "没有找到回滚配置。"
    fi
    pause
}

opt_sysctl() {
    while true; do
        print_title "内核参数调优"
        echo "1. 只读检查现状"
        echo "2. PMTU 路径测试"
        echo "3. iPerf3 关键方向测试"
        echo "4. 应用角色化 sysctl 调优"
        echo "5. 回滚上次调优"
        echo "0. 返回"
        read -e -r -p "选择: " sc
        case "$sc" in
            1) _sysctl_print_inspection ;;
            2) _sysctl_pmtu_test ;;
            3) _sysctl_iperf3_direction_test ;;
            4) _sysctl_apply_role_preset ;;
            5) _sysctl_rollback_tuning ;;
            0|q|"") break ;;
            *) print_error "无效选择"; pause ;;
        esac
    done
}

menu_opt() {
    fix_terminal
    while true; do
        print_title "系统优化"
        echo "1. 开启 BBR 加速
2. 虚拟内存 (Swap)
3. 修改主机名
4. 系统垃圾清理
5. 修改时区
6. 内核参数调优
0. 返回
"
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_swap ;;
            3) opt_hostname ;;
            4) opt_cleanup ;;
            5) select_timezone || true; pause ;;
            6) opt_sysctl ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
net_iperf3() {
    print_title "iPerf3 测速"
    install_package "iperf3"
    if ! command_exists iperf3; then
        print_error "iperf3 安装失败或命令不可用。"
        pause; return 1
    fi
    read -e -r -p "监听端口 [5201]: " port
    port=${port:-5201}
    if ! validate_port "$port"; then
        print_error "端口无效。"
        pause; return
    fi
    local ufw_opened=0
        if ufw_is_active; then
        if ! ufw status 2>/dev/null | grep -q "$port/tcp"; then
            if ! ufw allow "$port/tcp" comment "iPerf3-Temp" >/dev/null; then
                print_error "临时放行端口 $port 失败。"
                pause; return 1
            fi
            ufw_opened=1
            print_info "临时放行端口 $port"
        fi
    fi
    iperf3 -s -p "$port" &
    local iperf_pid=$!
    sleep 0.2
    if ! jobs -pr | grep -qx "$iperf_pid"; then
        wait "$iperf_pid" 2>/dev/null || true
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
        print_error "iPerf3 服务启动失败。"
        pause; return 1
    fi
    local ip4=$(get_public_ipv4)
    local ip6=$(get_public_ipv6 || echo "")
    [[ -z "$ip6" ]] && ip6="未检测到"
    echo -e "\n${C_BLUE}=== 客户端测速命令 ===${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Upload: ${C_YELLOW}iperf3 -c $ip4 -p $port${C_RESET}"
    [[ -n "$ip4" ]] && echo -e "IPv4 Download: ${C_YELLOW}iperf3 -c $ip4 -p $port -R${C_RESET}"
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Upload: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port${C_RESET}"
    [[ -n "$ip6" && "$ip6" != "未检测到" ]] && echo -e "IPv6 Download: ${C_YELLOW}iperf3 -6 -c $ip6 -p $port -R${C_RESET}"
    echo -e "${C_RED}按 Ctrl+C 停止测试...${C_RESET}"
    local cleaned=0

    cleanup_iperf() {
        [[ $cleaned -eq 1 ]] && return
        cleaned=1
        echo ""
        print_info "正在停止 iPerf3 服务..."
        if [[ -n "$iperf_pid" ]] && kill -0 "$iperf_pid" 2>/dev/null; then
            kill "$iperf_pid" 2>/dev/null || true
            wait "$iperf_pid" 2>/dev/null || true
        fi
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$port/tcp" >/dev/null 2>&1 || true
            print_info "防火墙规则已移除。"
        fi
        print_success "iPerf3 服务已停止。"
    }
    trap 'cleanup_iperf; trap - SIGINT SIGTERM' SIGINT SIGTERM
    wait $iperf_pid 2>/dev/null || true
    trap 'handle_interrupt' SIGINT SIGTERM
    cleanup_iperf
    log_action "iPerf3 test completed on port $port"
    pause
}

_net_resolved_conf_path() {
    printf '%s' "/etc/systemd/resolved.conf"
}

_net_gai_conf_path() {
    printf '%s' "/etc/gai.conf"
}

_net_openwrt_reload_network() {
    /etc/init.d/network reload
}

_net_render_resolved_dns_conf() {
    local conf_file="$1" dns="$2"
    if [[ -f "$conf_file" ]]; then
        awk -v dns="$dns" '
            BEGIN { in_resolve=0; seen_resolve=0; inserted=0 }
            /^[[:space:]]*\[Resolve\][[:space:]]*$/ {
                print
                if (!inserted) {
                    print "DNS=" dns
                    inserted=1
                }
                in_resolve=1
                seen_resolve=1
                next
            }
            /^[[:space:]]*\[/ {
                in_resolve=0
            }
            in_resolve && /^[[:space:]]*DNS[[:space:]]*=/ {
                next
            }
            { print }
            END {
                if (!seen_resolve) {
                    print ""
                    print "[Resolve]"
                    print "DNS=" dns
                }
            }
        ' "$conf_file"
    else
        printf '[Resolve]\nDNS=%s\n' "$dns"
    fi
}

_net_apply_systemd_resolved_dns() {
    local dns="$1" res_conf old_content had_file=0 new_content
    res_conf="$(_net_resolved_conf_path)"
    if [[ -f "$res_conf" ]]; then
        old_content=$(cat "$res_conf")
        had_file=1
    else
        old_content=""
    fi
    new_content="$(_net_render_resolved_dns_conf "$res_conf" "$dns")" || return 1
    if ! write_file_atomic "$res_conf" "$new_content"; then
        print_error "写入 $res_conf 失败"
        return 1
    fi
    if systemctl restart systemd-resolved; then
        return 0
    fi
    print_error "重启 systemd-resolved 失败，正在回滚 DNS 配置"
    if [[ "$had_file" -eq 1 ]]; then
        write_file_atomic "$res_conf" "$old_content" >/dev/null 2>&1 || true
    else
        rm -f "$res_conf" 2>/dev/null || true
    fi
    return 1
}

_net_render_gai_conf() {
    local conf_file="$1" mode="${2:-ipv6}"
    if [[ -f "$conf_file" ]]; then
        awk '
            /^# BEGIN server-manage ip-priority/ { in_block=1; next }
            in_block {
                if (/^# END server-manage ip-priority/) in_block=0
                next
            }
            /^[[:space:]]*precedence[[:space:]]+::ffff:0:0\/96[[:space:]]+100([[:space:]]*(#.*)?)?$/ { next }
            { print }
        ' "$conf_file"
    fi
    if [[ "$mode" == "ipv4" ]]; then
        printf '\n# BEGIN server-manage ip-priority\n'
        printf 'precedence ::ffff:0:0/96  100\n'
        printf '# END server-manage ip-priority\n'
    fi
}

_net_apply_gai_priority() {
    local mode="$1" gai_path new_content
    gai_path="$(_net_gai_conf_path)"
    mkdir -p "$(dirname "$gai_path")" || return 1
    new_content="$(_net_render_gai_conf "$gai_path" "$mode")" || return 1
    write_file_atomic "$gai_path" "$new_content"
}

_net_openwrt_restore_dns_snapshot() {
    local iface="$1" had_dns="$2" dns_snapshot="$3" had_peerdns="$4" peerdns_snapshot="$5"
    local rc=0
    uci -q delete "network.${iface}.dns" 2>/dev/null || true
    if [[ "$had_dns" == "true" && -n "$dns_snapshot" ]]; then
        local ip
        while IFS= read -r ip; do
            [[ -n "$ip" ]] || continue
            uci add_list "network.${iface}.dns=$ip" >/dev/null 2>&1 || rc=1
        done <<< "$dns_snapshot"
    fi
    if [[ "$had_peerdns" == "true" ]]; then
        uci set "network.${iface}.peerdns=${peerdns_snapshot}" >/dev/null 2>&1 || rc=1
    else
        uci -q delete "network.${iface}.peerdns" 2>/dev/null || true
    fi
    uci commit network >/dev/null 2>&1 || rc=1
    _net_openwrt_reload_network >/dev/null 2>&1 || rc=1
    return "$rc"
}

_net_openwrt_apply_dns() {
    local iface="$1" dns="$2"
    local had_dns=false dns_snapshot="" had_peerdns=false peerdns_snapshot="" ip
    if dns_snapshot=$(uci -q get "network.${iface}.dns" 2>/dev/null); then
        had_dns=true
    fi
    if peerdns_snapshot=$(uci -q get "network.${iface}.peerdns" 2>/dev/null); then
        had_peerdns=true
    fi

    uci -q delete "network.${iface}.dns" 2>/dev/null || true
    for ip in $dns; do
        if ! uci add_list "network.${iface}.dns=$ip"; then
            print_error "写入 OpenWrt DNS 失败: $ip"
            _net_openwrt_restore_dns_snapshot "$iface" "$had_dns" "$dns_snapshot" "$had_peerdns" "$peerdns_snapshot" \
                || print_error "恢复 OpenWrt DNS 配置失败，请手动检查 network 配置。"
            return 1
        fi
    done
    if ! uci set "network.${iface}.peerdns=0"; then
        print_error "设置 OpenWrt peerdns 失败"
        _net_openwrt_restore_dns_snapshot "$iface" "$had_dns" "$dns_snapshot" "$had_peerdns" "$peerdns_snapshot" \
            || print_error "恢复 OpenWrt DNS 配置失败，请手动检查 network 配置。"
        return 1
    fi
    if ! uci commit network; then
        print_error "提交 OpenWrt network 配置失败"
        _net_openwrt_restore_dns_snapshot "$iface" "$had_dns" "$dns_snapshot" "$had_peerdns" "$peerdns_snapshot" \
            || print_error "恢复 OpenWrt DNS 配置失败，请手动检查 network 配置。"
        return 1
    fi
    if ! _net_openwrt_reload_network 2>/dev/null; then
        print_error "重载 OpenWrt network 失败，已恢复原 DNS 配置。"
        _net_openwrt_restore_dns_snapshot "$iface" "$had_dns" "$dns_snapshot" "$had_peerdns" "$peerdns_snapshot" \
            || print_error "恢复 OpenWrt DNS 配置失败，请手动检查 network 配置。"
        return 1
    fi
    return 0
}

net_dns() {
    print_title "DNS 配置"
    echo -e "${C_CYAN}当前 DNS:${C_RESET}"
    if is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolvectl status 2>/dev/null | grep -E "DNS Servers|DNS Server" | head -5 || cat /etc/resolv.conf
    else
        cat /etc/resolv.conf
    fi
    echo -e "${C_CYAN}=== DNS 预设方案 ===${C_RESET}"
    echo -e "  ${C_YELLOW}-- 境外通用 --${C_RESET}"
    echo "  1. Cloudflare          1.1.1.1 1.0.0.1
  2. Google              8.8.8.8 8.8.4.4
  3. Cloudflare + Google 1.1.1.1 8.8.8.8
"
    echo -e "  ${C_YELLOW}-- 境内通用 --${C_RESET}"
    echo "  4. 阿里 DNS            223.5.5.5 223.6.6.6
  5. 腾讯 DNS            119.29.29.29 119.28.28.28
  6. 114 DNS             114.114.114.114 114.114.115.115
"
    echo -e "  ${C_YELLOW}-- IPv6 --${C_RESET}"
    echo "  7. Cloudflare IPv6     2606:4700:4700::1111 2606:4700:4700::1001
  8. Google IPv6         2001:4860:4860::8888 2001:4860:4860::8844
  9. 阿里 IPv6           2400:3200::1 2400:3200:baba::1
"
    echo -e "  ${C_YELLOW}-- 混合方案 --${C_RESET}"
    echo "  10. 境外双栈 (CF v4+v6)       1.1.1.1 2606:4700:4700::1111
  11. 境内双栈 (阿里 v4+v6)     223.5.5.5 2400:3200::1
  12. 境内+境外混合              223.5.5.5 1.1.1.1
  13. 自定义输入
  0. 返回上一级
"
    read -e -r -p "选择方案 [0=返回]: " dns_choice
    dns_choice=${dns_choice:-0}
    local dns=""
    case $dns_choice in
        1)  dns="1.1.1.1 1.0.0.1" ;;
        2)  dns="8.8.8.8 8.8.4.4" ;;
        3)  dns="1.1.1.1 8.8.8.8" ;;
        4)  dns="223.5.5.5 223.6.6.6" ;;
        5)  dns="119.29.29.29 119.28.28.28" ;;
        6)  dns="114.114.114.114 114.114.115.115" ;;
        7)  dns="2606:4700:4700::1111 2606:4700:4700::1001" ;;
        8)  dns="2001:4860:4860::8888 2001:4860:4860::8844" ;;
        9)  dns="2400:3200::1 2400:3200:baba::1" ;;
        10) dns="1.1.1.1 2606:4700:4700::1111" ;;
        11) dns="223.5.5.5 2400:3200::1" ;;
        12) dns="223.5.5.5 1.1.1.1" ;;
        13)
            echo -e "${C_YELLOW}输入 DNS IP (空格隔开)，输入 0 取消${C_RESET}"
            read -e -r -p "DNS: " dns
            [[ -z "$dns" || "$dns" == "0" ]] && return
            ;;
        0|q|Q) return ;;
        *) print_error "无效选择"; pause; return ;;
    esac
    [[ -z "$dns" ]] && return
    echo -e "${C_CYAN}将设置 DNS 为:${C_RESET} $dns"
    if ! confirm "确认修改?"; then return; fi
    for ip in $dns; do
        if ! validate_ip "$ip"; then
            print_error "IP 地址 $ip 格式无效！"
            pause; return
        fi
    done
    if [[ "$PLATFORM" == "openwrt" ]]; then
        local network_wan="wan" network_lan="lan" dns_iface
        dns_iface="$network_wan"
        uci -q get "network.${dns_iface}" >/dev/null 2>&1 || dns_iface="$network_lan"
        uci -q get "network.${dns_iface}" >/dev/null 2>&1 || { print_error "未找到 OpenWrt wan/lan 网络接口"; pause; return 1; }
        _net_openwrt_apply_dns "$dns_iface" "$dns" || { pause; return 1; }
        print_success "DNS 已通过 uci 修改 (接口: ${dns_iface}, 持久化)。"
    elif is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        _net_apply_systemd_resolved_dns "$dns" || { pause; return 1; }
        print_success "DNS 已修改。"
    else
        local resolv_content=""
        for ip in $dns; do
            resolv_content+="nameserver $ip"$'\n'
        done
        write_file_atomic /etc/resolv.conf "${resolv_content%$'\n'}" || { print_error "写入 /etc/resolv.conf 失败"; pause; return 1; }
        print_success "DNS 已修改。"
    fi
    log_action "DNS changed to: $dns"
    pause
}

net_diag() {
    print_title "网络诊断工具"
    echo "1. Ping 测试
2. Traceroute / MTR 路由追踪
3. 端口连通性测试 (从服务器往外测)
0. 返回"
    read -e -r -p "选择: " c
    case $c in
    1)
        read -e -r -p "目标 IP/域名: " target
        [[ -z "$target" ]] && return
        read -e -r -p "次数 [4]: " cnt
        cnt=${cnt:-4}
        ping -c "$cnt" "$target"
        ;;
    2)
        read -e -r -p "目标 IP/域名: " target
        [[ -z "$target" ]] && return
        if command_exists mtr; then
            mtr --report --report-cycles 5 "$target"
        elif command_exists traceroute; then
            traceroute "$target"
        else
            print_info "正在安装 mtr..."
            install_package "mtr" "silent"
            if command_exists mtr; then
                mtr --report --report-cycles 5 "$target"
            else
                print_error "mtr 安装失败，请手动安装"
            fi
        fi
        ;;
    3)
        read -e -r -p "目标 IP/域名: " host
        [[ -z "$host" ]] && return
        if ! validate_host "$host"; then
            print_error "目标主机格式无效（仅支持 IP 或普通域名）"; pause; return
        fi
        read -e -r -p "端口: " port
        if ! validate_port "$port"; then
            print_error "端口无效"; pause; return
        fi
        print_info "测试 ${host}:${port} ..."
        if command_exists nc; then
            if nc -zv -w 5 "$host" "$port" 2>&1; then
                print_success "端口可达"
            else
                print_error "端口不可达或超时"
            fi
        else
            if timeout 5 bash -c 'echo >/dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null; then
                print_success "端口可达"
            else
                print_error "端口不可达或超时"
            fi
        fi
        ;;
    0|q) return ;;
    esac
    pause
}

menu_net() {
    fix_terminal
    while true; do
        print_title "网络管理工具"
        echo "1. DNS 配置
2. IPv4/IPv6 优先级
3. iPerf3 测速
4. 网络诊断 (Ping/MTR/端口测试)
0. 返回上一级
"
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2)
                echo "1. 优先 IPv4"
                echo "2. 优先 IPv6"
                echo "0. 返回上一级"
                read -e -r -p "选: " p
                case $p in
                    1)
                        if _net_apply_gai_priority ipv4; then
                            print_success "IPv4 优先。"
                            log_action "IP priority changed: ipv4"
                        else
                            print_error "写入 /etc/gai.conf 失败。"
                        fi
                        pause
                        ;;
                    2)
                        if _net_apply_gai_priority ipv6; then
                            print_success "IPv6 优先。"
                            log_action "IP priority changed: ipv6"
                        else
                            print_error "写入 /etc/gai.conf 失败。"
                        fi
                        pause
                        ;;
                    0|q|Q|"") ;;
                    *) print_error "无效选择"; pause ;;
                esac
                ;;
            3) net_iperf3 ;;
            4) net_diag ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
# 子模块按依赖顺序加载:
#   09a → 依赖管理 + 通用辅助函数
#   09b → Cloudflare API / Origin Rules / DNS
#   09c → 域名管理 (添加/查看/删除 + 证书)
#   09d → 反向代理 + 主菜单
#   09e → 家宽内网服务公网暴露（一键配置）
#
# 注意: 通过 build.sh 构建时，此文件和子模块会被直接拼接，
# 不需要额外的 source 调用。此注释仅用于人类阅读。
_web_dep_check_results=()

_web_dep_run_check() {
    local check_id="$1"
    case "$check_id" in
        jq) command_exists jq ;;
        nginx) command_exists nginx ;;
        nginx_dirs) _check_nginx_dirs ;;
        certbot) command_exists certbot ;;
        certbot_dns_cf) _check_certbot_dns_cf ;;
        *) return 1 ;;
    esac
}

_web_dep_run_install() {
    local install_id="$1"
    case "$install_id" in
        jq) install_package jq silent ;;
        nginx) _install_nginx ;;
        nginx_dirs) mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets ;;
        certbot) _install_certbot ;;
        certbot_dns_cf) _install_certbot_dns_cf ;;
        *) return 1 ;;
    esac
}

_web_dep_verify() {
    local name="$1" check_id="$2"
    if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
        _web_dep_check_results+=("${C_GREEN}✓${C_RESET} $name")
        return 0
    else
        _web_dep_check_results+=("${C_RED}✗${C_RESET} $name")
        return 1
    fi
}

_web_dep_fix() {
    local name="$1" check_id="$2" install_id="$3"
    if ! _web_dep_run_check "$check_id" >/dev/null 2>&1; then
        print_info "修复: $name ..."
        if _web_dep_run_install "$install_id"; then
            if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
                print_success "$name 修复成功"
                return 0
            fi
        fi
        print_error "$name 修复失败"
        return 1
    fi
    return 0
}

_purge_snap_certbot() {
    if snap list certbot &>/dev/null 2>&1; then
        print_info "检测到 snap 版 certbot，正在清理..."
        snap remove certbot 2>/dev/null || true
        snap remove certbot-dns-cloudflare 2>/dev/null || true
        local link target
        for link in /usr/bin/certbot /snap/bin/certbot; do
            if [[ -L "$link" ]]; then
                target=$(readlink "$link" 2>/dev/null || true)
                if [[ "$link" == "/snap/bin/certbot" || "$target" == "/snap/bin/certbot" || "$target" == *"/snap/certbot/"* ]]; then
                    rm -f "$link" 2>/dev/null || true
                fi
            fi
        done
        if [[ $(snap list 2>/dev/null | tail -n +2 | wc -l) -eq 0 ]]; then
            print_info "snap 中无其他软件包，清理 snapd..."
            systemctl stop snapd snapd.socket 2>/dev/null || true
            apt-get purge -y snapd 2>/dev/null || true
            print_success "snapd 已清理"
        fi
        log_action "Purged snap certbot"
    fi
}

_install_certbot_apt() {
    _purge_snap_certbot
    update_apt_cache
    apt-get install -y certbot >/dev/null 2>&1
}

_install_certbot_snap() {
    install_package "snapd" "silent" || return 1
    snap install --classic certbot >/dev/null 2>&1 || return 1
    ln -sf /snap/bin/certbot /usr/bin/certbot
}

_install_certbot_dns_cf_apt() {
    _purge_snap_certbot
    update_apt_cache
    if ! dpkg -s certbot &>/dev/null; then
        apt-get install -y certbot >/dev/null 2>&1 || return 1
    fi
    apt-get install -y python3-certbot-dns-cloudflare >/dev/null 2>&1
}

_install_certbot_dns_cf_snap() {
    if ! command_exists snap; then
        install_package "snapd" "silent" || { print_error "snapd 安装失败"; return 1; }
        if is_systemd; then
            systemctl enable --now snapd.socket >/dev/null 2>&1 || true
            print_info "等待 snapd 初始化 (低配机器可能需要几分钟)..."
            local wait=0
            while [[ $wait -lt 120 ]]; do
                snap version &>/dev/null && break
                echo -ne "\r  已等待 ${wait}s..."
                sleep 3; wait=$((wait + 3))
            done
            if ! snap version &>/dev/null; then
                print_error "snapd 未就绪 (等待 ${wait}s 超时)"
                return 1
            fi
        fi
    fi
    snap install core 2>/dev/null || true
    snap refresh core 2>/dev/null || true
    print_info "snap 安装 certbot (可能需要几分钟，请耐心等待)..."
    if ! snap install --classic certbot 2>&1; then
        print_error "snap install certbot 失败"
        return 1
    fi
    ln -sf /snap/bin/certbot /usr/bin/certbot
    # 授权插件 root 权限（snap 强制要求）
    snap set certbot trust-plugin-with-root=ok 2>/dev/null || true
    print_info "snap 安装 certbot-dns-cloudflare..."
    if ! snap install certbot-dns-cloudflare 2>&1; then
        print_error "snap install certbot-dns-cloudflare 失败"
        return 1
    fi
    snap connect certbot:plugin certbot-dns-cloudflare >/dev/null 2>&1 || true
    print_success "snap 安装完成"
    return 0
}

_install_certbot_dns_cf() {
    # 先尝试 apt 安装
    _install_certbot_dns_cf_apt || true

    # 检查 apt 装的版本是否可用（版本号 >= 1.0）
    if _check_certbot_dns_cf; then
        return 0
    fi

    # apt 版本不可用（如 20.04 的 0.39），切换 snap
    print_warn "apt 版本不兼容，切换 snap 安装..."
    apt-get remove -y certbot python3-certbot-dns-cloudflare 2>/dev/null || true
    _install_certbot_dns_cf_snap
}

# 统一的 certbot 安装入口（先 apt 后 snap）
_install_certbot() {
    _install_certbot_apt && return 0
    print_warn "apt 安装 certbot 失败，尝试 snap..."
    _install_certbot_snap
}

_install_nginx() {
    update_apt_cache
    apt-get install -y nginx >/dev/null 2>&1 || return 1
    is_systemd && systemctl enable --now nginx >/dev/null 2>&1 || true
}

# 检测 nginx 是否具备 stream 模块（ssl_preread 分流依赖）。
# 三种可用形态：静态编入(--with-stream)、动态模块已加载(modules-enabled 下有 stream so),
# 或发行版把 stream so 装在 modules 目录但未 load（此时需 load_module，交给 _ensure_nginx_stream 处理）。
_check_nginx_stream() {
    command_exists nginx || return 1
    local vout; vout="$(nginx -V 2>&1)"
    # 静态编入：nginx -V 中出现独立 token "--with-stream"。
    # 关键：必须逐 token 精确匹配（tr 空格换行 + grep -x），否则会把
    #   --with-stream=dynamic（动态模块，需 .so + load_module，非静态可用）
    #   --with-stream_ssl_module / --with-stream_ssl_preread_module（子模块 token）
    # 这类子串误判为「静态编入可用」——Debian 12 官方 nginx 正是 --with-stream=dynamic
    # 且 /usr/lib/nginx/modules 为空，误判会导致 stream{} 加载失败却报可用。
    if tr ' ' '\n' <<< "$vout" | grep -qx -- '--with-stream'; then
        return 0
    fi
    # 动态模块：必须「已在 modules-enabled 下 load」且「对应 .so 真实存在」才算当前可用。
    if ls /etc/nginx/modules-enabled/ 2>/dev/null | grep -q 'stream' && _nginx_stream_module_available; then
        return 0
    fi
    return 1
}

# 动态 stream 模块的 so 是否存在（用于判断能否走 load_module 而无需换源）
_nginx_stream_module_available() {
    ls /usr/lib/nginx/modules/ngx_stream_module.so \
       /usr/share/nginx/modules/ngx_stream_module.so 2>/dev/null | grep -q . && return 0
    return 1
}

# 安装官方 nginx.org 源（带 stream 模块，静态编入）。仅 Debian/Ubuntu。
_nginx_keyring_path() {
    printf '%s' "${NGINX_KEYRING_FILE:-/usr/share/keyrings/nginx-archive-keyring.gpg}"
}

_nginx_source_list_path() {
    printf '%s' "${NGINX_SOURCE_LIST_FILE:-/etc/apt/sources.list.d/nginx.list}"
}

_nginx_preferences_path() {
    printf '%s' "${NGINX_APT_PIN_FILE:-/etc/apt/preferences.d/99nginx}"
}

_nginx_stream_module_conf_path() {
    printf '%s' "${NGINX_STREAM_MODULE_CONF:-/etc/nginx/modules-enabled/50-mod-stream.conf}"
}

_nginx_render_official_source() {
    local distro="$1" codename="$2" keyring="$3"
    [[ "$distro" =~ ^(debian|ubuntu)$ ]] || return 1
    [[ "$codename" =~ ^[A-Za-z0-9._+-]+$ ]] || return 1
    [[ "$keyring" == /* && "$keyring" != *$'\n'* ]] || return 1
    printf 'deb [signed-by=%s] http://nginx.org/packages/%s %s nginx\n' "$keyring" "$distro" "$codename"
}

_nginx_render_official_pin() {
    printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n'
}

_nginx_install_official_keyring() {
    local keyring dir tmp_key tmp_ring
    command_exists curl || return 1
    command_exists gpg || return 1
    keyring="$(_nginx_keyring_path)"
    dir="$(dirname "$keyring")"
    mkdir -p "$dir" || return 1
    tmp_key=$(mktemp "${dir}/.tmp.server-manage.nginx-key.XXXXXX") || return 1
    _tmp_register "$tmp_key"
    tmp_ring=$(mktemp "${dir}/.tmp.server-manage.nginx-keyring.XXXXXX") || {
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    }
    _tmp_register "$tmp_ring"
    if ! curl -fsSL https://nginx.org/keys/nginx_signing.key -o "$tmp_key"; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    if ! gpg --batch --yes --dearmor -o "$tmp_ring" "$tmp_key" 2>/dev/null; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    chmod 644 "$tmp_ring" 2>/dev/null || true
    chown root:root "$tmp_ring" 2>/dev/null || true
    if ! mv "$tmp_ring" "$keyring"; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    _tmp_unregister "$tmp_ring"
    rm -f "$tmp_key" 2>/dev/null || true
    _tmp_unregister "$tmp_key"
    return 0
}

_nginx_write_official_apt_files() {
    local distro="$1" codename="$2" keyring source_file pin_file source_content pin_content
    keyring="$(_nginx_keyring_path)"
    source_file="$(_nginx_source_list_path)"
    pin_file="$(_nginx_preferences_path)"
    source_content="$(_nginx_render_official_source "$distro" "$codename" "$keyring")" || return 1
    pin_content="$(_nginx_render_official_pin)" || return 1
    write_file_atomic "$source_file" "$source_content" || return 1
    chmod 644 "$source_file" 2>/dev/null || true
    write_file_atomic "$pin_file" "$pin_content" || return 1
    chmod 644 "$pin_file" 2>/dev/null || true
}

_nginx_write_stream_module_conf() {
    local so="$1" conf_file content
    [[ -f "$so" && "$so" == /* && "$so" != *$'\n'* ]] || return 1
    conf_file="$(_nginx_stream_module_conf_path)"
    content="$(printf 'load_module %s;\n' "$so")" || return 1
    write_file_atomic "$conf_file" "$content" || return 1
    chmod 644 "$conf_file" 2>/dev/null || true
}

_install_nginx_official() {
    [[ "$PLATFORM" == "debian" ]] || return 1
    command_exists curl || install_package "curl" "silent" || return 1
    install_package "gnupg2" "silent" || install_package "gnupg" "silent" || true
    install_package "ca-certificates" "silent" || true
    install_package "lsb-release" "silent" || true
    local codename; codename=$(lsb_release -cs 2>/dev/null || true)
    [[ -n "$codename" ]] || { print_error "无法获取发行版代号 (lsb_release)"; return 1; }
    local distro="ubuntu"
    grep -qi debian /etc/os-release 2>/dev/null && distro="debian"
    if ! _nginx_install_official_keyring; then
        print_error "下载 nginx.org 签名密钥失败"
        return 1
    fi
    if ! _nginx_write_official_apt_files "$distro" "$codename"; then
        print_error "写入 nginx.org apt 源失败"
        return 1
    fi
    APT_UPDATED=0
    update_apt_cache
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx >/dev/null 2>&1 || return 1
    # enable --now 对已运行的 nginx 是 no-op（不会重启），换源装的带 stream 新二进制不会生效；
    # 显式 restart 确保运行态换成新二进制，再复核 stream 可用。
    if is_systemd; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl restart nginx >/dev/null 2>&1 || true
    else
        service nginx restart >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1 || true
    fi
    _check_nginx_stream
}

# 确保 nginx 具备可用的 stream 模块。返回 0 表示可用。
# 策略：已可用→直接返回；有动态 so→注入 load_module；否则装官方源（静态编入）。
_ensure_nginx_stream() {
    if _check_nginx_stream; then
        return 0
    fi
    # 发行版自带 libnginx-mod-stream 的情况：先尝试装该包
    if [[ "$PLATFORM" == "debian" ]]; then
        if ! _nginx_stream_module_available; then
            update_apt_cache
            apt-get install -y libnginx-mod-stream >/dev/null 2>&1 || true
        fi
    fi
    # 有动态 so 但未加载 → 注入 load_module 到 nginx.conf 顶部
    if _nginx_stream_module_available; then
        local so=""
        for so in /usr/lib/nginx/modules/ngx_stream_module.so /usr/share/nginx/modules/ngx_stream_module.so; do
            [[ -f "$so" ]] && break
        done
        # Debian 的 libnginx-mod-stream 会在 modules-enabled 放 .conf 自动 load，
        # 若已如此则 _check_nginx_stream 已返回 0；这里兜底手动 load。
        if ! ls /etc/nginx/modules-enabled/ 2>/dev/null | grep -q stream; then
            _nginx_write_stream_module_conf "$so" || return 1
        fi
        # 关键：load_module 只在 nginx 启动时处理，reload(SIGHUP) 不会把新动态模块加载进
        # 正在运行的 master 进程。若此处只 reload，运行态 nginx 仍无 stream，而调用方（enable）
        # 随后会让 sing-box 下沉释放 443，届时公网 443 无人监听 → 节点全废却可能误报成功。
        # 故写入 load_module 后必须 restart（而非 reload），让模块真正加载，再复核。
        if nginx -t >/dev/null 2>&1; then
            if is_systemd; then
                systemctl restart nginx >/dev/null 2>&1 || true
            else
                service nginx restart >/dev/null 2>&1 || { nginx -s stop 2>/dev/null; nginx 2>/dev/null; } || true
            fi
            # restart 后用运行态证据复核：nginx -V 含 stream 模块，或已能实际解析 stream{}。
            # _check_nginx_stream 只看配置文件存在偏乐观，这里叠加 nginx -t 通过 + 服务在跑。
            if _check_nginx_stream && nginx -t >/dev/null 2>&1 \
               && { ! is_systemd || systemctl is-active --quiet nginx; }; then
                return 0
            fi
        fi
    fi
    # 最后手段：换官方源装带 stream 的 nginx
    print_warn "当前 nginx 无 stream 模块，尝试安装官方 nginx.org 源版本 (含 stream)..."
    _install_nginx_official
}

_check_certbot_dns_cf() {
    command_exists certbot || return 1
    certbot plugins 2>/dev/null | grep -q dns-cloudflare || return 1
    # Ubuntu 20.04: certbot-dns-cloudflare 0.39 与 cloudflare 2.1 不兼容
    local cb_ver=$(certbot --version 2>&1 | grep -oP '[\d.]+')
    if [[ "${cb_ver%%.*}" == "0" ]]; then
        print_warn "certbot $cb_ver 版本过旧，不支持 API Token"
        return 1
    fi
    return 0
}

_check_nginx_dirs() {
    [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]
}

# ── 通用辅助函数 ──

# 安全加载 .conf 配置文件（避免 source 注入风险）
_safe_source_conf() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    # 仅读取 KEY="VALUE" 格式的行，忽略其他内容
    while IFS='=' read -r key val; do
        # 跳过注释和空行
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        # 去除首尾引号和空格
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | sed 's/^"//;s/"$//' | sed "s/^'//;s/'$//")
        # 仅允许合法变量名
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        printf -v "$key" '%s' "$val"
    done < "$file"
}

# Nginx 安全重载
_nginx_reload() {
    if is_systemd; then
        systemctl reload nginx
    else
        nginx -s reload 2>/dev/null || service nginx reload
    fi
}

# Reality 443 共存：建站请求的 HTTPS 端口下沉。
# 共存启用且用户请求 443 时，改写为 web 内部端口（真站退到 loopback，443 归 nginx stream）。
# 回显最终生效端口（stdout）；说明打到 stderr，不污染回显。未启用或非 443 原样返回。
# 依赖 15-singbox-reality.sh 的 reality_coexist_enabled / reality_coexist_web_port（构建时同脚本）。
_web_coexist_https_port() {
    local requested="$1" web_port
    if ! declare -F reality_coexist_enabled >/dev/null 2>&1 || ! reality_coexist_enabled; then
        printf '%s' "$requested"; return 0
    fi
    [[ "$requested" == "443" ]] || { printf '%s' "$requested"; return 0; }
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$web_port" || { printf '%s' "$requested"; return 0; }
    print_warn "本机已启用 Reality 443 共存，网站自动使用 ${web_port}，由 nginx 分流层统一对外提供 443。" >&2
    printf '%s' "$web_port"
}

# Reality 443 共存：计算 80→HTTPS 跳转应带的端口后缀。
# 常规：非 443 端口跳转要带 ":端口"。但共存下真站虽监听 web 内部端口(如 12443)，
# 对外仍由 nginx stream 经 443 提供，故此时后缀必须为空（跳到隐含 443），否则会 301 到
# 公网不可达的内部端口导致真站 HTTP 入口失效。回显后缀（空或 ":端口"）到 stdout。
_web_coexist_redir_suffix() {
    local https_port="$1" web_port
    if declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled; then
        web_port="$(reality_coexist_web_port 2>/dev/null || true)"
        # 该站监听的正是共存 web 内部端口 → 对外是 443，后缀留空
        [[ -n "$web_port" && "$https_port" == "$web_port" ]] && { printf '%s' ""; return 0; }
    fi
    [[ "$https_port" != "443" ]] && printf ':%s' "$https_port"
    return 0
}

# Reality 443 共存：判断某端口是否为共存 web 内部端口（仅 loopback，不应对公网放行）。
# 返回 0 表示"是内部端口，调用方应跳过 ufw allow"；否则返回 1（正常放行）。
_web_coexist_is_inner_port() {
    local port="$1" web_port
    declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled || return 1
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    [[ -n "$web_port" && "$port" == "$web_port" ]]
}

_web_allow_public_tcp_port() {
    local port="$1" comment="${2:-Web}" label="${3:-${port}/tcp}" rc
    if ! declare -F firewall_allow_tcp_port >/dev/null 2>&1; then
        print_warn "未找到防火墙放行 helper，请手动确认 ${label} 已放行。"
        return 2
    fi
    firewall_allow_tcp_port "$port" "$comment"
    rc=$?
    case "$rc" in
        0)
            print_success "已放行端口 ${label}"
            return 0
            ;;
        2)
            print_info "请确认服务器防火墙/云安全组已放行 ${label}"
            return 0
            ;;
        *)
            print_error "防火墙放行失败: ${label}"
            return 1
            ;;
    esac
}

# 确保 SSL 参数文件存在
_ensure_ssl_params() {
    [[ -f /etc/nginx/snippets/ssl-params.conf ]] && return 0
    mkdir -p /etc/nginx/snippets
    local ssl_params="ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security \"max-age=15768000\" always;"
    write_file_atomic "/etc/nginx/snippets/ssl-params.conf" "$ssl_params"
}

# 生成 HTTPS listen + HTTP/2 配置块。
# Nginx 1.25.1 起官方将 `listen ... http2` 标记为 deprecated，推荐独立 `http2 on;`。
# Debian/Ubuntu 稳定仓库仍可能是旧版 Nginx，旧版又不认识 `http2 on;`，因此按运行时版本选择语法。
_nginx_tls_http2_block() {
    local port="$1" version raw major minor patch
    raw=$(nginx -v 2>&1 || true)
    version=$(echo "$raw" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    major=${version%%.*}
    minor=${version#*.}; minor=${minor%%.*}
    patch=${version##*.}

    # Reality 443 共存：若本 server 监听的正是共存 web 内部端口，则只绑 loopback
    # （127.0.0.1 + [::1]），使该站仅能经 nginx stream 443 分流到达，杜绝内部端口公网暴露。
    # 非共存 / 非内部端口保持原样绑全地址。
    local host_v4="" host_v6="[::]:"
    if declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled; then
        local _wp; _wp="$(reality_coexist_web_port 2>/dev/null || true)"
        if [[ -n "$_wp" && "$port" == "$_wp" ]]; then
            host_v4="127.0.0.1:"; host_v6="[::1]:"
        fi
    fi

    if [[ -n "$version" ]] && {
        (( major > 1 )) ||
        (( major == 1 && minor > 25 )) ||
        (( major == 1 && minor == 25 && patch >= 1 ))
    }; then
        printf '    listen %s%s ssl;\n' "$host_v4" "$port"
        printf '    listen %s%s ssl;\n' "$host_v6" "$port"
        printf '    http2 on;\n'
    else
        printf '    listen %s%s ssl %s;\n' "$host_v4" "$port" "http2"
        printf '    listen %s%s ssl %s;\n' "$host_v6" "$port" "http2"
    fi
}

_nginx_deploy_conf_restore() {
    local avail="$1" enabled="$2" had_avail="$3" had_enabled="$4" enabled_was_symlink="$5" old_enabled_target="$6" backup_avail="$7" backup_enabled="$8"
    rm -f "$enabled"
    if [[ "$had_enabled" -eq 1 ]]; then
        if [[ "$enabled_was_symlink" -eq 1 && -n "$old_enabled_target" ]]; then
            ln -s "$old_enabled_target" "$enabled" 2>/dev/null || true
        elif [[ -n "$backup_enabled" && -e "$backup_enabled" ]]; then
            mv "$backup_enabled" "$enabled" 2>/dev/null || true
        fi
    fi
    if [[ "$had_avail" -eq 1 && -n "$backup_avail" && -e "$backup_avail" ]]; then
        mv "$backup_avail" "$avail" 2>/dev/null || true
    else
        rm -f "$avail"
    fi
}

# Nginx 配置部署（写入 + 测试 + 加载，失败自动回滚）
# 用法: _nginx_deploy_conf "域名" "配置内容" 成功返回0，失败返回1
_nginx_deploy_conf() {
    local domain="$1" conf_content="$2"
    local sites_available="${NGINX_SITES_AVAILABLE_DIR:-/etc/nginx/sites-available}"
    local sites_enabled="${NGINX_SITES_ENABLED_DIR:-/etc/nginx/sites-enabled}"
    local avail="${sites_available}/${domain}.conf"
    local enabled="${sites_enabled}/${domain}.conf"
    local backup_avail="" backup_enabled="" old_enabled_target=""
    local had_avail=0 had_enabled=0 enabled_was_symlink=0

    if [[ -e "$avail" ]]; then
        had_avail=1
        backup_avail=$(mktemp "/etc/nginx/sites-available/.${domain}.conf.bak.XXXXXX") || return 1
        cp -a "$avail" "$backup_avail" || { rm -f "$backup_avail"; return 1; }
    fi
    if [[ -L "$enabled" ]]; then
        had_enabled=1
        enabled_was_symlink=1
        old_enabled_target=$(readlink "$enabled" 2>/dev/null || true)
    elif [[ -e "$enabled" ]]; then
        had_enabled=1
        backup_enabled=$(mktemp "/etc/nginx/sites-enabled/.${domain}.conf.bak.XXXXXX") || { rm -f "$backup_avail"; return 1; }
        cp -a "$enabled" "$backup_enabled" || { rm -f "$backup_avail" "$backup_enabled"; return 1; }
    fi

    write_file_atomic "$avail" "$conf_content" || { print_error "写入 Nginx 配置失败"; rm -f "$backup_avail" "$backup_enabled"; return 1; }
    if ! ln -sfn "$avail" "$enabled"; then
        print_error "启用 Nginx 配置失败"
        _nginx_deploy_conf_restore "$avail" "$enabled" "$had_avail" "$had_enabled" "$enabled_was_symlink" "$old_enabled_target" "$backup_avail" "$backup_enabled"
        nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
        rm -f "$backup_avail" "$backup_enabled"
        return 1
    fi

    if nginx -t >/dev/null 2>&1 && _nginx_reload; then
        rm -f "$backup_avail" "$backup_enabled"
        return 0
    fi

    print_error "Nginx 配置测试或重载失败，正在恢复旧配置！"
    nginx -t 2>&1 | tail -5
    _nginx_deploy_conf_restore "$avail" "$enabled" "$had_avail" "$had_enabled" "$enabled_was_symlink" "$old_enabled_target" "$backup_avail" "$backup_enabled"
    nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
    rm -f "$backup_avail" "$backup_enabled"
    return 1
}

web_env_check() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        for pkg in jq curl openssl-util ca-bundle; do
            if ! opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
                opkg update >/dev/null 2>&1
                opkg install "$pkg" >/dev/null 2>&1 || true
            fi
        done
        if ! command_exists certbot; then
            print_warn "OpenWrt 上 certbot 可能不可用。"
            print_info "建议使用 opkg install acme acme-dnsapi 或手动安装 certbot。"
            if ! confirm "是否继续尝试？"; then
                return 1
            fi
        fi
        if ! command_exists nginx; then
            print_info "安装 nginx..."
            opkg update >/dev/null 2>&1
            opkg install nginx-ssl >/dev/null 2>&1 || opkg install nginx >/dev/null 2>&1 || {
                print_warn "nginx 安装失败，反代功能可能不可用"
            }
        fi
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets 2>/dev/null || true
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        return 0
    fi
    print_info "Web 环境依赖自检..."
    local deps=(
        "jq|jq|jq"
        "nginx|nginx|nginx"
        "nginx 目录结构|nginx_dirs|nginx_dirs"
        "certbot|certbot|certbot"
        "certbot dns-cloudflare 插件|certbot_dns_cf|certbot_dns_cf"
    )

    # 第一轮: 检查
    _web_dep_check_results=()
    local need_fix=0
    for dep in "${deps[@]}"; do
        IFS='|' read -r name check_id install_id <<< "$dep"
        if ! _web_dep_verify "$name" "$check_id"; then
            need_fix=1
        fi
    done
    echo -e "${C_CYAN}依赖检查结果:${C_RESET}"
    for r in "${_web_dep_check_results[@]}"; do
        echo -e "  $r"
    done

    # 第二轮: 修复
    if [[ $need_fix -eq 1 ]]; then
        print_warn "检测到缺失依赖，正在自动修复..."
        local fix_failed=0
        for dep in "${deps[@]}"; do
            IFS='|' read -r name check_id install_id <<< "$dep"
            if ! _web_dep_fix "$name" "$check_id" "$install_id"; then
                fix_failed=1
            fi
        done

        # 第三轮: 最终验证
        if [[ $fix_failed -eq 1 ]]; then
            print_error "部分依赖修复失败，最终验证:"
            local final_ok=1
            for dep in "${deps[@]}"; do
                IFS='|' read -r name check_id install_id <<< "$dep"
                if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"
                else
                    echo -e "  ${C_RED}✗${C_RESET} $name"
                    final_ok=0
                fi
            done
            if [[ $final_ok -eq 0 ]]; then
                print_error "关键依赖缺失，无法继续。请手动修复后重试。"
                echo "手动修复参考:
  apt-get update
  apt-get install -y certbot python3-certbot-dns-cloudflare nginx jq
或使用 snap:
  snap install --classic certbot
  snap install certbot-dns-cloudflare
  snap connect certbot:plugin certbot-dns-cloudflare"
                return 1
            fi
        fi
        print_success "所有依赖已就绪"
    else
        print_success "所有依赖检查通过"
    fi
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    return 0
}

# ── 通用域名清理 ──
# 一次性清除指定域名的所有关联配置
# 用法: _web_cleanup_domain "域名" [quiet]
# quiet 模式仅打印摘要，不打印每项细节
_web_cleanup_domain() {
    local domain="$1" quiet="${2:-}"
    [[ -z "$domain" ]] && return 1
    if ! validate_domain "$domain"; then
        [[ -z "$quiet" ]] && print_error "域名格式无效，拒绝清理: $domain"
        return 1
    fi
    local cleaned=0
    local cert_prefix="${CERT_PATH_PREFIX%/}"
    if [[ -z "$cert_prefix" || "$cert_prefix" == "/" ]]; then
        [[ -z "$quiet" ]] && print_error "证书目录前缀异常，拒绝清理"
        return 1
    fi

    # Certbot 证书
    if certbot certificates 2>/dev/null | grep -Fq -- "$domain"; then
        certbot delete --cert-name "$domain" --non-interactive 2>/dev/null && cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "证书已删除"
    fi
    # 本地证书拷贝
    rm -rf "${cert_prefix}/${domain}" 2>/dev/null

    # Nginx 配置
    local ng_en="/etc/nginx/sites-enabled/${domain}.conf"
    local ng_av="/etc/nginx/sites-available/${domain}.conf"
    if [[ -f "$ng_en" || -f "$ng_av" ]]; then
        rm -f "$ng_en" "$ng_av"
        nginx -t >/dev/null 2>&1 && _nginx_reload 2>/dev/null
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "Nginx 配置已删除"
        # 443 共存：站点 conf 已删，刷新 stream SNI 白名单剔除该域名（未启用则 no-op）。
        # 与建站三处（09c/09d/09e）对称，避免白名单残留指向已消失 web server 的死映射。
        declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
    fi

    # Hook 脚本
    local hook hook_cleaned=false
    for hook in "${CERT_HOOKS_DIR}/renew-${domain}.sh" "/root/cert-renew-hook-${domain}.sh"; do
        if [[ -f "$hook" ]]; then
            rm -f "$hook" && hook_cleaned=true
        fi
    done
    if [[ "$hook_cleaned" == "true" ]]; then
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "Hook 脚本已删除"
    fi

    # Cron 任务 (续签)
    cron_remove_job "CertRenew_${domain}" 2>/dev/null
    cron_remove_job "cert-renew-hook-${domain}.sh" 2>/dev/null

    # CF 凭据
    rm -f "/root/.cloudflare-${domain}.ini" 2>/dev/null

    # DDNS 配置 (域名本身 + origin.${domain} 子域；不要用通配，避免误删其他域名的 origin DDNS)
    local ddns_cleaned=false
    for ddns_f in "${DDNS_CONFIG_DIR}/${domain}.conf" "${DDNS_CONFIG_DIR}/origin.${domain}.conf"; do
        if [[ -f "$ddns_f" ]]; then
            rm -f "$ddns_f"; ddns_cleaned=true
        fi
    done
    # 根域 origin DDNS（仅当 root_part 与 domain 不同才单独删）
    local root_part="${domain#*.}"
    if [[ "$root_part" != "$domain" && -f "${DDNS_CONFIG_DIR}/origin.${root_part}.conf" ]]; then
        rm -f "${DDNS_CONFIG_DIR}/origin.${root_part}.conf"; ddns_cleaned=true
    fi
    if [[ "$ddns_cleaned" == "true" ]]; then
        cleaned=$((cleaned+1))
        ddns_rebuild_cron 2>/dev/null
        [[ -z "$quiet" ]] && print_success "DDNS 配置已清理"
    fi

    # 提示: CF Origin Rule 无法自动清理 (需 API Token)
    [[ -z "$quiet" ]] && print_info "提示: 如有 CF Origin Rule，请通过菜单 [12.删除回源规则] 手动清理"

    # 域名管理配置
    if [[ -f "${CONFIG_DIR}/${domain}.conf" ]]; then
        rm -f "${CONFIG_DIR}/${domain}.conf"
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "域名管理配置已删除"
    fi

    if [[ $cleaned -gt 0 ]]; then
        [[ -n "$quiet" ]] && print_success "已清理 ${domain} 的 ${cleaned} 项旧配置"
        log_action "Cleanup domain: $domain ($cleaned items)"
    fi
    return 0
}

# ── CF API 核心 ──

_cf_api() {
    # 基础速率保护：防止触发 CF API 1200 req/5min 限制
    sleep 0.3 2>/dev/null || sleep 1
    local method=$1 endpoint=$2 token=$3; shift 3
    local attempt resp
    for attempt in 1 2 3; do
        resp=$(curl -s --max-time 30 -X "$method" "https://api.cloudflare.com/client/v4${endpoint}" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" "$@" 2>/dev/null)
        # 成功获取响应则返回
        [[ -n "$resp" ]] && { echo "$resp"; return 0; }
        # 重试前等待（指数退避）
        [[ $attempt -lt 3 ]] && sleep $((attempt * 2))
    done
    # 3 次全失败，返回错误 JSON
    echo '{"success":false,"errors":[{"message":"API 请求超时（已重试 3 次）"}]}'
    return 1
}

_cf_api_ok() { [[ "$(jq -r '.success // false' 2>/dev/null <<< "$1")" == "true" ]]; }
_cf_api_err() { jq -r '.errors[0].message // "未知错误"' 2>/dev/null <<< "$1" || echo "未知错误"; }

# 分页读取 Token 可见的 Cloudflare Zones。
# 参数:
#   $1 token
#   $2 附加 query（可选，如 status=active）
#   $3 per_page（可选，默认 50）
_cf_list_zones() {
    local token="$1" query="${2:-}" per_page="${3:-50}"
    local page=1 resp all='[]' total_pages count endpoint

    while true; do
        endpoint="/zones?per_page=${per_page}&page=${page}"
        [[ -n "$query" ]] && endpoint="${endpoint}&${query}"
        resp=$(_cf_api GET "$endpoint" "$token")
        if ! _cf_api_ok "$resp"; then
            echo "$resp"
            return 1
        fi

        all=$(jq -c --argjson acc "$all" '$acc + (.result // [])' <<< "$resp" 2>/dev/null) || {
            echo '{"success":false,"errors":[{"message":"解析 Zone 分页响应失败"}]}'
            return 1
        }
        total_pages=$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)
        count=$(jq -r '.result | length' <<< "$resp" 2>/dev/null)

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

# CF API Token 验证
_cf_verify_token() {
    local token="$1"
    local vr=$(_cf_api GET "/user/tokens/verify" "$token")
    if ! _cf_api_ok "$vr"; then
        print_error "Token 验证失败: $(_cf_api_err "$vr")"
        return 1
    fi
    return 0
}

# 读取并验证 CF API Token
_cf_read_token() {
    local _var_name="${1:-CF_API_TOKEN}"
    local token=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    print_info "验证 Token..."
    if ! _cf_verify_token "$token"; then
        return 1
    fi
    print_success "Token 有效"
    printf -v "$_var_name" '%s' "$token"
    return 0
}

# ── DNS 操作 ──

_cf_get_zone_id() {
    local domain=$1 token=$2
    # 逐级尝试: gpt.xx.kg -> xx.kg -> kg
    local current="$domain"
    while [[ "$current" == *"."* ]]; do
        local resp=$(_cf_api GET "/zones?name=$current" "$token")
        if _cf_api_ok "$resp"; then
            local zid=$(echo "$resp" | jq -r '.result[0].id // empty')
            [[ -n "$zid" ]] && { echo "$zid"; return 0; }
        fi
        current="${current#*.}"
    done
    # Fallback: 列出所有 zone，本地匹配 (解决二级域名 zone 查找问题)
    local resp=$(_cf_list_zones "$token")
    if _cf_api_ok "$resp"; then
        local try="$domain"
        while [[ "$try" == *"."* ]]; do
            local zid=$(echo "$resp" | jq -r --arg d "$try" '.result[] | select(.name == $d) | .id' | head -1)
            [[ -n "$zid" ]] && { echo "$zid"; return 0; }
            try="${try#*.}"
        done
    fi
    return 1
}

_cf_dns_delete() {
    local zone_id=$1 token=$2 type=$3 name=$4
    local resp
    resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
    if ! _cf_api_ok "$resp"; then
        print_error "读取 DNS 记录失败: $(_cf_api_err "$resp")"
        return 1
    fi
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    [[ -n "$rid" ]] || return 0
    resp=$(_cf_api DELETE "/zones/$zone_id/dns_records/$rid" "$token")
    if ! _cf_api_ok "$resp"; then
        print_error "删除 DNS 记录失败: $(_cf_api_err "$resp")"
        return 1
    fi
}

_cf_dns_snapshot_records() {
    local zone_id="$1" token="$2" name="$3"
    shift 3
    local types=("$@")
    [[ ${#types[@]} -gt 0 ]] || types=(A AAAA CNAME)

    local type resp snapshot='[]'
    for type in "${types[@]}"; do
        resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
        if ! _cf_api_ok "$resp"; then
            print_error "读取 DNS 快照失败: $type $(_cf_api_err "$resp")"
            return 1
        fi
        snapshot=$(jq -c --argjson acc "$snapshot" \
            '$acc + [(.result // [])[] | {type,name,content,ttl,proxied,comment,tags} | with_entries(select(.value != null))]' \
            <<< "$resp") || {
            print_error "解析 DNS 快照失败: $type"
            return 1
        }
    done
    printf '%s\n' "$snapshot"
}

_cf_dns_restore_records() {
    local zone_id="$1" token="$2" name="$3" snapshot="$4"
    shift 4
    local types=("$@")
    [[ ${#types[@]} -gt 0 ]] || types=(A AAAA CNAME)

    if ! jq -e 'type == "array"' >/dev/null 2>&1 <<< "$snapshot"; then
        print_error "DNS 快照格式无效，无法恢复"
        return 1
    fi

    local type resp id payload record
    for type in "${types[@]}"; do
        resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
        if ! _cf_api_ok "$resp"; then
            print_error "读取待恢复 DNS 记录失败: $type $(_cf_api_err "$resp")"
            return 1
        fi
        while IFS= read -r id; do
            [[ -n "$id" ]] || continue
            resp=$(_cf_api DELETE "/zones/$zone_id/dns_records/$id" "$token")
            if ! _cf_api_ok "$resp"; then
                print_error "删除待恢复 DNS 记录失败: $type $(_cf_api_err "$resp")"
                return 1
            fi
        done < <(jq -r '.result[]?.id // empty' <<< "$resp")
    done

    while IFS= read -r record; do
        [[ -n "$record" ]] || continue
        payload=$(jq -c '{
            type: .type,
            name: .name,
            content: .content,
            ttl: (.ttl // 1),
            proxied: (.proxied // false)
        }
        + (if has("comment") then {comment: .comment} else {} end)
        + (if has("tags") then {tags: .tags} else {} end)' <<< "$record") || {
            print_error "构造 DNS 恢复 payload 失败"
            return 1
        }
        resp=$(_cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$payload")
        if ! _cf_api_ok "$resp"; then
            print_error "恢复 DNS 记录失败: $(_cf_api_err "$resp")"
            return 1
        fi
    done < <(jq -c '.[]' <<< "$snapshot")
    return 0
}

# 通用 DNS 记录更新
_cf_update_dns_record() {
    local zone_id="$1" token="$2" domain="$3" type="$4" ip="$5" proxied="$6"
    if [[ -z "$ip" ]]; then
        print_error "$type 记录缺少目标 IP，已中止"
        return 1
    fi
    print_info "处理 $type 记录 -> $ip (代理: $proxied)"
    local records=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain" "$token")
    if ! _cf_api_ok "$records"; then
        print_error "读取 $type 记录失败: $(_cf_api_err "$records")"
        return 1
    fi
    local record_id=$(jq -r '.result[0].id // empty' <<< "$records")
    local count=$(jq -r '.result | length' <<< "$records")
    local extra_ids=""
    if [[ "$count" -gt 1 ]]; then
        print_warn "警告: 存在 ${count} 条 $type 记录，将保留第一条并清理多余记录。"
        extra_ids=$(jq -r '.result[1:][] | .id // empty' <<< "$records")
    fi
    local data=$(jq -n --arg type "$type" --arg name "$domain" --arg content "$ip" --argjson proxied "$proxied" \
        '{type:$type, name:$name, content:$content, ttl:1, proxied:$proxied}')
    local resp
    if [[ -n "$record_id" ]]; then
        resp=$(_cf_api PUT "/zones/$zone_id/dns_records/$record_id" "$token" --data "$data")
    else
        resp=$(_cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$data")
    fi
    if _cf_api_ok "$resp"; then
        local extra_id delete_resp
        while IFS= read -r extra_id; do
            [[ -n "$extra_id" ]] || continue
            delete_resp=$(_cf_api DELETE "/zones/$zone_id/dns_records/$extra_id" "$token")
            if ! _cf_api_ok "$delete_resp"; then
                print_error "删除多余 $type 记录失败: $(_cf_api_err "$delete_resp")"
                return 1
            fi
        done <<< "$extra_ids"
        print_success "$([[ -n "$record_id" ]] && echo '更新' || echo '创建')成功"
        return 0
    else
        print_error "$([[ -n "$record_id" ]] && echo '更新' || echo '创建')失败: $(_cf_api_err "$resp")"
        return 1
    fi
}

cf_dns_sync_node_grey() {
    local token="$1" domain="$2" ipv4="${3:-}" ipv6="${4:-}" enable_ddns="${5:-true}" interval="${6:-5}"
    [[ -z "$token" || -z "$domain" ]] && return 1
    command_exists jq || install_package "jq" "silent" || return 1
    print_info "验证 Cloudflare Token..."
    _cf_verify_token "$token" || return 1
    local zone_id
    zone_id=$(_cf_get_zone_id "$domain" "$token")
    [[ -z "$zone_id" ]] && { print_error "无法获取 Zone ID: $domain"; return 1; }
    [[ -n "$ipv4" || -n "$ipv6" ]] || { print_error "未提供任何公网 IP，无法同步 DNS/DDNS"; return 1; }
    local has_v4=false has_v6=false
    if [[ -n "$ipv4" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "A" "$ipv4" "false" || return 1
        has_v4=true
    fi
    if [[ -n "$ipv6" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "AAAA" "$ipv6" "false" || return 1
        has_v6=true
    fi
    if [[ "$enable_ddns" == "true" ]]; then
        ddns_setup_noninteractive "$domain" "$token" "$zone_id" "$has_v4" "$has_v6" "false" "$interval" || return 1
        print_success "DDNS 已启用: $domain"
    fi
    log_action "Cloudflare Reality node DNS synced: $domain proxied=false"
}

# ── DNS 智能解析 ──

_CF_RESULT_DOMAIN=""
_CF_RESULT_TOKEN=""

web_cf_dns_update() {
    local DOMAIN="" CF_API_TOKEN=""
    _CF_RESULT_DOMAIN=""
    _CF_RESULT_TOKEN=""
    print_title "Cloudflare DNS 智能解析"
    command_exists jq || install_package "jq" "silent"
    print_info "正在探测本机公网 IP..."
    local ipv4 ipv6
    if [[ ( -n "${CACHED_IPV4:-}" && "${CACHED_IPV4:-}" != "N/A" ) || ( -n "${CACHED_IPV6:-}" && "${CACHED_IPV6:-}" != "N/A" ) ]]; then
        ipv4="${CACHED_IPV4:-}"; ipv6="${CACHED_IPV6:-}"
    else
        ipv4=$(get_public_ipv4 2>/dev/null || true)
        ipv6=$(get_public_ipv6 2>/dev/null || true)
    fi
    if [[ -n "$ipv4" ]]; then
        if ! validate_ip "$ipv4" || [[ "$ipv4" == *:* ]]; then
            print_warn "IPv4 探测结果异常 ($ipv4)，已忽略"
            ipv4=""
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        if ! validate_ip "$ipv6" || [[ "$ipv6" != *:* ]]; then
            print_warn "IPv6 探测结果异常 ($ipv6)，已忽略"
            ipv6=""
        fi
    fi
    CACHED_IPV4="$ipv4"; CACHED_IPV6="$ipv6"
    echo "----------------------------------------"
    echo "IPv4: ${ipv4:-[✗] 未检测到}"
    echo "IPv6: ${ipv6:-[✗] 未检测到}"
    echo "----------------------------------------"
    echo "1. 仅解析 IPv4 (A)
2. 仅解析 IPv6 (AAAA)
3. 双栈解析 (A + AAAA)
0. 返回上一级"
    read -e -r -p "请选择: " mode
    case "$mode" in
        1|2|3) ;;
        0|q|Q|"") return ;;
        *) print_error "无效选择，请输入 1/2/3，或输入 0 返回"; pause; return ;;
    esac
    if [[ "$mode" == "1" && -z "$ipv4" ]]; then
        print_error "仅 IPv4 模式未检测到 IPv4 地址，无法配置 A 记录"
        pause; return 1
    fi
    if [[ "$mode" == "2" && -z "$ipv6" ]]; then
        print_error "仅 IPv6 模式未检测到 IPv6 地址，无法配置 AAAA 记录"
        pause; return 1
    fi
    if [[ "$mode" == "3" && ( -z "$ipv4" || -z "$ipv6" ) ]]; then
        print_error "双栈解析需要同时检测到 IPv4 和 IPv6 地址"
        pause; return 1
    fi
    # 读取并验证 Token
    if ! _cf_read_token "CF_API_TOKEN"; then
        pause; return
    fi
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名: " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    print_info "正在获取 Zone ID..."
    local zone_id=""
    zone_id=$(_cf_get_zone_id "$DOMAIN" "$CF_API_TOKEN")
    if [[ -z "$zone_id" ]]; then
        print_error "无法获取 Zone ID，请检查 Token 权限和域名是否已托管在 CF"
        pause; return
    fi
    print_success "找到 Zone ID: $zone_id"
    echo -e "${C_YELLOW}注意: 开启代理后，只有 HTTP/HTTPS 流量能通过 Cloudflare。${C_RESET}"
    echo -e "${C_YELLOW}SSH、RDP、端口转发等非 HTTP 服务将无法使用此域名访问。${C_RESET}"
    read -e -r -p "是否开启 Cloudflare 代理 (小云朵)? [y/N]: " proxy_choice
    local proxied="false"
    [[ "${proxy_choice,,}" == "y" ]] && proxied="true"

    # 使用提取的模块级函数
    case $mode in
        1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied" || { pause; return 1; } ;;
        2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" || { pause; return 1; } ;;
        3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied" || { pause; return 1; }
           _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" || { pause; return 1; } ;;
    esac
    print_success "DNS 配置完成。"
    log_action "Cloudflare DNS updated for $DOMAIN"
    local ddns_v4=$([[ "$mode" == "1" || "$mode" == "3" ]] && echo "true" || echo "false")
    local ddns_v6=$([[ "$mode" == "2" || "$mode" == "3" ]] && echo "true" || echo "false")
    if ! ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_v4" "$ddns_v6" "$proxied"; then
        print_error "DDNS 配置失败"
        pause; return 1
    fi
    _CF_RESULT_DOMAIN="$DOMAIN"
    _CF_RESULT_TOKEN="$CF_API_TOKEN"
    sleep 2
}

# ── Origin Rules ──

_cf_get_origin_ruleset() {
    local token="$1" zone_id="$2"
    local url="https://api.cloudflare.com/client/v4/zones/${zone_id}/rulesets/phases/http_request_origin/entrypoint"
    local attempt resp code body curl_rc
    for attempt in 1 2 3; do
        resp=$(curl -sS --connect-timeout 10 --max-time 30 -w "
%{http_code}" -X GET "$url"             -H "Authorization: Bearer $token" -H "Content-Type: application/json" 2>/dev/null)
        curl_rc=$?
        if [[ $curl_rc -eq 0 && -n "$resp" ]]; then
            code=$(echo "$resp" | tail -1)
            body=$(echo "$resp" | sed '$d')
            [[ "$code" =~ ^[0-9]{3}$ ]] && break
        fi
        [[ $attempt -lt 3 ]] && sleep $((attempt * 2))
    done
    if [[ ${curl_rc:-1} -ne 0 || ! "${code:-}" =~ ^[0-9]{3}$ ]]; then
        echo '{"success":false,"errors":[{"message":"Origin Rules 读取失败或超时"}]}'
        return 1
    fi
    if [[ "$code" == "200" ]]; then
        if _cf_api_ok "$body"; then
            echo "$body"
            return 0
        fi
        echo "$body"
        return 1
    elif [[ "$code" == "404" ]]; then
        return 0
    else
        echo "$body"
        return 1
    fi
}

_cf_put_origin_ruleset() {
    local token="$1" zone_id="$2" rules_json="$3"
    local url="https://api.cloudflare.com/client/v4/zones/${zone_id}/rulesets/phases/http_request_origin/entrypoint"
    local payload
    payload=$(jq -n \
        --argjson rules "$rules_json" \
        '{ "rules": $rules }') || { echo "构造 Origin Rules payload 失败"; return 1; }
    local attempt resp curl_rc
    for attempt in 1 2 3; do
        resp=$(curl -sS --connect-timeout 10 --max-time 30 -X PUT "$url" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" \
            --data "$payload" 2>/dev/null)
        curl_rc=$?
        [[ $curl_rc -eq 0 && -n "$resp" ]] && break
        [[ $attempt -lt 3 ]] && sleep $((attempt * 2))
    done
    if [[ ${curl_rc:-1} -ne 0 || -z "${resp:-}" ]]; then
        echo "Origin Rules 写入失败或超时"
        return 1
    fi
    if _cf_api_ok "$resp"; then
        return 0
    else
        _cf_api_err "$resp"
        return 1
    fi
}

_cf_origin_rules_snapshot() {
    local token="$1" zone_id="$2" existing rules
    if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
        print_error "Origin Rules 快照读取失败"
        return 1
    fi
    if [[ -n "$existing" ]]; then
        rules=$(jq -c '.result.rules // []' <<< "$existing" 2>/dev/null) || {
            print_error "Origin Rules 快照解析失败"
            return 1
        }
    else
        rules="[]"
    fi
    printf '%s\n' "$rules"
}

_cf_origin_rules_restore() {
    local token="$1" zone_id="$2" rules_snapshot="$3" err
    if ! jq -e 'type == "array"' >/dev/null 2>&1 <<< "$rules_snapshot"; then
        print_error "Origin Rules 快照格式无效，无法恢复"
        return 1
    fi
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$rules_snapshot"); then
        print_error "Origin Rules 快照恢复失败: $err"
        return 1
    fi
    return 0
}

web_cf_origin_rule_create() {
    print_title "创建 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    echo -e "${C_YELLOW}功能说明:${C_RESET}"
    echo "  解决运营商封锁 443 端口的问题。
  用户仍用标准 https:// 访问，CF 自动将回源端口改为你指定的端口。
"

    # 收集信息
    local token="" domain="" port=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    while [[ -z "$domain" ]]; do
        read -e -r -p "完整域名 (如 www.example.com): " domain
        if ! validate_domain "$domain"; then
            print_error "域名格式无效"; domain=""
        fi
    done
    while true; do
        read -e -r -p "回源端口 (如 8443, 2053, 2083, 2087, 2096): " port
        if validate_port "$port" 2>/dev/null || [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
            break
        fi
        print_warn "端口无效，请输入 1-65535 之间的数字"
    done

    # 获取 Zone ID
    print_info "获取 Zone ID..."
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID，请检查 Token 权限和域名"; pause; return
    fi
    print_success "Zone ID: $zone_id"

    # 获取现有规则
    print_info "读取现有回源规则..."
    local existing
    existing=$(_cf_get_origin_ruleset "$token" "$zone_id")
    if [[ $? -ne 0 ]]; then
        print_error "API 请求失败: $(echo "$existing" | jq -r '.errors[0].message // "未知错误"')"
        pause; return
    fi

    # 提取现有 rules 数组（如果有的话）
    local existing_rules="[]"
    if [[ -n "$existing" ]]; then
        existing_rules=$(echo "$existing" | jq '.result.rules // []')
    fi

    # 检查是否已存在同域名的规则，如果有则替换
    local desc="Script-Origin-${domain}-${port}"
    local filtered_rules=$(echo "$existing_rules" | jq --arg d "$domain" \
        '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]')

    # 构建新规则
    local new_rule=$(jq -n \
        --arg expr "http.host eq \"${domain}\"" \
        --arg desc "$desc" \
        --argjson port "$port" \
        '{
            "action": "route",
            "action_parameters": { "origin": { "port": $port } },
            "expression": $expr,
            "description": $desc,
            "enabled": true
        }')

    # 合并：旧规则 + 新规则
    local final_rules=$(echo "$filtered_rules" | jq --argjson new "$new_rule" '. + [$new]')

    # 写入
    print_info "写入回源规则..."
    local err
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules"); then
        print_error "规则创建失败: $err"; pause; return
    fi
    print_success "回源规则创建成功！"
    echo -e "  域名: ${C_GREEN}${domain}${C_RESET}"
    echo -e "  链路: 用户 :443 → CF 边缘 → 回源 :${C_GREEN}${port}${C_RESET} → 你的服务器"
    echo -e "  生效: 约 30 秒"

    # 提示服务器端操作
    draw_line
    echo -e "${C_CYAN}服务器端操作提示:${C_RESET}"
    echo "  1. Nginx 监听端口改为 ${port}:"
    echo "     listen ${port} ssl;"
    echo "     http2 on;   # Nginx 1.25.1+；旧版可继续使用 listen ... ssl + HTTP/2 参数"
    echo "  2. 防火墙放行:"
    echo "     ufw allow ${port}/tcp"
    echo "  3. 如果服务器在 NAT 后面（如家宽），路由器需要转发外网 ${port} → 内网 ${port}"
    pause
}

web_cf_origin_rule_list() {
    print_title "查看 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    local token=""
    if ! _cf_read_token "token"; then
        pause; return
    fi
    local domain=""
    read -e -r -p "根域名 (如 example.com): " domain
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID"; pause; return
    fi
    local resp
    if ! resp=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
        print_error "读取回源规则失败: $(echo "$resp" | jq -r '.errors[0].message // "未知错误"')"
        pause; return
    fi
    if [[ -z "$resp" ]]; then
        print_warn "该域名下没有任何回源规则"
        pause; return
    fi
    local count=$(echo "$resp" | jq '.result.rules | length')
    if [[ "$count" == "0" ]]; then
        print_warn "该域名下没有任何回源规则"
        pause; return
    fi
    echo -e "${C_CYAN}当前回源规则 (共 ${count} 条):${C_RESET}"
    draw_line
    echo "$resp" | jq -r '.result.rules[] | [
        "  描述: \(.description // "无")",
        "  表达式: \(.expression)",
        "  回源端口: \(.action_parameters.origin.port // "默认")",
        "  状态: \(if .enabled then "启用" else "禁用" end)",
        "  ---"
    ] | .[]'
    pause
}

web_cf_origin_rule_delete() {
    print_title "删除 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    local token=""
    if ! _cf_read_token "token"; then
        pause; return
    fi
    local domain=""
    read -e -r -p "根域名 (如 example.com): " domain
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID"; pause; return
    fi
    local resp
    if ! resp=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
        print_error "读取回源规则失败: $(echo "$resp" | jq -r '.errors[0].message // "未知错误"')"
        pause; return
    fi
    if [[ -z "$resp" ]]; then
        print_warn "没有任何回源规则"; pause; return
    fi
    local rules=$(echo "$resp" | jq '.result.rules')
    local count=$(echo "$rules" | jq 'length')
    if [[ "$count" == "0" ]]; then
        print_warn "没有任何回源规则"; pause; return
    fi

    # 列出规则供选择
    echo -e "${C_CYAN}当前规则:${C_RESET}"
    for i in $(seq 0 $((count - 1))); do
        local desc=$(echo "$rules" | jq -r ".[$i].description // \"规则$((i+1))\"")
        local expr=$(echo "$rules" | jq -r ".[$i].expression")
        local port=$(echo "$rules" | jq -r ".[$i].action_parameters.origin.port // \"默认\"")
        echo -e "  ${C_GREEN}$((i+1))${C_RESET}. ${desc}"
        echo "     匹配: ${expr} → 端口: ${port}"
    done
    read -e -r -p "输入要删除的规则编号 (0=取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then return; fi
    if [[ ! "$choice" =~ ^[0-9]+$ ]]; then
        print_error "编号无效"; pause; return
    fi
    local idx=$((choice - 1))
    if [[ $idx -lt 0 || $idx -ge $count ]]; then
        print_error "编号无效"; pause; return
    fi
    local del_desc=$(echo "$rules" | jq -r ".[$idx].description // \"规则\"")

    # 移除选中的规则
    local new_rules=$(echo "$rules" | jq --argjson i "$idx" 'del(.[$i])')
    read -e -r -p "确认删除 [${del_desc}]? (y/N): " del_confirm
    [[ "$del_confirm" != "y" && "$del_confirm" != "Y" ]] && return
    print_info "删除中..."
    local err
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$new_rules"); then
        print_error "删除失败: $err"; pause; return
    fi
    print_success "规则已删除"
    pause
}

_web_add_domain_clean_start() {
    local domain="$1" cert_prefix="${CERT_PATH_PREFIX%/}" root_part
    [[ -n "$domain" && -n "$cert_prefix" && "$cert_prefix" != "/" ]] || return 1
    root_part="${domain#*.}"

    local paths=(
        "${CONFIG_DIR}/${domain}.conf"
        "${cert_prefix}/${domain}"
        "${CERT_HOOKS_DIR}/renew-${domain}.sh"
        "/root/cert-renew-hook-${domain}.sh"
        "/root/.cloudflare-${domain}.ini"
        "${DDNS_CONFIG_DIR}/${domain}.conf"
        "${DDNS_CONFIG_DIR}/origin.${domain}.conf"
        "/etc/nginx/sites-available/${domain}.conf"
        "/etc/nginx/sites-enabled/${domain}.conf"
        "/etc/letsencrypt/live/${domain}"
    )
    if [[ "$root_part" != "$domain" ]]; then
        paths+=("${DDNS_CONFIG_DIR}/origin.${root_part}.conf")
    fi

    local path
    for path in "${paths[@]}"; do
        [[ -e "$path" || -L "$path" ]] && return 1
    done
    if command_exists certbot && certbot certificates 2>/dev/null | grep -Fq -- "$domain"; then
        return 1
    fi
    return 0
}

_web_add_domain_rollback() {
    local domain="$1" clean_start="${2:-0}"
    local zone_id="${3:-}" token="${4:-}" dns_snapshot="${5:-}" restore_dns="${6:-0}"
    if [[ "$restore_dns" == "1" && -n "$zone_id" && -n "$token" && -n "$dns_snapshot" ]]; then
        print_warn "安装失败，正在恢复 Cloudflare DNS 快照..."
        if _cf_dns_restore_records "$zone_id" "$token" "$domain" "$dns_snapshot" A AAAA CNAME; then
            print_success "Cloudflare DNS 已恢复到安装前状态"
        else
            print_warn "Cloudflare DNS 快照恢复失败，请人工核查 ${domain} 的 A/AAAA/CNAME 记录"
        fi
    fi

    if [[ "$clean_start" != "1" ]]; then
        print_warn "安装失败：检测到该域名安装前已有本地配置/证书，已跳过自动清理以避免误删旧配置"
        print_info "请检查 ${CONFIG_DIR}/${domain}.conf、${CERT_PATH_PREFIX%/}/${domain}、续签 Hook 与 DDNS 配置是否需要手动清理"
        return 0
    fi

    print_warn "安装失败，正在清理本次创建的本地半成品..."
    _web_cleanup_domain "$domain" "quiet" || {
        print_warn "半成品清理未完全成功，请稍后通过删除域名配置重试"
        return 1
    }
    return 0
}

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    web_env_check || { pause; return 1; }

    # 配置收集阶段
    echo -e "\n${C_CYAN}=== 收集配置信息 ===${C_RESET}\n"

    # 1. CF API Token
    local CF_API_TOKEN=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 -> My Profile -> API Tokens -> Create Token${C_RESET}"
    if ! _cf_read_token "CF_API_TOKEN"; then
        pause; return 1
    fi

    # 2. 选择域名 (自动列出 Token 可管理的域名)
    print_info "获取 Token 可管理的域名列表..."
    local zones_json zone_list=() zone_ids=()
    zones_json=$(_cf_list_zones "$CF_API_TOKEN" "status=active")
    if ! _cf_api_ok "$zones_json"; then
        print_error "获取域名列表失败: $(_cf_api_err "$zones_json")"
        pause; return 1
    fi
    while IFS='|' read -r zname zid; do
        [[ -z "$zname" ]] && continue
        zone_list+=("$zname")
        zone_ids+=("$zid")
    done < <(echo "$zones_json" | jq -r '.result[] | "\(.name)|\(.id)"')

    if [[ ${#zone_list[@]} -eq 0 ]]; then
        print_error "该 Token 无可管理的域名，请检查 Token 权限"
        pause; return 1
    fi

    echo -e "${C_CYAN}可用域名:${C_RESET}"
    for i in "${!zone_list[@]}"; do
        echo "  $((i+1)). ${zone_list[$i]}"
    done
    local zone_choice
    while true; do
        read -e -r -p "选择域名 [1]: " zone_choice
        zone_choice=${zone_choice:-1}
        if [[ "$zone_choice" =~ ^[0-9]+$ ]] && (( zone_choice >= 1 && zone_choice <= ${#zone_list[@]} )); then
            break
        fi
        print_warn "请输入 1-${#zone_list[@]}"
    done
    local root_domain="${zone_list[$((zone_choice-1))]}"
    local zone_id="${zone_ids[$((zone_choice-1))]}"
    print_success "已选择: ${root_domain} (Zone: ${zone_id})"

    # 3. 子域名前缀
    local sub_prefix="" DOMAIN=""
    print_guide "输入子域名前缀"
    echo -e "  ${C_GRAY}例如输入 www -> 完整域名为 www.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}例如输入 panel -> 完整域名为 panel.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}直接回车 -> 使用根域名 ${root_domain}${C_RESET}"
    while true; do
        read -e -r -p "子域名前缀 [留空=根域名]: " sub_prefix
        if [[ -z "$sub_prefix" ]]; then
            DOMAIN="$root_domain"
            break
        fi
        if validate_dns_label "$sub_prefix"; then
            DOMAIN="${sub_prefix}.${root_domain}"
            break
        fi
        print_error "子域名前缀格式无效（仅小写字母、数字、短横；首尾不能为短横，1-63 字符）"
    done

    # 检查是否已有配置
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        print_warn "${DOMAIN} 配置已存在"
        if ! confirm "覆盖现有配置？"; then pause; return; fi
    fi

    # 4. Nginx 反向代理
    local do_nginx=0 NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL="" LOCAL_PROXY_PASS=""
    if confirm "是否配置 Nginx 反向代理 (用于隐藏后端端口)?"; then
        do_nginx=1
        print_guide "Nginx 监听端口"
        while true; do
            read -e -r -p "HTTP 端口 [80]: " hp
            NGINX_HTTP_PORT=${hp:-80}
            if validate_port "$NGINX_HTTP_PORT"; then break; fi
            print_warn "端口无效"
        done
        while true; do
            read -e -r -p "HTTPS 端口 [443]: " sp
            NGINX_HTTPS_PORT=${sp:-443}
            if validate_port "$NGINX_HTTPS_PORT"; then break; fi
            print_warn "端口无效"
        done
        # Reality 443 共存：请求 443 时下沉到 web 内部端口，443 归 nginx stream 分流。
        NGINX_HTTPS_PORT="$(_web_coexist_https_port "$NGINX_HTTPS_PORT")"
        read -e -r -p "后端协议 [1]http [2]https: " proto
        BACKEND_PROTOCOL=$([[ "$proto" == "2" ]] && echo "https" || echo "http")
        print_guide "后端服务地址"
        echo -e "  ${C_GRAY}服务在本机: 直接输入端口号即可，如 54321${C_RESET}"
        echo -e "  ${C_GRAY}服务在其他设备: 输入 IP:端口，如 192.168.1.100:5244${C_RESET}"
        # 支持调用方通过 _WEB_PRESET_PROXY 预填反代目标 (如端口转发联动)
        if [[ -n "${_WEB_PRESET_PROXY:-}" ]]; then
            local _preset_inp="$_WEB_PRESET_PROXY"
            _WEB_PRESET_PROXY=""
            [[ "$_preset_inp" =~ ^[0-9]+$ ]] && _preset_inp="127.0.0.1:$_preset_inp"
            if [[ "$_preset_inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${_preset_inp}"
                print_info "反代目标 (已预填): ${LOCAL_PROXY_PASS}"
            fi
        fi
        while [[ -z "$LOCAL_PROXY_PASS" ]]; do
            read -e -r -p "后端地址 [127.0.0.1:54321]: " inp
            inp=${inp:-"127.0.0.1:54321"}
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"
            else
                print_warn "格式错误，请输入 端口号 或 IP:端口"
            fi
        done
    else
        echo ""
        print_guide "您选择了【不配置 Nginx】。"
        print_guide "证书生成后，请手动在面板设置中填写公钥/私钥路径。"
        echo ""
    fi

    # 5. DNS 解析
    print_info "探测本机公网 IP..."
    local ipv4 ipv6
    ipv4=$(get_public_ipv4 2>/dev/null || true)
    ipv6=$(get_public_ipv6 2>/dev/null || true)
    if [[ -n "$ipv4" ]]; then
        if ! validate_ip "$ipv4" || [[ "$ipv4" == *:* ]]; then
            print_warn "IPv4 探测异常 ($ipv4)，已忽略"
            ipv4=""
        fi
    fi
    if [[ -n "$ipv6" ]]; then
        if ! validate_ip "$ipv6" || [[ "$ipv6" != *:* ]]; then
            print_warn "IPv6 探测异常 ($ipv6)，已忽略"
            ipv6=""
        fi
    fi
    CACHED_IPV4="$ipv4"; CACHED_IPV6="$ipv6"
    echo "  IPv4: ${ipv4:-[✗] 未检测到}"
    echo "  IPv6: ${ipv6:-[✗] 未检测到}"
    local dns_mode=""
    echo -e "${C_CYAN}DNS 解析方式:${C_RESET}"
    echo "  1. 仅 A 记录 (IPv4)"
    echo "  2. 仅 AAAA 记录 (IPv6)"
    echo "  3. 双栈 (A + AAAA)"
    echo "  0. 跳过 DNS (手动管理)"
    read -e -r -p "选择 [1]: " dns_mode
    dns_mode=${dns_mode:-1}
    local dns_proxied="false"
    if [[ "$dns_mode" != "0" ]]; then
        echo -e "${C_YELLOW}注意: 开启代理后，仅 HTTP/HTTPS 流量能通过 Cloudflare${C_RESET}"
        read -e -r -p "是否开启 Cloudflare 代理 (小云朵)? [y/N]: " proxy_choice
        [[ "${proxy_choice,,}" == "y" ]] && dns_proxied="true"
    fi

    # ══════════════════════════════════════════════════════════════
    #  配置确认
    # ══════════════════════════════════════════════════════════════
    echo ""
    draw_line
    echo -e "${C_CYAN}配置确认:${C_RESET}"
    echo -e "  域名:         ${C_GREEN}${DOMAIN}${C_RESET}"
    echo -e "  根域名:       ${C_GREEN}${root_domain}${C_RESET} (Zone: ${zone_id})"
    if [[ $do_nginx -eq 1 ]]; then
        echo -e "  Nginx:        ${C_GREEN}开启${C_RESET} (HTTP:${NGINX_HTTP_PORT} HTTPS:${NGINX_HTTPS_PORT})"
        echo -e "  反代目标:     ${C_GREEN}${LOCAL_PROXY_PASS}${C_RESET}"
    else
        echo -e "  Nginx:        ${C_YELLOW}关闭${C_RESET} (仅申请证书)"
    fi
    case $dns_mode in
        1) echo -e "  DNS:          ${C_GREEN}A → ${ipv4:-未检测到}${C_RESET} (代理: ${dns_proxied})" ;;
        2) echo -e "  DNS:          ${C_GREEN}AAAA → ${ipv6:-未检测到}${C_RESET} (代理: ${dns_proxied})" ;;
        3) echo -e "  DNS:          ${C_GREEN}A+AAAA${C_RESET} (代理: ${dns_proxied})" ;;
        0) echo -e "  DNS:          ${C_YELLOW}跳过${C_RESET}" ;;
    esac
    echo ""
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    local auto_step=1
    [[ "$dns_mode" != "0" ]] && { echo -e "    ${auto_step}. DNS 解析配置"; ((auto_step++)); }
    echo -e "    ${auto_step}. SSL 证书申请 (Let's Encrypt DNS 验证)"; ((auto_step++))
    [[ $do_nginx -eq 1 ]] && { echo -e "    ${auto_step}. Nginx 反向代理部署"; ((auto_step++)); }
    [[ $do_nginx -eq 1 ]] && { echo -e "    ${auto_step}. 防火墙端口放行"; ((auto_step++)); }
    echo -e "    ${auto_step}. 证书自动续签配置"; ((auto_step++))
    [[ "$dns_mode" != "0" ]] && echo -e "    ${auto_step}. DDNS 动态解析"
    draw_line
    if ! confirm "确认开始执行?"; then
        print_warn "已取消"; pause; return
    fi

    # ══════════════════════════════════════════════════════════════
    #  执行阶段
    # ══════════════════════════════════════════════════════════════
    local step=1
    local rollback_clean_start=0
    local dns_snapshot="" dns_restore_needed=0
    _web_add_domain_clean_start "$DOMAIN" && rollback_clean_start=1

    # ── DNS 解析 ──
    if [[ "$dns_mode" != "0" ]]; then
        echo -e "\n${C_CYAN}=== [${step}] DNS 解析 ===${C_RESET}"
        dns_snapshot=$(_cf_dns_snapshot_records "$zone_id" "$CF_API_TOKEN" "$DOMAIN" A AAAA CNAME) || {
            print_error "DNS 快照创建失败，已中止以避免后续失败无法恢复 Cloudflare 远端状态"
            pause; return 1
        }
        dns_restore_needed=1
        case $dns_mode in
            1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied" ;;
            2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
            3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied" \
               && _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
        esac || {
            print_error "DNS 记录配置失败"
            _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"
            pause; return 1
        }
        ((step++))
    fi

    # ── SSL 证书 ──
    echo -e "\n${C_CYAN}=== [${step}] SSL 证书申请 ===${C_RESET}"
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}" || { print_error "证书目录创建失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
    local CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_private_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN" || { print_error "Cloudflare 凭据写入失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
    print_info "正在申请证书 (DNS 验证，可能需要 1-2 分钟)..."
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive; then
        print_success "证书获取成功！"
        local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
        copy_cert_pair_atomic "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir" || {
            print_error "证书复制失败"
            _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"
            pause; return 1
        }
        ((step++))

        # ── Nginx 反向代理 ──
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}=== [${step}] Nginx 反向代理 ===${C_RESET}"
            _ensure_ssl_params
            local redir_port
            redir_port="$(_web_coexist_redir_suffix "$NGINX_HTTPS_PORT")"
            local nginx_conf="# Config for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION
server {
    listen $NGINX_HTTP_PORT;
    listen [::]:$NGINX_HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$NGINX_HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass $LOCAL_PROXY_PASS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
            }"
            if ! _nginx_deploy_conf "$DOMAIN" "$nginx_conf"; then
                _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"
                pause; return 1
            fi
            print_success "Nginx 配置已生效"
            # 443 共存模式：把本站域名加入 stream SNI 白名单（未启用则 no-op）
            declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
            ((step++))

            # ── 防火墙 ──
            echo -e "\n${C_CYAN}=== [${step}] 防火墙 ===${C_RESET}"
            _web_allow_public_tcp_port "$NGINX_HTTP_PORT" "Nginx-HTTP" "${NGINX_HTTP_PORT}/tcp" || { _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
            # 443 共存：HTTPS 端口若已下沉为 web 内部端口，则它仅需 loopback 可达（对外走 443 stream），
            # 不放行到公网，避免真站直连入口被旁路探测。
            if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$NGINX_HTTPS_PORT"; then
                print_info "共存模式：${NGINX_HTTPS_PORT} 为内部端口，仅 loopback 可达，不放行到公网（对外由 443 提供）"
            else
                _web_allow_public_tcp_port "$NGINX_HTTPS_PORT" "Nginx-HTTPS" "${NGINX_HTTPS_PORT}/tcp" || { _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
            fi
            if command_exists ufw && ufw_is_active; then
                print_success "防火墙规则已更新"
            fi
            ((step++))
        fi

        # ── 证书自动续签 ──
        echo -e "\n${C_CYAN}=== [${step}] 证书自动续签 ===${C_RESET}"
        mkdir -p "$CERT_HOOKS_DIR" || { print_error "续签 Hook 目录创建失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
        local DEPLOY_HOOK_SCRIPT="${CERT_HOOKS_DIR}/renew-${DOMAIN}.sh"
        local hook_content="#!/bin/bash
# Auto-generated renewal hook for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=\"$DOMAIN\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"
echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

$(render_cert_pair_hook_helper)

# Copy certificates
if copy_cert_pair_atomic \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}\"; then
    echo \"[\$(date)] Certificates copied successfully\" >> /var/log/cert-renew.log
else
    echo \"[\$(date)] ERROR: Certificate files not found\" >> /var/log/cert-renew.log
    exit 1
fi
"
        if [[ $do_nginx -eq 1 ]]; then
            hook_content+="
# Reload Nginx
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx 2>&1 | tee -a /var/log/cert-renew.log
elif command -v service >/dev/null 2>&1; then
    service nginx reload 2>&1 | tee -a /var/log/cert-renew.log
else
    nginx -s reload 2>&1 | tee -a /var/log/cert-renew.log
fi
echo \"[\$(date)] Nginx reloaded\" >> /var/log/cert-renew.log
"
        fi
        hook_content+="
echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content" || { print_error "续签 Hook 写入失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
        chmod +x "$DEPLOY_HOOK_SCRIPT" || { print_error "续签 Hook 授权失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
        local cron_tag="CertRenew_${DOMAIN}"
        local cron_minute=$(( $(echo "$DOMAIN" | cksum | cut -d' ' -f1) % 60 ))
        cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${DOMAIN}' --deploy-hook '${DEPLOY_HOOK_SCRIPT}' # ${cron_tag}" || { print_error "自动续签 cron 配置失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
        print_success "自动续签已配置 (每日 3:$(printf '%02d' $cron_minute) AM)"

        # 保存域名管理配置
        local config_content="# Domain configuration for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION at $(date)
DOMAIN=\"$DOMAIN\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"$DEPLOY_HOOK_SCRIPT\"
CLOUDFLARE_CREDENTIALS=\"$CLOUDFLARE_CREDENTIALS\"
"
        if [[ $do_nginx -eq 1 ]]; then
            config_content+="NGINX_CONF_PATH=\"/etc/nginx/sites-available/${DOMAIN}.conf\"

NGINX_HTTP_PORT=\"$NGINX_HTTP_PORT\"
NGINX_HTTPS_PORT=\"$NGINX_HTTPS_PORT\"
LOCAL_PROXY_PASS=\"$LOCAL_PROXY_PASS\"
"
        fi
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "$config_content" || { print_error "域名管理配置写入失败"; _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"; pause; return 1; }
        ((step++))

        # ── DDNS 动态解析 ──
        if [[ "$dns_mode" != "0" ]]; then
            echo -e "\n${C_CYAN}=== [${step}] DDNS 动态解析 ===${C_RESET}"
            local ddns_ipv4="false" ddns_ipv6="false"
            [[ "$dns_mode" == "1" || "$dns_mode" == "3" ]] && ddns_ipv4="true"
            [[ "$dns_mode" == "2" || "$dns_mode" == "3" ]] && ddns_ipv6="true"
            ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "$dns_proxied" || {
                print_error "DDNS 配置失败"
                _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"
                pause; return 1
            }
        fi
        dns_restore_needed=0

        # ══════════════════════════════════════════════════════════════
        #  完成报告
        # ══════════════════════════════════════════════════════════════
        echo ""
        draw_line
        print_success "域名配置完成！"
        draw_line
        echo -e "${C_CYAN}[证书路径]${C_RESET}"
        echo "  公钥: ${cert_dir}/fullchain.pem"
        echo "  私钥: ${cert_dir}/privkey.pem"
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}[访问地址]${C_RESET}"
            echo "  https://${DOMAIN}:${NGINX_HTTPS_PORT}"
            echo -e "\n${C_CYAN}[反代配置]${C_RESET}"
            echo "  后端: $LOCAL_PROXY_PASS"
        else
            echo -e "\n${C_YELLOW}[手动配置提示]${C_RESET}"
            echo "  请在面板设置中填写上述证书路径"
        fi
        echo -e "\n${C_CYAN}[自动续签]${C_RESET}"
        echo "  Hook 脚本: $DEPLOY_HOOK_SCRIPT"
        echo "  Crontab: 每日 3:$(printf '%02d' $cron_minute) AM 自动检查"
        draw_line
        log_action "Domain configured: $DOMAIN (Nginx: $do_nginx)"
    else
        print_error "证书申请失败！请检查:"
        echo "1. 域名 DNS 是否正确解析到本机
2. API Token 权限是否正确
3. 网络连接是否正常"
        if [[ "$rollback_clean_start" == "1" ]]; then
            _web_add_domain_rollback "$DOMAIN" "$rollback_clean_start" "$zone_id" "$CF_API_TOKEN" "$dns_snapshot" "$dns_restore_needed"
        else
            rm -f "$CLOUDFLARE_CREDENTIALS"
        fi
        pause; return 1
    fi
    pause
}

web_view_config() {
    print_title "查看详细配置"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    local i=1
    local domains=()
    local files=()
    echo "请选择要查看的域名:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    read -e -r -p "请输入序号: " idx
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    local DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
    if ! validate_conf_file "$target_conf"; then
        print_error "配置文件格式异常"; pause; return
    fi
    _safe_source_conf "$target_conf"
    CERT_PATH=${CERT_PATH:-"${CERT_PATH_PREFIX}/${target_domain}"}
    DEPLOY_HOOK_SCRIPT=${DEPLOY_HOOK_SCRIPT:-"/root/cert-renew-hook-${target_domain}.sh"}
    print_title "配置详情: $target_domain"
    echo -e "${C_CYAN}[基础信息]${C_RESET}"
    echo "域名: $target_domain"
    echo "证书目录: $CERT_PATH"
    echo "Hook 脚本: $DEPLOY_HOOK_SCRIPT"
    echo -e "\n${C_CYAN}[自动续签计划 (Crontab)]${C_RESET}"
    local cron_out=$(crontab -l 2>/dev/null | grep -v -E "^[[:space:]]*no crontab for " || true)
    local domain_cron=$(echo "$cron_out" | grep -F "$target_domain" | grep "certbot" || true)
    if [[ -n "$domain_cron" ]]; then
        echo "$domain_cron"
    else
        echo -e "${C_YELLOW}未配置自动续签任务${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[证书状态]${C_RESET}"
    local fullchain="$CERT_PATH/fullchain.pem"
    local privkey="$CERT_PATH/privkey.pem"
    if [[ -f "$fullchain" ]]; then
        local end_date=$(openssl x509 -enddate -noout -in "$fullchain" | cut -d= -f2)
        local end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local days_left=$(( (end_epoch - now_epoch) / 86400 ))
        if [ "$days_left" -lt 0 ]; then
            echo -e "过期时间: ${C_RED}${end_date} (已过期)${C_RESET}"
        elif [ "$days_left" -lt 30 ]; then
            echo -e "过期时间: ${C_YELLOW}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        else
            echo -e "过期时间: ${C_GREEN}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        fi
    else
        echo -e "公钥文件: ${C_RED}未找到${C_RESET}"
    fi
    if [[ -f "$privkey" ]]; then
        echo "私钥文件: $privkey (存在)"
    else
        echo -e "私钥文件: ${C_RED}未找到${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[Nginx 配置摘要]${C_RESET}"
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_status="已启用"
    if [[ ! -f "$nginx_conf" ]]; then
        local avail_conf="/etc/nginx/sites-available/${target_domain}.conf"
        if [[ -f "$avail_conf" ]]; then
            nginx_conf="$avail_conf"
            nginx_status="${C_YELLOW}未启用${C_RESET}"
        fi
    fi
    if [[ -f "$nginx_conf" ]]; then
        echo -e "配置文件: $nginx_conf ($nginx_status)"
        echo "关键指令:"
        grep -E "^\s*(listen|server_name|proxy_pass|ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)\b" "$nginx_conf" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_YELLOW}该域名未配置 Nginx 反代。${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[Hook 脚本摘要]${C_RESET}"
    if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        echo "脚本路径: $DEPLOY_HOOK_SCRIPT"
        echo "关键动作:"
        grep -E 'export PATH=|cp -L|reload nginx|x-ui|3x-ui' "$DEPLOY_HOOK_SCRIPT" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_RED}Hook 脚本丢失！建议重新添加域名。${C_RESET}"
    fi
    pause
}

web_delete_domain() {
    print_title "删除域名配置"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    local i=1
    local domains=()
    local files=()
    echo "发现以下配置:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    read -e -r -p "请输入序号删除: " idx
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    echo -e "${C_RED}"
    echo "!!! 危险操作 !!!"
    echo "即将删除域名: $target_domain"
    echo "这将执行:
1. 删除 SSL 证书 (certbot delete)
2. 删除 Nginx 配置文件并重载
3. 删除 自动续签 Hook 脚本
4. 清理 Crontab 定时任务
5. 删除 脚本保存的配置"
    echo -e "${C_RESET}"
    if ! confirm "确认彻底删除吗?"; then return; fi
    print_info "正在执行清理..."
    if ! _web_cleanup_domain "$target_domain"; then
        print_error "域名清理失败。"
        pause; return 1
    fi
    log_action "Deleted domain config: $target_domain"
    pause
}

web_cert_overview() {
    print_title "证书状态总览"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已管理的域名。"
        pause; return
    fi
    echo -e "${C_CYAN}#    域名                             剩余天数       过期时间               状态${C_RESET}"
    draw_line
    local i=1 warn_count=0 expired_count=0 ok_count=0 missing_count=0
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        [[ -z "$d" ]] && continue
        local cert_path="${CERT_PATH_PREFIX}/${d}"
        local fullchain="${cert_path}/fullchain.pem"
        local days_str expiry_str status_str
        if [[ -f "$fullchain" ]]; then
            local end_date
            end_date=$(openssl x509 -enddate -noout -in "$fullchain" 2>/dev/null | cut -d= -f2)
            if [[ -n "$end_date" ]]; then
                local end_epoch now_epoch days_left
                end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
                now_epoch=$(date +%s)
                days_left=$(( (end_epoch - now_epoch) / 86400 ))
                expiry_str=$(date -d "$end_date" '+%Y-%m-%d' 2>/dev/null || echo "$end_date")
                if [[ $days_left -lt 0 ]]; then
                    days_str="${C_RED}已过期${C_RESET}"
                    status_str="${C_RED}✗ 过期${C_RESET}"
                    expired_count=$((expired_count + 1))
                elif [[ $days_left -lt 7 ]]; then
                    days_str="${C_RED}${days_left} 天${C_RESET}"
                    status_str="${C_RED}! 紧急${C_RESET}"
                    warn_count=$((warn_count + 1))
                elif [[ $days_left -lt 30 ]]; then
                    days_str="${C_YELLOW}${days_left} 天${C_RESET}"
                    status_str="${C_YELLOW}△ 即将过期${C_RESET}"
                    warn_count=$((warn_count + 1))
                else
                    days_str="${C_GREEN}${days_left} 天${C_RESET}"
                    status_str="${C_GREEN}✓ 正常${C_RESET}"
                    ok_count=$((ok_count + 1))
                fi
            else
                expiry_str="解析失败"
                days_str="-"
                status_str="${C_RED}? 异常${C_RESET}"
                missing_count=$((missing_count + 1))
            fi
        else
            expiry_str="无证书文件"
            days_str="-"
            status_str="${C_RED}✗ 缺失${C_RESET}"
            missing_count=$((missing_count + 1))
        fi
        echo -e "  $i  $d  $days_str  $expiry_str  $status_str"
        ((i++))
    done
    draw_line
    local total=$((ok_count + warn_count + expired_count + missing_count))
    echo -e "共 ${C_CYAN}${total}${C_RESET} 个域名: ${C_GREEN}正常 ${ok_count}${C_RESET} | ${C_YELLOW}警告 ${warn_count}${C_RESET} | ${C_RED}过期 ${expired_count}${C_RESET} | ${C_RED}缺失 ${missing_count}${C_RESET}"
    if [[ $warn_count -gt 0 || $expired_count -gt 0 ]]; then
        echo ""
        print_warn "有证书需要关注，建议使用 [8.手动续签] 进行续签。"
    fi
    pause
}

_replace_proxy_pass_backend() {
    local new_backend="${1:-}" conf_file="${2:-}"
    [[ -n "$new_backend" && -f "$conf_file" ]] || return 1
    NEW_BACKEND="$new_backend" awk '
        BEGIN { new_backend = ENVIRON["NEW_BACKEND"] }
        /^[[:space:]]*proxy_pass[[:space:]]+/ {
            if (match($0, /proxy_pass[[:space:]]+[^;]+;/)) {
                $0 = substr($0, 1, RSTART - 1) "proxy_pass " new_backend ";" substr($0, RSTART + RLENGTH)
            }
        }
        { print }
    ' "$conf_file"
}

_web_update_reverse_proxy_backend() {
    local target_conf="${1:-}" new_backend="${2:-}"
    local backup_conf tmp_conf conf_dir base
    [[ -n "$target_conf" && -f "$target_conf" && -n "$new_backend" ]] || return 1
    conf_dir="$(dirname "$target_conf")"
    base="$(basename "$target_conf")"
    backup_conf=$(mktemp "${conf_dir}/.${base}.bak.XXXXXX") || return 1
    _tmp_register "$backup_conf"
    tmp_conf=$(mktemp "${conf_dir}/.${base}.tmp.XXXXXX") || {
        rm -f "$backup_conf"
        _tmp_unregister "$backup_conf"
        return 1
    }
    _tmp_register "$tmp_conf"
    if ! cp -a "$target_conf" "$backup_conf"; then
        rm -f "$backup_conf" "$tmp_conf"
        _tmp_unregister "$backup_conf"; _tmp_unregister "$tmp_conf"
        return 1
    fi
    if ! _replace_proxy_pass_backend "$new_backend" "$target_conf" > "$tmp_conf"; then
        rm -f "$backup_conf" "$tmp_conf"
        _tmp_unregister "$backup_conf"; _tmp_unregister "$tmp_conf"
        return 1
    fi
    chmod --reference="$target_conf" "$tmp_conf" 2>/dev/null || true
    chown --reference="$target_conf" "$tmp_conf" 2>/dev/null || true
    if ! mv "$tmp_conf" "$target_conf"; then
        rm -f "$backup_conf" "$tmp_conf"
        _tmp_unregister "$backup_conf"; _tmp_unregister "$tmp_conf"
        return 1
    fi
    _tmp_unregister "$tmp_conf"
    if nginx -t >/dev/null 2>&1 && _nginx_reload; then
        rm -f "$backup_conf"
        _tmp_unregister "$backup_conf"
        return 0
    fi
    mv "$backup_conf" "$target_conf" 2>/dev/null || true
    _tmp_unregister "$backup_conf"
    return 1
}

_cert_name_matches_domain() {
    local pattern="${1:-}" domain="${2:-}" suffix left
    pattern="${pattern%.}"
    domain="${domain%.}"
    pattern="${pattern,,}"
    domain="${domain,,}"
    [[ -z "$pattern" || -z "$domain" ]] && return 1

    [[ "$pattern" == "$domain" ]] && return 0

    # RFC 6125 常见语义：*.example.com 只覆盖 api.example.com，
    # 不覆盖 example.com 或 deep.api.example.com。
    if [[ "$pattern" == \*.* ]]; then
        suffix="${pattern#\*.}"
        [[ -z "$suffix" || "$suffix" == *"*"* ]] && return 1
        [[ "$domain" == *".${suffix}" ]] || return 1
        left="${domain%.${suffix}}"
        [[ -n "$left" && "$left" != *.* ]] && return 0
    fi
    return 1
}

_cert_covers_domain() {
    local cert_file="${1:-}" domain="${2:-}" entry name
    [[ -f "$cert_file" && -n "$domain" ]] || return 1
    command -v openssl >/dev/null 2>&1 || return 1

    while IFS= read -r entry; do
        [[ "$entry" == *DNS:* ]] || continue
        name="${entry#*DNS:}"
        name="${name%%[[:space:]]*}"
        name="${name%,}"
        [[ -z "$name" ]] && continue
        _cert_name_matches_domain "$name" "$domain" && return 0
    done < <(openssl x509 -in "$cert_file" -noout -ext subjectAltName 2>/dev/null | tr ',' '\n')
    return 1
}

web_reverse_proxy_site() {
    local prefill_backend="${1:-}"
    print_title "添加反向代理网站"
    
    # 检查 Nginx 是否可用
    if ! command_exists nginx; then
        print_error "Nginx 未安装。请先使用菜单 1 添加域名以自动安装依赖。"
        pause; return
    fi
    echo -e "${C_CYAN}选择反代模板:${C_RESET}"
    echo "  1. Emby / Jellyfin (流媒体优化: 大缓冲区/WebSocket/超长超时)
  2. Alist 网盘 (大文件上传/WebDAV)
  3. Nextcloud (大文件 + CalDAV/CardDAV 重写)
  4. Home Assistant (WebSocket 长连接)
  5. 通用反代 (适用于大多数 Web 服务)
  0. 返回
"
    read -e -r -p "选择模板: " tpl_choice
    [[ "$tpl_choice" == "0" || -z "$tpl_choice" ]] && return
    local template_name=""
    case $tpl_choice in
        1) template_name="emby" ;;
        2) template_name="alist" ;;
        3) template_name="nextcloud" ;;
        4) template_name="homeassistant" ;;
        5) template_name="generic" ;;
        *) print_error "无效选项"; pause; return ;;
    esac
    
    # 域名输入
    local DOMAIN=""
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名 (如 emby.example.com, 0 返回): " DOMAIN
        [[ "$DOMAIN" == "0" ]] && return
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    
    # 检查 Nginx 配置是否已存在
    if [[ -f "/etc/nginx/sites-available/${DOMAIN}.conf" ]]; then
        print_warn "该域名的 Nginx 配置已存在: /etc/nginx/sites-available/${DOMAIN}.conf"
        if ! confirm "是否覆盖?"; then
            pause; return
        fi
    fi
    
    # 证书路径
    local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
    local has_cert=0
    if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/privkey.pem" ]]; then
        print_success "检测到已有证书: ${cert_dir}"
        has_cert=1
    else
        # 尝试查找通配符证书或主域证书
        local parent_domain=$(echo "$DOMAIN" | sed 's/^[^.]*\.//')
        local parent_cert="${CERT_PATH_PREFIX}/${parent_domain}/fullchain.pem"
        local parent_key="${CERT_PATH_PREFIX}/${parent_domain}/privkey.pem"
        if [[ -f "$parent_cert" && -f "$parent_key" ]]; then
            if _cert_covers_domain "$parent_cert" "$DOMAIN"; then
                cert_dir="${CERT_PATH_PREFIX}/${parent_domain}"
                print_success "使用覆盖 ${DOMAIN} 的父域/通配符证书: ${cert_dir}"
                has_cert=1
            else
                print_warn "检测到父域证书 ${CERT_PATH_PREFIX}/${parent_domain}，但证书 SAN 不覆盖 ${DOMAIN}，不能复用。"
            fi
        fi
    fi
    if [[ $has_cert -eq 0 ]]; then
        print_warn "未找到证书。"
        echo "  1. 使用菜单 [1.添加域名] 先申请证书再回来配置反代
  2. 手动指定证书路径
"
        read -e -r -p "选择: " cert_opt
        case $cert_opt in
            1) pause; return ;;
            2)
                read -e -r -p "证书公钥路径 (fullchain.pem): " custom_cert
                read -e -r -p "证书私钥路径 (privkey.pem): " custom_key
                if [[ ! -f "$custom_cert" || ! -f "$custom_key" ]]; then
                    print_error "证书文件不存在"; pause; return
                fi
                copy_cert_pair_atomic "$custom_cert" "$custom_key" "$cert_dir" || {
                    print_error "证书导入失败"
                    pause; return
                }
                has_cert=1
                ;;
            *) pause; return ;;
        esac
    fi
    
    # 后端地址
    local BACKEND_URL=""
    if [[ -n "$prefill_backend" ]]; then
        # 预填模式 (来自端口转发联动等)
        if [[ "$prefill_backend" =~ ^(http|https):// ]]; then
            BACKEND_URL="$prefill_backend"
        else
            BACKEND_URL="http://${prefill_backend}"
        fi
        echo -e "  后端地址: ${C_GREEN}${BACKEND_URL}${C_RESET} (自动填充)"
        if ! confirm "使用此后端地址?"; then
            BACKEND_URL=""
        fi
    fi
    if [[ -z "$BACKEND_URL" ]]; then
        print_guide "输入后端服务地址 (例如 127.0.0.1:8096, 或完整URL http://127.0.0.1:8096, 0 返回)"
        while [[ -z "$BACKEND_URL" ]]; do
            read -e -r -p "后端地址: " inp
            [[ "$inp" == "0" ]] && return
            # 纯端口号自动补全
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            # 没有协议头的自动补 http
            if [[ "$inp" =~ ^(http|https):// ]]; then
                BACKEND_URL="$inp"
            elif [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                BACKEND_URL="http://${inp}"
            else
                print_warn "格式错误，请输入 IP:端口 或完整URL"
            fi
        done
    fi
    
    # 端口配置
    local HTTP_PORT HTTPS_PORT
    read -e -r -p "HTTP 端口 [80] (0 返回): " hp
    [[ "$hp" == "0" ]] && return
    HTTP_PORT=${hp:-80}
    validate_port "$HTTP_PORT" || { print_error "端口无效"; pause; return; }
    read -e -r -p "HTTPS 端口 [443] (0 返回): " sp
    [[ "$sp" == "0" ]] && return
    HTTPS_PORT=${sp:-443}
    validate_port "$HTTPS_PORT" || { print_error "端口无效"; pause; return; }
    # Reality 443 共存：请求 443 时下沉到 web 内部端口，443 归 nginx stream 分流。
    HTTPS_PORT="$(_web_coexist_https_port "$HTTPS_PORT")"
    
    # 确保 SSL 参数文件存在
    _ensure_ssl_params
    local redir_port
    redir_port="$(_web_coexist_redir_suffix "$HTTPS_PORT")"
    
    # 根据模板生成 Nginx 配置
    local nginx_conf=""
    if [[ "$template_name" == "emby" ]]; then
        nginx_conf="# Emby/Jellyfin 流媒体反代配置
# Generated by $SCRIPT_NAME $VERSION
# 模板: Emby/Jellyfin 流媒体优化
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;

    # 流媒体优化参数
    client_max_body_size 128M;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    send_timeout 86400s;

    # 主页面和 API
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Protocol \$scheme;
        proxy_set_header X-Forwarded-Host \$http_host;
        
        # WebSocket 支持 (Emby/Jellyfin 远程控制)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        
        # 流媒体缓冲优化
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # WebSocket 端点
    location /embywebsocket {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Jellyfin WebSocket 端点
    location /socket {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}"
    elif [[ "$template_name" == "alist" ]]; then
        nginx_conf="# Alist 网盘反代配置
# Generated by $SCRIPT_NAME $VERSION
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 20G;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}"
    elif [[ "$template_name" == "nextcloud" ]]; then
        nginx_conf="# Nextcloud 反代配置
# Generated by $SCRIPT_NAME $VERSION
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 10G;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_buffering off;
        proxy_request_buffering off;
    }
    location /.well-known/carddav { return 301 \$scheme://\$host/remote.php/dav; }
    location /.well-known/caldav  { return 301 \$scheme://\$host/remote.php/dav; }
}"
    elif [[ "$template_name" == "homeassistant" ]]; then
        nginx_conf="# Home Assistant 反代配置
# Generated by $SCRIPT_NAME $VERSION
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_buffering off;
    }
    location /api/websocket {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}"
    else
        # 通用反代模板
        nginx_conf="# 通用反向代理配置
# Generated by $SCRIPT_NAME $VERSION
# 模板: 通用
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$HTTPS_PORT")
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
}"
    fi
    # 部署配置（使用提取的辅助函数）
    if ! _nginx_deploy_conf "$DOMAIN" "$nginx_conf"; then
        pause; return
    fi
    print_success "Nginx 反代配置已生效。"
    # 443 共存模式：把本站域名加入 stream SNI 白名单（未启用则 no-op）
    declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
    
    # 防火墙规则
    _web_allow_public_tcp_port "$HTTP_PORT" "ReverseProxy-HTTP" "${HTTP_PORT}/tcp" || { pause; return 1; }
    # 443 共存：HTTPS 端口若已下沉为 web 内部端口，仅 loopback 可达（对外走 443 stream），不放行到公网。
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$HTTPS_PORT"; then
        print_info "共存模式：${HTTPS_PORT} 为内部端口，仅 loopback 可达，不放行到公网（对外由 443 提供）"
    else
        _web_allow_public_tcp_port "$HTTPS_PORT" "ReverseProxy-HTTPS" "${HTTPS_PORT}/tcp" || { pause; return 1; }
    fi
    if command_exists ufw && ufw_is_active; then
        print_success "防火墙规则已更新。"
    fi
    draw_line
    print_success "反向代理配置完成！"
    draw_line
    echo -e "${C_CYAN}[访问地址]${C_RESET}"
    echo "  https://${DOMAIN}${redir_port}"
    echo -e "\n${C_CYAN}[反代后端]${C_RESET}"
    echo "  $BACKEND_URL"
    echo -e "\n${C_CYAN}[模板]${C_RESET}"
    echo "  $( [[ "$template_name" == "emby" ]] && echo "Emby/Jellyfin 流媒体优化" || echo "通用")"
    echo -e "\n${C_CYAN}[配置文件]${C_RESET}"
    echo "  /etc/nginx/sites-available/${DOMAIN}.conf"
    draw_line
    log_action "Reverse proxy configured: $DOMAIN -> $BACKEND_URL (template=$template_name)"
    pause
}

web_edit_reverse_proxy() {
    print_title "修改反向代理后端地址"
    if ! command_exists nginx; then
        print_error "Nginx 未安装。"
        pause; return
    fi
    shopt -s nullglob
    local confs=(/etc/nginx/sites-available/*.conf)
    shopt -u nullglob
    if [[ ${#confs[@]} -eq 0 ]]; then
        print_warn "未找到 Nginx 反代配置。"
        pause; return
    fi
    local i=1 domains=() files=()
    echo "请选择要修改的站点:"
    for conf in "${confs[@]}"; do
        local domain=$(basename "$conf" .conf)
        local backend=$(grep -oP 'proxy_pass\s+\K[^;]+' "$conf" | head -1)
        echo -e "  $i. ${C_CYAN}${domain}${C_RESET} → ${backend:-未知}"
        domains+=("$domain")
        files+=("$conf")
        ((i++))
    done
    echo "  0. 返回"
    read -e -r -p "选择: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt ${#files[@]} ]]; then
        print_error "无效序号"; pause; return
    fi
    local target_conf="${files[$((idx-1))]}"
    local target_domain="${domains[$((idx-1))]}"
    local current_backend=$(grep -oP 'proxy_pass\s+\K[^;]+' "$target_conf" | head -1)
    echo ""
    echo -e "当前后端: ${C_YELLOW}${current_backend}${C_RESET}"
    echo ""
    print_guide "输入新的后端地址 (例如 127.0.0.1:8096, 或完整URL http://127.0.0.1:8096)"
    local new_backend=""
    while [[ -z "$new_backend" ]]; do
        read -e -r -p "新后端地址 (留空取消): " inp
        [[ -z "$inp" ]] && return
        [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
        if [[ "$inp" =~ ^(http|https):// ]]; then
            new_backend="$inp"
        elif [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
            new_backend="http://${inp}"
        else
            print_warn "格式错误，请输入 IP:端口 或完整URL"
        fi
    done
    if [[ "$new_backend" == "$current_backend" ]]; then
        print_warn "新地址与当前相同，无需修改。"
        pause; return
    fi
    if _web_update_reverse_proxy_backend "$target_conf" "$new_backend"; then
        print_success "反向代理后端已更新: ${target_domain}"
        echo -e "  ${current_backend} → ${C_GREEN}${new_backend}${C_RESET}"
    else
        print_error "Nginx 配置测试失败，已回滚。"
        nginx -t 2>&1 | tail -5
    fi
    log_action "Reverse proxy backend updated: $target_domain ${current_backend} -> ${new_backend}"
    pause
}

# ── 主菜单 ──

menu_web() {
    fix_terminal
    while true; do
        print_title "Web 服务管理 (SSL + Nginx + DDNS)"
        local cert_count=$(find "$CONFIG_DIR" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l)
        local ddns_count=$(find "$DDNS_CONFIG_DIR" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l)
        echo -e "证书域名: ${C_GREEN}${cert_count}${C_RESET} | DDNS域名: ${C_GREEN}${ddns_count}${C_RESET}"
        [[ $ddns_count -gt 0 ]] && crontab -l 2>/dev/null | grep -q "ddns-update.sh" && echo -e "DDNS状态: ${C_GREEN}运行中${C_RESET}"
        echo -e "${C_CYAN}--- 域名管理 ---${C_RESET}"
        echo "1. 添加域名 (申请证书 + 配置反代 + DDNS)
2. 查看已配置域名详情
3. 删除域名配置
"
        echo -e "${C_CYAN}--- DNS & DDNS ---${C_RESET}"
        echo "4. Cloudflare DNS 解析 (支持 DDNS)
5. 查看 DDNS 配置
6. 删除 DDNS 配置
7. 立即更新 DDNS
"
        echo -e "${C_CYAN}--- 证书维护 ---${C_RESET}"
        echo "8. 手动续签所有证书
9. 查看日志 (证书/DDNS)
"
        echo -e "${C_CYAN}--- 回源规则 (解决端口封锁) ---${C_RESET}"
        echo "10. 创建回源规则 (Origin Rules)
11. 查看回源规则
12. 删除回源规则
"
        echo -e "${C_CYAN}--- 反向代理 ---${C_RESET}"
        echo "13. 添加反代网站 (Emby/Jellyfin/通用)
14. 修改反代后端地址
"
        echo -e "${C_CYAN}--- 证书总览 ---${C_RESET}"
        echo "15. 证书状态总览
"
        echo -e "${C_CYAN}--- 一键配置 ---${C_RESET}"
        echo -e "16. 家宽内网服务公网暴露（一键配置）${C_GRAY} ← 需先在路由器开启端口转发${C_RESET}
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) web_add_domain ;;
            2) web_view_config ;;
            3) web_delete_domain ;;
            4) web_env_check && web_cf_dns_update || pause ;;
            5) ddns_list ;;
            6) ddns_delete ;;
            7) ddns_force_update ;;
            8)
                print_title "手动续签证书"
                command_exists certbot || { print_error "Certbot 未安装"; pause; continue; }
                echo "1. 常规续签 (仅续签即将过期的证书)
2. 强制续签 (忽略过期时间，可能触发 Let's Encrypt 频率限制)"
                read -e -r -p "选择 [1]: " renew_mode
                renew_mode=${renew_mode:-1}
                print_info "正在续签..."
                local renew_log="/var/log/certbot-renew.log"
                if [[ "$renew_mode" == "2" ]]; then
                    print_warn "强制续签: Let's Encrypt 限制每周 5 次相同证书"
                    if confirm "确认强制续签?"; then
                        certbot renew --force-renewal 2>&1 | tee "$renew_log"
                        local renew_rc=${PIPESTATUS[0]}
                    else
                        pause; continue
                    fi
                else
                    certbot renew 2>&1 | tee "$renew_log"
                    local renew_rc=${PIPESTATUS[0]}
                fi
                if [[ ${renew_rc:-1} -ne 0 ]]; then
                    print_warn "证书续签可能失败 (退出码: ${renew_rc})"
                fi
                shopt -s nullglob
                for hook in "${CERT_HOOKS_DIR}"/*.sh /root/cert-renew-hook-*.sh; do
                    [[ -x "$hook" ]] && bash "$hook"
                done
                shopt -u nullglob
                log_action "Manual cert renewal (mode=$renew_mode)"
                pause
                ;;
            9)
                echo "1. 证书续签日志"
                echo "2. DDNS 更新日志"
                echo "0. 返回上一级"
                read -e -r -p "选择 [0=返回]: " lc
                case $lc in
                    1) [[ -f /var/log/cert-renew.log ]] && tail -n 50 /var/log/cert-renew.log || print_warn "无日志" ;;
                    2) [[ -f "$DDNS_LOG" ]] && tail -n 50 "$DDNS_LOG" || print_warn "无日志" ;;
                    0|q|Q|"") continue ;;
                    *) print_error "无效选项，请输入 1/2，或输入 0 返回" ;;
                esac
                pause
                ;;
            10) web_cf_origin_rule_create ;;
            11) web_cf_origin_rule_list ;;
            12) web_cf_origin_rule_delete ;;
            13) web_reverse_proxy_site ;;
            14) web_edit_reverse_proxy ;;
            15) web_cert_overview ;;
            16) web_home_expose ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
# 整合 DNS + 证书 + Nginx + DDNS + Origin Rules 为一条龙流程

_web_home_expose_rollback() {
    local domain="$1" zone_id="$2" token="$3" dns_snapshot="$4" restore_dns="${5:-0}"
    local origin_rules_snapshot="${6:-}" restore_origin="${7:-0}" cleanup_local="${8:-0}"

    if [[ "$restore_origin" == "1" && -n "$origin_rules_snapshot" ]]; then
        print_warn "配置失败，正在恢复 Cloudflare Origin Rules 快照..."
        _cf_origin_rules_restore "$token" "$zone_id" "$origin_rules_snapshot" || \
            print_warn "Origin Rules 快照恢复失败，请人工核查 ${domain} 的回源规则"
    fi
    if [[ "$restore_dns" == "1" && -n "$dns_snapshot" ]]; then
        print_warn "配置失败，正在恢复 Cloudflare DNS 快照..."
        _cf_dns_restore_records "$zone_id" "$token" "$domain" "$dns_snapshot" A AAAA CNAME || \
            print_warn "Cloudflare DNS 快照恢复失败，请人工核查 ${domain} 的 A/AAAA/CNAME 记录"
    fi
    if [[ "$cleanup_local" == "1" ]]; then
        print_warn "正在清理本地半成品..."
        _web_cleanup_domain "$domain" "quiet" || true
    fi
}

web_home_expose() {
    print_title "家宽内网服务公网暴露（一键配置）"
    echo -e "${C_CYAN}将家庭宽带内网服务通过 DDNS + CF + HTTPS 暴露到公网${C_RESET}"
    echo -e "  适用: Alist / Jellyfin / NAS / HomeAssistant 等"
    echo -e "  自动完成: DNS -> 证书 -> Nginx -> DDNS -> 回源规则"

    # 依赖检查
    web_env_check || { pause; return; }

    # Phase 1: 一次性收集所有配置信息
    echo -e "\n${C_CYAN}=== 第一阶段: 收集配置信息 ===${C_RESET}\n"

    # 1. CF API Token
    local token=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 -> My Profile -> API Tokens -> Create Token${C_RESET}"
    while [[ -z "$token" ]]; do
        read -s -r -p "API Token: " token; echo ""
    done
    print_info "验证 Token..."
    if ! _cf_verify_token "$token"; then
        pause; return
    fi
    print_success "Token 有效"

    # 2. 选择域名 (自动列出 Token 可管理的域名)
    print_info "获取 Token 可管理的域名列表..."
    local zones_json zone_list=() zone_ids=()
    zones_json=$(_cf_list_zones "$token" "status=active")
    if ! _cf_api_ok "$zones_json"; then
        print_error "获取域名列表失败: $(_cf_api_err "$zones_json")"
        pause; return
    fi
    while IFS='|' read -r zname zid; do
        [[ -z "$zname" ]] && continue
        zone_list+=("$zname")
        zone_ids+=("$zid")
    done < <(echo "$zones_json" | jq -r '.result[] | "\(.name)|\(.id)"')

    if [[ ${#zone_list[@]} -eq 0 ]]; then
        print_error "该 Token 无可管理的域名，请检查 Token 权限"
        pause; return
    fi

    echo -e "${C_CYAN}可用域名:${C_RESET}"
    for i in "${!zone_list[@]}"; do
        echo "  $((i+1)). ${zone_list[$i]}"
    done
    local zone_choice
    while true; do
        read -e -r -p "选择域名 [1]: " zone_choice
        zone_choice=${zone_choice:-1}
        if [[ "$zone_choice" =~ ^[0-9]+$ ]] && (( zone_choice >= 1 && zone_choice <= ${#zone_list[@]} )); then
            break
        fi
        print_warn "请输入 1-${#zone_list[@]}"
    done
    local root_domain="${zone_list[$((zone_choice-1))]}"
    local zone_id="${zone_ids[$((zone_choice-1))]}"
    print_success "已选择: ${root_domain} (Zone: ${zone_id})"

    # 3. (SaaS 优选已移除 - CF NS 接入不支持，需第三方 DNS)

    # 4. 子域名前缀
    local sub_prefix=""
    print_guide "输入子域名前缀"
    echo -e "  ${C_GRAY}例如输入 alist -> 访问地址为 alist.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}例如输入 nas -> 访问地址为 nas.${root_domain}${C_RESET}"
    while true; do
        read -e -r -p "子域名前缀: " sub_prefix
        if [[ -z "$sub_prefix" ]]; then
            print_warn "不能为空"
            continue
        fi
        validate_dns_label "$sub_prefix" && break
        print_error "子域名前缀格式无效（仅小写字母、数字、短横；首尾不能为短横，1-63 字符）"
        sub_prefix=""
    done
    local full_domain="${sub_prefix}.${root_domain}"

    # 检查是否已有配置
    if [[ -f "${CONFIG_DIR}/${full_domain}.conf" ]] || \
       [[ -f "/etc/nginx/sites-available/${full_domain}.conf" ]]; then
        print_warn "${full_domain} 已有配置 (域名/Nginx/DDNS 等)"
        if ! confirm "自动清除旧配置并重新配置？"; then pause; return; fi
        print_info "清理旧配置..."
        _web_cleanup_domain "$full_domain" "quiet"
    fi

    # 5. 后端服务地址
    local backend_addr=""
    print_guide "内网服务地址 (IP:端口)"
    echo -e "  ${C_GRAY}服务在本机: 直接输入端口号即可，如 5244${C_RESET}"
    echo -e "  ${C_GRAY}服务在其他设备: 输入 IP:端口，如 192.168.1.100:5244${C_RESET}"
    echo -e "  ${C_GRAY}常用端口: Alist 5244, Jellyfin/Emby 8096${C_RESET}"
    while true; do
        read -e -r -p "后端地址 [127.0.0.1:5244]: " backend_addr
        backend_addr=${backend_addr:-"127.0.0.1:5244"}
        # 只输入了端口号，自动补 127.0.0.1
        if [[ "$backend_addr" =~ ^[0-9]+$ ]]; then
            if (( backend_addr >= 1 && backend_addr <= 65535 )); then
                backend_addr="127.0.0.1:${backend_addr}"
                break
            fi
            print_warn "端口无效，请输入 1-65535"
            continue
        fi
        # IP:端口 格式校验
        if [[ "$backend_addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
            local _bport=${backend_addr##*:}
            if (( _bport >= 1 && _bport <= 65535 )); then
                break
            fi
        fi
        print_warn "格式无效，请输入 端口号 或 IP:端口"
    done
    print_success "后端地址: ${backend_addr}"

    # 6. Nginx HTTPS 监听端口
    local https_port="" requested_https_port="" origin_rule_needed=0
    print_guide "Nginx HTTPS 监听端口 (对外暴露的端口)"
    echo -e "  ${C_GRAY}家宽通常 443 被封，建议用 8443${C_RESET}"
    echo -e "  ${C_GRAY}CF 支持的 HTTPS 端口: 443 2053 2083 2087 2096 8443${C_RESET}"
    while true; do
        read -e -r -p "HTTPS 端口 [8443]: " https_port
        https_port=${https_port:-8443}
        if [[ "$https_port" =~ ^[0-9]+$ ]] && (( https_port >= 1 && https_port <= 65535 )); then
            break
        fi
        print_warn "端口无效"
    done
    requested_https_port="$https_port"
    # Reality 443 共存：用户选择 443 时，Nginx 下沉到 web 内部端口；公网 443 由 stream 分流。
    https_port="$(_web_coexist_https_port "$https_port")"
    if [[ "$https_port" != "443" ]]; then
        if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
            origin_rule_needed=0
        else
            origin_rule_needed=1
        fi
    fi


    # 7. DDNS 间隔
    local ddns_interval=""
    read -e -r -p "DDNS 检测间隔(分钟, 1-59) [5]: " ddns_interval
    ddns_interval=${ddns_interval:-5}
    if [[ ! "$ddns_interval" =~ ^[0-9]+$ ]] || (( ddns_interval < 1 || ddns_interval > 59 )); then
        print_warn "间隔无效，使用默认值 5"
        ddns_interval=5
    fi

    # 8. 探测公网 IP
    print_info "探测公网 IP..."
    local public_ip=""
    public_ip=$(get_public_ipv4)
    if [[ -z "$public_ip" ]]; then
        print_warn "未自动检测到 IPv4，请手动输入"
        read -e -r -p "公网 IPv4: " public_ip
        if ! validate_ip "$public_ip"; then
            print_error "IP 格式无效"; pause; return
        fi
    fi
    print_success "公网 IP: $public_ip"

    # 配置确认
    echo ""
    draw_line
    echo -e "${C_CYAN}配置确认:${C_RESET}"
    echo -e "  访问域名:     ${C_GREEN}${full_domain}${C_RESET}"
    echo -e "  根域名:       ${C_GREEN}${root_domain}${C_RESET} (Zone: ${zone_id})"
    echo -e "  公网 IP:      ${C_GREEN}${public_ip}${C_RESET}"
    echo -e "  后端地址:     ${C_GREEN}${backend_addr}${C_RESET} (内网服务)"
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        echo -e "  HTTPS 端口:   ${C_GREEN}${requested_https_port}${C_RESET} (对外) / ${C_GREEN}${https_port}${C_RESET} (Nginx 内部监听)"
    else
        echo -e "  HTTPS 端口:   ${C_GREEN}${https_port}${C_RESET} (Nginx 对外监听)"
    fi
    echo -e "  DDNS 间隔:    ${C_GREEN}${ddns_interval} 分钟${C_RESET}"
    echo -e "  加速模式:     ${C_GREEN}CF CDN 代理${C_RESET} (A 记录 + Proxied)"
    echo ""
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    local auto_step=1
    echo -e "    ${auto_step}. DNS 解析 -> ${full_domain} -> ${public_ip} (CF 代理)"; ((auto_step++))
    echo -e "    ${auto_step}. SSL 证书申请 (Let's Encrypt DNS 验证)"; ((auto_step++))
    echo -e "    ${auto_step}. Nginx 反向代理 (:${https_port} -> ${backend_addr})"; ((auto_step++))
    echo -e "    ${auto_step}. DDNS 自动更新 (每 ${ddns_interval} 分钟)"; ((auto_step++))
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        echo -e "    ${auto_step}. 共存模式刷新 SNI 白名单（公网 443 -> 内部 ${https_port}）"; ((auto_step++))
    else
        echo -e "    ${auto_step}. 防火墙放行端口 ${https_port}"; ((auto_step++))
    fi
    [[ "$origin_rule_needed" -eq 1 ]] && { echo -e "    ${auto_step}. CF Origin Rule (用户 :443 -> 回源 :${https_port})"; ((auto_step++)); }
    echo ""
    echo -e "  ${C_YELLOW}[手动操作提醒]${C_RESET}"
    echo -e "  ${C_YELLOW}  请确保路由器 (OpenWrt/爱快等) 已做端口转发:${C_RESET}"
    echo -e "  ${C_YELLOW}  外网 ${requested_https_port}/TCP -> 内网运行 Nginx 的设备IP:${requested_https_port}/TCP${C_RESET}"
    if [[ "$backend_addr" != 127.0.0.1:* ]]; then
        echo -e "  ${C_YELLOW}  后端服务在其他设备 (${backend_addr})，请确保内网互通${C_RESET}"
    fi
    draw_line
    if ! confirm "确认开始执行?"; then
        print_warn "已取消"; pause; return
    fi

    # Phase 2: 自动执行
    local step=1 total_steps=5
    local dns_snapshot="" dns_restore_needed=0 origin_rules_snapshot="" origin_restore_needed=0
    [[ "$origin_rule_needed" -eq 1 ]] && total_steps=$((total_steps + 1))

    # Step: DNS 解析
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DNS 解析 ===${C_RESET}"
    dns_snapshot=$(_cf_dns_snapshot_records "$zone_id" "$token" "$full_domain" A AAAA CNAME) || {
        print_error "DNS 快照创建失败，已中止以避免后续失败无法恢复 Cloudflare 远端状态"
        pause; return 1
    }
    dns_restore_needed=1
    # 重新配置时可能残留旧 CNAME，CF 不允许同名 A/CNAME 共存，需先清除
    if ! _cf_dns_delete "$zone_id" "$token" "CNAME" "$full_domain"; then
        print_error "清理旧 CNAME 记录失败，已中止以避免 A/CNAME 冲突或覆盖失败。"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 0
        pause; return 1
    fi
    print_info "创建 A 记录: ${full_domain} -> ${public_ip} (开启 CF 代理)"
    if ! _cf_update_dns_record "$zone_id" "$token" "$full_domain" "A" "$public_ip" "true"; then
        print_error "DNS 记录创建失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 0
        pause; return 1
    fi
    ((step++))

    # Step: SSL 证书
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] SSL 证书申请 ===${C_RESET}"
    local cert_dir="${CERT_PATH_PREFIX}/${full_domain}"
    mkdir -p "$cert_dir" || {
        print_error "证书目录创建失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    local cf_cred="/root/.cloudflare-${full_domain}.ini"
    write_private_file_atomic "$cf_cred" "dns_cloudflare_api_token = $token" || {
        print_error "Cloudflare 凭据写入失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    print_info "正在申请证书 (DNS 验证，可能需要 1-2 分钟)..."
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$cf_cred" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$full_domain" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive; then
        copy_cert_pair_atomic "/etc/letsencrypt/live/${full_domain}/fullchain.pem" "/etc/letsencrypt/live/${full_domain}/privkey.pem" "$cert_dir" || {
            print_error "证书复制失败"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
        print_success "证书获取成功"
    else
        print_error "证书申请失败！请检查 Token 权限和网络"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    ((step++))

    # Step: Nginx 反向代理
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] Nginx 反向代理 ===${C_RESET}"
    _ensure_ssl_params
    local redir_port
    redir_port="$(_web_coexist_redir_suffix "$https_port")"
    local nginx_conf="# 家宽公网暴露 - ${full_domain}
# Generated by $SCRIPT_NAME $VERSION (web_home_expose)
server {
    listen 80;
    listen [::]:80;
    server_name ${full_domain};
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$https_port")
    server_name ${full_domain};
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass http://${backend_addr};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}"
    if ! _nginx_deploy_conf "$full_domain" "$nginx_conf"; then
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    print_success "Nginx 已部署 (:${https_port} -> ${backend_addr})"
    # 443 共存模式：把本站域名加入 stream SNI 白名单（未启用则 no-op）
    declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
    ((step++))

    # Step: DDNS
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DDNS 动态解析 ===${C_RESET}"
    local ddns_domain="$full_domain"
    local ddns_proxied="true"
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN=\"${ddns_domain}\"
DDNS_TOKEN=\"${token}\"
DDNS_ZONE_ID=\"${zone_id}\"
DDNS_IPV4=\"true\"
DDNS_IPV6=\"false\"
DDNS_PROXIED=\"${ddns_proxied}\"
DDNS_INTERVAL=\"${ddns_interval}\""
    write_private_file_atomic "$DDNS_CONFIG_DIR/${ddns_domain}.conf" "$ddns_conf_content" || {
        print_error "DDNS 配置写入失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    ddns_create_script || {
        print_error "DDNS 更新脚本生成失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    ddns_rebuild_cron || {
        print_error "DDNS cron 更新失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    print_success "DDNS 已配置: ${ddns_domain} (每 ${ddns_interval} 分钟)"
    ((step++))

    # Step: 防火墙
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] 防火墙 ===${C_RESET}"
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        print_info "共存模式：${https_port} 为内部端口，仅 loopback 可达，不放行到公网（对外由 443 提供）"
        if ! command_exists ufw || ! ufw_is_active; then
            print_info "UFW 未启用，跳过 (共存模式请确保服务器防火墙已放行公网 ${requested_https_port})"
        fi
    else
        _web_allow_public_tcp_port "$https_port" "HomeExpose-${full_domain}" "${https_port}/tcp" || {
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
    fi
    ((step++))

    # Step: Origin Rule (公网 443 需回源到非内部端口时)
    if [[ "$origin_rule_needed" -eq 1 ]]; then
        echo -e "\n${C_CYAN}=== [${step}/${total_steps}] CF Origin Rule (端口回源) ===${C_RESET}"
        print_info "创建回源规则: 用户访问 :443 -> CF 回源 :${https_port}"
        local existing
        if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
            print_error "Origin Rules 读取失败，端口回源规则未创建。"
            print_warn "请稍后通过菜单 [10.创建回源规则] 手动添加后再使用该公网 443 入口。"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause
            return 1
        else
            local existing_rules="[]"
            if [[ -n "$existing" ]]; then
                existing_rules=$(echo "$existing" | jq -c '.result.rules // []') || {
                    print_error "Origin Rules 响应解析失败"
                    _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                    pause; return 1
                }
            fi
            origin_rules_snapshot="$existing_rules"
            origin_restore_needed=1
            # 移除同域名旧规则
        local filtered_rules=$(echo "$existing_rules" | jq --arg d "$full_domain" \
            '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]') || {
                print_error "Origin Rules 过滤旧规则失败"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause; return 1
            }
        # 构建新规则
        local new_rule=$(jq -n \
            --arg expr "http.host eq \"${full_domain}\"" \
            --arg desc "HomeExpose-${full_domain}-${https_port}" \
            --argjson port "$https_port" \
            '{
                "action": "route",
                "action_parameters": { "origin": { "port": $port } },
                "expression": $expr,
                "description": $desc,
                "enabled": true
            }') || {
                print_error "Origin Rules 新规则构造失败"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause; return 1
            }
        local final_rules=$(echo "$filtered_rules" | jq --argjson new "$new_rule" '. + [$new]') || {
            print_error "Origin Rules 新旧规则合并失败"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
        local err
            if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules"); then
                print_error "Origin Rule 创建失败: $err"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause
                return 1
            else
                print_success "Origin Rule 已创建 (用户 :443 -> 回源 :${https_port})"
            fi
            ((step++))
        fi
    fi

    # Step: SSL/TLS Full 模式
    print_info "设置 SSL/TLS 为 Full 模式..."
    local ssl_resp=$(_cf_api PATCH "/zones/$zone_id/settings/ssl" "$token" \
        --data '{"value":"full"}')
    _cf_api_ok "$ssl_resp" && print_success "SSL/TLS -> Full" || \
        print_warn "SSL 设置: $(_cf_api_err "$ssl_resp") (可能已是 Full)"

    # 保存配置文件 + 证书续签 Hook
    mkdir -p "$CONFIG_DIR" "$CERT_HOOKS_DIR"

    # 续签 Hook 脚本
    local hook_script="${CERT_HOOKS_DIR}/renew-${full_domain}.sh"
    local hook_content="#!/bin/bash
# Auto-generated renewal hook for $full_domain (home expose)
# Generated by $SCRIPT_NAME $VERSION
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=\"$full_domain\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"
echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

$(render_cert_pair_hook_helper)

if copy_cert_pair_atomic \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}\"; then
    echo \"[\$(date)] Certificates copied successfully\" >> /var/log/cert-renew.log
else
    echo \"[\$(date)] ERROR: Certificate files not found\" >> /var/log/cert-renew.log
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx 2>&1 | tee -a /var/log/cert-renew.log
else
    nginx -s reload 2>&1 | tee -a /var/log/cert-renew.log
fi
echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
    if ! write_file_atomic "$hook_script" "$hook_content"; then
        print_error "证书续签 Hook 写入失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    if ! chmod +x "$hook_script"; then
        print_error "证书续签 Hook 权限设置失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi

    # Crontab 自动续签
    local cron_tag="CertRenew_${full_domain}"
    local cron_minute=$(( $(echo "$full_domain" | cksum | cut -d' ' -f1) % 60 ))
    if ! cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${full_domain}' --deploy-hook '${hook_script}' # ${cron_tag}"; then
        print_error "证书续签 cron 安装失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi

    # 域名管理配置文件
    local domain_config_content="# Domain configuration for ${full_domain}
# Generated by $SCRIPT_NAME $VERSION (web_home_expose)
DOMAIN=\"${full_domain}\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"${hook_script}\"
CLOUDFLARE_CREDENTIALS=\"${cf_cred}\"
NGINX_HTTP_PORT=\"80\"
NGINX_HTTPS_PORT=\"${https_port}\"
LOCAL_PROXY_PASS=\"http://${backend_addr}\"
HOME_EXPOSE=\"true\""
    if ! write_file_atomic "${CONFIG_DIR}/${full_domain}.conf" "$domain_config_content"; then
        print_error "域名管理配置写入失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    dns_restore_needed=0
    origin_restore_needed=0

    # 完成报告
    echo ""
    draw_line
    print_success "家宽公网暴露配置完成！"
    draw_line
    echo -e "  ${C_CYAN}[访问地址]${C_RESET}"
    echo -e "    https://${full_domain}"
    echo ""
    echo -e "  ${C_CYAN}[访问链路]${C_RESET}"
    echo -e "    用户 -> ${C_GREEN}${full_domain}${C_RESET} (CF CDN 代理)"
    [[ "$origin_rule_needed" -eq 1 ]] && \
    echo -e "      -> Origin Rule :443 -> :${C_GREEN}${https_port}${C_RESET}"
    echo -e "      -> 家宽路由器 -> 内网 Nginx -> ${C_GREEN}${backend_addr}${C_RESET}"
    echo ""
    echo -e "  ${C_CYAN}[证书]${C_RESET}"
    echo -e "    公钥: ${cert_dir}/fullchain.pem"
    echo -e "    私钥: ${cert_dir}/privkey.pem"
    echo -e "    续签: 每日 3:$(printf '%02d' $cron_minute) AM 自动检查"
    echo ""
    echo -e "  ${C_CYAN}[DDNS]${C_RESET}"
    echo -e "    域名: ${ddns_domain}"
    echo -e "    间隔: 每 ${ddns_interval} 分钟"
    echo ""
    echo -e "  ${C_YELLOW}[路由器操作 - 需要手动完成]${C_RESET}"
    echo -e "    请在路由器 (OpenWrt/爱快等) 做端口转发:"
    echo -e "    外网 ${C_GREEN}${requested_https_port}${C_RESET}/TCP -> 运行 Nginx 的设备IP:${C_GREEN}${requested_https_port}${C_RESET}/TCP"
    if [[ "$backend_addr" != 127.0.0.1:* ]]; then
        echo -e "    后端服务在 ${C_GREEN}${backend_addr}${C_RESET}，请确保内网互通"
    fi
    echo -e "    当前 CF 支持的 HTTPS 代理端口: ${C_GREEN}443 2053 2083 2087 2096 8443${C_RESET}"
    draw_line
    log_action "Home expose configured: ${full_domain} -> ${backend_addr} (port=${https_port})"

    # 可选: 内网 DNS 劫持 (解决 NAT 回环)
    echo ""
    echo -e "${C_CYAN}内网 DNS 劫持 (解决 NAT 回环问题):${C_RESET}"
    echo -e "  ${C_GRAY}问题: 内网设备访问 ${full_domain} -> 解析到公网 IP -> 路由器 -> 无法回环${C_RESET}"
    echo -e "  ${C_GRAY}解决: 在路由器 dnsmasq 添加本地解析，内网直连不走公网${C_RESET}"
    if confirm "是否自动配置路由器内网 DNS 劫持 (需 SSH 到 OpenWrt)?"; then
        # 检测网关 IP
        local gw_ip=""
        gw_ip=$(ip route | grep '^default' | awk '{print $3}' | head -1)
        [[ -z "$gw_ip" ]] && gw_ip="10.10.100.1"
        read -e -r -p "路由器 SSH 地址 [root@${gw_ip}]: " router_ssh
        router_ssh=${router_ssh:-"root@${gw_ip}"}

        # 检测本机内网 IP (Nginx 所在设备)
        local local_ip=""
        local_ip=$(ip route get "${gw_ip}" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
        [[ -z "$local_ip" ]] && local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        read -e -r -p "本机内网 IP (运行 Nginx 的设备) [${local_ip}]: " nginx_ip
        nginx_ip=${nginx_ip:-"$local_ip"}

        if [[ -z "$nginx_ip" ]]; then
            print_error "未能检测到内网 IP，请手动输入"
            read -e -r -p "内网 IP: " nginx_ip
            [[ -z "$nginx_ip" ]] && { print_warn "跳过 DNS 劫持配置"; pause; return; }
        fi
        if ! validate_ip "$nginx_ip"; then
            print_error "内网 IP 无效: ${nginx_ip}"
            print_warn "跳过 DNS 劫持配置"
            pause
            return 0
        fi

        echo -e "${C_CYAN}配置预览:${C_RESET}"
        echo -e "  路由器: ${C_GREEN}${router_ssh}${C_RESET}"
        echo -e "  规则:   ${C_GREEN}${full_domain} -> ${nginx_ip}${C_RESET}"
        echo ""
        print_info "正在 SSH 到路由器配置 dnsmasq..."

        # 通过 uci 配置 (兼容所有 OpenWrt 版本)
        local uci_cmds="
DHCP_BACKUP=\$(mktemp /tmp/server-manage-dhcp.XXXXXX 2>/dev/null) || exit 1
cleanup_dhcp_domain() { rm -f \"\$DHCP_BACKUP\" 2>/dev/null; }
rollback_dhcp_domain() {
    rc=\${1:-1}
    if [ -f \"\$DHCP_BACKUP\" ]; then
        uci import dhcp < \"\$DHCP_BACKUP\" >/dev/null 2>&1 || true
        uci commit dhcp >/dev/null 2>&1 || true
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    fi
    cleanup_dhcp_domain
    exit \"\$rc\"
}
trap cleanup_dhcp_domain EXIT
uci export dhcp > \"\$DHCP_BACKUP\" || rollback_dhcp_domain 1
# 精确清除: 遍历查找并删除匹配的 domain 条目
idx=0
while uci -q get dhcp.@domain[\$idx] >/dev/null 2>&1; do
    name=\$(uci -q get dhcp.@domain[\$idx].name 2>/dev/null) || rollback_dhcp_domain 1
    if [ \"\$name\" = '${full_domain}' ]; then
        uci delete dhcp.@domain[\$idx] || rollback_dhcp_domain 1
    else
        idx=\$((idx + 1))
    fi
done
# 添加新记录
uci add dhcp domain >/dev/null || rollback_dhcp_domain 1
uci set dhcp.@domain[-1].name='${full_domain}' || rollback_dhcp_domain 1
uci set dhcp.@domain[-1].ip='${nginx_ip}' || rollback_dhcp_domain 1
uci commit dhcp || rollback_dhcp_domain 1
/etc/init.d/dnsmasq restart || rollback_dhcp_domain 1
cleanup_dhcp_domain
		"
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
            "$router_ssh" "${uci_cmds}" 2>&1; then
            print_success "内网 DNS 劫持配置成功！"
            echo -e "  ${C_GREEN}${full_domain} -> ${nginx_ip}${C_RESET} (内网直连)"
        else
            print_warn "SSH 配置失败，请手动在路由器上执行:"
            echo -e "  ${C_YELLOW}ssh ${router_ssh}${C_RESET}"
            echo -e "  ${C_YELLOW}uci add dhcp domain${C_RESET}"
            echo -e "  ${C_YELLOW}uci set dhcp.@domain[-1].name='${full_domain}'${C_RESET}"
            echo -e "  ${C_YELLOW}uci set dhcp.@domain[-1].ip='${nginx_ip}'${C_RESET}"
            echo -e "  ${C_YELLOW}uci commit dhcp${C_RESET}"
            echo -e "  ${C_YELLOW}/etc/init.d/dnsmasq restart${C_RESET}"
        fi
    fi
    pause
}
docker_remove_conflicting_packages() {
    # Docker 官方 Debian/Ubuntu 安装文档要求先移除这些可能冲突的发行版包。
    # 失败不阻断：部分精简系统未安装 apt 包数据库或包名不存在。
    local conflicts=(docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc)
    print_info "移除可能冲突的旧 Docker/Compose 包..."
    apt-get remove -y "${conflicts[@]}" >/dev/null 2>&1 || true
}

_docker_keyring_path() {
    printf '%s' "${DOCKER_KEYRING_FILE:-/etc/apt/keyrings/docker.gpg}"
}

_docker_source_list_path() {
    printf '%s' "${DOCKER_SOURCE_LIST_FILE:-/etc/apt/sources.list.d/docker.list}"
}

_docker_compose_bin_path() {
    printf '%s' "${DOCKER_COMPOSE_BIN:-/usr/local/bin/docker-compose}"
}

_docker_render_apt_source() {
    local arch="$1" docker_gpg="$2" docker_repo_os="$3" version_codename="$4"
    printf 'deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n' \
        "$arch" "$docker_gpg" "$docker_repo_os" "$version_codename"
}

_docker_install_keyring() {
    local docker_repo_os="$1" docker_gpg="$2" dir tmp_armored tmp_gpg
    [[ "$docker_gpg" == /* ]] || return 1
    dir="$(dirname "$docker_gpg")"
    mkdir -p "$dir" || return 1
    tmp_armored=$(mktemp "${dir}/.tmp.server-manage.docker-gpg.asc.XXXXXX") || return 1
    _tmp_register "$tmp_armored"
    tmp_gpg=$(mktemp "${dir}/.tmp.server-manage.docker-gpg.XXXXXX") || {
        rm -f -- "$tmp_armored" 2>/dev/null || true
        _tmp_unregister "$tmp_armored"
        return 1
    }
    _tmp_register "$tmp_gpg"
    if curl -fsSL "https://download.docker.com/linux/${docker_repo_os}/gpg" -o "$tmp_armored" 2>/dev/null \
        && gpg --dearmor < "$tmp_armored" > "$tmp_gpg" 2>/dev/null; then
        chmod 0644 "$tmp_gpg" 2>/dev/null || true
        chown root:root "$tmp_gpg" 2>/dev/null || true
        if mv "$tmp_gpg" "$docker_gpg"; then
            rm -f -- "$tmp_armored" 2>/dev/null || true
            _tmp_unregister "$tmp_armored"
            _tmp_unregister "$tmp_gpg"
            return 0
        fi
    fi
    rm -f -- "$tmp_armored" "$tmp_gpg" 2>/dev/null || true
    _tmp_unregister "$tmp_armored"
    _tmp_unregister "$tmp_gpg"
    return 1
}

_docker_write_apt_source() {
    local docker_list="$1" arch="$2" docker_gpg="$3" docker_repo_os="$4" version_codename="$5" content
    [[ "$docker_list" == /* && "$docker_gpg" == /* ]] || return 1
    content="$(_docker_render_apt_source "$arch" "$docker_gpg" "$docker_repo_os" "$version_codename")"
    write_file_atomic "$docker_list" "$content" || return 1
    chmod 0644 "$docker_list" 2>/dev/null || true
}

docker_install() {
    print_title "Docker 安装"
    if command_exists docker; then
        print_warn "Docker 已安装。"
        docker --version
        pause; return
    fi
    print_info "正在安装 Docker..."
    update_apt_cache
    # 官方冲突包列表：docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc
    docker_remove_conflicting_packages
    install_package "ca-certificates" "silent"
    install_package "curl" "silent"
    install_package "gnupg" "silent"
    local docker_gpg="$(_docker_keyring_path)"
    local keyring_dir
    keyring_dir="$(dirname "$docker_gpg")"
    if ! mkdir -p "$keyring_dir"; then
        print_error "Docker keyring 目录创建失败。"
        pause; return 1
    fi
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local docker_repo_os="${os_id}"
    [[ "$docker_repo_os" != "ubuntu" && "$docker_repo_os" != "debian" ]] && docker_repo_os="debian"
    if [[ ! -f "$docker_gpg" ]]; then
        print_info "添加 Docker GPG 密钥..."
        # 根据实际系统选择正确的官方仓库 OS；非 Debian/Ubuntu 系回退到 debian 时，
        # GPG URL 与 apt source 必须保持一致。
        if ! _docker_install_keyring "$docker_repo_os" "$docker_gpg"; then
            print_error "GPG 密钥下载失败。"
            pause; return 1
        fi
    fi
    local version_codename=$(grep 'VERSION_CODENAME' /etc/os-release | cut -d= -f2)
    if [[ -z "$version_codename" ]]; then
        version_codename=$(grep 'UBUNTU_CODENAME' /etc/os-release | cut -d= -f2)
    fi
    if [[ -z "$version_codename" ]]; then
        print_error "无法检测系统版本代号，Docker 源配置可能失败。"
        print_info "请手动安装 Docker: https://docs.docker.com/engine/install/"
        pause; return 1
    fi
    local docker_list="$(_docker_source_list_path)"
    if [[ ! -f "$docker_list" ]]; then
        print_info "添加 Docker 软件源..."
        if ! _docker_write_apt_source "$docker_list" "$(dpkg --print-architecture)" "$docker_gpg" "$docker_repo_os" "$version_codename"; then
            print_error "Docker 软件源写入失败。"
            pause; return 1
        fi
    fi
    if ! apt-get update -qq >/dev/null 2>&1; then
        print_error "Docker 软件源更新失败。"
        pause; return 1
    fi
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then
        if is_systemd; then
            if ! systemctl enable docker >/dev/null 2>&1 || ! systemctl start docker >/dev/null 2>&1; then
                print_error "Docker 已安装但服务启动失败。"
                pause; return 1
            fi
        fi
        print_success "Docker 安装成功。"
        docker --version
        log_action "Docker installed"
    else
        print_error "Docker 安装失败。"
        pause; return 1
    fi
    pause
}

docker_uninstall() {
    print_title "Docker 卸载"
    if ! command_exists docker; then
        print_warn "Docker 未安装。"
        pause; return
    fi
    echo -e "${C_RED}警告: 这将删除 Docker 及所有容器、镜像、卷！${C_RESET}"
    if ! confirm "确认卸载？"; then return; fi
    print_info "正在停止服务..."
    if is_systemd; then
        systemctl stop docker docker.socket containerd 2>/dev/null || true
        systemctl disable docker docker.socket containerd 2>/dev/null || true
    fi
    print_info "正在卸载软件包..."
    apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    rm -f "$DOCKER_PROXY_CONF"
    rm -rf "$DOCKER_PROXY_DIR"
    if confirm "是否删除所有 Docker 数据 (/var/lib/docker)?"; then
        rm -rf /var/lib/docker /var/lib/containerd /etc/docker
        print_success "数据已删除。"
    else
        rm -rf /etc/docker
    fi
    rm -f /etc/apt/sources.list.d/docker.list
    rm -f /etc/apt/keyrings/docker.gpg
    hash -r 2>/dev/null || true
    print_success "Docker 已卸载。"
    log_action "Docker uninstalled"
    pause
}

_docker_compose_standalone_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        armv7l|armv7*) echo "armv7" ;;
        *) uname -m ;;
    esac
}

_docker_compose_install_standalone() {
    local compose_url="$1" target_bin="$(_docker_compose_bin_path)" target_dir tmp_bin tmp_sha hash
    [[ "$target_bin" == /* ]] || return 1
    target_dir="$(dirname "$target_bin")"
    mkdir -p "$target_dir" || return 1
    tmp_bin=$(mktemp "${target_dir}/.tmp.server-manage.docker-compose.XXXXXX") || return 1
    _tmp_register "$tmp_bin"
    tmp_sha=$(mktemp "${target_dir}/.tmp.server-manage.docker-compose.sha256.XXXXXX") || {
        rm -f -- "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    }
    _tmp_register "$tmp_sha"
    if curl -fL --retry 3 "$compose_url" -o "$tmp_bin" 2>/dev/null \
        && curl -fL --retry 3 "${compose_url}.sha256" -o "$tmp_sha" 2>/dev/null \
        && hash=$(awk '{print $1; exit}' "$tmp_sha") \
        && [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] \
        && printf '%s  %s\n' "$hash" "$tmp_bin" | sha256sum -c - >/dev/null; then
        chmod 0755 "$tmp_bin" 2>/dev/null || true
        chown root:root "$tmp_bin" 2>/dev/null || true
        if mv "$tmp_bin" "$target_bin"; then
            rm -f -- "$tmp_sha" 2>/dev/null || true
            _tmp_unregister "$tmp_bin"
            _tmp_unregister "$tmp_sha"
            return 0
        fi
    fi
    rm -f -- "$tmp_bin" "$tmp_sha" 2>/dev/null || true
    _tmp_unregister "$tmp_bin"
    _tmp_unregister "$tmp_sha"
    return 1
}

_docker_systemd_reload_restart() {
    is_systemd || return 0
    systemctl daemon-reload >/dev/null || return 1
    systemctl restart docker >/dev/null || return 1
}

_docker_restore_proxy_conf() {
    local backup="$1" had_old="$2"
    if [[ "$had_old" -eq 1 && -f "$backup" ]]; then
        mkdir -p "$DOCKER_PROXY_DIR" 2>/dev/null || true
        cp -a "$backup" "$DOCKER_PROXY_CONF" 2>/dev/null || true
    else
        rm -f "$DOCKER_PROXY_CONF" 2>/dev/null || true
    fi
}

_docker_apply_proxy_conf() {
    local proxy_conf="$1" backup="" had_old=0
    mkdir -p "$DOCKER_PROXY_DIR" || return 1
    if [[ -f "$DOCKER_PROXY_CONF" ]]; then
        backup=$(mktemp "${DOCKER_PROXY_DIR}/.http-proxy.conf.bak.XXXXXX") || return 1
        cp -a "$DOCKER_PROXY_CONF" "$backup" || { rm -f "$backup"; return 1; }
        had_old=1
    fi
    if ! write_file_atomic "$DOCKER_PROXY_CONF" "$proxy_conf"; then
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    if ! _docker_systemd_reload_restart; then
        _docker_restore_proxy_conf "$backup" "$had_old"
        _docker_systemd_reload_restart >/dev/null 2>&1 || true
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    rm -f "$backup" 2>/dev/null || true
    return 0
}

_docker_clear_proxy_conf() {
    local backup="" had_old=0
    if [[ -f "$DOCKER_PROXY_CONF" ]]; then
        mkdir -p "$DOCKER_PROXY_DIR" || return 1
        backup=$(mktemp "${DOCKER_PROXY_DIR}/.http-proxy.conf.bak.XXXXXX") || return 1
        cp -a "$DOCKER_PROXY_CONF" "$backup" || { rm -f "$backup"; return 1; }
        had_old=1
    fi
    rm -f "$DOCKER_PROXY_CONF" || { rm -f "$backup" 2>/dev/null || true; return 1; }
    if ! _docker_systemd_reload_restart; then
        _docker_restore_proxy_conf "$backup" "$had_old"
        _docker_systemd_reload_restart >/dev/null 2>&1 || true
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    rm -f "$backup" 2>/dev/null || true
    return 0
}

docker_compose_install() {
    print_title "Docker Compose 安装"
    if command_exists docker && docker compose version >/dev/null 2>&1; then
        print_warn "Docker Compose (Plugin) 已安装。"
        docker compose version
        pause; return
    fi
    if command_exists docker-compose && ! command_exists docker; then
        print_warn "Docker Compose (Standalone) 已安装。"
        docker-compose --version
        pause; return
    fi
    if command_exists docker-compose; then
        print_warn "检测到旧 standalone docker-compose，但当前官方推荐 Compose Plugin；将优先安装 plugin。"
    fi

    print_info "正在安装 Docker Compose Plugin..."
    update_apt_cache
    if apt-get install -y docker-compose-plugin >/dev/null 2>&1 && command_exists docker && docker compose version >/dev/null 2>&1; then
        print_success "Docker Compose Plugin 安装成功。"
        docker compose version
        log_action "Docker Compose plugin installed"
        pause; return
    fi

    print_warn "Compose Plugin 安装失败，尝试 standalone fallback。"
    
    # 自动获取最新版本，失败时使用固定版本作为 fallback
    local compose_version
    if command_exists jq; then
        compose_version=$(curl -s --max-time 10 https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null)
    else
        compose_version=$(curl -s --max-time 10 https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)
    fi
    [[ -z "$compose_version" ]] && compose_version="v2.24.5"
    print_info "版本: $compose_version"
    local compose_arch
    compose_arch=$(_docker_compose_standalone_arch)
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-${compose_arch}"
    if _docker_compose_install_standalone "$compose_url"; then
        print_success "Docker Compose Standalone 安装成功。"
        docker-compose --version
        log_action "Docker Compose standalone installed"
    else
        print_error "下载失败。"
        pause; return 1
    fi
    pause
}

docker_proxy_config() {
    print_title "Docker 代理配置"
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    echo "1. 配置 Docker 守护进程代理 (拉取镜像用)
2. 清除代理配置
0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            read -e -r -p "代理地址 (如 http://proxy.example.com:3128): " proxy
            if [[ -z "$proxy" ]]; then return; fi
            # 校验代理地址格式，防止注入 systemd 指令
            if [[ ! "$proxy" =~ ^https?://[a-zA-Z0-9._-]+(:[0-9]+)?(/.*)?$ ]] && \
               [[ ! "$proxy" =~ ^socks5?://[a-zA-Z0-9._-]+(:[0-9]+)?$ ]]; then
                print_error "代理地址格式无效 (应为 http(s)://host:port 或 socks5://host:port)"
                pause; return
            fi
            local proxy_conf="[Service]
Environment=\"HTTP_PROXY=$proxy\"
Environment=\"HTTPS_PROXY=$proxy\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy\"
Environment=\"https_proxy=$proxy\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
            if ! _docker_apply_proxy_conf "$proxy_conf"; then
                print_error "Docker 代理配置失败，已回滚。"
                pause; return 1
            fi
            print_success "Docker 代理已配置。"
            log_action "Docker proxy configured: $proxy"
            ;;
        2)
            if ! _docker_clear_proxy_conf; then
                print_error "代理配置清除失败，已回滚。"
                pause; return 1
            fi
            print_success "代理配置已清除。"
            log_action "Docker proxy removed"
            ;;
        0|q) return ;;
    esac
    pause
}

docker_images_manage() {
    print_title "Docker 镜像管理"
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    echo "1. 列出所有镜像
2. 删除未使用的镜像
3. 删除所有镜像 (危险)
0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            docker images
            ;;
        2)
            if confirm "删除未使用的镜像？"; then
                if docker image prune -a -f; then
                    print_success "清理完成。"
                    log_action "Docker unused images pruned"
                else
                    print_error "镜像清理失败。"
                    pause; return 1
                fi
            fi
            ;;
        3)
            if confirm "删除所有镜像？这将影响所有容器！"; then
                local all_images=$(docker images -q)
                if [[ -n "$all_images" ]]; then
                    if docker rmi -f $all_images; then
                        print_success "所有镜像已删除。"
                        log_action "Docker all images removed"
                    else
                        print_error "镜像删除失败。"
                        pause; return 1
                    fi
                else
                    print_warn "没有镜像可删除。"
                fi
            fi
            ;;
        0|q) return ;;
    esac
    pause
}

docker_print_stats_table() {
    local stats_output=""
    stats_output=$(docker stats --no-stream --format "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null || true)
    [[ -z "$stats_output" ]] && { print_warn "暂无资源占用数据"; return; }

    if command_exists column; then
        printf '%s\n' "$stats_output" | column -t -s $'\t'
        return
    fi

    printf "  %-24s %-10s %s\n" "名称" "CPU" "内存"
    while IFS=$'\t' read -r name cpu mem; do
        [[ -z "$name" ]] && continue
        printf "  %-24s %-10s %s\n" "$name" "$cpu" "$mem"
    done <<< "$stats_output"
}

docker_containers_manage() {
    if ! command_exists docker; then
        print_error "Docker 未安装。"; pause; return
    fi
    while true; do
        print_title "Docker 容器管理"
        # Build container table
        local containers=()
        local fmt='{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
        while IFS=$'\t' read -r id name image status ports; do
            [[ -z "$id" ]] && continue
            containers+=("$id|$name|$image|$status|$ports")
        done < <(docker ps -a --format "$fmt" 2>/dev/null)
        if [[ ${#containers[@]} -eq 0 ]]; then
            print_warn "没有容器。"
        else
            printf "  ${C_CYAN}%-3s %-4s %-20s %-25s %-30s${C_RESET}\n" "#" "状态" "名称" "镜像" "端口"
            local idx=1
            for entry in "${containers[@]}"; do
                IFS='|' read -r id name image status ports <<< "$entry"
                local icon="${C_RED}○${C_RESET}"
                [[ "$status" == Up* ]] && icon="${C_GREEN}●${C_RESET}"
                [[ ${#image} -gt 25 ]] && image="${image:0:22}..."
                [[ ${#ports} -gt 30 ]] && ports="${ports:0:27}..."
                printf "  %-3s %b  %-20s %-25s %-30s\n" "$idx" "$icon" "$name" "$image" "$ports"
                ((idx++)) || true
            done
        fi
        local running_ids=$(docker ps -q 2>/dev/null)
        if [[ -n "$running_ids" ]]; then
            echo ""
            echo -e "${C_CYAN}[资源占用]${C_RESET}"
            docker_print_stats_table
        fi
        echo ""
        echo -e "${C_CYAN}操作:${C_RESET} 1.启动 2.停止 3.重启 4.日志 5.删除  6.停止所有 7.删除所有  0.返回"
        read -e -r -p "操作 [如 '3 2' 表示重启第2个容器]: " action_input
        [[ -z "$action_input" || "$action_input" == "0" || "$action_input" == "q" ]] && break
        local action=$(echo "$action_input" | awk '{print $1}')
        local target_idx=$(echo "$action_input" | awk '{print $2}')
        if [[ "$action" == "6" ]]; then
            if confirm "停止所有容器?"; then
                local rq=$(docker ps -q)
                if [[ -z "$rq" ]]; then
                    print_warn "无运行中容器"
                elif docker stop $rq >/dev/null; then
                    print_success "已停止"
                    log_action "Docker all containers stopped"
                else
                    print_error "停止失败"
                fi
            fi
            pause; continue
        fi
        if [[ "$action" == "7" ]]; then
            if confirm "删除所有容器? (危险)"; then
                local aq=$(docker ps -aq)
                if [[ -z "$aq" ]]; then
                    print_warn "无容器"
                elif docker rm -f $aq >/dev/null; then
                    print_success "已删除"
                    log_action "Docker all containers removed"
                else
                    print_error "删除失败"
                fi
            fi
            pause; continue
        fi
        if [[ -z "$target_idx" || ! "$target_idx" =~ ^[0-9]+$ ]]; then
            print_error "格式: 操作编号 容器序号 (如 '3 2')"; pause; continue
        fi
        if [[ "$target_idx" -lt 1 || "$target_idx" -gt ${#containers[@]} ]]; then
            print_error "容器序号超出范围"; pause; continue
        fi
        local target_entry="${containers[$((target_idx-1))]}"
        local target_id=$(echo "$target_entry" | cut -d'|' -f1)
        local target_name=$(echo "$target_entry" | cut -d'|' -f2)
        case $action in
            1) docker start "$target_id" && print_success "已启动: $target_name" || print_error "启动失败" ;;
            2) docker stop "$target_id" && print_success "已停止: $target_name" || print_error "停止失败" ;;
            3) docker restart "$target_id" && print_success "已重启: $target_name" || print_error "重启失败" ;;
            4)
                print_info "按 Ctrl+C 退出日志并返回菜单..."
                trap - INT
                docker logs --tail 50 -f "$target_id" || true
                trap 'handle_interrupt' INT
                ;;
            5)
                if confirm "确认删除容器 $target_name?"; then
                    if docker rm -f "$target_id"; then
                        print_success "已删除: $target_name"
                        log_action "Docker container removed: $target_name"
                    else
                        print_error "删除失败"
                    fi
                fi
                ;;
            *) print_error "无效操作" ;;
        esac
        pause
    done
}

menu_docker() {
    fix_terminal
    while true; do
        print_title "Docker 管理"
        if command_exists docker; then
            local dver=$(docker --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
            local cver=$(docker compose version 2>/dev/null | grep -oP '[\d.]+' | head -1)
            local running=$(docker ps -q 2>/dev/null | wc -l)
            local total=$(docker ps -aq 2>/dev/null | wc -l)
            echo -e "${C_GREEN}Docker $dver${C_RESET}${cver:+ | Compose $cver} | 容器: ${running}/${total} 运行中"
        else
            echo -e "${C_YELLOW}Docker 未安装${C_RESET}"
        fi
        echo "1. 安装 Docker
2. 卸载 Docker
3. 安装 Docker Compose
4. 配置 Docker 代理
5. 镜像管理
6. 容器管理 (一览式)
7. 系统清理 (prune)
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) docker_install ;;
            2) docker_uninstall ;;
            3) docker_compose_install ;;
            4) docker_proxy_config ;;
            5) docker_images_manage ;;
            6) docker_containers_manage ;;
            7)
                if command_exists docker; then
                    if confirm "清理未使用的容器、网络、镜像、构建缓存？"; then
                        if docker system prune -a -f --volumes; then
                            print_success "清理完成。"
                            log_action "Docker system pruned"
                        else
                            print_error "清理失败。"
                        fi
                    fi
                else
                    print_error "Docker 未安装。"
                fi
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# 判断一个 IPv4 是否属于私有/CGNAT 地址段
_wg_is_private_ip() {
    local ip="$1"
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"
    [[ "$o1" -eq 10 ]] && return 0
    [[ "$o1" -eq 172 && "$o2" -ge 16 && "$o2" -le 31 ]] && return 0
    [[ "$o1" -eq 192 && "$o2" -eq 168 ]] && return 0
    [[ "$o1" -eq 100 && "$o2" -ge 64 && "$o2" -le 127 ]] && return 0
    return 1
}

# 检测本机是否拥有公网 IP
wg_check_public_ip() {
    local found_public=false found_any=false
    local line ip iface
    while IFS= read -r line; do
        [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/[0-9]+.*[[:space:]]([a-zA-Z0-9_.-]+)[[:space:]]*$ ]] || continue
        ip="${BASH_REMATCH[1]}"
        iface="${BASH_REMATCH[2]}"
        case "$iface" in
            docker*|br-*|veth*|virbr*|lo|cni*|flannel*|cali*) continue ;;
        esac
        found_any=true
        if _wg_is_private_ip "$ip"; then
            echo -e "  ${C_YELLOW}- ${iface}: ${ip} (内网)${C_RESET}"
        else
            echo -e "  ${C_GREEN}- ${iface}: ${ip} (公网)${C_RESET}"
            found_public=true
        fi
    done < <(ip -4 addr show scope global 2>/dev/null | grep 'inet ')
    if ! $found_any; then
        echo -e "  ${C_RED}- 未检测到任何 scope global 的 IPv4 地址${C_RESET}"
        return 1
    fi
    $found_public && return 0 || return 1
}

# OpenWrt 环境兼容性全面检测
# 返回 0 = 全部通过，返回 1 = 有致命项失败
wg_check_openwrt_compat() {
    echo -e "\n${C_CYAN}[OpenWrt 环境兼容性检测]${C_RESET}"
    draw_line

    local fatal=0 warn=0

    # ── [必须] 平台确认 ──
    if [[ "$PLATFORM" == "openwrt" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   平台: OpenWrt"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} 平台: ${PLATFORM} (当前仅支持 OpenWrt)"
        fatal=$((fatal + 1))
    fi

    # ── [信息] 发行版详情 ──
    if [[ -f /etc/openwrt_release ]]; then
        local distro version
        distro=$(grep 'DISTRIB_DESCRIPTION' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
        version=$(grep 'DISTRIB_RELEASE' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 发行版: ${distro:-未知}"
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 版本号: ${version:-未知}"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} 未找到 /etc/openwrt_release"
        warn=$((warn + 1))
    fi

    # ── [必须] opkg 包管理器 ──
    if command -v opkg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   opkg 包管理器可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} opkg 不可用 (无法安装软件包)"
        fatal=$((fatal + 1))
    fi

    # ── [必须] uci 命令 ──
    if command -v uci &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   uci 配置系统可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} uci 不可用 (无法管理网络/防火墙配置)"
        fatal=$((fatal + 1))
    fi

    # ── [必须] nft 命令 + 权限 ──
    if command -v nft &>/dev/null; then
        if nft list tables &>/dev/null; then
            echo -e "  ${C_GREEN}[OK]${C_RESET}   nftables 可用且有权限"
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} nft 命令存在但无执行权限 (需要 root)"
            fatal=$((fatal + 1))
        fi
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} nft 不可用 (防火墙规则依赖 nftables)"
        fatal=$((fatal + 1))
    fi

    # ── [检测] fw4 mangle_prerouting 链 ──
    if nft list chain inet fw4 mangle_prerouting &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   fw4 mangle_prerouting 链存在"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} fw4 mangle_prerouting 链不存在 (Mihomo bypass 将在其运行后自动配置)"
        warn=$((warn + 1))
    fi

    # ── [检测] 内核 WireGuard 支持 ──
    local wg_kernel=false
    if [[ -d /sys/module/wireguard ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    elif lsmod 2>/dev/null | grep -q wireguard; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    fi
    if [[ "$wg_kernel" != "true" ]]; then
        # 尝试检测是否可安装
        if opkg list 2>/dev/null | grep -q 'kmod-wireguard'; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} 内核 WireGuard 模块未加载 (kmod-wireguard 可从 feeds 安装)"
            warn=$((warn + 1))
        elif opkg list-installed 2>/dev/null | grep -q 'kmod-wireguard'; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} kmod-wireguard 已安装但模块未加载 (可能需要重启)"
            warn=$((warn + 1))
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} 内核不支持 WireGuard 且 kmod-wireguard 不在可用包列表中"
            echo -e "         可能的原因: 自定义固件未编译 WireGuard 支持或 feeds 不匹配"
            fatal=$((fatal + 1))
        fi
    fi

    # ── [推荐] jq ──
    if command -v jq &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   jq 已安装"
    else
        if opkg list 2>/dev/null | grep -q '^jq '; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} jq 未安装 (将在安装阶段自动安装)"
            warn=$((warn + 1))
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} jq 未安装且不在可用包列表中 (JSON 数据库操作依赖)"
            fatal=$((fatal + 1))
        fi
    fi

    # ── [推荐] qrencode ──
    if command -v qrencode &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   qrencode 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} qrencode 未安装 (二维码功能不可用，不影响核心功能)"
        warn=$((warn + 1))
    fi

    # ── [推荐] wg 工具 ──
    if command -v wg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   wireguard-tools 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} wireguard-tools 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [信息] IP 转发状态 ──
    local ipfwd
    ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "$ipfwd" == "1" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   IP 转发已启用"
    else
        echo -e "  ${C_CYAN}[INFO]${C_RESET} IP 转发未启用 (安装时将自动开启)"
    fi

    # ── [信息] br-lan 网段 ──
    local br_lan_addr
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | awk '/^[[:space:]]*inet[[:space:]]/ { print $2; exit }')
    if [[ -n "$br_lan_addr" ]]; then
        echo -e "  ${C_CYAN}[INFO]${C_RESET} br-lan 网段: ${br_lan_addr}"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} 未检测到 br-lan 接口 (服务端 LAN 映射需要手动指定)"
        warn=$((warn + 1))
    fi

    # ── [信息] 本机网络 ──
    echo -e "\n${C_CYAN}  本机网络地址:${C_RESET}"
    wg_check_public_ip

    # ── 汇总 ──
    draw_line
    if [[ $fatal -gt 0 ]]; then
        echo -e "  ${C_RED}检测结果: ${fatal} 项致命错误, ${warn} 项警告${C_RESET}"
        print_error "环境不满足安装条件，请先解决上述 [FAIL] 项"
        return 1
    elif [[ $warn -gt 0 ]]; then
        echo -e "  ${C_YELLOW}检测结果: 全部通过, ${warn} 项警告${C_RESET}"
        print_success "环境检测通过 (存在警告但不影响安装)"
    else
        echo -e "  ${C_GREEN}检测结果: 全部通过${C_RESET}"
        print_success "OpenWrt 环境完全兼容"
    fi
    return 0
}
# Sub-modules (loaded via build.sh concatenation):
#   11a -> OpenWrt 环境兼容性检测
#   11  -> constants + db + utilities (this file)
#   11c -> server install/control/uninstall
#   11d -> peer management
#   11e -> Clash/OpenClash config
#   11g -> watchdog + import/export + menus
readonly WG_INTERFACE="wg0"
readonly WG_DB_DIR="${WG_SHARED_DB_DIR}"
readonly WG_DB_FILE="${WG_SHARED_DB_FILE}"
readonly WG_CONF="/etc/wireguard/${WG_INTERFACE}.conf"
readonly WG_ROLE_FILE="${WG_SHARED_ROLE_FILE}"

wg_write_private_file() {
    local file="$1" content="$2" dir tmp old_umask _rc
    dir="$(dirname "$file")"
    mkdir -p "$dir" || return 1
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/.tmp.server-manage.wg.XXXXXX")
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    if declare -F _tmp_register >/dev/null 2>&1; then _tmp_register "$tmp"; fi
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    chown root:root "$tmp" 2>/dev/null || true
    if ! mv -f "$tmp" "$file"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
    return 0
}

wg_shared_export_file() {
    local dir="${WG_EXPORT_DIR:-/root/wireguard-exports}" tmp old_umask _rc
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" 2>/dev/null || true
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/${SCRIPT_NAME}-wg-peers.XXXXXX")
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    chmod 600 "$tmp" 2>/dev/null || true
    chown root:root "$tmp" 2>/dev/null || true
    printf '%s\n' "$tmp"
}

wg_shared_db_init() {
    mkdir -p "$WG_SHARED_DB_DIR"
    [[ -f "$WG_SHARED_DB_FILE" ]] && return 0
    local content
    content=$(cat <<'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "client": {}
}
WGEOF
)
    wg_write_private_file "$WG_SHARED_DB_FILE" "$content"
}

wg_shared_db_get() { jq -r "$@" "$WG_SHARED_DB_FILE" 2>/dev/null; }

wg_shared_db_set() {
    local tmp
    tmp=$(mktemp "${WG_SHARED_DB_DIR}/.tmp.XXXXXX") || { print_error "无法创建临时文件"; return 1; }
    (
        if [[ "$PLATFORM" == "openwrt" ]]; then
            local _retry=0
            while ! flock -n 200 2>/dev/null; do
                _retry=$((_retry+1))
                [[ $_retry -ge 10 ]] && { rm -f "$tmp"; print_error "无法获取数据库锁"; return 1; }
                sleep 0.5
            done
        else
            flock -w 5 200 || { rm -f "$tmp"; print_error "无法获取数据库锁"; return 1; }
        fi
        if jq "$@" "$WG_SHARED_DB_FILE" > "$tmp" 2>/dev/null; then
            chmod 600 "$tmp" 2>/dev/null || true
            chown root:root "$tmp" 2>/dev/null || true
            mv "$tmp" "$WG_SHARED_DB_FILE"
        else
            rm -f "$tmp"; print_error "数据库写入失败"; return 1
        fi
    ) 200>"${WG_SHARED_DB_FILE}.lock"
}

wg_shared_get_role() {
    local role=""
    [[ -f "$WG_SHARED_ROLE_FILE" ]] && role=$(cat "$WG_SHARED_ROLE_FILE" 2>/dev/null)
    [[ -z "$role" && -f "$WG_SHARED_DB_FILE" ]] && role=$(wg_shared_db_get '.role // empty')
    if [[ -z "$role" && -f "$WG_SHARED_DB_FILE" ]]; then
        local spk
        spk=$(wg_shared_db_get '.server.private_key // empty')
        [[ -n "$spk" ]] && role="server"
    fi
    echo "${role:-none}"
}

wg_shared_set_role() {
    mkdir -p /etc/wireguard
    wg_write_private_file "$WG_SHARED_ROLE_FILE" "$1" || return 1
    wg_shared_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_shared_gateway_lans() {
    local get_fn="${1:-}"
    declare -F "$get_fn" >/dev/null 2>&1 || return 1
    local pc
    pc=$("$get_fn" '.peers | length' 2>/dev/null)
    [[ "$pc" =~ ^[0-9]+$ ]] || pc=0

    local i=0 seen="" result="" enabled is_gw lans IFS_BAK sub
    while [[ $i -lt $pc ]]; do
        enabled=$("$get_fn" ".peers[$i].enabled" 2>/dev/null)
        is_gw=$("$get_fn" ".peers[$i].is_gateway // false" 2>/dev/null)
        lans=$("$get_fn" ".peers[$i].lan_subnets // empty" 2>/dev/null)
        if [[ "$enabled" == "true" && "$is_gw" == "true" && -n "$lans" && "$lans" != "null" ]]; then
            IFS_BAK="$IFS"; IFS=','
            for sub in $lans; do
                sub=$(echo "$sub" | xargs)
                [[ -n "$sub" ]] || continue
                validate_cidr "$sub" || continue
                case "$seen" in
                    *"|$sub|"*) ;;
                    *)
                        seen="${seen}|${sub}|"
                        [[ -n "$result" ]] && result="${result}"$'\n'
                        result="${result}${sub}"
                        ;;
                esac
            done
            IFS="$IFS_BAK"
        fi
        i=$((i + 1))
    done
    printf '%s\n' "$result" | sed '/^$/d'
}

wg_shared_sync_gateway_routes() {
    local get_fn="${1:-}" iface="${2:-}" state_file="${3:-$WG_SHARED_ROUTE_STATE_FILE}"
    [[ -n "$iface" ]] || return 1
    command_exists ip || return 1

    local current old rc=0
    current=$(wg_shared_gateway_lans "$get_fn") || return 1

    if [[ -f "$state_file" ]]; then
        while IFS= read -r old || [[ -n "$old" ]]; do
            old=$(echo "$old" | xargs)
            [[ -n "$old" ]] || continue
            validate_cidr "$old" || continue
            if ! printf '%s\n' "$current" | grep -Fxq -- "$old"; then
                if [[ "$old" == *:* ]]; then
                    ip -6 route del "$old" dev "$iface" >/dev/null 2>&1 || true
                else
                    ip route del "$old" dev "$iface" >/dev/null 2>&1 || true
                fi
            fi
        done < "$state_file"
    fi

    while IFS= read -r old || [[ -n "$old" ]]; do
        old=$(echo "$old" | xargs)
        [[ -n "$old" ]] || continue
        if [[ "$old" == *:* ]]; then
            ip -6 route replace "$old" dev "$iface" >/dev/null 2>&1 || rc=1
        elif ! ip route replace "$old" dev "$iface" >/dev/null 2>&1; then
            rc=1
        fi
    done <<< "$current"
    [[ "$rc" -eq 0 ]] || return 1

    if [[ -n "$current" ]]; then
        wg_write_private_file "$state_file" "$current" || return 1
    else
        rm -f -- "$state_file" 2>/dev/null || return 1
    fi
    return 0
}

wg_db_init() { wg_shared_db_init; }
wg_db_get() { wg_shared_db_get "$@"; }
wg_db_set() { wg_shared_db_set "$@"; }
wg_get_role() { wg_shared_get_role; }
wg_set_role() { wg_shared_set_role "$@"; }

wg_shared_endpoint_host() {
    local host="${1:-}"
    if [[ "$host" =~ ^\[(.*)\]:[0-9]+$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "$host" =~ ^\[(.*)\]$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "$host" =~ ^([^:]+):[0-9]+$ ]]; then
        host="${BASH_REMATCH[1]}"
    fi
    printf '%s\n' "$host"
}

wg_shared_normalize_endpoint_host() {
    local endpoint="${1:-}" host
    host=$(wg_shared_endpoint_host "$endpoint")
    validate_host "$host" || return 1
    printf '%s\n' "$host"
}

wg_shared_format_endpoint() {
    local host port
    host=$(wg_shared_endpoint_host "${1:-}")
    port="${2:-}"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s\n' "$host" "$port"
    else
        printf '%s:%s\n' "$host" "$port"
    fi
}

wg_is_installed() { command_exists wg && [[ -f "$WG_DB_FILE" ]]; }
wg_is_running()   { ip link show "$WG_INTERFACE" &>/dev/null; }

wg_get_server_name() {
    local name
    name=$(wg_db_get '.server.name // empty')
    if [[ -z "$name" || "$name" == "null" ]]; then
        name=$(hostname -s 2>/dev/null)
        [[ -z "$name" ]] && name="server"
    fi
    echo "$name"
}

wg_rename_server() {
    print_title "修改服务器名称"
    local current_name=$(wg_get_server_name)
    echo -e "  当前名称: ${C_CYAN}${current_name}${C_RESET}"
    local new_name=""
    read -e -r -p "新名称 [${current_name}]: " new_name
    new_name=${new_name:-$current_name}
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "名称只能包含字母、数字、下划线、连字符"
        pause; return
    fi
    wg_db_set --arg n "$new_name" '.server.name = $n'
    print_success "服务器名称已更新为: ${new_name}"
    log_action "WireGuard server renamed: ${current_name} -> ${new_name}"
    pause
}

wg_check_installed() {
    if ! wg_is_installed; then
        print_error "WireGuard 未安装，请先执行安装。"
        pause; return 1
    fi
    return 0
}

wg_check_server() {
    wg_check_installed || return 1
    if [[ "$(wg_get_role)" != "server" ]]; then
        print_error "当前不是服务端模式，此功能仅服务端可用。"
        pause; return 1
    fi
    return 0
}

wg_select_peer() {
    local prompt="${1:-选择设备序号}" show_status="${2:-false}"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"; pause; return 1
    fi
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip mark=""
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        if [[ "$show_status" == "true" ]]; then
            local enabled
            enabled=$(wg_db_get ".peers[$i].enabled")
            [[ "$enabled" == "true" ]] && mark=" ${C_GREEN}(已启用)${C_RESET}" || mark=" ${C_RED}(已禁用)${C_RESET}"
        fi
        local is_gw
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        [[ "$is_gw" == "true" ]] && mark+=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回
"
    local idx
    read -e -r -p "${prompt}: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return 1
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return 1
    fi
    REPLY=$((idx - 1))
    return 0
}


wg_install_packages() {
    print_info "安装 WireGuard 软件包..."
    opkg update >/dev/null 2>&1
    local essential_pkgs=(wireguard-tools kmod-wireguard luci-proto-wireguard jq)
    local optional_pkgs=(qrencode)
    for pkg in "${essential_pkgs[@]}"; do
        install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
    done
    for pkg in "${optional_pkgs[@]}"; do
        install_package "$pkg" "silent" || print_warn "安装 $pkg 失败（不影响核心功能）"
    done
    # 重启 rpcd 使 LuCI 识别 wireguard 协议
    /etc/init.d/rpcd restart 2>/dev/null || true
    print_success "软件包安装完成"
    return 0
}

wg_next_ip() {
    local subnet prefix
    subnet=$(wg_db_get '.server.subnet')
    prefix=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    # 一次性获取所有已用 IP，避免 N+1 次 jq 调用
    local used_ips
    used_ips=$(wg_db_get '[.server.ip] + [.peers[].ip] | join(" ")')
    local next
    for next in $(seq 2 254); do
        local candidate="${prefix}.${next}"
        printf '%s\n' $used_ips | grep -Fxq -- "$candidate" || { echo "$candidate"; return 0; }
    done
    print_error "子网 IP 已耗尽"; return 1
}

wg_format_bytes() {
    local bytes=$1
    [[ -z "$bytes" || "$bytes" == "0" ]] && { echo "0 B"; return; }
    awk -v b="$bytes" 'BEGIN {
        if (b>=1073741824) printf "%.2f GB",b/1073741824
        else if (b>=1048576) printf "%.2f MB",b/1048576
        else if (b>=1024) printf "%.2f KB",b/1024
        else printf "%d B",b
    }'
}

_wg_openwrt_restore_network_uci_snapshot() {
    local snapshot="${1:-}"
    [[ -s "$snapshot" ]] || return 0
    uci revert network >/dev/null 2>&1 || true
    if ! uci import network < "$snapshot" >/dev/null 2>&1; then
        print_warn "恢复 OpenWrt network UCI 配置失败，请手动检查。"
        return 1
    fi
    if ! uci commit network >/dev/null 2>&1; then
        print_warn "提交恢复后的 OpenWrt network UCI 配置失败，请手动检查。"
        return 1
    fi
}

_wg_openwrt_write_network_uci_from_db() {
    local priv_key="${1:-}" port="${2:-}" server_ip="${3:-}" mask="${4:-}" mtu="${5:-}"
    local pc i

    while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
        uci delete network.@wireguard_wg0[0] || return 1
    done

    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key="$priv_key" || return 1
    uci -q delete network.wg0.addresses 2>/dev/null || true
    uci add_list network.wg0.addresses="${server_ip}/${mask}" || return 1
    uci set network.wg0.listen_port="$port" || return 1
    uci set network.wg0.mtu="$mtu" || return 1
    uci set network.wg0.route_allowed_ips='1' || return 1

    pc=$(wg_db_get '.peers | length') || return 1
    i=0
    while [[ $i -lt $pc ]]; do
        if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
            local peer_name pub_key psk peer_ip is_gw lan_sub sub IFS_BAK
            peer_name=$(wg_db_get ".peers[$i].name") || return 1
            pub_key=$(wg_db_get ".peers[$i].public_key") || return 1
            psk=$(wg_db_get ".peers[$i].preshared_key") || return 1
            peer_ip=$(wg_db_get ".peers[$i].ip") || return 1
            is_gw=$(wg_db_get ".peers[$i].is_gateway // false") || return 1
            lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty") || return 1

            uci add network wireguard_wg0 >/dev/null || return 1
            uci set network.@wireguard_wg0[-1].description="$peer_name" || return 1
            uci set network.@wireguard_wg0[-1].public_key="$pub_key" || return 1
            uci set network.@wireguard_wg0[-1].preshared_key="$psk" || return 1
            uci set network.@wireguard_wg0[-1].persistent_keepalive='25' || return 1

            uci -q delete network.@wireguard_wg0[-1].allowed_ips 2>/dev/null || true
            uci add_list network.@wireguard_wg0[-1].allowed_ips="${peer_ip}/32" || return 1
            if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                IFS_BAK="$IFS"; IFS=','
                for sub in $lan_sub; do
                    sub=$(echo "$sub" | xargs)
                    if [[ -n "$sub" ]]; then
                        uci add_list network.@wireguard_wg0[-1].allowed_ips="$sub" || {
                            IFS="$IFS_BAK"
                            return 1
                        }
                    fi
                done
                IFS="$IFS_BAK"
            fi
        fi
        i=$((i + 1))
    done

    uci commit network || return 1
}


wg_rebuild_uci_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local apply_mode="${1:-reload}"
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT

    local uci_snapshot_dir uci_snapshot
    uci_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-uci.XXXXXX") || {
        print_error "创建 OpenWrt network UCI 快照目录失败"
        return 1
    }
    chmod 700 "$uci_snapshot_dir" 2>/dev/null || true
    uci_snapshot="${uci_snapshot_dir}/network.uci"
    if ! uci export network > "$uci_snapshot" 2>/dev/null; then
        rm -rf "$uci_snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi

    _wg_openwrt_write_network_uci_from_db "$priv_key" "$port" "$server_ip" "$mask" "$mtu"
    local uci_rc=$?
    if [[ $uci_rc -ne 0 ]]; then
        print_error "OpenWrt network UCI 配置提交失败"
        _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
        rm -rf "$uci_snapshot_dir" 2>/dev/null || true
        return 1
    fi

    # --- 非 peer 热应用路径仍允许重启接口；peer 操作传 no_reload 后用 wg syncconf 热同步 ---
    if wg_is_running && [[ "$apply_mode" != "no_reload" ]]; then
        ifdown wg0 2>/dev/null || true
        sleep 1
        if ! ifup wg0 2>/dev/null; then
            print_error "OpenWrt wg0 接口重载失败"
            _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
            rm -rf "$uci_snapshot_dir" 2>/dev/null || true
            return 1
        fi
        sleep 1
        if ! wg_sync_peer_routes; then
            print_error "OpenWrt WireGuard 路由同步失败"
            _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
            rm -rf "$uci_snapshot_dir" 2>/dev/null || true
            return 1
        fi
    fi
    rm -rf "$uci_snapshot_dir" 2>/dev/null || true
    return 0
}

wg_apply_runtime_conf() {
    wg_rebuild_conf || return 1
    wg_is_running || return 0
    local tmp_dir tmp
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-sync.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    tmp="${tmp_dir}/sync.conf"
    awk '
        /^\[Interface\]$/ { section="interface"; print; next }
        /^\[Peer\]$/ { section="peer"; print; next }
        section=="interface" && /^(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
        section=="peer" && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
    ' "$WG_CONF" > "$tmp" || { rm -rf "$tmp_dir"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true
    if wg syncconf "$WG_INTERFACE" "$tmp" >/dev/null 2>&1; then
        rm -rf "$tmp_dir"
        wg_sync_peer_routes || return 1
        return 0
    fi
    rm -rf "$tmp_dir"
    return 1
}

# 同步网关 peer 的 LAN 路由到内核路由表
# (部分 OpenWrt 固件的 proto-wireguard 不支持 route_allowed_ips，需手动添加)
wg_sync_peer_routes() {
    wg_is_running || return 0
    wg_shared_sync_gateway_routes wg_db_get "$WG_INTERFACE"
}

# 生成 wg0.conf 只读快照（供导出/备份/查看用，不用于运行）
wg_rebuild_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        log_action "wg_rebuild_conf failed: missing fields" "ERROR"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    local conf_content
    conf_content=$(
    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "MTU = ${mtu}"
        local pc=$(wg_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo ""
                echo "[Peer]"
                echo "PublicKey = $(wg_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_db_get ".peers[$i].ip")
                local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
            fi
            i=$((i + 1))
        done
    }
)
    wg_write_private_file "$WG_CONF" "$conf_content"
}

wg_regenerate_client_confs() {
    local pc=$(wg_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport endpoint sdns mask mtu
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    endpoint=$(wg_shared_format_endpoint "$sep" "$sport")
    sdns=$(wg_db_get '.server.dns')
    mask=$(echo "$(wg_db_get '.server.subnet')" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    mkdir -p /etc/wireguard/clients
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_db_get ".peers[$i].name")
        local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local conf_content="[Interface]
PrivateKey = $(wg_db_get ".peers[$i].private_key")
Address = $(wg_db_get ".peers[$i].ip")/${mask}
MTU = ${mtu}"
        [[ "$is_gw" != "true" ]] && conf_content+=$'\n'"DNS = ${sdns}"
        conf_content+="
[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_db_get ".peers[$i].preshared_key")
Endpoint = ${endpoint}
AllowedIPs = $(wg_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        wg_write_private_file "/etc/wireguard/clients/${name}.conf" "$conf_content" || return 1
        i=$((i + 1))
    done
}
_wg_openwrt_rc_local_path() {
    printf '%s' "${WG_OPENWRT_RC_LOCAL_FILE:-/etc/rc.local}"
}

_wg_openwrt_delete_allow_port_rules() {
    local h
    for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
}

_wg_openwrt_delete_allow_port_rules_matching() {
    local want="${1:-}" mode="${2:-match}" h
    validate_port "$want" || return 1
    for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | awk -v want="$want" -v mode="$mode" '
        /wg_allow_port/ {
            dport = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "dport") dport = $(i + 1)
            }
            if ((mode == "match" && dport == want) || (mode == "except" && dport != want)) print $NF
        }
    '); do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
}

_wg_openwrt_list_wireguard_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\/none/ && current != "" {
            print current
            current=""
        }
    '
}

_wg_openwrt_allow_port_handles() {
    local want="${1:-}"
    validate_port "$want" || return 1
    nft -a list chain inet fw4 input_wan 2>/dev/null | awk -v want="$want" '
        /wg_allow_port/ {
            dport = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "dport") dport = $(i + 1)
            }
            if (dport == want) print $NF
        }
    '
}

_wg_openwrt_persist_allow_port() {
    local port="${1:-}"
    validate_port "$port" || { print_error "WireGuard UDP 端口无效: $port"; return 1; }
    local snapshot_dir snapshot
    snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-fw.XXXXXX") || {
        print_error "创建 OpenWrt firewall UCI 快照目录失败"
        return 1
    }
    chmod 700 "$snapshot_dir" 2>/dev/null || true
    snapshot="${snapshot_dir}/firewall.uci"
    if ! uci export firewall > "$snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    if ! _wg_openwrt_write_allow_port_uci "$port"; then
        print_error "OpenWrt 防火墙持久化放行 ${port}/udp 失败"
        _wg_openwrt_restore_uci_package firewall "$snapshot" || true
        rm -rf "$snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$snapshot_dir" 2>/dev/null || true
}

_wg_openwrt_write_allow_port_uci() {
    local port="${1:-}"
    validate_port "$port" || return 1
    uci set firewall.wg_allow_port=rule || return 1
    uci set firewall.wg_allow_port.name='Allow-WG-UDP' || return 1
    uci set firewall.wg_allow_port.src='wan' || return 1
    uci set firewall.wg_allow_port.dest_port="$port" || return 1
    uci set firewall.wg_allow_port.proto='udp' || return 1
    uci set firewall.wg_allow_port.target='ACCEPT' || return 1
    uci commit firewall || return 1
}

_wg_openwrt_write_allow_port_rc_local() {
    local port="${1:-}" rc_block rc_file
    validate_port "$port" || return 1
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_rc_local_cleanup_managed_entries allow-port "$rc_file" || return 1
    rc_block="# BEGIN server-manage wireguard allow-port\nnft insert rule inet fw4 input_wan udp dport ${port} counter accept comment \\\"wg_allow_port\\\" 2>/dev/null || true # wg_allow_port\n# END server-manage wireguard allow-port"
    _wg_rc_local_insert_block "$rc_block" "$rc_file"
}

_wg_openwrt_apply_allow_port() {
    local port="${1:-}" before_handles after_handles h
    validate_port "$port" || { print_error "WireGuard UDP 端口无效: $port"; return 1; }
    if ! nft list chain inet fw4 input_wan >/dev/null 2>&1; then
        print_error "OpenWrt fw4 input_wan 链不存在，无法实时放行 ${port}/udp"
        return 1
    fi
    before_handles=$(_wg_openwrt_allow_port_handles "$port" 2>/dev/null || true)
    if ! nft insert rule inet fw4 input_wan udp dport "$port" counter accept comment "wg_allow_port" 2>/dev/null; then
        print_error "OpenWrt nft 实时放行 ${port}/udp 失败"
        return 1
    fi
    if ! _wg_openwrt_persist_allow_port "$port"; then
        after_handles=$(_wg_openwrt_allow_port_handles "$port" 2>/dev/null || true)
        for h in $after_handles; do
            printf '%s\n' "$before_handles" | grep -Fxq -- "$h" || nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
        done
        return 1
    fi
    for h in $before_handles; do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
    _wg_openwrt_delete_allow_port_rules_matching "$port" except
    _wg_openwrt_write_allow_port_rc_local "$port" || print_warn "写入 /etc/rc.local 端口放行规则失败"
    return 0
}

_wg_openwrt_rollback_server_modify() {
    local old_port="${1:-}" old_dns="${2:-}" old_ep="${3:-}" old_lan="${4:-}" port_firewall_changed="${5:-false}"
    validate_port "$old_port" || return 1
    if [[ "$port_firewall_changed" == "true" ]]; then
        _wg_openwrt_apply_allow_port "$old_port" >/dev/null 2>&1 || print_warn "回滚 OpenWrt 防火墙端口到 ${old_port}/udp 失败，请手动检查"
    fi
    if ! wg_db_set --argjson p "$old_port" \
                  --arg d "$old_dns" \
                  --arg e "$old_ep" \
                  --arg l "${old_lan:-}" \
                  '.server.port = $p | .server.dns = $d | .server.endpoint = $e | .server.server_lan_subnet = $l' >/dev/null 2>&1; then
        print_warn "回滚 WireGuard 服务端数据库失败，请手动检查"
        return 1
    fi
    _wg_update_peer_routes >/dev/null 2>&1 || true
    wg_rebuild_uci_conf >/dev/null 2>&1 || true
    wg_rebuild_conf >/dev/null 2>&1 || true
    wg_regenerate_client_confs >/dev/null 2>&1 || true
}

wg_update_server_endpoint_metadata() {
    wg_check_server || return 1
    local new_ep="${1:-}" new_ddns="${2:-}" old_ep old_ddns snapshot
    local clients_dir="/etc/wireguard/clients" clients_snapshot_dir="" clients_existed=false
    if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
        print_error "公网端点无效，仅支持 IP 或域名"
        return 1
    fi
    if [[ -n "$new_ddns" ]]; then
        if ! new_ddns=$(wg_shared_normalize_endpoint_host "$new_ddns"); then
            print_error "DDNS 域名无效"
            return 1
        fi
    fi

    old_ep=$(wg_db_get '.server.endpoint // empty')
    old_ddns=$(wg_db_get '.server.ddns_domain // empty')
    snapshot=$(cat "$WG_DB_FILE" 2>/dev/null) || {
        print_error "读取 WireGuard 数据库失败"
        return 1
    }
    clients_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-clients.XXXXXX") || {
        print_error "创建客户端配置快照目录失败"
        return 1
    }
    chmod 700 "$clients_snapshot_dir" 2>/dev/null || true
    if [[ -d "$clients_dir" ]]; then
        clients_existed=true
        cp -p "$clients_dir"/* "$clients_snapshot_dir"/ 2>/dev/null || true
    fi

    if ! wg_db_set --arg e "$new_ep" \
                  --arg d "${new_ddns:-}" \
                  '.server.endpoint = $e | .server.ddns_domain = $d'; then
        print_error "WireGuard 数据库写入失败"
        rm -rf "$clients_snapshot_dir" 2>/dev/null || true
        return 1
    fi

    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚 endpoint 元数据"
        wg_write_private_file "$WG_DB_FILE" "$snapshot" >/dev/null 2>&1 || print_warn "回滚 WireGuard 数据库失败，请手动检查"
        rm -rf "$clients_dir" 2>/dev/null || true
        if [[ "$clients_existed" == "true" ]]; then
            mkdir -p "$clients_dir" 2>/dev/null || true
            cp -p "$clients_snapshot_dir"/* "$clients_dir"/ 2>/dev/null || true
        fi
        rm -rf "$clients_snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$clients_snapshot_dir" 2>/dev/null || true

    log_action "WireGuard server endpoint metadata updated: ${old_ep:-none} -> ${new_ep} ddns=${new_ddns:-none}"
    [[ "${old_ep:-}" != "$new_ep" ]] && print_success "服务端 endpoint 元数据已更新: ${old_ep:-无} -> ${new_ep}"
    [[ "${old_ddns:-}" != "${new_ddns:-}" ]] && print_info "DDNS 元数据: ${old_ddns:-无} -> ${new_ddns:-无}"
    print_info "已重生成 /etc/wireguard/clients/*.conf，未重载服务端 wg0/UCI。"
    return 0
}

wg_modify_server_endpoint_only() {
    wg_check_server || return 1
    print_title "仅修改 WireGuard 服务端公网端点"
    local cur_ep cur_ddns new_ep
    cur_ep=$(wg_db_get '.server.endpoint')
    cur_ddns=$(wg_db_get '.server.ddns_domain // empty')
    echo -e "  当前端点: ${C_GREEN}${cur_ep}${C_RESET}"
    [[ -n "$cur_ddns" && "$cur_ddns" != "null" ]] && echo -e "  当前 DDNS: ${C_CYAN}${cur_ddns}${C_RESET}"
    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" == "$cur_ep" ]]; then
        print_info "未做任何更改"
        pause; return 0
    fi
    local endpoint_ddns=""
    validate_ip "$new_ep" || endpoint_ddns="$new_ep"
    wg_update_server_endpoint_metadata "$new_ep" "$endpoint_ddns"
    local rc=$?
    pause
    return "$rc"
}

_wg_openwrt_configure_server_uci() {
    local server_privkey="${1:-}" server_ip="${2:-}" wg_mask="${3:-}" wg_port="${4:-}" mtu="${5:-}"
    local snapshot_dir network_snapshot firewall_snapshot
    snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-server-uci.XXXXXX") || {
        print_error "创建 OpenWrt UCI 配置快照目录失败"
        return 1
    }
    chmod 700 "$snapshot_dir" 2>/dev/null || true
    network_snapshot="${snapshot_dir}/network.uci"
    firewall_snapshot="${snapshot_dir}/firewall.uci"
    if ! uci export network > "$network_snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi
    if ! uci export firewall > "$firewall_snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    if ! _wg_openwrt_write_server_uci "$server_privkey" "$server_ip" "$wg_mask" "$wg_port" "$mtu"; then
        print_error "OpenWrt 网络/防火墙 UCI 配置提交失败"
        _wg_openwrt_restore_uci_package network "$network_snapshot" || true
        _wg_openwrt_restore_uci_package firewall "$firewall_snapshot" || true
        rm -rf "$snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$snapshot_dir" 2>/dev/null || true
}

_wg_openwrt_write_server_uci() {
    local server_privkey="${1:-}" server_ip="${2:-}" wg_mask="${3:-}" wg_port="${4:-}" mtu="${5:-}"
    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key="$server_privkey" || return 1
    uci -q delete network.wg0.addresses 2>/dev/null || true
    uci add_list network.wg0.addresses="${server_ip}/${wg_mask}" || return 1
    uci set network.wg0.listen_port="$wg_port" || return 1
    uci set network.wg0.mtu="$mtu" || return 1
    uci set network.wg0.route_allowed_ips='1' || return 1

    uci set firewall.wg_zone=zone || return 1
    uci set firewall.wg_zone.name='wg' || return 1
    uci set firewall.wg_zone.input='ACCEPT' || return 1
    uci set firewall.wg_zone.output='ACCEPT' || return 1
    uci set firewall.wg_zone.forward='ACCEPT' || return 1
    uci set firewall.wg_zone.masq='1' || return 1
    uci -q delete firewall.wg_zone.network 2>/dev/null || true
    uci add_list firewall.wg_zone.network='wg0' || return 1
    uci set firewall.wg_fwd_lan=forwarding || return 1
    uci set firewall.wg_fwd_lan.src='lan' || return 1
    uci set firewall.wg_fwd_lan.dest='wg' || return 1
    uci set firewall.wg_fwd_wg=forwarding || return 1
    uci set firewall.wg_fwd_wg.src='wg' || return 1
    uci set firewall.wg_fwd_wg.dest='lan' || return 1

    uci commit network || return 1
    uci commit firewall || return 1
}

_wg_openwrt_snapshot_file() {
    local src="${1:-}" dst="${2:-}" marker="${3:-}"
    [[ -n "$src" && -n "$dst" && -n "$marker" ]] || return 1
    [[ -e "$src" ]] || return 0
    mkdir -p "$(dirname "$dst")" || return 1
    cp -p "$src" "$dst" || return 1
    : > "$marker"
}

_wg_openwrt_restore_snapshot_file() {
    local dst="${1:-}" snap="${2:-}" marker="${3:-}"
    [[ -n "$dst" && -n "$snap" && -n "$marker" ]] || return 0
    if [[ -f "$marker" ]]; then
        mkdir -p "$(dirname "$dst")" 2>/dev/null || true
        cp -p "$snap" "$dst" 2>/dev/null || print_warn "恢复 $dst 失败，请手动检查。"
    else
        rm -f "$dst" 2>/dev/null || print_warn "删除新建文件 $dst 失败，请手动检查。"
    fi
}

_wg_openwrt_snapshot_server_install() {
    local snapshot_dir="${1:-}" rc_file sysctl_conf
    [[ -n "$snapshot_dir" ]] || return 1
    mkdir -p "$snapshot_dir" || return 1
    if ! uci export network > "${snapshot_dir}/network.uci" 2>/dev/null; then
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi
    if ! uci export firewall > "${snapshot_dir}/firewall.uci" 2>/dev/null; then
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_openwrt_snapshot_file "$WG_DB_FILE" "${snapshot_dir}/db" "${snapshot_dir}/db.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_ROLE_FILE" "${snapshot_dir}/role" "${snapshot_dir}/role.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_CONF" "${snapshot_dir}/conf" "${snapshot_dir}/conf.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_SHARED_ROUTE_STATE_FILE" "${snapshot_dir}/routes" "${snapshot_dir}/routes.exists" || return 1
    _wg_openwrt_snapshot_file "$rc_file" "${snapshot_dir}/rc.local" "${snapshot_dir}/rc.local.exists" || return 1
    sysctl_conf="$(_sysctl_conf_path)"
    _wg_openwrt_snapshot_file "$sysctl_conf" "${snapshot_dir}/sysctl.conf" "${snapshot_dir}/sysctl.exists" || return 1
    sysctl -n net.ipv4.ip_forward > "${snapshot_dir}/ip_forward.runtime" 2>/dev/null || true
}

_wg_openwrt_restore_uci_package() {
    local pkg="${1:-}" snapshot="${2:-}"
    [[ -n "$pkg" && -s "$snapshot" ]] || return 0
    uci revert "$pkg" >/dev/null 2>&1 || true
    if ! uci import "$pkg" < "$snapshot" >/dev/null 2>&1; then
        print_warn "恢复 OpenWrt ${pkg} UCI 配置失败，请手动检查。"
        return 1
    fi
    if ! uci commit "$pkg" >/dev/null 2>&1; then
        print_warn "提交恢复后的 OpenWrt ${pkg} UCI 配置失败，请手动检查。"
        return 1
    fi
}

_wg_openwrt_rollback_server_install() {
    local snapshot_dir="${1:-}" rollback_forward="${2:-false}" rc_file sysctl_conf ip_forward_runtime
    [[ -n "$snapshot_dir" ]] || return 0
    ifdown wg0 2>/dev/null || true
    wg_mihomo_bypass_clean >/dev/null 2>&1 || true
    _wg_openwrt_delete_allow_port_rules >/dev/null 2>&1 || true
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_rc_local_cleanup_managed_entries all "$rc_file" >/dev/null 2>&1 || true

    _wg_openwrt_restore_uci_package network "${snapshot_dir}/network.uci" || true
    _wg_openwrt_restore_uci_package firewall "${snapshot_dir}/firewall.uci" || true
    /etc/init.d/network reload >/dev/null 2>&1 || true
    /etc/init.d/firewall reload >/dev/null 2>&1 || true

    _wg_openwrt_restore_snapshot_file "$WG_DB_FILE" "${snapshot_dir}/db" "${snapshot_dir}/db.exists"
    _wg_openwrt_restore_snapshot_file "$WG_ROLE_FILE" "${snapshot_dir}/role" "${snapshot_dir}/role.exists"
    _wg_openwrt_restore_snapshot_file "$WG_CONF" "${snapshot_dir}/conf" "${snapshot_dir}/conf.exists"
    _wg_openwrt_restore_snapshot_file "$WG_SHARED_ROUTE_STATE_FILE" "${snapshot_dir}/routes" "${snapshot_dir}/routes.exists"
    _wg_openwrt_restore_snapshot_file "$rc_file" "${snapshot_dir}/rc.local" "${snapshot_dir}/rc.local.exists"
    if [[ "$rollback_forward" == "true" ]]; then
        sysctl_conf="$(_sysctl_conf_path)"
        _wg_openwrt_restore_snapshot_file "$sysctl_conf" "${snapshot_dir}/sysctl.conf" "${snapshot_dir}/sysctl.exists"
        ip_forward_runtime=$(cat "${snapshot_dir}/ip_forward.runtime" 2>/dev/null || true)
        if [[ "$ip_forward_runtime" =~ ^[01]$ ]]; then
            sysctl -w "net.ipv4.ip_forward=${ip_forward_runtime}" >/dev/null 2>&1 || true
        elif [[ -f "$sysctl_conf" ]]; then
            sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
        fi
    fi
    rmdir "$(dirname "$WG_CONF")" 2>/dev/null || true
}

wg_server_install() {
    print_title "安装 WireGuard 服务端"
    if wg_is_installed && [[ "$(wg_get_role)" == "server" ]]; then
        print_warn "WireGuard 服务端已安装。"
        wg_is_running && echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}" || echo -e "  状态: ${C_RED}● 已停止${C_RESET}"
        pause; return 0
    fi
    if wg_is_installed && [[ "$(wg_get_role)" == "client" ]]; then
        print_error "当前已安装为客户端模式。如需切换为服务端，请先卸载。"
        pause; return 1
    fi

    # ── [1/7] OpenWrt 环境检测 ──
    print_info "[1/7] OpenWrt 环境检测..."
    wg_check_openwrt_compat || { pause; return 1; }

    # ── [2/7] 安装软件包 ──
    print_info "[2/7] 安装软件包..."
    wg_install_packages || { pause; return 1; }

    local wg_install_snapshot_dir=""
    local wg_forward_changed=false
    wg_install_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-openwrt-install.XXXXXX") || {
        print_error "创建 OpenWrt 安装回滚快照目录失败"
        pause; return 1
    }
    if ! _wg_openwrt_snapshot_server_install "$wg_install_snapshot_dir"; then
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [3/7] 配置 IP 转发 ──
    print_info "[3/7] 配置 IP 转发..."
    if ! _sysctl_enable_wireguard_forward; then
        print_error "IP 转发配置失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    wg_forward_changed=true
    print_success "IP 转发已开启"

    # ── [4/7] 配置服务端参数 ──
    print_info "[4/7] 配置服务端参数..."

    local wg_port listen_addr mtu wg_dns wg_endpoint=""
    local wg_subnet="10.66.66.0/24"
    listen_addr="0.0.0.0"
    mtu=$WG_MTU_DIRECT

    # WG 监听端口
    while true; do
        read -e -r -p "WireGuard 监听端口 [${WG_DEFAULT_PORT}]: " wg_port
        wg_port=${wg_port:-$WG_DEFAULT_PORT}
        if validate_port "$wg_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    # VPN 子网
    while true; do
        read -e -r -p "VPN 内网子网 [10.66.66.0/24]: " wg_subnet
        wg_subnet=${wg_subnet:-10.66.66.0/24}
        if [[ "$wg_subnet" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$ ]]; then
            local o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]} mask=${BASH_REMATCH[5]}
            if [[ $o1 -le 255 && $o2 -le 255 && $o3 -le 255 && $o4 -le 255 && "$mask" == "24" ]]; then
                break
            fi
        fi
        print_warn "子网格式无效，仅支持 /24 子网，示例: 10.66.66.0/24"
    done
    local prefix server_ip
    prefix=$(echo "$wg_subnet" | cut -d'.' -f1-3)
    server_ip="${prefix}.1"

    # 客户端 DNS
    read -e -r -p "客户端 DNS [223.5.5.5, 114.114.114.114]: " wg_dns
    wg_dns=${wg_dns:-"223.5.5.5, 114.114.114.114"}

    # 服务端 LAN 子网 (自动检测 br-lan)
    local server_lan_subnet=""
    local br_lan_addr
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | awk '/^[[:space:]]*inet[[:space:]]/ { print $2; exit }')
    if [[ -n "$br_lan_addr" ]]; then
        # 从 br-lan 地址推算网段 (如 10.10.100.1/24 → 10.10.100.0/24)
        local lan_ip lan_mask lan_prefix
        lan_ip=$(echo "$br_lan_addr" | cut -d'/' -f1)
        lan_mask=$(echo "$br_lan_addr" | cut -d'/' -f2)
        lan_prefix=$(echo "$lan_ip" | cut -d'.' -f1-3)
        local default_lan="${lan_prefix}.0/${lan_mask}"
        echo -e "  检测到 br-lan 网段: ${C_CYAN}${default_lan}${C_RESET}"
        read -e -r -p "服务端 LAN 子网 (映射到 WG 网络) [${default_lan}]: " server_lan_subnet
        server_lan_subnet=${server_lan_subnet:-$default_lan}
    else
        echo -e "  ${C_YELLOW}未检测到 br-lan 接口${C_RESET}"
        read -e -r -p "服务端 LAN 子网 (留空跳过): " server_lan_subnet
    fi

    # Endpoint: 优先使用 DDNS 域名
    local ddns_domain=""
    if [[ -d "$DDNS_CONFIG_DIR" ]] && ls "$DDNS_CONFIG_DIR"/*.conf &>/dev/null 2>&1; then
        echo ""
        echo -e "${C_CYAN}检测到已配置的 DDNS 域名:${C_RESET}"
        local idx=1 ddns_domains=()
        for conf in "$DDNS_CONFIG_DIR"/*.conf; do
            [[ -f "$conf" ]] || continue
            local d=$(grep '^DDNS_DOMAIN=' "$conf" | cut -d'"' -f2)
            [[ -n "$d" ]] && { ddns_domains+=("$d"); echo "  ${idx}. ${d}"; idx=$((idx+1)); }
        done
        if [[ ${#ddns_domains[@]} -gt 0 ]]; then
            echo "  0. 不使用 DDNS，手动输入 IP/域名"
            local ddns_choice
            read -e -r -p "选择 DDNS 域名 [1]: " ddns_choice
            ddns_choice=${ddns_choice:-1}
            if [[ "$ddns_choice" != "0" && "$ddns_choice" =~ ^[0-9]+$ && "$ddns_choice" -ge 1 && "$ddns_choice" -le ${#ddns_domains[@]} ]]; then
                ddns_domain="${ddns_domains[$((ddns_choice-1))]}"
                wg_endpoint="$ddns_domain"
                print_success "Endpoint 将使用 DDNS 域名: ${ddns_domain}"
            fi
        fi
    fi
    if [[ -z "$wg_endpoint" ]]; then
        local default_ip
        default_ip=$(get_public_ipv4 2>/dev/null || echo "")
        if [[ -n "$default_ip" ]]; then
            read -e -r -p "公网端点 IP/域名 [${default_ip}]: " wg_endpoint
            wg_endpoint=${wg_endpoint:-$default_ip}
        else
            while [[ -z "$wg_endpoint" ]]; do
                read -e -r -p "公网端点 IP/域名: " wg_endpoint
            done
        fi
    fi
    if ! wg_endpoint=$(wg_shared_normalize_endpoint_host "$wg_endpoint"); then
        print_error "公网端点无效，仅支持 IP 或域名"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [5/7] 生成密钥 ──
    print_info "[5/7] 生成服务端密钥..."
    local server_privkey server_pubkey
    server_privkey=$(wg genkey)
    server_pubkey=$(echo "$server_privkey" | wg pubkey)
    if [[ -z "$server_privkey" || -z "$server_pubkey" ]]; then
        print_error "WireGuard 服务端密钥生成失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    print_success "密钥已生成"

    # 服务器名称
    local server_name=""
    local default_name=$(hostname -s 2>/dev/null)
    [[ -z "$default_name" ]] && default_name="server"
    read -e -r -p "服务器名称 [${default_name}]: " server_name
    server_name=${server_name:-$default_name}

    # ── [6/7] 写入数据库 + 配置 OpenWrt 网络和防火墙 ──
    print_info "[6/7] 写入配置..."
    # 配置 uci 网络接口
    print_info "配置 OpenWrt 网络接口..."
    local wg_mask
    wg_mask=$(echo "$wg_subnet" | cut -d'/' -f2)
    if ! _wg_openwrt_configure_server_uci "$server_privkey" "$server_ip" "$wg_mask" "$wg_port" "$mtu"; then
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    print_info "配置 OpenWrt 防火墙端口..."
    if ! _wg_openwrt_apply_allow_port "$wg_port"; then
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    if ! wg_db_init; then
        print_error "WireGuard 数据库初始化失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_db_set --arg sname "$server_name" \
                   --arg pk "$server_privkey" \
                   --arg pub "$server_pubkey" \
                   --arg ip "$server_ip" \
                   --arg sub "$wg_subnet" \
                   --arg port "$wg_port" \
                   --arg dns "$wg_dns" \
                   --arg ep "$wg_endpoint" \
                   --arg laddr "$listen_addr" \
                   --argjson mtu "$mtu" \
                   --arg ddns "${ddns_domain:-}" \
                   --arg lan "${server_lan_subnet:-}" \
    '.server = {
        name: $sname,
        private_key: $pk,
        public_key: $pub,
        ip: $ip,
        subnet: $sub,
        port: ($port | tonumber),
        dns: $dns,
        endpoint: $ep,
        listen_address: $laddr,
        mtu: $mtu,
        ddns_domain: $ddns,
        server_lan_subnet: $lan
    } | .schema_version = 2'; then
        print_error "WireGuard 数据库写入失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_set_role "server"; then
        print_error "WireGuard 角色写入失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # 生成只读快照 wg0.conf
    if ! wg_rebuild_conf; then
        print_error "生成 WireGuard 配置快照失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [7/7] Mihomo bypass + 启动 ──
    print_info "[7/7] 配置 Mihomo bypass 并启动..."
    if ! wg_setup_mihomo_bypass "$wg_subnet"; then
        print_error "Mihomo bypass 配置失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! ifup wg0 2>/dev/null; then
        print_error "启动 wg0 失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    sleep 2
    wg_sync_peer_routes

    # ── 安装结果展示 ──
    draw_line
    if ! wg_is_running; then
        print_error "wg0 未运行，请检查 logread | grep netifd"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
    print_success "WireGuard 服务端安装并启动成功！"
    echo -e "  角色:       ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听地址:   ${C_GREEN}${listen_addr}:${wg_port}/udp${C_RESET}"
    echo -e "  MTU:        ${C_GREEN}${mtu}${C_RESET}"
    echo -e "  内网子网:   ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP:  ${C_GREEN}${server_ip}${C_RESET}"
    [[ -n "$server_lan_subnet" ]] && echo -e "  服务端 LAN: ${C_GREEN}${server_lan_subnet}${C_RESET}"
    if [[ -n "${ddns_domain:-}" ]]; then
        echo -e "  公网端点:   ${C_GREEN}${ddns_domain}:${wg_port}${C_RESET} (DDNS)"
    else
        echo -e "  公网端点:   ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    fi
    draw_line

    log_action "WireGuard server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint mtu=$mtu lan=${server_lan_subnet:-none}"

    # 自动安装服务端看门狗
    echo ""
    wg_setup_watchdog "true"

    pause
}

wg_modify_server() {
    wg_check_server || return 1
    print_title "修改 WireGuard 服务端配置"
    local cur_port cur_dns cur_ep cur_lan
    cur_port=$(wg_db_get '.server.port')
    cur_dns=$(wg_db_get '.server.dns')
    cur_ep=$(wg_db_get '.server.endpoint')
    cur_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
    [[ -n "$cur_lan" && "$cur_lan" != "null" ]] && echo -e "  当前 LAN:   ${C_GREEN}${cur_lan}${C_RESET}"
    local changed=false lan_changed=false port_changed=false dns_changed=false endpoint_changed=false port_firewall_changed=false

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            changed=true
            port_changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
            new_port="$cur_port"
        fi
    fi

    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        changed=true
        dns_changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
            print_warn "端点无效，保持原值"
            new_ep="$cur_ep"
        else
            changed=true
            endpoint_changed=true
            print_info "端点将更改为 ${new_ep}"
        fi
    fi

    read -e -r -p "新服务端 LAN 子网 [${cur_lan:-无}]: " new_lan
    new_lan=${new_lan:-$cur_lan}
    if [[ "$new_lan" != "$cur_lan" ]]; then
        if ! validate_cidr_list "$new_lan"; then
            print_warn "LAN 子网格式无效，保持原值"
            new_lan="$cur_lan"
        else
            changed=true
            lan_changed=true
            print_info "LAN 子网将更改为 ${new_lan}"
        fi
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return 0
    fi

    if [[ "$endpoint_changed" == "true" && "$port_changed" != "true" && "$dns_changed" != "true" && "$lan_changed" != "true" ]]; then
        local endpoint_ddns=""
        validate_ip "$new_ep" || endpoint_ddns="$new_ep"
        if wg_update_server_endpoint_metadata "$new_ep" "$endpoint_ddns"; then
            pause; return 0
        fi
        pause; return 1
    fi

    if [[ "$port_changed" == "true" ]]; then
        if ! _wg_openwrt_apply_allow_port "$new_port"; then
            print_error "新 WireGuard UDP 端口未放行，已取消修改"
            pause; return 1
        fi
        port_firewall_changed=true
    fi

    if ! wg_db_set --argjson p "$new_port" \
                  --arg d "$new_dns" \
                  --arg e "$new_ep" \
                  --arg l "${new_lan:-}" \
                  '.server.port = $p | .server.dns = $d | .server.endpoint = $e | .server.server_lan_subnet = $l'; then
        print_error "WireGuard 数据库写入失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi

    if [[ "$lan_changed" == "true" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "更新 peer 路由失败，正在回滚"
            _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
            pause; return 1
        fi
    fi

    if ! wg_rebuild_uci_conf; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi
    if ! wg_rebuild_conf; then
        print_error "生成 WireGuard 配置快照失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi

    # LAN 子网或端口变更都需要重建 bypass (因为 bypass 包含所有子网)
    if [[ "$new_port" != "$cur_port" || "${new_lan:-}" != "${cur_lan:-}" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
            pause; return 1
        fi
    fi

    print_success "服务端配置已更新"
    log_action "WireGuard server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep} lan=${new_lan:-none}"
    pause
}

wg_server_status() {
    wg_check_server || return 1
    print_title "WireGuard 服务端状态"
    local port subnet endpoint dns mtu server_lan
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    endpoint=$(wg_db_get '.server.endpoint')
    dns=$(wg_db_get '.server.dns')
    mtu=$(wg_db_get '.server.mtu // empty')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    if wg_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi
    echo -e "  端口:     ${port}/udp"
    [[ -n "$mtu" && "$mtu" != "null" ]] && echo -e "  MTU:      ${mtu}"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    [[ -n "$server_lan" && "$server_lan" != "null" ]] && echo -e "  服务端 LAN: ${C_CYAN}${server_lan}${C_RESET}"
    local ddns_domain=$(wg_db_get '.server.ddns_domain // empty')
    [[ -n "$ddns_domain" && "$ddns_domain" != "null" ]] && echo -e "  DDNS:     ${C_CYAN}${ddns_domain}${C_RESET}"

    # Mihomo bypass 状态
    echo ""
    local bypass_ok=true
    if nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass'; then
        echo -e "  Mihomo bypass: ${C_GREEN}已启用${C_RESET}"
    else
        echo -e "  Mihomo bypass: ${C_YELLOW}未检测到规则${C_RESET}"
        bypass_ok=false
    fi

    echo ""
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line
    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "类型" "状态" "最近握手" "流量"
        draw_line
        local wg_dump=""
        wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip pubkey enabled peer_type
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            pubkey=$(wg_db_get ".peers[$i].public_key")
            enabled=$(wg_db_get ".peers[$i].enabled")
            peer_type=$(wg_db_get ".peers[$i].peer_type // \"standard\"")
            local type_str
            case "$peer_type" in
                gateway) type_str="${C_YELLOW}网关${C_RESET}" ;;
                clash)   type_str="${C_CYAN}Clash${C_RESET}" ;;
                *)       type_str="标准" ;;
            esac
            local status_str handshake_str transfer_str
            if [[ "$enabled" != "true" ]]; then
                status_str="${C_RED}禁用${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            elif [[ -n "$wg_dump" ]]; then
                local peer_line
                peer_line=$(echo "$wg_dump" | grep "^${pubkey}" || true)
                if [[ -n "$peer_line" ]]; then
                    local last_hs rx tx
                    last_hs=$(echo "$peer_line" | awk '{print $5}')
                    rx=$(echo "$peer_line" | awk '{print $6}')
                    tx=$(echo "$peer_line" | awk '{print $7}')
                    if [[ "$last_hs" -gt 0 ]] 2>/dev/null; then
                        local now hs_ago
                        now=$(date +%s)
                        hs_ago=$((now - last_hs))
                        if [[ $hs_ago -lt 180 ]]; then
                            status_str="${C_GREEN}在线${C_RESET}"
                        else
                            status_str="${C_YELLOW}离线${C_RESET}"
                        fi
                        if [[ $hs_ago -lt 60 ]]; then
                            handshake_str="${hs_ago}秒前"
                        elif [[ $hs_ago -lt 3600 ]]; then
                            handshake_str="$((hs_ago / 60))分钟前"
                        elif [[ $hs_ago -lt 86400 ]]; then
                            handshake_str="$((hs_ago / 3600))小时前"
                        else
                            handshake_str="$((hs_ago / 86400))天前"
                        fi
                    else
                        status_str="${C_YELLOW}离线${C_RESET}"
                        handshake_str="从未"
                    fi
                    transfer_str="↓$(wg_format_bytes "$rx") ↑$(wg_format_bytes "$tx")"
                else
                    status_str="${C_YELLOW}离线${C_RESET}"
                    handshake_str="-"
                    transfer_str="-"
                fi
            else
                status_str="${C_GRAY}未知${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            fi
            printf "%-4s %-16s %-18s %-8b %-8b %-20s %-16s\n" \
                "$((i + 1))" "$name" "$ip" "$type_str" "$status_str" "$handshake_str" "$transfer_str"
            i=$((i + 1))
        done
    else
        print_info "暂无设备"
    fi
    draw_line
    pause
}

wg_start() {
    if wg_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi
    print_info "正在启动 WireGuard..."
    ifup wg0 2>/dev/null
    sleep 2
    if wg_is_running; then
        # 启动后确保 bypass 规则存在
        wg_mihomo_bypass_rebuild 2>/dev/null
        wg_sync_peer_routes
        print_success "WireGuard 已启动"
        log_action "WireGuard started"
        return 0
    else
        print_error "启动失败，请检查 logread | grep netifd"
        log_action "WireGuard start failed"
        return 1
    fi
}

wg_stop() {
    if ! wg_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi
    print_info "正在停止 WireGuard..."
    ifdown wg0 2>/dev/null
    sleep 1
    if ! wg_is_running; then
        print_success "WireGuard 已停止"
        log_action "WireGuard stopped"
        return 0
    else
        print_error "停止失败"
        log_action "WireGuard stop failed"
        return 1
    fi
}

wg_restart() {
    print_info "正在重启 WireGuard..."
    wg_is_running && ifdown wg0 2>/dev/null
    sleep 1
    ifup wg0 2>/dev/null
    sleep 2
    if wg_is_running; then
        wg_mihomo_bypass_rebuild 2>/dev/null
        wg_sync_peer_routes
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
        return 0
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
        return 1
    fi
}

# ── Mihomo bypass 函数 ──

_wg_rc_local_cleanup_managed_entries() {
    local kind="${1:-all}" rc_file="${2:-/etc/rc.local}" tmp_out rc_dir
    case "$kind" in all|bypass|allow-port) ;; *) return 1 ;; esac
    [[ -f "$rc_file" ]] || return 0
    rc_dir="$(dirname "$rc_file")"
    tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-clean.XXXXXX") || return 1
    if awk -v kind="$kind" '
        function marker_matches(line) {
            if (kind == "all") return 1
            return index(line, " " kind) > 0
        }
        /^# BEGIN server-manage wireguard / {
            if (marker_matches($0)) { skip=1; next }
        }
        /^# END server-manage wireguard / {
            if (skip) { skip=0; next }
        }
        skip { next }
        kind != "allow-port" && /^# WireGuard bypass Mihomo/ { next }
        kind != "allow-port" && /# wg_bypass[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_peer_route[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_ep_resolve[[:space:]]*$/ { next }
        kind != "bypass" && /# wg_allow_port[[:space:]]*$/ { next }
        kind != "bypass" && /nft insert rule inet fw4 input_wan udp dport .*comment .*wg_allow_port/ { next }
        { print }
    ' "$rc_file" > "$tmp_out"; then
        chmod +x "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_out"; return 1; }
        chmod +x "$rc_file" 2>/dev/null || true
        rm -f "$tmp_out"
        return 0
    fi
    rm -f "$tmp_out"
    return 1
}

_wg_rc_local_insert_block() {
    local rc_block="${1:-}" rc_file="${2:-/etc/rc.local}"
    [[ -n "$rc_block" ]] || return 1
    local tmp_block tmp_out rc_dir
    rc_dir="$(dirname "$rc_file")"
    tmp_block=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-block.XXXXXX") || return 1
    tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-local.XXXXXX") || { rm -f "$tmp_block"; return 1; }
    if [[ ! -f "$rc_file" ]]; then
        printf '#!/bin/sh\nexit 0\n' > "$tmp_out" 2>/dev/null || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        chmod 755 "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-local.XXXXXX") || { rm -f "$tmp_block"; return 1; }
    fi
    printf '%b\n' "$rc_block" > "$tmp_block"
    if awk '
        FNR == NR { block = block $0 ORS; next }
        /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?$/ && !inserted { printf "%s", block; inserted=1 }
        { print }
        END { if (!inserted) printf "%s", block }
    ' "$tmp_block" "$rc_file" > "$tmp_out"; then
        chmod +x "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        chmod +x "$rc_file" 2>/dev/null || true
        rm -f "$tmp_block" "$tmp_out"
        return 0
    fi
    rm -f "$tmp_block" "$tmp_out"
    return 1
}

wg_setup_mihomo_bypass() {
    local wg_subnet="${1:-$(wg_db_get '.server.subnet')}"
    [[ -z "$wg_subnet" || "$wg_subnet" == "null" ]] && return 1

    # 检查 mangle_prerouting 链是否存在 (Mihomo 未运行时可能没有)
    if ! nft list chain inet fw4 mangle_prerouting &>/dev/null; then
        print_warn "fw4 mangle_prerouting 链不存在 (Mihomo 可能未运行)，跳过 bypass 配置"
        return 0
    fi

    # 先清理旧规则
    wg_mihomo_bypass_clean 2>/dev/null

    # ── 收集所有需要 bypass 的子网 ──
    local -a bypass_subnets=("$wg_subnet")
    # 服务端 LAN
    local server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    [[ -n "$server_lan" && "$server_lan" != "null" ]] && bypass_subnets+=("$server_lan")
    # 所有网关 peer 的 LAN 子网
    local pc=$(wg_db_get '.peers | length' 2>/dev/null) pi=0
    while [[ $pi -lt ${pc:-0} ]]; do
        local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" && "$pls" != "null" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $pls; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && bypass_subnets+=("$cidr")
            done
            IFS="$IFS_BAK"
        fi
        pi=$((pi + 1))
    done
    # 去重
    local -a unique_subnets
    mapfile -t unique_subnets < <(printf '%s\n' "${bypass_subnets[@]}" | sort -u)

    # wg0 接口流量跳过 Mihomo tproxy
    nft insert rule inet fw4 mangle_prerouting iifname \"wg0\" counter return comment \"wg_bypass_iface\" 2>/dev/null || true
    # 所有 VPN 相关子网跳过 Mihomo
    local cidr nft_family
    for cidr in "${unique_subnets[@]}"; do
        nft_family=$(nft_addr_family_for_cidr "$cidr")
        nft insert rule inet fw4 mangle_prerouting "$nft_family" daddr "$cidr" counter return comment \"wg_bypass_subnet\" 2>/dev/null || true
    done

    # 持久化到 /etc/rc.local
    _wg_rc_local_cleanup_managed_entries bypass || print_warn "清理 /etc/rc.local 旧 bypass 规则失败"
    local rc_block="# BEGIN server-manage wireguard bypass\n# WireGuard bypass Mihomo\nnft insert rule inet fw4 mangle_prerouting iifname \\\"wg0\\\" counter return comment \\\"wg_bypass_iface\\\" 2>/dev/null || true # wg_bypass"
    for cidr in "${unique_subnets[@]}"; do
        nft_family=$(nft_addr_family_for_cidr "$cidr")
        rc_block="${rc_block}\nnft insert rule inet fw4 mangle_prerouting ${nft_family} daddr \\\"${cidr}\\\" counter return comment \\\"wg_bypass_subnet\\\" 2>/dev/null || true"
    done
    # 网关 peer LAN 路由持久化 (proto-wireguard 不一定自动创建)
    local pc=$(wg_db_get '.peers | length' 2>/dev/null) pi=0
    while [[ $pi -lt ${pc:-0} ]]; do
        if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" && "$(wg_db_get ".peers[$pi].is_gateway // false")" == "true" ]]; then
            local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
            if [[ -n "$pls" && "$pls" != "null" ]]; then
                local IFS_BAK="$IFS"; IFS=','
                for sub in $pls; do
                    sub=$(echo "$sub" | xargs)
                    [[ -n "$sub" ]] && rc_block="${rc_block}\nip route replace ${sub} dev wg0 2>/dev/null || true # wg_peer_route"
                done
                IFS="$IFS_BAK"
            fi
        fi
        pi=$((pi + 1))
    done
    rc_block="${rc_block}\n# END server-manage wireguard bypass"
    _wg_rc_local_insert_block "$rc_block" || print_warn "写入 /etc/rc.local 持久化规则失败"

    print_success "Mihomo bypass 规则已配置 (${#unique_subnets[@]} 个子网)"
}

wg_mihomo_bypass_status() {
    print_title "Mihomo bypass 规则状态"
    local ok=true
    echo ""

    # 检查 nft 规则
    if nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        echo -e "  ${C_GREEN}[OK]${C_RESET} mangle_prerouting: wg_bypass_iface (wg0 接口跳过)"
    else
        echo -e "  ${C_RED}[缺失]${C_RESET} mangle_prerouting: wg_bypass_iface"
        ok=false
    fi

    if nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_subnet'; then
        echo -e "  ${C_GREEN}[OK]${C_RESET} mangle_prerouting: wg_bypass_subnet (WG 子网跳过)"
    else
        echo -e "  ${C_RED}[缺失]${C_RESET} mangle_prerouting: wg_bypass_subnet"
        ok=false
    fi

    if nft list chain inet fw4 input_wan 2>/dev/null | grep -q 'wg_allow_port'; then
        echo -e "  ${C_GREEN}[OK]${C_RESET} input_wan: wg_allow_port (WG UDP 端口放行)"
    else
        echo -e "  ${C_YELLOW}[缺失]${C_RESET} input_wan: wg_allow_port"
        ok=false
    fi

    # 检查 /etc/rc.local 持久化
    echo ""
    if grep -q 'wg_bypass' /etc/rc.local 2>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET} /etc/rc.local: bypass 持久化规则存在"
    else
        echo -e "  ${C_RED}[缺失]${C_RESET} /etc/rc.local: 无 bypass 持久化规则"
        ok=false
    fi

    echo ""
    if [[ "$ok" == "true" ]]; then
        print_success "所有 bypass 规则正常"
    else
        print_warn "部分规则缺失，可选择重建"
        if confirm "是否立即重建 bypass 规则?"; then
            wg_mihomo_bypass_rebuild
        fi
    fi
    pause
}

wg_mihomo_bypass_clean() {
    # 清理 nft 中所有 wg_bypass 相关规则
    local h
    for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print $NF}'); do
        nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null || true
    done
    # 清理 /etc/rc.local 中的持久化条目
    _wg_rc_local_cleanup_managed_entries bypass || true
}

wg_mihomo_bypass_rebuild() {
    local wg_subnet wg_port
    wg_subnet=$(wg_db_get '.server.subnet')
    wg_port=$(wg_db_get '.server.port')
    [[ -z "$wg_subnet" || "$wg_subnet" == "null" ]] && return 1

    wg_setup_mihomo_bypass "$wg_subnet" || return 1

    # 重建端口放行规则
    if [[ -n "$wg_port" && "$wg_port" != "null" ]]; then
        _wg_openwrt_apply_allow_port "$wg_port" || return 1
    fi
    return 0
}

# ── 卸载 ──

wg_uninstall() {
    print_title "卸载 WireGuard"
    if ! wg_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return 0
    fi
    local role
    role=$(wg_get_role)
    echo -e "  当前角色: ${C_GREEN}${role:-未知}${C_RESET}"
    print_warn "此操作将完全卸载 WireGuard，包括所有配置和密钥！"
    if ! confirm "确认卸载 WireGuard?"; then
        return
    fi
    if ! confirm "再次确认: 所有配置将被永久删除，是否继续?"; then
        return
    fi

    print_info "[1/6] 停止并删除所有 WireGuard 接口..."
    ifdown wg0 2>/dev/null || true
    ifdown wg_mesh 2>/dev/null || true
    local _wg_ifaces
    _wg_ifaces=$(_wg_openwrt_list_wireguard_ifaces | tr '\n' ' ')
    for _must in "$WG_INTERFACE" wg_mesh wg-mesh; do
        if ip link show "$_must" &>/dev/null && ! echo "$_wg_ifaces" | grep -qw "$_must"; then
            _wg_ifaces="${_wg_ifaces:+$_wg_ifaces $_must}"
            [[ -z "$_wg_ifaces" ]] && _wg_ifaces="$_must"
        fi
    done
    for _iface in $_wg_ifaces; do
        print_info "  清理接口: $_iface"
        ip link set "$_iface" down 2>/dev/null || true
        ip link delete "$_iface" 2>/dev/null || true
    done

    print_info "[2/6] 清理 OpenWrt 网络和防火墙配置..."
    # 删除所有 wireguard peer 配置段
    while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
        uci delete network.@wireguard_wg0[0] 2>/dev/null || true
    done
    while uci -q get network.@wireguard_wg_mesh[0] >/dev/null 2>&1; do
        uci delete network.@wireguard_wg_mesh[0] 2>/dev/null || true
    done
    uci delete network.wg_server 2>/dev/null || true
    uci delete network.wg0 2>/dev/null || true
    uci delete network.wg_mesh 2>/dev/null || true
    # 删除防火墙配置
    uci delete firewall.wg_zone 2>/dev/null || true
    uci delete firewall.wg_fwd_lan 2>/dev/null || true
    uci delete firewall.wg_fwd_wg 2>/dev/null || true
    uci delete firewall.wg_allow_port 2>/dev/null || true
    uci delete firewall.wg_mesh_zone 2>/dev/null || true
    uci delete firewall.wg_mesh_fwd 2>/dev/null || true
    uci delete firewall.wg_mesh_fwd_lan 2>/dev/null || true
    local _fwi=0
    while uci get firewall.@zone[$_fwi] &>/dev/null 2>&1; do
        local _fname=$(uci get firewall.@zone[$_fwi].name 2>/dev/null)
        if [[ "$_fname" == "wg" || "$_fname" == "wireguard" || "$_fname" == "wg_mesh" ]]; then
            uci delete "firewall.@zone[$_fwi]" 2>/dev/null || true
            continue
        fi
        _fwi=$((_fwi + 1))
    done
    if ! uci commit network; then
        print_error "提交 OpenWrt network 清理失败，已中止卸载。请修复 UCI 后重试，避免本地状态先被删除。"
        pause; return 1
    fi
    if ! uci commit firewall; then
        print_error "提交 OpenWrt firewall 清理失败，已中止卸载。请修复 UCI 后重试，避免本地状态先被删除。"
        pause; return 1
    fi

    print_info "[3/6] 清理 Mihomo bypass 和 nft 规则..."
    wg_mihomo_bypass_clean
    # 旧版 prio 100 策略路由没有可验证标记，不能粗暴删除第三方规则。

    print_info "[4/6] 清理看门狗和定时任务..."
    cron_remove_job_command "/usr/bin/wg-watchdog.sh" 2>/dev/null || true
    cron_remove_job_command "/usr/local/bin/wg-watchdog.sh" 2>/dev/null || true
    rm -f /usr/bin/wg-watchdog.sh /usr/local/bin/wg-watchdog.sh \
          /var/log/wg-watchdog.log /var/run/server-manage/wg-watchdog.log \
          /var/run/server-manage/.wg-watchdog-log.* \
          /tmp/wg-watchdog.log /tmp/wg-watchdog.log.tmp 2>/dev/null || true

    print_info "[5/6] 删除配置文件..."
    rm -f "$WG_CONF" 2>/dev/null || true
    rm -rf /etc/wireguard/clients 2>/dev/null || true
    rm -f "$WG_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DB_DIR" 2>/dev/null || true
    rm -f "$WG_ROLE_FILE" 2>/dev/null || true
    rmdir /etc/wireguard 2>/dev/null || true
    rm -rf /tmp/.wg-wd-fail /tmp/.wg-watchdog-ping-fail \
           /tmp/.wg-db-tmp.json /tmp/clash-wg-*.yaml \
           /tmp/.wg-watchdog-stale 2>/dev/null || true

    print_info "[6/6] 卸载软件包..."
    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        opkg remove wireguard-tools luci-proto-wireguard kmod-wireguard 2>/dev/null || true
    fi

    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            _sysctl_disable_wireguard_forward || print_warn "恢复 IP 转发设置失败，请手动检查 /etc/sysctl.conf"
        fi
    fi

    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line
    log_action "WireGuard uninstalled: role=${role}"
    pause
}

wg_openwrt_clean_cmd() {
    print_title "OpenWrt 清空 WireGuard 配置"
    echo -e "${C_YELLOW}复制以下命令到 OpenWrt SSH 终端执行:${C_RESET}"
    draw_line
    cat << 'CLEANEOF'
# === 停止所有 WireGuard 接口 ===
die() { echo "[!] $*" >&2; exit 1; }
list_wg_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\/none/ && current != "" {
            print current
            current=""
        }
    '
}
ifdown wg0 2>/dev/null; true
ifdown wg_mesh 2>/dev/null; true
for iface in $(list_wg_ifaces); do
    ip link set "$iface" down 2>/dev/null; true
    ip link delete "$iface" 2>/dev/null; true
    echo "[+] 已删除接口: $iface"
done
for iface in wg0 wg_mesh wg-mesh; do
    if ip link show "$iface" >/dev/null 2>&1; then
        ip link set "$iface" down 2>/dev/null; true
        ip link delete "$iface" 2>/dev/null; true
        echo "[+] 已删除接口: $iface"
    fi
done

# === 清理看门狗 ===
rm -f /usr/bin/wg-watchdog.sh 2>/dev/null; true
(crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"') | crontab - 2>/dev/null; true
/etc/init.d/cron restart 2>/dev/null; true
echo '[+] 看门狗已清理'

# === 删除所有 wireguard peer 配置段 ===
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done
while uci -q get network.@wireguard_wg_mesh[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg_mesh[0]
done
uci delete network.wg_server 2>/dev/null; true
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_mesh 2>/dev/null; true

# === 删除防火墙配置 ===
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci delete firewall.wg_allow_port 2>/dev/null; true
uci delete firewall.wg_mesh_zone 2>/dev/null; true
uci delete firewall.wg_mesh_fwd 2>/dev/null; true
uci delete firewall.wg_mesh_fwd_lan 2>/dev/null; true
i=0
while uci get firewall.@zone[$i] >/dev/null 2>&1; do
    zname=$(uci get firewall.@zone[$i].name 2>/dev/null)
    case "$zname" in
        wg|wireguard|wg_mesh)
            uci delete "firewall.@zone[$i]" 2>/dev/null; true
            echo "[+] 已删除匿名防火墙 zone: $zname"
            continue
            ;;
    esac
    i=$((i + 1))
done
i=0
while uci get firewall.@forwarding[$i] >/dev/null 2>&1; do
    fsrc=$(uci get firewall.@forwarding[$i].src 2>/dev/null)
    fdest=$(uci get firewall.@forwarding[$i].dest 2>/dev/null)
    case "$fsrc" in wg|wg_mesh) ;; *) case "$fdest" in wg|wg_mesh) ;; *) i=$((i+1)); continue ;; esac ;; esac
    uci delete "firewall.@forwarding[$i]" 2>/dev/null; true
    echo "[+] 已删除匿名防火墙 forwarding: $fsrc -> $fdest"
done

# === 清理 Mihomo bypass 和 nft 规则 ===
# 旧版 prio 100 策略路由没有可验证标记，不能粗暴删除第三方规则。
for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print $NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
done
for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
    nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null; true
done
if [ -f /etc/rc.local ]; then
    WG_RC_TMP="$(mktemp /etc/.rc.local.clean.XXXXXX 2>/dev/null)" || { echo '[!] 创建 rc.local 清理临时文件失败' >&2; exit 1; }
    if awk '
        /^# BEGIN server-manage wireguard / { skip=1; next }
        /^# END server-manage wireguard / { skip=0; next }
        skip { next }
        /^# WireGuard bypass Mihomo/ { next }
        /# wg_bypass[[:space:]]*$/ { next }
        /# wg_peer_route[[:space:]]*$/ { next }
        /# wg_ep_resolve[[:space:]]*$/ { next }
        /# wg_allow_port[[:space:]]*$/ { next }
        /nft insert rule inet fw4 input_wan udp dport .*comment .*wg_allow_port/ { next }
        { print }
    ' /etc/rc.local > "$WG_RC_TMP"; then
        chmod +x "$WG_RC_TMP" 2>/dev/null && mv "$WG_RC_TMP" /etc/rc.local || { rm -f "$WG_RC_TMP"; die "安装清理后的 /etc/rc.local 失败"; }
    else
        rm -f "$WG_RC_TMP"
        die "生成清理后的 /etc/rc.local 失败"
    fi
    rm -f "$WG_RC_TMP"
fi

# === 提交配置 ===
uci commit network || die "提交 network 清理失败"
uci commit firewall || die "提交 firewall 清理失败"

# === 最终验证 ===
echo ''
if ip link show wg0 >/dev/null 2>&1; then
    echo '[!] 警告: wg0 接口仍存在，请手动执行: ip link delete wg0'
else
    echo '[OK] WireGuard 配置已完全清空'
fi
CLEANEOF
    draw_line
    echo -e "${C_CYAN}执行后可在 LuCI -> Network -> Interfaces 确认 wg0 已消失${C_RESET}"
    pause
}
_wg_openwrt_snapshot_db() {
    [[ -f "$WG_DB_FILE" ]] || return 1
    cat "$WG_DB_FILE"
}

_wg_openwrt_restore_peer_snapshot() {
    local snapshot="${1:-}" cleanup_file="${2:-}" rebuild_bypass="${3:-false}"
    [[ -n "$snapshot" ]] || return 1
    wg_write_private_file "$WG_DB_FILE" "$snapshot" || return 1
    wg_rebuild_uci_conf "no_reload" >/dev/null 2>&1 || true
    wg_apply_runtime_conf >/dev/null 2>&1 || true
    wg_regenerate_client_confs >/dev/null 2>&1 || true
    if [[ -n "$cleanup_file" ]]; then
        rm -f -- "$cleanup_file" 2>/dev/null || true
    fi
    if [[ "$rebuild_bypass" == "true" ]]; then
        wg_mihomo_bypass_rebuild >/dev/null 2>&1 || true
    fi
}

wg_add_peer() {
    wg_check_server || return 1
    print_title "添加 WireGuard 设备 (Peer)"
    local peer_name
    while true; do
        read -e -r -p "设备名称 (如 phone, laptop): " peer_name
        [[ -z "$peer_name" ]] && { print_warn "名称不能为空"; continue; }
        local exists
        exists=$(wg_db_get --arg n "$peer_name" '.peers[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "设备名 '$peer_name' 已存在"; continue; }
        [[ ! "$peer_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母、数字、下划线、连字符"; continue; }
        break
    done
    local peer_ip
    peer_ip=$(wg_next_ip) || { pause; return 1; }
    echo -e "  分配 IP: ${C_GREEN}${peer_ip}${C_RESET}"
    local peer_privkey peer_pubkey psk
    peer_privkey=$(wg genkey) || { print_error "生成 peer 私钥失败"; pause; return 1; }
    peer_pubkey=$(printf '%s\n' "$peer_privkey" | wg pubkey) || { print_error "生成 peer 公钥失败"; pause; return 1; }
    psk=$(wg genpsk) || { print_error "生成预共享密钥失败"; pause; return 1; }

    # ── 设备类型选择 (三种) ──
    local peer_type="standard"
    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:"
    echo -e "  1. ${C_CYAN}Clash 客户端${C_RESET} (手机/电脑，通过 FlClash/FClash 规则接入)"
    echo -e "  2. ${C_YELLOW}网关设备${C_RESET} (OpenWrt 路由器，暴露自身 LAN 子网)"
    echo -e "  3. 标准 WireGuard 客户端 (原生 .conf 配置)"
    read -e -r -p "选择 [1]: " device_type
    device_type=${device_type:-1}

    case "$device_type" in
        1)
            peer_type="clash"
            is_gateway="false"
            ;;
        2)
            peer_type="gateway"
            is_gateway="true"
            echo ""
            print_guide "请输入该网关后面的 LAN 网段 (将被路由到 VPN 中)"
            print_guide "示例: 192.168.123.0/24"
            print_guide "多个网段用逗号分隔: 192.168.1.0/24, 192.168.2.0/24"
            while [[ -z "$lan_subnets" ]]; do
                read -e -r -p "LAN 网段: " lan_subnets
                if [[ -z "$lan_subnets" ]]; then
                    print_warn "网关设备必须指定 LAN 网段"
                elif ! validate_cidr_list "$lan_subnets"; then
                    print_warn "格式无效，示例: 192.168.123.0/24"
                    lan_subnets=""
                fi
            done
            ;;
        3)
            peer_type="standard"
            is_gateway="false"
            ;;
        *)
            peer_type="clash"
            is_gateway="false"
            ;;
    esac

    # ── 路由模式 ──
    local client_allowed_ips server_subnet server_lan route_mode="managed"
    server_subnet=$(wg_db_get '.server.subnet')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')

    # 收集所有网关 LAN 网段 (含当前新设备)
    local all_lan_subnets=""
    local pc=$(wg_db_get '.peers | length') pi=0
    local target_idx="$pc"
    while [[ $pi -lt $pc ]]; do
        local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" && "$pls" != "null" ]]; then
            [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
            all_lan_subnets="${all_lan_subnets}${pls}"
        fi
        pi=$((pi + 1))
    done
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
        all_lan_subnets="${all_lan_subnets}${lan_subnets}"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        # Clash 客户端: 路由 VPN 子网 + 服务端 LAN + 所有网关 LAN
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
        echo -e "  Clash 路由模式: ${C_CYAN}VPN 子网 + 所有 LAN 子网${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    elif [[ "$peer_type" == "gateway" ]]; then
        # 网关设备: VPN 子网 + 服务端 LAN + 其他网关 LAN (排除自己的 LAN)
        local other_lans=""
        local IFS_BAK="$IFS"; IFS=','
        for cidr in $all_lan_subnets; do
            cidr=$(echo "$cidr" | xargs)
            [[ -z "$cidr" ]] && continue
            local dominated=false
            local IFS2_BAK="$IFS"; IFS=','
            for own in $lan_subnets; do
                own=$(echo "$own" | xargs)
                [[ "$cidr" == "$own" ]] && { dominated=true; break; }
            done
            IFS="$IFS2_BAK"
            [[ "$dominated" != "true" ]] && { [[ -n "$other_lans" ]] && other_lans="${other_lans}, "; other_lans="${other_lans}${cidr}"; }
        done
        IFS="$IFS_BAK"
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$other_lans" ]] && client_allowed_ips="${client_allowed_ips}, ${other_lans}"
        echo -e "  网关路由模式: ${C_YELLOW}VPN 子网 + 服务端 LAN + 其他网关 LAN${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    else
        # 标准客户端: 交互选择
        echo ""
        echo "客户端路由模式:"
        echo "  1. 全局代理 (所有流量走 VPN) - 0.0.0.0/0"
        echo "  2. 仅 VPN 内网 (只访问 VPN 内部设备)"
        echo "  3. VPN 内网 + 所有 LAN 网段 (访问远程内网设备)"
        echo "  4. 自定义路由"
        read -e -r -p "选择 [1]: " route_mode
        route_mode=${route_mode:-1}
        case $route_mode in
            1) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
            2) client_allowed_ips="$server_subnet"; route_mode="vpn" ;;
            3)
                route_mode="managed"
                client_allowed_ips="$server_subnet"
                [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
                [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
                ;;
            4)
                read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
                [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
                if validate_wg_allowed_ips "$client_allowed_ips"; then
                    route_mode="custom"
                else
                    print_warn "自定义路由格式无效，回退为仅 VPN 内网"
                    client_allowed_ips="$server_subnet"
                    route_mode="vpn"
                fi
                ;;
            *) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
        esac
    fi

    local conf_file="/etc/wireguard/clients/${peer_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }

    # ── 写入数据库 ──
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    if ! wg_db_set --arg name "$peer_name" \
                   --arg ip "$peer_ip" \
                   --arg privkey "$peer_privkey" \
                   --arg pubkey "$peer_pubkey" \
                   --arg psk "$psk" \
                   --arg allowed "$client_allowed_ips" \
                   --arg created "$now" \
                   --arg gw "$is_gateway" \
                   --arg lans "$lan_subnets" \
                   --arg ptype "$peer_type" \
                   --arg route_mode "$route_mode" \
    '.peers += [{
        name: $name,
        ip: $ip,
        private_key: $privkey,
        public_key: $pubkey,
        preshared_key: $psk,
        client_allowed_ips: $allowed,
        enabled: true,
        created: $created,
        is_gateway: ($gw == "true"),
        lan_subnets: $lans,
        peer_type: $ptype,
        route_mode: $route_mode
    }]'; then
        print_error "数据库写入失败，设备未添加"
        pause; return 1
    fi

    # ── 网关设备: 联动更新其他 peer 的 allowed_ips ──
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" true
            pause; return 1
        fi
    fi

    # ── 重建配置并应用 ──
    if ! wg_rebuild_uci_conf "no_reload"; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi
    if ! wg_apply_runtime_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi

    # 网关 peer 添加/删除会改变 LAN 子网列表，需重建 Mihomo bypass
    if [[ "$is_gateway" == "true" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" true
            pause; return 1
        fi
    fi

    # ── 结果展示 ──
    draw_line
    print_success "设备 '${peer_name}' 添加成功！"
    draw_line
    echo -e "  名称: ${C_GREEN}${peer_name}${C_RESET}"
    echo -e "  IP:   ${C_GREEN}${peer_ip}${C_RESET}"
    case "$peer_type" in
        clash)   echo -e "  类型: ${C_CYAN}Clash 客户端${C_RESET}" ;;
        gateway) echo -e "  类型: ${C_YELLOW}网关设备${C_RESET}"; echo -e "  LAN:  ${C_CYAN}${lan_subnets}${C_RESET}" ;;
        *)       echo -e "  类型: 标准客户端" ;;
    esac
    echo -e "  路由: ${C_CYAN}${client_allowed_ips}${C_RESET}"
    echo -e "  配置: ${C_CYAN}${conf_file}${C_RESET}"
    draw_line

    # ── 后续操作提示 ──
    if [[ "$peer_type" == "clash" ]]; then
        echo ""
        read -e -r -p "是否立即生成 Clash/Mihomo 客户端配置? [Y/n]: " _gen_clash
        _gen_clash=${_gen_clash:-Y}
        [[ "$_gen_clash" =~ ^[Yy]$ ]] && wg_generate_clash_config
    elif [[ "$peer_type" == "gateway" ]]; then
        echo -e "\n${C_YELLOW}[网关设备部署提示]${C_RESET}"
        echo "  • LAN 内设备无需安装任何 VPN 客户端，网关自动代理"
        echo "  • 确保 VPN 子网 (${server_subnet}) 与 LAN 子网 (${lan_subnets}) 不冲突"
        echo ""
        read -e -r -p "是否立即显示 OpenWrt 部署命令? [Y/n]: " _show_cmd
        _show_cmd=${_show_cmd:-Y}
        [[ "$_show_cmd" =~ ^[Yy]$ ]] && _wg_show_openwrt_deploy "$target_idx"
    fi

    log_action "WireGuard peer added: ${peer_name} (${peer_ip}) type=${peer_type} gateway=${is_gateway} lan=${lan_subnets}"
    pause
}

# 内部函数: 联动更新所有 peer 的 allowed_ips (当网关 LAN 变动时)
_wg_update_peer_routes() {
    local server_subnet=$(wg_db_get '.server.subnet')
    local server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    local _pc=$(wg_db_get '.peers | length')

    # 收集所有网关的 LAN 网段
    local _all_lans="" _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
        [[ -n "$_pls" && "$_pls" != "null" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
        _pi=$((_pi + 1))
    done

    _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _cur=$(wg_db_get ".peers[$_pi].client_allowed_ips")
        # 跳过全局代理和仅 VPN 内网的
        [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
        [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

        local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_db_get ".peers[$_pi].peer_type // \"standard\"")
        local _route_mode=$(wg_db_get ".peers[$_pi].route_mode // empty")
        [[ "$_route_mode" == "custom" ]] && { _pi=$((_pi + 1)); continue; }

        if [[ "$_is_gw" == "true" ]]; then
            # 网关: VPN 子网 + 服务端 LAN + 其他网关 LAN (排除自己)
            local _other="" _IFS_BAK="$IFS"; IFS=','
            for _c in $_all_lans; do
                _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                local _skip=false _IFS2="$IFS"; IFS=','
                for _o in $_own; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                IFS="$_IFS2"
                [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
            done; IFS="$_IFS_BAK"
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_other" ]] && _new="${_new}, ${_other}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        elif [[ "$_ptype" == "clash" ]]; then
            # Clash: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        else
            # 标准: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        fi
        _pi=$((_pi + 1))
    done
    return 0
}

wg_toggle_peer() {
    wg_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name current_state
    target_name=$(wg_db_get ".peers[$target_idx].name")
    current_state=$(wg_db_get ".peers[$target_idx].enabled")
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            if ! wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_rebuild_uci_conf "no_reload"; then
                print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            if ! wg_apply_runtime_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            if ! wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_rebuild_uci_conf "no_reload"; then
                print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            if ! wg_apply_runtime_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            print_success "设备 '${target_name}' 已启用"
            log_action "WireGuard peer enabled: ${target_name}"
        fi
    fi
    pause
}

wg_delete_peer() {
    wg_check_server || return 1
    print_title "删除 WireGuard 设备"
    wg_select_peer "选择要删除的设备序号" true || return
    local target_idx=$REPLY
    local target_name
    target_name=$(wg_db_get ".peers[$target_idx].name")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    local _del_gw=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_db_get ".peers[$target_idx].lan_subnets // empty")
    local conf_file="/etc/wireguard/clients/${target_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if ! wg_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'; then
        print_error "数据库写入失败，设备未删除"
        pause; return 1
    fi

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" true
            pause; return 1
        fi
    fi

    if ! wg_rebuild_uci_conf "no_reload"; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi
    if ! wg_apply_runtime_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi
    rm -f -- "$conf_file" 2>/dev/null || print_warn "删除客户端配置文件失败: $conf_file"
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi

    # 网关 peer 删除后 LAN 子网列表变化，需重建 Mihomo bypass
    if [[ "$_del_gw" == "true" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" true
            pause; return 1
        fi
    fi

    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard peer deleted: ${target_name}"
    pause
}

wg_show_peer_conf() {
    wg_check_server || return 1
    print_title "查看设备配置"
    wg_select_peer "选择设备序号" true || return
    local target_idx=$REPLY
    local target_name peer_type
    target_name=$(wg_db_get ".peers[$target_idx].name")
    peer_type=$(wg_db_get ".peers[$target_idx].peer_type // \"standard\"")
    local conf_file="/etc/wireguard/clients/${target_name}.conf"

    # 确保配置文件存在
    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."
        wg_regenerate_client_confs
        [[ ! -f "$conf_file" ]] && { print_error "配置文件生成失败"; pause; return; }
        print_success "配置文件已重新生成"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        # ── Clash 客户端: 只显示生成 Clash 配置的选项 ──
        echo -e "  设备类型: ${C_CYAN}Clash 客户端${C_RESET}"
        echo -e "  (Clash 客户端不使用 .conf 文件，请生成 Clash YAML 配置)"
        echo ""
        if confirm "是否生成 Clash/Mihomo 配置?"; then
            wg_generate_clash_config
        fi
    elif [[ "$peer_type" == "gateway" ]]; then
        # ── 网关设备: 显示 .conf + OpenWrt 部署命令 ──
        draw_line
        echo -e "${C_CYAN}=== ${target_name} 客户端配置 (网关) ===${C_RESET}"
        draw_line
        cat "$conf_file"
        draw_line
        echo ""
        if confirm "显示 OpenWrt uci 部署命令?"; then
            _wg_show_openwrt_deploy "$target_idx"
        fi
    else
        # ── 标准客户端: 显示 .conf + 二维码 ──
        draw_line
        echo -e "${C_CYAN}=== ${target_name} 客户端配置 ===${C_RESET}"
        draw_line
        cat "$conf_file"
        draw_line
        if command_exists qrencode; then
            if confirm "显示二维码 (手机扫码导入)?"; then
                echo -e "${C_CYAN}=== ${target_name} 二维码 ===${C_RESET}"
                qrencode -t ansiutf8 < "$conf_file"
                echo ""
            fi
        fi
    fi

    echo -e "配置文件路径: ${C_CYAN}${conf_file}${C_RESET}"
    echo -e "下载命令: ${C_GRAY}scp root@服务器IP:${conf_file} ./${C_RESET}"
    pause
}

# 生成网关 peer 的 OpenWrt uci 一键部署命令
_wg_show_openwrt_deploy() {
    local target_idx="$1"
    [[ -z "$target_idx" ]] && { target_idx=$REPLY; }

    local peer_privkey peer_ip psk client_allowed_ips
    peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
    peer_ip=$(wg_db_get ".peers[$target_idx].ip")
    psk=$(wg_db_get ".peers[$target_idx].preshared_key")
    client_allowed_ips=$(wg_db_get ".peers[$target_idx].client_allowed_ips")

    local spub sep sport ssub mask
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    ssub=$(wg_db_get '.server.subnet')
    mask=$(echo "$ssub" | cut -d'/' -f2)
    local ep_host
    ep_host=$(wg_shared_endpoint_host "$sep")

    local uci_allowed_lines=""
    local IFS_BAK="$IFS"; IFS=','
    for cidr in $client_allowed_ips; do
        cidr=$(echo "$cidr" | xargs)
        [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}' || return 1
"
    done
    IFS="$IFS_BAK"

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
    draw_line
    cat << OPENWRT_EOF

# === 清理旧配置 ===
die() { echo "[!] \$*" >&2; exit 1; }
WG_UCI_SNAPSHOT_DIR=""
restore_uci_snapshots() {
    [ -n "\$WG_UCI_SNAPSHOT_DIR" ] || return 0
    if [ -s "\$WG_UCI_SNAPSHOT_DIR/network.uci" ]; then
        uci revert network >/dev/null 2>&1 || true
        uci import network < "\$WG_UCI_SNAPSHOT_DIR/network.uci" >/dev/null 2>&1 || true
        uci commit network >/dev/null 2>&1 || true
    fi
    if [ -s "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" ]; then
        uci revert firewall >/dev/null 2>&1 || true
        uci import firewall < "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" >/dev/null 2>&1 || true
        uci commit firewall >/dev/null 2>&1 || true
    fi
}
cleanup_uci_snapshots() {
    [ -n "\$WG_UCI_SNAPSHOT_DIR" ] && rm -rf "\$WG_UCI_SNAPSHOT_DIR" 2>/dev/null; true
}
die_restore() {
    msg="\$1"
    restore_uci_snapshots
    cleanup_uci_snapshots
    die "\$msg"
}
WG_UCI_SNAPSHOT_DIR="\$(mktemp -d /tmp/server-manage-wg-deploy-uci.XXXXXX 2>/dev/null)" || die "创建 UCI 回滚快照目录失败"
chmod 700 "\$WG_UCI_SNAPSHOT_DIR" 2>/dev/null || true
uci export network > "\$WG_UCI_SNAPSHOT_DIR/network.uci" 2>/dev/null || die_restore "备份 network UCI 失败"
uci export firewall > "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" 2>/dev/null || die_restore "备份 firewall UCI 失败"
list_wg_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=\$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\\/none/ && current != "" {
            print current
            current=""
        }
    '
}
wg_resolve_real() {
    WG_RESOLVE_HOST="\$1"
    WG_RESOLVE_DNS="\$2"
    nslookup "\$WG_RESOLVE_HOST" "\$WG_RESOLVE_DNS" 2>/dev/null | awk '
        /^Name:/ { seen_name=1; next }
        seen_name && /^Address[[:space:]][0-9]+:/ {
            ip=\$3
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
        seen_name && /^Address:/ {
            ip=\$2
            sub(/#.*/, "", ip)
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
    '
}
ifdown wg0 2>/dev/null; true
for iface in \$(list_wg_ifaces); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
done
for iface in wg0 wg_mesh wg-mesh; do
    ip link show "\$iface" >/dev/null 2>&1 && { ip link set "\$iface" down; ip link delete "\$iface"; } 2>/dev/null; true
done
rm -f /usr/bin/wg-watchdog.sh /var/run/server-manage/wg-watchdog.log /var/run/server-manage/.wg-watchdog-log.* /tmp/wg-watchdog.log /tmp/wg-watchdog.log.tmp 2>/dev/null; true
WG_CRON_TMP="\$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null)" && {
    crontab -l 2>/dev/null | awk '\$6 != "/usr/bin/wg-watchdog.sh"' > "\$WG_CRON_TMP"
    mkdir -p /etc/crontabs 2>/dev/null
    cp "\$WG_CRON_TMP" /etc/crontabs/root 2>/dev/null
    chmod 600 /etc/crontabs/root 2>/dev/null
    rm -f "\$WG_CRON_TMP"
}; true
/etc/init.d/wg-client disable 2>/dev/null; true
rm -f /etc/init.d/wg-client 2>/dev/null; true
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do uci delete network.@wireguard_wg0[0]; done
uci delete network.wg_server 2>/dev/null; true
uci delete network.wg0 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
i=0; while uci get firewall.@zone[\$i] >/dev/null 2>&1; do
    zname=\$(uci get firewall.@zone[\$i].name 2>/dev/null)
    case "\$zname" in wg|wireguard) uci delete "firewall.@zone[\$i]" 2>/dev/null; true; continue ;; esac
    i=\$((i + 1))
done
# 旧版 prio 100 规则没有可验证标记，不能粗暴删除全部 prio 100（可能属于第三方）。
for h in \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "\$h" 2>/dev/null; true
done
wg_rc_local_cleanup_managed() {
    WG_RC_KIND="\${1:-all}"
    [ -f /etc/rc.local ] || return 0
    WG_RC_CLEAN_TMP="\$(mktemp /etc/.rc.local.clean.XXXXXX 2>/dev/null)" || { echo '[!] 创建 rc.local 清理临时文件失败' >&2; return 1; }
    if awk -v kind="\$WG_RC_KIND" '
        function marker_matches(line) {
            if (kind == "all") return 1
            return index(line, " " kind) > 0
        }
        /^# BEGIN server-manage wireguard / {
            if (marker_matches(\$0)) { skip=1; next }
        }
        /^# END server-manage wireguard / {
            if (skip) { skip=0; next }
        }
        skip { next }
        kind != "allow-port" && /^# WireGuard bypass Mihomo/ { next }
        kind != "allow-port" && /# wg_bypass[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_peer_route[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_ep_resolve[[:space:]]*$/ { next }
        kind != "bypass" && /# wg_allow_port[[:space:]]*$/ { next }
        kind != "bypass" && /nft insert rule inet fw4 input_wan udp dport .*comment .*wg_allow_port/ { next }
        { print }
    ' /etc/rc.local > "\$WG_RC_CLEAN_TMP"; then
        chmod +x "\$WG_RC_CLEAN_TMP" 2>/dev/null && mv "\$WG_RC_CLEAN_TMP" /etc/rc.local || { rm -f "\$WG_RC_CLEAN_TMP"; return 1; }
        rm -f "\$WG_RC_CLEAN_TMP"
        return 0
    fi
    rm -f "\$WG_RC_CLEAN_TMP"
    return 1
}
wg_rc_local_cleanup_managed all || die_restore "清理 /etc/rc.local 旧 WireGuard 片段失败"
uci commit network >/dev/null 2>&1 || die_restore "提交清理后的 network 配置失败"
uci commit firewall >/dev/null 2>&1 || die_restore "提交清理后的 firewall 配置失败"

# === 安装 WireGuard 组件 ===
WG_KERNEL=0
[ -d /sys/module/wireguard ] || lsmod 2>/dev/null | grep -q wireguard && WG_KERNEL=1
for _retry in 1 2 3; do
    opkg update && break
    echo "[!] opkg update 失败 (第\${_retry}次), 3秒后重试..."
    sleep 3
done
[ "\$WG_KERNEL" = "0" ] && { opkg install kmod-wireguard 2>/dev/null || echo '[!] kmod-wireguard 安装失败'; }
opkg install wireguard-tools 2>/dev/null || echo '[!] wireguard-tools 安装失败'
opkg install luci-proto-wireguard 2>/dev/null || echo '[!] luci-proto-wireguard 安装失败'
/etc/init.d/rpcd restart 2>/dev/null; true
sleep 1
wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}
wg_ensure_wireguard_proto() {
    wg_proto_registered && return 0
    echo '[*] 重启 network/netifd 以加载 WireGuard 协议处理器...'
    /etc/init.d/network restart >/dev/null 2>&1 || return 1
    sleep 5
    wg_proto_registered
}
wg_ensure_wireguard_proto || die_restore "netifd 未注册 wireguard 协议"

# === 配置 WireGuard 接口 ===
write_wg_uci() {
    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key='${peer_privkey}' || return 1
    uci delete network.wg0.addresses 2>/dev/null; true
    uci add_list network.wg0.addresses='${peer_ip}/${mask}' || return 1
    uci set network.wg0.mtu='1420' || return 1
    uci set network.wg_server=wireguard_wg0 || return 1
    uci set network.wg_server.public_key='${spub}' || return 1
    uci set network.wg_server.preshared_key='${psk}' || return 1
    uci set network.wg_server.endpoint_host='${ep_host}' || return 1
    uci set network.wg_server.endpoint_port='${sport}' || return 1
    uci set network.wg_server.persistent_keepalive='25' || return 1
    uci set network.wg_server.route_allowed_ips='1' || return 1
${uci_allowed_lines}
    # === 配置防火墙 ===
    uci set firewall.wg_zone=zone || return 1
    uci set firewall.wg_zone.name='wg' || return 1
    uci set firewall.wg_zone.input='ACCEPT' || return 1
    uci set firewall.wg_zone.output='ACCEPT' || return 1
    uci set firewall.wg_zone.forward='ACCEPT' || return 1
    uci set firewall.wg_zone.masq='1' || return 1
    uci add_list firewall.wg_zone.network='wg0' || return 1
    uci set firewall.wg_fwd_lan=forwarding || return 1
    uci set firewall.wg_fwd_lan.src='lan' || return 1
    uci set firewall.wg_fwd_lan.dest='wg' || return 1
    uci set firewall.wg_fwd_wg=forwarding || return 1
    uci set firewall.wg_fwd_wg.src='wg' || return 1
    uci set firewall.wg_fwd_wg.dest='lan' || return 1
    uci commit network || return 1
    uci commit firewall || return 1
}
write_wg_uci || die_restore "写入 WireGuard UCI 配置失败"
ubus call network reload >/dev/null 2>&1 || true
sleep 1

# === Mihomo/OpenClash bypass: WG endpoint 流量直连 ===
# 关键: 使用外部 DNS 直连解析, 绕过 OpenClash fake-ip 劫持
EP_IP='${ep_host}'
case "\${EP_IP}" in
    *:*) ;;
    *)
if ! echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$'; then
    # 依次尝试多个外部 DNS 直连解析 (绕过本地 Clash/Mihomo fake-ip)
    for DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
        EP_IP=\$(wg_resolve_real '${ep_host}' "\$DNS_SRV")
        if [ -n "\$EP_IP" ]; then
            echo "[+] endpoint 解析: ${ep_host} -> \$EP_IP (via \$DNS_SRV)"
            break
        fi
    done
fi
        ;;
esac
if [ -z "\${EP_IP}" ]; then
    echo '[!] 警告: 无法解析 endpoint 真实 IP, bypass 规则可能无效!'
fi
if [ -n "\${EP_IP}" ]; then
    case "\${EP_IP}" in
        *:*)
            NFT_FAMILY="ip6"
            ip -6 rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
            ip -6 rule add to "\${EP_IP}" lookup main prio 100
            ;;
        *)
            NFT_FAMILY="ip"
            ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
            ip rule add to "\${EP_IP}" lookup main prio 100
            ;;
    esac
    nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1 && {
        nft insert rule inet fw4 mangle_prerouting "\${NFT_FAMILY}" daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting iifname \"wg0\" counter return comment \"wg_bypass_iface\" 2>/dev/null; true
    }
    echo "[+] Mihomo bypass 规则已添加: \${EP_IP}"
fi

# 持久化: rc.local 中使用外部 DNS 动态解析 (每次开机重新解析)
wg_rc_local_cleanup_managed bypass || die_restore "清理 rc.local 旧 bypass 片段失败"
WG_RC_BLOCK="\$(mktemp /etc/.wg-rc-block.XXXXXX 2>/dev/null)" || die_restore "创建 rc.local 片段临时文件失败"
WG_RC_TMP="\$(mktemp /etc/.rc.local.XXXXXX 2>/dev/null)" || { rm -f "\$WG_RC_BLOCK"; die_restore "创建 rc.local 临时文件失败"; }
if ! cat > "\$WG_RC_BLOCK" << 'WG_RC_EOF'
# BEGIN server-manage wireguard bypass
# WireGuard bypass Mihomo (dynamic resolve, bypass fake-ip) # wg_bypass
wg_resolve_real() {
    WG_RESOLVE_HOST="\$1"
    WG_RESOLVE_DNS="\$2"
    nslookup "\$WG_RESOLVE_HOST" "\$WG_RESOLVE_DNS" 2>/dev/null | awk '
        /^Name:/ { seen_name=1; next }
        seen_name && /^Address[[:space:]][0-9]+:/ {
            ip=\$3
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
        seen_name && /^Address:/ {
            ip=\$2
            sub(/#.*/, "", ip)
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
    '
}
case '${ep_host}' in
    *:*) WG_EP='${ep_host}' ;;
    *)
        WG_EP=""
        for WG_DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
            WG_EP=\$(wg_resolve_real '${ep_host}' "\$WG_DNS_SRV")
            [ -n "\$WG_EP" ] && break
        done
        ;;
esac # wg_ep_resolve
[ -n "\$WG_EP" ] && case "\$WG_EP" in *:*) WG_NFT_FAMILY=ip6; ip -6 rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true ;; *) WG_NFT_FAMILY=ip; ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true ;; esac # wg_bypass
[ -n "\$WG_EP" ] && nft insert rule inet fw4 mangle_prerouting "\$WG_NFT_FAMILY" daddr "\$WG_EP" udp dport ${sport} counter return comment "wg_bypass" 2>/dev/null; true # wg_bypass
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true # wg_bypass
# END server-manage wireguard bypass
WG_RC_EOF
then
    rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"
    die_restore "写入 rc.local 片段失败"
fi
if [ ! -f /etc/rc.local ]; then
    WG_RC_NEW="\$(mktemp /etc/.rc.local.new.XXXXXX 2>/dev/null)" || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"; die_restore "创建 rc.local 初始化临时文件失败"; }
    printf '#!/bin/sh\nexit 0\n' > "\$WG_RC_NEW" || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP" "\$WG_RC_NEW"; die_restore "写入 rc.local 初始化文件失败"; }
    chmod +x "\$WG_RC_NEW" 2>/dev/null && mv "\$WG_RC_NEW" /etc/rc.local || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP" "\$WG_RC_NEW"; die_restore "安装 /etc/rc.local 失败"; }
fi
if awk '
    FNR == NR { block = block \$0 ORS; next }
    /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?\$/ && !inserted { printf "%s", block; inserted=1 }
    { print }
    END { if (!inserted) printf "%s", block }
	' "\$WG_RC_BLOCK" /etc/rc.local > "\$WG_RC_TMP"; then
    chmod +x "\$WG_RC_TMP" 2>/dev/null && mv "\$WG_RC_TMP" /etc/rc.local || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"; die_restore "安装 /etc/rc.local 失败"; }
else
    rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"
    die_restore "生成 /etc/rc.local 失败"
fi
chmod +x /etc/rc.local 2>/dev/null; true
rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"

# === 开机自恢复服务 ===
WG_CLIENT_TMP="\$(mktemp /etc/init.d/.wg-client.XXXXXX 2>/dev/null)" || die_restore "创建 wg-client init 临时文件失败"
if ! cat > "\$WG_CLIENT_TMP" << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=0
boot() { start; }
wg_is_up() {
    ifstatus wg0 2>/dev/null | grep -q '"up": true'
}
wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}
wg_ensure_wireguard_proto() {
    wg_proto_registered && return 0
    logger -t wg-client "wireguard proto missing, restarting network"
    /etc/init.d/network restart >/dev/null 2>&1 || true
    sleep 5
    wg_proto_registered
}
start() {
    if command -v wg >/dev/null 2>&1 && uci -q get network.wg0.proto >/dev/null 2>&1; then
        wg_ensure_wireguard_proto || logger -t wg-client "wireguard proto still missing after network restart"
        ifup wg0 >/dev/null 2>&1 || true
        sleep 2
        wg_is_up && return 0
        logger -t wg-client "WireGuard configured but not up, restoring"
    else
        logger -t wg-client "WireGuard missing, restoring..."
    fi
    for _r in 1 2 3; do opkg update && break; sleep 3; done
    opkg install kmod-wireguard wireguard-tools luci-proto-wireguard 2>/dev/null
    /etc/init.d/rpcd restart 2>/dev/null; sleep 1
    restore_wg_uci() {
        uci set network.wg0=interface || return 1
        uci set network.wg0.proto='wireguard' || return 1
        uci set network.wg0.private_key='${peer_privkey}' || return 1
        uci set network.wg0.mtu='1420' || return 1
        uci delete network.wg0.addresses 2>/dev/null; true
        uci add_list network.wg0.addresses='${peer_ip}/${mask}' || return 1
        uci set network.wg_server=wireguard_wg0 || return 1
        uci set network.wg_server.public_key='${spub}' || return 1
        uci set network.wg_server.preshared_key='${psk}' || return 1
        uci set network.wg_server.endpoint_host='${ep_host}' || return 1
        uci set network.wg_server.endpoint_port='${sport}' || return 1
        uci set network.wg_server.persistent_keepalive='25' || return 1
        uci set network.wg_server.route_allowed_ips='1' || return 1
${uci_allowed_lines}        uci set firewall.wg_zone=zone || return 1
        uci set firewall.wg_zone.name='wg' || return 1
        uci set firewall.wg_zone.input='ACCEPT' || return 1
        uci set firewall.wg_zone.output='ACCEPT' || return 1
        uci set firewall.wg_zone.forward='ACCEPT' || return 1
        uci set firewall.wg_zone.masq='1' || return 1
        uci add_list firewall.wg_zone.network='wg0' || return 1
        uci set firewall.wg_fwd_lan=forwarding || return 1
        uci set firewall.wg_fwd_lan.src='lan' || return 1
        uci set firewall.wg_fwd_lan.dest='wg' || return 1
        uci set firewall.wg_fwd_wg=forwarding || return 1
        uci set firewall.wg_fwd_wg.src='wg' || return 1
        uci set firewall.wg_fwd_wg.dest='lan' || return 1
        uci commit network || return 1
        uci commit firewall || return 1
    }
    if ! restore_wg_uci; then
        logger -t wg-client "WireGuard restore failed"
        return 1
    fi
    wg_ensure_wireguard_proto || {
        logger -t wg-client "wireguard proto missing before ifup"
        return 1
    }
    ubus call network reload >/dev/null 2>&1 || true
    sleep 1
    ifup wg0 >/dev/null 2>&1 || true
    sleep 2
    if ! wg_is_up; then
        logger -t wg-client "WireGuard restore failed"
        return 1
    fi
    logger -t wg-client "WireGuard restored"
}
INITEOF
then
    rm -f "\$WG_CLIENT_TMP"
    die_restore "写入 wg-client init 失败"
fi
chmod 0700 "\$WG_CLIENT_TMP" && mv "\$WG_CLIENT_TMP" /etc/init.d/wg-client || { rm -f "\$WG_CLIENT_TMP"; die_restore "安装 wg-client init 失败"; }
rm -f "\$WG_CLIENT_TMP"
/etc/init.d/wg-client enable || die_restore "启用 wg-client init 失败"
echo '[+] 开机自恢复服务已安装'

# === 启动接口 ===
ifup wg0 || die_restore "启动 wg0 失败"

# === 验证 ===
sleep 3
if ifstatus wg0 2>/dev/null | grep -q '"up": true'; then
    echo '[+] wg0 接口启动成功!'
else
    echo '[!] wg0 接口未启动，请检查: logread | grep -i wireguard'
fi
if [ -n "\${EP_IP}" ]; then
    echo "[*] 验证 endpoint: wg show wg0 endpoints"
    wg show wg0 endpoints 2>/dev/null
fi

OPENWRT_EOF

    # 如果 endpoint 是域名，追加看门狗
    if [[ ! "$ep_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        cat << 'WDEOF'

# === WireGuard 看门狗 (fake-ip检测 + DNS直连解析 + 完整bypass自恢复 + 握手保活 + 安全日志) ===
WG_WATCHDOG_TMP="$(mktemp /usr/bin/.wg-watchdog.XXXXXX 2>/dev/null)" || die_restore "创建 wg-watchdog 临时文件失败"
if ! cat > "$WG_WATCHDOG_TMP" << 'WDSCRIPT'
#!/bin/sh
LOG_DIR="/var/run/server-manage"
LOG_FILE="$LOG_DIR/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    size=0
    tmp=""
    logger -t wg-watchdog "$1"
    if [ -L "$LOG_DIR" ] || { [ -e "$LOG_DIR" ] && [ ! -d "$LOG_DIR" ]; }; then
        return 0
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    chmod 0700 "$LOG_DIR" 2>/dev/null || true
    [ -L "$LOG_FILE" ] && return 0
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || return 0
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        case "$size" in *[!0-9]*|"") size=0 ;; esac
    fi
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        tmp=$(mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX" 2>/dev/null) || tmp=""
        if [ -n "$tmp" ]; then
            tail -n 50 "$LOG_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_FILE"
            rm -f "$tmp" 2>/dev/null || true
        fi
    fi
}

resolve_real() {
    local host="$1" ip=""
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] || continue
        echo "$ip"; return 0
    done
    return 1
}

wg_endpoint_host() {
    local endpoint="$1"
    case "$endpoint" in
        \[*\]:*) echo "$endpoint" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p' ;;
        *:*)     echo "$endpoint" | sed 's/:[0-9][0-9]*$//' ;;
        *)       echo "$endpoint" ;;
    esac
}

wg_format_endpoint() {
    local host="$1" port="$2"
    case "$host" in
        *:*) echo "[${host}]:${port}" ;;
        *)   echo "${host}:${port}" ;;
    esac
}

wg_nft_addr_family() {
    case "$1" in
        *:*) echo "ip6" ;;
        *)   echo "ip" ;;
    esac
}

wg_ip_rule_show() {
    case "$1" in
        *:*) ip -6 rule show 2>/dev/null ;;
        *)   ip rule show 2>/dev/null ;;
    esac
}

wg_ip_rule_del() {
    case "$1" in
        *:*) ip -6 rule del to "$1" lookup main prio 100 2>/dev/null ;;
        *)   ip rule del to "$1" lookup main prio 100 2>/dev/null ;;
    esac
}

wg_ip_rule_add() {
    case "$1" in
        *:*) ip -6 rule add to "$1" lookup main prio 100 2>/dev/null ;;
        *)   ip rule add to "$1" lookup main prio 100 2>/dev/null ;;
    esac
}

wg_is_up() {
    ifstatus wg0 2>/dev/null | grep -q '"up": true'
}

wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}

if ! wg_is_up; then
    wdlog "wg0 not up, restarting"
    if ! wg_proto_registered; then
        wdlog "wireguard proto missing, restarting network"
        /etc/init.d/network restart >/dev/null 2>&1 || true
        sleep 5
    fi
    ifup wg0 >/dev/null 2>&1 || true
    exit 0
fi

# resolve endpoint (always set RESOLVED for bypass self-heal)
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif echo "$EP_HOST" | grep -q ':'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

# DNS re-resolve + endpoint update (only for domain endpoints)
if [ -n "$EP_HOST" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && ! echo "$EP_HOST" | grep -q ':'; then
    CURRENT_EP=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | head -1)
    CURRENT=$(wg_endpoint_host "$CURRENT_EP")
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*) FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        WG_ENDPOINT=$(wg_format_endpoint "$RESOLVED" "$PORT")
        NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
        wg set wg0 peer "$PUB" endpoint "$WG_ENDPOINT"
        for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
            nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
        done
        nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        wg_ip_rule_del "$RESOLVED"; true
        wg_ip_rule_add "$RESOLVED"; true
        wdlog "bypass updated -> $RESOLVED"
    fi
fi

# bypass rule self-heal (complete: iface + IP + ip rule)
if nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ]; then
        if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
            PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
            NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
            nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wdlog "restored IP bypass -> $RESOLVED"
        fi
    fi
fi
if [ -n "$RESOLVED" ] && ! wg_ip_rule_show "$RESOLVED" | grep -q "$RESOLVED"; then
    wg_ip_rule_add "$RESOLVED"; true
    wdlog "restored ip rule -> $RESOLVED"
fi

# connectivity check (handshake timeout + ping fallback)
LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" >/dev/null 2>&1; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
then
    rm -f "$WG_WATCHDOG_TMP"
    die_restore "写入 wg-watchdog 失败"
fi
chmod 0700 "$WG_WATCHDOG_TMP" && mv "$WG_WATCHDOG_TMP" /usr/bin/wg-watchdog.sh || { rm -f "$WG_WATCHDOG_TMP"; die_restore "安装 wg-watchdog 失败"; }
rm -f "$WG_WATCHDOG_TMP"
WG_CRON_TMP="$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null)" || die_restore "创建 wg-watchdog cron 临时文件失败"
(crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"'; echo '* * * * * /usr/bin/wg-watchdog.sh') > "$WG_CRON_TMP" || { rm -f "$WG_CRON_TMP"; die_restore "生成 wg-watchdog cron 失败"; }
mkdir -p /etc/crontabs 2>/dev/null || { rm -f "$WG_CRON_TMP"; die_restore "创建 OpenWrt cron 目录失败"; }
cp "$WG_CRON_TMP" /etc/crontabs/root 2>/dev/null || { rm -f "$WG_CRON_TMP"; die_restore "写入 OpenWrt cron 文件失败"; }
chmod 600 /etc/crontabs/root 2>/dev/null || true
rm -f "$WG_CRON_TMP"
awk '$6 == "/usr/bin/wg-watchdog.sh" { found=1 } END { exit !found }' /etc/crontabs/root || die_restore "安装 wg-watchdog cron 失败"
/etc/init.d/cron restart || die_restore "重启 cron 失败"
cleanup_uci_snapshots
echo '[+] 看门狗已安装 (DNS直连 + fake-ip检测 + 完整bypass自恢复 + 握手保活 + 日志持久化)'
WDEOF
    else
        cat << 'NO_WATCHDOG_EOF'
cleanup_uci_snapshots
NO_WATCHDOG_EOF
    fi

    draw_line
    echo -e "${C_GREEN}复制以上全部命令到目标 OpenWrt SSH 终端执行即可。${C_RESET}"
    echo -e "${C_CYAN}验证方法:${C_RESET}"
    echo "  1. wg show (确认 endpoint 不是 198.19.x.x)"
    echo "  2. ping $(wg_db_get '.server.ip') (从 LAN 设备 ping VPN 服务端)"
    echo -e "${C_YELLOW}重启保护:${C_RESET}"
    echo "  • rc.local: 开机动态解析 endpoint (绕过 fake-ip)"
    echo "  • 看门狗: 每分钟检测 fake-ip 并自动修正"
    draw_line
}

wg_show_openwrt_endpoint_migrate_cmd() {
    wg_check_server || return 1
    print_title "生成 OpenWrt 客户端 endpoint 安全迁移命令"

    local cur_ep cur_port new_ep ep_host server_ip server_lan health_lan=""
    cur_ep=$(wg_db_get '.server.endpoint')
    cur_port=$(wg_db_get '.server.port')
    server_ip=$(wg_db_get '.server.ip')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    echo -e "  当前服务端 endpoint: ${C_GREEN}${cur_ep}:${cur_port}${C_RESET}"
    read -e -r -p "目标 endpoint 主机名/IP [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if ! ep_host=$(wg_shared_normalize_endpoint_host "$new_ep"); then
        print_error "endpoint 无效"
        pause; return 1
    fi

    if [[ -n "$server_lan" && "$server_lan" != "null" && "$server_lan" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.0/24$ ]]; then
        health_lan="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.1"
    fi

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 客户端 endpoint 安全迁移命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt 客户端 SSH 终端执行。脚本会先运行态切换并健康检查，成功后才持久化。${C_RESET}"
    draw_line
    cat << MIGRATE_HEAD
NEW_HOST='${ep_host}'
NEW_PORT='${cur_port}'
HEALTH_WG='${server_ip}'
HEALTH_LAN='${health_lan}'
MIGRATE_HEAD
    cat <<'MIGRATE_BODY'
set -u
WG_IF="wg0"
SNAP_DIR="/root/wg-endpoint-migrate-$(date +%Y%m%d-%H%M%S)"

die() { echo "[!] $*" >&2; exit 1; }
mkdir -p "$SNAP_DIR" || die "创建回滚快照目录失败"
chmod 700 "$SNAP_DIR" 2>/dev/null || true
uci export network > "$SNAP_DIR/network.uci" 2>/dev/null || die "备份 network UCI 失败"
for f in /etc/init.d/wg-client /etc/rc.local /usr/bin/wg-watchdog.sh; do
    [ -e "$f" ] && cp -p "$f" "$SNAP_DIR/$(basename "$f").bak" 2>/dev/null || true
done

OLD_HOST=$(uci -q get network.wg_server.endpoint_host 2>/dev/null || true)
OLD_PORT=$(uci -q get network.wg_server.endpoint_port 2>/dev/null || true)
[ -n "$OLD_HOST" ] || die "未找到 network.wg_server.endpoint_host"
[ -n "$NEW_PORT" ] || NEW_PORT="$OLD_PORT"
[ -n "$NEW_PORT" ] || die "未找到 endpoint_port"
PUB=$(wg show "$WG_IF" peers 2>/dev/null | head -1)
OLD_RUNTIME_EP=$(wg show "$WG_IF" endpoints 2>/dev/null | awk '{print $2}' | head -1)
[ -n "$PUB" ] || die "未找到 WireGuard peer"

restore_all() {
    echo "[!] 回滚 endpoint 迁移" >&2
    [ -s "$SNAP_DIR/network.uci" ] && {
        uci revert network >/dev/null 2>&1 || true
        uci import network < "$SNAP_DIR/network.uci" >/dev/null 2>&1 || true
        uci commit network >/dev/null 2>&1 || true
    }
    [ -f "$SNAP_DIR/wg-client.bak" ] && cp -p "$SNAP_DIR/wg-client.bak" /etc/init.d/wg-client 2>/dev/null || true
    [ -f "$SNAP_DIR/rc.local.bak" ] && cp -p "$SNAP_DIR/rc.local.bak" /etc/rc.local 2>/dev/null || true
    [ -f "$SNAP_DIR/wg-watchdog.sh.bak" ] && cp -p "$SNAP_DIR/wg-watchdog.sh.bak" /usr/bin/wg-watchdog.sh 2>/dev/null || true
    [ -n "${OLD_RUNTIME_EP:-}" ] && wg set "$WG_IF" peer "$PUB" endpoint "$OLD_RUNTIME_EP" 2>/dev/null || true
}

resolve_real() {
    h="$1"
    case "$h" in *:*) echo "$h"; return 0 ;; esac
    echo "$h" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && { echo "$h"; return 0; }
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$h" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    done
    return 1
}

format_endpoint() {
    case "$1" in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac
}

replace_literal() {
    file="$1"; old="$2"; new="$3"
    [ -f "$file" ] || return 0
    old_re=$(printf '%s' "$old" | sed 's/[.[\*^$()+?{}|\\]/\\&/g')
    new_re=$(printf '%s' "$new" | sed 's/[\/&]/\\&/g')
    tmp=$(mktemp "$(dirname "$file")/.endpoint-migrate.XXXXXX") || return 1
    sed "s/${old_re}/${new_re}/g" "$file" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 700 "$tmp" 2>/dev/null || true
    mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
}

install_rc_local_bypass() {
    host="$1"; port="$2"; rc="/etc/rc.local"
    [ -f "$rc" ] || { printf '#!/bin/sh\nexit 0\n' > "$rc" || return 1; chmod 755 "$rc" 2>/dev/null || true; }
    dir=$(dirname "$rc")
    base=$(mktemp "$dir/.endpoint-migrate-rc-base.XXXXXX") || return 1
    block=$(mktemp "$dir/.endpoint-migrate-rc-block.XXXXXX") || { rm -f "$base"; return 1; }
    tmp=$(mktemp "$dir/.endpoint-migrate-rc.XXXXXX") || { rm -f "$base" "$block"; return 1; }
    awk '
        /^# BEGIN server-manage wireguard bypass$/ { skip=1; next }
        /^# END server-manage wireguard bypass$/ { skip=0; next }
        skip { next }
        /# wg_bypass/ { next }
        /# wg_ep_resolve/ { next }
        { print }
    ' "$rc" > "$base" || { rm -f "$base" "$block" "$tmp"; return 1; }
    cat > "$block" <<RCBLOCK || { rm -f "$base" "$block" "$tmp"; return 1; }
# BEGIN server-manage wireguard bypass
wg_resolve_real() {
    h="\$1"
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=\$(nslookup "\$h" "\$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=\$3
                if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=\$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "\$ip" ] && { echo "\$ip"; return 0; }
    done
    return 1
}
WG_EP=""
case '$host' in
    *:*) WG_EP='$host' ;;
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) WG_EP='$host' ;;
    *) WG_EP=\$(wg_resolve_real '$host' || true) ;;
esac
if [ -n "\$WG_EP" ]; then
    case "\$WG_EP" in
        *:*) WG_NFT_FAMILY=ip6; ip -6 rule add to "\$WG_EP" lookup main prio 100 2>/dev/null || true ;;
        *) WG_NFT_FAMILY=ip; ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null || true ;;
    esac
    nft insert rule inet fw4 mangle_prerouting "\$WG_NFT_FAMILY" daddr "\$WG_EP" udp dport $port counter return comment "wg_bypass" 2>/dev/null || true
fi
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null || true
# END server-manage wireguard bypass
RCBLOCK
    awk -v block="$block" '
        function emit_block() {
            while ((getline line < block) > 0) print line
            close(block)
        }
        BEGIN { inserted=0 }
        {
            if (!inserted && $0 ~ /^[[:space:]]*exit[[:space:]]+0[[:space:]]*($|#)/) {
                emit_block()
                inserted=1
            }
            print
        }
        END {
            if (!inserted) {
                emit_block()
                print "exit 0"
            }
        }
    ' "$base" > "$tmp" || { rm -f "$base" "$block" "$tmp"; return 1; }
    chmod 755 "$tmp" 2>/dev/null || true
    mv "$tmp" "$rc" || { rm -f "$base" "$block" "$tmp"; return 1; }
    rm -f "$base" "$block"
}

install_watchdog() {
    tmp=$(mktemp /usr/bin/.wg-watchdog.XXXXXX 2>/dev/null) || return 1
    cat > "$tmp" <<'WDSCRIPT'
#!/bin/sh
LOG_DIR="/var/run/server-manage"
LOG_FILE="$LOG_DIR/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    size=0
    tmp=""
    logger -t wg-watchdog "$1"
    if [ -L "$LOG_DIR" ] || { [ -e "$LOG_DIR" ] && [ ! -d "$LOG_DIR" ]; }; then return 0; fi
    mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    chmod 0700 "$LOG_DIR" 2>/dev/null || true
    [ -L "$LOG_FILE" ] && return 0
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || return 0
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        case "$size" in *[!0-9]*|"") size=0 ;; esac
    fi
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        tmp=$(mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX" 2>/dev/null) || tmp=""
        [ -n "$tmp" ] && tail -n 50 "$LOG_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_FILE"
        rm -f "$tmp" 2>/dev/null || true
    fi
}

resolve_real() {
    host="$1"
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    done
    return 1
}

wg_endpoint_host() {
    case "$1" in \[*\]:*) echo "$1" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p' ;; *:*) echo "$1" | sed 's/:[0-9][0-9]*$//' ;; *) echo "$1" ;; esac
}
wg_format_endpoint() { case "$1" in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac; }
wg_nft_addr_family() { case "$1" in *:*) echo "ip6" ;; *) echo "ip" ;; esac; }
wg_ip_rule_show() { case "$1" in *:*) ip -6 rule show 2>/dev/null ;; *) ip rule show 2>/dev/null ;; esac; }
wg_ip_rule_del() { case "$1" in *:*) ip -6 rule del to "$1" lookup main prio 100 2>/dev/null ;; *) ip rule del to "$1" lookup main prio 100 2>/dev/null ;; esac; }
wg_ip_rule_add() { case "$1" in *:*) ip -6 rule add to "$1" lookup main prio 100 2>/dev/null ;; *) ip rule add to "$1" lookup main prio 100 2>/dev/null ;; esac; }
wg_is_up() { ifstatus wg0 2>/dev/null | grep -q '"up": true'; }
wg_proto_registered() { ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'; }

if ! wg_is_up; then
    wdlog "wg0 not up, restarting"
    if ! wg_proto_registered; then
        wdlog "wireguard proto missing, restarting network"
        /etc/init.d/network restart >/dev/null 2>&1 || true
        sleep 5
    fi
    ifup wg0 >/dev/null 2>&1 || true
    exit 0
fi

EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif echo "$EP_HOST" | grep -q ':'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

if [ -n "$EP_HOST" ] && [ -n "$PORT" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && ! echo "$EP_HOST" | grep -q ':'; then
    CURRENT_EP=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | head -1)
    CURRENT=$(wg_endpoint_host "$CURRENT_EP")
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*|"") FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        PUB=$(wg show wg0 endpoints 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$PUB" ]; then
            wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
            wg set wg0 peer "$PUB" endpoint "$(wg_format_endpoint "$RESOLVED" "$PORT")" >/dev/null 2>&1 || true
            for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
                nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
            done
            NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
            nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wg_ip_rule_del "$RESOLVED"; true
            wg_ip_rule_add "$RESOLVED"; true
            wdlog "bypass updated -> $RESOLVED"
        fi
    fi
fi

if nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ] && ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
        NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
        nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        wdlog "restored IP bypass -> $RESOLVED"
    fi
fi
if [ -n "$RESOLVED" ] && ! wg_ip_rule_show "$RESOLVED" | grep -q "$RESOLVED"; then
    wg_ip_rule_add "$RESOLVED"; true
    wdlog "restored ip rule -> $RESOLVED"
fi

LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" >/dev/null 2>&1; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
    chmod 0700 "$tmp" && mv "$tmp" /usr/bin/wg-watchdog.sh || { rm -f "$tmp"; return 1; }
    cron_tmp=$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null) || return 1
    (crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"'; echo '* * * * * /usr/bin/wg-watchdog.sh') > "$cron_tmp" || { rm -f "$cron_tmp"; return 1; }
    mkdir -p /etc/crontabs 2>/dev/null || { rm -f "$cron_tmp"; return 1; }
    cp "$cron_tmp" /etc/crontabs/root 2>/dev/null || { rm -f "$cron_tmp"; return 1; }
    chmod 600 /etc/crontabs/root 2>/dev/null || true
    rm -f "$cron_tmp"
    /etc/init.d/cron restart >/dev/null 2>&1 || return 1
}

NEW_IP=$(resolve_real "$NEW_HOST") || die "解析新 endpoint 失败: $NEW_HOST"
NEW_RUNTIME_EP=$(format_endpoint "$NEW_IP" "$NEW_PORT")
echo "[*] runtime endpoint: ${OLD_RUNTIME_EP:-none} -> $NEW_RUNTIME_EP"
wg set "$WG_IF" peer "$PUB" endpoint "$NEW_RUNTIME_EP" || { restore_all; exit 1; }
sleep 2
ping -c 2 -W 2 "$HEALTH_WG" >/dev/null 2>&1 || { restore_all; die "运行态切换后 VPN 健康检查失败"; }
[ -z "$HEALTH_LAN" ] || ping -c 2 -W 2 "$HEALTH_LAN" >/dev/null 2>&1 || { restore_all; die "运行态切换后 LAN 健康检查失败"; }

uci set network.wg_server.endpoint_host="$NEW_HOST" || { restore_all; exit 1; }
uci set network.wg_server.endpoint_port="$NEW_PORT" || { restore_all; exit 1; }
uci commit network || { restore_all; exit 1; }
replace_literal /etc/init.d/wg-client "$OLD_HOST" "$NEW_HOST" || { restore_all; exit 1; }
install_rc_local_bypass "$NEW_HOST" "$NEW_PORT" || { restore_all; exit 1; }
install_watchdog || { restore_all; die "安装新版 wg-watchdog 失败"; }
/usr/bin/wg-watchdog.sh >/dev/null 2>&1 || true
sleep 2
ping -c 2 -W 2 "$HEALTH_WG" >/dev/null 2>&1 || { restore_all; die "持久化后 VPN 健康检查失败"; }
[ -z "$HEALTH_LAN" ] || ping -c 2 -W 2 "$HEALTH_LAN" >/dev/null 2>&1 || { restore_all; die "持久化后 LAN 健康检查失败"; }
echo "[+] endpoint 已迁移: $NEW_HOST:$NEW_PORT"
echo "[+] 快照目录: $SNAP_DIR"
wg show "$WG_IF" endpoints 2>/dev/null || true
MIGRATE_BODY
    draw_line
    pause
}
_wg_clash_db_get() {
    local mode="$1"; shift
    case "$mode" in
        debian) wg_deb_db_get "$@" ;;
        *)      wg_db_get "$@" ;;
    esac
}

_wg_clash_check_server() {
    local mode="$1"
    case "$mode" in
        debian) wg_deb_check_server ;;
        *)      wg_check_server ;;
    esac
}

_wg_clash_server_name() {
    local mode="$1"
    case "$mode" in
        debian) wg_deb_get_server_name ;;
        *)      wg_get_server_name ;;
    esac
}

wg_generate_clash_config() {
    _wg_generate_clash_config_impl "openwrt"
}

wg_deb_generate_clash_config() {
    _wg_generate_clash_config_impl "debian"
}

_wg_clash_rule_type_for_addr() {
    case "${1:-}" in
        *:*) printf 'IP-CIDR6' ;;
        *)   printf 'IP-CIDR' ;;
    esac
}

_wg_clash_endpoint_direct_rule() {
    local endpoint="${1:-}" host
    host=$(wg_shared_endpoint_host "$endpoint")
    if validate_ip "$host"; then
        if [[ "$host" == *:* ]]; then
            printf '  - IP-CIDR6,%s/128,DIRECT\n' "$host"
        else
            printf '  - IP-CIDR,%s/32,DIRECT\n' "$host"
        fi
    else
        printf '  - DOMAIN,%s,DIRECT\n' "$host"
    fi
}

_wg_clash_cidr_rule() {
    local cidr="${1:-}" group="${2:-}"
    printf '  - %s,%s,%s\n' "$(_wg_clash_rule_type_for_addr "$cidr")" "$cidr" "$group"
}

_wg_generate_clash_config_impl() {
    local mode="${1:-openwrt}"
    _wg_clash_check_server "$mode" || return 1
    print_title "生成 Clash (OpenClash) WireGuard 配置"
    local peer_count=$(_wg_clash_db_get "$mode" '.peers | length')
    if [[ "$peer_count" -eq 0 ]]; then
        print_warn "暂无设备，请先添加 Peer"
        pause; return
    fi

    # 选择设备
    echo "选择要生成 Clash 配置的设备:"
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name=$(_wg_clash_db_get "$mode" ".peers[$i].name")
        local ip=$(_wg_clash_db_get "$mode" ".peers[$i].ip")
        local is_gw=$(_wg_clash_db_get "$mode" ".peers[$i].is_gateway // false")
        local mark=""
        [[ "$is_gw" == "true" ]] && mark=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i+1)). ${name} (${ip})${mark}"
        i=$((i+1))
    done
    echo "  0. 返回"
    read -e -r -p "选择设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return
    fi
    local ti=$((idx-1))
    local peer_name=$(_wg_clash_db_get "$mode" ".peers[$ti].name")
    local peer_ip=$(_wg_clash_db_get "$mode" ".peers[$ti].ip")
    local peer_privkey=$(_wg_clash_db_get "$mode" ".peers[$ti].private_key")
    local peer_psk=$(_wg_clash_db_get "$mode" ".peers[$ti].preshared_key")
    local server_pubkey=$(_wg_clash_db_get "$mode" '.server.public_key')
    local server_endpoint=$(_wg_clash_db_get "$mode" '.server.endpoint')
    local server_port=$(_wg_clash_db_get "$mode" '.server.port')
    local server_subnet=$(_wg_clash_db_get "$mode" '.server.subnet')
    local server_dns=$(_wg_clash_db_get "$mode" '.server.dns' | cut -d',' -f1 | xargs)
    local mask=$(echo "$server_subnet" | cut -d'/' -f2)

    # 收集所有 VPN 路由网段 (含服务端 LAN)
    local vpn_cidrs=("$server_subnet")
    local server_lan=$(_wg_clash_db_get "$mode" '.server.server_lan_subnet // empty')
    [[ -n "$server_lan" && "$server_lan" != "null" ]] && vpn_cidrs+=("$server_lan")
    local pi=0
    while [[ $pi -lt $peer_count ]]; do
        local pls=$(_wg_clash_db_get "$mode" ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" && "$pls" != "null" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $pls; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && vpn_cidrs+=("$cidr")
            done
            IFS="$IFS_BAK"
        fi
        pi=$((pi+1))
    done
    local -a unique_cidrs
    mapfile -t unique_cidrs < <(printf '%s\n' "${vpn_cidrs[@]}" | sort -u)

    # ── 构建 proxy 节点列表 ──
    local all_proxy_names=()
    local all_proxy_yaml=""
    local allowed_ips_yaml=""
    local cidr
    for cidr in "${unique_cidrs[@]}"; do
        allowed_ips_yaml+="      - ${cidr}
"
    done

    # 主机节点
    local primary_name="WG-$(_wg_clash_server_name "$mode")"
    all_proxy_names+=("$primary_name")

    local mtu=$(_wg_clash_db_get "$mode" '.server.mtu // 1420')
    all_proxy_yaml+="  - name: \"${primary_name}\"
    type: wireguard
    server: ${server_endpoint}
    port: ${server_port}
    ip: ${peer_ip}
    allowed-ips:
${allowed_ips_yaml}    private-key: \"${peer_privkey}\"
    public-key: \"${server_pubkey}\"
    pre-shared-key: \"${peer_psk}\"
    reserved: [0, 0, 0]
    udp: true
    mtu: ${mtu}
    remote-dns-resolve: false
    dns:
      - ${server_dns}
"

    # ── 构建 proxy-group ──
    local group_name="WireGuard-VPN"
    local wg_group_yaml="  - name: ${group_name}
    type: select
    proxies:
      - ${all_proxy_names[0]}
      - DIRECT"

    # ── 构建 rules ──
    local wg_rules_yaml=""
    # 服务器 endpoint 走 DIRECT（防止死循环）
    wg_rules_yaml+="$(_wg_clash_endpoint_direct_rule "$server_endpoint")"
    for cidr in "${unique_cidrs[@]}"; do
        wg_rules_yaml+="$(_wg_clash_cidr_rule "$cidr" "$group_name")"
    done

    # ── 输出 ──
    draw_line
    echo -e "${C_CYAN}设备: ${peer_name}${C_RESET}"
    draw_line
    echo ""
    echo "请选择操作方式:
  1. 生成 YAML 片段 (手动合并到现有配置)
  2. 粘贴现有 YAML，自动注入 WireGuard 规则
  0. 返回"
    read -e -r -p "选择 [1]: " gen_mode
    gen_mode=${gen_mode:-1}
    case $gen_mode in
        1)
            draw_line
            echo -e "${C_CYAN}=== 需要添加到 YAML 的内容 ===${C_RESET}"
            draw_line
            echo -e "${C_YELLOW}# === 第1步: 在 proxies: 段末尾添加 ===${C_RESET}"
            echo "$all_proxy_yaml"
            echo -e "${C_YELLOW}# === 第2步: 在 proxy-groups: 段末尾添加 ===${C_RESET}"
            echo "$wg_group_yaml"
            echo -e "${C_YELLOW}# === 第3步: 在 rules: 段最前面添加 ===${C_RESET}"
            echo -n "$wg_rules_yaml"
            draw_line
            if [[ ${#all_proxy_names[@]} -gt 1 ]]; then
                echo -e "${C_CYAN}[多节点说明]${C_RESET}"
                echo "  • 所有节点共享同一密钥，客户端 IP 相同"
                echo "  • Clash 自动在 ${#all_proxy_names[@]} 个节点间选择最优"
                echo "  • 服务器 Endpoint 全部走 DIRECT 防止死循环
"
            fi
            echo -e "${C_YELLOW}要求: Clash Meta (mihomo) 内核 1.14.0+${C_RESET}"
            echo -e "${C_YELLOW}OpenClash 请在设置中切换到 Meta 内核${C_RESET}"
            echo ""
            echo -e "${C_YELLOW}[DNS 提示] 如果使用 proxy-providers 订阅，请在 dns.nameserver-policy 中添加:${C_RESET}"
            echo -e "  nameserver-policy:"
            echo -e "    \"+.你的订阅域名\": [223.5.5.5, 114.114.114.114]"
            echo -e "  ${C_DIM}(避免 DNS 鸡蛋问题: fallback DNS 需代理，但代理尚未建立)${C_RESET}"
            draw_line
            ;;
        2)
            echo -e "${C_CYAN}请粘贴你现有的完整 YAML 配置 (粘贴完成后按 Ctrl+D):${C_RESET}"
            local original_yaml
            original_yaml=$(cat)
            if [[ -z "$original_yaml" ]]; then
                print_error "内容为空"; pause; return
            fi
            if ! echo "$original_yaml" | grep -qE '^[[:space:]]*proxies:'; then
                print_error "YAML 中未找到 'proxies:' 段"
                pause; return
            fi
            local output_dir output_file
            local old_umask inject_rc
            old_umask=$(umask)
            umask 077
            if ! output_dir=$(mktemp -d "${TMPDIR:-/tmp}/clash-wg.XXXXXX" 2>/dev/null); then
                umask "$old_umask"
                print_error "无法创建安全临时目录"
                pause; return
            fi
            umask "$old_umask"
            chmod 700 "$output_dir" 2>/dev/null || true
            output_file="${output_dir}/clash-config.yaml"
            local has_proxy_groups=false
            echo "$original_yaml" | grep -qE '^[[:space:]]*proxy-groups:' && has_proxy_groups=true

            # 用 Python/jq 辅助或简单 awk 注入
            # 改进: 追踪缩进层级判断段结束
            old_umask=$(umask)
            umask 077
            awk \
                -v proxy_nodes="$all_proxy_yaml" \
                -v proxy_group="$wg_group_yaml" \
                -v rules="$wg_rules_yaml" \
                -v has_proxy_groups="$has_proxy_groups" \
            '
            BEGIN { state="init"; proxy_done=0; group_done=0; rule_done=0 }

            # 检测顶级 key (行首非空格开头，含冒号)
            function is_top_key(line) {
                return (line ~ /^[a-zA-Z_-]+:/)
            }
            /^proxies:/ { state="proxies"; print; next }
            /^proxy-groups:/ {
                if(state=="proxies" && !proxy_done) {
                    print ""; print proxy_nodes;
                    proxy_done=1
                }
                state="groups"; print; next
            }
            /^rules:/ {
                if(state=="proxies" && !proxy_done) {
                    print ""; print proxy_nodes
                    proxy_done=1
                }
                if(state=="groups" && !group_done) {
                    print ""; print proxy_group; print ""
                    group_done=1
                }
                if(has_proxy_groups != "true" && !group_done) {
                    print ""; print "proxy-groups:"; print proxy_group; print ""
                    group_done=1
                }
                print $0
                print "  # === WireGuard VPN 路由规则 (自动生成) ==="
                printf "%s", rules
                rule_done=1
                state="rules"
                next
            }

            # 其他顶级 key 触发前一个段的注入
            is_top_key($0) && state=="proxies" && !proxy_done {
                print ""; print proxy_nodes; proxy_done=1; state="init"
            }
            is_top_key($0) && state=="groups" && !group_done {
                print ""; print proxy_group; print ""; group_done=1; state="init"
            }
            { print }
            END {
                if(!proxy_done) { print ""; print proxy_nodes }
                if(!group_done) {
                    print ""
                    if(has_proxy_groups != "true") { print "proxy-groups:" }
                    print proxy_group
                }
                if(!rule_done) { print ""; print "rules:"; print "  # === WireGuard VPN 路由规则 ==="; printf "%s", rules }
            }
            ' <<< "$original_yaml" > "$output_file"
            inject_rc=$?
            umask "$old_umask"
            chmod 600 "$output_file" 2>/dev/null || true
            if [[ $inject_rc -ne 0 ]]; then
                print_error "YAML 注入失败"
                rm -rf "$output_dir"
                pause; return
            fi

            # ── 自动注入 nameserver-policy: 订阅域名走国内 DNS 直连解析 ──
            # 避免 DNS 鸡蛋问题: fallback DNS (Google/Cloudflare DoH) 需要代理才能访问
            # 但此时代理尚未建立，订阅 URL 无法解析 → 节点拉取失败
            local _prov_block=""
            _prov_block=$(awk '
                /^proxy-providers:/ { in_providers=1; print; next }
                in_providers && /^[A-Za-z_-]+:/ { exit }
                in_providers { print }
            ' "$output_file" 2>/dev/null || true)
            if [[ -n "$_prov_block" ]]; then
                local _inject_ns=""
                while IFS= read -r _purl; do
                    [[ -z "$_purl" ]] && continue
                    local _host
                    _host=$(echo "$_purl" | sed 's|https\?://||;s|/.*||')
                    [[ -z "$_host" ]] && continue
                    # 提取根域名 (sub.example.com -> example.com)
                    local _root
                    _root=$(echo "$_host" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print}')
                    case "$_root" in
                        github.com|githubusercontent.com|gstatic.com|cloudflare.com) continue ;;
                    esac
                    if ! grep -qF "+.${_root}" "$output_file" 2>/dev/null; then
                        _inject_ns="${_inject_ns}    \"+.${_root}\": [223.5.5.5, 114.114.114.114]\n"
                    fi
                done < <(echo "$_prov_block" | grep -oE "https?://[^\"' ]+" | sort -u)
                if [[ -n "$_inject_ns" ]]; then
                    local _tmpf
                    _tmpf=$(mktemp "${output_dir}/.clash-config.yaml.policy.XXXXXX") || {
                        print_error "创建 nameserver-policy 临时文件失败"
                        rm -rf "$output_dir"
                        pause; return
                    }
                    chmod 600 "$_tmpf" 2>/dev/null || true
                    if grep -q 'nameserver-policy:' "$output_file"; then
                        if awk -v ns="$_inject_ns" '
                            /nameserver-policy:/ { print; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf"; then
                            mv "$_tmpf" "$output_file" || {
                                rm -f "$_tmpf"
                                print_error "nameserver-policy 注入失败"
                                rm -rf "$output_dir"
                                pause; return
                            }
                        else
                            rm -f "$_tmpf"
                            print_error "nameserver-policy 注入失败"
                            rm -rf "$output_dir"
                            pause; return
                        fi
                    elif grep -q '^dns:' "$output_file"; then
                        if awk -v ns="$_inject_ns" '
                            /^dns:/ { print; print "  nameserver-policy:"; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf"; then
                            mv "$_tmpf" "$output_file" || {
                                rm -f "$_tmpf"
                                print_error "nameserver-policy 注入失败"
                                rm -rf "$output_dir"
                                pause; return
                            }
                        else
                            rm -f "$_tmpf"
                            print_error "nameserver-policy 注入失败"
                            rm -rf "$output_dir"
                            pause; return
                        fi
                    else
                        rm -f "$_tmpf"
                    fi
                fi
            fi

            draw_line
            print_success "配置已生成!"
            draw_line
            echo -e "文件路径: ${C_CYAN}${output_file}${C_RESET}"
            echo "查看方式:
  1. 在终端显示完整配置
  2. 仅显示注入的部分
  3. 跳过"
            read -e -r -p "选择 [3]: " view_mode
            view_mode=${view_mode:-3}
            case $view_mode in
                1) echo ""; cat "$output_file"; echo "" ;;
                2)
                    echo -e "${C_CYAN}=== WireGuard 节点 ===${C_RESET}"
                    echo "$all_proxy_yaml"
                    echo -e "${C_CYAN}=== VPN 分组 ===${C_RESET}"
                    echo "$wg_group_yaml"
                    echo -e "${C_CYAN}=== 路由规则 ===${C_RESET}"
                    echo -n "$wg_rules_yaml"
                    echo ""
                    ;;
            esac
            echo -e "${C_CYAN}下载命令:${C_RESET}"
            echo "  scp root@$(_wg_clash_db_get "$mode" '.server.endpoint'):${output_file} ./clash-config.yaml"
            draw_line
            ;;
        0|"") return ;;
        *) print_error "无效选项" ;;
    esac
    echo -e "${C_YELLOW}[重要提示]${C_RESET}"
    echo "  • 需要 Clash Meta (mihomo) 内核 1.14.0+
  • OpenClash 设置中需切换到 Meta 内核"
    if [[ ${#all_proxy_names[@]} -gt 1 ]]; then
        echo "  • 多节点模式下，所有服务器必须已同步相同的 peers 配置
  • 使用 '同步 Peers 到所有节点' 确保配置一致"
    fi
    log_action "Clash WireGuard config generated: ${peer_name} nodes=${#all_proxy_names[@]}"
    pause
}
wg_setup_watchdog() {
    wg_check_installed || return 1
    local watchdog_script="/usr/local/bin/wg-watchdog.sh"
    local watchdog_log="/var/log/wg-watchdog.log"
    local auto_mode="${1:-}"

    # 已启用时的管理界面
    if [[ -z "$auto_mode" ]] && cron_has_job_command "$watchdog_script"; then
        print_title "WireGuard 看门狗"
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
        echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
        echo "  1. 禁用看门狗
  2. 查看日志
  3. 手动触发一次检测
  0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1)
                cron_remove_job_command "$watchdog_script"
                rm -f "$watchdog_script"
                print_success "看门狗已禁用"
                log_action "WireGuard watchdog disabled"
                ;;
            2) echo ""; tail -n 30 "$watchdog_log" 2>/dev/null || print_warn "无日志" ;;
            3)
                if [[ -x "$watchdog_script" ]]; then
                    sh "$watchdog_script"
                    print_success "检测完成"
                    echo ""; tail -n 5 "$watchdog_log" 2>/dev/null
                else
                    print_warn "看门狗脚本不存在"
                fi
                ;;
        esac
        pause; return
    fi

    if [[ -z "$auto_mode" ]]; then
        print_title "WireGuard 服务端看门狗"
        echo "看门狗功能:
  • 每分钟检测 wg0 接口状态
  • 接口消失 → 立即拉起
  • wg show 失败 → 重启接口"
        if ! confirm "启用看门狗?"; then pause; return; fi
    fi

    mkdir -p "$(dirname "$watchdog_script")" || { print_error "创建看门狗目录失败"; [[ -z "$auto_mode" ]] && pause; return 1; }
    local watchdog_tmp
    watchdog_tmp=$(mktemp "$(dirname "$watchdog_script")/.tmp.server-manage.wg-watchdog.XXXXXX") || {
        print_error "创建看门狗临时脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    }
    _tmp_register "$watchdog_tmp"

    # ── OpenWrt 看门狗 (#!/bin/sh + ifup/ifdown + Mihomo bypass + 路由检查) ──
    if ! cat > "$watchdog_tmp" << 'WDEOF_OPENWRT'
#!/bin/sh
LOG="logger -t wg-watchdog"
DB="/etc/wireguard/db/wg-data.json"

wg_nft_addr_family_for_cidr() {
    case "$1" in
        *:*) echo "ip6" ;;
        *)   echo "ip" ;;
    esac
}

# 检测接口存活
if ! ifstatus wg0 >/dev/null 2>&1; then
    $LOG "wg0 down, restarting"
    ifup wg0
    sleep 2
fi

# 检测 wg show 是否正常
if ! wg show wg0 >/dev/null 2>&1; then
    $LOG "wg show failed, restarting"
    ifdown wg0; sleep 1; ifup wg0
    sleep 2
fi

# 检测 Mihomo bypass 规则是否存在
if nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1; then
    NFT_RULES=$(nft list chain inet fw4 mangle_prerouting 2>/dev/null)
    if ! echo "$NFT_RULES" | grep -q "wg_bypass_iface"; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null || true
        $LOG "restored wg_bypass_iface rule"
    fi
    if [ -f "$DB" ] && command -v jq >/dev/null 2>&1; then
        jq -r '[.server.subnet, (.server.server_lan_subnet // empty), (.peers[]? | select(.enabled == true and .is_gateway == true) | .lan_subnets // empty)] | .[] | select(. != null and . != "")' "$DB" 2>/dev/null | \
        tr ',' '\n' | while IFS= read -r sub; do
            sub=$(echo "$sub" | xargs)
            [ -z "$sub" ] && continue
            if ! echo "$NFT_RULES" | grep -q "daddr $sub"; then
                NFT_FAMILY=$(wg_nft_addr_family_for_cidr "$sub")
                nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$sub" counter return comment "wg_bypass_subnet" 2>/dev/null || true
                $LOG "restored wg_bypass_subnet rule: $sub"
            fi
        done
    fi
fi

# 检测网关 peer LAN 路由是否存在
if [ -f "$DB" ] && command -v jq >/dev/null 2>&1; then
    jq -r '.peers[] | select(.enabled == true and .is_gateway == true) | .lan_subnets // empty' "$DB" 2>/dev/null | \
    tr ',' '\n' | while IFS= read -r sub; do
        sub=$(echo "$sub" | xargs)
        [ -z "$sub" ] && continue
        if ! ip route show "$sub" dev wg0 2>/dev/null | grep -q .; then
            $LOG "route missing: $sub dev wg0, adding"
            ip route replace "$sub" dev wg0 2>/dev/null || true
        fi
    done
fi
WDEOF_OPENWRT
    then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "写入看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    chmod 0755 "$watchdog_tmp" 2>/dev/null || true
    if ! mv "$watchdog_tmp" "$watchdog_script"; then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "安装看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    _tmp_unregister "$watchdog_tmp"
    if ! cron_add_job_command "$watchdog_script" "* * * * * $watchdog_script >/dev/null 2>&1"; then
        rm -f "$watchdog_script" 2>/dev/null || true
        print_error "安装看门狗 cron 任务失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo "  检测: 接口存活 → wg show → Mihomo bypass 规则"
    log_action "WireGuard watchdog enabled (platform=openwrt)"
    [[ -z "$auto_mode" ]] && pause
}

wg_export_peers() {
    wg_check_server || return 1
    print_title "导出 WireGuard 设备配置"
    local peer_count
    if ! peer_count=$(wg_db_get '.peers | length') || [[ ! "$peer_count" =~ ^[0-9]+$ ]]; then
        print_error "读取设备数量失败"
        pause; return 1
    fi
    if [[ "$peer_count" -eq 0 ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(wg_shared_export_file) || { print_error "无法创建导出文件"; pause; return 1; }
    if jq '{
        export_version: 2,
        export_date: (now | todate),
        server: {
            endpoint: .server.endpoint,
            port: .server.port,
            subnet: .server.subnet,
            dns: .server.dns,
            public_key: .server.public_key,
            server_lan_subnet: .server.server_lan_subnet
        },
        peers: .peers
    }' "$WG_DB_FILE" > "$export_file" 2>/dev/null; then
        print_success "已导出 $peer_count 个设备到:"
        echo -e "  ${C_CYAN}${export_file}${C_RESET}"
        local fsize=$(du -h "$export_file" 2>/dev/null | awk '{print $1}')
        echo "  文件大小: $fsize"
        echo ""
        print_warn "该文件包含私钥等敏感信息，请妥善保管！"
        echo "可使用 [导入设备配置] 在其他服务器恢复。"
        log_action "WireGuard peers exported: count=$peer_count file=$export_file"
    else
        print_error "导出失败"
        rm -f "$export_file" 2>/dev/null || true
        pause; return 1
    fi
    pause
}

_wg_openwrt_import_snapshot_clients() {
    local backup_dir="$1"
    mkdir -p "$(dirname "$backup_dir")" || return 1
    rm -rf "$backup_dir" 2>/dev/null || true
    if [[ -d /etc/wireguard/clients ]]; then
        cp -a /etc/wireguard/clients "$backup_dir" || return 1
    else
        mkdir -p "$backup_dir" || return 1
    fi
}

_wg_openwrt_import_restore_snapshot() {
    local db_snapshot="${1:-}" client_backup="${2:-}"
    [[ -n "$db_snapshot" ]] && wg_write_private_file "$WG_DB_FILE" "$db_snapshot" >/dev/null 2>&1 || true
    if [[ -n "$client_backup" && -d "$client_backup" ]]; then
        rm -rf /etc/wireguard/clients 2>/dev/null || true
        mkdir -p /etc/wireguard 2>/dev/null || true
        cp -a "$client_backup" /etc/wireguard/clients 2>/dev/null || true
    fi
    wg_rebuild_uci_conf "no_reload" >/dev/null 2>&1 || true
    wg_regenerate_client_confs >/dev/null 2>&1 || true
    wg_apply_runtime_conf >/dev/null 2>&1 || true
    wg_mihomo_bypass_rebuild >/dev/null 2>&1 || true
}

wg_import_peers() {
    wg_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return 1
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return 1
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return 1
    fi
    echo -e "发现 ${C_CYAN}${import_count}${C_RESET} 个设备:"
    jq -r '.peers[] | "  - \(.name) (\(.ip))"' "$import_file" 2>/dev/null
    echo ""
    echo "导入模式:
  1. 完整导入 (保留原始密钥，适用于服务器迁移/endpoint 不变)
  2. 重新生成密钥 (适用于新服务器，需重新下发客户端配置)
  0. 返回
"
    read -e -r -p "选择: " mode
    [[ "$mode" == "0" || -z "$mode" ]] && return
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return 1; }

    local db_snapshot client_backup
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    client_backup=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-import-clients.XXXXXX") || {
        print_error "创建客户端配置快照目录失败"; pause; return 1;
    }
    chmod 700 "$client_backup" 2>/dev/null || true
    if ! _wg_openwrt_import_snapshot_clients "$client_backup/clients"; then
        rm -rf "$client_backup" 2>/dev/null || true
        print_error "备份客户端配置失败"; pause; return 1
    fi

    local existing_count
    existing_count=$(wg_db_get '.peers | length')
    local merge_mode="1"
    if [[ "$existing_count" -gt 0 ]]; then
        print_warn "当前已有 $existing_count 个设备。"
        echo "  1. 追加 (跳过同名/同IP设备)
  2. 覆盖 (删除所有现有设备后导入)"
        read -e -r -p "选择 [1]: " merge_mode
        merge_mode=${merge_mode:-1}
        if [[ "$merge_mode" == "2" ]]; then
            if ! confirm "确认删除所有现有设备?"; then
                rm -rf "$client_backup" 2>/dev/null || true
                return
            fi
            # 先从运行中的接口移除所有 peer
            if wg_is_running; then
                local pc=$(wg_db_get '.peers | length') pi=0
                while [[ $pi -lt $pc ]]; do
                    local pk=$(wg_db_get ".peers[$pi].public_key")
                    wg set "$WG_INTERFACE" peer "$pk" remove 2>/dev/null || true
                    pi=$((pi + 1))
                done
            fi
            if ! wg_db_set '.peers = []'; then
                _wg_openwrt_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
                rm -rf "$client_backup" 2>/dev/null || true
                print_error "清空现有设备失败，已恢复原配置"
                pause; return 1
            fi
            rm -f /etc/wireguard/clients/*.conf 2>/dev/null
        fi
    fi

    local imported=0 skipped=0
    local i=0
    while [[ $i -lt $import_count ]]; do
        local name ip privkey pubkey psk allowed enabled is_gw lans created peer_type route_mode
        name=$(jq -r ".peers[$i].name" "$import_file")
        ip=$(jq -r ".peers[$i].ip" "$import_file")
        privkey=$(jq -r ".peers[$i].private_key" "$import_file")
        pubkey=$(jq -r ".peers[$i].public_key" "$import_file")
        psk=$(jq -r ".peers[$i].preshared_key" "$import_file")
        allowed=$(jq -r ".peers[$i].client_allowed_ips" "$import_file")
        enabled=$(jq -r ".peers[$i].enabled // true" "$import_file")
        is_gw=$(jq -r ".peers[$i].is_gateway // false" "$import_file")
        lans=$(jq -r ".peers[$i].lan_subnets // empty" "$import_file")
        created=$(jq -r ".peers[$i].created // empty" "$import_file")
        peer_type=$(jq -r ".peers[$i].peer_type // empty" "$import_file")
        route_mode=$(jq -r ".peers[$i].route_mode // empty" "$import_file")
        # 兼容旧版 JSON: 无 peer_type 时根据 is_gateway 推断
        if [[ -z "$peer_type" || "$peer_type" == "null" ]]; then
            [[ "$is_gw" == "true" ]] && peer_type="gateway" || peer_type="standard"
        fi
        [[ -z "$route_mode" || "$route_mode" == "null" ]] && route_mode="managed"
        [[ "$enabled" == "true" || "$enabled" == "false" ]] || enabled=true
        [[ "$is_gw" == "true" || "$is_gw" == "false" ]] || is_gw=false

        if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            print_warn "跳过: $name (名称格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_ip "$ip"; then
            print_warn "跳过: $name (IP 格式无效: $ip)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if [[ -z "$allowed" || "$allowed" == "null" ]] || ! validate_cidr_list "$allowed"; then
            print_warn "跳过: $name (AllowedIPs 格式无效: $allowed)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_cidr_list "$lans"; then
            print_warn "跳过: $name (LAN 网段格式无效: $lans)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        case "$peer_type" in
            standard|gateway) ;;
            *) print_warn "跳过: $name (设备类型无效: $peer_type)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac
        case "$route_mode" in
            managed|custom|full|vpn) ;;
            *) print_warn "跳过: $name (路由模式无效: $route_mode)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac

        # 检查重名
        local exists
        exists=$(wg_db_get --arg n "$name" '.peers[] | select(.name == $n) | .name')
        if [[ -n "$exists" ]]; then
            print_warn "跳过: $name (名称已存在)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        # 检查 IP 冲突
        local ip_exists
        ip_exists=$(wg_db_get --arg ip "$ip" '.peers[] | select(.ip == $ip) | .ip')
        if [[ -n "$ip_exists" ]]; then
            print_warn "跳过: $name (IP $ip 已被使用)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        if [[ "$mode" == "2" ]]; then
            privkey=$(wg genkey)
            pubkey=$(echo "$privkey" | wg pubkey)
            psk=$(wg genpsk)
        fi
        if ! validate_wg_key "$privkey"; then
            print_warn "跳过: $name (私钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$pubkey"; then
            print_warn "跳过: $name (公钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$psk"; then
            print_warn "跳过: $name (预共享密钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        [[ -z "$created" || "$created" == "null" ]] && created=$(date '+%Y-%m-%d %H:%M:%S')

        if ! wg_db_set --arg name "$name" \
                  --arg ip "$ip" \
                  --arg privkey "$privkey" \
                  --arg pubkey "$pubkey" \
                  --arg psk "$psk" \
                  --arg allowed "$allowed" \
                  --argjson enabled "$enabled" \
                  --arg created "$created" \
                  --arg gw "$is_gw" \
                  --arg lans "$lans" \
                  --arg ptype "$peer_type" \
                  --arg route_mode "$route_mode" \
            '.peers += [{
                name: $name,
                ip: $ip,
                private_key: $privkey,
                public_key: $pubkey,
                preshared_key: $psk,
                client_allowed_ips: $allowed,
                enabled: $enabled,
                created: $created,
                is_gateway: ($gw == "true"),
                lan_subnets: $lans,
                peer_type: $ptype,
                route_mode: $route_mode
            }]'; then
            _wg_openwrt_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "导入 $name 时数据库写入失败，已恢复原配置"
            pause; return 1
        fi
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        if ! wg_rebuild_uci_conf "no_reload" || ! wg_apply_runtime_conf || ! wg_regenerate_client_confs; then
            _wg_openwrt_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "WireGuard 运行配置热应用失败，已恢复原配置"
            pause; return 1
        fi
    fi
    rm -rf "$client_backup" 2>/dev/null || true
    echo ""
    print_success "导入完成: 成功 ${imported}, 跳过 ${skipped}"
    [[ "$mode" == "2" ]] && print_warn "已重新生成密钥，请重新下发所有客户端配置。"
    log_action "WireGuard peers imported: imported=$imported skipped=$skipped mode=$mode"
    pause
}

wg_server_menu() {
    while true; do
        print_title "WireGuard 服务端管理"
        local srv_name=$(wg_get_server_name)
        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        fi
        local peer_count=$(wg_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"
        echo "  [设备管理]
  1. 查看状态
  2. 添加设备
  3. 删除设备
  4. 启用/禁用设备
  5. 查看设备配置/二维码
  6. 生成 Clash/OpenClash 配置
  [服务控制]
  7. 启动 WireGuard
  8. 停止 WireGuard
  9. 重启 WireGuard
  10. 修改服务端配置
  11. 修改服务器名称
  12. 卸载 WireGuard
  13. 生成 OpenWrt 清空 WG 配置命令
  14. 服务端看门狗 (自动重启保活)
  15. Mihomo bypass 规则管理
  18. 仅修改公网端点 (不重载 wg0)
  19. 生成 OpenWrt 客户端 endpoint 迁移命令
  [数据管理]
  16. 导出设备配置 (JSON)
  17. 导入设备配置 (JSON)
  0. 返回上级菜单
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice
        case $choice in
            1) wg_server_status ;;
            2) wg_add_peer ;;
            3) wg_delete_peer ;;
            4) wg_toggle_peer ;;
            5) wg_show_peer_conf ;;
            6) wg_generate_clash_config ;;
            7) wg_start; pause ;;
            8) wg_stop; pause ;;
            9) wg_restart; pause ;;
            10) wg_modify_server ;;
            11) wg_rename_server ;;
            12) wg_uninstall; return ;;
            13) wg_openwrt_clean_cmd ;;
            14) wg_setup_watchdog ;;
            15) wg_mihomo_bypass_status ;;
            16) wg_export_peers ;;
            17) wg_import_peers ;;
            18) wg_modify_server_endpoint_only ;;
            19) wg_show_openwrt_endpoint_migrate_cmd ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}


wg_install_menu() {
    wg_server_install
}

wg_main_menu() {
    while true; do
        if wg_is_installed; then
            local role
            role=$(wg_get_role)
            local server_private_key=""
            server_private_key=$(wg_db_get '.server.private_key // empty')
            if [[ "$role" == "server" ]] || { [[ "$role" == "none" || -z "$role" ]] && [[ -f "$WG_CONF" ]] && [[ -n "$server_private_key" && "$server_private_key" != "null" ]]; }; then
                [[ "$role" == "server" ]] || wg_set_role "server"
                print_title "WireGuard VPN"
                local srv_name
                srv_name=$(wg_get_server_name)
                if wg_is_running; then
                    echo -e "  状态: ${C_GREEN}运行中${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                else
                    echo -e "  状态: ${C_RED}已停止${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                fi
                echo ""
                echo "1. 服务端管理"
                echo "2. 卸载 WireGuard"
                echo "0. 返回主菜单"
                read -e -r -p "选择: " c
                case "$c" in
                    1) wg_server_menu ;;
                    2) wg_uninstall ;;
                    0|q|Q|"") return ;;
                    *) print_warn "无效选项"; pause ;;
                esac
            else
                print_warn "WireGuard 已安装但无配置文件"
                echo "  1. 重新安装服务端
  2. 卸载
  0. 返回"
                read -e -r -p "选择: " rc
                case $rc in
                    1) wg_server_install; continue ;;
                    2) wg_uninstall; continue ;;
                    *) return ;;
                esac
            fi
        else
            print_title "WireGuard VPN"
            echo -e "  状态: ${C_YELLOW}未安装${C_RESET}"
            echo ""
            echo "1. 安装 WireGuard 服务端"
            echo "0. 返回主菜单"
            read -e -r -p "选择: " c
            case "$c" in
                1) wg_server_install ;;
                0|q|Q|"") return ;;
                *) print_warn "无效选项"; pause ;;
            esac
        fi
    done
}

# Debian/Ubuntu 环境兼容性全面检测
# 返回 0 = 全部通过，返回 1 = 有致命项失败
wg_deb_check_compat() {
    echo -e "\n${C_CYAN}[Debian/Ubuntu 环境兼容性检测]${C_RESET}"
    draw_line

    local fatal=0 warn=0

    # ── [必须] 平台确认 ──
    if [[ "$PLATFORM" == "debian" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   平台: Debian/Ubuntu"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} 平台: ${PLATFORM} (此模块仅支持 Debian/Ubuntu)"
        fatal=$((fatal + 1))
    fi

    # ── [信息] 发行版详情 ──
    if [[ -f /etc/os-release ]]; then
        local distro version
        distro=$(grep 'PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d'"' -f2)
        version=$(grep 'VERSION_ID' /etc/os-release 2>/dev/null | cut -d'"' -f2)
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 发行版: ${distro:-未知}"
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 版本号: ${version:-未知}"
    fi

    # ── [必须] apt 包管理器 ──
    if command -v apt-get &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   apt 包管理器可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} apt 不可用 (无法安装软件包)"
        fatal=$((fatal + 1))
    fi

    # ── [检测] 内核 WireGuard 支持 ──
    local wg_kernel=false
    if [[ -d /sys/module/wireguard ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    elif lsmod 2>/dev/null | grep -q wireguard; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    fi
    if [[ "$wg_kernel" != "true" ]]; then
        local kver
        kver=$(uname -r | cut -d'.' -f1-2)
        local kmajor kminor
        kmajor=$(echo "$kver" | cut -d'.' -f1)
        kminor=$(echo "$kver" | cut -d'.' -f2)
        if [[ "$kmajor" -gt 5 ]] || [[ "$kmajor" -eq 5 && "$kminor" -ge 6 ]]; then
            echo -e "  ${C_CYAN}[INFO]${C_RESET} 内核 $(uname -r) (≥5.6, 内置 WireGuard 支持)"
        else
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} 内核 $(uname -r) (<5.6, 可能需要 wireguard-dkms)"
            warn=$((warn + 1))
        fi
    fi

    # ── [推荐] jq ──
    if command -v jq &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   jq 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} jq 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [推荐] wg 工具 ──
    if command -v wg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   wireguard-tools 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} wireguard-tools 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [推荐] qrencode ──
    if command -v qrencode &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   qrencode 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} qrencode 未安装 (二维码功能不可用，不影响核心功能)"
        warn=$((warn + 1))
    fi

    # ── [检测] iptables ──
    if command -v iptables &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   iptables 可用"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} iptables 不可用 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [信息] IP 转发状态 ──
    local ipfwd
    ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "$ipfwd" == "1" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   IP 转发已启用"
    else
        echo -e "  ${C_CYAN}[INFO]${C_RESET} IP 转发未启用 (安装时将自动开启)"
    fi

    # ── [信息] systemd ──
    if command -v systemctl &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   systemd 可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} systemd 不可用 (wg-quick 服务依赖 systemd)"
        fatal=$((fatal + 1))
    fi

    # ── [信息] 本机网络 ──
    echo -e "\n${C_CYAN}  本机网络地址:${C_RESET}"
    wg_check_public_ip

    # ── 汇总 ──
    draw_line
    if [[ $fatal -gt 0 ]]; then
        echo -e "  ${C_RED}检测结果: ${fatal} 项致命错误, ${warn} 项警告${C_RESET}"
        print_error "环境不满足安装条件，请先解决上述 [FAIL] 项"
        return 1
    elif [[ $warn -gt 0 ]]; then
        echo -e "  ${C_YELLOW}检测结果: 全部通过, ${warn} 项警告${C_RESET}"
        print_success "环境检测通过 (存在警告但不影响安装)"
    else
        echo -e "  ${C_GREEN}检测结果: 全部通过${C_RESET}"
        print_success "Debian/Ubuntu 环境完全兼容"
    fi
    return 0
}
# 使用 wg_deb_ 前缀隔离平台入口；DB/role 路径通过 WG_SHARED_* 显式共享，便于跨平台导入/管理。

readonly WG_DEB_INTERFACE="wg0"
readonly WG_DEB_DB_DIR="${WG_SHARED_DB_DIR}"
readonly WG_DEB_DB_FILE="${WG_SHARED_DB_FILE}"
readonly WG_DEB_CONF="/etc/wireguard/${WG_DEB_INTERFACE}.conf"
readonly WG_DEB_ROLE_FILE="${WG_SHARED_ROLE_FILE}"
readonly WG_DEB_CLIENT_DIR="/etc/wireguard/clients"

wg_deb_db_init() { wg_shared_db_init; }
wg_deb_db_get() { wg_shared_db_get "$@"; }
wg_deb_db_set() { wg_shared_db_set "$@"; }
wg_deb_get_role() { wg_shared_get_role; }
wg_deb_set_role() { wg_shared_set_role "$@"; }

wg_deb_is_installed() { command_exists wg && [[ -f "$WG_DEB_DB_FILE" ]]; }
wg_deb_is_running()   { ip link show "$WG_DEB_INTERFACE" &>/dev/null; }

wg_deb_get_server_name() {
    local name
    name=$(wg_deb_db_get '.server.name // empty')
    if [[ -z "$name" || "$name" == "null" ]]; then
        name=$(hostname -s 2>/dev/null)
        [[ -z "$name" ]] && name="server"
    fi
    echo "$name"
}

wg_deb_rename_server() {
    print_title "修改服务器名称"
    local current_name=$(wg_deb_get_server_name)
    echo -e "  当前名称: ${C_CYAN}${current_name}${C_RESET}"
    local new_name=""
    read -e -r -p "新名称 [${current_name}]: " new_name
    new_name=${new_name:-$current_name}
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "名称只能包含字母、数字、下划线、连字符"
        pause; return
    fi
    wg_deb_db_set --arg n "$new_name" '.server.name = $n'
    print_success "服务器名称已更新为: ${new_name}"
    log_action "WireGuard(deb) server renamed: ${current_name} -> ${new_name}"
    pause
}

wg_deb_check_installed() {
    if ! wg_deb_is_installed; then
        print_error "WireGuard 未安装，请先执行安装。"
        pause; return 1
    fi
    return 0
}

wg_deb_check_server() {
    wg_deb_check_installed || return 1
    if [[ "$(wg_deb_get_role)" != "server" ]]; then
        print_error "当前不是服务端模式，此功能仅服务端可用。"
        pause; return 1
    fi
    return 0
}

wg_deb_select_peer() {
    local prompt="${1:-选择设备序号}" show_status="${2:-false}"
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"; pause; return 1
    fi
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip mark=""
        name=$(wg_deb_db_get ".peers[$i].name")
        ip=$(wg_deb_db_get ".peers[$i].ip")
        if [[ "$show_status" == "true" ]]; then
            local enabled
            enabled=$(wg_deb_db_get ".peers[$i].enabled")
            [[ "$enabled" == "true" ]] && mark=" ${C_GREEN}(已启用)${C_RESET}" || mark=" ${C_RED}(已禁用)${C_RESET}"
        fi
        local is_gw
        is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
        [[ "$is_gw" == "true" ]] && mark+=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回
"
    local idx
    read -e -r -p "${prompt}: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return 1
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return 1
    fi
    REPLY=$((idx - 1))
    return 0
}

wg_deb_install_packages() {
    print_info "安装 WireGuard 软件包..."
    apt-get update -qq >/dev/null 2>&1
    local essential_pkgs=(wireguard wireguard-tools jq iptables)
    local optional_pkgs=(qrencode)
    for pkg in "${essential_pkgs[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            apt-get install -y -qq "$pkg" >/dev/null 2>&1 || { print_error "安装 $pkg 失败"; return 1; }
        fi
    done
    for pkg in "${optional_pkgs[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            apt-get install -y -qq "$pkg" >/dev/null 2>&1 || print_warn "安装 $pkg 失败（不影响核心功能）"
        fi
    done
    print_success "软件包安装完成"
    return 0
}

wg_deb_next_ip() {
    local subnet prefix
    subnet=$(wg_deb_db_get '.server.subnet')
    prefix=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local used_ips
    used_ips=$(wg_deb_db_get '[.server.ip] + [.peers[].ip] | join(" ")')
    local next
    for next in $(seq 2 254); do
        local candidate="${prefix}.${next}"
        printf '%s\n' $used_ips | grep -Fxq -- "$candidate" || { echo "$candidate"; return 0; }
    done
    print_error "子网 IP 已耗尽"; return 1
}

wg_deb_format_bytes() {
    local bytes=$1
    [[ -z "$bytes" || "$bytes" == "0" ]] && { echo "0 B"; return; }
    awk -v b="$bytes" 'BEGIN {
        if (b>=1073741824) printf "%.2f GB",b/1073741824
        else if (b>=1048576) printf "%.2f MB",b/1048576
        else if (b>=1024) printf "%.2f KB",b/1024
        else printf "%d B",b
    }'
}

# 检测默认出口网卡
wg_deb_detect_default_iface() {
    ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1
}

_wg_deb_cleanup_nat_iface() {
    local subnet="${1:-}" iface="${2:-}"
    [[ -n "$subnet" && -n "$iface" && "$iface" != "null" ]] || return 0
    command_exists iptables || return 0
    iptables -t nat -D POSTROUTING -s "$subnet" -o "$iface" -j MASQUERADE >/dev/null 2>&1 || true
}

# 生成 /etc/wireguard/wg0.conf (Debian 的运行配置)
wg_deb_rebuild_conf() {
    [[ "$(wg_deb_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_deb_db_get '.server.private_key')
    port=$(wg_deb_db_get '.server.port')
    subnet=$(wg_deb_db_get '.server.subnet')
    server_ip=$(wg_deb_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        log_action "wg_deb_rebuild_conf failed: missing fields" "ERROR"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT

    # 检测默认出口网卡
    local def_iface
    def_iface=$(wg_deb_db_get '.server.default_iface // empty')
    [[ -z "$def_iface" || "$def_iface" == "null" ]] && def_iface=$(wg_deb_detect_default_iface)
    [[ -z "$def_iface" ]] && def_iface="eth0"

    local conf_content
    conf_content=$(
    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "MTU = ${mtu}"
        echo ""
        echo "# NAT + 转发规则"
        echo "PostUp = sysctl -qw net.ipv4.ip_forward=1"
        echo "PostUp = iptables -t nat -A POSTROUTING -s ${subnet} -o ${def_iface} -j MASQUERADE"
        echo "PostUp = iptables -A FORWARD -i ${WG_DEB_INTERFACE} -j ACCEPT"
        echo "PostUp = iptables -A FORWARD -o ${WG_DEB_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT"
        echo "PostDown = iptables -t nat -D POSTROUTING -s ${subnet} -o ${def_iface} -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i ${WG_DEB_INTERFACE} -j ACCEPT"
        echo "PostDown = iptables -D FORWARD -o ${WG_DEB_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT"

        local pc=$(wg_deb_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_deb_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo ""
                echo "[Peer]"
                echo "# $(wg_deb_db_get ".peers[$i].name")"
                echo "PublicKey = $(wg_deb_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_deb_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_deb_db_get ".peers[$i].ip")
                local is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_deb_db_get ".peers[$i].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
                echo "PersistentKeepalive = 25"
            fi
            i=$((i + 1))
        done
    }
)
    wg_write_private_file "$WG_DEB_CONF" "$conf_content"
}

wg_deb_regenerate_client_confs() {
    local pc=$(wg_deb_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport endpoint sdns mask mtu
    spub=$(wg_deb_db_get '.server.public_key')
    sep=$(wg_deb_db_get '.server.endpoint')
    sport=$(wg_deb_db_get '.server.port')
    endpoint=$(wg_shared_format_endpoint "$sep" "$sport")
    sdns=$(wg_deb_db_get '.server.dns')
    mask=$(echo "$(wg_deb_db_get '.server.subnet')" | cut -d'/' -f2)
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    mkdir -p "$WG_DEB_CLIENT_DIR"
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_deb_db_get ".peers[$i].name")
        local is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
        local conf_content="[Interface]
PrivateKey = $(wg_deb_db_get ".peers[$i].private_key")
Address = $(wg_deb_db_get ".peers[$i].ip")/${mask}
MTU = ${mtu}"
        [[ "$is_gw" != "true" ]] && conf_content+=$'\n'"DNS = ${sdns}"
        conf_content+="
[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_deb_db_get ".peers[$i].preshared_key")
Endpoint = ${endpoint}
AllowedIPs = $(wg_deb_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        wg_write_private_file "${WG_DEB_CLIENT_DIR}/${name}.conf" "$conf_content" || return 1
        i=$((i + 1))
    done
}

wg_deb_apply_conf() {
    wg_deb_rebuild_conf || return 1
    wg_deb_regenerate_client_confs || return 1
    wg_deb_is_running || return 0
    local tmp_dir tmp
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-deb-sync.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    tmp="${tmp_dir}/sync.conf"
    awk '
        /^\[Interface\]$/ { section="interface"; print; next }
        /^\[Peer\]$/ { section="peer"; print; next }
        section=="interface" && /^(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
        section=="peer" && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
    ' "$WG_DEB_CONF" > "$tmp" || { rm -rf "$tmp_dir"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true
    if wg syncconf "$WG_DEB_INTERFACE" "$tmp" >/dev/null 2>&1; then
        rm -rf "$tmp_dir"
        wg_deb_sync_peer_routes || return 1
        return 0
    fi
    rm -rf "$tmp_dir"
    return 1
}

wg_deb_sync_peer_routes() {
    wg_deb_is_running || return 0
    wg_shared_sync_gateway_routes wg_deb_db_get "$WG_DEB_INTERFACE"
}
_wg_deb_ufw_has_udp_allow() {
    local port="${1:-}"
    validate_port "$port" || return 1
    command_exists ufw || return 1
    LANG=C ufw show added 2>/dev/null | awk -v rule="${port}/udp" '
        $1 == "ufw" && $2 == "allow" && $3 == rule { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_wg_deb_rollback_new_udp_allow() {
    local port="${1:-}" added="${2:-false}" non_ufw_backends="${3:-}"
    validate_port "$port" || return 0
    if [[ "$added" == "true" ]] && command_exists ufw && ufw_is_active; then
        ufw delete allow "$port"/udp >/dev/null 2>&1 || true
    fi
    if [[ -n "$non_ufw_backends" ]] && declare -F firewall_rollback_udp_port >/dev/null; then
        firewall_rollback_udp_port "$port" "$non_ufw_backends" "WireGuard-Debian"
    fi
}

_wg_deb_rollback_server_port_change() {
    local cur_port="${1:-}" new_port="${2:-}" added="${3:-false}" rebuild="${4:-false}" non_ufw_backends="${5:-}"
    if validate_port "$cur_port"; then
        if ! wg_deb_db_set --argjson p "$cur_port" '.server.port = $p' >/dev/null 2>&1; then
            print_warn "端口回滚写入数据库失败，请手动检查 WireGuard 配置。"
        elif [[ "$rebuild" == "true" ]]; then
            wg_deb_rebuild_conf >/dev/null 2>&1 || print_warn "端口回滚后重建服务端配置失败，请手动检查。"
            wg_deb_regenerate_client_confs >/dev/null 2>&1 || print_warn "端口回滚后重建客户端配置失败，请手动检查。"
        fi
    fi
    _wg_deb_rollback_new_udp_allow "$new_port" "$added" "$non_ufw_backends"
}

_wg_deb_rollback_server_modify() {
    local snapshot="${1:-}" cur_port="${2:-}" new_port="${3:-}" added="${4:-false}" rebuild="${5:-false}" non_ufw_backends="${6:-}"
    if [[ -n "$snapshot" ]]; then
        if ! wg_write_private_file "$WG_DEB_DB_FILE" "$snapshot" >/dev/null 2>&1; then
            print_warn "服务端配置回滚写入数据库失败，请手动检查 WireGuard 配置。"
        elif [[ "$rebuild" == "true" ]]; then
            wg_deb_rebuild_conf >/dev/null 2>&1 || print_warn "服务端配置回滚后重建服务端配置失败，请手动检查。"
            wg_deb_regenerate_client_confs >/dev/null 2>&1 || print_warn "服务端配置回滚后重建客户端配置失败，请手动检查。"
        fi
    else
        _wg_deb_rollback_server_port_change "$cur_port" "$new_port" "$added" "$rebuild" "$non_ufw_backends"
        return
    fi
    _wg_deb_rollback_new_udp_allow "$new_port" "$added" "$non_ufw_backends"
}

_wg_deb_rollback_server_install() {
    local wg_port="${1:-}" wg_udp_rule_added="${2:-false}" snapshot_dir="${3:-}"
    local db_existed="${4:-false}" role_existed="${5:-false}" conf_existed="${6:-false}"
    local non_ufw_backends="${7:-}"

    systemctl stop "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1 || true
    systemctl disable "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1 || true

    if [[ "$db_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/db" ]]; then
        mkdir -p "$(dirname "$WG_DEB_DB_FILE")" 2>/dev/null || true
        cp -p "${snapshot_dir}/db" "$WG_DEB_DB_FILE" 2>/dev/null || print_warn "恢复 WireGuard 数据库失败，请手动检查。"
    else
        rm -f "$WG_DEB_DB_FILE" 2>/dev/null || print_warn "删除新建 WireGuard 数据库失败，请手动检查。"
    fi

    if [[ "$role_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/role" ]]; then
        mkdir -p "$(dirname "$WG_DEB_ROLE_FILE")" 2>/dev/null || true
        cp -p "${snapshot_dir}/role" "$WG_DEB_ROLE_FILE" 2>/dev/null || print_warn "恢复 WireGuard 角色文件失败，请手动检查。"
    else
        rm -f "$WG_DEB_ROLE_FILE" 2>/dev/null || print_warn "删除新建 WireGuard 角色文件失败，请手动检查。"
    fi

    if [[ "$conf_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/conf" ]]; then
        mkdir -p "$(dirname "$WG_DEB_CONF")" 2>/dev/null || true
        cp -p "${snapshot_dir}/conf" "$WG_DEB_CONF" 2>/dev/null || print_warn "恢复 WireGuard 配置文件失败，请手动检查。"
    else
        rm -f "$WG_DEB_CONF" 2>/dev/null || print_warn "删除新建 WireGuard 配置文件失败，请手动检查。"
    fi

    _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$non_ufw_backends"
}

wg_deb_server_install() {
    print_title "安装 WireGuard 服务端 (Debian/Ubuntu)"
    if wg_deb_is_installed && [[ "$(wg_deb_get_role)" == "server" ]]; then
        print_warn "WireGuard 服务端已安装。"
        wg_deb_is_running && echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}" || echo -e "  状态: ${C_RED}● 已停止${C_RESET}"
        pause; return 0
    fi

    # ── [1/7] 环境检测 ──
    print_info "[1/7] Debian/Ubuntu 环境检测..."
    wg_deb_check_compat || { pause; return 1; }

    # ── [2/7] 安装软件包 ──
    print_info "[2/7] 安装软件包..."
    wg_deb_install_packages || { pause; return 1; }

    # ── [3/7] 配置 IP 转发 ──
    print_info "[3/7] 配置 IP 转发..."
    _sysctl_enable_wireguard_forward || { print_error "IP 转发配置失败"; pause; return 1; }
    print_success "IP 转发已开启"

    # ── [4/7] 配置服务端参数 ──
    print_info "[4/7] 配置服务端参数..."

    local wg_port listen_addr mtu wg_dns wg_endpoint=""
    local wg_subnet="10.66.66.0/24"
    listen_addr="0.0.0.0"
    mtu=$WG_MTU_DIRECT

    # WG 监听端口
    while true; do
        read -e -r -p "WireGuard 监听端口 [${WG_DEFAULT_PORT}]: " wg_port
        wg_port=${wg_port:-$WG_DEFAULT_PORT}
        if validate_port "$wg_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    # VPN 子网
    while true; do
        read -e -r -p "VPN 内网子网 [10.66.66.0/24]: " wg_subnet
        wg_subnet=${wg_subnet:-10.66.66.0/24}
        if [[ "$wg_subnet" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)/([0-9]+)$ ]]; then
            local o1=${BASH_REMATCH[1]} o2=${BASH_REMATCH[2]} o3=${BASH_REMATCH[3]} o4=${BASH_REMATCH[4]} mask=${BASH_REMATCH[5]}
            if [[ $o1 -le 255 && $o2 -le 255 && $o3 -le 255 && $o4 -le 255 && "$mask" == "24" ]]; then
                break
            fi
        fi
        print_warn "子网格式无效，仅支持 /24 子网，示例: 10.66.66.0/24"
    done
    local prefix server_ip
    prefix=$(echo "$wg_subnet" | cut -d'.' -f1-3)
    server_ip="${prefix}.1"

    # 客户端 DNS
    read -e -r -p "客户端 DNS [8.8.8.8, 1.1.1.1]: " wg_dns
    wg_dns=${wg_dns:-"8.8.8.8, 1.1.1.1"}

    # 服务端 LAN 子网 (自动检测)
    local server_lan_subnet=""
    local def_iface
    def_iface=$(wg_deb_detect_default_iface)
    if [[ -n "$def_iface" ]]; then
        local lan_addr
        lan_addr=$(ip -4 addr show "$def_iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
        if [[ -n "$lan_addr" ]]; then
            local lan_ip lan_mask lan_prefix
            lan_ip=$(echo "$lan_addr" | cut -d'/' -f1)
            lan_mask=$(echo "$lan_addr" | cut -d'/' -f2)
            lan_prefix=$(echo "$lan_ip" | cut -d'.' -f1-3)
            local default_lan="${lan_prefix}.0/${lan_mask}"
            # 只有内网 IP 才提示 LAN 子网映射
            if _wg_is_private_ip "$lan_ip"; then
                echo -e "  检测到 ${def_iface} 网段: ${C_CYAN}${default_lan}${C_RESET}"
                read -e -r -p "服务端 LAN 子网 (映射到 WG 网络) [${default_lan}]: " server_lan_subnet
                server_lan_subnet=${server_lan_subnet:-$default_lan}
            fi
        fi
    fi
    if [[ -z "$server_lan_subnet" ]]; then
        read -e -r -p "服务端 LAN 子网 (留空跳过，VPS 一般不需要): " server_lan_subnet
    fi

    # Endpoint: 优先使用 DDNS 域名
    local ddns_domain=""
    if [[ -d "$DDNS_CONFIG_DIR" ]] && ls "$DDNS_CONFIG_DIR"/*.conf &>/dev/null 2>&1; then
        echo ""
        echo -e "${C_CYAN}检测到已配置的 DDNS 域名:${C_RESET}"
        local idx=1 ddns_domains=()
        for conf in "$DDNS_CONFIG_DIR"/*.conf; do
            [[ -f "$conf" ]] || continue
            local d=$(grep '^DDNS_DOMAIN=' "$conf" | cut -d'"' -f2)
            [[ -n "$d" ]] && { ddns_domains+=("$d"); echo "  ${idx}. ${d}"; idx=$((idx+1)); }
        done
        if [[ ${#ddns_domains[@]} -gt 0 ]]; then
            echo "  0. 不使用 DDNS，手动输入 IP/域名"
            local ddns_choice
            read -e -r -p "选择 DDNS 域名 [1]: " ddns_choice
            ddns_choice=${ddns_choice:-1}
            if [[ "$ddns_choice" != "0" && "$ddns_choice" =~ ^[0-9]+$ && "$ddns_choice" -ge 1 && "$ddns_choice" -le ${#ddns_domains[@]} ]]; then
                ddns_domain="${ddns_domains[$((ddns_choice-1))]}"
                wg_endpoint="$ddns_domain"
                print_success "Endpoint 将使用 DDNS 域名: ${ddns_domain}"
            fi
        fi
    fi
    if [[ -z "$wg_endpoint" ]]; then
        local default_ip
        default_ip=$(get_public_ipv4 2>/dev/null || echo "")
        if [[ -n "$default_ip" ]]; then
            read -e -r -p "公网端点 IP/域名 [${default_ip}]: " wg_endpoint
            wg_endpoint=${wg_endpoint:-$default_ip}
        else
            while [[ -z "$wg_endpoint" ]]; do
                read -e -r -p "公网端点 IP/域名: " wg_endpoint
            done
        fi
    fi
    if ! wg_endpoint=$(wg_shared_normalize_endpoint_host "$wg_endpoint"); then
        print_error "公网端点无效，仅支持 IP 或域名"
        pause; return 1
    fi

    print_info "预检 WireGuard UDP 端口..."
    local wg_udp_rule_added=false
    local wg_non_ufw_open_backends=""
    local fw_rc=0 had_wg_udp_rule=false
    _wg_deb_ufw_has_udp_allow "$wg_port" && had_wg_udp_rule=true
    firewall_allow_udp_port "$wg_port" "WireGuard-Debian"
    fw_rc=$?
    case "$fw_rc" in
        0)
            if [[ "$had_wg_udp_rule" != "true" ]] && _wg_deb_ufw_has_udp_allow "$wg_port"; then
                wg_udp_rule_added=true
            fi
            print_info "已预先放行 ${wg_port}/udp"
            ;;
        2)
            if declare -F firewall_prepare_non_ufw_udp_port >/dev/null; then
                if ! firewall_prepare_non_ufw_udp_port "$wg_port" "WireGuard-Debian"; then
                    print_error "本机防火墙未放行 WireGuard UDP 端口，已中止安装"
                    pause; return 1
                fi
                wg_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"
                [[ -n "$wg_non_ufw_open_backends" ]] && print_info "已通过非 UFW 本地防火墙放行 ${wg_port}/udp"
            fi
            print_warn "请确认云安全组或上游防火墙已放行 ${wg_port}/udp"
            ;;
        *)
            print_error "放行 WireGuard UDP 端口失败，已中止安装"
            pause; return 1
            ;;
    esac

    # ── [5/7] 生成密钥 ──
    print_info "[5/7] 生成服务端密钥..."
    local server_privkey server_pubkey
    server_privkey=$(wg genkey)
    server_pubkey=$(echo "$server_privkey" | wg pubkey)
    print_success "密钥已生成"

    # 服务器名称
    local server_name=""
    local default_name=$(hostname -s 2>/dev/null)
    [[ -z "$default_name" ]] && default_name="server"
    read -e -r -p "服务器名称 [${default_name}]: " server_name
    server_name=${server_name:-$default_name}

    # 检测默认出口网卡
    [[ -z "$def_iface" ]] && def_iface="eth0"

    # ── [6/7] 写入数据库 + 生成配置 ──
    print_info "[6/7] 写入配置..."
    local wg_install_snapshot_dir=""
    local wg_db_existed=false wg_role_existed=false wg_conf_existed=false
    wg_install_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-deb-install.XXXXXX") || {
        print_error "创建安装回滚快照失败，已中止安装"
        _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
        pause; return 1
    }
    if [[ -f "$WG_DEB_DB_FILE" ]]; then
        wg_db_existed=true
        cp -p "$WG_DEB_DB_FILE" "${wg_install_snapshot_dir}/db" || {
            print_error "备份 WireGuard 数据库失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi
    if [[ -f "$WG_DEB_ROLE_FILE" ]]; then
        wg_role_existed=true
        cp -p "$WG_DEB_ROLE_FILE" "${wg_install_snapshot_dir}/role" || {
            print_error "备份 WireGuard 角色文件失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi
    if [[ -f "$WG_DEB_CONF" ]]; then
        wg_conf_existed=true
        cp -p "$WG_DEB_CONF" "${wg_install_snapshot_dir}/conf" || {
            print_error "备份 WireGuard 配置文件失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi

    if ! wg_deb_db_init; then
        print_error "初始化数据库失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_deb_db_set --arg sname "$server_name" \
              --arg pk "$server_privkey" \
              --arg pub "$server_pubkey" \
              --arg ip "$server_ip" \
              --arg sub "$wg_subnet" \
              --arg port "$wg_port" \
              --arg dns "$wg_dns" \
              --arg ep "$wg_endpoint" \
              --arg laddr "$listen_addr" \
              --argjson mtu "$mtu" \
              --arg ddns "${ddns_domain:-}" \
              --arg lan "${server_lan_subnet:-}" \
              --arg iface "$def_iface" \
    '.server = {
        name: $sname,
        private_key: $pk,
        public_key: $pub,
        ip: $ip,
        subnet: $sub,
        port: ($port | tonumber),
        dns: $dns,
        endpoint: $ep,
        listen_address: $laddr,
        mtu: $mtu,
        ddns_domain: $ddns,
        server_lan_subnet: $lan,
        default_iface: $iface
    } | .schema_version = 2'; then
        print_error "数据库写入失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_deb_set_role "server"; then
        print_error "角色写入失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # 生成 wg0.conf
    if ! wg_deb_rebuild_conf; then
        print_error "生成 WireGuard 服务端配置失败"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [7/7] 启动服务 ──
    print_info "[7/7] 启动 WireGuard..."
    if ! systemctl enable "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1; then
        print_error "启用 WireGuard 服务失败，请检查 systemd 状态"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! systemctl start "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1; then
        print_error "启动 WireGuard 服务失败，请检查 journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    sleep 2
    if ! wg_deb_is_running; then
        print_error "WireGuard 启动后未运行，请检查 journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true

    # ── 安装结果展示 ──
    draw_line
    print_success "WireGuard 服务端安装并启动成功！"
    echo -e "  角色:       ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听地址:   ${C_GREEN}${listen_addr}:${wg_port}/udp${C_RESET}"
    echo -e "  MTU:        ${C_GREEN}${mtu}${C_RESET}"
    echo -e "  内网子网:   ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP:  ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  出口网卡:   ${C_GREEN}${def_iface}${C_RESET}"
    [[ -n "$server_lan_subnet" ]] && echo -e "  服务端 LAN: ${C_GREEN}${server_lan_subnet}${C_RESET}"
    if [[ -n "${ddns_domain:-}" ]]; then
        echo -e "  公网端点:   ${C_GREEN}${ddns_domain}:${wg_port}${C_RESET} (DDNS)"
    else
        echo -e "  公网端点:   ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    fi
    draw_line

    log_action "WireGuard(deb) server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint mtu=$mtu iface=$def_iface lan=${server_lan_subnet:-none}"

    # 自动安装服务端看门狗
    echo ""
    wg_deb_setup_watchdog "true" || print_warn "WireGuard 看门狗安装失败，服务端已安装并运行，请稍后手动配置。"

    pause
}

wg_deb_modify_server() {
    wg_deb_check_server || return 1
    print_title "修改 WireGuard 服务端配置"
    local cur_port cur_dns cur_ep cur_lan cur_iface cur_subnet
    cur_port=$(wg_deb_db_get '.server.port')
    cur_dns=$(wg_deb_db_get '.server.dns')
    cur_ep=$(wg_deb_db_get '.server.endpoint')
    cur_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    cur_iface=$(wg_deb_db_get '.server.default_iface // empty')
    cur_subnet=$(wg_deb_db_get '.server.subnet')
    [[ -z "$cur_iface" || "$cur_iface" == "null" ]] && cur_iface=$(wg_deb_detect_default_iface)
    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
    echo -e "  出口网卡:   ${C_GREEN}${cur_iface}${C_RESET}"
    [[ -n "$cur_lan" && "$cur_lan" != "null" ]] && echo -e "  当前 LAN:   ${C_GREEN}${cur_lan}${C_RESET}"
    local changed=false lan_changed=false iface_changed=false port_changed=false
    local new_udp_rule_added=false
    local new_non_ufw_open_backends=""
    local server_snapshot=""
    [[ -f "$WG_DEB_DB_FILE" ]] && server_snapshot=$(cat "$WG_DEB_DB_FILE" 2>/dev/null || true)

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            local fw_rc=0 had_new_udp_rule=false
            _wg_deb_ufw_has_udp_allow "$new_port" && had_new_udp_rule=true
            firewall_allow_udp_port "$new_port" "WireGuard-Debian"
            fw_rc=$?
            case "$fw_rc" in
                0)
                    if [[ "$had_new_udp_rule" != "true" ]] && _wg_deb_ufw_has_udp_allow "$new_port"; then
                        new_udp_rule_added=true
                    fi
                    print_info "已预先放行新端口 ${new_port}/udp"
                    ;;
                2)
                    if declare -F firewall_prepare_non_ufw_udp_port >/dev/null; then
                        if ! firewall_prepare_non_ufw_udp_port "$new_port" "WireGuard-Debian"; then
                            print_error "本机防火墙未放行新 WireGuard UDP 端口，端口未修改"
                            pause; return 1
                        fi
                        new_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"
                        [[ -n "$new_non_ufw_open_backends" ]] && print_info "已通过非 UFW 本地防火墙放行新端口 ${new_port}/udp"
                    fi
                    print_warn "请确认云安全组或上游防火墙已放行 ${new_port}/udp"
                    ;;
                *)
                    print_error "放行新 WireGuard UDP 端口失败，端口未修改"
                    pause; return 1
                    ;;
            esac
            if ! wg_deb_db_set --argjson p "$new_port" '.server.port = $p'; then
                print_error "数据库写入失败，端口未修改"
                _wg_deb_rollback_new_udp_allow "$new_port" "$new_udp_rule_added" "$new_non_ufw_open_backends"
                pause; return 1
            fi
            changed=true
            port_changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
            new_port="$cur_port"
        fi
    fi

    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        if ! wg_deb_db_set --arg d "$new_dns" '.server.dns = $d'; then
            print_error "数据库写入失败，DNS 未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
            print_warn "端点无效，保持原值"
            new_ep="$cur_ep"
        else
        if ! wg_deb_db_set --arg e "$new_ep" '.server.endpoint = $e'; then
            print_error "数据库写入失败，端点未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        print_info "端点将更改为 ${new_ep}"
        fi
    fi

    read -e -r -p "新服务端 LAN 子网 [${cur_lan:-无}]: " new_lan
    new_lan=${new_lan:-$cur_lan}
    if [[ "$new_lan" != "$cur_lan" ]]; then
        if ! validate_cidr_list "$new_lan"; then
            print_warn "LAN 子网格式无效，保持原值"
            new_lan="$cur_lan"
        else
            if ! wg_deb_db_set --arg l "$new_lan" '.server.server_lan_subnet = $l'; then
                print_error "数据库写入失败，LAN 子网未修改"
                _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
                pause; return 1
            fi
            changed=true
            lan_changed=true
            print_info "LAN 子网将更改为 ${new_lan}"
        fi
    fi

    read -e -r -p "出口网卡 [${cur_iface}]: " new_iface
    new_iface=${new_iface:-$cur_iface}
    if [[ "$new_iface" != "$cur_iface" ]]; then
        if ! wg_deb_db_set --arg i "$new_iface" '.server.default_iface = $i'; then
            print_error "数据库写入失败，出口网卡未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        iface_changed=true
        print_info "出口网卡将更改为 ${new_iface}"
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi

    if [[ "$lan_changed" == "true" ]] && ! _wg_deb_update_peer_routes; then
        print_error "联动更新客户端路由失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    if ! wg_deb_rebuild_conf; then
        print_error "重建服务端配置失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
        pause; return 1
    fi
    if ! wg_deb_regenerate_client_confs; then
        print_error "重建客户端配置失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    # 重启服务使配置生效
    if ! systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1; then
        print_error "WireGuard 重启失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi
    sleep 2
    if ! wg_deb_is_running; then
        print_error "WireGuard 重启后未运行，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    # 新端口已放行且服务已切换后，再尽量清理旧端口规则。
    if [[ "$port_changed" == "true" ]] && ufw_is_active; then
        if ufw delete allow "$cur_port"/udp >/dev/null 2>&1; then
            print_info "已清理旧 UFW 端口 ${cur_port}/udp"
        else
            print_warn "旧 UFW 端口 ${cur_port}/udp 删除失败或规则不存在，请手动检查"
        fi
    fi
    [[ "$iface_changed" == "true" ]] && _wg_deb_cleanup_nat_iface "$cur_subnet" "$cur_iface"

    print_success "服务端配置已更新"
    log_action "WireGuard(deb) server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep} lan=${new_lan:-none} iface=${new_iface}"
    pause
}

wg_deb_server_status() {
    wg_deb_check_server || return 1
    print_title "WireGuard 服务端状态"
    local port subnet endpoint dns mtu server_lan def_iface
    port=$(wg_deb_db_get '.server.port')
    subnet=$(wg_deb_db_get '.server.subnet')
    endpoint=$(wg_deb_db_get '.server.endpoint')
    dns=$(wg_deb_db_get '.server.dns')
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    def_iface=$(wg_deb_db_get '.server.default_iface // empty')
    echo -e "  角色:     ${C_GREEN}服务端 (Server) [Debian]${C_RESET}"
    if wg_deb_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi
    echo -e "  端口:     ${port}/udp"
    [[ -n "$mtu" && "$mtu" != "null" ]] && echo -e "  MTU:      ${mtu}"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    [[ -n "$def_iface" && "$def_iface" != "null" ]] && echo -e "  出口网卡: ${C_CYAN}${def_iface}${C_RESET}"
    [[ -n "$server_lan" && "$server_lan" != "null" ]] && echo -e "  服务端 LAN: ${C_CYAN}${server_lan}${C_RESET}"
    local ddns_domain=$(wg_deb_db_get '.server.ddns_domain // empty')
    [[ -n "$ddns_domain" && "$ddns_domain" != "null" ]] && echo -e "  DDNS:     ${C_CYAN}${ddns_domain}${C_RESET}"

    # systemd 服务状态
    echo ""
    local svc_status
    svc_status=$(systemctl is-active wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || echo "unknown")
    local svc_enabled
    svc_enabled=$(systemctl is-enabled wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || echo "unknown")
    echo -e "  systemd:  active=${C_CYAN}${svc_status}${C_RESET}  enabled=${C_CYAN}${svc_enabled}${C_RESET}"

    echo ""
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line
    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "类型" "状态" "最近握手" "流量"
        draw_line
        local wg_dump=""
        wg_deb_is_running && wg_dump=$(wg show "$WG_DEB_INTERFACE" dump 2>/dev/null | tail -n +2)
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip pubkey enabled peer_type
            name=$(wg_deb_db_get ".peers[$i].name")
            ip=$(wg_deb_db_get ".peers[$i].ip")
            pubkey=$(wg_deb_db_get ".peers[$i].public_key")
            enabled=$(wg_deb_db_get ".peers[$i].enabled")
            peer_type=$(wg_deb_db_get ".peers[$i].peer_type // \"standard\"")
            local type_str
            case "$peer_type" in
                gateway) type_str="${C_YELLOW}网关${C_RESET}" ;;
                clash)   type_str="${C_CYAN}Clash${C_RESET}" ;;
                *)       type_str="标准" ;;
            esac
            local status_str handshake_str transfer_str
            if [[ "$enabled" != "true" ]]; then
                status_str="${C_RED}禁用${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            elif [[ -n "$wg_dump" ]]; then
                local peer_line
                peer_line=$(echo "$wg_dump" | grep "^${pubkey}" || true)
                if [[ -n "$peer_line" ]]; then
                    local last_hs rx tx
                    last_hs=$(echo "$peer_line" | awk '{print $5}')
                    rx=$(echo "$peer_line" | awk '{print $6}')
                    tx=$(echo "$peer_line" | awk '{print $7}')
                    if [[ "$last_hs" -gt 0 ]] 2>/dev/null; then
                        local now hs_ago
                        now=$(date +%s)
                        hs_ago=$((now - last_hs))
                        if [[ $hs_ago -lt 180 ]]; then
                            status_str="${C_GREEN}在线${C_RESET}"
                        else
                            status_str="${C_YELLOW}离线${C_RESET}"
                        fi
                        if [[ $hs_ago -lt 60 ]]; then
                            handshake_str="${hs_ago}秒前"
                        elif [[ $hs_ago -lt 3600 ]]; then
                            handshake_str="$((hs_ago / 60))分钟前"
                        elif [[ $hs_ago -lt 86400 ]]; then
                            handshake_str="$((hs_ago / 3600))小时前"
                        else
                            handshake_str="$((hs_ago / 86400))天前"
                        fi
                    else
                        status_str="${C_YELLOW}离线${C_RESET}"
                        handshake_str="从未"
                    fi
                    transfer_str="↓$(wg_deb_format_bytes "$rx") ↑$(wg_deb_format_bytes "$tx")"
                else
                    status_str="${C_YELLOW}离线${C_RESET}"
                    handshake_str="-"
                    transfer_str="-"
                fi
            else
                status_str="${C_GRAY}未知${C_RESET}"
                handshake_str="-"
                transfer_str="-"
            fi
            printf "%-4s %-16s %-18s %-8b %-8b %-20s %-16s\n" \
                "$((i + 1))" "$name" "$ip" "$type_str" "$status_str" "$handshake_str" "$transfer_str"
            i=$((i + 1))
        done
    else
        print_info "暂无设备"
    fi
    draw_line
    pause
}

wg_deb_start() {
    if wg_deb_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi
    print_info "正在启动 WireGuard..."
    systemctl start wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
    if wg_deb_is_running; then
        print_success "WireGuard 已启动"
        log_action "WireGuard(deb) started"
        return 0
    else
        print_error "启动失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) start failed"
        return 1
    fi
}

wg_deb_stop() {
    if ! wg_deb_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi
    print_info "正在停止 WireGuard..."
    systemctl stop wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 1
    if ! wg_deb_is_running; then
        print_success "WireGuard 已停止"
        log_action "WireGuard(deb) stopped"
        return 0
    else
        print_error "停止失败"
        log_action "WireGuard(deb) stop failed"
        return 1
    fi
}

wg_deb_restart() {
    print_info "正在重启 WireGuard..."
    systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
    if wg_deb_is_running; then
        print_success "WireGuard 已重启"
        log_action "WireGuard(deb) restarted"
        return 0
    else
        print_error "重启失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) restart failed"
        return 1
    fi
}

# ── 卸载 ──

wg_deb_uninstall() {
    print_title "卸载 WireGuard"
    if ! wg_deb_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return 0
    fi
    local role
    role=$(wg_deb_get_role)
    echo -e "  当前角色: ${C_GREEN}${role:-未知}${C_RESET}"
    print_warn "此操作将完全卸载 WireGuard，包括所有配置和密钥！"
    if ! confirm "确认卸载 WireGuard?"; then
        return
    fi
    if ! confirm "再次确认: 所有配置将被永久删除，是否继续?"; then
        return
    fi

    print_info "[1/5] 停止 WireGuard 服务..."
    systemctl stop wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || true
    systemctl disable wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || true
    # 确保接口已删除
    ip link set "$WG_DEB_INTERFACE" down 2>/dev/null || true
    ip link delete "$WG_DEB_INTERFACE" 2>/dev/null || true

    print_info "[2/5] 清理防火墙规则..."
    if ufw_is_active; then
        local wg_port
        wg_port=$(wg_deb_db_get '.server.port' 2>/dev/null)
        [[ -n "$wg_port" && "$wg_port" != "null" ]] && ufw delete allow "$wg_port"/udp >/dev/null 2>&1
    fi

    print_info "[3/5] 清理看门狗和定时任务..."
    cron_remove_job_command "/usr/local/bin/wg-watchdog.sh" 2>/dev/null || true
    rm -f /usr/local/bin/wg-watchdog.sh /var/log/wg-watchdog.log 2>/dev/null || true

    print_info "[4/5] 删除配置文件..."
    rm -f "$WG_DEB_CONF" 2>/dev/null || true
    rm -rf "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
    rm -f "$WG_DEB_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DEB_DB_DIR" 2>/dev/null || true
    rm -f "$WG_DEB_ROLE_FILE" 2>/dev/null || true
    rm -f /etc/sysctl.d/99-wireguard.conf 2>/dev/null || true
    rmdir /etc/wireguard 2>/dev/null || true

    print_info "[5/5] 卸载软件包..."
    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        apt-get remove -y wireguard wireguard-tools 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
    fi

    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            _sysctl_disable_wireguard_forward || print_warn "恢复 IP 转发设置失败，请手动检查 /etc/sysctl.conf"
        fi
    fi

    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line
    log_action "WireGuard(deb) uninstalled: role=${role}"
    pause
}
_wg_deb_snapshot_db() {
    [[ -f "$WG_DEB_DB_FILE" ]] || return 1
    cat "$WG_DEB_DB_FILE"
}

_wg_deb_restore_peer_snapshot() {
    local snapshot="${1:-}" cleanup_file="${2:-}"
    [[ -n "$snapshot" ]] || return 1
    wg_write_private_file "$WG_DEB_DB_FILE" "$snapshot" || return 1
    wg_deb_rebuild_conf >/dev/null 2>&1 || true
    wg_deb_regenerate_client_confs >/dev/null 2>&1 || true
    wg_deb_is_running && wg_deb_apply_conf >/dev/null 2>&1 || true
    if [[ -n "$cleanup_file" ]]; then
        rm -f -- "$cleanup_file" 2>/dev/null || true
    fi
}

wg_deb_add_peer() {
    wg_deb_check_server || return 1
    print_title "添加 WireGuard 设备 (Peer)"
    local peer_name
    while true; do
        read -e -r -p "设备名称 (如 phone, laptop): " peer_name
        [[ -z "$peer_name" ]] && { print_warn "名称不能为空"; continue; }
        local exists
        exists=$(wg_deb_db_get --arg n "$peer_name" '.peers[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "设备名 '$peer_name' 已存在"; continue; }
        [[ ! "$peer_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母、数字、下划线、连字符"; continue; }
        break
    done
    local peer_ip
    peer_ip=$(wg_deb_next_ip) || { pause; return 1; }
    echo -e "  分配 IP: ${C_GREEN}${peer_ip}${C_RESET}"
    local peer_privkey peer_pubkey psk
    peer_privkey=$(wg genkey) || { print_error "生成 peer 私钥失败"; pause; return 1; }
    peer_pubkey=$(printf '%s\n' "$peer_privkey" | wg pubkey) || { print_error "生成 peer 公钥失败"; pause; return 1; }
    psk=$(wg genpsk) || { print_error "生成预共享密钥失败"; pause; return 1; }

    # ── 设备类型选择 ──
    local peer_type="standard"
    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:"
    echo -e "  1. ${C_CYAN}Clash 客户端${C_RESET} (手机/电脑，通过 FlClash/FClash 规则接入)"
    echo -e "  2. ${C_YELLOW}网关设备${C_RESET} (路由器，暴露自身 LAN 子网)"
    echo -e "  3. 标准 WireGuard 客户端 (原生 .conf 配置)"
    read -e -r -p "选择 [1]: " device_type
    device_type=${device_type:-1}

    case "$device_type" in
        1)
            peer_type="clash"
            is_gateway="false"
            ;;
        2)
            peer_type="gateway"
            is_gateway="true"
            echo ""
            print_guide "请输入该网关后面的 LAN 网段 (将被路由到 VPN 中)"
            print_guide "示例: 192.168.123.0/24"
            print_guide "多个网段用逗号分隔: 192.168.1.0/24, 192.168.2.0/24"
            while [[ -z "$lan_subnets" ]]; do
                read -e -r -p "LAN 网段: " lan_subnets
                if [[ -z "$lan_subnets" ]]; then
                    print_warn "网关设备必须指定 LAN 网段"
                elif ! validate_cidr_list "$lan_subnets"; then
                    print_warn "格式无效，示例: 192.168.123.0/24"
                    lan_subnets=""
                fi
            done
            ;;
        3)
            peer_type="standard"
            is_gateway="false"
            ;;
        *)
            peer_type="clash"
            is_gateway="false"
            ;;
    esac

    # ── 路由模式 ──
    local client_allowed_ips server_subnet server_lan route_mode="managed"
    server_subnet=$(wg_deb_db_get '.server.subnet')
    server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')

    # 收集所有网关 LAN 网段
    local all_lan_subnets=""
    local pc=$(wg_deb_db_get '.peers | length') pi=0
    while [[ $pi -lt $pc ]]; do
        local pls=$(wg_deb_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" && "$pls" != "null" ]]; then
            [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
            all_lan_subnets="${all_lan_subnets}${pls}"
        fi
        pi=$((pi + 1))
    done
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
        all_lan_subnets="${all_lan_subnets}${lan_subnets}"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
        echo -e "  Clash 路由模式: ${C_CYAN}VPN 子网 + 所有 LAN 子网${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    elif [[ "$peer_type" == "gateway" ]]; then
        local other_lans=""
        local IFS_BAK="$IFS"; IFS=','
        for cidr in $all_lan_subnets; do
            cidr=$(echo "$cidr" | xargs)
            [[ -z "$cidr" ]] && continue
            local dominated=false
            local IFS2_BAK="$IFS"; IFS=','
            for own in $lan_subnets; do
                own=$(echo "$own" | xargs)
                [[ "$cidr" == "$own" ]] && { dominated=true; break; }
            done
            IFS="$IFS2_BAK"
            [[ "$dominated" != "true" ]] && { [[ -n "$other_lans" ]] && other_lans="${other_lans}, "; other_lans="${other_lans}${cidr}"; }
        done
        IFS="$IFS_BAK"
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$other_lans" ]] && client_allowed_ips="${client_allowed_ips}, ${other_lans}"
        echo -e "  网关路由模式: ${C_YELLOW}VPN 子网 + 服务端 LAN + 其他网关 LAN${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    else
        echo ""
        echo "客户端路由模式:"
        echo "  1. 全局代理 (所有流量走 VPN) - 0.0.0.0/0"
        echo "  2. 仅 VPN 内网 (只访问 VPN 内部设备)"
        echo "  3. VPN 内网 + 所有 LAN 网段 (访问远程内网设备)"
        echo "  4. 自定义路由"
        read -e -r -p "选择 [1]: " route_mode
        route_mode=${route_mode:-1}
        case $route_mode in
            1) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
            2) client_allowed_ips="$server_subnet"; route_mode="vpn" ;;
            3)
                route_mode="managed"
                client_allowed_ips="$server_subnet"
                [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
                [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
                ;;
            4)
                read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
                [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
                if validate_wg_allowed_ips "$client_allowed_ips"; then
                    route_mode="custom"
                else
                    print_warn "自定义路由格式无效，回退为仅 VPN 内网"
                    client_allowed_ips="$server_subnet"
                    route_mode="vpn"
                fi
                ;;
            *) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
        esac
    fi

    # ── 写入数据库 ──
    local conf_file="${WG_DEB_CLIENT_DIR}/${peer_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_deb_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    if ! wg_deb_db_set --arg name "$peer_name" \
              --arg ip "$peer_ip" \
              --arg privkey "$peer_privkey" \
              --arg pubkey "$peer_pubkey" \
              --arg psk "$psk" \
              --arg allowed "$client_allowed_ips" \
              --arg created "$now" \
              --arg gw "$is_gateway" \
              --arg lans "$lan_subnets" \
              --arg ptype "$peer_type" \
              --arg route_mode "$route_mode" \
    '.peers += [{
        name: $name,
        ip: $ip,
        private_key: $privkey,
        public_key: $pubkey,
        preshared_key: $psk,
        client_allowed_ips: $allowed,
        enabled: true,
        created: $created,
        is_gateway: ($gw == "true"),
        lan_subnets: $lans,
        peer_type: $ptype,
        route_mode: $route_mode
    }]'; then
        rm -f "$conf_file"
        print_error "数据库写入失败，已清理生成的客户端配置"
        pause; return 1
    fi

    # ── 网关设备: 联动更新其他 peer 的 allowed_ips ──
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        if ! _wg_deb_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_deb_restore_peer_snapshot "$db_snapshot" "$conf_file"
            pause; return 1
        fi
    fi

    # ── 重建配置并热应用 ──
    if ! wg_deb_apply_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_deb_restore_peer_snapshot "$db_snapshot" "$conf_file"
        pause; return 1
    fi

    # ── 结果展示 ──
    draw_line
    print_success "设备 '${peer_name}' 添加成功！"
    draw_line
    echo -e "  名称: ${C_GREEN}${peer_name}${C_RESET}"
    echo -e "  IP:   ${C_GREEN}${peer_ip}${C_RESET}"
    case "$peer_type" in
        clash)   echo -e "  类型: ${C_CYAN}Clash 客户端${C_RESET}" ;;
        gateway) echo -e "  类型: ${C_YELLOW}网关设备${C_RESET}"; echo -e "  LAN:  ${C_CYAN}${lan_subnets}${C_RESET}" ;;
        *)       echo -e "  类型: 标准客户端" ;;
    esac
    echo -e "  路由: ${C_CYAN}${client_allowed_ips}${C_RESET}"
    echo -e "  配置: ${C_CYAN}${conf_file}${C_RESET}"
    draw_line

    # ── 后续操作提示 ──
    if [[ "$peer_type" == "clash" ]]; then
        echo ""
        read -e -r -p "是否立即生成 Clash/Mihomo 客户端配置? [Y/n]: " _gen_clash
        _gen_clash=${_gen_clash:-Y}
        [[ "$_gen_clash" =~ ^[Yy]$ ]] && wg_deb_generate_clash_config
    elif [[ "$peer_type" == "gateway" ]]; then
        echo -e "\n${C_YELLOW}[网关设备部署提示]${C_RESET}"
        echo "  • LAN 内设备无需安装任何 VPN 客户端，网关自动代理"
        echo "  • 确保 VPN 子网 (${server_subnet}) 与 LAN 子网 (${lan_subnets}) 不冲突"
    fi

    log_action "WireGuard(deb) peer added: ${peer_name} (${peer_ip}) type=${peer_type} gateway=${is_gateway} lan=${lan_subnets}"
    pause
}

# 内部函数: 联动更新所有 peer 的 allowed_ips (当网关 LAN 变动时)
_wg_deb_update_peer_routes() {
    local server_subnet=$(wg_deb_db_get '.server.subnet')
    local server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    local _pc=$(wg_deb_db_get '.peers | length')

    # 收集所有网关的 LAN 网段
    local _all_lans="" _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _pls=$(wg_deb_db_get ".peers[$_pi].lan_subnets // empty")
        [[ -n "$_pls" && "$_pls" != "null" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
        _pi=$((_pi + 1))
    done

    _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _cur=$(wg_deb_db_get ".peers[$_pi].client_allowed_ips")
        local _is_gw=$(wg_deb_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_deb_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_deb_db_get ".peers[$_pi].peer_type // \"standard\"")
        local _route_mode=$(wg_deb_db_get ".peers[$_pi].route_mode // empty")
        case "$_route_mode" in
            custom|full|vpn)
                _pi=$((_pi + 1))
                continue
                ;;
        esac
        [[ "$_cur" == *"0.0.0.0/0"* || "$_cur" == *"::/0"* ]] && { _pi=$((_pi + 1)); continue; }
        [[ -z "$_route_mode" && "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

        if [[ "$_is_gw" == "true" ]]; then
            local _other="" _IFS_BAK="$IFS"; IFS=','
            for _c in $_all_lans; do
                _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                local _skip=false _IFS2="$IFS"; IFS=','
                for _o in $_own; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                IFS="$_IFS2"
                [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
            done; IFS="$_IFS_BAK"
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_other" ]] && _new="${_new}, ${_other}"
            if ! wg_deb_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'; then
                print_error "数据库写入失败，客户端路由未完整更新"
                return 1
            fi
        else
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            if ! wg_deb_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'; then
                print_error "数据库写入失败，客户端路由未完整更新"
                return 1
            fi
        fi
        _pi=$((_pi + 1))
    done
}

wg_deb_toggle_peer() {
    wg_deb_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_deb_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name target_pubkey current_state
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_deb_db_get ".peers[$target_idx].public_key")
    current_state=$(wg_deb_db_get ".peers[$target_idx].enabled")
    local db_snapshot
    db_snapshot=$(_wg_deb_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            if ! wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_deb_apply_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_deb_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard(deb) peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            if ! wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_deb_apply_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_deb_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            print_success "设备 '${target_name}' 已启用"
            log_action "WireGuard(deb) peer enabled: ${target_name}"
        fi
    fi
    pause
}

wg_deb_delete_peer() {
    wg_deb_check_server || return 1
    print_title "删除 WireGuard 设备"
    wg_deb_select_peer "选择要删除的设备序号" true || return
    local target_idx=$REPLY
    local target_name
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    local _del_gw=$(wg_deb_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_deb_db_get ".peers[$target_idx].lan_subnets // empty")
    local conf_file="${WG_DEB_CLIENT_DIR}/${target_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_deb_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if ! wg_deb_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'; then
        print_error "数据库写入失败，设备未删除"
        pause; return 1
    fi

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        if ! _wg_deb_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_deb_restore_peer_snapshot "$db_snapshot"
            pause; return 1
        fi
    fi

    if ! wg_deb_apply_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_deb_restore_peer_snapshot "$db_snapshot"
        pause; return 1
    fi
    rm -f -- "$conf_file" 2>/dev/null || print_warn "删除客户端配置文件失败: $conf_file"

    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard(deb) peer deleted: ${target_name}"
    pause
}

wg_deb_show_peer_conf() {
    wg_deb_check_server || return 1
    print_title "查看设备配置"
    wg_deb_select_peer "选择设备序号" true || return
    local target_idx=$REPLY
    local target_name peer_type
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    peer_type=$(wg_deb_db_get ".peers[$target_idx].peer_type // \"standard\"")
    local conf_file="${WG_DEB_CLIENT_DIR}/${target_name}.conf"

    # 确保配置文件存在
    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."
        wg_deb_regenerate_client_confs
        [[ ! -f "$conf_file" ]] && { print_error "配置文件生成失败"; pause; return; }
        print_success "配置文件已重新生成"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        echo -e "  设备类型: ${C_CYAN}Clash 客户端${C_RESET}"
        echo -e "  (Clash 客户端不使用 .conf 文件，请生成 Clash YAML 配置)"
        echo ""
        if confirm "是否生成 Clash/Mihomo 配置?"; then
            wg_deb_generate_clash_config
        fi
    else
        draw_line
        echo -e "${C_CYAN}=== ${target_name} 客户端配置 ===${C_RESET}"
        draw_line
        cat "$conf_file"
        draw_line
        if command_exists qrencode; then
            if confirm "显示二维码 (手机扫码导入)?"; then
                echo -e "${C_CYAN}=== ${target_name} 二维码 ===${C_RESET}"
                qrencode -t ansiutf8 < "$conf_file"
                echo ""
            fi
        fi
    fi

    echo -e "配置文件路径: ${C_CYAN}${conf_file}${C_RESET}"
    echo -e "下载命令: ${C_GRAY}scp root@服务器IP:${conf_file} ./${C_RESET}"
    pause
}
wg_deb_setup_watchdog() {
    wg_deb_check_installed || return 1
    local watchdog_script="/usr/local/bin/wg-watchdog.sh"
    local watchdog_log="/var/log/wg-watchdog.log"
    local auto_mode="${1:-}"

    # 已启用时的管理界面
    if [[ -z "$auto_mode" ]] && cron_has_job_command "$watchdog_script"; then
        print_title "WireGuard 看门狗"
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
        echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
        echo "  1. 禁用看门狗
  2. 查看日志
  3. 手动触发一次检测
  0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1)
                cron_remove_job_command "$watchdog_script"
                rm -f "$watchdog_script"
                print_success "看门狗已禁用"
                log_action "WireGuard(deb) watchdog disabled"
                ;;
            2) echo ""; tail -n 30 "$watchdog_log" 2>/dev/null || print_warn "无日志" ;;
            3)
                if [[ -x "$watchdog_script" ]]; then
                    bash "$watchdog_script"
                    print_success "检测完成"
                    echo ""; tail -n 5 "$watchdog_log" 2>/dev/null
                else
                    print_warn "看门狗脚本不存在"
                fi
                ;;
        esac
        pause; return
    fi

    if [[ -z "$auto_mode" ]]; then
        print_title "WireGuard 服务端看门狗 (Debian)"
        echo "看门狗功能:
  • 每分钟检测 ${WG_DEB_INTERFACE} 接口状态
  • 接口消失 → 自动 systemctl restart
  • wg show 失败 → 自动重启"
        if ! confirm "启用看门狗?"; then pause; return; fi
    fi

    mkdir -p "$(dirname "$watchdog_script")" || { print_error "创建看门狗目录失败"; [[ -z "$auto_mode" ]] && pause; return 1; }
    local watchdog_tmp
    watchdog_tmp=$(mktemp "$(dirname "$watchdog_script")/.tmp.server-manage.wg-watchdog.XXXXXX") || {
        print_error "创建看门狗临时脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    }
    _tmp_register "$watchdog_tmp"

    # ── Debian 看门狗 (systemctl 管理) ──
    if ! {
        cat << 'WDEOF_DEB'
#!/bin/bash
WDEOF_DEB
        printf 'WG_DEB_INTERFACE=%q\n' "$WG_DEB_INTERFACE"
        cat << 'WDEOF_DEB'
LOG="/var/log/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    logger -t wg-watchdog "$1"
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG"
    if [[ -f "$LOG" ]] && [[ $(wc -c < "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        tail -n 50 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
}

# 检测接口存活
if ! ip link show "$WG_DEB_INTERFACE" &>/dev/null; then
    wdlog "${WG_DEB_INTERFACE} down, restarting via systemctl"
    systemctl restart "wg-quick@${WG_DEB_INTERFACE}"
    exit 0
fi

# 检测 wg show 是否正常
if ! wg show "$WG_DEB_INTERFACE" &>/dev/null; then
    wdlog "wg show ${WG_DEB_INTERFACE} failed, restarting"
    systemctl restart "wg-quick@${WG_DEB_INTERFACE}"
    exit 0
fi
WDEOF_DEB
    } > "$watchdog_tmp"; then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "写入看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    chmod 0755 "$watchdog_tmp" 2>/dev/null || true
    if ! mv "$watchdog_tmp" "$watchdog_script"; then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "安装看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    _tmp_unregister "$watchdog_tmp"
    if ! cron_add_job_command "$watchdog_script" "* * * * * $watchdog_script >/dev/null 2>&1"; then
        rm -f "$watchdog_script" 2>/dev/null || true
        print_error "安装看门狗 cron 任务失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo "  检测: 接口存活 → wg show"
    log_action "WireGuard(deb) watchdog enabled"
    [[ -z "$auto_mode" ]] && pause
    return 0
}

wg_deb_export_peers() {
    wg_deb_check_server || return 1
    print_title "导出 WireGuard 设备配置"
    local peer_count
    if ! peer_count=$(wg_deb_db_get '.peers | length') || [[ ! "$peer_count" =~ ^[0-9]+$ ]]; then
        print_error "读取设备数量失败"
        pause; return 1
    fi
    if [[ "$peer_count" -eq 0 ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(wg_shared_export_file) || { print_error "无法创建导出文件"; pause; return 1; }
    if jq '{
        export_version: 2,
        export_date: (now | todate),
        server: {
            endpoint: .server.endpoint,
            port: .server.port,
            subnet: .server.subnet,
            dns: .server.dns,
            public_key: .server.public_key,
            server_lan_subnet: .server.server_lan_subnet
        },
        peers: .peers
    }' "$WG_DEB_DB_FILE" > "$export_file" 2>/dev/null; then
        print_success "已导出 $peer_count 个设备到:"
        echo -e "  ${C_CYAN}${export_file}${C_RESET}"
        local fsize=$(du -h "$export_file" 2>/dev/null | awk '{print $1}')
        echo "  文件大小: $fsize"
        echo ""
        print_warn "该文件包含私钥等敏感信息，请妥善保管！"
        echo "可使用 [导入设备配置] 在其他服务器恢复。"
        log_action "WireGuard(deb) peers exported: count=$peer_count file=$export_file"
    else
        print_error "导出失败"
        rm -f "$export_file" 2>/dev/null || true
        pause; return 1
    fi
    pause
}

_wg_deb_import_snapshot_clients() {
    local backup_dir="$1"
    mkdir -p "$(dirname "$backup_dir")" || return 1
    rm -rf "$backup_dir" 2>/dev/null || true
    if [[ -d "$WG_DEB_CLIENT_DIR" ]]; then
        cp -a "$WG_DEB_CLIENT_DIR" "$backup_dir" || return 1
    else
        mkdir -p "$backup_dir" || return 1
    fi
}

_wg_deb_import_restore_snapshot() {
    local db_snapshot="${1:-}" client_backup="${2:-}"
    [[ -n "$db_snapshot" ]] && wg_write_private_file "$WG_DEB_DB_FILE" "$db_snapshot" >/dev/null 2>&1 || true
    if [[ -n "$client_backup" && -d "$client_backup" ]]; then
        rm -rf "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
        mkdir -p "$(dirname "$WG_DEB_CLIENT_DIR")" 2>/dev/null || true
        cp -a "$client_backup" "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
    fi
    wg_deb_rebuild_conf >/dev/null 2>&1 || true
    wg_deb_regenerate_client_confs >/dev/null 2>&1 || true
    wg_deb_is_running && wg_deb_apply_conf >/dev/null 2>&1 || true
}

wg_deb_import_peers() {
    wg_deb_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return 1
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return 1
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return 1
    fi
    echo -e "发现 ${C_CYAN}${import_count}${C_RESET} 个设备:"
    jq -r '.peers[] | "  - \(.name) (\(.ip))"' "$import_file" 2>/dev/null
    echo ""
    echo "导入模式:
  1. 完整导入 (保留原始密钥，适用于服务器迁移/endpoint 不变)
  2. 重新生成密钥 (适用于新服务器，需重新下发客户端配置)
  0. 返回
"
    read -e -r -p "选择: " mode
    [[ "$mode" == "0" || -z "$mode" ]] && return
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return 1; }

    local db_snapshot client_backup
    db_snapshot=$(_wg_deb_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    client_backup=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-deb-import-clients.XXXXXX") || {
        print_error "创建客户端配置快照目录失败"; pause; return 1;
    }
    chmod 700 "$client_backup" 2>/dev/null || true
    if ! _wg_deb_import_snapshot_clients "$client_backup/clients"; then
        rm -rf "$client_backup" 2>/dev/null || true
        print_error "备份客户端配置失败"; pause; return 1
    fi

    local existing_count
    existing_count=$(wg_deb_db_get '.peers | length')
    local merge_mode="1"
    if [[ "$existing_count" -gt 0 ]]; then
        print_warn "当前已有 $existing_count 个设备。"
        echo "  1. 追加 (跳过同名/同IP设备)
  2. 覆盖 (删除所有现有设备后导入)"
        read -e -r -p "选择 [1]: " merge_mode
        merge_mode=${merge_mode:-1}
        if [[ "$merge_mode" == "2" ]]; then
            if ! confirm "确认删除所有现有设备?"; then
                rm -rf "$client_backup" 2>/dev/null || true
                return
            fi
            if ! wg_deb_db_set '.peers = []'; then
                _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
                rm -rf "$client_backup" 2>/dev/null || true
                print_error "清空现有设备失败，已恢复原配置"
                pause; return 1
            fi
            rm -f "${WG_DEB_CLIENT_DIR}"/*.conf 2>/dev/null
        fi
    fi

    local imported=0 skipped=0
    local i=0
    while [[ $i -lt $import_count ]]; do
        local name ip privkey pubkey psk allowed enabled is_gw lans created peer_type route_mode
        name=$(jq -r ".peers[$i].name" "$import_file")
        ip=$(jq -r ".peers[$i].ip" "$import_file")
        privkey=$(jq -r ".peers[$i].private_key" "$import_file")
        pubkey=$(jq -r ".peers[$i].public_key" "$import_file")
        psk=$(jq -r ".peers[$i].preshared_key" "$import_file")
        allowed=$(jq -r ".peers[$i].client_allowed_ips" "$import_file")
        enabled=$(jq -r ".peers[$i].enabled // true" "$import_file")
        is_gw=$(jq -r ".peers[$i].is_gateway // false" "$import_file")
        lans=$(jq -r ".peers[$i].lan_subnets // empty" "$import_file")
        created=$(jq -r ".peers[$i].created // empty" "$import_file")
        peer_type=$(jq -r ".peers[$i].peer_type // empty" "$import_file")
        route_mode=$(jq -r ".peers[$i].route_mode // empty" "$import_file")
        if [[ -z "$peer_type" || "$peer_type" == "null" ]]; then
            [[ "$is_gw" == "true" ]] && peer_type="gateway" || peer_type="standard"
        fi
        [[ -z "$route_mode" || "$route_mode" == "null" ]] && route_mode="managed"
        [[ "$enabled" == "true" || "$enabled" == "false" ]] || enabled=true
        [[ "$is_gw" == "true" || "$is_gw" == "false" ]] || is_gw=false

        if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            print_warn "跳过: $name (名称格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_ip "$ip"; then
            print_warn "跳过: $name (IP 格式无效: $ip)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if [[ -z "$allowed" || "$allowed" == "null" ]] || ! validate_cidr_list "$allowed"; then
            print_warn "跳过: $name (AllowedIPs 格式无效: $allowed)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_cidr_list "$lans"; then
            print_warn "跳过: $name (LAN 网段格式无效: $lans)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        case "$peer_type" in
            standard|gateway) ;;
            *) print_warn "跳过: $name (设备类型无效: $peer_type)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac
        case "$route_mode" in
            managed|custom|full|vpn) ;;
            *) print_warn "跳过: $name (路由模式无效: $route_mode)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac

        # 检查重名
        local exists
        exists=$(wg_deb_db_get --arg n "$name" '.peers[] | select(.name == $n) | .name')
        if [[ -n "$exists" ]]; then
            print_warn "跳过: $name (名称已存在)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        # 检查 IP 冲突
        local ip_exists
        ip_exists=$(wg_deb_db_get --arg ip "$ip" '.peers[] | select(.ip == $ip) | .ip')
        if [[ -n "$ip_exists" ]]; then
            print_warn "跳过: $name (IP $ip 已被使用)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        if [[ "$mode" == "2" ]]; then
            privkey=$(wg genkey)
            pubkey=$(echo "$privkey" | wg pubkey)
            psk=$(wg genpsk)
        fi
        if ! validate_wg_key "$privkey"; then
            print_warn "跳过: $name (私钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$pubkey"; then
            print_warn "跳过: $name (公钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$psk"; then
            print_warn "跳过: $name (预共享密钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        [[ -z "$created" || "$created" == "null" ]] && created=$(date '+%Y-%m-%d %H:%M:%S')

        if ! wg_deb_db_set --arg name "$name" \
                  --arg ip "$ip" \
                  --arg privkey "$privkey" \
                  --arg pubkey "$pubkey" \
                  --arg psk "$psk" \
                  --arg allowed "$allowed" \
                  --argjson enabled "$enabled" \
                  --arg created "$created" \
                  --arg gw "$is_gw" \
                  --arg lans "$lans" \
                  --arg ptype "$peer_type" \
                  --arg route_mode "$route_mode" \
            '.peers += [{
                name: $name,
                ip: $ip,
                private_key: $privkey,
                public_key: $pubkey,
                preshared_key: $psk,
                client_allowed_ips: $allowed,
                enabled: $enabled,
                created: $created,
                is_gateway: ($gw == "true"),
                lan_subnets: $lans,
                peer_type: $ptype,
                route_mode: $route_mode
            }]'; then
            _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "导入 $name 时数据库写入失败，已恢复原配置"
            pause; return 1
        fi
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        if ! wg_deb_apply_conf; then
            _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "WireGuard 运行配置热应用失败，已恢复原配置"
            pause; return 1
        fi
    fi
    rm -rf "$client_backup" 2>/dev/null || true
    echo ""
    print_success "导入完成: 成功 ${imported}, 跳过 ${skipped}"
    [[ "$mode" == "2" ]] && print_warn "已重新生成密钥，请重新下发所有客户端配置。"
    log_action "WireGuard(deb) peers imported: imported=$imported skipped=$skipped mode=$mode"
    pause
}

wg_deb_server_menu() {
    while true; do
        print_title "WireGuard 服务端管理 (Debian/Ubuntu)"
        local srv_name=$(wg_deb_get_server_name)
        if wg_deb_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        fi
        local peer_count=$(wg_deb_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"
        echo "  [设备管理]
  1. 查看状态
  2. 添加设备
  3. 删除设备
  4. 启用/禁用设备
  5. 查看设备配置/二维码
  6. 生成 Clash/OpenClash 配置
  [服务控制]
  7. 启动 WireGuard
  8. 停止 WireGuard
  9. 重启 WireGuard
  10. 修改服务端配置
  11. 修改服务器名称
  12. 卸载 WireGuard
  13. 服务端看门狗 (自动重启保活)
  [数据管理]
  14. 导出设备配置 (JSON)
  15. 导入设备配置 (JSON)
  0. 返回上级菜单
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice
        case $choice in
            1) wg_deb_server_status ;;
            2) wg_deb_add_peer ;;
            3) wg_deb_delete_peer ;;
            4) wg_deb_toggle_peer ;;
            5) wg_deb_show_peer_conf ;;
            6) wg_deb_generate_clash_config ;;
            7) wg_deb_start; pause ;;
            8) wg_deb_stop; pause ;;
            9) wg_deb_restart; pause ;;
            10) wg_deb_modify_server ;;
            11) wg_deb_rename_server ;;
            12) wg_deb_uninstall; return ;;
            13) wg_deb_setup_watchdog ;;
            14) wg_deb_export_peers ;;
            15) wg_deb_import_peers ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_deb_install_menu() {
    wg_deb_server_install
}

wg_deb_main_menu() {
    while true; do
        if wg_deb_is_installed; then
            local role
            role=$(wg_deb_get_role)
            local server_private_key=""
            server_private_key=$(wg_deb_db_get '.server.private_key // empty')
            if [[ "$role" == "server" ]] || { [[ "$role" == "none" || -z "$role" ]] && [[ -f "$WG_DEB_CONF" ]] && [[ -n "$server_private_key" && "$server_private_key" != "null" ]]; }; then
                [[ "$role" == "server" ]] || wg_deb_set_role "server"
                print_title "WireGuard VPN"
                local srv_name
                srv_name=$(wg_deb_get_server_name)
                if wg_deb_is_running; then
                    echo -e "  状态: ${C_GREEN}运行中${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                else
                    echo -e "  状态: ${C_RED}已停止${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                fi
                echo ""
                echo "1. 服务端管理"
                echo "2. 卸载 WireGuard"
                echo "0. 返回主菜单"
                read -e -r -p "选择: " c
                case "$c" in
                    1) wg_deb_server_menu ;;
                    2) wg_deb_uninstall ;;
                    0|q|Q|"") return ;;
                    *) print_warn "无效选项"; pause ;;
                esac
            else
                print_warn "WireGuard 已安装但无配置文件"
                echo "  1. 重新安装服务端
  2. 卸载
  0. 返回"
                read -e -r -p "选择: " rc
                case $rc in
                    1) wg_deb_server_install; continue ;;
                    2) wg_deb_uninstall; continue ;;
                    *) return ;;
                esac
            fi
        else
            print_title "WireGuard VPN"
            echo -e "  状态: ${C_YELLOW}未安装${C_RESET}"
            echo ""
            echo "1. 安装 WireGuard 服务端"
            echo "0. 返回主菜单"
            read -e -r -p "选择: " c
            case "$c" in
                1) wg_deb_server_install ;;
                0|q|Q|"") return ;;
                *) print_warn "无效选项"; pause ;;
            esac
        fi
    done
}
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

_email_write_private_file() {
    local file="$1" content="$2" dir tmp old_umask
    dir="$(dirname "$file")"
    mkdir -p "$dir" || return 1
    old_umask="$(umask)"
    umask 077
    tmp=$(mktemp "${dir}/.tmp.server-manage.email.XXXXXX")
    local mktemp_rc=$?
    umask "$old_umask"
    [[ "$mktemp_rc" -eq 0 ]] || return 1
    if declare -F _tmp_register >/dev/null 2>&1; then _tmp_register "$tmp"; fi
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    chown root:root "$tmp" 2>/dev/null || true
    if ! mv -f "$tmp" "$file"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
    return 0
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

_email_clear_sensitive_env() {
    unset CF_API_TOKEN CF_ACCOUNT_ID CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
    unset EMAIL_RESEND_TOKEN EMAIL_RESEND_DKIM EMAIL_JWT_SECRET EMAIL_ADMIN_PASSWORD
    trap - RETURN 2>/dev/null || true
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
    "$@" >> "$EMAIL_LOG_FILE" 2>&1
    local rc=$?
    if (( rc == 0 )); then
        printf '\r%b\n' "${C_GREEN}[✓]${C_RESET} $label                                                  "
        return 0
    fi
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
        -e 's/(ADMIN_PASSWORDS|[A-Z0-9_]*TOKEN)([[:space:]]*=[[:space:]]*|:[[:space:]]*)["'"'"']?[^[:space:]"'"'"']+["'"'"']?/\1\2<redacted>/g' \
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
    local backup tmp
    backup=$(mktemp "${pages_dir}/.wrangler.toml.bak.XXXXXX") || return 1
    tmp=$(mktemp "${pages_dir}/.wrangler.toml.XXXXXX") || { rm -f "$backup"; return 1; }
    cp -a "$pages_toml" "$backup" || { rm -f "$backup" "$tmp"; return 1; }
    awk -v worker="$EMAIL_WORKER_NAME" '
        /^[[:space:]]*service[[:space:]]*=/ {
            sub(/"[^"]+"/, "\"" worker "\"")
        }
        { print }
    ' "$pages_toml" > "$tmp" || { rm -f "$backup" "$tmp"; return 1; }
    mv -f "$tmp" "$pages_toml" || { rm -f "$backup" "$tmp"; return 1; }
    EMAIL_PAGES_TOML_BACKUP="$backup"
    EMAIL_PAGES_TOML_BACKUP_TARGET="$pages_toml"
    email_log "Patched pages/wrangler.toml service binding → ${EMAIL_WORKER_NAME}"
    return 0
}

_email_restore_pages_service_binding() {
    local backup="${EMAIL_PAGES_TOML_BACKUP:-}" target="${EMAIL_PAGES_TOML_BACKUP_TARGET:-}"
    [[ -n "$backup" && -n "$target" && -f "$backup" ]] || return 0
    mv -f "$backup" "$target" # restore wrangler.toml
    unset EMAIL_PAGES_TOML_BACKUP EMAIL_PAGES_TOML_BACKUP_TARGET
}
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

# ── 入口 ──
email_deploy() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "Cloudflare Temp Email 一键部署"
    echo -e "${C_CYAN}项目: https://github.com/dreamhunter2333/cloudflare_temp_email${C_RESET}"
    echo ""

    # 已部署：让用户决定是否覆盖
    if email_state_load 2>/dev/null; then
        print_warn "检测到已有部署：${EMAIL_FRONTEND_DOMAIN:-?} / ${EMAIL_API_DOMAIN:-?}"
        print_error "已安装状态不允许直接覆盖部署，避免生成新的 D1/Pages 后丢失旧资源 ID。"
        print_info "如需更新，请使用管理菜单【重新部署/升级】；如需重装，请先执行完整卸载。"
        pause
        return 1
    # 半成品（state 存在但 INSTALLED=0）：强警告，建议先卸载残留
    elif [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
        _email_state_reset_vars
        # shellcheck disable=SC1090
        source "$EMAIL_STATE_FILE"
        echo -e "${C_RED}⚠ 检测到上次部署未完成（state 存在但 EMAIL_INSTALLED=0）${C_RESET}"
        echo "  旧 state 中记录的资源："
        [[ -n "$EMAIL_D1_ID" ]]         && echo "    • D1:     $EMAIL_D1_NAME ($EMAIL_D1_ID)"
        [[ -n "$EMAIL_WORKER_NAME" ]]   && echo "    • Worker: $EMAIL_WORKER_NAME"
        [[ -n "$EMAIL_PAGES_PROJECT" ]] && echo "    • Pages:  $EMAIL_PAGES_PROJECT"
        echo ""
        print_warn "强烈建议先返回菜单选【强制卸载】清理远端残留，再重新部署。"
        print_warn "直接覆盖部署会生成新的 D1/Pages 名，旧资源 ID 将永远丢失，导致后续无法精准回收。"
        echo ""
        if ! confirm "确定要继续覆盖部署？（旧 state 会备份到 .bak.<时间戳>）"; then
            pause; return
        fi
        local bak
        bak=$(email_state_backup) && [[ -n "$bak" ]] && print_info "已备份旧 state → $bak"
    fi

    _email_state_reset_vars
    email_state_init_dirs
    email_log "===== email_deploy start ====="

    _email_deploy_check_env || { pause; return 1; }
    _email_deploy_collect_inputs || { pause; return 1; }

    # 校验 token / 拉 zone
    if ! email_run "校验 Cloudflare API Token" _email_cf_token_verify; then
        print_error "Token 验证失败，请检查 Token 权限与有效性"
        return 1
    fi

    if ! EMAIL_ZONE_ID=$(_email_cf_zone_id_by_name "$EMAIL_DOMAIN"); then
        print_error "无法获取域名 Zone ID，确认 $EMAIL_DOMAIN 已托管到 Cloudflare"
        return 1
    fi
    email_log "Zone ID: $EMAIL_ZONE_ID"
    print_success "Zone ID: $EMAIL_ZONE_ID"

    _email_deploy_pick_worker_name || { pause; return 1; }

    _email_deploy_clone_project || { pause; return 1; }
    _email_deploy_setup_d1 || { pause; return 1; }
    _email_deploy_render_toml || { pause; return 1; }
    _email_deploy_worker || { pause; return 1; }
    _email_deploy_secrets || { pause; return 1; }
    _email_deploy_frontend || { pause; return 1; }
    _email_deploy_pages || { pause; return 1; }
    _email_deploy_dns || { pause; return 1; }
    _email_deploy_email_routing || { pause; return 1; }

    EMAIL_INSTALLED=1
    EMAIL_INSTALL_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
    email_state_write

    _email_deploy_postcheck
    _email_deploy_summary
    log_action "Cloudflare Temp Email deployed: ${EMAIL_FRONTEND_DOMAIN} / ${EMAIL_API_DOMAIN}"
    pause
}

# ── 1. 环境依赖 ──
_email_validate_dns_label() {
    validate_dns_label "${1:-}"
}

# 当 Token 可见多个 Account 时，强制让用户选；只有 1 个时静默选用
_email_deploy_pick_account() {
    local accounts_raw count
    accounts_raw=$(_email_cf_accounts_list 2>/dev/null) || {
        print_error "获取 Account 列表失败（Token 权限不足?）"
        return 1
    }
    count=$(printf '%s\n' "$accounts_raw" | grep -c .)
    if [[ "$count" -eq 0 ]]; then
        print_error "Token 未关联任何 Account"
        return 1
    fi
    if [[ "$count" -eq 1 ]]; then
        CF_ACCOUNT_ID=$(printf '%s' "$accounts_raw" | awk -F'\t' '{print $1}')
        export CF_ACCOUNT_ID
        local aname
        aname=$(printf '%s' "$accounts_raw" | awk -F'\t' '{print $2}')
        print_success "Account: $aname ($CF_ACCOUNT_ID)"
        return 0
    fi
    echo -e "${C_CYAN}Token 可见多个 Cloudflare Account，请选择:${C_RESET}"
    local i=1 ids=() names=() aid aname
    while IFS=$'\t' read -r aid aname; do
        [[ -z "$aid" ]] && continue
        printf "  %d. %s (%s)\n" "$i" "$aname" "$aid"
        ids+=("$aid"); names+=("$aname"); ((i++)) || true
    done <<< "$accounts_raw"
    local sel
    while true; do
        read -e -r -p "选择 [1-$((i-1))]: " sel
        if [[ "$sel" =~ ^[0-9]+$ && "$sel" -ge 1 && "$sel" -le $((i-1)) ]]; then
            CF_ACCOUNT_ID="${ids[$((sel-1))]}"
            export CF_ACCOUNT_ID
            print_success "Account: ${names[$((sel-1))]} ($CF_ACCOUNT_ID)"
            return 0
        fi
        print_error "无效选择"
    done
}

_email_deploy_check_env() {
    print_info "检查运行环境..."
    local pkg
    for pkg in git curl jq; do
        command_exists "$pkg" || install_package "$pkg" || { print_error "$pkg 安装失败"; return 1; }
    done

    if ! command_exists node; then
        email_run "安装 Node.js LTS" bash -o pipefail -c '
            set -e
            tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/server-manage-email-node.XXXXXX")
            chmod 700 "$tmp_dir" 2>/dev/null || true
            tmp="$tmp_dir/setup_lts.x"
            cleanup_node_tmp() { rm -rf "$tmp_dir"; }
            trap cleanup_node_tmp EXIT
            curl -fsSL https://deb.nodesource.com/setup_lts.x -o "$tmp"
            chmod 600 "$tmp" 2>/dev/null || true
            bash "$tmp" >/dev/null 2>&1
            apt-get install -y -qq nodejs
        ' || { print_error "Node.js 安装失败，请手动安装"; return 1; }
    fi
    if command_exists corepack; then
        email_run "启用 corepack" corepack enable || true
    fi
    command_exists pnpm || email_run "安装 pnpm" npm install -g pnpm || return 1
    print_success "环境检查通过 (node=$(node -v 2>/dev/null) pnpm=$(pnpm -v 2>/dev/null) wrangler=项目本地依赖)"
}

# ── 2. 交互式收集（Token 隐藏 / 管理员密码不回显）──
_email_deploy_collect_inputs() {
    echo ""
    email_read_secret "Cloudflare API Token" CF_API_TOKEN || { print_error "Token 不能为空"; return 1; }
    export CF_API_TOKEN
    print_info "已收到 Token: $(email_mask_token "$CF_API_TOKEN")"

    local cf_aid=""
    read -e -r -p "Cloudflare Account ID (留空让脚本列出可见账户): " cf_aid
    if [[ -z "$cf_aid" ]]; then
        _email_deploy_pick_account || return 1
    else
        CF_ACCOUNT_ID="$cf_aid"
        export CF_ACCOUNT_ID
    fi
    # 持久化到 state，供后续管理/卸载使用，避免多 Account 场景下误用第一个
    EMAIL_CF_ACCOUNT_ID="$CF_ACCOUNT_ID"
    # 同步导出 Wrangler 新版环境变量（避免走 deprecated CF_*）
    _email_export_wrangler_env

    read -e -r -p "域名 (如 example.com): " EMAIL_DOMAIN
    validate_domain "$EMAIL_DOMAIN" || { print_error "域名格式无效"; return 1; }

    while :; do
        read -e -r -p "API 子域名前缀 [mail-api]: " EMAIL_API_PREFIX
        EMAIL_API_PREFIX="${EMAIL_API_PREFIX:-mail-api}"
        _email_validate_dns_label "$EMAIL_API_PREFIX" && break
        print_error "前缀格式无效（DNS label: 仅 a-z 0-9 -，首尾非短横，1-63 字符）"
    done
    while :; do
        read -e -r -p "前端子域名前缀 [mail]: " EMAIL_FRONTEND_PREFIX
        EMAIL_FRONTEND_PREFIX="${EMAIL_FRONTEND_PREFIX:-mail}"
        _email_validate_dns_label "$EMAIL_FRONTEND_PREFIX" && break
        print_error "前缀格式无效（DNS label）"
    done
    while :; do
        read -e -r -p "邮箱地址前缀 (留空无前缀): " EMAIL_ADDRESS_PREFIX
        # 邮箱地址前缀可为空；非空时按 DNS label 字符集校验（更严格的 mailbox local-part 略过）
        [[ -z "$EMAIL_ADDRESS_PREFIX" ]] && break
        _email_validate_dns_label "$EMAIL_ADDRESS_PREFIX" && break
        print_error "前缀格式无效（仅 a-z 0-9 -）"
    done

    EMAIL_API_DOMAIN="${EMAIL_API_PREFIX}.${EMAIL_DOMAIN}"
    EMAIL_FRONTEND_DOMAIN="${EMAIL_FRONTEND_PREFIX}.${EMAIL_DOMAIN}"
    # Pages 项目用随机后缀彻底避免撞名（pages 名不影响 worker 路由）
    EMAIL_PAGES_PROJECT="temp-email-pages-$(openssl rand -hex 3)"
    EMAIL_D1_NAME="temp-email-$(openssl rand -hex 3)"
    # Worker 名在 _email_deploy_pick_worker_name 中决定（需要先验证 Token）
    EMAIL_WORKER_NAME=""

    echo -e "${C_GRAY}留空将自动生成 32 位十六进制密码（部署完成后展示并保存到 ${EMAIL_ADMIN_FILE}）${C_RESET}"
    local admin_pw=""
    # 隐藏输入避免肩窥；email_read_secret 在空值时返回 1，但这里允许留空走自动生成
    read -r -s -p "$(echo -e "${C_YELLOW}管理员密码 [留空自动生成]: ${C_RESET}")" admin_pw
    echo ""
    EMAIL_ADMIN_PASSWORD="$admin_pw"
    if [[ -z "$EMAIL_ADMIN_PASSWORD" ]]; then
        EMAIL_ADMIN_PASSWORD=$(openssl rand -hex 16)
        print_success "已自动生成管理员密码（部署完成后展示并保存到 $EMAIL_ADMIN_FILE）"
    else
        print_info "已收到管理员密码（不回显）"
    fi

    EMAIL_JWT_SECRET=$(openssl rand -hex 32)

    EMAIL_RESEND_TOKEN=""
    EMAIL_RESEND_DKIM=""
    if confirm "是否启用 Resend 发件能力?"; then
        email_read_secret "Resend API Token" EMAIL_RESEND_TOKEN || { print_error "Resend Token 不能为空"; return 1; }
        print_info "已收到 Resend Token: $(email_mask_token "$EMAIL_RESEND_TOKEN")"
        read -e -r -p "Resend DKIM 值 (p=MIGfMA0...): " EMAIL_RESEND_DKIM
        [[ -z "$EMAIL_RESEND_DKIM" ]] && { print_error "DKIM 不能为空"; return 1; }
        EMAIL_RESEND_ENABLED=1
        EMAIL_RESEND_SEND_DOMAIN="send.${EMAIL_DOMAIN}"
    fi

    echo ""
    print_info "配置确认:"
    echo "  域名:           $EMAIL_DOMAIN"
    echo "  API 地址:       https://$EMAIL_API_DOMAIN"
    echo "  前端地址:       https://$EMAIL_FRONTEND_DOMAIN"
    echo "  邮箱格式:       ${EMAIL_ADDRESS_PREFIX:+${EMAIL_ADDRESS_PREFIX}.}xxx@${EMAIL_DOMAIN}"
    echo "  D1 数据库名:    $EMAIL_D1_NAME"
    echo "  管理员密码:     $([[ -n "$admin_pw" ]] && echo "(用户提供)" || echo "(自动生成 — 完成后查看)")"
    echo "  Resend:         $([[ $EMAIL_RESEND_ENABLED -eq 1 ]] && echo "已启用" || echo "未启用")"
    echo ""
    echo -e "${C_RED}========== ⚠ MX 记录将被替换 — 请仔细阅读 ==========${C_RESET}"
    echo -e "${C_YELLOW}本部署会清空 ${C_RESET}${C_RED}${EMAIL_DOMAIN}${C_RESET}${C_YELLOW} 根域现有的所有 MX 记录，并写入 3 条 Cloudflare Email Routing：${C_RESET}"
    echo -e "${C_GRAY}    • route1.mx.cloudflare.net  (priority 12)${C_RESET}"
    echo -e "${C_GRAY}    • route2.mx.cloudflare.net  (priority 41)${C_RESET}"
    echo -e "${C_GRAY}    • route3.mx.cloudflare.net  (priority 69)${C_RESET}"
    echo -e "${C_RED}如该域名已有：Google Workspace / Microsoft 365 / Zoho / 自建邮件服务器 / 任何企业邮箱，${C_RESET}"
    echo -e "${C_RED}部署后这些服务将立即停止收信！${C_RESET}"
    echo -e "${C_GREEN}推荐做法：使用一个未托管邮件的专用域名作为 EMAIL_DOMAIN${C_RESET}"
    echo -e "${C_GREEN}（例如新购的 .top/.xyz 等便宜域名，从未配置过 MX）。${C_RESET}"
    echo -e "${C_GRAY}如需用子域名（如 ${C_RESET}${C_CYAN}tmp.${EMAIL_DOMAIN}${C_RESET}${C_GRAY}），${C_RESET}"
    echo -e "${C_GRAY}必须先在 Cloudflare 控制台把该子域名独立托管/委派为新 Zone（与主域 Zone 分离），${C_RESET}"
    echo -e "${C_GRAY}否则部署会在 \"获取 Zone ID\" 阶段失败 — CF Email Routing 要求收信域名必须是独立 Zone。${C_RESET}"
    echo -e "${C_RED}======================================================${C_RESET}"
    echo ""
    confirm "确认以上配置开始部署?" || return 1
    # 二次确认 MX 替换 — 防止用户在第一道 confirm 时未仔细看警告
    if ! confirm "$(echo -e "${C_RED}再次确认：${EMAIL_DOMAIN} 没有正在使用的企业邮箱或其他 MX 服务，可以清空现有 MX?${C_RESET}")"; then
        print_warn "已取消部署 — 强烈建议改用专用域名（或已独立托管为 Zone 的子域名）后重试"
        return 1
    fi
}

# ── 2b. Worker 名字决策（需要 Token 已验证）──
_email_deploy_pick_worker_name() {
    local default_name="cloudflare_temp_email"
    local exists_rc
    _email_cf_worker_exists "$default_name"
    exists_rc=$?
    case "$exists_rc" in
        1)
            EMAIL_WORKER_NAME="$default_name"
            print_success "Worker 名: $EMAIL_WORKER_NAME"
            return 0
            ;;
        0)
            ;;
        *)
            print_error "无法确认默认 Worker 是否存在，已中止以避免覆盖生产 Worker"
            print_info "请检查 Cloudflare Token 权限、Account ID 与网络后重试。"
            return 1
            ;;
    esac
    print_warn "账户已存在名为 ${default_name} 的 Worker"
    echo "  1. 取消部署"
    echo "  2. 使用自定义 Worker 名"
    echo "  3. 覆盖现有 Worker (危险：会破坏当前同名 Worker 的部署!)"
    local ans new_name
    while true; do
        read -e -r -p "选择 [1]: " ans
        case "${ans:-1}" in
            1)
                print_warn "已取消部署"
                return 1
                ;;
            2)
                read -e -r -p "新 Worker 名 (3-63 字符, 仅 a-z 0-9 - _): " new_name
                if [[ ! "$new_name" =~ ^[a-z][a-z0-9_-]{2,62}$ ]]; then
                    print_error "名字格式无效（需以小写字母开头）"
                    continue
                fi
                _email_cf_worker_exists "$new_name"
                exists_rc=$?
                case "$exists_rc" in
                    0)
                        print_error "$new_name 也已存在，请换一个"
                        continue
                        ;;
                    1)
                        ;;
                    *)
                        print_error "无法确认 $new_name 是否存在，已中止以避免覆盖生产 Worker"
                        return 1
                        ;;
                esac
                EMAIL_WORKER_NAME="$new_name"
                print_success "Worker 名: $EMAIL_WORKER_NAME"
                return 0
                ;;
            3)
                confirm "确认覆盖现有 ${default_name}? 此操作不可逆" || continue
                EMAIL_WORKER_NAME="$default_name"
                print_warn "将覆盖现有 Worker: $EMAIL_WORKER_NAME"
                return 0
                ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ── 3. clone 项目 ──
_email_deploy_clone_project() {
    if [[ -d "$EMAIL_INSTALL_DIR/.git" ]]; then
        email_run "更新仓库" git -C "$EMAIL_INSTALL_DIR" fetch --tags --prune || return 1
    else
        rm -rf "$EMAIL_INSTALL_DIR"
        email_run "克隆 cloudflare_temp_email" git clone --quiet \
            https://github.com/dreamhunter2333/cloudflare_temp_email.git "$EMAIL_INSTALL_DIR" || return 1
    fi
    local latest_tag
    latest_tag=$(git -C "$EMAIL_INSTALL_DIR" describe --tags "$(git -C "$EMAIL_INSTALL_DIR" rev-list --tags --max-count=1)" 2>/dev/null || echo "")
    if [[ -z "$latest_tag" ]]; then
        print_error "未能解析 git tag，仓库可能异常"
        return 1
    fi
    email_run "切换到最新 tag $latest_tag" git -C "$EMAIL_INSTALL_DIR" checkout --quiet "$latest_tag" || return 1
    EMAIL_INSTALL_VERSION="$latest_tag"
    print_success "项目版本: $latest_tag"
}

# ── 4. D1 数据库 ──
_email_deploy_setup_d1() {
    cd "$EMAIL_INSTALL_DIR/worker" || return 1
    email_run "安装 Worker 依赖" pnpm install --no-frozen-lockfile || return 1

    local out
    print_info "创建 D1 数据库 $EMAIL_D1_NAME..."
    if ! out=$(_email_wrangler d1 create "$EMAIL_D1_NAME" 2>&1); then
        email_log "D1 create failed: $out"
        print_error "D1 创建失败"; tail -n 10 "$EMAIL_LOG_FILE" | sed 's/^/  /'
        return 1
    fi
    echo "$out" >> "$EMAIL_LOG_FILE"
    EMAIL_D1_ID=$(echo "$out" | grep -oE 'database_id\s*=\s*"[^"]+"' | head -1 | grep -oE '"[^"]+"' | tr -d '"')
    [[ -n "$EMAIL_D1_ID" ]] || { print_error "解析 D1 ID 失败"; return 1; }
    print_success "D1 ID: $EMAIL_D1_ID"

    # 立刻写一份临时 state 以便失败时能回收
    email_state_write

    # 渲染最小 wrangler.toml 以便 d1 execute 找到 binding
    _email_render_min_toml || return 1

    # 按字母序应用所有 migration: schema.sql 优先，然后 *-patch.sql
    local patches=("../db/schema.sql")
    local p
    while IFS= read -r p; do
        patches+=("$p")
    done < <(ls "$EMAIL_INSTALL_DIR/db"/*-patch.sql 2>/dev/null | sort)

    for p in "${patches[@]}"; do
        [[ -f "$p" ]] || continue
        local base
        base=$(basename "$p")
        email_run "应用 D1 schema: $base" \
            _email_wrangler d1 execute "$EMAIL_D1_NAME" --file="$p" --remote || return 1
        EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED} ${base}"
    done
    EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED# }"
}

# 仅含 D1 binding 的最小 toml（供 d1 execute 使用）
_email_render_min_toml() {
    local content
    content=$(cat <<EOF
name = "${EMAIL_WORKER_NAME}"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]

[[d1_databases]]
binding = "DB"
database_name = "${EMAIL_D1_NAME}"
database_id = "${EMAIL_D1_ID}"
EOF
)
    _email_write_private_file "$EMAIL_INSTALL_DIR/worker/wrangler.toml" "$content"
}

# ── 5. 完整 wrangler.toml ──
_email_deploy_render_toml() {
    local domains_json prefix_val admin_json
    domains_json="[\"${EMAIL_DOMAIN}\"]"
    admin_json=$(jq -nc --arg p "$EMAIL_ADMIN_PASSWORD" '[$p]')
    # 上游 Worker 直接把 PREFIX 拼到 local-part 前面（无分隔符）。
    # 为得到用户在确认页看到的 "prefix.xxx@domain" 形态，写入 wrangler.toml 时自动补 "."
    # 末尾。用户已带 "." 时不重复。
    if [[ -n "$EMAIL_ADDRESS_PREFIX" ]]; then
        if [[ "${EMAIL_ADDRESS_PREFIX: -1}" == "." ]]; then
            prefix_val="$EMAIL_ADDRESS_PREFIX"
        else
            prefix_val="${EMAIL_ADDRESS_PREFIX}."
        fi
    else
        prefix_val=""
    fi

    local content
    content=$(cat <<EOF
name = "${EMAIL_WORKER_NAME}"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]
keep_vars = true

routes = [
    { pattern = "${EMAIL_API_DOMAIN}", custom_domain = true },
]

# 注意：Cloudflare Send Email binding（[[send_email]]）要求 Email Routing 已启用 + 发件地址
# 已在 Dashboard 完成验证，否则首次 wrangler deploy 会失败。本脚本默认不启用此 binding，
# 与上游 wrangler.toml.template 保持一致；Resend 用户走 RESEND_TOKEN secret，无需 send_email。
# 如确需使用 Cloudflare 原生 SEND_MAIL，请手动在 Dashboard 完成地址验证后取消下列注释并重新部署。
#send_email = [
#    { name = "SEND_MAIL" },
#]

[triggers]
crons = [ "0 0 * * *" ]

[vars]
PREFIX = "${prefix_val}"
DEFAULT_DOMAINS = ${domains_json}
DOMAINS = ${domains_json}
JWT_SECRET = "${EMAIL_JWT_SECRET}"
BLACK_LIST = ""
ENABLE_USER_CREATE_EMAIL = true
ENABLE_USER_DELETE_EMAIL = true
ENABLE_AUTO_REPLY = false
ADMIN_PASSWORDS = ${admin_json}

[[d1_databases]]
binding = "DB"
database_name = "${EMAIL_D1_NAME}"
database_id = "${EMAIL_D1_ID}"
EOF
)
    _email_write_private_file "$EMAIL_INSTALL_DIR/worker/wrangler.toml" "$content" || return 1
    print_success "wrangler.toml 已生成"
}

# ── 6. 部署 Worker ──
_email_deploy_worker() {
    cd "$EMAIL_INSTALL_DIR/worker" || return 1
    email_run "安装 Worker 依赖" pnpm install --no-frozen-lockfile || return 1
    email_run "部署 Worker (${EMAIL_API_DOMAIN})" _email_wrangler deploy || return 1
}

# ── 7. 写 secrets：ADMIN_PASSWORDS + Resend Token（走 API 不走 wrangler）──
_email_deploy_secrets() {
    # ADMIN_PASSWORDS 走 secret — 值为 JSON 数组字面量 ["pw"]，上游 Worker 端 JSON.parse 后得数组
    # 不要再 | tostring，否则 secret 变成字符串字面量 "[\"pw\"]"，JSON.parse 得字符串而不是数组
    local admin_json
    admin_json=$(jq -nc --arg p "$EMAIL_ADMIN_PASSWORD" '[$p]')
    if ! _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "ADMIN_PASSWORDS" "$admin_json"; then
        print_error "ADMIN_PASSWORDS secret 写入失败"
        return 1
    fi
    print_success "ADMIN_PASSWORDS 已通过 secret 配置"
    email_save_admin_password "$EMAIL_ADMIN_PASSWORD"

    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        if _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$EMAIL_RESEND_TOKEN"; then
            print_success "RESEND_TOKEN 已通过 secret 配置"
        else
            EMAIL_RESEND_ENABLED=0
            EMAIL_RESEND_SEND_DOMAIN=""
            EMAIL_DNS_DKIM_ID=""; EMAIL_DNS_SPF_ID=""; EMAIL_DNS_SEND_MX_ID=""; EMAIL_DNS_DMARC_ID=""
            email_state_write 2>/dev/null || true
            print_error "RESEND_TOKEN 配置失败，已停止部署并保留 partial state 供卸载/重试。"
            return 1
        fi
    fi
}

# ── 8. 构建前端 ──
_email_deploy_frontend() {
    cd "$EMAIL_INSTALL_DIR/frontend" || return 1
    email_run "安装前端依赖" pnpm install --no-frozen-lockfile || return 1
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "构建前端 (VITE_API_BASE=${VITE_API_BASE})" pnpm build:pages || return 1
}

# ── 9. 部署 Pages 前端 ──
_email_deploy_pages() {
    cd "$EMAIL_INSTALL_DIR/pages" || return 1

    # 同步 pages/wrangler.toml service binding（升级/重部署链路同样调用此 helper，避免遗漏）
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（文件可能缺失，请手工检查）"

    email_run "安装 Pages 依赖" pnpm install --no-frozen-lockfile || {
        _email_restore_pages_service_binding
        return 1
    }

    # 创建项目（已存在则忽略）
    if ! _email_cf_pages_project_create "$EMAIL_PAGES_PROJECT" 2>/dev/null; then
        email_log "Pages project create returned non-zero — 可能已存在，继续"
    fi

    local deploy_rc=0
    email_run "部署 Pages (${EMAIL_PAGES_PROJECT})" \
        _email_wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
            --branch production --commit-dirty=true || deploy_rc=$?
    _email_restore_pages_service_binding
    [[ "$deploy_rc" -eq 0 ]] || return "$deploy_rc"

    EMAIL_PAGES_DOMAIN=$(_email_cf_pages_get_subdomain "$EMAIL_PAGES_PROJECT" 2>/dev/null)
    [[ -n "$EMAIL_PAGES_DOMAIN" ]] || EMAIL_PAGES_DOMAIN="${EMAIL_PAGES_PROJECT}.pages.dev"
    print_success "Pages 部署完成: $EMAIL_PAGES_DOMAIN"

    # 绑定自定义域名
    if _email_cf_pages_attach_domain "$EMAIL_PAGES_PROJECT" "$EMAIL_FRONTEND_DOMAIN" 2>/dev/null; then
        print_success "Pages 自定义域名: $EMAIL_FRONTEND_DOMAIN"
    else
        EMAIL_INSTALLED=0
        email_state_write 2>/dev/null || true
        print_error "Pages 自定义域名绑定失败，已停止部署并保留 partial state 供卸载/重试。"
        print_info "请确认 ${EMAIL_FRONTEND_DOMAIN} 在当前 Cloudflare Zone 下，且 Pages Custom Domains 权限可用。"
        return 1
    fi
}

# ── 10. DNS 记录 ──
# 收信关键记录（Frontend CNAME / MX）失败时 return 1，由 email_deploy 阻断完成标记；
# 用户选择启用 Resend 时，secret/DNS 任一失败也 fail-closed，避免 state 显示已启用但链路不可用。
_email_deploy_dns() {
    print_info "添加 DNS 记录..."
    local zid="$EMAIL_ZONE_ID"
    local _dns_fail=0

    # 前端 CNAME（橙云代理）— 若同名记录已存在，先清理
    if ! _email_cf_dns_purge "$zid" CNAME "$EMAIL_FRONTEND_DOMAIN"; then
        print_error "清理旧前端 CNAME 失败 — 已停止写入新的 CNAME"
        _dns_fail=1
    elif _email_cf_dns_create_record_into EMAIL_DNS_FRONTEND_ID "$zid" "CNAME" \
            "$EMAIL_FRONTEND_DOMAIN" "$EMAIL_PAGES_DOMAIN" "" "true"; then
        print_success "CNAME $EMAIL_FRONTEND_PREFIX → $EMAIL_PAGES_DOMAIN"
    else
        print_error "前端 CNAME 添加失败 — 用户将无法通过 ${EMAIL_FRONTEND_DOMAIN} 访问 UI"
        _dns_fail=1
    fi

    # MX 记录到 Cloudflare Email Routing（3 条任一缺失会降级路由，全失败则无法收信）
    local _mx_ok=0
    if ! _email_cf_dns_purge "$zid" MX "$EMAIL_DOMAIN"; then
        print_error "清理旧 MX 记录失败 — 已停止写入 Cloudflare Email Routing MX"
        _dns_fail=1
    else
        if _email_cf_dns_create_record_into EMAIL_DNS_MX1_ID "$zid" "MX" "$EMAIL_DOMAIN" "route1.mx.cloudflare.net" "12"; then
            print_success "MX 1 (route1)"; _mx_ok=$((_mx_ok+1))
        else
            print_warn "MX 1 失败"
        fi
        if _email_cf_dns_create_record_into EMAIL_DNS_MX2_ID "$zid" "MX" "$EMAIL_DOMAIN" "route2.mx.cloudflare.net" "41"; then
            print_success "MX 2 (route2)"; _mx_ok=$((_mx_ok+1))
        else
            print_warn "MX 2 失败"
        fi
        if _email_cf_dns_create_record_into EMAIL_DNS_MX3_ID "$zid" "MX" "$EMAIL_DOMAIN" "route3.mx.cloudflare.net" "69"; then
            print_success "MX 3 (route3)"; _mx_ok=$((_mx_ok+1))
        else
            print_warn "MX 3 失败"
        fi
    fi
    if [[ "$_mx_ok" -eq 0 ]]; then
        print_error "MX 记录全部添加失败 — 邮箱将无法收信"
        _dns_fail=1
    elif [[ "$_mx_ok" -lt 3 ]]; then
        print_warn "MX 记录仅创建 ${_mx_ok}/3 — Cloudflare 推荐 3 条，建议 Dashboard 补齐"
    fi

    # Resend 相关（DKIM/SPF/SEND_MX/DMARC）：用户选择启用时必须全部写入成功。
    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        local send_sub="send.${EMAIL_DOMAIN}"
        local _resend_purge_fail=0 _resend_create_fail=0
        _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}" || _resend_purge_fail=1
        _email_cf_dns_purge "$zid" TXT "$send_sub" || _resend_purge_fail=1
        _email_cf_dns_purge "$zid" MX  "$send_sub" || _resend_purge_fail=1
        _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}" || _resend_purge_fail=1

        if [[ "$_resend_purge_fail" -ne 0 ]]; then
            EMAIL_RESEND_ENABLED=0
            EMAIL_RESEND_SEND_DOMAIN=""
            EMAIL_DNS_DKIM_ID=""; EMAIL_DNS_SPF_ID=""; EMAIL_DNS_SEND_MX_ID=""; EMAIL_DNS_DMARC_ID=""
            print_error "清理旧 Resend DNS 记录失败，已停止启用 Resend。"
            _dns_fail=1
        else
            _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$EMAIL_RESEND_DKIM" \
                && print_success "DKIM (resend._domainkey)" || { print_warn "DKIM 失败"; _resend_create_fail=1; }
            _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
                && print_success "SPF (send.${EMAIL_DOMAIN})" || { print_warn "SPF 失败"; _resend_create_fail=1; }
            _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
                && print_success "Send MX" || { print_warn "Send MX 失败"; _resend_create_fail=1; }
            _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
                && print_success "DMARC" || { print_warn "DMARC 失败"; _resend_create_fail=1; }
            if [[ "$_resend_create_fail" -ne 0 ]]; then
                EMAIL_RESEND_ENABLED=0
                EMAIL_RESEND_SEND_DOMAIN=""
                print_error "创建 Resend DNS 记录失败，已停止启用 Resend 并保留已创建记录 ID 供卸载/重试。"
                _dns_fail=1
            fi
        fi
    fi

    # 失败也落盘 record_id（已创建的部分仍可被卸载回收），主流程根据 return 决定是否标 installed
    email_state_write
    return $_dns_fail
}

# ── 11. Email Routing catch-all → Worker ──
# routing enable 或 catch-all 任一失败 → return 1，主流程不会标 installed
_email_deploy_email_routing() {
    if ! email_run "启用 Cloudflare Email Routing" _email_cf_email_routing_enable "$EMAIL_ZONE_ID"; then
        print_error "Email Routing 启用失败 — 临时邮箱无法收信"
        print_info "请登录 Dashboard → Email → Email Routing 手动启用后，进 partial 菜单【强制卸载】+【重新部署】"
        email_state_write
        return 1
    fi
    if ! email_run "配置 Catch-all → Worker(${EMAIL_WORKER_NAME})" _email_cf_catch_all_to_worker "$EMAIL_ZONE_ID" "$EMAIL_WORKER_NAME"; then
        print_error "Catch-all 自动配置失败 — 邮件不会路由到 Worker（收信不入库）"
        print_info "Dashboard → Email Routing → Catch-all → 手动指向 Worker(${EMAIL_WORKER_NAME})"
        email_state_write
        return 1
    fi
    EMAIL_CATCH_ALL_ENABLED=1
    email_state_write
    return 0
}

# ── 12. 健康检查 ──
_email_deploy_postcheck() {
    print_info "等待部署生效 (10s)..."
    sleep 10
    local resp
    resp=$(curl -sS --max-time 10 "https://${EMAIL_API_DOMAIN}/health_check" 2>/dev/null)
    if [[ "$resp" == "OK" ]]; then
        print_success "Worker 后端健康检查通过"
    else
        print_warn "Worker 暂未响应 — DNS/边缘可能需要数分钟生效"
    fi
}

# ── 13. 汇总 ──
_email_deploy_summary() {
    echo ""
    echo -e "${C_GREEN}========== 部署完成 ==========${C_RESET}"
    echo -e "  前端地址:    ${C_CYAN}https://${EMAIL_FRONTEND_DOMAIN}${C_RESET}"
    echo -e "  API 地址:    ${C_CYAN}https://${EMAIL_API_DOMAIN}${C_RESET}"
    echo -e "  管理面板:    ${C_CYAN}https://${EMAIL_FRONTEND_DOMAIN}/admin${C_RESET}"
    echo -e "  管理员密码:  ${C_YELLOW}${EMAIL_ADMIN_PASSWORD}${C_RESET}"
    echo -e "  密码已保存:  ${C_GRAY}${EMAIL_ADMIN_FILE} (mode 600)${C_RESET}"
    echo -e "  状态文件:    ${C_GRAY}${EMAIL_STATE_FILE}${C_RESET}"
    echo -e "  部署日志:    ${C_GRAY}${EMAIL_LOG_FILE}${C_RESET}"
    echo ""
    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        echo -e "${C_YELLOW}Resend 后续:${C_RESET} 访问 https://resend.com/domains 触发验证"
        echo ""
    fi

    # 防止敏感变量残留
    unset CF_API_TOKEN EMAIL_RESEND_TOKEN EMAIL_RESEND_DKIM EMAIL_JWT_SECRET EMAIL_ADMIN_PASSWORD
}

# 前置：所有 manage 操作均要求 state 已加载 + Token 已输入
_email_manage_prepare() {
    if ! email_state_load 2>/dev/null; then
        print_error "未检测到已部署的临时邮箱（缺少 ${EMAIL_STATE_FILE}）"
        return 1
    fi
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        echo -e "${C_GRAY}管理操作需要 Cloudflare API Token (与部署时同 Token 即可)${C_RESET}"
        email_read_secret "Cloudflare API Token" CF_API_TOKEN || return 1
        export CF_API_TOKEN
        if ! _email_cf_token_verify 2>/dev/null; then
            print_error "Token 校验失败"
            unset CF_API_TOKEN
            return 1
        fi
    fi
    if [[ -z "${CF_ACCOUNT_ID:-}" ]]; then
        if [[ -n "${EMAIL_CF_ACCOUNT_ID:-}" ]]; then
            CF_ACCOUNT_ID="$EMAIL_CF_ACCOUNT_ID"
            export CF_ACCOUNT_ID
        else
            # 兼容旧 state（无持久化 ACCOUNT_ID）— 强制让用户选，避免误取第一个
            print_warn "state 中未记录 Account ID（旧版本部署），需要重新选择"
            _email_deploy_pick_account || return 1
            EMAIL_CF_ACCOUNT_ID="$CF_ACCOUNT_ID"
            email_state_write
        fi
    fi
    # 同步导出 Wrangler 新版环境变量
    _email_export_wrangler_env
    cd "$EMAIL_INSTALL_DIR/worker" 2>/dev/null || {
        print_error "本地项目目录缺失: $EMAIL_INSTALL_DIR/worker"
        return 1
    }
}

# 解析 wrangler.toml [vars] 中的 string 字段值（用于保留 JWT_SECRET 等）
_email_toml_get_var() {
    local key="$1" toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    [[ -f "$toml" ]] || return 1
    grep -E "^${key}[[:space:]]*=" "$toml" | head -1 | sed -E 's/^[^=]+=[[:space:]]*"?([^"]*)"?.*/\1/'
}

_email_manage_update_admin_passwords_var() {
    local admin_json="$1"
    local toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    [[ -f "$toml" ]] || return 1

    cp -a "$toml" "${toml}.adminpw.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    local line="ADMIN_PASSWORDS = ${admin_json}"
    local content
    if grep -qE '^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=' "$toml"; then
        content=$(ADMIN_PASSWORDS_LINE="$line" awk '
            BEGIN { line = ENVIRON["ADMIN_PASSWORDS_LINE"] }
            /^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=/ { print line; next }
            { print }
        ' "$toml") || return 1
    else
        content=$(ADMIN_PASSWORDS_LINE="$line" awk '
            BEGIN { line = ENVIRON["ADMIN_PASSWORDS_LINE"]; inserted=0 }
            /^\[vars\]/ { print; print line; inserted=1; next }
            { print }
            END {
                if (!inserted) {
                    print ""
                    print "[vars]"
                    print line
                }
            }
        ' "$toml") || return 1
    fi
    _email_write_private_file "$toml" "$content" || return 1
    _email_export_wrangler_env
    cd "$EMAIL_INSTALL_DIR/worker" || return 1
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || return 1
    email_run "更新 ADMIN_PASSWORDS 普通变量并重新部署 Worker" _email_wrangler deploy
}

# ── 1. 修改管理员密码 ──
email_manage_change_admin_password() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "修改管理员密码"
    _email_manage_prepare || { pause; return; }

    echo -e "${C_GRAY}留空将自动生成 32 位十六进制密码${C_RESET}"
    local new_pw=""
    # 隐藏输入避免肩窥；空值走自动生成分支
    read -r -s -p "$(echo -e "${C_YELLOW}新管理员密码 [留空自动生成]: ${C_RESET}")" new_pw
    echo ""
    if [[ -z "$new_pw" ]]; then
        new_pw=$(openssl rand -hex 16)
        print_info "已自动生成"
    else
        print_info "已收到密码（不回显）"
    fi
    if (( ${#new_pw} < 8 )); then
        print_error "密码长度不足 8 位"; pause; return
    fi

    local admin_json
    # 与 14c 一致：JSON 数组字面量 ["pw"]，不要 | tostring
    admin_json=$(jq -nc --arg p "$new_pw" '[$p]')
    if ! email_run "写入 ADMIN_PASSWORDS secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "ADMIN_PASSWORDS" "$admin_json"; then
        print_warn "secret 写入失败，尝试兼容旧部署的 ADMIN_PASSWORDS 普通变量"
        if ! _email_manage_update_admin_passwords_var "$admin_json"; then
            print_error "管理员密码更新失败"
            pause; return
        fi
    fi
    email_save_admin_password "$new_pw"
    echo ""
    echo -e "${C_GREEN}========== 管理员密码已更新 ==========${C_RESET}"
    echo -e "  新密码:       ${C_YELLOW}${new_pw}${C_RESET}"
    echo -e "  已保存:       ${C_GRAY}${EMAIL_ADMIN_FILE}${C_RESET}"
    log_action "Email admin password rotated"
    unset new_pw
    pause
}

# ── 2. 管理收信域名 DOMAINS ──
email_manage_domains() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "管理收信域名 (DOMAINS)"
    _email_manage_prepare || { pause; return; }

    local toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    local current
    current=$(grep -E '^DOMAINS[[:space:]]*=' "$toml" | head -1 | sed -E 's/^DOMAINS[[:space:]]*=[[:space:]]*//')
    [[ -z "$current" ]] && current='["'"$EMAIL_DOMAIN"'"]'
    echo -e "${C_CYAN}当前 DOMAINS:${C_RESET} $current"
    echo ""
    echo "1. 追加一个域名"
    echo "2. 移除一个域名"
    echo "0. 返回"
    read -e -r -p "选择: " act
    [[ "$act" != "1" && "$act" != "2" ]] && return

    local target
    read -e -r -p "目标域名: " target
    validate_domain "$target" || { print_error "域名格式无效"; pause; return; }

    # 当前域名数组
    local arr
    if ! arr=$(printf '%s' "$current" | jq -c '.' 2>/dev/null) \
       || ! printf '%s' "$arr" | jq -e 'type == "array" and all(.[]; type == "string")' >/dev/null 2>&1; then
        print_error "DOMAINS 当前配置不是合法 JSON 字符串数组，请先手工修复 wrangler.toml"
        pause; return 1
    fi
    local new_arr
    case $act in
        1)
            if echo "$arr" | jq -e --arg d "$target" 'index($d) != null' >/dev/null 2>&1; then
                print_warn "$target 已存在"; pause; return
            fi
            new_arr=$(echo "$arr" | jq -c --arg d "$target" '. + [$d]')
            ;;
        2)
            if [[ "$target" == "$EMAIL_DOMAIN" ]]; then
                print_error "主域名 $EMAIL_DOMAIN 不能移除（如需更换请重新部署）"
                pause; return
            fi
            new_arr=$(echo "$arr" | jq -c --arg d "$target" 'map(select(. != $d))')
            ;;
    esac

    # 替换 DOMAINS 和 DEFAULT_DOMAINS。先备份，只有 Worker 重新部署成功才保留本地修改。
    local backup tmp
    backup=$(mktemp "${toml}.domains.bak.XXXXXX") || { print_error "创建备份失败"; pause; return; }
    tmp=$(mktemp "${toml}.domains.XXXXXX") || { rm -f "$backup"; print_error "创建临时文件失败"; pause; return; }
    cp -a "$toml" "$backup" || { rm -f "$backup" "$tmp"; print_error "备份 wrangler.toml 失败"; pause; return; }
    if ! DOMAINS_JSON="$new_arr" awk '
        BEGIN { value = ENVIRON["DOMAINS_JSON"]; seen_domains = 0; seen_defaults = 0 }
        /^[[:space:]]*DEFAULT_DOMAINS[[:space:]]*=/ { print "DEFAULT_DOMAINS = " value; seen_defaults = 1; next }
        /^[[:space:]]*DOMAINS[[:space:]]*=/ { print "DOMAINS = " value; seen_domains = 1; next }
        { print }
        END { if (!seen_domains || !seen_defaults) exit 2 }
    ' "$toml" > "$tmp"; then
        rm -f "$tmp"
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "wrangler.toml 缺少 DOMAINS/DEFAULT_DOMAINS，已恢复原文件"
        pause; return 1
    fi
    mv -f "$tmp" "$toml" || { cp -a "$backup" "$toml" 2>/dev/null || true; rm -f "$backup" "$tmp"; print_error "更新 wrangler.toml 失败，已恢复原文件"; pause; return; }
    chmod 600 "$toml"
    print_success "wrangler.toml 已更新"
    echo "  DOMAINS = $new_arr"

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || {
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "依赖安装失败，wrangler.toml 已恢复"
        pause; return 1
    }
    if email_run "重新部署 Worker" _email_wrangler deploy; then
        rm -f "$backup"
        print_success "Worker 已更新，新域名已生效"
        log_action "Email DOMAINS updated: $new_arr"
    else
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "部署失败，wrangler.toml 已恢复"
        pause; return 1
    fi
    pause
}

# ── 3. Resend ──
email_manage_resend() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "配置 / 更新 Resend"
    _email_manage_prepare || { pause; return; }

    echo -e "当前状态: $([[ ${EMAIL_RESEND_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_GRAY}未启用${C_RESET}")"
    [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]] && echo "  发件子域:  $EMAIL_RESEND_SEND_DOMAIN"
    echo ""
    echo "1. 启用 / 重新配置 Resend"
    echo "2. 仅更新 RESEND_TOKEN（不动 DNS）"
    echo "3. 禁用 Resend（删除相关 DNS 记录）"
    echo "0. 返回"
    read -e -r -p "选择: " act
    case $act in
        1) _email_manage_resend_setup ;;
        2) _email_manage_resend_token_only ;;
        3) _email_manage_resend_disable ;;
        *) return ;;
    esac
    pause
}

_email_manage_resend_setup() {
    local tok dkim
    email_read_secret "Resend API Token" tok || { print_error "Token 不能为空"; return 1; }
    print_info "已收到 Token: $(email_mask_token "$tok")"
    read -e -r -p "Resend DKIM (p=MIGfMA0...): " dkim
    [[ -z "$dkim" ]] && { print_error "DKIM 不能为空"; unset tok dkim; return 1; }

    if ! email_run "写入 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_error "secret 写入失败"
        unset tok dkim
        return 1
    fi

    local send_sub="send.${EMAIL_DOMAIN}"
    local zid="$EMAIL_ZONE_ID"

    # 清旧记录（按 type+name 全量清，避免脏数据残留）
    local purge_failed=0
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}" || purge_failed=1
    _email_cf_dns_purge "$zid" TXT "$send_sub" || purge_failed=1
    _email_cf_dns_purge "$zid" MX  "$send_sub" || purge_failed=1
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}" || purge_failed=1
    if [[ "$purge_failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "清理旧 Resend DNS 记录失败，已停止启用并保留当前 state。"
        print_warn "RESEND_TOKEN secret 可能已写入；请修复 Cloudflare DNS/API 问题后重试。"
        unset tok dkim
        return 1
    fi

    local create_failed=0
    _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$dkim" \
        && print_success "DKIM" || { print_warn "DKIM 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
        && print_success "SPF" || { print_warn "SPF 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
        && print_success "Send MX" || { print_warn "Send MX 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
        && print_success "DMARC" || { print_warn "DMARC 失败"; create_failed=1; }
    if [[ "$create_failed" -ne 0 ]]; then
        EMAIL_RESEND_ENABLED=0
        EMAIL_RESEND_SEND_DOMAIN=""
        email_state_write 2>/dev/null || true
        print_error "创建 Resend DNS 记录失败，已停止启用并保留当前 state。"
        print_warn "可能已有部分 DNS 记录创建成功；修复 Cloudflare DNS/API 问题后可重新配置。"
        unset tok dkim
        return 1
    fi

    EMAIL_RESEND_ENABLED=1
    EMAIL_RESEND_SEND_DOMAIN="$send_sub"
    email_state_write
    print_success "Resend 已启用"
    echo -e "${C_YELLOW}下一步:${C_RESET} 访问 https://resend.com/domains 触发 DKIM/SPF 验证"
    log_action "Email Resend enabled for $EMAIL_DOMAIN"
    unset tok dkim
}

_email_manage_resend_token_only() {
    local tok
    email_read_secret "新 Resend API Token" tok || return 1
    print_info "已收到 Token: $(email_mask_token "$tok")"
    if email_run "更新 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_success "RESEND_TOKEN 已更新"
        log_action "Email Resend token rotated"
    else
        print_error "RESEND_TOKEN 更新失败"
        unset tok
        return 1
    fi
    unset tok
}

_email_manage_resend_disable() {
    confirm "确认禁用 Resend 并删除相关 DNS 记录?" || return
    local zid="$EMAIL_ZONE_ID"
    local failed=0
    if [[ -n "${EMAIL_DNS_DKIM_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_DKIM_ID" && print_success "已删 DKIM" || { print_warn "DKIM 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_SPF_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_SPF_ID" && print_success "已删 SPF" || { print_warn "SPF 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_SEND_MX_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_SEND_MX_ID" && print_success "已删 Send MX" || { print_warn "Send MX 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_DMARC_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_DMARC_ID" && print_success "已删 DMARC" || { print_warn "DMARC 删除失败"; failed=1; }
    fi
    # 同步清掉可能的同名脏记录
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" TXT "send.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" MX  "send.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}" || failed=1

    if [[ "$failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "部分 Resend DNS 记录删除失败，已保留 Resend state，便于修复后重试。"
        return 1
    fi

    print_warn "RESEND_TOKEN secret 不会自动清除，如需彻底清理请在 Dashboard → Workers → Settings → Variables 删除"
    EMAIL_RESEND_ENABLED=0
    EMAIL_RESEND_SEND_DOMAIN=""
    EMAIL_DNS_DKIM_ID=""; EMAIL_DNS_SPF_ID=""; EMAIL_DNS_SEND_MX_ID=""; EMAIL_DNS_DMARC_ID=""
    email_state_write
    log_action "Email Resend disabled for $EMAIL_DOMAIN"
}

# ── 4. 升级到最新版本 ──
email_manage_upgrade() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "升级到最新版本"
    _email_manage_prepare || { pause; return; }
    local old_version="${EMAIL_INSTALL_VERSION:-未知}"

    echo -e "${C_CYAN}当前版本:${C_RESET} ${EMAIL_INSTALL_VERSION:-未知}"
    email_run "拉取上游 tags" git -C "$EMAIL_INSTALL_DIR" fetch --tags --prune || { pause; return; }

    local latest
    latest=$(git -C "$EMAIL_INSTALL_DIR" describe --tags "$(git -C "$EMAIL_INSTALL_DIR" rev-list --tags --max-count=1)" 2>/dev/null)
    [[ -z "$latest" ]] && { print_error "无法识别最新 tag"; pause; return; }
    echo -e "${C_CYAN}最新版本:${C_RESET} $latest"

    if [[ "$latest" == "${EMAIL_INSTALL_VERSION:-}" ]]; then
        print_success "已是最新版本，无需升级"
        pause; return
    fi
    confirm "确认升级到 $latest?" || return

    email_run "checkout $latest" git -C "$EMAIL_INSTALL_DIR" checkout --quiet "$latest" || { pause; return; }
    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || { pause; return; }

    # 增量 D1 migration：跑 patches_applied 中没出现过的
    local applied_str="${EMAIL_PATCHES_APPLIED:-} "
    local new_patches=()
    local p base
    while IFS= read -r p; do
        base=$(basename "$p")
        if [[ "$applied_str" != *" $base "* && "$applied_str" != "$base "* ]]; then
            new_patches+=("$p")
        fi
    done < <(ls "$EMAIL_INSTALL_DIR/db"/*-patch.sql 2>/dev/null | sort)

    if (( ${#new_patches[@]} > 0 )); then
        print_info "发现 ${#new_patches[@]} 个新 D1 migration"
        for p in "${new_patches[@]}"; do
            base=$(basename "$p")
            if email_run "应用 $base" _email_wrangler d1 execute "$EMAIL_D1_NAME" --file="$p" --remote; then
                EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED} ${base}"
                EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED# }"
                if ! email_state_write; then
                    print_error "patch $base 已应用，但写入升级进度失败；已中止升级（worker 未重新部署）"
                    pause; return
                fi
            else
                print_error "patch $base 失败，已中止升级（worker 未重新部署）"
                pause; return
            fi
        done
    else
        print_info "无新增 D1 migration"
    fi

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "部署 Worker $latest" _email_wrangler deploy || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/frontend" || return
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "前端依赖" pnpm install --no-frozen-lockfile || { pause; return; }
    email_run "构建前端" pnpm build:pages || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/pages" || return
    # 升级链路同样需要同步 pages service binding —
    # 上游 tag 切换后 pages/wrangler.toml 可能重置为默认 service=cloudflare_temp_email
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（请手工检查）"
    email_run "Pages 依赖" pnpm install --no-frozen-lockfile || {
        _email_restore_pages_service_binding
        pause; return
    }
    local pages_rc=0
    email_run "部署 Pages" _email_wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
        --branch production --commit-dirty=true || pages_rc=$?
    _email_restore_pages_service_binding
    if [[ "$pages_rc" -ne 0 ]]; then
        pause; return
    fi

    EMAIL_INSTALL_VERSION="$latest"
    email_state_write
    print_success "已升级到 $latest"
    log_action "Email upgraded ${old_version} → $latest"
    pause
}

# ── 5. 重新部署（保留 D1 数据）──
email_manage_redeploy() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "重新部署 Worker / Pages（保留 D1 数据）"
    _email_manage_prepare || { pause; return; }
    confirm "确认重新部署当前版本 ${EMAIL_INSTALL_VERSION}?" || return

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || { pause; return; }
    email_run "部署 Worker" _email_wrangler deploy || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/frontend" || return
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "构建前端" pnpm build:pages || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/pages" || return
    # 重部署链路也需要同步 service binding（防止本地 dirty 文件被覆盖后丢失自定义 worker 名）
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（请手工检查）"
    local pages_rc=0
    email_run "部署 Pages" _email_wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
        --branch production --commit-dirty=true || pages_rc=$?
    _email_restore_pages_service_binding
    if [[ "$pages_rc" -ne 0 ]]; then
        pause; return
    fi

    print_success "重新部署完成"
    log_action "Email redeployed: $EMAIL_INSTALL_VERSION"
    pause
}

email_uninstall() {
    print_title "完全卸载 Cloudflare Temp Email"

    # 不再硬卡 EMAIL_INSTALLED=1 — 只要 state 文件能加载，即视为有可回收的远端资源（涵盖部署中途失败的场景）
    local has_state=0
    if [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
        _email_state_reset_vars
        # shellcheck disable=SC1090
        source "$EMAIL_STATE_FILE"
        has_state=1
    fi
    trap '_email_clear_sensitive_env' RETURN

    if [[ $has_state -eq 0 ]]; then
        print_warn "未检测到 state 文件，将仅执行本地清理"
        if [[ -d "$EMAIL_INSTALL_DIR" ]]; then
            confirm "删除本地目录 $EMAIL_INSTALL_DIR ?" && rm -rf "$EMAIL_INSTALL_DIR"
        fi
        rm -f "$EMAIL_ADMIN_FILE"
        email_state_clear
        pause; return
    fi

    if [[ "${EMAIL_INSTALLED:-0}" != "1" ]]; then
        print_warn "检测到上次部署未完成（state 中 EMAIL_INSTALLED=0）"
        print_info "将尝试回收 state 中记录的部分资源"
    fi

    # 显示待清理资源清单
    echo -e "${C_YELLOW}以下 Cloudflare 资源将被删除：${C_RESET}"
    echo "  • Worker:        ${EMAIL_WORKER_NAME}"
    echo "  • Pages:         ${EMAIL_PAGES_PROJECT}"
    echo "  • D1 数据库:     ${EMAIL_D1_NAME} (${EMAIL_D1_ID})"
    echo "  • Catch-all:     ${EMAIL_DOMAIN}"
    local _dns_count=0
    local _id
    for _id in "$EMAIL_DNS_FRONTEND_ID" "$EMAIL_DNS_MX1_ID" "$EMAIL_DNS_MX2_ID" "$EMAIL_DNS_MX3_ID" \
               "$EMAIL_DNS_DKIM_ID" "$EMAIL_DNS_SPF_ID" "$EMAIL_DNS_SEND_MX_ID" "$EMAIL_DNS_DMARC_ID"; do
        [[ -n "$_id" ]] && _dns_count=$((_dns_count+1))
    done
    echo "  • DNS 记录:      $_dns_count 条 (front CNAME / MX / Resend TXT 等)"
    echo "  • 本地目录:      $EMAIL_INSTALL_DIR"
    echo "  • 状态/日志:     $EMAIL_STATE_FILE, $EMAIL_ADMIN_FILE"
    echo ""
    echo -e "${C_RED}⚠ D1 数据库中存储的所有邮件、用户、地址都将永久丢失！${C_RESET}"
    echo ""

    confirm "确认执行完全卸载?" || { pause; return; }
    local final
    read -e -r -p "再次确认请输入卸载目标域名 [$EMAIL_DOMAIN]: " final
    if [[ "$final" != "$EMAIL_DOMAIN" ]]; then
        print_warn "域名不匹配，已取消"; pause; return
    fi

    # 拿 Token
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        email_read_secret "Cloudflare API Token (具备删除权限)" CF_API_TOKEN || { pause; return; }
        export CF_API_TOKEN
        if ! _email_cf_token_verify 2>/dev/null; then
            print_error "Token 校验失败"; pause; return
        fi
    fi
    if [[ -z "${CF_ACCOUNT_ID:-}" ]]; then
        if [[ -n "${EMAIL_CF_ACCOUNT_ID:-}" ]]; then
            CF_ACCOUNT_ID="$EMAIL_CF_ACCOUNT_ID"
            export CF_ACCOUNT_ID
        else
            # 兼容旧 state — 强制让用户选，绝不取第一个（否则可能误删错账户资源）
            print_warn "state 中未记录 Account ID，需要选择正确账户以避免误删"
            _email_deploy_pick_account || { pause; return; }
        fi
    fi
    # 同步导出 Wrangler 新版环境变量
    _email_export_wrangler_env

    echo ""
    print_info "开始回收远程资源..."
    local uninstall_failed=0
    local _log_domain="${EMAIL_DOMAIN:-unknown}"

    # 1. 关闭 catch-all
    if [[ "${EMAIL_CATCH_ALL_ENABLED:-0}" == "1" && -n "$EMAIL_ZONE_ID" ]]; then
        if email_run "禁用 Email Routing catch-all" _email_cf_catch_all_disable "$EMAIL_ZONE_ID"; then
            EMAIL_CATCH_ALL_ENABLED=0
        else
            email_state_write 2>/dev/null || true
            print_error "Email Routing catch-all 禁用失败，已停止卸载并保留本地目录和 state。"
            print_warn "请检查 Cloudflare Token/网络后重新执行卸载，避免继续删除资源后丢失回收线索。"
            log_action "Cloudflare Temp Email uninstall incomplete: $_log_domain"
            unset CF_API_TOKEN CLOUDFLARE_API_TOKEN
            pause
            return 1
        fi
    fi

    # 2. DNS 记录（按 state 中记录的 ID 删除）
    if [[ -n "$EMAIL_ZONE_ID" ]]; then
        _email_uninstall_delete_dns || uninstall_failed=1
    fi

    # 3. Worker
    if [[ -n "$EMAIL_WORKER_NAME" ]]; then
        if email_run "删除 Worker ${EMAIL_WORKER_NAME}" _email_cf_worker_delete "$EMAIL_WORKER_NAME"; then :; else
            print_warn "Worker 删除失败（可能已不存在）"
            uninstall_failed=1
        fi
    fi

    # 4. Pages
    if [[ -n "$EMAIL_PAGES_PROJECT" ]]; then
        if email_run "删除 Pages ${EMAIL_PAGES_PROJECT}" _email_cf_pages_project_delete "$EMAIL_PAGES_PROJECT"; then :; else
            print_warn "Pages 删除失败（可能已不存在）"
            uninstall_failed=1
        fi
    fi

    # 5. D1
    if [[ -n "$EMAIL_D1_ID" ]]; then
        if email_run "删除 D1 ${EMAIL_D1_NAME}" _email_cf_d1_delete "$EMAIL_D1_ID"; then :; else
            print_warn "D1 删除失败 — 请登录 Dashboard 手动删除 ${EMAIL_D1_NAME}"
            uninstall_failed=1
        fi
    fi

    # 6. 本地目录与状态（先保存日志要用到的字段，再清 state）
    if [[ "$uninstall_failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "远端资源未完全删除，已保留本地目录和 state，避免丢失资源 ID。"
        print_warn "请根据上方失败项处理后重新执行卸载。"
        log_action "Cloudflare Temp Email uninstall incomplete: $_log_domain"
        unset CF_API_TOKEN CLOUDFLARE_API_TOKEN
        pause
        return 1
    fi

    rm -rf "$EMAIL_INSTALL_DIR"
    rm -f "$EMAIL_ADMIN_FILE"
    print_success "本地目录已删除: $EMAIL_INSTALL_DIR"
    print_success "管理员密码文件已删除"
    email_state_clear
    print_success "状态文件已清除"

    log_action "Cloudflare Temp Email fully uninstalled: $_log_domain"
    echo ""
    echo -e "${C_GREEN}========== 卸载完成 ==========${C_RESET}"
    echo -e "${C_GRAY}部署日志保留在 $EMAIL_LOG_FILE — 如确认无需可手动删除${C_RESET}"
    unset CF_API_TOKEN
    pause
}

_email_uninstall_delete_dns() {
    local zid="$EMAIL_ZONE_ID"
    local failed=0
    local pairs=(
        "EMAIL_DNS_FRONTEND_ID:CNAME(前端)"
        "EMAIL_DNS_MX1_ID:MX(route1)"
        "EMAIL_DNS_MX2_ID:MX(route2)"
        "EMAIL_DNS_MX3_ID:MX(route3)"
        "EMAIL_DNS_DKIM_ID:TXT(DKIM)"
        "EMAIL_DNS_SPF_ID:TXT(SPF)"
        "EMAIL_DNS_SEND_MX_ID:MX(Resend)"
        "EMAIL_DNS_DMARC_ID:TXT(DMARC)"
    )
    local entry var_name label rid
    for entry in "${pairs[@]}"; do
        var_name="${entry%%:*}"
        label="${entry#*:}"
        rid="${!var_name}"
        [[ -z "$rid" ]] && continue
        if _email_cf_dns_delete "$zid" "$rid" 2>/dev/null; then
            print_success "已删 DNS: $label"
        else
            print_warn "DNS 删除失败: $label (id=$rid)"
            failed=1
        fi
    done

    # 兜底：按 type+name 清理仍可能残留的同名记录（防 state 不完整）
    _email_cf_dns_purge "$zid" "CNAME" "$EMAIL_FRONTEND_DOMAIN" 2>/dev/null || failed=1
    _email_cf_dns_purge "$zid" "MX"    "$EMAIL_DOMAIN" 2>/dev/null || failed=1
    if [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]]; then
        _email_cf_dns_purge "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" 2>/dev/null || failed=1
        _email_cf_dns_purge "$zid" "TXT" "send.${EMAIL_DOMAIN}" 2>/dev/null || failed=1
        _email_cf_dns_purge "$zid" "MX"  "send.${EMAIL_DOMAIN}" 2>/dev/null || failed=1
        _email_cf_dns_purge "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" 2>/dev/null || failed=1
    fi
    return "$failed"
}
# 项目: https://github.com/dreamhunter2333/cloudflare_temp_email
# 模块拆分: 14a state / 14b cf-api / 14c deploy / 14d manage / 14e uninstall

email_status() {
    print_title "临时邮箱部署状态"
    if ! email_state_load 2>/dev/null; then
        print_warn "未部署"
        echo "  $(ls -ld "$EMAIL_INSTALL_DIR" 2>/dev/null || echo "本地目录不存在")"
        pause; return
    fi
    echo -e "  ${C_CYAN}域名:${C_RESET}        ${EMAIL_DOMAIN}"
    echo -e "  ${C_CYAN}前端:${C_RESET}        https://${EMAIL_FRONTEND_DOMAIN}"
    echo -e "  ${C_CYAN}API:${C_RESET}         https://${EMAIL_API_DOMAIN}"
    echo -e "  ${C_CYAN}管理面板:${C_RESET}    https://${EMAIL_FRONTEND_DOMAIN}/admin"
    echo -e "  ${C_CYAN}邮箱格式:${C_RESET}    ${EMAIL_ADDRESS_PREFIX:+${EMAIL_ADDRESS_PREFIX}.}xxx@${EMAIL_DOMAIN}"
    echo -e "  ${C_CYAN}版本:${C_RESET}        ${EMAIL_INSTALL_VERSION}"
    echo -e "  ${C_CYAN}部署时间:${C_RESET}    ${EMAIL_INSTALL_DATE}"
    echo -e "  ${C_CYAN}D1 数据库:${C_RESET}   ${EMAIL_D1_NAME}"
    echo -e "  ${C_CYAN}Resend:${C_RESET}      $([[ ${EMAIL_RESEND_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_GRAY}未启用${C_RESET}")"
    echo -e "  ${C_CYAN}Catch-all:${C_RESET}   $([[ ${EMAIL_CATCH_ALL_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_YELLOW}需手动检查${C_RESET}")"
    echo -e "  ${C_GRAY}State:    ${EMAIL_STATE_FILE}${C_RESET}"
    echo -e "  ${C_GRAY}Log:      ${EMAIL_LOG_FILE}${C_RESET}"
    [[ -f "$EMAIL_ADMIN_FILE" ]] && echo -e "  ${C_GRAY}Admin pw: ${EMAIL_ADMIN_FILE} (mode 600)${C_RESET}"

    echo ""
    print_info "Worker 健康检查..."
    local resp
    resp=$(curl -sS --max-time 8 "https://${EMAIL_API_DOMAIN}/health_check" 2>/dev/null)
    if [[ "$resp" == "OK" ]]; then
        print_success "API 后端正常 (https://${EMAIL_API_DOMAIN}/health_check → OK)"
    else
        print_warn "API 未响应或 DNS 未生效 (response: ${resp:-空})"
    fi
    pause
}

email_view_log() {
    print_title "查看部署日志"
    if [[ ! -f "$EMAIL_LOG_FILE" ]]; then
        print_warn "日志尚未生成: $EMAIL_LOG_FILE"
        pause; return
    fi
    echo -e "${C_GRAY}（最近 80 行；完整日志: $EMAIL_LOG_FILE）${C_RESET}"
    draw_line
    # 走脱敏管道：兜底过滤旧版本日志里可能残留的 secret_text / Bearer / TOKEN= 形式
    tail -n 80 "$EMAIL_LOG_FILE" | _email_redact_secrets
    draw_line
    pause
}

menu_email() {
    fix_terminal
    while true; do
        print_title "Cloudflare 临时邮箱"
        # 三态：installed=完整部署 / partial=state 存在但 INSTALLED=0 / none=无 state
        local state_kind="none"
        if email_state_load 2>/dev/null; then
            state_kind="installed"
        elif [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
            _email_state_reset_vars
            # shellcheck disable=SC1090
            source "$EMAIL_STATE_FILE"
            state_kind="partial"
        fi

        case "$state_kind" in
            none)
                echo -e "  ${C_YELLOW}状态: 未部署${C_RESET}"
                echo ""
                echo "1. 一键部署"
                echo "2. 查看部署日志"
                echo "0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_deploy ;;
                    2) email_view_log ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
            partial)
                echo -e "  ${C_RED}状态: 部署未完成${C_RESET}  域名: ${EMAIL_DOMAIN:-?}"
                echo -e "  ${C_GRAY}（state 中 EMAIL_INSTALLED=0，远端可能残留 D1/Worker/Pages/DNS）${C_RESET}"
                echo ""
                echo -e "  ${C_GREEN}1. 强制卸载${C_RESET}（推荐 — 先回收远端残留再重新部署）"
                echo "  2. 重新部署（自动备份旧 state，但会生成新资源名 — 仅在确认旧资源已手工清理时使用）"
                echo "  3. 查看部署日志"
                echo "  0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_uninstall ;;
                    2) email_deploy ;;
                    3) email_view_log ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
            installed)
                echo -e "  ${C_GREEN}状态: 已部署${C_RESET}  ${EMAIL_FRONTEND_DOMAIN}  (${EMAIL_INSTALL_VERSION})"
                echo ""
                echo "1. 查看部署状态 + 健康检查"
                echo "2. 修改管理员密码"
                echo "3. 管理收信域名 (DOMAINS)"
                echo "4. 配置 / 更新 Resend"
                echo "5. 升级到最新版本"
                echo "6. 重新部署 Worker / Pages (保留 D1)"
                echo "7. 查看部署日志"
                echo "8. 完全卸载"
                echo "0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_status ;;
                    2) email_manage_change_admin_password ;;
                    3) email_manage_domains ;;
                    4) email_manage_resend ;;
                    5) email_manage_upgrade ;;
                    6) email_manage_redeploy ;;
                    7) email_view_log ;;
                    8) email_uninstall ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
        esac
    done
}
# ============================================================================
# Reality SNI 自动测速增强模块（内联）
# ============================================================================
# Reality SNI 自动测速选择增强模块（纯交互式版本）
# 所有配置通过菜单选择，无需编辑配置文件

# ============================================================================
# 默认参数（用户通过交互式菜单修改，不需要编辑此文件）
# ============================================================================

# bulianglin.com 候选池 URL
BULIANGLIN_SNI_POOL_URL="https://bulianglin.com/archives/nicename.html"

# 本地缓存文件
REALITY_SNI_CACHE_DIR="/etc/vps-mgr/reality"
REALITY_SNI_POOL_FILE="${REALITY_SNI_CACHE_DIR}/bulianglin-sni-pool.txt"
REALITY_SNI_FALLBACK_POOL_FILE="${REALITY_SNI_CACHE_DIR}/fallback-sni-pool.txt"
REALITY_SNI_CACHE_TTL=86400  # 24 小时

# 三级阈值（默认值，用户可在交互菜单中选择）
REALITY_SNI_LATENCY_THRESHOLD_STRICT=50
REALITY_SNI_LATENCY_THRESHOLD_NORMAL=200
REALITY_SNI_LATENCY_THRESHOLD_RELAXED=500

# 测速参数
REALITY_SNI_BATCH_SIZE=15
REALITY_SNI_TEST_TIMEOUT=3

_reality_sni_pool_count() {
    local file="$1"
    grep -cve '^[[:space:]]*$' "$file" 2>/dev/null || echo 0
}

_reality_sni_write_pool_file() {
    local target="$1" min_count="${2:-1}" dir base tmp count
    dir="$(dirname "$target")"
    base="$(basename "$target")"
    mkdir -p "$dir" || return 1
    tmp=$(mktemp "${dir}/.tmp.${base}.XXXXXX") || return 1
    if ! cat > "$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    count=$(_reality_sni_pool_count "$tmp")
    if [[ ! "$count" =~ ^[0-9]+$ || "$count" -lt "$min_count" ]]; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    if ! mv -f "$tmp" "$target"; then
        rm -f "$tmp" 2>/dev/null || true
        return 1
    fi
    return 0
}

# ============================================================================
# 核心函数：从 bulianglin.com 拉取候选池
# ============================================================================

reality_fetch_bulianglin_pool() {
    local html_content domains_json domains_content

    print_info "正在从 bulianglin.com 拉取最新 SNI 候选池..." >&2

    html_content=$(curl -fsSL --max-time 15 "$BULIANGLIN_SNI_POOL_URL" 2>/dev/null)
    if [[ -z "$html_content" ]]; then
        return 1
    fi

    domains_json=$(echo "$html_content" | grep -o 'const domains = \[.*\];' | sed 's/const domains = \[//; s/\];//')

    if [[ -z "$domains_json" ]]; then
        return 1
    fi

    domains_content=$(echo "$domains_json" | sed 's/"//g; s/, /\n/g' | sed 's/^ *//; s/ *$//' | sort -u)
    if ! printf '%s\n' "$domains_content" | _reality_sni_write_pool_file "$REALITY_SNI_POOL_FILE" 10; then
        return 1
    fi

    local count
    count=$(_reality_sni_pool_count "$REALITY_SNI_POOL_FILE")
    print_success "成功拉取 $count 个 SNI 候选域名" >&2
    return 0
}

# ============================================================================
# 核心函数：从 v2ray-agent 拉取备用候选池
# ============================================================================

reality_fetch_v2ray_agent_pool() {
    local v2ray_agent_url="https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    local temp_file

    temp_file=$(mktemp "${TMPDIR:-/tmp}/v2ray-agent-install.XXXXXX") || return 1

    print_info "正在从 v2ray-agent 拉取备用候选池..." >&2

    if ! curl -fsSL --max-time 15 "$v2ray_agent_url" -o "$temp_file" 2>/dev/null; then
        rm -f "$temp_file"
        return 1
    fi

    local domains_content
    domains_content=$(grep -A 100 '_realityDomainList()' "$temp_file" | grep -E '^\s*"[^"]+"\s*$' | sed 's/[" ]//g' | sort -u)

    if [[ -z "$domains_content" ]]; then
        rm -f "$temp_file"
        return 1
    fi

    if ! printf '%s\n' "$domains_content" | _reality_sni_write_pool_file "$REALITY_SNI_POOL_FILE" 10; then
        rm -f "$temp_file"
        return 1
    fi

    local count
    count=$(_reality_sni_pool_count "$REALITY_SNI_POOL_FILE")
    print_success "成功从 v2ray-agent 拉取 $count 个备用域名" >&2
    rm -f "$temp_file"
    return 0
}

# ============================================================================
# 核心函数：更新候选池（三级降级）
# ============================================================================

reality_update_sni_pool() {
    # 检查缓存
    if [[ -f "$REALITY_SNI_POOL_FILE" ]]; then
        local age count
        age=$(( $(date +%s) - $(stat -c %Y "$REALITY_SNI_POOL_FILE" 2>/dev/null || echo 0) ))
        count=$(_reality_sni_pool_count "$REALITY_SNI_POOL_FILE")

        if [[ $age -lt $REALITY_SNI_CACHE_TTL && "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]]; then
            print_info "使用缓存的候选池（$count 个域名，${age}s 前更新）" >&2
            return 0
        elif [[ $age -lt $REALITY_SNI_CACHE_TTL ]]; then
            print_warn "缓存候选池为空或无效，尝试重新拉取" >&2
        fi
    fi

    # 三级降级：bulianglin.com → v2ray-agent → 内置列表
    if reality_fetch_bulianglin_pool; then
        return 0
    fi

    print_warn "bulianglin.com 不可用，尝试 v2ray-agent 备用池..." >&2
    if reality_fetch_v2ray_agent_pool; then
        return 0
    fi

    print_warn "v2ray-agent 也不可用，使用内置列表" >&2
    printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | _reality_sni_write_pool_file "$REALITY_SNI_FALLBACK_POOL_FILE" 1 || return 1
    REALITY_SNI_POOL_FILE="$REALITY_SNI_FALLBACK_POOL_FILE"
    return 0
}

# ============================================================================
# 核心函数：TLS 握手测速
# ============================================================================

reality_test_sni_latency() {
    local domain="$1"
    local timeout="${2:-$REALITY_SNI_TEST_TIMEOUT}"
    local start_ms end_ms latency_ms

    start_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))

    if timeout "$timeout" openssl s_client -connect "${domain}:443" \
        -servername "$domain" -brief </dev/null >/dev/null 2>&1; then

        end_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
        latency_ms=$((end_ms - start_ms))

        echo "$latency_ms"
        return 0
    else
        echo "timeout"
        return 1
    fi
}

# ============================================================================
# 核心函数：批量测速
# ============================================================================

reality_batch_speedtest() {
    local batch_size="${1:-$REALITY_SNI_BATCH_SIZE}"
    local threshold="${2:-$REALITY_SNI_LATENCY_THRESHOLD_NORMAL}"
    local pool_file="${3:-$REALITY_SNI_POOL_FILE}"

    if [[ ! -f "$pool_file" ]]; then
        print_error "候选池文件不存在" >&2
        return 1
    fi

    local -a batch_domains
    mapfile -t batch_domains < <(shuf -n "$batch_size" "$pool_file")

    if [[ ${#batch_domains[@]} -eq 0 ]]; then
        print_error "候选池为空" >&2
        return 1
    fi

    print_info "开始测速（批次大小: ${#batch_domains[@]}，延迟阈值: ${threshold}ms）..." >&2
    echo "" >&2

    local -a results=()
    local domain latency status
    local qualified_count=0

    for domain in "${batch_domains[@]}"; do
        echo -n "  测试 ${domain} ... " >&2

        latency=$(reality_test_sni_latency "$domain")
        status=$?

        if [[ $status -eq 0 && "$latency" != "timeout" ]]; then
            if [[ $latency -le $threshold ]]; then
                echo -e "${C_GREEN}${latency}ms ✓${C_RESET}" >&2
                results+=("${latency}|${domain}")
                ((qualified_count++))
            else
                echo -e "${C_YELLOW}${latency}ms (超过阈值)${C_RESET}" >&2
            fi
        else
            echo -e "${C_RED}超时 ✗${C_RESET}" >&2
        fi
    done

    echo "" >&2
    print_info "测速完成: ${qualified_count}/${#batch_domains[@]} 个域名符合要求" >&2

    if [[ ${#results[@]} -gt 0 ]]; then
        printf '%s\n' "${results[@]}" | sort -t'|' -k1 -n
        return 0
    else
        return 1
    fi
}

# ============================================================================
# 核心函数：智能 SNI 选择（纯交互式，三级阈值）
# ============================================================================

reality_smart_sni_selection() {
    echo "" >&2
    echo "========================================" >&2
    echo "REALITY SNI 智能选择" >&2
    echo "========================================" >&2
    echo "" >&2
    echo -e "${C_CYAN}说明：${C_RESET}" >&2
    echo "  脚本将从 bulianglin.com 拉取 117+ 个大厂域名候选池" >&2
    echo "  自动进行 TLS 握手测速，筛选低延迟域名" >&2
    echo "" >&2

    # 更新候选池（自动三级降级）
    reality_update_sni_pool

    echo "" >&2
    echo -e "${C_CYAN}选择测速模式：${C_RESET}" >&2
    echo "" >&2
    echo "  1. 严格模式（延迟 < 50ms）" >&2
    echo "     适合：VPS 与 CDN 在同一地区（如美西 VPS 访问美西 CloudFront）" >&2
    echo "" >&2
    echo "  2. 正常模式（延迟 < 200ms）" >&2
    echo "     适合：大部分场景（如亚洲 VPS 访问全球 CDN）" >&2
    echo "" >&2
    echo "  3. 宽松模式（延迟 < 500ms）" >&2
    echo "     适合：跨洲访问或网络较慢的场景" >&2
    echo "" >&2
    echo "  4. 自动模式（智能三级降级）★ 推荐" >&2
    echo "     先尝试严格模式，无合格域名则自动降级到正常/宽松模式" >&2
    echo "" >&2
    echo "  5. 跳过测速（从候选池随机选择，不测速）" >&2
    echo "" >&2

    local mode_choice
    read -e -r -p "请选择模式 [4]: " mode_choice
    mode_choice=${mode_choice:-4}

    local threshold
    case "$mode_choice" in
        1) threshold=$REALITY_SNI_LATENCY_THRESHOLD_STRICT ;;
        2) threshold=$REALITY_SNI_LATENCY_THRESHOLD_NORMAL ;;
        3) threshold=$REALITY_SNI_LATENCY_THRESHOLD_RELAXED ;;
        4)
            # 自动模式（三级降级）
            reality_smart_sni_selection_auto
            return $?
            ;;
        5)
            # 跳过测速
            reality_select_from_pool_no_test
            return $?
            ;;
        *)
            print_error "无效选择，使用自动模式" >&2
            reality_smart_sni_selection_auto
            return $?
            ;;
    esac

    # 单一阈值模式
    echo "" >&2
    confirm "开始测速?" || return 1

    echo "" >&2
    local batch_output
    batch_output=$(reality_batch_speedtest "$REALITY_SNI_BATCH_SIZE" "$threshold" "$REALITY_SNI_POOL_FILE")

    if [[ -z "$batch_output" ]]; then
        print_error "未找到符合要求的域名" >&2
        echo "" >&2
        echo "建议：" >&2
        echo "  1. 选择更宽松的模式" >&2
        echo "  2. 检查 VPS 网络连接" >&2
        echo "  3. 手动输入 SNI 域名" >&2
        echo "" >&2

        if confirm "是否手动输入 SNI?"; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        fi

        return 1
    fi

    # 显示结果并让用户选择
    reality_display_and_select_sni "$batch_output"
}

# ============================================================================
# 辅助函数：自动模式（三级阈值降级）
# ============================================================================

reality_smart_sni_selection_auto() {
    echo "" >&2
    print_info "自动模式：将依次尝试严格（50ms）→ 正常（200ms）→ 宽松（500ms）阈值" >&2
    echo "" >&2
    confirm "开始测速?" || return 1

    local -a thresholds=(
        "$REALITY_SNI_LATENCY_THRESHOLD_STRICT:严格（< 50ms）"
        "$REALITY_SNI_LATENCY_THRESHOLD_NORMAL:正常（< 200ms）"
        "$REALITY_SNI_LATENCY_THRESHOLD_RELAXED:宽松（< 500ms）"
    )

    local -a all_results=()

    for tier in "${thresholds[@]}"; do
        local threshold="${tier%%:*}"
        local tier_name="${tier##*:}"

        echo "" >&2
        print_info "========== 尝试 ${tier_name} ==========" >&2
        echo "" >&2

        local batch_output
        batch_output=$(reality_batch_speedtest "$REALITY_SNI_BATCH_SIZE" "$threshold" "$REALITY_SNI_POOL_FILE")

        if [[ -n "$batch_output" ]]; then
            mapfile -t all_results < <(echo "$batch_output")
            print_success "在 ${tier_name} 下找到 ${#all_results[@]} 个合格域名" >&2
            break
        else
            print_warn "${tier_name} 下无合格域名，自动降级..." >&2
            sleep 1
        fi
    done

    if [[ ${#all_results[@]} -eq 0 ]]; then
        print_error "所有阈值级别均未找到合格域名" >&2
        echo "" >&2
        echo "建议：" >&2
        echo "  1. 检查 VPS 网络连接" >&2
        echo "  2. 手动输入 SNI 域名" >&2
        echo "" >&2

        if confirm "是否手动输入 SNI?"; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        fi

        return 1
    fi

    # 显示结果并让用户选择
    reality_display_and_select_sni "$(printf '%s\n' "${all_results[@]}")"
}

# ============================================================================
# 辅助函数：跳过测速，从候选池随机选择
# ============================================================================

reality_select_from_pool_no_test() {
    echo "" >&2
    print_info "从候选池中随机选择（不测速）" >&2
    echo "" >&2

    local -a shown
    mapfile -t shown < <(shuf -n 12 "$REALITY_SNI_POOL_FILE")

    while true; do
        echo "" >&2
        echo "========================================" >&2
        echo "REALITY SNI 候选域名" >&2
        echo "========================================" >&2
        echo "" >&2

        local i=1
        for domain in "${shown[@]}"; do
            printf "  %2d. %s\n" "$i" "$domain" >&2
            ((i++))
        done

        echo "" >&2
        echo -e "  ${C_CYAN}r${C_RESET}. 换一批" >&2
        echo -e "  ${C_CYAN}c${C_RESET}. 手动输入域名" >&2
        echo -e "  ${C_CYAN}s${C_RESET}. 切换到测速模式" >&2
        echo "" >&2

        local choice
        read -e -r -p "请选择 [1]: " choice
        choice=${choice:-1}

        if [[ "${choice,,}" == "r" ]]; then
            mapfile -t shown < <(shuf -n 12 "$REALITY_SNI_POOL_FILE")
            continue
        elif [[ "${choice,,}" == "s" ]]; then
            reality_smart_sni_selection
            return $?
        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#shown[@]} ]]; then
            echo "${shown[$((choice-1))]}"
            return 0
        else
            print_error "无效选择" >&2
            sleep 1
        fi
    done
}

# ============================================================================
# 辅助函数：显示测速结果并让用户选择
# ============================================================================

reality_display_and_select_sni() {
    local results_text="$1"

    if [[ -z "$results_text" ]]; then
        return 1
    fi

    local -a results
    mapfile -t results < <(echo "$results_text")

    echo "" >&2
    print_success "找到 ${#results[@]} 个合格域名：" >&2
    echo "" >&2

    local i=1
    local -a display_list=()

    for result in "${results[@]}"; do
        local latency="${result%%|*}"
        local domain="${result##*|}"
        display_list+=("$domain")
        printf "  %2d. %-50s [%4dms]\n" "$i" "$domain" "$latency" >&2
        ((i++))
    done

    echo "" >&2
    echo -e "  ${C_CYAN}a${C_RESET}. 自动选择延迟最低的（推荐）" >&2
    echo -e "  ${C_CYAN}r${C_RESET}. 重新测速" >&2
    echo -e "  ${C_CYAN}c${C_RESET}. 手动输入域名" >&2
    echo "" >&2

    while true; do
        local choice
        read -e -r -p "请选择 [a]: " choice
        choice=${choice:-a}

        if [[ "${choice,,}" == "a" ]]; then
            local best_domain="${results[0]##*|}"
            local best_latency="${results[0]%%|*}"
            print_success "已选择: $best_domain (${best_latency}ms)" >&2
            echo "$best_domain"
            return 0

        elif [[ "${choice,,}" == "r" ]]; then
            reality_smart_sni_selection
            return $?

        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi

        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#display_list[@]} ]]; then
            local selected_domain="${display_list[$((choice-1))]}"
            print_success "已选择: $selected_domain" >&2
            echo "$selected_domain"
            return 0
        else
            print_error "无效选择" >&2
        fi
    done
}

# ============================================================================
# 主入口函数（替换原有的 reality_prompt_sni）
# ============================================================================

reality_prompt_sni() {
    # 直接调用智能选择（纯交互式）
    reality_smart_sni_selection
}

# ============================================================================
# 使用说明
# ============================================================================

# 在 15-singbox-reality.sh 中集成此模块的方法：
#
# 1. 在文件开头 source 此脚本：
#    source /path/to/reality-sni-speedtest-interactive.sh
#
# 2. 原有的 reality_prompt_sni() 函数会被自动替换
#
# 3. 用户体验：
#    - 进入 Reality 安装流程
#    - 选择 SNI 时，自动弹出交互式菜单
#    - 用户选择测速模式（严格/正常/宽松/自动/跳过）
#    - 自动测速并展示结果
#    - 用户选择域名或自动选择最优
#    - 无需编辑任何配置文件

# ============================================================================
# 完整工作流程示例
# ============================================================================

# [用户执行安装脚本]
# bash <(curl -sSL https://raw.githubusercontent.com/xiler78177/VPS/dist/v4-built.sh)
#
# [进入 Reality 安装菜单]
# → 选择 SNI
#
# [系统输出]
# ========================================
# REALITY SNI 智能选择
# ========================================
#
# 说明：
#   脚本将从 bulianglin.com 拉取 117+ 个大厂域名候选池
#   自动进行 TLS 握手测速，筛选低延迟域名
#
# [INFO] 正在从 bulianglin.com 拉取最新 SNI 候选池...
# [SUCCESS] 成功拉取 117 个 SNI 候选域名
#
# 选择测速模式：
#
#   1. 严格模式（推荐，延迟 < 50ms）
#      适合：VPS 与 CDN 在同一地区（如美西 VPS 访问美西 CloudFront）
#
#   2. 正常模式（推荐，延迟 < 200ms）
#      适合：大部分场景（如亚洲 VPS 访问全球 CDN）
#
#   3. 宽松模式（兜底，延迟 < 500ms）
#      适合：跨洲访问或网络较慢的场景
#
#   4. 自动模式（智能，三级阈值自动降级）
#      先尝试严格模式，无合格域名则自动降级到正常/宽松模式
#
#   5. 跳过测速（从候选池随机选择，不测速）
#
# 请选择模式 [4]: 4
#
# [INFO] 自动模式：将依次尝试严格（50ms）→ 正常（200ms）→ 宽松（500ms）阈值
#
# 开始测速? [Y/n]: y
#
# ========== 尝试 严格（< 50ms）==========
#
# [INFO] 开始测速（批次大小: 15，延迟阈值: 50ms）...
#
#   测试 apps.apple.com ... 245ms (超过阈值)
#   测试 s0.awsstatic.com ... 312ms (超过阈值)
#   ...
#
# [INFO] 测速完成: 0/15 个域名符合要求
# [WARN] 严格（< 50ms）下无合格域名，自动降级...
#
# ========== 尝试 正常（< 200ms）==========
#
# [INFO] 开始测速（批次大小: 15，延迟阈值: 200ms）...
#
#   测试 github.gallerycdn.vsassets.io ... 189ms ✓
#   测试 gsp-ssl.ls.apple.com ... 134ms ✓
#   测试 statici.icloud.com ... 167ms ✓
#   ...
#
# [INFO] 测速完成: 5/15 个域名符合要求
# [SUCCESS] 在 正常（< 200ms）下找到 5 个合格域名
#
# [SUCCESS] 找到 5 个合格域名：
#
#   1. gsp-ssl.ls.apple.com                       [ 134ms]
#   2. statici.icloud.com                         [ 167ms]
#   3. github.gallerycdn.vsassets.io              [ 189ms]
#   4. apps.apple.com                             [ 195ms]
#   5. store-images.s-microsoft.com               [ 198ms]
#
#   a. 自动选择延迟最低的（推荐）
#   r. 重新测速
#   c. 手动输入域名
#
# 请选择 [a]: a
#
# [SUCCESS] 已选择: gsp-ssl.ls.apple.com (134ms)
#
# [继续 Reality 安装流程...]



REALITY_CANDIDATE_SNI=(
    "c.6sc.co"
    "j.6sc.co"
    "b.6sc.co"
    "ipv6.6sc.co"
    "rum.hlx.page"
    "c.marsflag.com"
    "snap.licdn.com"
    "s.go-mpulse.net"
    "tags.tiqcdn.com"
    "cdn.bizibly.com"
    "cdn.bizible.com"
    "s0.awsstatic.com"
    "a0.awsstatic.com"
    "sisu.xboxlive.com"
    "s.mp.marsflag.com"
    "c.s-microsoft.com"
    "beacon.gtv-pub.com"
    "ts1.tc.mm.bing.net"
    "ts2.tc.mm.bing.net"
    "ts3.tc.mm.bing.net"
    "ts4.tc.mm.bing.net"
    "ce.mf.marsflag.com"
    "d0.m.awsstatic.com"
    "t0.m.awsstatic.com"
    "tag.demandbase.com"
    "assets-www.xbox.com"
    "assets-xbxweb.xbox.com"
    "logx.optimizely.com"
    "aadcdn.msftauth.net"
    "acctcdn.msftauth.net"
    "d.oracleinfinity.io"
    "assets.adobedtm.com"
    "lpcdn.lpsnmedia.net"
    "res-1.cdn.office.net"
    "intelcorp.scene7.com"
    "cdnssl.clicktale.net"
    "catalog.gamepass.com"
    "consent.trustarc.com"
    "munchkin.marketo.net"
    "cdn77.api.userway.org"
    "cua-chat-ui.tesla.com"
    "ds-aksb-a.akamaihd.net"
    "static.cloud.coveo.com"
    "devblogs.microsoft.com"
    "s7mbrstream.scene7.com"
    "digitalassets.tesla.com"
    "d.impactradius-event.com"
    "downloadmirror.intel.com"
    "publisher.liveperson.net"
    "tag-logger.demandbase.com"
    "services.digitaleast.mobi"
    "gray-wowt-prod.gtv-cdn.com"
    "visualstudio.microsoft.com"
    "store-images.s-microsoft.com"
    "github.gallerycdn.vsassets.io"
    "vscjava.gallerycdn.vsassets.io"
    "ms-vscode.gallerycdn.vsassets.io"
    "ms-python.gallerycdn.vsassets.io"
    "gray-config-prod.api.arc-cdn.net"
    "gray.video-player.arcpublishing.com"
    "i7158c100-ds-aksb-a.akamaihd.net"
    "img-prod-cms-rt-microsoft-com.akamaized.net"
)

reality_urlencode() {
    local s="$1" out="" i c
    local LC_ALL=C
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            ' ') out+="%20" ;;
            *) printf -v c '%%%02X' "'${c}"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

reality_uri_host() {
    # vless:// URI 中 IPv6 literal 必须加 []，否则 host:port 无法可靠解析。
    local host="${1:-}"
    if [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

reality_validate_ws_path() {
    local path="${1:-}"
    [[ "$path" == /* ]] || return 1
    [[ ${#path} -ge 2 && ${#path} -le 128 ]] || return 1
    # 仅允许对 nginx location / sing-box WS path 都安全的可见字符。
    [[ "$path" =~ ^/[A-Za-z0-9._~/-]+$ ]]
}

reality_mask_secret() {
    local s="${1:-}" n=${#1}
    if (( n <= 12 )); then printf '%s' "$s"; else printf '%s…%s' "${s:0:6}" "${s: -4}"; fi
}

reality_json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

reality_port_in_use() {
    local port="$1"
    if command_exists ss; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
    elif command_exists netstat; then
        netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
    elif command_exists lsof; then
        lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

# 有界等待某端口“释放”（不再有 LISTEN）。用于消除异步 reload 竞态：
# nginx reload 释放 443 是异步的（旧 worker 优雅退出需时间），若紧接着 restart
# sing-box 抢绑 443，旧 worker 仍占用 → bind 失败 → systemd 重试前中断约 10 秒。
# 默认最多等 ${2:-50} 次 × 0.1s ≈ 5s；到点即返回（不阻断流程，restart 仍会兜底重试）。
reality_wait_port_free() {
    local port="$1" tries="${2:-50}" i=0
    validate_port "$port" || return 0
    while (( i < tries )); do
        reality_port_in_use "$port" || return 0
        sleep 0.1
        i=$((i+1))
    done
    return 1
}

# MED-4：统一“已保留端口”集合。各 feature 选内部端口时，除运行时 ss 检查外还要查此集合，
# 避免某服务当前停止(端口空闲) → 其保留端口被另一 feature 选走 → 服务重启后 bind 冲突。
# 汇总：落地 REALITY_PORT(_V6)、共存内部端口(reality/web)、CDN origin、所有 relay 监听端口。
# 逐行输出端口号（可能含重复/空行，调用方用 grep -qx 精确匹配即可）。
reality_reserved_ports() {
    [[ -n "${REALITY_PORT:-}" ]] && echo "$REALITY_PORT"
    [[ -n "${REALITY_PORT_V6:-}" ]] && echo "$REALITY_PORT_V6"
    # 共存内部端口（从 coexist state 读，未启用则回退常量默认值）
    local _cr _cw
    _cr="$(reality_coexist_reality_port 2>/dev/null || true)"; [[ -n "$_cr" ]] && echo "$_cr"
    _cw="$(reality_coexist_web_port 2>/dev/null || true)"; [[ -n "$_cw" ]] && echo "$_cw"
    echo "${REALITY_COEXIST_INNER_PORT:-18443}"
    echo "${REALITY_WEB_INNER_PORT:-12443}"
    [[ -n "${REALITY_CDN_ORIGIN_PORT:-}" ]] && echo "$REALITY_CDN_ORIGIN_PORT"
    [[ -n "${REALITY_CDN_INNER_PORT:-}" ]] && echo "$REALITY_CDN_INNER_PORT"
    # 所有已配置的 relay 监听端口（realm 可能当前停止，ss 查不到，故必须从磁盘枚举）
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        # 只读 RLY_LISTEN_PORT 行，避免 source 污染当前 RLY_* 全局
        local _p
        _p="$(grep -E '^RLY_LISTEN_PORT=' "$f" 2>/dev/null | head -n1 | sed -E 's/^RLY_LISTEN_PORT=["'\'']?([0-9]+)["'\'']?.*/\1/')"
        [[ -n "$_p" ]] && echo "$_p"
    done < <(reality_relay_route_files 2>/dev/null)
}

# 某端口是否已被本项目其他 feature 保留（逻辑占用，独立于运行时 ss 检查）。
reality_port_reserved() {
    local port="$1" exclude="${2:-}"
    [[ -n "$port" ]] || return 1
    reality_reserved_ports 2>/dev/null | grep -vxF "${exclude:-__none__}" | grep -qxF "$port"
}

reality_port_reserved_except_current_landing() {
    local port="$1" _old_p="${REALITY_PORT:-}" _old_p6="${REALITY_PORT_V6:-}"
    local _save_p="${REALITY_PORT:-}" _save_p6="${REALITY_PORT_V6:-}" _rc
    if [[ "$port" == "$_old_p" ]]; then
        REALITY_PORT=""
    fi
    if [[ "$port" == "$_old_p6" ]]; then
        REALITY_PORT_V6=""
    fi
    if reality_port_reserved "$port"; then
        _rc=0
    else
        _rc=$?
    fi
    REALITY_PORT="$_save_p"
    REALITY_PORT_V6="$_save_p6"
    return "$_rc"
}

reality_detect_local_ipv6_addr() {
    # 用于 split 双节点“IPv4/IPv6 共用 443”场景：
    #   IPv4 入站继续绑定 0.0.0.0:443；
    #   IPv6 入站必须绑定具体本机公网 IPv6:443，避免 [::]:443 与 0.0.0.0:443 在 bindv6only=0 下冲突。
    # 只接受公网可路由地址，跳过 fe80::/10 与 fc00::/7。
    if [[ -n "${REALITY_LISTEN_HOST_V6:-}" && "${REALITY_LISTEN_HOST_V6}" != "::" ]]; then
        printf '%s' "$REALITY_LISTEN_HOST_V6"
        return 0
    fi
    command_exists ip || return 1
    ip -o -6 addr show scope global 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "inet6") {
                    split($(i + 1), a, "/")
                    addr = tolower(a[1])
                    if (addr !~ /^fe80:/ && addr !~ /^fc/ && addr !~ /^fd/) {
                        if ($0 !~ / temporary / && $0 !~ / deprecated /) {
                            found = 1
                            print a[1]
                            exit
                        }
                        if (fallback == "") fallback = a[1]
                    }
                }
            }
        }
        END { if (!found && fallback != "") print fallback }'
}

reality_prepare_split_listen_hosts() {
    local port_v4="$1" port_v6="$2" v6_addr
    REALITY_LISTEN_HOST="split"
    REALITY_LISTEN_HOST_V4="${REALITY_LISTEN_HOST_V4:-0.0.0.0}"
    if [[ "$port_v4" == "$port_v6" ]]; then
        v6_addr="$(reality_detect_local_ipv6_addr 2>/dev/null || true)"
        if [[ -z "$v6_addr" || "$v6_addr" == "::" ]]; then
            print_error "IPv4/IPv6 双节点共用 ${port_v4}/tcp 需要绑定具体本机公网 IPv6，未检测到可用 IPv6。"
            print_error "请改用不同端口，或确认系统已有全局 IPv6 地址后重试。"
            return 1
        fi
        REALITY_LISTEN_HOST_V6="$v6_addr"
    else
        REALITY_LISTEN_HOST_V6="${REALITY_LISTEN_HOST_V6:-::}"
    fi
}

reality_warn_sni_risk() {
    local sni="${1,,}"
    [[ -n "$sni" ]] || return 0
    if [[ "$sni" == *apple* || "$sni" == *icloud* || "$sni" == *itunes* || "$sni" == *mzstatic* ]]; then
        print_warn "REALITY SNI/handshake 目标疑似 Apple/iCloud 系域名；Xray v26.3.27 已提示这类目标可能增加 IP 被封锁风险。"
    fi
}

reality_warn_port_risk() {
    local port="$1" label="${2:-Reality}"
    validate_port "$port" || return 0
    if [[ "$port" != "443" ]]; then
        print_warn "${label} 监听端口为 ${port}，不是 443；Xray v26.3.27 已提示 REALITY 非 443 监听可能增加 IP 被封锁风险。"
    fi
}

reality_random_port() {
    local min="${REALITY_PORT_MIN:-20000}" max="${REALITY_PORT_MAX:-60000}" port try range rand
    range=$((max - min + 1))
    if [[ -n "${REALITY_TEST_PORT_CANDIDATES:-}" ]]; then
        for port in $REALITY_TEST_PORT_CANDIDATES; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            [[ "$port" -ge "$min" && "$port" -le "$max" ]] || continue
            reality_port_in_use "$port" || { echo "$port"; return 0; }
        done
    fi
    for try in $(seq 1 200); do
        if command_exists shuf; then
            port=$(shuf -i "${min}-${max}" -n 1)
        elif command_exists od && [[ -r /dev/urandom ]]; then
            rand=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
            port=$(( rand % range + min ))
        else
            port=$(( (((RANDOM << 15) ^ RANDOM) % range) + min ))
        fi
        reality_port_in_use "$port" || { echo "$port"; return 0; }
    done
    return 1
}

reality_generate_short_id() {
    if command_exists openssl; then
        openssl rand -hex 8
    else
        tr -dc '0-9a-f' < /dev/urandom | head -c 16
        echo
    fi
}

# 随机挑一个「真实浏览器」uTLS 指纹（客户端 fp）。
# 目的：全网节点默认都填 chrome 会形成同一特征（fp=chrome 指纹画像），改为按节点随机分散。
# 关键取舍：不用 uTLS 的 "randomized"（每次连接换指纹反而异常——真实浏览器指纹是稳定的），
# 而是「装机时定一个真实浏览器指纹并持久化」→ 单节点稳定像真浏览器、节点之间彼此不同。
# 池仅取主流真实浏览器（sing-box uTLS 合法值），不含 360/q（地域性强、易反成特征）与 randomized。
reality_random_fingerprint() {
    local fps=(chrome firefox edge safari ios android)
    local n=${#fps[@]} idx
    if command_exists openssl; then
        idx=$(( 0x$(openssl rand -hex 2) % n ))
    else
        idx=$(( RANDOM % n ))
    fi
    printf '%s' "${fps[$idx]}"
}

# 校验是否为合法 uTLS 指纹（用于导入/回读兜底）。非法或空 → 回退 chrome。
reality_sanitize_fingerprint() {
    local fp="${1:-}"
    case "$fp" in
        chrome|firefox|edge|safari|ios|android|360|q|randomized) printf '%s' "$fp" ;;
        *) printf '%s' "chrome" ;;
    esac
}

# 当前落地机的有效客户端指纹：读 state 的 REALITY_FINGERPRINT，经 sanitize；
# 旧版 state 无该字段（空）→ 回退 chrome（保持老节点链接不变）。
reality_effective_fingerprint() {
    reality_sanitize_fingerprint "${REALITY_FINGERPRINT:-}"
}

reality_generate_uuid() {
    if command_exists sing-box; then
        sing-box generate uuid 2>/dev/null && return 0
    fi
    [[ -r /proc/sys/kernel/random/uuid ]] && { cat /proc/sys/kernel/random/uuid; return 0; }
    command_exists uuidgen && { uuidgen | tr 'A-Z' 'a-z'; return 0; }
    return 1
}

reality_generate_keypair() {
    local out private public
    out=$(sing-box generate reality-keypair 2>/dev/null) || return 1
    private=$(awk -F': *' '/PrivateKey|Private key|private_key/{print $2; exit}' <<< "$out")
    public=$(awk -F': *' '/PublicKey|Public key|public_key/{print $2; exit}' <<< "$out")
    if [[ -z "$private" || -z "$public" ]]; then
        private=$(sed -n '1p' <<< "$out" | awk '{print $NF}')
        public=$(sed -n '2p' <<< "$out" | awk '{print $NF}')
    fi
    [[ -n "$private" && -n "$public" ]] || return 1
    printf '%s\n%s\n' "$private" "$public"
}

reality_public_key_from_private() {
    # sing-box 目前没有可靠的 "private -> public" 子命令；不要调用
    # `sing-box generate reality-keypair --private-key ...`，实测会生成新 keypair。
    # 这里按 RFC8410 包装 X25519 raw private key，再由 openssl 导出 raw public key。
    local private="$1" tmp_dir raw der spki pub b64 len
    [[ -n "$private" ]] || return 1
    command_exists openssl || return 1
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-x25519.XXXXXX") || return 1
    raw="$tmp_dir/private.raw"
    der="$tmp_dir/private.der"
    spki="$tmp_dir/public.spki.der"
    pub="$tmp_dir/public.raw"
    b64="${private//-/+}"
    b64="${b64//_//}"
    case $(( ${#b64} % 4 )) in
        2) b64="${b64}==" ;;
        3) b64="${b64}=" ;;
        1) rm -rf "$tmp_dir"; return 1 ;;
    esac
    if ! printf '%s' "$b64" | openssl base64 -d -A > "$raw" 2>/dev/null; then
        rm -rf "$tmp_dir"; return 1
    fi
    len=$(wc -c < "$raw" | tr -d '[:space:]')
    if [[ "$len" != "32" ]]; then rm -rf "$tmp_dir"; return 1; fi
    printf '%b' '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20' > "$der"
    cat "$raw" >> "$der"
    if ! openssl pkey -inform DER -in "$der" -pubout -outform DER > "$spki" 2>/dev/null; then
        rm -rf "$tmp_dir"; return 1
    fi
    tail -c 32 "$spki" > "$pub"
    openssl base64 -A -in "$pub" 2>/dev/null | tr '+/' '-_' | sed 's/=*$//'
    rm -rf "$tmp_dir"
}

reality_detect_listen_host() {
    # 决定 sing-box / realm 应绑定的本机地址：
    #   本机存在全局 IPv6 地址 → "::"（双栈监听；bindv6only=0 默认下经 IPv4-mapped 同时覆盖 IPv4），
    #   否则 → "0.0.0.0"（纯 IPv4）。
    # 用本地接口判断而非公网探测，避免网络抖动导致 IPv6-only 机器误绑 0.0.0.0 而对外不可达。
    # 可用 REALITY_LISTEN_HOST 覆盖（测试/特殊网络）。
    # "split" 是双节点模式的哨兵值（sing-box 入站走 REALITY_LISTEN_HOST_V4/V6，不用此变量），
    # 不是合法 bind 地址；realm 等消费者遇到它时必须回落到接口探测（split 必有 IPv6→绑 ::），
    # 否则会渲染出 listen = "split:<port>" 致 realm 无法启动。
    if [[ -n "${REALITY_LISTEN_HOST:-}" && "${REALITY_LISTEN_HOST}" != "split" ]]; then printf '%s' "$REALITY_LISTEN_HOST"; return 0; fi
    if command_exists ip && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        printf '%s' "::"
    else
        printf '%s' "0.0.0.0"
    fi
}

# 把 host+port 组装为监听串：IPv6 字面量加方括号
reality_listen_endpoint() {
    local host="$1" port="$2"
    if [[ "$host" == *:* ]]; then printf '[%s]:%s' "$host" "$port"; else printf '%s:%s' "$host" "$port"; fi
}

# ============================================================================
# 443 共存模式（nginx stream + ssl_preread 分流）
# 开启后：443 由 nginx stream 独占，按 SNI 分流——真站域名→web(127.0.0.1:WEB_PORT)，
# default(借用SNI/未知/无SNI)→reality(127.0.0.1:REALITY_PORT)。sing-box reality 入站
# 从公网 443 改绑 127.0.0.1:<内部端口>；客户端链接仍是 443（连的是 nginx stream）。
# 关键：Reality 客户端 ClientHello 的 SNI 是借用大站域名（非节点域名），故必须 default→reality。
# ============================================================================

# 共存是否已启用（state 文件存在且 ENABLED=1、内部端口合法）
reality_coexist_enabled() {
    [[ -f "$REALITY_COEXIST_STATE_FILE" ]] || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        [[ "${REALITY_COEXIST_ENABLED:-0}" == "1" ]] || exit 1
        validate_port "${REALITY_COEXIST_REALITY_PORT:-}" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_WEB_PORT:-}" 2>/dev/null || exit 1
    )
}

# 加载共存 state 到全局（渲染/菜单/诊断用；渲染入站走子 shell 读取时不调它）
reality_coexist_load_state() {
    [[ -f "$REALITY_COEXIST_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_COEXIST_STATE_FILE" || return 1
    # shellcheck disable=SC1090
    source "$REALITY_COEXIST_STATE_FILE"
}

# 写共存 state（值经 reality_state_quote，满足 validate_conf_file 的 owner/600/字面量校验）
reality_coexist_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    validate_port "${REALITY_COEXIST_REALITY_PORT:-}" || { print_error "共存 reality 内部端口无效: ${REALITY_COEXIST_REALITY_PORT:-空}"; return 1; }
    validate_port "${REALITY_COEXIST_WEB_PORT:-}" || { print_error "共存 web 内部端口无效: ${REALITY_COEXIST_WEB_PORT:-空}"; return 1; }
    local content
    content=$(cat <<EOF
REALITY_COEXIST_ENABLED=$(reality_state_quote "${REALITY_COEXIST_ENABLED:-0}")
REALITY_COEXIST_REALITY_PORT=$(reality_state_quote "${REALITY_COEXIST_REALITY_PORT:-}")
REALITY_COEXIST_WEB_PORT=$(reality_state_quote "${REALITY_COEXIST_WEB_PORT:-}")
EOF
)
    reality_write_secure_file "$REALITY_COEXIST_STATE_FILE" "$content"
}

# 取共存 reality 内部端口（供 web 模块/诊断复用）；未启用返回非 0
reality_coexist_reality_port() {
    reality_coexist_enabled || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_REALITY_PORT:-}" 2>/dev/null || exit 1
        printf '%s' "${REALITY_COEXIST_REALITY_PORT}"
    )
}

# 取共存 web 内部端口（供 web 模块建站下沉复用）；未启用返回非 0
reality_coexist_web_port() {
    reality_coexist_enabled || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_WEB_PORT:-}" 2>/dev/null || exit 1
        printf '%s' "${REALITY_COEXIST_WEB_PORT}"
    )
}

# 收集需要走 443 stream SNI 白名单的真站域名。
# 真相源：/etc/nginx/sites-available/*.conf。关键：只收录“实际监听 web 内部端口”的站点，
# 从其 server_name 取域名——因为只有经 _web_coexist_https_port 下沉到 web_port 的站才真在该端口。
# 09e 家宽暴露（默认 8443）、用户自定义非 443 端口的站不会下沉，故不监听 web_port，
# 不应进白名单（否则会被 stream 路由到无人监听的 web_port 而连不上）。
# 排除 CDN 回源站（reality-cdn-*，走 8443 橙云回源，不经 443 stream）。
# 每域一行；无则输出空。
reality_coexist_collect_web_domains() {
    local f base web_port sn sites_dir="${REALITY_NGINX_SITES_DIR:-/etc/nginx/sites-available}"
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$web_port" 2>/dev/null || return 0
    [[ -d "$sites_dir" ]] || return 0
    for f in "$sites_dir"/*.conf; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f" .conf)
        # CDN 回源站不经 443 stream（独立回源端口 + 橙云），跳过
        [[ "$base" == reality-cdn-* ]] && continue
        # 该站必须真实监听 web 内部端口，否则不路由到 web。
        # 共存下真站由 _nginx_tls_http2_block 渲染成 loopback 绑定：
        #   listen 127.0.0.1:<port> ssl;  /  listen [::1]:<port> ssl;
        # 故 listen 行可能带 IPv4/IPv6 主机前缀（127.0.0.1: 或 [..]:），也可能是裸端口
        # （listen <port> / listen [::]:<port>）。全部需匹配，否则真站永不入白名单，
        # 所有 SNI 都落到 default→reality，web 侧共存静默失效。
        grep -Eq "^\s*listen\s+([0-9.]+:|\[[0-9a-fA-F:]+\]:)?${web_port}(\s|;)" "$f" 2>/dev/null || continue
        # 从 server_name 行取第一个域名（比文件名更准：文件名可能与 server_name 不一致）
        sn=$(grep -E '^\s*server_name\s+' "$f" 2>/dev/null | head -n1 \
             | sed -E 's/^\s*server_name\s+//; s/;.*$//' | awk '{print $1}')
        [[ -n "$sn" ]] || sn="$base"
        validate_domain "$sn" 2>/dev/null || continue
        printf '%s\n' "$sn"
    done | sort -u
}

# 渲染 stream 分流配置片段（写入独立文件，由 nginx.conf 的 stream{} include 引入）。
# map $ssl_preread_server_name：真站域名 → web upstream；default → reality upstream。
# 关键：default 必须指向 reality（Reality 客户端 SNI 是借用大站域名，非节点域名）。
reality_coexist_render_stream_conf() {
    local reality_port web_port
    reality_port="$(reality_coexist_reality_port 2>/dev/null || true)"
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$reality_port" || { print_error "共存 reality 内部端口无效"; return 1; }
    validate_port "$web_port" || { print_error "共存 web 内部端口无效"; return 1; }
    local -a domains=()
    local d
    while IFS= read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(reality_coexist_collect_web_domains)
    {
        echo "# Reality 443 共存分流 (nginx stream + ssl_preread)"
        echo "# Generated by ${SCRIPT_NAME} ${VERSION}"
        echo "# 443 由本 stream 独占；真站域名(白名单)→127.0.0.1:${web_port}，default→127.0.0.1:${reality_port}(reality)。"
        echo "map \$ssl_preread_server_name \$reality_coexist_backend {"
        for d in "${domains[@]}"; do
            printf '    %s reality_coexist_web;\n' "$d"
        done
        echo "    default reality_coexist_reality;"
        echo "}"
        echo "upstream reality_coexist_reality { server 127.0.0.1:${reality_port}; }"
        echo "upstream reality_coexist_web { server 127.0.0.1:${web_port}; }"
        echo "server {"
        echo "    listen 443;"
        echo "    listen [::]:443;"
        echo "    proxy_pass \$reality_coexist_backend;"
        echo "    ssl_preread on;"
        echo "}"
    }
}

# nginx.conf 是否已有顶层 stream{} 块（外部/发行版自带）。有则注入策略需谨慎。
# 除 nginx.conf 正文外，还展开其中 include 引入的文件——发行版常把 stream{} 放在
# include 进来的独立片段里（如 /etc/nginx/conf.d/*.conf、modules 等），只查正文会漏检，
# 导致我们再注入一个 stream{} 造成两个顶层 stream 块、nginx 启动失败。
# 排除我们自己的标记块与 stream-enabled 目录（那是本功能产物，非“外部已有”）。
reality_coexist_nginx_has_stream_block() {
    local main_conf="${1:-/etc/nginx/nginx.conf}"
    [[ -f "$main_conf" ]] || return 1
    local uncommented inc_line inc_glob g conf_dir
    conf_dir="$(dirname "$main_conf")"
    # 1) 正文（去注释）直接含 stream{ —— 但排除我们自己注入的标记块
    if ! grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null; then
        if grep -vE '^\s*#' "$main_conf" 2>/dev/null | grep -qE '(^|\s)stream\s*\{'; then
            return 0
        fi
    fi
    # 2) 展开 include 的文件再查（仅顶层 include；一层展开足以覆盖发行版默认布局）
    while IFS= read -r inc_line; do
        inc_glob=$(sed -E 's/^\s*include\s+//; s/;\s*$//' <<< "$inc_line")
        [[ -n "$inc_glob" ]] || continue
        # 相对路径按 nginx.conf 所在目录展开
        [[ "$inc_glob" != /* ]] && inc_glob="${conf_dir}/${inc_glob}"
        for g in $inc_glob; do
            [[ -f "$g" ]] || continue
            # 跳过我们自己的 stream-enabled 产物目录
            [[ "$g" == "$REALITY_STREAM_ENABLED_DIR"/* ]] && continue
            grep -vE '^\s*#' "$g" 2>/dev/null | grep -qE '(^|\s)stream\s*\{' && return 0
        done
    done < <(grep -vE '^\s*#' "$main_conf" 2>/dev/null | grep -E '^\s*include\s+')
    return 1
}

# 幂等地把 stream include 注入 nginx.conf 顶层。
# 用独立 stream{} 块 include 我们的 stream-enabled 目录；带唯一标记便于回滚移除。
reality_coexist_inject_nginx_include() {
    local main_conf="${1:-/etc/nginx/nginx.conf}" tmp
    [[ -f "$main_conf" ]] || { print_error "未找到 nginx.conf: $main_conf"; return 1; }
    mkdir -p "$REALITY_STREAM_ENABLED_DIR"
    # 已注入过（含标记）→ 幂等返回
    if grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null; then
        return 0
    fi
    if reality_coexist_nginx_has_stream_block "$main_conf"; then
        # 外部已有 stream{}：不改它，改为把 include 加进已有块——风险较高，交由调用方提示手动处理。
        print_warn "nginx.conf 已存在 stream{} 块；为避免破坏，请手动在其中加入: include ${REALITY_STREAM_ENABLED_DIR}/*.conf;"
        return 2
    fi
    reality_backup_file "$main_conf" || return 1
    tmp=$(mktemp "$(dirname "$main_conf")/.tmp.server-manage.nginx-stream-include.XXXXXX") || return 1
    declare -F _tmp_register >/dev/null 2>&1 && _tmp_register "$tmp"
    # 追加独立 stream 块到文件末尾（顶层合法），先写同目录候选文件，避免中断/写满磁盘污染 nginx.conf。
    if ! cat "$main_conf" > "$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    if ! cat >> "$tmp" <<EOF

# reality-coexist-stream-include (由 ${SCRIPT_NAME} 注入，可经菜单关闭共存自动移除)
stream {
    include ${REALITY_STREAM_ENABLED_DIR}/*.conf;
}
EOF
    then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    chmod --reference="$main_conf" "$tmp" 2>/dev/null || true
    chown --reference="$main_conf" "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$main_conf"; then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
}

# 移除注入的 stream include 块（回滚用）。仅删带唯一标记的块，不动外部 stream。
reality_coexist_remove_nginx_include() {
    local main_conf="${1:-/etc/nginx/nginx.conf}"
    [[ -f "$main_conf" ]] || return 0
    grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null || return 0
    reality_backup_file "$main_conf"
    # 删除从标记注释行起、到其后第一个单独成行的 '}' 为止的整块
    local tmp
    tmp=$(mktemp "$(dirname "$main_conf")/.tmp.nginxconf.XXXXXX") || return 1
    awk '
        /# reality-coexist-stream-include/ { skip=1; next }
        skip && /^\}/ { skip=0; next }
        skip { next }
        { print }
    ' "$main_conf" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$main_conf" "$tmp" 2>/dev/null || true
    mv "$tmp" "$main_conf" || { rm -f "$tmp"; return 1; }
}

# 刷新 stream 分流配置（web 模块增删域名后调用；仅在共存启用时生效）。
# 重写 stream 片段 → nginx -t → reload。失败保留旧片段并回滚。
reality_coexist_refresh() {
    reality_coexist_enabled || return 0
    command_exists nginx || return 0
    # stream 模块必须在场：refresh 也被 web 建站路径调用，若此时 nginx 无 stream 模块
    # （被外部改动卸载/换版本），我们注入的 stream{} 会让 nginx -t 整体失败，进而误伤
    # 刚部署的站点配置。此时告警并跳过刷新（不动 nginx），把 stream 恢复留给用户重开共存。
    if declare -F _check_nginx_stream >/dev/null 2>&1 && ! _check_nginx_stream; then
        print_warn "nginx 当前无 stream 模块，跳过 443 共存分流刷新；请重新启用共存或修复 stream 模块。"
        return 0
    fi
    mkdir -p "$REALITY_STREAM_ENABLED_DIR"
    local new_conf backup=""
    new_conf="$(reality_coexist_render_stream_conf)" || return 1
    if [[ -f "$REALITY_STREAM_CONF" ]]; then
        backup=$(mktemp "${REALITY_STREAM_ENABLED_DIR}/.reality-coexist.bak.XXXXXX") || return 1
        cp -a "$REALITY_STREAM_CONF" "$backup" || { rm -f "$backup"; return 1; }
    fi
    write_file_atomic "$REALITY_STREAM_CONF" "$new_conf" || {
        print_error "写入 stream 分流配置失败"
        [[ -n "$backup" ]] && rm -f "$backup"
        return 1
    }
    if nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1; then
        [[ -n "$backup" ]] && rm -f "$backup"
        return 0
    fi
    print_error "nginx 测试/重载失败，回滚 stream 分流配置"
    if [[ -n "$backup" && -e "$backup" ]]; then
        mv "$backup" "$REALITY_STREAM_CONF"
    else
        rm -f "$REALITY_STREAM_CONF"
    fi
    nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
    return 1
}

# 选一个未占用的 loopback 内部端口：优先用建议值，被占用则回落随机高位。
reality_coexist_pick_inner_port() {
    local prefer="$1" forbidden="${2:-}" p
    # 建议值(prefer)本身是共存常量，会出现在 reserved 集里，故检查保留时把 prefer 自身排除。
    if validate_port "$prefer" && [[ "$prefer" != "$forbidden" ]] \
        && ! reality_port_in_use "$prefer" && ! reality_port_reserved "$prefer" "$prefer"; then
        echo "$prefer"; return 0
    fi
    for _ in $(seq 1 200); do
        p=$(reality_random_port) || return 1
        [[ "$p" == "$forbidden" || "$p" == "${REALITY_PORT:-}" || "$p" == "${REALITY_CDN_ORIGIN_PORT:-8443}" ]] && continue
        # MED-4：除运行时占用，还要避开本项目其他 feature 已保留(可能当前停止)的端口。
        reality_port_reserved "$p" "$forbidden" && continue
        reality_port_in_use "$p" && continue
        echo "$p"; return 0
    done
    return 1
}

# 启用 443 共存模式：sing-box reality 入站下沉到 loopback，443 交给 nginx stream 分流。
# 顺序关键：先重渲 sing-box 释放公网 443，再让 nginx stream 抢 443，避免端口冲突。
reality_coexist_enable() {
    print_title "启用 Reality 443 共存模式（nginx stream + ssl_preread）"
    reality_require_supported_os || { pause; return 1; }
    if ! reality_load_state || [[ -z "${REALITY_UUID:-}" || -z "${REALITY_PORT:-}" || -z "${REALITY_SNI:-}" ]]; then
        print_error "本机尚未安装 Reality 落地机，请先用菜单 1 安装落地机。"
        pause; return 1
    fi
    if reality_coexist_enabled; then
        print_warn "443 共存模式已启用。"
        pause; return 0
    fi
    # split 双栈：共存分支只渲染单入站（用 REALITY_PORT），会丢掉 IPv6 节点，故明确拒绝。
    local _mode; _mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo auto)
    if [[ "$_mode" == "split" ]]; then
        print_error "IPv4/IPv6 双节点(split)模式暂不支持 443 共存：stream 分流与双入站需另行设计。"
        print_info "如需共存，请改用单节点(auto/ipv4/ipv6)模式重装落地机后再启用。"
        pause; return 1
    fi
    # 共存要求 Reality 对外走 443（由 nginx stream 持有）。若落地端口非 443，
    # 启用后客户端链接端口(REALITY_PORT)与实际对外端口(443)不一致，且 ufw/安全组未放行 443，
    # 会静默不可达。强制要求落地端口为 443。
    if [[ "${REALITY_PORT:-}" != "443" ]]; then
        print_error "当前 Reality 落地端口为 ${REALITY_PORT:-未知}，非 443。443 共存要求落地端口为 443。"
        print_info "请用菜单 1 以「443」端口重装落地机后再启用共存。"
        pause; return 1
    fi
    command_exists nginx || { print_error "Nginx 未安装。请先用 Web 菜单「添加域名」安装 nginx/certbot 依赖。"; pause; return 1; }
    echo "  说明：开启后 443 由 nginx stream 独占，按 SNI 分流——真站域名→web 内部端口，"
    echo "  default（Reality 借用大站 SNI/未知/无 SNI）→ sing-box reality loopback 入站。"
    echo "  Reality 直连伪装、借 SNI 轮换保持不变；客户端链接仍是 443（连的是 nginx stream）。"
    echo "  注意：此后每次 reload nginx（加站/改站）会让 Reality 连接瞬断重连。"
    echo "  注意：真站经 stream 透传后，其访问日志/按 IP 的限流/geo 会看到 127.0.0.1（非真实客户端 IP）；"
    echo "        因 stream 与 Reality 直连共用一个入口、无法只对真站启用 PROXY 协议，故不取真实 IP。"
    echo ""
    confirm "确认启用 443 共存模式?" || { print_info "已取消"; pause; return 0; }

    # 1) 确保 nginx 具备 stream 模块（缺失则装 libnginx-mod-stream 或换官方源）
    echo -e "\n${C_CYAN}=== [1] 检查/安装 nginx stream 模块 ===${C_RESET}"
    if ! _ensure_nginx_stream; then
        print_error "无法为 nginx 启用 stream 模块，已中止。可手动安装官方 nginx.org 源（含 stream）后重试。"
        pause; return 1
    fi
    print_success "nginx stream 模块可用"

    # 2) 选内部端口（loopback，仅本机 nginx 连接）
    local reality_inner web_inner
    reality_inner=$(reality_coexist_pick_inner_port "$REALITY_COEXIST_INNER_PORT") || { print_error "无法分配 reality 内部端口"; pause; return 1; }
    web_inner=$(reality_coexist_pick_inner_port "$REALITY_WEB_INNER_PORT" "$reality_inner") || { print_error "无法分配 web 内部端口"; pause; return 1; }

    # 3) 写共存 state（ENABLED=1 使 render 走 loopback 分支）
    REALITY_COEXIST_ENABLED=1
    REALITY_COEXIST_REALITY_PORT="$reality_inner"
    REALITY_COEXIST_WEB_PORT="$web_inner"
    reality_coexist_write_state || { print_error "写入共存 state 失败"; rm -f "$REALITY_COEXIST_STATE_FILE"; pause; return 1; }

    # 4) 重渲 sing-box：入站改绑 127.0.0.1:reality_inner，释放公网 443
    echo -e "\n${C_CYAN}=== [2] 重渲 sing-box（reality 入站下沉到 127.0.0.1:${reality_inner}）===${C_RESET}"
    local new_config
    if ! new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") \
       || ! reality_apply_singbox_config "$new_config"; then
        print_error "sing-box 重渲失败，回滚共存 state。"
        rm -f "$REALITY_COEXIST_STATE_FILE"
        pause; return 1
    fi
    print_success "sing-box reality 入站已下沉到 loopback，公网 443 已释放"

    # 5) 生成 stream 分流配置 + 注入 nginx.conf include + reload
    echo -e "\n${C_CYAN}=== [3] 部署 nginx stream 443 分流 ===${C_RESET}"
    local inject_rc
    reality_coexist_inject_nginx_include; inject_rc=$?
    # rc==0 注入成功；rc==2 外部已有 stream{} 块（我们未注入 include，若继续会导致分流配置成为
    # 死文件、公网 443 无人监听而节点全废且误报成功）；rc==1 写入失败。非 0 一律中止回滚。
    if [[ $inject_rc -ne 0 ]]; then
        if [[ $inject_rc -eq 2 ]]; then
            print_error "nginx.conf 已存在 stream{} 块，为避免破坏未自动注入。请手动在该 stream{} 内加入："
            print_error "    include ${REALITY_STREAM_ENABLED_DIR}/*.conf;"
            print_error "然后重新启用共存。已回滚（sing-box 改回直绑 443）。"
        else
            print_error "注入 nginx.conf stream include 失败，回滚。"
        fi
        reality_coexist_disable_internal
        pause; return 1
    fi
    if ! reality_coexist_refresh; then
        print_error "nginx stream 分流部署失败，回滚（sing-box 改回直绑 443）。"
        reality_coexist_disable_internal
        pause; return 1
    fi
    print_success "nginx stream 已接管 443 分流"
    # 确保对外 443 已放行（nginx stream 现在持有 443；落地端口原为 443 通常已放行，此处兜底）。
    # 内部端口 reality_inner/web_inner 仅 loopback，不放行、外部不可见。
    firewall_apply_reality_port 443 >/dev/null 2>&1 || \
        print_warn "未能自动放行 443/tcp，请确认 ufw/云安全组已放行 443（stream 分流对外入口）。"
    echo ""
    print_success "443 共存模式已启用！reality 内部端口 ${reality_inner}，web 内部端口 ${web_inner}。"
    print_info "此后用 Web 菜单新建的站点会自动使用 ${web_inner} 端口，由 443 stream 统一对外。"
    log_action "reality coexist enabled: reality=${reality_inner} web=${web_inner}"
    pause
}

# 内部回滚/关闭：不含交互确认，供 enable 失败回滚与 disable 菜单共用。
# 顺序：先移除 nginx stream（释放 443）→ 删共存 state → 重渲 sing-box 直绑 443。
reality_coexist_disable_internal() {
    rm -f "$REALITY_STREAM_CONF"
    reality_coexist_remove_nginx_include
    rm -f "$REALITY_COEXIST_STATE_FILE"
    if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
    # nginx reload 释放 443 是异步的（旧 worker 优雅退出需时间）。若紧接着 restart sing-box
    # 抢绑 443，旧 worker 可能仍持有 443 → bind 失败 → systemd 重试期间对外中断约 10s。
    # 故先有界等待 443 真正释放（最多 ~5s），再重渲 sing-box 直绑 443，消除竞态中断。
    reality_wait_port_free 443 50 || print_warn "443 释放等待超时，sing-box 直绑可能需 systemd 重试后生效。"
    if reality_load_state && [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" ]]; then
        local cfg
        cfg=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") \
            && reality_apply_singbox_config "$cfg" || true
    fi
}

# 关闭 443 共存模式（菜单入口，带确认）。
reality_coexist_disable() {
    print_title "关闭 Reality 443 共存模式"
    if ! reality_coexist_enabled; then
        print_warn "当前未启用 443 共存模式。"
        pause; return 0
    fi
    echo "  关闭后：nginx stream 443 分流移除，sing-box reality 入站改回直绑公网 443。"
    echo "  已建的真站若仍监听内部端口（如 12443），需你自行改回 443 或重建（脚本不自动改回）。"
    echo ""
    confirm "确认关闭 443 共存模式?" || { print_info "已取消"; pause; return 0; }
    reality_coexist_disable_internal
    print_success "443 共存模式已关闭，Reality 已改回直绑 443。"
    print_info "如有站点仍监听内部端口，请手动改回 443 后 reload nginx，或用 Web 菜单重建。"
    log_action "reality coexist disabled"
    pause
}

reality_render_singbox_config() {
    local uuid="$1" private_key="$2" port="$3" sni="$4" short_id="$5"
    local listen_host; listen_host="${REALITY_LISTEN_HOST:-$(reality_detect_listen_host)}"
    uuid=$(reality_json_escape "$uuid")
    private_key=$(reality_json_escape "$private_key")
    sni=$(reality_json_escape "$sni")
    short_id=$(reality_json_escape "$short_id")
    # CDN 链路（VLESS+WS）入站：若已启用则作为额外 inbound 一并渲染。
    # 关键：必须在“整体重渲染”里合并（不能事后追加），否则 rotate key/user、改名、重装
    # 等任何触发重渲染的操作都会把 WS 入站冲掉。子 shell 读取，避免污染本函数全局。
    local cdn_inbound; cdn_inbound="$(reality_cdn_inbound_json)"
    # 共存模式：sing-box reality 入站改绑 127.0.0.1:<内部端口>，443 由 nginx stream 对外分流。
    # 共存下单入站即可（v4/v6 都由 nginx stream 统一对外），故优先于 split 分支处理。
    local coexist_port; coexist_port="$(reality_coexist_reality_port 2>/dev/null || true)"
    if [[ -n "$coexist_port" ]]; then
        cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"127.0.0.1","listen_port":${coexist_port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
        return 0
    fi
    if [[ "${REALITY_DNS_MODE:-auto}" == "split" && -n "${REALITY_PORT_V6:-}" ]]; then
        local listen_host_v4="${REALITY_LISTEN_HOST_V4:-0.0.0.0}" listen_host_v6="${REALITY_LISTEN_HOST_V6:-::}" port_v6="${REALITY_PORT_V6}"
        cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-ipv4","listen":"${listen_host_v4}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}},{"type":"vless","tag":"vless-reality-ipv6","listen":"${listen_host_v6}","listen_port":${port_v6},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
        return 0
    fi
    cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"${listen_host}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
}

# ============================================================================
# CDN 链路（VLESS + WebSocket + TLS，CF 橙云 + 优选 IP）
# 与 Reality 直连链路并存：Reality 仍绑 443 灰云直连；CDN 的 WS 入站只绑
# 127.0.0.1:<内部端口>（明文），由 nginx 在 REALITY_CDN_ORIGIN_PORT 上做 TLS 终止
# + 反代到该内部端口，CF 橙云 Full(strict) 回源。客户端把 server 字段填优选 IP、
# host/sni 填真实 cdn 域名，CF 靠 Host 头路由回源。
# 优选 IP 时效仅几天，由国内机定时跑 CloudflareSpeedTest（B）+ 本地渲染/入口 DNS 同步（C）刷新。
# ============================================================================

# CDN 是否已启用（state 文件存在且关键字段齐全）
reality_cdn_enabled() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_CDN_STATE_FILE" 2>/dev/null && source "$REALITY_CDN_STATE_FILE" 2>/dev/null
        [[ -n "${REALITY_CDN_UUID:-}" && -n "${REALITY_CDN_WS_PATH:-}" && -n "${REALITY_CDN_INNER_PORT:-}" ]] && \
        validate_port "${REALITY_CDN_INNER_PORT:-}" 2>/dev/null && \
        reality_validate_ws_path "${REALITY_CDN_WS_PATH:-}" 2>/dev/null
    )
}

# 写 CDN state（值经 reality_state_quote，满足 validate_conf_file 的 owner/600/字面量校验）
reality_cdn_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    validate_domain "${REALITY_CDN_DOMAIN:-}" || { print_error "CDN 域名无效: ${REALITY_CDN_DOMAIN:-空}"; return 1; }
    [[ -n "${REALITY_CDN_UUID:-}" ]] || { print_error "CDN UUID 为空"; return 1; }
    reality_validate_ws_path "${REALITY_CDN_WS_PATH:-}" || { print_error "CDN WS path 无效: ${REALITY_CDN_WS_PATH:-空}"; return 1; }
    validate_port "${REALITY_CDN_INNER_PORT:-}" || { print_error "CDN 内部端口无效: ${REALITY_CDN_INNER_PORT:-空}"; return 1; }
    validate_port "${REALITY_CDN_ORIGIN_PORT:-}" || { print_error "CDN 回源端口无效: ${REALITY_CDN_ORIGIN_PORT:-空}"; return 1; }
    local content
    content=$(cat <<EOF
REALITY_CDN_DOMAIN=$(reality_state_quote "${REALITY_CDN_DOMAIN:-}")
REALITY_CDN_UUID=$(reality_state_quote "${REALITY_CDN_UUID:-}")
REALITY_CDN_WS_PATH=$(reality_state_quote "${REALITY_CDN_WS_PATH:-}")
REALITY_CDN_INNER_PORT=$(reality_state_quote "${REALITY_CDN_INNER_PORT:-}")
REALITY_CDN_ORIGIN_PORT=$(reality_state_quote "${REALITY_CDN_ORIGIN_PORT:-}")
REALITY_CDN_PREFER_IP=$(reality_state_quote "${REALITY_CDN_PREFER_IP:-}")
REALITY_CDN_NODE_NAME=$(reality_state_quote "${REALITY_CDN_NODE_NAME:-}")
EOF
)
    reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$content"
}

# 加载 CDN state 到全局（供向导/卸载/产物使用；渲染入站走子 shell 不调它）
reality_cdn_load_state() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_CDN_STATE_FILE" || return 1
    # shellcheck disable=SC1090
    source "$REALITY_CDN_STATE_FILE"
}

# 生成 CDN 的 WS 入站 JSON 片段（带前导逗号，拼到 reality 入站之后）。
# 子 shell 读取 state，避免污染调用方（reality_render_singbox_config）的全局变量。
# 未启用 / 字段不全 → 输出空串（即不渲染该入站）。
reality_cdn_inbound_json() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 0
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_CDN_STATE_FILE" 2>/dev/null && source "$REALITY_CDN_STATE_FILE" 2>/dev/null || exit 0
        [[ -n "${REALITY_CDN_UUID:-}" && -n "${REALITY_CDN_WS_PATH:-}" && -n "${REALITY_CDN_INNER_PORT:-}" ]] || exit 0
        validate_port "${REALITY_CDN_INNER_PORT}" 2>/dev/null || exit 0
        reality_validate_ws_path "${REALITY_CDN_WS_PATH}" 2>/dev/null || exit 0
        local u p path
        u=$(reality_json_escape "$REALITY_CDN_UUID")
        path=$(reality_json_escape "$REALITY_CDN_WS_PATH")
        p="$REALITY_CDN_INNER_PORT"
        printf ',{"type":"vless","tag":"vless-cdn-ws","listen":"127.0.0.1","listen_port":%s,"users":[{"name":"cdn","uuid":"%s"}],"transport":{"type":"ws","path":"%s"}}' \
            "$p" "$u" "$path"
    )
}

# 生成 CDN 客户端 vless 链接（WS+TLS）。server=优选IP(默认=域名)，host/sni=真实 cdn 域名。
# fp 复用落地机的有效指纹（CDN 与落地共用 UUID，同属一台机器的客户端身份）。
reality_cdn_build_link() {
    local server="$1" name="$2" encoded_name encoded_path server_uri fp
    fp=$(reality_effective_fingerprint)
    encoded_name=$(reality_urlencode "$name")
    encoded_path=$(reality_urlencode "$REALITY_CDN_WS_PATH")
    server_uri=$(reality_uri_host "$server")
    printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=%s&type=ws&host=%s&path=%s#%s\n' \
        "$REALITY_CDN_UUID" "$server_uri" "$REALITY_CDN_DOMAIN" "$fp" "$REALITY_CDN_DOMAIN" "$encoded_path" "$encoded_name"
}

# 写 CDN 客户端产物（链接 + sing-box JSON）。server 优先用优选 IP，无则回落域名。
reality_cdn_write_client_artifacts() {
    mkdir -p "$REALITY_CONFIG_DIR"
    local server="${REALITY_CDN_PREFER_IP:-$REALITY_CDN_DOMAIN}"
    local name="${REALITY_CDN_NODE_NAME:-cdn-$( printf '%s' "$REALITY_CDN_DOMAIN" | cut -d. -f1 )}"
    [[ -n "$REALITY_CDN_UUID" && -n "$REALITY_CDN_DOMAIN" && -n "$REALITY_CDN_WS_PATH" ]] || return 1
    reality_validate_ws_path "$REALITY_CDN_WS_PATH" || return 1
    local json_name; json_name=$(reality_json_escape "$name")
    local json_path; json_path=$(reality_json_escape "$REALITY_CDN_WS_PATH")
    local json_host; json_host=$(reality_json_escape "$REALITY_CDN_DOMAIN")
    local json_server; json_server=$(reality_json_escape "$server")
    local json_uuid; json_uuid=$(reality_json_escape "$REALITY_CDN_UUID")
    local cdn_fp; cdn_fp=$(reality_effective_fingerprint)
    local link_content json_content
    link_content="$(reality_cdn_build_link "$server" "$name")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_server}","server_port":443,"uuid":"${json_uuid}","tls":{"enabled":true,"server_name":"${json_host}","utls":{"enabled":true,"fingerprint":"${cdn_fp}"}},"transport":{"type":"ws","path":"${json_path}","headers":{"Host":"${json_host}"}}}
EOF
)
    reality_write_secure_file "$REALITY_CDN_LINK_FILE" "$link_content" || return 1
    reality_write_secure_file "$REALITY_CDN_CLIENT_JSON" "$json_content" || return 1
}

reality_cdn_nginx_site_name() {
    local domain="${1:-}"
    printf 'reality-cdn-%s' "$domain"
}

reality_cdn_cf_cred_path() {
    local domain="${1:-}" dir="${REALITY_CDN_CF_CRED_DIR:-/root}"
    [[ -n "$domain" ]] || return 1
    printf '%s/.cloudflare-%s.ini' "${dir%/}" "$domain"
}

reality_cdn_le_live_dir() {
    local domain="${1:-}" dir="${REALITY_CDN_LE_LIVE_DIR:-/etc/letsencrypt/live}"
    [[ -n "$domain" ]] || return 1
    printf '%s/%s' "${dir%/}" "$domain"
}

reality_cdn_cleanup_cert_resources() {
    local domain="$1" clean_cert_dir="${2:-0}" clean_cred="${3:-0}" clean_hook="${4:-0}" clean_cron="${5:-0}" clean_le="${6:-0}" snapshot_dir="${7:-}"
    [[ -n "$domain" ]] || return 0
    validate_domain "$domain" || return 1
    local cert_prefix="${CERT_PATH_PREFIX%/}" cert_dir="" cred_path="" hook_path="${CERT_HOOKS_DIR}/renew-${domain}.sh" le_dir=""
    [[ -n "$cert_prefix" && "$cert_prefix" != "/" ]] && cert_dir="${cert_prefix}/${domain}"
    cred_path="$(reality_cdn_cf_cred_path "$domain")" || cred_path=""
    le_dir="$(reality_cdn_le_live_dir "$domain")" || le_dir=""

    if [[ "$clean_cron" -eq 1 ]]; then
        if [[ -n "$snapshot_dir" && -f "$snapshot_dir/crontab" ]] && command_exists crontab; then
            crontab "$snapshot_dir/crontab" 2>/dev/null || cron_remove_job "CertRenew_${domain}" 2>/dev/null || true
        else
            cron_remove_job "CertRenew_${domain}" 2>/dev/null || true
        fi
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/hook" && -n "$hook_path" ]]; then
        mkdir -p "$(dirname "$hook_path")" 2>/dev/null || true
        rm -f "$hook_path" 2>/dev/null || true
        cp -a "$snapshot_dir/hook" "$hook_path" 2>/dev/null || true
    elif [[ "$clean_hook" -eq 1 ]]; then
        rm -f "$hook_path" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/cf-cred" && -n "$cred_path" ]]; then
        mkdir -p "$(dirname "$cred_path")" 2>/dev/null || true
        rm -f "$cred_path" 2>/dev/null || true
        cp -a "$snapshot_dir/cf-cred" "$cred_path" 2>/dev/null || true
    elif [[ "$clean_cred" -eq 1 && -n "$cred_path" ]]; then
        rm -f "$cred_path" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/cert-dir" && -n "$cert_dir" ]]; then
        rm -rf "$cert_dir" 2>/dev/null || true
        mkdir -p "$(dirname "$cert_dir")" 2>/dev/null || true
        cp -a "$snapshot_dir/cert-dir" "$cert_dir" 2>/dev/null || true
    elif [[ "$clean_cert_dir" -eq 1 && -n "$cert_dir" ]]; then
        rm -rf "$cert_dir" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/le-live" && -n "$le_dir" ]]; then
        rm -rf "$le_dir" 2>/dev/null || true
        mkdir -p "$(dirname "$le_dir")" 2>/dev/null || true
        cp -a "$snapshot_dir/le-live" "$le_dir" 2>/dev/null || true
    elif [[ "$clean_le" -eq 1 && -n "$le_dir" ]]; then
        command_exists certbot && certbot delete --cert-name "$domain" --non-interactive 2>/dev/null || true
        rm -rf "$le_dir" 2>/dev/null || true
    fi
    [[ -n "$snapshot_dir" ]] && rm -rf -- "$snapshot_dir" 2>/dev/null || true
}

reality_cdn_remove_nginx_conf() {
    local domain="$1" site legacy_av legacy_en f
    [[ -n "$domain" ]] || return 0
    site="$(reality_cdn_nginx_site_name "$domain")"
    rm -f "/etc/nginx/sites-enabled/${site}.conf" "/etc/nginx/sites-available/${site}.conf"
    # 兼容旧版本曾使用 ${domain}.conf 的 CDN 回源站点；只删除带 CDN 生成标记的文件，
    # 避免误删 Web 菜单托管的同名站点。
    legacy_av="/etc/nginx/sites-available/${domain}.conf"
    legacy_en="/etc/nginx/sites-enabled/${domain}.conf"
    for f in "$legacy_en" "$legacy_av"; do
        [[ -f "$f" ]] || continue
        if grep -q "CDN 回源站点 (VLESS+WS+TLS) for ${domain}" "$f" 2>/dev/null; then
            rm -f "$f"
        fi
    done
}

reality_cdn_restore_state_snapshot() {
    local had_state="${1:-0}" state_snapshot="${2:-}"
    if [[ "$had_state" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$state_snapshot" || return 1
    else
        rm -f "$REALITY_CDN_STATE_FILE"
    fi
}

reality_cdn_reapply_current_singbox() {
    reality_load_state || return 1
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_SHORT_ID:-}" ]] || return 1
    local rollback_config
    rollback_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    reality_apply_singbox_config "$rollback_config"
}

reality_cdn_install_rollback() {
    local had_state="${1:-0}" state_snapshot="${2:-}" cdn_domain="${3:-}" nginx_deployed="${4:-0}" reapply_singbox="${5:-0}"
    local had_link="${6:-0}" link_snapshot="${7-}" had_client_json="${8:-0}" client_json_snapshot="${9-}"
    local clean_cert_dir="${10:-0}" clean_cred="${11:-0}" clean_hook="${12:-0}" clean_cron="${13:-0}" clean_le="${14:-0}" cert_snapshot_dir="${15:-}"
    if ! reality_cdn_restore_state_snapshot "$had_state" "$state_snapshot"; then
        print_warn "恢复安装前 CDN state 失败，请手动检查 ${REALITY_CDN_STATE_FILE}"
    fi
    if [[ "$had_link" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_LINK_FILE" "$link_snapshot" || print_warn "恢复旧 CDN 链接产物失败，请手动检查 ${REALITY_CDN_LINK_FILE}"
    else
        rm -f "$REALITY_CDN_LINK_FILE"
    fi
    if [[ "$had_client_json" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_CLIENT_JSON" "$client_json_snapshot" || print_warn "恢复旧 CDN JSON 产物失败，请手动检查 ${REALITY_CDN_CLIENT_JSON}"
    else
        rm -f "$REALITY_CDN_CLIENT_JSON"
    fi
    if [[ "$nginx_deployed" -eq 1 && -n "$cdn_domain" ]]; then
        local restored_old_nginx=0 old_nginx_conf old_cert_dir
        if [[ "$had_state" -eq 1 ]] && reality_cdn_load_state 2>/dev/null && [[ "${REALITY_CDN_DOMAIN:-}" == "$cdn_domain" ]]; then
            old_cert_dir="${CERT_PATH_PREFIX}/${REALITY_CDN_DOMAIN}"
            if old_nginx_conf=$(reality_cdn_render_nginx_conf "$REALITY_CDN_DOMAIN" "${REALITY_CDN_ORIGIN_PORT:-8443}" "$REALITY_CDN_WS_PATH" "$REALITY_CDN_INNER_PORT" "$old_cert_dir") \
                && _nginx_deploy_conf "$(reality_cdn_nginx_site_name "$REALITY_CDN_DOMAIN")" "$old_nginx_conf"; then
                restored_old_nginx=1
            else
                print_warn "恢复旧 CDN nginx 回源站失败，请手动检查 ${cdn_domain}"
            fi
        fi
        if [[ "$restored_old_nginx" -ne 1 ]]; then
            reality_cdn_remove_nginx_conf "$cdn_domain"
            if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
        fi
    fi
    if [[ "$reapply_singbox" -eq 1 ]]; then
        reality_cdn_reapply_current_singbox >/dev/null 2>&1 || print_warn "回滚后重载 sing-box 失败，请手动检查 ${REALITY_SINGBOX_CONFIG}"
    fi
    reality_cdn_cleanup_cert_resources "$cdn_domain" "$clean_cert_dir" "$clean_cred" "$clean_hook" "$clean_cron" "$clean_le" "$cert_snapshot_dir"
}

# 渲染 CDN 回源 nginx 站点：TLS 终止 + 隐秘 WS path 反代到内部端口；其余路径 444 断开。
reality_cdn_render_nginx_conf() {
    local domain="$1" origin_port="$2" ws_path="$3" inner_port="$4" cert_dir="$5"
    validate_domain "$domain" || return 1
    validate_port "$origin_port" || return 1
    validate_port "$inner_port" || return 1
    reality_validate_ws_path "$ws_path" || return 1
    cat <<EOF
# CDN 回源站点 (VLESS+WS+TLS) for ${domain}
# Generated by ${SCRIPT_NAME} ${VERSION}
# CF 橙云 Full(strict) 回源到本机 ${origin_port}；仅隐秘 path 反代到 sing-box WS 入站，其余 444。
server {
    # WebSocket 反代必须走 HTTP/1.1(Upgrade 机制),不能启用 HTTP/2,否则 CF 回源协商 h2 时 WS 握手 400。
    # 故 CDN 回源站用纯 ssl listen(不接 http2);web 模块的 _nginx_tls_http2_block 是普通 HTTPS 反代,不受影响。
    listen ${origin_port} ssl;
    listen [::]:${origin_port} ssl;
    server_name ${domain};
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    location ${ws_path} {
        proxy_pass http://127.0.0.1:${inner_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    location / {
        return 444;
    }
}
EOF
}

# 同步 cdn 域名为 CF 橙云 A/AAAA（proxied=true）。复用通用 DNS upsert。
reality_cdn_sync_dns_orange() {
    local domain="$1" token="$2" zone_id ipv4 ipv6
    [[ -n "$domain" && -n "$token" ]] || return 1
    command_exists jq || install_package "jq" "silent" || return 1
    _cf_verify_token "$token" || return 1
    zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || { print_error "无法获取 Zone ID: $domain"; return 1; }
    reality_detect_ips
    ipv4="$REALITY_IPV4"; ipv6="$REALITY_IPV6"
    [[ -n "$ipv4" || -n "$ipv6" ]] || { print_error "未检测到本机公网 IP，无法同步 CDN 域名"; return 1; }
    if [[ -n "$ipv4" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "A" "$ipv4" "true" || return 1
    else
        reality_cf_delete_dns_type "$domain" "$token" "A" "$zone_id" || { print_error "清理 ${domain} 的旧 A 记录失败"; return 1; }
    fi
    if [[ -n "$ipv6" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "AAAA" "$ipv6" "true" || return 1
    else
        reality_cf_delete_dns_type "$domain" "$token" "AAAA" "$zone_id" || { print_error "清理 ${domain} 的旧 AAAA 记录失败"; return 1; }
    fi
    log_action "CDN orange-cloud DNS synced: $domain proxied=true"
}

# 建/更新 CF Origin Rule：把 cdn 域名的回源端口改写到 origin_port（解决与 Reality 抢 443）。
reality_cdn_apply_origin_rule() {
    local domain="$1" token="$2" origin_port="$3" zone_id existing existing_rules filtered new_rule final err
    command_exists jq || install_package "jq" "silent" || return 1
    validate_domain "$domain" || { print_error "Origin Rule: 域名无效"; return 1; }
    validate_port "$origin_port" || { print_error "Origin Rule: 回源端口无效"; return 1; }
    zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || { print_error "Origin Rule: 无法获取 Zone ID"; return 1; }
    if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
        print_error "Origin Rule: 读取现有规则失败，已中止以避免覆盖既有规则。"
        return 1
    fi
    if [[ -n "$existing" ]]; then
        existing_rules=$(jq '.result.rules // []' <<< "$existing" 2>/dev/null) || {
            print_error "Origin Rule: 解析现有规则失败，已中止。"
            return 1
        }
    else
        existing_rules="[]"
    fi
    filtered=$(jq --arg d "$domain" '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]' <<< "$existing_rules") || {
        print_error "Origin Rule: 过滤现有规则失败，已中止。"
        return 1
    }
    new_rule=$(jq -n --arg expr "http.host eq \"${domain}\"" --arg desc "Script-CDN-${domain}-${origin_port}" --argjson port "$origin_port" \
        '{action:"route", action_parameters:{origin:{port:$port}}, expression:$expr, description:$desc, enabled:true}') || {
        print_error "Origin Rule: 构造新规则失败。"
        return 1
    }
    final=$(jq --argjson new "$new_rule" '. + [$new]' <<< "$filtered") || {
        print_error "Origin Rule: 合并规则失败。"
        return 1
    }
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final"); then
        print_error "Origin Rule 写入失败: $err"; return 1
    fi
    log_action "CDN origin rule set: $domain -> origin port $origin_port"
}

reality_build_vless_link() {
    local uuid="$1" node="$2" port="$3" sni="$4" public_key="$5" short_id="$6" name="${7:-singbox-reality}" fp="${8:-}" flow="${9:-xtls-rprx-vision}"
    local encoded_name node_uri
    encoded_name=$(reality_urlencode "$name")
    node_uri=$(reality_uri_host "$node")
    # fp 未显式传入时回退 chrome（保持旧调用/旧节点链接不变）；经 sanitize 防非法值。
    fp=$(reality_sanitize_fingerprint "${fp:-chrome}")
    flow="${flow:-xtls-rprx-vision}"
    printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp&flow=%s#%s\n' \
        "$uuid" "$node_uri" "$port" "$sni" "$fp" "$public_key" "$short_id" "$flow" "$encoded_name"
}

reality_parse_vless_link() {
    local link="$1" body user hostport query param key value host port
    [[ "$link" == vless://* ]] || return 1
    body="${link#vless://}"
    user="${body%@*}"
    body="${body#*@}"
    hostport="${body%%\?*}"
    query="${body#*\?}"
    query="${query%%#*}"
    REALITY_UUID="$user"
    if [[ "$hostport" == \[*\]:* ]]; then
        host="${hostport#\[}"
        host="${host%%\]*}"
        port="${hostport##*\]:}"
    else
        host="${hostport%:*}"
        port="${hostport##*:}"
    fi
    REALITY_NODE_DOMAIN="$host"
    REALITY_PORT="$port"
    # 关键：先把可选字段清空，再逐项解析。否则调用前若 reality_load_state 已把本机
    # 落地身份写进这些全局，链接里缺失的参数会"继承"本机旧值 —— 缺 sni 会用本机 sni
    # 通过非空守卫（烘进错误 SNI → 下游握手不匹配、静默不通）；缺 fp 会用本机指纹（破坏
    # 每节点 fp 分散设计）。清空后，缺失即为空，末尾的非空守卫才能真正拦住残缺链接。
    REALITY_SNI=""; REALITY_PUBLIC_KEY=""; REALITY_SHORT_ID=""; REALITY_FLOW=""; REALITY_FINGERPRINT=""
    while IFS= read -r param; do
        key="${param%%=*}"
        value="${param#*=}"
        case "$key" in
            sni|serverName) REALITY_SNI="$value" ;;
            pbk|publicKey) REALITY_PUBLIC_KEY="$value" ;;
            sid|shortId) REALITY_SHORT_ID="$value" ;;
            flow) REALITY_FLOW="$value" ;;
            fp|fingerprint) REALITY_FINGERPRINT="$value" ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]
}

reality_cf_dns_payload() {
    local type="$1" name="$2" content="$3"
    type=$(reality_json_escape "$type")
    name=$(reality_json_escape "$name")
    content=$(reality_json_escape "$content")
    printf '{"type":"%s","name":"%s","content":"%s","ttl":1,"proxied":false}\n' "$type" "$name" "$content"
}

reality_render_realm_config() {
    local listen_port="$1" target_host="$2" target_port="$3"
    # 经 reality_detect_listen_host 解析，以处理 split 哨兵值（直接读 REALITY_LISTEN_HOST 会把 "split" 当 bind 地址）。
    local listen_host; listen_host="$(reality_detect_listen_host)"
    cat <<EOF
log.level = "warn"

[[endpoints]]
listen = "$(reality_listen_endpoint "$listen_host" "$listen_port")"
remote = "$(reality_listen_endpoint "$target_host" "$target_port")"
EOF
}

reality_resolve_public_a() {
    local domain="$1" resp ip
    [[ -n "$domain" ]] || return 1
    command_exists curl || return 1
    resp=$(curl -fsS --max-time 8 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${domain}&type=A" 2>/dev/null) || return 1
    if command_exists _extract_ipv4_from_text; then
        ip=$(_extract_ipv4_from_text "$resp") || return 1
    else
        ip=$(printf '%s' "$resp" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
        [[ -n "$ip" ]] || return 1
    fi
    printf '%s\n' "$ip"
}

reality_resolve_public_aaaa() {
    local domain="$1" resp ip
    [[ -n "$domain" ]] || return 1
    command_exists curl || return 1
    resp=$(curl -fsS --max-time 8 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${domain}&type=AAAA" 2>/dev/null) || return 1
    ip=$(printf '%s' "$resp" | grep -Eo '"data":"[0-9a-fA-F:]+"' | head -n 1 | sed -E 's/"data":"([0-9a-fA-F:]+)"/\1/')
    [[ -n "$ip" && "$ip" == *:* ]] || return 1
    printf '%s\n' "$ip"
}

reality_local_client_self_test() {
    reality_load_state || return 1
    command_exists sing-box || { print_warn "sing-box 不存在，跳过本机协议自测"; return 1; }
    command_exists curl || { print_warn "curl 不存在，跳过本机协议自测"; return 1; }
    local test_port="${REALITY_SELFTEST_PORT:-19090}" tmp_dir cfg log curl_log pid_file pid i
    local old_umask
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-client-test.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    cfg="$tmp_dir/client.json"
    log="$tmp_dir/sing-box.log"
    curl_log="$tmp_dir/curl.log"
    pid_file="$tmp_dir/sing-box.pid"
    local st_fp; st_fp=$(reality_effective_fingerprint)
    old_umask=$(umask)
    umask 077
    if ! cat > "$cfg" <<EOF
{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"self-test","server":"127.0.0.1","server_port":${REALITY_PORT},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"${st_fp}"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}],"route":{"final":"self-test"}}
EOF
    then
        umask "$old_umask"
        rm -rf "$tmp_dir"
        return 1
    fi
    umask "$old_umask"
    ( sing-box run -c "$cfg" > "$log" 2>&1 & echo $! > "$pid_file" )
    pid=$(cat "$pid_file" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if curl -x "socks5h://127.0.0.1:${test_port}" -fsS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace >"$curl_log" 2>&1; then
        print_success "本机协议自测通过: sing-box client -> 127.0.0.1:${REALITY_PORT} -> 外网"
        [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        return 0
    fi
    print_warn "本机协议自测失败，最近日志:"
    tail -n 20 "$curl_log" 2>/dev/null || true
    sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
    return 1
}

reality_require_supported_os() {
    [[ "$PLATFORM" != "openwrt" ]] || { print_error "Reality 节点模块暂不支持 OpenWrt"; return 1; }
    is_systemd || { print_error "Reality 节点模块需要 systemd"; return 1; }
    local os_id="" ver=""
    if [[ -f /etc/os-release ]]; then
        os_id=$(grep '^ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
        ver=$(grep '^VERSION_ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
    fi
    case "$os_id:$ver" in
        debian:12|debian:13|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;;
        *) print_warn "未在支持列表中的系统: ${os_id:-unknown} ${ver:-unknown}，将尝试继续" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64|aarch64|arm64) return 0 ;;
        *) print_error "仅支持 amd64/arm64 架构"; return 1 ;;
    esac
}

_reality_abs_system_path() {
    local path="${1:-}"
    [[ -n "$path" && "$path" == /* ]] || return 1
    [[ "$path" != *[[:space:]]* ]]
}

_reality_sagernet_keyring_path() {
    printf '%s' "${REALITY_SAGERNET_KEYRING_FILE:-/etc/apt/keyrings/sagernet.asc}"
}

_reality_sagernet_source_path() {
    printf '%s' "${REALITY_SAGERNET_SOURCE_FILE:-/etc/apt/sources.list.d/sagernet.sources}"
}

_reality_realm_service_path() {
    printf '%s' "${REALITY_REALM_SERVICE_FILE:-/etc/systemd/system/realm.service}"
}

_reality_realm_bin_path() {
    if [[ -n "${REALITY_REALM_BIN:-}" ]]; then
        printf '%s' "$REALITY_REALM_BIN"
        return 0
    fi
    local bin
    bin="$(type -P realm 2>/dev/null || true)"
    printf '%s' "${bin:-/usr/local/bin/realm}"
}

_reality_realm_config_path() {
    printf '%s' "${REALITY_REALM_CONFIG:-/etc/realm/config.toml}"
}

_reality_render_sagernet_source() {
    local keyring="$1"
    _reality_abs_system_path "$keyring" || return 1
    cat <<EOF
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: $keyring
EOF
}

_reality_install_sagernet_keyring() {
    local keyring dir tmp_key
    command_exists curl || return 1
    keyring="$(_reality_sagernet_keyring_path)"
    _reality_abs_system_path "$keyring" || return 1
    dir="$(dirname "$keyring")"
    mkdir -p "$dir" || return 1
    tmp_key=$(mktemp "${dir}/.tmp.server-manage.sagernet-key.XXXXXX") || return 1
    _tmp_register "$tmp_key"
    if ! curl -fsSL https://sing-box.app/gpg.key -o "$tmp_key"; then
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    fi
    chmod 644 "$tmp_key" 2>/dev/null || true
    chown root:root "$tmp_key" 2>/dev/null || true
    if ! mv "$tmp_key" "$keyring"; then
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    fi
    _tmp_unregister "$tmp_key"
    return 0
}

_reality_write_sagernet_source() {
    local keyring source_file content
    keyring="$(_reality_sagernet_keyring_path)"
    source_file="$(_reality_sagernet_source_path)"
    _reality_abs_system_path "$source_file" || return 1
    content="$(_reality_render_sagernet_source "$keyring")" || return 1
    write_file_atomic "$source_file" "$content" || return 1
    chmod 644 "$source_file" 2>/dev/null || true
}

_reality_render_realm_service_unit() {
    local realm_bin="${1:-$(_reality_realm_bin_path)}" realm_config="${2:-$(_reality_realm_config_path)}"
    _reality_abs_system_path "$realm_bin" || return 1
    _reality_abs_system_path "$realm_config" || return 1
    cat <<EOF
[Unit]
Description=Realm TCP Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$realm_bin -c $realm_config
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

_reality_install_realm_service_unit() {
    local service_file content
    service_file="$(_reality_realm_service_path)"
    _reality_abs_system_path "$service_file" || return 1
    content="$(_reality_render_realm_service_unit)" || return 1
    write_file_atomic "$service_file" "$content" || return 1
    chmod 644 "$service_file" 2>/dev/null || true
}

_reality_install_realm_binary_file() {
    local src="$1" target="${2:-$(_reality_realm_bin_path)}" dir tmp_bin
    [[ -f "$src" ]] || return 1
    _reality_abs_system_path "$target" || return 1
    dir="$(dirname "$target")"
    mkdir -p "$dir" || return 1
    tmp_bin=$(mktemp "${dir}/.tmp.server-manage.realm.XXXXXX") || return 1
    _tmp_register "$tmp_bin"
    if ! cp "$src" "$tmp_bin"; then
        rm -f "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    fi
    chmod 0755 "$tmp_bin" 2>/dev/null || true
    chown root:root "$tmp_bin" 2>/dev/null || true
    if ! mv "$tmp_bin" "$target"; then
        rm -f "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    fi
    _tmp_unregister "$tmp_bin"
    return 0
}

reality_install_singbox_official() {
    reality_require_supported_os || return 1
    install_package "curl" "silent" || return 1
    install_package "ca-certificates" "silent" || return 1
    install_package "gnupg" "silent" || return 1
    install_package "openssl" "silent" || return 1
    install_package "jq" "silent" || true
    if ! command_exists sing-box; then
        print_info "添加 sing-box 官方 APT 源..."
        _reality_install_sagernet_keyring || return 1
        _reality_write_sagernet_source || return 1
        APT_UPDATED=0
        update_apt_cache
        DEBIAN_FRONTEND=noninteractive apt-get install -y sing-box >/dev/null || return 1
    fi
    command_exists sing-box || { print_error "sing-box 安装失败"; return 1; }
}

reality_verify_sni() {
    local domain="$1"
    validate_domain "$domain" || return 1
    command_exists openssl || install_package "openssl" "silent" || return 1
    local timeout_cmd="" tmp_dir old_umask rc
    command_exists timeout && timeout_cmd="timeout 12"
    reality_cleanup_sni_check_log
    old_umask=$(umask)
    umask 077
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-sni-check.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    REALITY_SNI_CHECK_DIR="$tmp_dir"
    REALITY_SNI_CHECK_LOG="$tmp_dir/sni-check.log"
    : > "$REALITY_SNI_CHECK_LOG" || { reality_cleanup_sni_check_log; return 1; }
    chmod 600 "$REALITY_SNI_CHECK_LOG" 2>/dev/null || true
    $timeout_cmd openssl s_client -connect "${domain}:443" -servername "$domain" -verify_hostname "$domain" -verify_return_error -brief </dev/null >"$REALITY_SNI_CHECK_LOG" 2>&1
}

reality_cleanup_sni_check_log() {
    if [[ -n "${REALITY_SNI_CHECK_DIR:-}" ]]; then
        rm -rf -- "$REALITY_SNI_CHECK_DIR" 2>/dev/null || true
    elif [[ -n "${REALITY_SNI_CHECK_LOG:-}" ]]; then
        rm -f -- "$REALITY_SNI_CHECK_LOG" 2>/dev/null || true
    fi
    REALITY_SNI_CHECK_DIR=""
    REALITY_SNI_CHECK_LOG=""
}

reality_pick_sni_candidates() {
    local count="${1:-12}"
    if command_exists shuf; then
        printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | shuf | head -n "$count"
    else
        printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | awk 'BEGIN{srand()} {print rand() "\t" $0}' | sort -n | cut -f2- | head -n "$count"
    fi
}

reality_prompt_sni_legacy() {
    local choice sni i shown=()
    while true; do
        mapfile -t shown < <(reality_pick_sni_candidates 12)
        echo -e "${C_CYAN}REALITY SNI/handshake 目标:${C_RESET}" >&2
        echo "  这个域名不是你的节点连接域名，而是 REALITY 握手时模拟访问的 HTTPS 成品网站或自建网站。" >&2
        echo "  下面随机提供一批较小众的成品网站候选；脚本会对所选域名进行校验 TLS/SAN 和 443 连通性测试。" >&2
        echo "  请选择一个 SNI 候选编号，或输入 c 自定义 SNI；这里不是节点连接域名。" >&2
        echo "  如果你使用自建网站，请确保它是正常 HTTPS 站点，且不要填写 Cloudflare 灰云节点域名本身。" >&2
        i=1
        for sni in "${shown[@]}"; do echo "  ${i}. ${sni}" >&2; ((i++)); done
        echo "  r. 换一批候选域名" >&2
        echo "  c. 自定义域名" >&2
        read -e -r -p "请选择一个 SNI 候选编号，或输入 c 自定义 [c]: " choice
        choice=${choice:-c}
        if [[ "${choice,,}" == "r" ]]; then
            continue
        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#shown[@]} ]]; then
            sni="${shown[$((choice-1))]}"
        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "SNI 域名: " sni
        else
            sni="$choice"
        fi
        validate_domain "$sni" || { print_error "域名格式无效" >&2; continue; }
        print_info "校验 TLS/SAN: $sni" >&2
        if reality_verify_sni "$sni"; then
            print_success "SNI 校验通过: $sni" >&2
            reality_cleanup_sni_check_log
            echo "$sni"; return 0
        fi
        print_warn "SNI 校验未通过或网络不可达: $sni" >&2
        tail -n 3 "${REALITY_SNI_CHECK_LOG:-/dev/null}" >&2 2>/dev/null || true
        reality_cleanup_sni_check_log
        confirm "仍然使用该 SNI?" && { echo "$sni"; return 0; }
    done
}

if ! declare -F reality_prompt_sni >/dev/null; then
    reality_prompt_sni() {
        reality_prompt_sni_legacy "$@"
    }
fi

reality_backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    mkdir -p "$REALITY_BACKUP_DIR"
    chmod 700 "$REALITY_BACKUP_DIR" 2>/dev/null || true
    cp -a "$file" "$REALITY_BACKUP_DIR/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
}

reality_write_secure_file() {
    # 原子写入含密钥/UUID/path 的状态文件，避免 “cat > file; chmod 600”
    # 在宽 umask 下出现短暂 0644 暴露窗口。
    local file="$1" content="$2" dir tmp
    dir="$(dirname "$file")"
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" 2>/dev/null || true
    tmp=$(mktemp "${dir}/.tmp.server-manage.reality.XXXXXX") || return 1
    if declare -F _tmp_register >/dev/null 2>&1; then _tmp_register "$tmp"; fi
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$file"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
    return 0
}

reality_apply_singbox_config() {
    local content="$1" target="${2:-$REALITY_SINGBOX_CONFIG}"
    [[ -n "$content" ]] || { print_error "sing-box 配置内容为空"; return 1; }
    command_exists sing-box || { print_error "sing-box 未安装"; return 1; }
    mkdir -p "$(dirname "$target")"
    local tmp backup="" had_old=0
    tmp=$(mktemp "$(dirname "$target")/.tmp.server-manage.singbox.XXXXXX") || return 1
    _tmp_register "$tmp"
    printf '%s\n' "$content" > "$tmp" || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true

    if ! sing-box check -c "$tmp" >/dev/null 2>&1; then
        print_error "sing-box 新配置校验失败，已保留原配置。"
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi

    if [[ -f "$target" ]]; then
        backup=$(mktemp "$(dirname "$target")/.bak.server-manage.singbox.XXXXXX") || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
        _tmp_register "$backup"
        cp -a "$target" "$backup" || { rm -f "$tmp" "$backup"; _tmp_unregister "$tmp"; _tmp_unregister "$backup"; return 1; }
        had_old=1
    fi

    if ! mv "$tmp" "$target"; then
        print_error "写入 sing-box 配置失败，已保留原配置。"
        rm -f "$tmp"
        [[ -n "$backup" ]] && rm -f "$backup"
        _tmp_unregister "$tmp"
        [[ -n "$backup" ]] && _tmp_unregister "$backup"
        return 1
    fi
    _tmp_unregister "$tmp"

    if ! systemctl restart sing-box >/dev/null 2>&1; then
        print_error "sing-box 重启失败，正在回滚原配置。"
        if [[ $had_old -eq 1 && -n "$backup" ]]; then
            mv "$backup" "$target" 2>/dev/null || true
            _tmp_unregister "$backup"
        else
            rm -f "$target"
        fi
        systemctl restart sing-box >/dev/null 2>&1 || true
        return 1
    fi

    [[ -n "$backup" ]] && rm -f "$backup"
    [[ -n "$backup" ]] && _tmp_unregister "$backup"
    return 0
}

reality_state_quote() {
    local s="${1:-}"
    s=${s//$'\r'/ }
    s=${s//$'\n'/ }
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//\$/\\\$}
    s=${s//\`/\\\`}
    printf '"%s"' "$s"
}

reality_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    local content
    content=$(cat <<EOF
REALITY_ROLE=$(reality_state_quote "${REALITY_ROLE:-}")
REALITY_NODE_NAME=$(reality_state_quote "${REALITY_NODE_NAME:-}")
REALITY_NODE_DOMAIN=$(reality_state_quote "${REALITY_NODE_DOMAIN:-}")
REALITY_DNS_MODE=$(reality_state_quote "${REALITY_DNS_MODE:-}")
REALITY_NODE_DOMAIN_V4=$(reality_state_quote "${REALITY_NODE_DOMAIN_V4:-}")
REALITY_NODE_DOMAIN_V6=$(reality_state_quote "${REALITY_NODE_DOMAIN_V6:-}")
REALITY_NODE_NAME_V4=$(reality_state_quote "${REALITY_NODE_NAME_V4:-}")
REALITY_NODE_NAME_V6=$(reality_state_quote "${REALITY_NODE_NAME_V6:-}")
REALITY_SNI=$(reality_state_quote "${REALITY_SNI:-}")
REALITY_PORT=$(reality_state_quote "${REALITY_PORT:-}")
REALITY_PORT_V6=$(reality_state_quote "${REALITY_PORT_V6:-}")
REALITY_UUID=$(reality_state_quote "${REALITY_UUID:-}")
REALITY_PRIVATE_KEY=$(reality_state_quote "${REALITY_PRIVATE_KEY:-}")
REALITY_PUBLIC_KEY=$(reality_state_quote "${REALITY_PUBLIC_KEY:-}")
REALITY_SHORT_ID=$(reality_state_quote "${REALITY_SHORT_ID:-}")
REALITY_FINGERPRINT=$(reality_state_quote "${REALITY_FINGERPRINT:-}")
REALITY_LISTEN_HOST=$(reality_state_quote "${REALITY_LISTEN_HOST:-}")
REALITY_LISTEN_HOST_V4=$(reality_state_quote "${REALITY_LISTEN_HOST_V4:-}")
REALITY_LISTEN_HOST_V6=$(reality_state_quote "${REALITY_LISTEN_HOST_V6:-}")
REALITY_RELAY_DOMAIN=$(reality_state_quote "${REALITY_RELAY_DOMAIN:-}")
REALITY_RELAY_PORT=$(reality_state_quote "${REALITY_RELAY_PORT:-}")
REALITY_RELAY_TARGET_HOST=$(reality_state_quote "${REALITY_RELAY_TARGET_HOST:-}")
REALITY_RELAY_TARGET_PORT=$(reality_state_quote "${REALITY_RELAY_TARGET_PORT:-}")
EOF
)
    reality_write_secure_file "$REALITY_STATE_FILE" "$content"
}

reality_load_state() {
    [[ -f "$REALITY_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_STATE_FILE" || return 1
    source "$REALITY_STATE_FILE"
}

reality_validate_node_name() {
    local name="$1"
    [[ -n "$name" && ${#name} -le 64 ]] || return 1
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._[:space:]-]{0,63}$ ]]
}

reality_default_node_name() {
    local host="${REALITY_RELAY_DOMAIN:-${REALITY_NODE_DOMAIN:-singbox}}"
    host="${host%%.*}"
    [[ -n "$host" ]] || host="singbox"
    printf '%s-reality' "$host"
}

reality_effective_node_name() {
    if [[ -n "${REALITY_NODE_NAME:-}" ]]; then
        printf '%s' "$REALITY_NODE_NAME"
    else
        reality_default_node_name
    fi
}

reality_normalize_dns_mode() {
    local mode="${1:-auto}"
    mode="${mode,,}"
    case "$mode" in
        auto|dual|both|same|same-domain|"") echo "auto" ;;
        ipv4|ip4|v4|4) echo "ipv4" ;;
        ipv6|ip6|v6|6) echo "ipv6" ;;
        split|dual-node|dual-nodes|split-dual|v4v6|ipv4-ipv6) echo "split" ;;
        *) return 1 ;;
    esac
}

reality_dns_mode_label() {
    case "${1:-auto}" in
        ipv4) echo "IPv4-only 单节点（仅 A 记录）" ;;
        ipv6) echo "IPv6-only 单节点（仅 AAAA 记录）" ;;
        split) echo "IPv4+IPv6 双节点（A-only + AAAA-only，独立链接，优先共用 443）" ;;
        *) echo "自动/双栈单节点（同域名 A/AAAA）" ;;
    esac
}

reality_node_name_with_suffix() {
    local base="${1:-singbox-reality}" suffix="$2" max
    max=$((64 - ${#suffix}))
    (( max < 1 )) && max=1
    printf '%s%s' "${base:0:max}" "$suffix"
}

reality_prompt_node_name() {
    local default_name="${1:-}" name=""
    [[ -n "$default_name" ]] || default_name="$(reality_default_node_name)"
    echo -e "${C_CYAN}节点名称/备注说明:${C_RESET}" >&2
    echo "  这个名称只用于本机状态展示、vless:// 链接 #备注、sing-box 客户端 tag，方便区分几十台 VPS。" >&2
    echo "  不影响 Reality 协议参数，不会写入 Cloudflare DNS。" >&2
    echo "  建议使用英文/数字/短横线，示例: us-nat-01、jp-relay-02。" >&2
    while true; do
        read -e -r -p "节点名称/备注 [${default_name}]: " name
        name="${name:-$default_name}"
        if reality_validate_node_name "$name"; then
            printf '%s' "$name"
            return 0
        fi
        print_error "节点名称无效：请使用 1-64 位英文、数字、空格、点、下划线或短横线" >&2
    done
}

reality_write_one_client_artifact() {
    local link_path="$1" json_path="$2" link_host="$3" link_port="$4" name="$5" json_name
    [[ -n "$link_path" && -n "$json_path" && -n "$link_host" && -n "$link_port" ]] || return 1
    validate_port "$link_port" || return 1
    json_name=$(reality_json_escape "$name")
    local json_host; json_host=$(reality_json_escape "$link_host")
    local json_uuid; json_uuid=$(reality_json_escape "$REALITY_UUID")
    local json_sni; json_sni=$(reality_json_escape "$REALITY_SNI")
    local json_public_key; json_public_key=$(reality_json_escape "$REALITY_PUBLIC_KEY")
    local json_short_id; json_short_id=$(reality_json_escape "$REALITY_SHORT_ID")
    local fp; fp=$(reality_effective_fingerprint)
    local link_content json_content
    link_content="$(reality_build_vless_link "$REALITY_UUID" "$link_host" "$link_port" "$REALITY_SNI" "$REALITY_PUBLIC_KEY" "$REALITY_SHORT_ID" "$name" "$fp")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${link_port},"uuid":"${json_uuid}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}}
EOF
)
    reality_write_secure_file "$link_path" "$link_content" || return 1
    reality_write_secure_file "$json_path" "$json_content" || return 1
}

reality_write_client_artifacts() {
    mkdir -p "$REALITY_CONFIG_DIR"
    local mode="${REALITY_DNS_MODE:-auto}"
    mode=$(reality_normalize_dns_mode "$mode" 2>/dev/null || echo "auto")
    if [[ "$mode" == "split" ]]; then
        local host_v4="${REALITY_NODE_DOMAIN_V4:-$REALITY_NODE_DOMAIN}" host_v6="${REALITY_NODE_DOMAIN_V6:-}"
        local port_v4="${REALITY_PORT}" port_v6="${REALITY_PORT_V6:-}"
        local name_v4="${REALITY_NODE_NAME_V4:-}" name_v6="${REALITY_NODE_NAME_V6:-}"
        [[ -n "$host_v4" && -n "$host_v6" && -n "$port_v4" && -n "$port_v6" ]] || return 1
        [[ -n "$name_v4" ]] || name_v4="$(reality_node_name_with_suffix "$(reality_effective_node_name)" "-ipv4")"
        [[ -n "$name_v6" ]] || name_v6="$(reality_node_name_with_suffix "$(reality_effective_node_name)" "-ipv6")"
        reality_write_one_client_artifact "$REALITY_LINK_FILE_V4" "$REALITY_CLIENT_JSON_V4" "$host_v4" "$port_v4" "$name_v4" || return 1
        reality_write_one_client_artifact "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V6" "$host_v6" "$port_v6" "$name_v6" || return 1
        local combined_links combined_json
        combined_links="$(cat "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6")" || return 1
        combined_json="$(cat "$REALITY_CLIENT_JSON_V4")" || return 1
        reality_write_secure_file "$REALITY_LINK_FILE" "$combined_links" || return 1
        reality_write_secure_file "$REALITY_CLIENT_JSON" "$combined_json" || return 1
        return 0
    fi

    local link_host="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" link_port="${REALITY_RELAY_PORT:-$REALITY_PORT}" name
    [[ -n "$link_host" && -n "$link_port" ]] || return 1
    name="$(reality_effective_node_name)"
    reality_write_one_client_artifact "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" "$link_host" "$link_port" "$name"
    rm -f "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6" 2>/dev/null || true
}

# 本机网卡是否真实绑定了全局公网 IPv4(排除私有/CGNAT/WARP 172.16.0.x/链路本地)。有=返回0。
reality_has_local_public_ipv4() {
    command_exists ip || return 0   # 无 ip 命令无法判断,则不拦,保持原行为
    ip -o -4 addr show scope global 2>/dev/null | awk '
        { for(i=1;i<=NF;i++) if($i=="inet"){ split($(i+1),a,"/"); p=a[1]
            if(p ~ /^10\./)                                 continue
            if(p ~ /^192\.168\./)                           continue
            if(p ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)         continue
            if(p ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./) continue
            if(p ~ /^127\./ || p ~ /^169\.254\./)           continue
            found=1 } }
        END { exit (found?0:1) }'
}

reality_ipv4_is_likely_warp_egress() {
    local ip="${1:-}"
    # Cloudflare WARP 常见 IPv4 出口段。若本机网卡没有公网 IPv4 且探测到这些出口，
    # 不能把它写进 CF 回源 A 记录，否则 CF 会回源到 WARP 出口而不是本机。
    case "$ip" in
        104.28.*|104.29.*) return 0 ;;
    esac
    return 1
}

reality_has_warp_interface() {
    command_exists ip || return 1
    ip -o link show 2>/dev/null | grep -Eiq '(warp|wgcf|cloudflare)'
}

reality_should_clear_detected_ipv4() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || return 1
    reality_has_local_public_ipv4 && return 1
    # 没有本地公网 IPv4 有两种常见情况：
    # 1) IPv6-only + WARP：公网 IPv4 是 WARP 出口，必须清空；
    # 2) OCI/云厂商 1:1 NAT：公网 IPv4 不绑在网卡上，但仍可入站回源，必须保留。
    # 因此只在明确像 WARP 时清空；普通云 NAT IPv4 保留。
    reality_ipv4_is_likely_warp_egress "$ip" && return 0
    reality_has_warp_interface && return 0
    return 1
}

reality_detect_ips() {
    REALITY_IPV4="$(get_public_ipv4 2>/dev/null || true)"
    REALITY_IPV6="$(get_public_ipv6 2>/dev/null || true)"
    [[ -n "$REALITY_IPV6" && "$REALITY_IPV6" != *:* ]] && REALITY_IPV6=""
    # 防 WARP/NAT64 幽灵 IPv4，同时兼容 OCI/云厂商 1:1 NAT 公网 IPv4 不绑定到客机网卡的场景。
    if [[ -n "$REALITY_IPV4" ]] && reality_should_clear_detected_ipv4 "$REALITY_IPV4"; then
        REALITY_IPV4=""
    fi
}

reality_cf_delete_dns_type() {
    local domain="$1" token="$2" type="$3" zone_id="${4:-}" resp id ids=() page=1 per_page=100 total_pages count del_resp
    [[ -z "$domain" || -z "$token" || -z "$type" ]] && return 1
    command_exists jq || install_package "jq" "silent" || return 1
    [[ -n "$zone_id" ]] || zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || return 1
    while true; do
        resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain&per_page=$per_page&page=$page" "$token") || return 1
        _cf_api_ok "$resp" || return 1
        while IFS= read -r id; do
            [[ -n "$id" ]] && ids+=("$id")
        done < <(jq -r '.result[].id // empty' <<< "$resp" 2>/dev/null)
        total_pages=$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)
        count=$(jq -r '.result | length' <<< "$resp" 2>/dev/null)
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
    for id in "${ids[@]}"; do
        [[ -n "$id" ]] || continue
        del_resp=$(_cf_api DELETE "/zones/$zone_id/dns_records/$id" "$token") || return 1
        _cf_api_ok "$del_resp" || return 1
    done
}

reality_sync_cloudflare_dns() {
    local domain="$1" token="$2" mode="${3:-auto}"
    [[ -z "$domain" || -z "$token" ]] && return 1
    mode=$(reality_normalize_dns_mode "$mode" 2>/dev/null || echo "auto")
    reality_detect_ips
    case "$mode" in
        ipv4)
            [[ -n "$REALITY_IPV4" ]] || { print_error "未检测到公网 IPv4，无法同步 IPv4-only 节点"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "$REALITY_IPV4" "" "true" "5" || return 1
            reality_cf_delete_dns_type "$domain" "$token" "AAAA" || { print_error "清理 ${domain} 的 AAAA 记录失败；IPv4-only 节点可能仍被解析到 IPv6"; return 1; }
            ;;
        ipv6)
            [[ -n "$REALITY_IPV6" ]] || { print_error "未检测到公网 IPv6，无法同步 IPv6-only 节点"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "" "$REALITY_IPV6" "true" "5" || return 1
            reality_cf_delete_dns_type "$domain" "$token" "A" || { print_error "清理 ${domain} 的 A 记录失败；IPv6-only 节点可能仍被解析到 IPv4"; return 1; }
            ;;
        *)
            [[ -n "$REALITY_IPV4" || -n "$REALITY_IPV6" ]] || { print_error "未检测到公网 IP"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "$REALITY_IPV4" "$REALITY_IPV6" "true" "5"
            ;;
    esac
}

reality_sync_cloudflare_dns_by_state() {
    local token="$1" mode
    [[ -n "$token" ]] || return 1
    mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    if [[ "$mode" == "split" ]]; then
        [[ -n "${REALITY_NODE_DOMAIN_V4:-}" && -n "${REALITY_NODE_DOMAIN_V6:-}" ]] || { print_error "双节点模式缺少 IPv4/IPv6 域名"; return 1; }
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN_V4" "$token" "ipv4" || return 1
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN_V6" "$token" "ipv6" || return 1
    else
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN" "$token" "$mode"
    fi
}

reality_cf_zone_names_from_json() {
    local json="$1"
    if command_exists jq; then
        jq -r '.result[].name // empty' <<< "$json"
    else
        grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$json" | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
    fi
}

reality_cf_list_zones() {
    local token="$1" resp page=1 per_page=50 all='[]' total_pages count
    [[ -z "$token" ]] && return 1
    if declare -F _cf_list_zones >/dev/null 2>&1; then
        resp=$(_cf_list_zones "$token") || return 1
        _cf_api_ok "$resp" || return 1
        reality_cf_zone_names_from_json "$resp"
        return 0
    fi
    while true; do
        resp=$(_cf_api GET "/zones?per_page=$per_page&page=$page" "$token") || return 1
        _cf_api_ok "$resp" || return 1
        all=$(jq -c --argjson acc "$all" '$acc + (.result // [])' <<< "$resp" 2>/dev/null) || return 1
        total_pages=$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)
        count=$(jq -r '.result | length' <<< "$resp" 2>/dev/null)
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
    resp=$(jq -n --argjson result "$all" '{success:true, errors:[], messages:[], result:$result}') || return 1
    reality_cf_zone_names_from_json "$resp"
}

reality_join_subdomain() {
    local prefix="$1" zone="$2"
    prefix="${prefix#.}"
    prefix="${prefix%.}"
    if [[ "$prefix" == *.* ]]; then
        printf '%s\n' "$prefix"
    else
        printf '%s.%s\n' "$prefix" "$zone"
    fi
}

reality_prompt_domain_with_zones() {
    local purpose="$1" token="$2" default_prefix="${3:-$(hostname)-reality}" zone="" prefix="" zones=() i choice domain
    if [[ -n "$token" ]]; then
        mapfile -t zones < <(reality_cf_list_zones "$token" 2>/dev/null || true)
    fi
    if [[ ${#zones[@]} -gt 0 ]]; then
        echo -e "${C_CYAN}${purpose}域名后缀:${C_RESET}" >&2
        echo "  已通过 Cloudflare API Token 获取到你的域名后缀，请选择一个 zone。" >&2
        i=1
        for zone in "${zones[@]}"; do echo "  ${i}. ${zone}" >&2; ((i++)); done
        while true; do
            read -e -r -p "请选择域名后缀 [1]: " choice
            choice=${choice:-1}
            [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#zones[@]} ]] && { zone="${zones[$((choice-1))]}"; break; }
            print_error "无效选择" >&2
        done
        while true; do
            echo "  只需要填写自定义前缀，脚本会拼接为完整域名并自动创建/更新 Cloudflare 灰云 DNS。" >&2
            read -e -r -p "${purpose}自定义前缀 [${default_prefix}]: " prefix
            prefix=${prefix:-$default_prefix}
            domain=$(reality_join_subdomain "$prefix" "$zone")
            validate_domain "$domain" && { echo "$domain"; return 0; }
            print_error "域名前缀无效" >&2
        done
    fi
    while true; do
        read -e -r -p "${purpose}完整域名(Cloudflare 灰云): " domain
        validate_domain "$domain" && { echo "$domain"; return 0; }
        print_error "域名无效" >&2
    done
}

reality_prompt_cf_token() {
    local token=""
    echo -e "${C_CYAN}Cloudflare 自动 DNS 说明:${C_RESET}" >&2
    echo "  本脚本会使用 Cloudflare API Token 自动创建/更新节点域名 DNS，并强制设置为 DNS only / 灰云。" >&2
    echo "  如果 Token 能读取 zone，后续只需要选择域名后缀并填写自定义前缀。" >&2
    echo "  这不是让你手动去 Cloudflare 添加记录；脚本会自动 upsert A/AAAA 并配置 DDNS。" >&2
    echo "  Token 建议使用最小权限: Zone:Read + DNS:Edit。Token 仅用于本机 DNS/DDNS 配置。" >&2
    read -s -r -p "Cloudflare API Token (留空则跳过自动 DNS/DDNS): " token
    echo "" >&2
    printf '%s' "$token"
}

reality_install_landing() {
    local node_domain="$1" sni="$2" port="$3" cf_token="${4:-}" node_name="${5:-}"
    local dns_mode="${6:-auto}" node_domain_v4="${7:-}" node_domain_v6="${8:-}" port_v6="${9:-}"
    local node_name_v4="${10:-}" node_name_v6="${11:-}"
    dns_mode=$(reality_normalize_dns_mode "$dns_mode") || { print_error "网络/DNS 模式无效"; return 1; }
    validate_domain "$sni" || { print_error "SNI 域名无效"; return 1; }
    validate_port "$port" || { print_error "端口无效"; return 1; }
    reality_warn_sni_risk "$sni"
    reality_warn_port_risk "$port" "Reality"
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    # 443 共存已开时的重装防护：render 会走 loopback 分支（reality_coexist_reality_port 有值即触发），
    # 此时若本次端口非 443，客户端链接会指向一个既不监听、也不被 stream 覆盖的端口 → 静默不可达；
    # 若本次是 split，coexist 分支优先于 split 分支渲染，只出单入站会丢掉 IPv6 节点。故一律拦下。
    if reality_coexist_enabled 2>/dev/null; then
        if [[ "$dns_mode" == "split" ]]; then
            print_error "当前已启用 443 共存模式，暂不支持以 split 双节点模式重装落地机。"
            print_info "请先用菜单「关闭 443 共存模式」再重装，或改用单节点模式。"
            return 1
        fi
        if [[ "$port" != "443" ]]; then
            print_error "当前已启用 443 共存模式，重装落地机的端口必须为 443（对外由 nginx stream 持有）。"
            print_info "本次端口为 ${port}，非 443。请以 443 重装，或先关闭 443 共存模式再用其他端口。"
            return 1
        fi
    fi
    if [[ "$dns_mode" == "split" ]]; then
        node_domain_v4="${node_domain_v4:-$node_domain}"
        validate_domain "$node_domain_v4" || { print_error "IPv4 节点域名无效"; return 1; }
        validate_domain "$node_domain_v6" || { print_error "IPv6 节点域名无效"; return 1; }
        [[ "$node_domain_v4" != "$node_domain_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 域名不能相同"; return 1; }
        validate_port "$port_v6" || { print_error "IPv6 端口无效"; return 1; }
        reality_warn_port_risk "$port_v6" "IPv6 Reality"
        [[ -z "$node_name_v4" ]] || reality_validate_node_name "$node_name_v4" || { print_error "IPv4 节点名称无效"; return 1; }
        [[ -z "$node_name_v6" ]] || reality_validate_node_name "$node_name_v6" || { print_error "IPv6 节点名称无效"; return 1; }
    else
        validate_domain "$node_domain" || { print_error "节点域名无效"; return 1; }
    fi
    reality_load_state || true
    if reality_port_reserved_except_current_landing "$port"; then
        print_error "Reality 端口已被本项目其他功能保留: ${port}"
        return 1
    fi
    if [[ "$dns_mode" == "split" ]]; then
        if reality_port_reserved_except_current_landing "$port_v6"; then
            print_error "IPv6 Reality 端口已被本项目其他功能保留: ${port_v6}"
            return 1
        fi
    fi
    local had_relay=0
    [[ "${REALITY_ROLE:-}" == *"relay"* ]] && had_relay=1
    reality_install_singbox_official || return 1
    REALITY_UUID=$(reality_generate_uuid) || return 1
    local keys
    keys=$(reality_generate_keypair) || { print_error "生成 Reality keypair 失败"; return 1; }
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    # 客户端指纹：重装保留旧节点已定的指纹（reality_load_state 已回读），
    # 全新安装则随机挑一个真实浏览器指纹并持久化（分散全网 fp=chrome 特征）。
    if [[ -z "${REALITY_FINGERPRINT:-}" ]]; then
        REALITY_FINGERPRINT=$(reality_random_fingerprint)
    else
        REALITY_FINGERPRINT=$(reality_sanitize_fingerprint "$REALITY_FINGERPRINT")
    fi
    if [[ "$had_relay" -eq 1 ]]; then
        REALITY_ROLE="landing+relay"
    else
        REALITY_ROLE="landing"
    fi
    REALITY_NODE_NAME="$node_name"
    REALITY_DNS_MODE="$dns_mode"
    REALITY_SNI="$sni"
    REALITY_PORT="$port"
    REALITY_PORT_V6=""
    REALITY_NODE_DOMAIN_V4=""
    REALITY_NODE_DOMAIN_V6=""
    REALITY_NODE_NAME_V4=""
    REALITY_NODE_NAME_V6=""
    REALITY_LISTEN_HOST_V4=""
    REALITY_LISTEN_HOST_V6=""
    if [[ "$dns_mode" == "split" ]]; then
        REALITY_NODE_DOMAIN="$node_domain_v4"
        REALITY_NODE_DOMAIN_V4="$node_domain_v4"
        REALITY_NODE_DOMAIN_V6="$node_domain_v6"
        REALITY_PORT_V6="$port_v6"
        REALITY_NODE_NAME_V4="${node_name_v4:-$(reality_node_name_with_suffix "${node_name:-$(reality_default_node_name)}" "-ipv4")}"
        REALITY_NODE_NAME_V6="${node_name_v6:-$(reality_node_name_with_suffix "${node_name:-$(reality_default_node_name)}" "-ipv6")}"
        REALITY_LISTEN_HOST_V4=""
        REALITY_LISTEN_HOST_V6=""
        reality_prepare_split_listen_hosts "$REALITY_PORT" "$REALITY_PORT_V6" || return 1
    else
        REALITY_NODE_DOMAIN="$node_domain"
        case "$dns_mode" in
            ipv4) REALITY_LISTEN_HOST="0.0.0.0" ;;
            ipv6) REALITY_LISTEN_HOST="::" ;;
            *)
                # 重新探测监听地址：IPv6-only / 双栈机器绑定 ::，纯 IPv4 机器绑定 0.0.0.0。
                # 每次安装都重新探测，使旧节点重装即自愈为正确的绑定地址。
                REALITY_LISTEN_HOST="$(reality_detect_listen_host)"
                ;;
        esac
    fi
    local new_config
    new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    local _fw_rc _fw_need_setup=0 _fw_port
    for _fw_port in "$REALITY_PORT" "${REALITY_PORT_V6:-}"; do
        [[ -n "$_fw_port" ]] || continue
        firewall_apply_reality_port "$_fw_port"
        _fw_rc=$?
        if [[ $_fw_rc -eq 1 ]]; then
            return 1
        elif [[ $_fw_rc -eq 2 ]]; then
            _fw_need_setup=1
        fi
    done
    if [[ $_fw_need_setup -eq 1 ]]; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行 Reality 端口?"; then
            ufw_setup
            for _fw_port in "$REALITY_PORT" "${REALITY_PORT_V6:-}"; do
                [[ -n "$_fw_port" ]] || continue
                firewall_apply_reality_port "$_fw_port" || \
                    print_warn "UFW 仍未生效，请确认云安全组已放行 ${_fw_port}/tcp"
            done
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 Reality 端口: ${REALITY_PORT}${REALITY_PORT_V6:+/${REALITY_PORT_V6}}/tcp"
        fi
    fi
    systemctl enable sing-box >/dev/null || return 1
    reality_apply_singbox_config "$new_config" || return 1
    [[ -n "$cf_token" ]] && reality_sync_cloudflare_dns_by_state "$cf_token"
    reality_write_state
    reality_write_client_artifacts
    print_success "Sing-box Reality 落地机安装完成"
    reality_show_info
}

reality_realm_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) return 1 ;;
    esac
}

reality_select_realm_asset_url() {
    local api="$1" arch="$2" url=""
    url=$(grep -Eo "https://[^\" ]+/realm-${arch}\.tar\.gz" <<< "$api" | head -n 1)
    if [[ -z "$url" ]]; then
        url=$(grep -Eo "https://[^\" ]+/realm-slim-${arch}\.tar\.gz" <<< "$api" | head -n 1)
    fi
    [[ -n "$url" ]] || return 1
    printf '%s\n' "$url"
}

reality_select_realm_checksum_url() {
    local api="$1" asset_url="$2" asset_name checksum_url=""
    asset_name="$(basename "$asset_url")"
    checksum_url=$(grep -Eo "https://[^\" ]+/${asset_name}\.(sha256|sha256sum|sha256.txt)" <<< "$api" | head -n 1)
    if [[ -z "$checksum_url" ]]; then
        checksum_url=$(grep -Eo 'https://[^" ]+/(SHA256SUMS|sha256sums\.txt|checksums\.txt|checksum\.txt)' <<< "$api" | head -n 1)
    fi
    [[ -n "$checksum_url" ]] || return 1
    printf '%s\n' "$checksum_url"
}

reality_verify_sha256_file() {
    local file="$1" checksum_file="$2" asset_name hash line
    asset_name="${3:-$(basename "$file")}"
    command_exists sha256sum || { print_error "缺少 sha256sum，无法校验下载文件"; return 1; }
    line=$(grep -F "$asset_name" "$checksum_file" 2>/dev/null | head -n 1 || true)
    if [[ -n "$line" ]]; then
        hash=$(awk '{print $1}' <<< "$line")
    else
        hash=$(grep -Eo '^[a-fA-F0-9]{64}' "$checksum_file" | head -n 1)
    fi
    [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] || { print_error "无法解析 sha256 校验文件"; return 1; }
    printf '%s  %s\n' "$hash" "$file" | sha256sum -c - >/dev/null
}

reality_find_realm_binary() {
    local dir="$1" bin=""
    bin=$(find "$dir" -type f -name realm -print -quit 2>/dev/null)
    if [[ -z "$bin" ]]; then
        bin=$(find "$dir" -type f \( -name 'realm-*' -o -name 'realm' \) ! -name '*.sha*' ! -name '*.txt' -print 2>/dev/null | sort | head -n 1)
    fi
    [[ -n "$bin" ]] || return 1
    printf '%s\n' "$bin"
}

# 上游 zhboner/realm 发布包不附带任何 sha256/SHA256SUMS 校验文件，
# 因此固定 Realm 版本并内置各架构校验值，既保留"下载后强制 sha256 校验"，
# 又避免"校验文件缺失即拒绝安装"导致中转链路永远装不上。
# 升级版本时需同步更新此处版本号与对应 sha256（来自官方发布包）。
REALITY_REALM_VERSION="${REALITY_REALM_VERSION:-v2.9.4}"

reality_realm_pinned_sha256() {
    case "$1" in
        x86_64-unknown-linux-gnu)  echo "9dec109386b8abc828b452d0d1cecde35b7a2f8cfa93eae757fe9c248ad07ddd" ;;
        aarch64-unknown-linux-gnu) echo "1f7f06e82fe0ea798b5c8e8e32906ee212a7085629a1c5cef9957ca270fcad99" ;;
        *) return 1 ;;
    esac
}

reality_install_realm_binary() {
    command_exists curl || install_package "curl" "silent" || return 1
    command_exists tar || install_package "tar" "silent" || true
    if command_exists realm; then return 0; fi
    local arch expected url tmp bin asset_name old_umask rc
    arch=$(reality_realm_arch) || { print_error "Realm 不支持当前架构"; return 1; }
    expected=$(reality_realm_pinned_sha256 "$arch") || { print_error "无内置 Realm ${arch} 校验值，已拒绝安装"; return 1; }
    asset_name="realm-${arch}.tar.gz"
    url="https://github.com/zhboner/realm/releases/download/${REALITY_REALM_VERSION}/${asset_name}"
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/server-manage-realm.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    chmod 700 "$tmp" 2>/dev/null || true
    curl -fsSL "$url" -o "$tmp/realm.tgz" || { print_error "Realm 发布包下载失败"; rm -rf "$tmp"; return 1; }
    # 用内置校验值生成本地 checksum 文件，复用统一校验 helper（含 sha256sum -c）。
    printf '%s  %s\n' "$expected" "$asset_name" > "$tmp/realm.sha256"
    reality_verify_sha256_file "$tmp/realm.tgz" "$tmp/realm.sha256" "$asset_name" || {
        print_error "Realm 发布包 sha256 校验失败，已拒绝安装"; rm -rf "$tmp"; return 1
    }
    tar -xzf "$tmp/realm.tgz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    bin=$(reality_find_realm_binary "$tmp") || { print_error "Realm 发布包中未找到可安装二进制"; rm -rf "$tmp"; return 1; }
    _reality_install_realm_binary_file "$bin" "$(_reality_realm_bin_path)" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

# ============================================================================
# 多路中转（A 既做落地、又同时给多台落地机 B/C/D… 做 Realm TCP 中转）
# 每条线路独立存储自己的落地 Reality 身份，互不串扰；relays 目录是 realm 配置的
# 唯一真相源。客户端复用本机域名、用不同监听端口区分各条线路。
# ============================================================================

# 列出全部中转线路文件（稳定排序）
reality_relay_route_files() {
    [[ -d "$REALITY_RELAY_DIR" ]] || return 0
    find "$REALITY_RELAY_DIR" -maxdepth 1 -type f -name 'relay-*.conf' 2>/dev/null | sort
}

reality_relay_next_port() {
    local base="${REALITY_RELAY_PORT_BASE:-35101}" max port f start
    validate_port "$base" || base="35101"
    max=$((base - 1))
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        port="$(grep -E '^RLY_LISTEN_PORT=' "$f" 2>/dev/null | head -n1 | sed -E 's/^RLY_LISTEN_PORT=["'\'']?([0-9]+)["'\'']?.*/\1/')"
        validate_port "$port" || continue
        (( port > max )) && max="$port"
    done < <(reality_relay_route_files)
    start=$((max + 1))
    (( start < base )) && start="$base"
    for port in $(seq "$start" 65535); do
        reality_port_reserved "$port" && continue
        reality_port_in_use "$port" && continue
        printf '%s\n' "$port"
        return 0
    done
    return 1
}

# 校验并加载一条线路到 RLY_* 全局；校验失败跳过
reality_relay_load_route() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    validate_conf_file "$file" || { print_warn "中转线路文件校验失败，已跳过: $file"; return 1; }
    RLY_NAME=""; RLY_LISTEN_PORT=""; RLY_CONNECT_HOST=""; RLY_TARGET_HOST=""; RLY_TARGET_PORT=""
    RLY_UUID=""; RLY_SNI=""; RLY_PUBLIC_KEY=""; RLY_SHORT_ID=""; RLY_FLOW=""; RLY_FINGERPRINT=""
    # shellcheck disable=SC1090
    source "$file"
}

reality_host_resolves() {
    local host="$1"
    [[ -n "$host" ]] || return 1
    validate_ip "$host" 2>/dev/null && return 0
    [[ "$host" == *:* ]] && return 0
    if command_exists getent; then
        getent ahosts "$host" >/dev/null 2>&1 && return 0
        return 1
    fi
    if command_exists python3; then
        python3 - "$host" <<'PY' >/dev/null 2>&1
import socket
import sys
socket.getaddrinfo(sys.argv[1], None)
PY
        return $?
    fi
    return 2
}

reality_tcp_connect_check() {
    local host="$1" port="$2" timeout_s="${3:-5}"
    [[ -n "$host" ]] && validate_port "$port" || return 1
    if command_exists nc; then
        if command_exists timeout; then
            timeout "$((timeout_s + 2))" nc -z -w "$timeout_s" "$host" "$port" >/dev/null 2>&1
        else
            nc -z -w "$timeout_s" "$host" "$port" >/dev/null 2>&1
        fi
        return $?
    fi
    if command_exists python3; then
        python3 - "$host" "$port" "$timeout_s" <<'PY' >/dev/null 2>&1
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
timeout_s = float(sys.argv[3])
with socket.create_connection((host, port), timeout_s):
    pass
PY
        return $?
    fi
    return 2
}

reality_relay_preflight_route() {
    local mode="${1:-new}" rc=0 dns_rc tcp_rc public_ip dns_ip
    validate_port "${RLY_LISTEN_PORT:-}" || { print_error "中转监听端口无效: ${RLY_LISTEN_PORT:-空}"; return 1; }
    validate_domain "${RLY_CONNECT_HOST:-}" || validate_ip "${RLY_CONNECT_HOST:-}" || { print_error "中转连接域名/IP 无效: ${RLY_CONNECT_HOST:-空}"; return 1; }
    validate_domain "${RLY_TARGET_HOST:-}" || validate_ip "${RLY_TARGET_HOST:-}" || { print_error "落地地址无效: ${RLY_TARGET_HOST:-空}"; return 1; }
    validate_port "${RLY_TARGET_PORT:-}" || { print_error "落地端口无效: ${RLY_TARGET_PORT:-空}"; return 1; }
    [[ -n "${RLY_UUID:-}" && -n "${RLY_SNI:-}" && -n "${RLY_PUBLIC_KEY:-}" && -n "${RLY_SHORT_ID:-}" ]] || {
        print_error "中转线路缺少 Reality 客户端身份(uuid/sni/pbk/sid)"
        return 1
    }
    if [[ "$mode" != "existing" && -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.conf" ]]; then
        print_error "该端口已有中转线路: ${RLY_LISTEN_PORT}"
        return 1
    fi
    if [[ "$mode" != "existing" ]] && reality_port_reserved "$RLY_LISTEN_PORT"; then
        print_error "中转端口已被本项目其他功能保留: ${RLY_LISTEN_PORT}"
        return 1
    fi
    if [[ "$mode" != "existing" ]] && reality_port_in_use "$RLY_LISTEN_PORT"; then
        print_error "中转端口已被占用: ${RLY_LISTEN_PORT}"
        return 1
    fi

    if validate_domain "$RLY_TARGET_HOST"; then
        reality_host_resolves "$RLY_TARGET_HOST"; dns_rc=$?
        if [[ "$dns_rc" -eq 1 ]]; then
            print_error "落地域名无法解析: ${RLY_TARGET_HOST}"
            rc=1
        elif [[ "$dns_rc" -eq 2 ]]; then
            print_warn "缺少 DNS 检查工具(getent/python3)，已跳过落地域名解析预检"
        fi
    fi
    reality_tcp_connect_check "$RLY_TARGET_HOST" "$RLY_TARGET_PORT" "${REALITY_RELAY_PREFLIGHT_TIMEOUT:-5}"; tcp_rc=$?
    if [[ "$tcp_rc" -eq 1 ]]; then
        print_error "中转机无法 TCP 连接落地: ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
        rc=1
    elif [[ "$tcp_rc" -eq 2 ]]; then
        print_warn "缺少 TCP 检查工具(nc/python3)，已跳过落地端口预检"
    fi

    if validate_domain "$RLY_CONNECT_HOST"; then
        if declare -F get_public_ipv4 >/dev/null 2>&1; then
            public_ip="$(get_public_ipv4 2>/dev/null || true)"
        else
            public_ip=""
        fi
        dns_ip="$(reality_resolve_public_a "$RLY_CONNECT_HOST" 2>/dev/null || true)"
        if [[ -n "$public_ip" && -n "$dns_ip" && "$public_ip" != "$dns_ip" ]]; then
            if [[ "${REALITY_RELAY_STRICT_CONNECT_DNS:-0}" == "1" ]]; then
                print_error "中转域名 A 记录(${dns_ip})与本机公网 IPv4(${public_ip})不一致: ${RLY_CONNECT_HOST}"
                rc=1
            else
                print_warn "中转域名 A 记录(${dns_ip})与本机公网 IPv4(${public_ip})不一致: ${RLY_CONNECT_HOST}"
            fi
        fi
    fi
    return "$rc"
}

# 用当前 RLY_* 写出一条线路文件（值经 reality_state_quote，满足 validate_conf_file）
reality_relay_write_route() {
    local port="$1" file
    file="$REALITY_RELAY_DIR/relay-${port}.conf"
    mkdir -p "$REALITY_RELAY_DIR"
    chmod 700 "$REALITY_RELAY_DIR" 2>/dev/null || true
    local content
    content=$(cat <<EOF
RLY_NAME=$(reality_state_quote "${RLY_NAME:-}")
RLY_LISTEN_PORT=$(reality_state_quote "${RLY_LISTEN_PORT:-}")
RLY_CONNECT_HOST=$(reality_state_quote "${RLY_CONNECT_HOST:-}")
RLY_TARGET_HOST=$(reality_state_quote "${RLY_TARGET_HOST:-}")
RLY_TARGET_PORT=$(reality_state_quote "${RLY_TARGET_PORT:-}")
RLY_UUID=$(reality_state_quote "${RLY_UUID:-}")
RLY_SNI=$(reality_state_quote "${RLY_SNI:-}")
RLY_PUBLIC_KEY=$(reality_state_quote "${RLY_PUBLIC_KEY:-}")
RLY_SHORT_ID=$(reality_state_quote "${RLY_SHORT_ID:-}")
RLY_FLOW=$(reality_state_quote "${RLY_FLOW:-}")
RLY_FINGERPRINT=$(reality_state_quote "${RLY_FINGERPRINT:-}")
EOF
)
    reality_write_secure_file "$file" "$content"
}

# 用当前 RLY_* 写该线路客户端链接/JSON（身份=落地机，host:port=本机中转入口）
reality_relay_write_client_artifacts() {
    local port="${RLY_LISTEN_PORT:-}" host="${RLY_CONNECT_HOST:-}" name="${RLY_NAME:-relay-${RLY_LISTEN_PORT:-0}}" json_name
    [[ -n "$host" && -n "$port" && -n "${RLY_UUID:-}" && -n "${RLY_SNI:-}" && -n "${RLY_PUBLIC_KEY:-}" && -n "${RLY_SHORT_ID:-}" ]] || return 1
    validate_port "$port" || return 1
    mkdir -p "$REALITY_RELAY_DIR"
    chmod 700 "$REALITY_RELAY_DIR" 2>/dev/null || true
    json_name=$(reality_json_escape "$name")
    local json_host; json_host=$(reality_json_escape "$host")
    local json_uuid; json_uuid=$(reality_json_escape "$RLY_UUID")
    local json_sni; json_sni=$(reality_json_escape "$RLY_SNI")
    local json_public_key; json_public_key=$(reality_json_escape "$RLY_PUBLIC_KEY")
    local json_short_id; json_short_id=$(reality_json_escape "$RLY_SHORT_ID")
    local rly_fp rly_flow; rly_fp=$(reality_sanitize_fingerprint "${RLY_FINGERPRINT:-}")
    rly_flow="${RLY_FLOW:-xtls-rprx-vision}"
    local link_path="${REALITY_RELAY_DIR}/relay-${port}.link.txt"
    local json_path="${REALITY_RELAY_DIR}/relay-${port}.client.json"
    local link_content json_content
    link_content="$(reality_build_vless_link "$RLY_UUID" "$host" "$port" "$RLY_SNI" "$RLY_PUBLIC_KEY" "$RLY_SHORT_ID" "$name" "$rly_fp" "$rly_flow")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${port},"uuid":"${json_uuid}","flow":"${rly_flow}","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${rly_fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}}
EOF
)
    reality_write_secure_file "$link_path" "$link_content" || return 1
    reality_write_secure_file "$json_path" "$json_content" || return 1
}

reality_relay_validate_route() {
    local expected_exit_ip="${1:-}" test_url="${REALITY_RELAY_TEST_URL:-https://api.ipify.org}" tmp_dir cfg log curl_log pid_file pid test_port i out rc status="failed" json_path
    command_exists sing-box || { print_warn "sing-box 不存在，跳过中转端到端验证"; return 2; }
    command_exists curl || { print_warn "curl 不存在，跳过中转端到端验证"; return 2; }
    test_port="${REALITY_RELAY_SELFTEST_PORT:-}"
    if [[ -z "$test_port" ]]; then
        for i in $(seq 1 100); do
            test_port=$((19090 + i))
            reality_port_in_use "$test_port" || break
        done
    fi
    validate_port "$test_port" || return 1
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-relay-test.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    cfg="$tmp_dir/client.json"
    log="$tmp_dir/sing-box.log"
    curl_log="$tmp_dir/curl.log"
    pid_file="$tmp_dir/sing-box.pid"
    json_path="${REALITY_RELAY_DIR}/relay-${RLY_LISTEN_PORT}.health.json"
    local rly_fp rly_flow json_name json_host json_uuid json_sni json_public_key json_short_id
    rly_fp=$(reality_sanitize_fingerprint "${RLY_FINGERPRINT:-}")
    rly_flow="${RLY_FLOW:-xtls-rprx-vision}"
    json_name=$(reality_json_escape "${RLY_NAME:-relay-${RLY_LISTEN_PORT:-0}}")
    json_host=$(reality_json_escape "$RLY_CONNECT_HOST")
    json_uuid=$(reality_json_escape "$RLY_UUID")
    json_sni=$(reality_json_escape "$RLY_SNI")
    json_public_key=$(reality_json_escape "$RLY_PUBLIC_KEY")
    json_short_id=$(reality_json_escape "$RLY_SHORT_ID")
    cat > "$cfg" <<EOF
{"log":{"level":"warn","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${RLY_LISTEN_PORT},"uuid":"${json_uuid}","flow":"${rly_flow}","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${rly_fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}},{"type":"direct","tag":"direct"}],"route":{"final":"${json_name}"}}
EOF
    if ! sing-box check -c "$cfg" > "$log" 2>&1; then
        print_warn "中转客户端配置自检失败"
        sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
        rm -rf "$tmp_dir"
        return 1
    fi
    ( sing-box run -c "$cfg" >> "$log" 2>&1 & echo $! > "$pid_file" )
    pid=$(cat "$pid_file" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if out=$(curl -4 -sS --max-time "${REALITY_RELAY_VALIDATE_TIMEOUT:-25}" --socks5-hostname "127.0.0.1:${test_port}" "$test_url" 2>"$curl_log"); then
        rc=0
    else
        rc=$?
    fi
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true
    mkdir -p "$REALITY_RELAY_DIR"
    if [[ "$rc" -eq 0 && ( -z "$expected_exit_ip" || "$out" == "$expected_exit_ip" ) ]]; then
        status="ok"
        print_success "中转端到端验证通过: ${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} 出口 ${out}"
    elif [[ "$rc" -eq 0 ]]; then
        status="mismatch"
        print_warn "中转端到端验证出口不符: got=${out} expected=${expected_exit_ip}"
    else
        status="failed"
        print_warn "中转端到端验证失败，最近日志:"
        tail -n 10 "$curl_log" 2>/dev/null || true
        sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    fi
    local health_content
    health_content=$(cat <<EOF
{"route":"${json_name}","listen_port":${RLY_LISTEN_PORT},"connect_host":"${json_host}","target_host":"$(reality_json_escape "${RLY_TARGET_HOST:-}")","target_port":${RLY_TARGET_PORT:-0},"status":"${status}","exit_ip":"$(reality_json_escape "$out")","expected_exit_ip":"$(reality_json_escape "$expected_exit_ip")","checked_at":"$(date -Is 2>/dev/null || date)"}
EOF
)
    reality_write_secure_file "$json_path" "$health_content" || true
    rm -rf "$tmp_dir"
    [[ "$status" == "ok" ]]
}

# 由全部线路渲染 realm 多端点配置（保持单端点格式：log.level + [[endpoints]]）
reality_render_realm_config_multi() {
    local f listen_host
    # 经 reality_detect_listen_host 解析，避免 split 哨兵值直接当 bind 地址渲染出 listen = "split:<port>"
    listen_host="$(reality_detect_listen_host)"
    echo 'log.level = "warn"'
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        [[ -n "$RLY_TARGET_HOST" && -n "$RLY_TARGET_PORT" ]] || continue
        cat <<EOF

[[endpoints]]
listen = "$(reality_listen_endpoint "$listen_host" "$RLY_LISTEN_PORT")"
remote = "$(reality_listen_endpoint "$RLY_TARGET_HOST" "$RLY_TARGET_PORT")"
EOF
    done < <(reality_relay_route_files)
}

# 写 realm systemd 单元
reality_relay_ensure_service() {
    _reality_install_realm_service_unit || return 1
    systemctl daemon-reload
}

# 旧版单中转字段（REALITY_RELAY_*）一次性迁移为一条线路
reality_relay_migrate_legacy() {
    [[ -n "${REALITY_RELAY_TARGET_HOST:-}" && -n "${REALITY_RELAY_PORT:-}" ]] || return 0
    [[ -z "$(reality_relay_route_files)" ]] || return 0
    validate_port "$REALITY_RELAY_PORT" || return 0
    RLY_NAME="$(reality_effective_node_name)"
    RLY_LISTEN_PORT="$REALITY_RELAY_PORT"
    RLY_CONNECT_HOST="${REALITY_RELAY_DOMAIN:-${REALITY_NODE_DOMAIN:-}}"
    RLY_TARGET_HOST="$REALITY_RELAY_TARGET_HOST"
    RLY_TARGET_PORT="${REALITY_RELAY_TARGET_PORT:-}"
    RLY_UUID="${REALITY_UUID:-}"; RLY_SNI="${REALITY_SNI:-}"
    RLY_PUBLIC_KEY="${REALITY_PUBLIC_KEY:-}"; RLY_SHORT_ID="${REALITY_SHORT_ID:-}"
    RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    reality_relay_write_route "$RLY_LISTEN_PORT"
    reality_relay_write_client_artifacts || true
    REALITY_RELAY_DOMAIN=""; REALITY_RELAY_PORT=""
    REALITY_RELAY_TARGET_HOST=""; REALITY_RELAY_TARGET_PORT=""
    reality_write_state
}

# 根据 relays 目录重建 realm 配置、放行端口、刷新各线路客户端产物并重启 realm
reality_relay_regenerate() {
    local realm_config
    realm_config="$(_reality_realm_config_path)"
    _reality_abs_system_path "$realm_config" || return 1
    mkdir -p "$(dirname "$realm_config")" "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR"
    reality_relay_migrate_legacy
    if [[ -z "$(reality_relay_route_files)" ]]; then
        systemctl disable --now realm >/dev/null 2>&1 || true
        rm -f "$realm_config"
        return 0
    fi
    reality_install_realm_binary || return 1
    reality_backup_file "$realm_config"
    # 临时文件落在目标目录(/etc/realm)内，确保下方 mv 是同文件系统的原子 rename
    # （mktemp 默认落 /tmp 会跨文件系统退化为 copy+delete 且受目标 umask 影响）。
    mkdir -p "$(dirname "$realm_config")"
    local _tmp_cfg; _tmp_cfg="$(mktemp "$(dirname "$realm_config")/.realm.XXXXXX")" || return 1
    reality_render_realm_config_multi > "$_tmp_cfg"
    # LOW-1：只数有效端点。若路由文件都校验失败→0 端点，不能拿空配置 restart realm
    # （会启动一个空转/或静默“成功”的服务，且旧转发被静默丢弃）。此时保留旧配置并报错。
    # grep -c 匹配 0 次时输出 "0" 但退出码为 1；不要在后面追加 echo 0（会变成 "0\n0"
    # 触发算术比较语法错误）。改用 grep -o | wc -l，始终单行数字、退出码无关。
    local _ep_count; _ep_count="$(grep -o '^\[\[endpoints\]\]' "$_tmp_cfg" 2>/dev/null | wc -l | tr -d '[:space:]')"
    if [[ "${_ep_count:-0}" -eq 0 ]]; then
        rm -f "$_tmp_cfg"
        print_error "所有中转线路文件校验失败，渲染出 0 个端点；已保留原 realm 配置，未重启。"
        return 1
    fi
    mv -f "$_tmp_cfg" "$realm_config"
    chmod 600 "$realm_config"
    reality_relay_ensure_service
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        firewall_apply_realm_port "$RLY_LISTEN_PORT" >/dev/null 2>&1 || true
        reality_relay_write_client_artifacts || true
    done < <(reality_relay_route_files)
    systemctl enable realm >/dev/null 2>&1 || true
    if ! systemctl restart realm; then
        # restart 失败：恢复最近一次备份配置（若有），避免留下坏配置继续对外。
        local _bak
        _bak="$(ls -1t "$REALITY_BACKUP_DIR/$(basename "$realm_config")".*.bak 2>/dev/null | head -n1)"
        if [[ -n "$_bak" && -f "$_bak" ]]; then
            cp -a "$_bak" "$realm_config" 2>/dev/null || true
            systemctl restart realm >/dev/null 2>&1 || true
        fi
        print_error "realm 重启失败，已尝试恢复上一版配置。"
        return 1
    fi
    return 0
}

# 交互：添加一条中转线路（导入下游落地 vless 链接）
reality_relay_add() {
    print_title "添加中转线路（导入落地 vless 链接）"
    reality_require_supported_os || return 1
    reality_load_state || true
    local link=""
    read -e -r -p "粘贴落地机 vless:// 链接 (留空取消): " link
    [[ -n "$link" ]] || { print_info "已取消"; pause; return 0; }
    # 快照本机落地身份，避免被链接解析覆盖
    local _s_uuid="${REALITY_UUID:-}" _s_node="${REALITY_NODE_DOMAIN:-}" _s_port="${REALITY_PORT:-}" \
          _s_sni="${REALITY_SNI:-}" _s_pbk="${REALITY_PUBLIC_KEY:-}" _s_sid="${REALITY_SHORT_ID:-}" _s_flow="${REALITY_FLOW:-}" \
          _s_fp="${REALITY_FINGERPRINT:-}"
    reality_parse_vless_link "$link" || { print_error "落地机 vless 链接解析失败"; pause; return 1; }
    RLY_TARGET_HOST="$REALITY_NODE_DOMAIN"; RLY_TARGET_PORT="$REALITY_PORT"
    RLY_UUID="$REALITY_UUID"; RLY_SNI="$REALITY_SNI"; RLY_PUBLIC_KEY="$REALITY_PUBLIC_KEY"
    RLY_SHORT_ID="$REALITY_SHORT_ID"; RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    # 中转客户端指纹沿用导入链接里的 fp（真实落地机身份的一部分）；链接无 fp 时留空→回退 chrome。
    RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    # 恢复本机落地身份
    REALITY_UUID="$_s_uuid"; REALITY_NODE_DOMAIN="$_s_node"; REALITY_PORT="$_s_port"
    REALITY_SNI="$_s_sni"; REALITY_PUBLIC_KEY="$_s_pbk"; REALITY_SHORT_ID="$_s_sid"; REALITY_FLOW="$_s_flow"
    REALITY_FINGERPRINT="$_s_fp"
    validate_domain "$RLY_TARGET_HOST" || validate_ip "$RLY_TARGET_HOST" || { print_error "落地地址无效"; pause; return 1; }
    validate_port "$RLY_TARGET_PORT" || { print_error "落地端口无效"; pause; return 1; }
    [[ -n "$RLY_PUBLIC_KEY" && -n "$RLY_UUID" && -n "$RLY_SHORT_ID" ]] || { print_error "链接缺少 Reality 参数(pbk/uuid/sid)"; pause; return 1; }
    # 解析结果核对页（任意 read 处输入 0/q 可取消返回）
    draw_line
    echo "已解析落地机参数，请核对:"
    echo "  转发目标 : ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
    echo "  SNI      : ${RLY_SNI}"
    echo "  UUID     : $(reality_mask_secret "$RLY_UUID")"
    echo "  公钥(pbk): $(reality_mask_secret "$RLY_PUBLIC_KEY")"
    echo "  ShortID  : ${RLY_SHORT_ID}"
    draw_line
    confirm "以上落地参数是否正确?" || { print_info "已取消"; pause; return 0; }
    # 客户端连接域名：默认复用本机落地/中转域名，可覆盖
    local connect_default="${REALITY_NODE_DOMAIN:-${REALITY_RELAY_DOMAIN:-}}" in_host=""
    RLY_CONNECT_HOST=""
    while [[ -z "$RLY_CONNECT_HOST" ]]; do
        read -e -r -p "客户端连接本机的域名/IP [${connect_default:-必填}] (0=取消): " in_host
        in_host="${in_host:-$connect_default}"
        [[ "$in_host" == "0" || "$in_host" == "q" ]] && { print_info "已取消"; pause; return 0; }
        validate_domain "$in_host" || validate_ip "$in_host" || { print_error "地址无效"; continue; }
        RLY_CONNECT_HOST="$in_host"
    done
    [[ "$RLY_CONNECT_HOST" == "$connect_default" && -n "$connect_default" ]] && echo "（复用本机域名，按端口区分线路）"
    # 监听端口：唯一、未占用、不等于本机落地端口；优先推荐 443，无法使用时按已有 relay 最大端口递增。
    local def_port="443"
    if [[ "${REALITY_PORT:-}" == "443" || -f "$REALITY_RELAY_DIR/relay-443.conf" ]] || reality_port_in_use 443 || reality_port_reserved 443; then
        local candidate_port=""
        def_port="$(reality_relay_next_port 2>/dev/null || true)"
        for _ in $(seq 1 200); do
            [[ -n "$def_port" ]] && break
            candidate_port=$(reality_random_port 2>/dev/null || echo "")
            [[ -n "$candidate_port" ]] || continue
            reality_port_reserved "$candidate_port" && continue
            reality_port_in_use "$candidate_port" && continue
            def_port="$candidate_port"
            break
        done
        [[ -n "$def_port" ]] || { print_error "无法生成可用随机端口"; pause; return 1; }
        print_warn "本机 443/tcp 已被占用或已用于落地/其他中转，本条线路默认回落到随机端口；非 443 入口伪装弱于 443。"
    fi
    RLY_LISTEN_PORT=""
    while true; do
        read -e -r -p "本机中转监听端口 [${def_port}] (0=取消): " RLY_LISTEN_PORT
        RLY_LISTEN_PORT="${RLY_LISTEN_PORT:-$def_port}"
        [[ "$RLY_LISTEN_PORT" == "0" || "$RLY_LISTEN_PORT" == "q" ]] && { print_info "已取消"; pause; return 0; }
        validate_port "$RLY_LISTEN_PORT" || { print_error "端口无效"; continue; }
        if [[ -n "${REALITY_PORT:-}" && "$RLY_LISTEN_PORT" == "${REALITY_PORT}" ]]; then print_error "不能与本机落地端口相同"; continue; fi
        [[ -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.conf" ]] && { print_error "该端口已有中转线路"; continue; }
        if reality_port_reserved "$RLY_LISTEN_PORT"; then print_error "端口已被本项目其他功能保留"; continue; fi
        if reality_port_in_use "$RLY_LISTEN_PORT"; then print_error "端口已被占用"; continue; fi
        reality_warn_port_risk "$RLY_LISTEN_PORT" "Realm 中转入口"
        if [[ "$RLY_LISTEN_PORT" != "443" && -t 0 ]] && ! confirm "确认使用非 443 中转入口端口?"; then
            continue
        fi
        break
    done
    # 线路名称
    local def_name="relay-${RLY_LISTEN_PORT}"
    read -e -r -p "线路名称/备注 [${def_name}]: " RLY_NAME
    RLY_NAME="${RLY_NAME:-$def_name}"
    reality_validate_node_name "$RLY_NAME" || { print_error "名称无效：1-64 位英文/数字/空格/点/下划线/短横线"; pause; return 1; }
    # 固定本条新线路标识：reality_relay_regenerate 内部会遍历所有线路并复用 RLY_* 全局，
    # 返回后 RLY_* 已是“最后一条线路”的值；后续引用必须用这些 local，否则报错/回滚会指向别的线路。
    local new_port="$RLY_LISTEN_PORT" new_name="$RLY_NAME" new_chost="$RLY_CONNECT_HOST" \
          new_thost="$RLY_TARGET_HOST" new_tport="$RLY_TARGET_PORT"
    reality_relay_preflight_route new || { pause; return 1; }
    reality_relay_write_route "$new_port"
    # 应用失败时回滚刚加的线路，避免把 realm 留在半残/停止状态
    if ! reality_relay_regenerate; then
        print_error "Realm 配置应用失败，正在回滚本条线路"
        rm -f "$REALITY_RELAY_DIR/relay-${new_port}.conf" \
              "$REALITY_RELAY_DIR/relay-${new_port}.link.txt" \
              "$REALITY_RELAY_DIR/relay-${new_port}.client.json"
        reality_relay_regenerate || true   # 用剩余线路恢复到原先可用状态
        pause; return 1
    fi
    # 防火墙：regenerate 已对所有线路放行；此处仅在 UFW 未启用时给交互引导
    if command_exists ufw && ! ufw_is_active; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行中转端口?"; then
            ufw_setup
            firewall_apply_realm_port "$new_port" || print_warn "UFW 仍未生效，请确认云安全组已放行 ${new_port}/tcp"
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 ${new_port}/tcp"
        fi
    fi
    # 角色刷新
    reality_load_state || true
    if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then REALITY_ROLE="landing+relay"; else REALITY_ROLE="relay"; fi
    reality_write_state
    print_success "中转线路已添加: ${new_name} (本机 ${new_chost}:${new_port} -> ${new_thost}:${new_tport})"
    echo ""
    [[ -f "$REALITY_RELAY_DIR/relay-${new_port}.link.txt" ]] && cat "$REALITY_RELAY_DIR/relay-${new_port}.link.txt"
    pause
}

# 列出全部中转线路及客户端链接
reality_relay_list() {
    print_title "中转线路列表"
    local f n=0 st health status exit_ip
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        n=$((n+1))
        st="[未监听]"
        if command_exists ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${RLY_LISTEN_PORT}$"; then st="[监听中]"; fi
        health=""
        if [[ -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" ]]; then
            status="$(grep -Eo '"status":"[^"]+"' "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" 2>/dev/null | head -n1 | cut -d'"' -f4)"
            exit_ip="$(grep -Eo '"exit_ip":"[^"]*"' "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" 2>/dev/null | head -n1 | cut -d'"' -f4)"
            [[ -n "$status" ]] && health="  [验证:${status}${exit_ip:+/$exit_ip}]"
        fi
        echo "${n}. ${RLY_NAME}  本机:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}  ${st}${health}"
    done < <(reality_relay_route_files)
    if [[ $n -eq 0 ]]; then
        print_warn "暂无中转线路"
    else
        echo ""
        print_info "完整客户端链接请到「查看/修改节点信息 → 查看节点信息」获取"
    fi
    pause
}

# 删除一条中转线路
reality_relay_remove() {
    print_title "删除中转线路"
    local files=() f
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(reality_relay_route_files)
    [[ ${#files[@]} -gt 0 ]] || { print_warn "暂无中转线路"; pause; return 0; }
    local i=1
    for f in "${files[@]}"; do
        reality_relay_load_route "$f" && echo "  ${i}. ${RLY_NAME} (${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT})"
        i=$((i+1))
    done
    local sel; read -e -r -p "选择要删除的线路序号 [0=取消]: " sel
    [[ "$sel" =~ ^[0-9]+$ ]] || { print_error "无效序号"; pause; return 1; }
    [[ "$sel" -ge 1 && "$sel" -le ${#files[@]} ]] || return 0
    f="${files[$((sel-1))]}"
    reality_relay_load_route "$f" || { print_error "读取失败"; pause; return 1; }
    confirm "确认删除中转线路 ${RLY_NAME} (端口 ${RLY_LISTEN_PORT})?" || return 0
    local port="$RLY_LISTEN_PORT"
    rm -f "$f" "$REALITY_RELAY_DIR/relay-${port}.link.txt" "$REALITY_RELAY_DIR/relay-${port}.client.json"
    if command_exists ufw && ufw_is_active; then ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true; fi
    reality_relay_regenerate || true
    reality_load_state || true
    if [[ -z "$(reality_relay_route_files)" ]]; then
        if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then REALITY_ROLE="landing"; else REALITY_ROLE=""; fi
        reality_write_state
    fi
    print_success "已删除中转线路 (端口 ${port})"
    pause
}

# 中转线路管理子菜单
reality_relay_menu() {
    # 旧版单中转安装首次进入本菜单时，自动把 REALITY_RELAY_* 迁移为一条线路，
    # 使其在列表中可见、可管理（仅转换表示，不重启 realm）。
    reality_load_state 2>/dev/null && reality_relay_migrate_legacy 2>/dev/null || true
    while true; do
        print_title "中转线路管理（A 给多台落地机做中转）"
        echo "1. 添加中转线路（导入落地链接）"
        echo "2. 查看中转线路（清单/状态）"
        echo "3. 删除中转线路"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_relay_add ;;
            2) reality_relay_list ;;
            3) reality_relay_remove ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

firewall_remove_reality_ports() {
    command_exists ufw || return 0
    ufw_is_active || return 0
    local port f
    for port in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}" "${REALITY_RELAY_PORT:-}"; do
        validate_port "$port" || continue
        ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
    done
    # 回收所有中转线路监听端口
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        ufw delete allow "${RLY_LISTEN_PORT}/tcp" >/dev/null 2>&1 || true
    done < <(reality_relay_route_files)
}

reality_install_relay() {
    local relay_domain="$1" listen_port="$2" target_host="$3" target_port="$4" cf_token="${5:-}" node_name="${6:-}"
    validate_domain "$relay_domain" || { print_error "中转域名无效"; return 1; }
    validate_port "$listen_port" || { print_error "中转端口无效"; return 1; }
    validate_domain "$target_host" || validate_ip "$target_host" || { print_error "落地地址无效"; return 1; }
    validate_port "$target_port" || { print_error "落地端口无效"; return 1; }
    reality_warn_port_risk "$listen_port" "Realm 中转入口"
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    # 导入落地 vless 链接带入的客户端 Reality 身份(公钥/UUID/SNI/ShortID/flow/fp)只进 RLY_*
    # （中转线路的独立身份），绝不写入会被 reality_write_state 持久化的 REALITY_*。
    # 教训(HIGH-1)：曾把导入值经 REALITY_* 中转再赋给 RLY_*，导致本机 state.conf 被下游身份污染、
    # 甚至私钥被抹空(链接无私钥)——本机落地节点不可逆损坏。故此处快照后不再触碰 REALITY_*。
    local _imp_uuid="${REALITY_UUID:-}" _imp_sni="${REALITY_SNI:-}" \
          _imp_pbk="${REALITY_PUBLIC_KEY:-}" _imp_sid="${REALITY_SHORT_ID:-}" \
          _imp_node="${REALITY_NODE_DOMAIN:-}" _imp_port="${REALITY_PORT:-}" \
          _imp_flow="${REALITY_FLOW:-}" _imp_fp="${REALITY_FINGERPRINT:-}"
    # 先清空 REALITY_* 身份字段：否则 relay-only 全新机上 reality_load_state 失败时，
    # 这些字段会残留上面 parse 出的下游值，被 reality_write_state 误持久化成"伪落地"state
    # （UUID=下游、私钥空），日后误跑 rotate-key 会崩。清空后 load_state 只会填回本机真落地身份。
    REALITY_UUID=""; REALITY_SNI=""; REALITY_PUBLIC_KEY=""; REALITY_SHORT_ID=""
    REALITY_NODE_DOMAIN=""; REALITY_PORT=""; REALITY_PRIVATE_KEY=""; REALITY_FLOW=""; REALITY_FINGERPRINT=""
    # 加载本机落地 state（若有）以便保留本机落地身份 + 判断 landing 角色；导入值不覆盖它。
    reality_load_state || true
    if reality_port_reserved "$listen_port"; then
        print_error "中转端口已被本项目其他功能保留: ${listen_port}"
        return 1
    fi
    reality_warn_sni_risk "${_imp_sni:-${REALITY_SNI:-}}"
    reality_require_supported_os || return 1
    # 写为一条独立身份的中转线路（relays 目录是 realm 配置的唯一真相源）。
    # RLY_* 优先取导入的下游身份(_imp_*)；未导入链接时回退本机落地身份(REALITY_*)。
    RLY_NAME="${node_name:-$(reality_effective_node_name)}"
    RLY_LISTEN_PORT="$listen_port"
    RLY_CONNECT_HOST="$relay_domain"
    RLY_TARGET_HOST="$target_host"
    RLY_TARGET_PORT="$target_port"
    if [[ -n "$_imp_pbk" ]]; then
        RLY_UUID="$_imp_uuid"; RLY_SNI="$_imp_sni"
        RLY_PUBLIC_KEY="$_imp_pbk"; RLY_SHORT_ID="$_imp_sid"
        RLY_FLOW="${_imp_flow:-xtls-rprx-vision}"; RLY_FINGERPRINT="$_imp_fp"
    else
        RLY_UUID="${REALITY_UUID:-}"; RLY_SNI="${REALITY_SNI:-}"
        RLY_PUBLIC_KEY="${REALITY_PUBLIC_KEY:-}"; RLY_SHORT_ID="${REALITY_SHORT_ID:-}"
        RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"; RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    fi
    # MED-2：先迁移老版单中转字段（REALITY_RELAY_*）为一条独立线路，再写本次新线路。
    # 否则本次 write_route 会让 relays 目录非空 → regenerate 里的 migrate 提前 return →
    # 老线路永远不被渲染，升级用户原有中转静默失效。菜单路径已先迁移，这里对齐。
    reality_relay_migrate_legacy
    reality_relay_preflight_route new || return 1
    reality_relay_write_route "$listen_port"
    if [[ -n "$cf_token" ]]; then reality_sync_cloudflare_dns "$relay_domain" "$cf_token"; fi
    # MED-3：regenerate 失败时回滚本次新写的线路文件并重建，避免残留半配置线路
    # （下次 regenerate 会把它渲染进 realm，复活一条坏线路）。对齐 reality_relay_add 的回滚。
    if ! reality_relay_regenerate; then
        rm -f "${REALITY_RELAY_DIR}/relay-${listen_port}.conf" \
              "${REALITY_RELAY_DIR}/relay-${listen_port}.link.txt" \
              "${REALITY_RELAY_DIR}/relay-${listen_port}.client.json" 2>/dev/null || true
        reality_relay_regenerate || true
        print_error "Realm 中转重建失败，已回滚本次新增线路"
        return 1
    fi
    firewall_apply_realm_port "$listen_port"
    local _fw_rc=$?
    if [[ $_fw_rc -eq 1 ]]; then
        return 1
    elif [[ $_fw_rc -eq 2 ]]; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行 Realm 中转端口?"; then
            ufw_setup
            firewall_apply_realm_port "$listen_port" || \
                print_warn "UFW 仍未生效，请确认云安全组已放行 ${listen_port}/tcp"
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 ${listen_port}/tcp"
        fi
    fi
    if [[ -n "${REALITY_UUID:-}" && "${REALITY_ROLE:-}" == *"landing"* ]]; then
        REALITY_ROLE="landing+relay"
    else
        REALITY_ROLE="relay"
    fi
    [[ -n "$node_name" ]] && REALITY_NODE_NAME="$node_name"
    reality_write_state
    print_success "Realm 中转线路安装完成"
    reality_show_info
}

reality_prompt_port() {
    local prompt="$1" forbidden="${2:-}" allow_current_landing="${3:-0}" choice port input_port
    while true; do
        echo -e "${C_CYAN}${prompt} 端口策略:${C_RESET}" >&2
        echo "  1. 使用 443（推荐：最符合正常 HTTPS/REALITY 伪装）" >&2
        echo "  2. 自定义端口（非 443 会提示风险）" >&2
        echo "  3. 随机高位端口（仅备用；非 443 伪装弱于 443）" >&2
        read -e -r -p "请选择端口策略 [1]: " choice
        case "${choice:-1}" in
            1)
                input_port="443"
                ;;
            2)
                read -e -r -p "${prompt} 自定义端口: " input_port
                ;;
            3)
                input_port=""
                for _ in $(seq 1 200); do
                    port=$(reality_random_port) || { print_error "无法生成可用随机端口"; return 1; }
                    [[ -n "$forbidden" && "$port" == "$forbidden" ]] && continue
                    if [[ "$allow_current_landing" == "1" ]]; then
                        reality_port_reserved_except_current_landing "$port" && continue
                    else
                        reality_port_reserved "$port" && continue
                    fi
                    input_port="$port"
                    break
                done
                [[ -n "$input_port" ]] || { print_error "无法生成可用随机端口"; return 1; }
                ;;
            *) print_error "无效选择"; continue ;;
        esac
        validate_port "$input_port" || { print_error "端口无效"; continue; }
        if [[ -n "$forbidden" && "$input_port" == "$forbidden" ]]; then
            print_error "端口不能与 ${forbidden} 相同"
            continue
        fi
        if [[ "$allow_current_landing" == "1" ]]; then
            if reality_port_reserved_except_current_landing "$input_port"; then
                print_error "端口 ${input_port} 已被本项目其他功能保留"
                continue
            fi
        elif reality_port_reserved "$input_port"; then
            print_error "端口 ${input_port} 已被本项目其他功能保留"
            continue
        fi
        if reality_port_in_use "$input_port"; then
            print_warn "端口 ${input_port}/tcp 当前已被监听。若这是重装同一个 sing-box/realm 服务通常可以继续；否则启动可能失败。"
            if [[ -t 0 ]] && ! confirm "仍继续使用 ${input_port}/tcp?"; then
                continue
            fi
        fi
        reality_warn_port_risk "$input_port" "$prompt"
        if [[ "$input_port" != "443" && -t 0 ]] && ! confirm "确认使用非 443 Reality/Realm 入口端口?"; then
            continue
        fi
        echo "$input_port"
        return 0
    done
}

reality_prompt_split_ports() {
    local choice p4="" p6=""
    while true; do
        echo -e "${C_CYAN}IPv4/IPv6 双 Reality 端口策略:${C_RESET}" >&2
        echo "  1. IPv4 与 IPv6 均使用 443（推荐；脚本会让 IPv6 入站绑定具体 IPv6，避免端口冲突）" >&2
        echo "  2. IPv4 使用 443，IPv6 单独选择端口" >&2
        echo "  3. IPv6 使用 443，IPv4 单独选择端口" >&2
        echo "  4. IPv4/IPv6 分别选择端口（非 443 会提示风险）" >&2
        read -e -r -p "请选择端口策略 [1]: " choice
        case "${choice:-1}" in
            1) p4="443"; p6="443" ;;
            2) p4="443"; p6=$(reality_prompt_port "IPv6 Reality 监听" "" 1) || return 1 ;;
            3) p6="443"; p4=$(reality_prompt_port "IPv4 Reality 监听" "" 1) || return 1 ;;
            4)
                p4=$(reality_prompt_port "IPv4 Reality 监听" "" 1) || return 1
                p6=$(reality_prompt_port "IPv6 Reality 监听" "" 1) || return 1
                ;;
            *) print_error "无效选择"; continue ;;
        esac
        validate_port "$p4" && validate_port "$p6" || { print_error "端口无效"; continue; }
        printf '%s %s\n' "$p4" "$p6"
        return 0
    done
}

reality_prompt_landing_dns_mode() {
    local choice
    reality_detect_ips
    echo -e "${C_CYAN}节点网络/DNS 模式:${C_RESET}" >&2
    echo "  当前检测: IPv4=${REALITY_IPV4:-N/A}  IPv6=${REALITY_IPV6:-N/A}" >&2
    echo "  1. 自动/双栈单节点：同一域名写入可用的 A/AAAA（保持旧行为）" >&2
    echo "  2. IPv4-only 单节点：域名仅保留 A 记录" >&2
    echo "  3. IPv6-only 单节点：域名仅保留 AAAA 记录" >&2
    echo "  4. IPv4+IPv6 双节点：两个域名、两条客户端链接，端口优先共用 443（推荐双栈线路对比）" >&2
    while true; do
        read -e -r -p "请选择网络模式 [1]: " choice
        case "${choice:-1}" in
            1) echo "auto"; return 0 ;;
            2) echo "ipv4"; return 0 ;;
            3) echo "ipv6"; return 0 ;;
            4) echo "split"; return 0 ;;
            *) print_error "无效选择" >&2 ;;
        esac
    done
}

reality_install_wizard() {
    local role="" node="" node_v4="" node_v6="" dns_mode="" sni="" port="" port_v6="" cf_token="" relay_domain="" relay_port="" target_host="" target_port="" landing_link="" node_name="" node_name_v4="" node_name_v6="" _split_ports=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --landing) role="landing"; shift ;;
            --relay) role="relay"; shift ;;
            --both) role="both"; shift ;;
            --name|--node-name) node_name="$2"; shift 2 ;;
            --name-v4|--node-name-v4) node_name_v4="$2"; shift 2 ;;
            --name-v6|--node-name-v6) node_name_v6="$2"; shift 2 ;;
            --node) node="$2"; shift 2 ;;
            --node-v4|--ipv4-node) node_v4="$2"; shift 2 ;;
            --node-v6|--ipv6-node) node_v6="$2"; shift 2 ;;
            --dns-mode|--network-mode) dns_mode="$2"; shift 2 ;;
            --split|--dual-node|--dual-nodes) dns_mode="split"; shift ;;
            --sni) sni="$2"; shift 2 ;;
            --port) port="$2"; shift 2 ;;
            --port-v6|--ipv6-port) port_v6="$2"; shift 2 ;;
            --cf-token) cf_token="$2"; shift 2 ;;
            --relay-domain) relay_domain="$2"; shift 2 ;;
            --relay-port) relay_port="$2"; shift 2 ;;
            --target-host) target_host="$2"; shift 2 ;;
            --target-port) target_port="$2"; shift 2 ;;
            --landing-link) landing_link="$2"; shift 2 ;;
            *) print_warn "忽略未知参数: $1"; shift ;;
        esac
    done
    print_title "Sing-box Reality 节点安装向导"
    if [[ -z "$role" ]]; then
        echo "1. 落地机 (sing-box VLESS REALITY)"
        echo "2. 中转机 (Realm TCP 单跳转发)"
        echo "3. 落地 + 本机中转"
        echo "0. 返回上一级"
        read -e -r -p "请选择 [1, 0=返回]: " role_choice
        case "${role_choice:-1}" in
            1) role="landing" ;;
            2) role="relay" ;;
            3) role="both" ;;
            0|q|Q) return 0 ;;
            *) print_error "无效选择"; return 1 ;;
        esac
    fi
    if [[ "$role" == "landing" || "$role" == "both" ]]; then
        if [[ -z "$cf_token" ]]; then
            cf_token=$(reality_prompt_cf_token)
        fi
        if [[ -z "$dns_mode" ]]; then
            dns_mode=$(reality_prompt_landing_dns_mode)
        fi
        dns_mode=$(reality_normalize_dns_mode "$dns_mode") || { print_error "网络/DNS 模式无效: $dns_mode"; return 1; }
        if [[ "$dns_mode" == "split" ]]; then
            [[ -n "$node_v4" || -z "$node" ]] || node_v4="$node"
            while [[ -z "$node_v4" ]]; do
                echo -e "${C_CYAN}IPv4 节点连接域名说明:${C_RESET}"
                echo "  该域名会被同步为 A-only，用于客户端强制走 IPv4 线路。"
                node_v4=$(reality_prompt_domain_with_zones "IPv4 节点连接" "$cf_token" "$(hostname)-reality-v4")
                validate_domain "$node_v4" || { print_error "IPv4 节点域名无效"; node_v4=""; }
            done
            while [[ -z "$node_v6" ]]; do
                echo -e "${C_CYAN}IPv6 节点连接域名说明:${C_RESET}"
                echo "  该域名会被同步为 AAAA-only，用于客户端强制走 IPv6 线路。"
                node_v6=$(reality_prompt_domain_with_zones "IPv6 节点连接" "$cf_token" "$(hostname)-reality-v6")
                validate_domain "$node_v6" || { print_error "IPv6 节点域名无效"; node_v6=""; }
            done
            [[ "$node_v4" != "$node_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 域名不能相同"; return 1; }
            node="$node_v4"
        else
            while [[ -z "$node" ]]; do
                echo -e "${C_CYAN}节点连接域名说明:${C_RESET}"
                echo "  这是客户端实际连接的节点域名，会写入 vless:// 链接的 @host 部分。"
                echo "  脚本会通过 Cloudflare API 自动创建/更新此域名到当前 VPS 公网 IP，并强制 Cloudflare 灰云。"
                echo "  这里不是让你手动去 Cloudflare 添加记录；如果 Token 能列出 zone，只需要填写自定义前缀。"
                echo "  示例: 选择 example.com 后输入 node-us-01，脚本会生成 node-us-01.example.com -> 当前 VPS 公网 IP"
                node=$(reality_prompt_domain_with_zones "节点连接" "$cf_token")
                validate_domain "$node" || { print_error "域名无效"; node=""; }
            done
        fi
        if [[ -z "$node_name" ]]; then
            REALITY_NODE_DOMAIN="$node"
            node_name=$(reality_prompt_node_name "$(reality_default_node_name)")
        fi
        if [[ "$dns_mode" == "split" ]]; then
            [[ -n "$node_name_v4" ]] || node_name_v4=$(reality_node_name_with_suffix "$node_name" "-ipv4")
            [[ -n "$node_name_v6" ]] || node_name_v6=$(reality_node_name_with_suffix "$node_name" "-ipv6")
        fi
        [[ -z "$sni" ]] && sni=$(reality_prompt_sni)
        if [[ "$dns_mode" == "split" ]]; then
            if [[ -z "$port" && -z "$port_v6" ]]; then
                _split_ports="$(reality_prompt_split_ports)" || return 1
                read -r port port_v6 <<< "$_split_ports"
            elif [[ -z "$port" && "$port_v6" == "443" ]]; then
                port="443"
            elif [[ -z "$port_v6" && "$port" == "443" ]]; then
                port_v6="443"
            else
                [[ -z "$port" ]] && port=$(reality_prompt_port "IPv4 Reality 监听" "" 1)
                [[ -z "$port_v6" ]] && port_v6=$(reality_prompt_port "IPv6 Reality 监听" "" 1)
            fi
        else
            [[ -z "$port" ]] && port=$(reality_prompt_port "Reality 监听" "" 1)
        fi
        reality_install_landing "$node" "$sni" "$port" "$cf_token" "$node_name" "$dns_mode" "$node_v4" "$node_v6" "$port_v6" "$node_name_v4" "$node_name_v6" || return 1
    fi
    if [[ "$role" == "relay" || "$role" == "both" ]]; then
        if [[ -n "$landing_link" ]]; then
            reality_parse_vless_link "$landing_link" || { print_error "落地机 VLESS 链接解析失败"; return 1; }
            [[ -z "$target_host" ]] && target_host="$REALITY_NODE_DOMAIN"
            [[ -z "$target_port" ]] && target_port="$REALITY_PORT"
        elif [[ "$role" == "relay" ]] && confirm "是否导入落地机 VLESS 链接以生成中转客户端链接?"; then
            read -e -r -p "粘贴落地机 vless:// 链接: " landing_link
            reality_parse_vless_link "$landing_link" || { print_error "落地机 VLESS 链接解析失败"; return 1; }
            [[ -z "$target_host" ]] && target_host="$REALITY_NODE_DOMAIN"
            [[ -z "$target_port" ]] && target_port="$REALITY_PORT"
        fi
        if [[ -z "$cf_token" ]]; then
            cf_token=$(reality_prompt_cf_token)
        fi
        while [[ -z "$relay_domain" ]]; do
            echo -e "${C_CYAN}中转机连接域名说明:${C_RESET}"
            echo "  这是客户端实际连接的中转机域名，会替换客户端链接里的 @host。"
            echo "  脚本会通过 Cloudflare API 自动创建/更新此域名到当前中转机公网 IP，并强制 Cloudflare 灰云。"
            echo "  这里不是让你手动去 Cloudflare 添加记录；如果 Token 能列出 zone，只需要填写自定义前缀。"
            echo "  Realm 会把该端口的 TCP 流量转发到落地机 Reality 端口。"
            relay_domain=$(reality_prompt_domain_with_zones "中转机连接" "$cf_token")
            validate_domain "$relay_domain" || { print_error "域名无效"; relay_domain=""; }
        done
        if [[ -z "$node_name" ]]; then
            REALITY_RELAY_DOMAIN="$relay_domain"
            node_name=$(reality_prompt_node_name "$(reality_default_node_name)")
        fi
        local _relay_forbidden_port=""
        [[ "$role" == "both" ]] && _relay_forbidden_port="$port"
        [[ -z "$relay_port" ]] && relay_port=$(reality_prompt_port "Realm 中转监听" "$_relay_forbidden_port")
        if [[ "$role" == "both" ]]; then
            target_host="127.0.0.1"; target_port="$port"
            [[ "$relay_port" != "$port" ]] || { print_error "本机中转端口不能与本机落地 Reality 端口相同"; return 1; }
        else
            while [[ -z "$target_host" ]]; do read -e -r -p "落地机域名/IP: " target_host; validate_domain "$target_host" || validate_ip "$target_host" || { print_error "地址无效"; target_host=""; }; done
            while [[ -z "$target_port" ]]; do read -e -r -p "落地机 Reality 端口: " target_port; validate_port "$target_port" || { print_error "端口无效"; target_port=""; }; done
        fi
        reality_install_relay "$relay_domain" "$relay_port" "$target_host" "$target_port" "$cf_token" "$node_name" || return 1
        if reality_load_state && [[ -n "${REALITY_UUID:-}" ]]; then reality_write_client_artifacts; fi
    fi
}

reality_show_info() {
    print_title "Sing-box Reality 节点信息"
    reality_load_state || { print_warn "未发现 Reality 状态文件"; pause; return 0; }
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    echo -e "角色: ${C_GREEN}${REALITY_ROLE:-未知}${C_RESET}"
    echo "节点名称: $(reality_effective_node_name)"
    echo "网络模式: $(reality_dns_mode_label "$mode")"
    if [[ "$mode" == "split" ]]; then
        [[ -n "${REALITY_NODE_DOMAIN_V4:-}" ]] && echo "IPv4节点: ${REALITY_NODE_DOMAIN_V4}:${REALITY_PORT} (${REALITY_NODE_NAME_V4:-IPv4})"
        [[ -n "${REALITY_NODE_DOMAIN_V6:-}" ]] && echo "IPv6节点: ${REALITY_NODE_DOMAIN_V6}:${REALITY_PORT_V6} (${REALITY_NODE_NAME_V6:-IPv6})"
    else
        [[ -n "${REALITY_NODE_DOMAIN:-}" ]] && echo "落地域名: $REALITY_NODE_DOMAIN"
        [[ -n "${REALITY_PORT:-}" ]] && echo "Reality端口: $REALITY_PORT"
    fi
    [[ -n "${REALITY_SNI:-}" ]] && echo "SNI: $REALITY_SNI"
    [[ -n "${REALITY_RELAY_DOMAIN:-}" ]] && echo "中转域名: $REALITY_RELAY_DOMAIN"
    [[ -n "${REALITY_RELAY_PORT:-}" ]] && echo "中转端口: $REALITY_RELAY_PORT"
    [[ -n "${REALITY_RELAY_TARGET_HOST:-}" ]] && echo "中转目标: ${REALITY_RELAY_TARGET_HOST}:${REALITY_RELAY_TARGET_PORT}"
    if [[ -f "$REALITY_LINK_FILE" ]]; then
        draw_line
        echo "落地客户端链接:"
        cat "$REALITY_LINK_FILE"
    fi
    # 多路中转线路：每条独立身份、独立客户端链接
    local _f _n=0
    while IFS= read -r _f; do
        [[ -n "$_f" ]] || continue
        reality_relay_load_route "$_f" || continue
        _n=$((_n+1))
        draw_line
        echo "中转线路 ${_n}: ${RLY_NAME}  本机 ${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
        local _lf="$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.link.txt"
        [[ -f "$_lf" ]] && cat "$_lf"
    done < <(reality_relay_route_files)
    # CDN 链路（橙云 + 优选 IP）：与 Reality 直连并存，单独展示
    if reality_cdn_load_state 2>/dev/null && [[ -n "${REALITY_CDN_DOMAIN:-}" ]]; then
        draw_line
        echo "CDN 链路 (VLESS+WS+TLS 橙云): ${REALITY_CDN_NODE_NAME:-cdn}"
        echo "  CDN 域名: ${REALITY_CDN_DOMAIN}  回源端口: ${REALITY_CDN_ORIGIN_PORT:-8443}  WS path: ${REALITY_CDN_WS_PATH:-}"
        echo "  当前优选 IP: ${REALITY_CDN_PREFER_IP:-（未设置，server 暂用域名；由国内机 B+C 自动刷新）}"
        [[ -f "$REALITY_CDN_LINK_FILE" ]] && cat "$REALITY_CDN_LINK_FILE"
    fi
    pause
}

reality_status() {
    print_title "Reality 服务状态"
    command_exists systemctl || { print_warn "systemctl 不可用"; pause; return; }
    local status_out
    if status_out=$(systemctl --no-pager --full status sing-box 2>&1); then
        printf '%s\n' "$status_out" | sed -n '1,12p'
    else
        print_warn "sing-box 未运行"
        printf '%s\n' "$status_out" | sed -n '1,6p'
    fi
    echo ""
    if status_out=$(systemctl --no-pager --full status realm 2>&1); then
        printf '%s\n' "$status_out" | sed -n '1,12p'
    fi
    pause
}

reality_diagnose() {
    print_title "Reality 诊断/自检"
    reality_load_state || { print_error "未发现状态文件: $REALITY_STATE_FILE"; pause; return 1; }

    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    local has_landing=0; [[ -n "${REALITY_PORT:-}" && -n "${REALITY_NODE_DOMAIN:-}" ]] && has_landing=1
    # 连接核对目标：优先落地域名；纯中转机回落到首条线路的连接域名
    local connect_domain="${REALITY_NODE_DOMAIN:-}" connect_port="${REALITY_PORT:-}"
    if [[ -z "$connect_domain" ]]; then
        local _first; _first=$(reality_relay_route_files | head -n1)
        if [[ -n "$_first" ]] && reality_relay_load_route "$_first"; then
            connect_domain="$RLY_CONNECT_HOST"; connect_port="$RLY_LISTEN_PORT"
        fi
    fi
    local public_ip="" dns_ip="" system_dns=""

    echo "节点角色: ${REALITY_ROLE:-unknown}"
    echo "网络模式: $(reality_dns_mode_label "$mode")"
    echo "客户端连接: ${connect_domain:-未设置}:${connect_port:-未设置}"
    if [[ "$has_landing" -eq 1 && "$mode" == "split" ]]; then
        echo "IPv4节点: ${REALITY_NODE_DOMAIN_V4:-未设置}:${REALITY_PORT:-未设置}"
        echo "IPv6节点: ${REALITY_NODE_DOMAIN_V6:-未设置}:${REALITY_PORT_V6:-未设置}"
    elif [[ "$has_landing" -eq 1 ]]; then
        echo "落地端口: ${REALITY_PORT}"
    fi
    [[ -n "${REALITY_SNI:-}" ]] && echo "落地 SNI: ${REALITY_SNI}"
    echo ""

    if [[ "$has_landing" -eq 1 ]]; then
        if command_exists sing-box; then
            sing-box version 2>/dev/null | head -n 1 || true
            if [[ -f "$REALITY_SINGBOX_CONFIG" ]]; then
                sing-box check -c "$REALITY_SINGBOX_CONFIG" >/dev/null 2>&1 \
                    && print_success "sing-box 配置检查通过" \
                    || print_error "sing-box 配置检查失败"
            fi
        else
            print_warn "sing-box 未安装"
        fi

        if command_exists systemctl; then
            systemctl is-active --quiet sing-box \
                && print_success "sing-box 服务 active" \
                || print_error "sing-box 服务未运行"
        fi

        if command_exists ss; then
            local _co_rport=""
            _co_rport="$(reality_coexist_reality_port 2>/dev/null || true)"
            if [[ -n "$_co_rport" ]]; then
                # 共存模式：sing-box 绑 127.0.0.1:<内部端口>，公网 443 由 nginx stream 持有。
                if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${_co_rport}$"; then
                    print_success "本机正在监听 Reality 内部端口(loopback): ${_co_rport}/tcp（443 共存模式）"
                else
                    print_error "本机未监听 Reality 内部端口: ${_co_rport}/tcp（443 共存模式，sing-box 可能未起）"
                fi
            else
                local _rp
                for _rp in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}"; do
                    validate_port "$_rp" || continue
                    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${_rp}$"; then
                        print_success "本机正在监听 Reality 端口: ${_rp}/tcp"
                    else
                        print_error "本机未监听 Reality 端口: ${_rp}/tcp"
                    fi
                done
            fi
        fi

        if command_exists ufw; then
            local _up
            for _up in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}"; do
                validate_port "$_up" || continue
                if ufw status 2>/dev/null | grep -q "${_up}/tcp"; then
                    print_success "UFW 已放行 Reality 端口: ${_up}/tcp"
                else
                    print_warn "UFW 状态中未看到 ${_up}/tcp 放行规则"
                fi
            done
        fi
    fi

    # 443 共存模式诊断：stream 模块 / 443 归属 / 内部端口 / SNI 白名单
    if reality_coexist_enabled 2>/dev/null; then
        echo ""
        print_info "443 共存模式（nginx stream + ssl_preread）诊断:"
        local _co_rport _co_wport
        _co_rport="$(reality_coexist_reality_port 2>/dev/null || true)"
        _co_wport="$(reality_coexist_web_port 2>/dev/null || true)"
        echo "  reality 内部端口: ${_co_rport:-未知}   web 内部端口: ${_co_wport:-未知}"
        if declare -F _check_nginx_stream >/dev/null && _check_nginx_stream; then
            print_success "nginx stream 模块可用"
        else
            print_error "nginx stream 模块不可用（443 分流无法工作）"
        fi
        if command_exists ss; then
            if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)443$"; then
                print_success "本机正在监听 443/tcp（应为 nginx stream 持有）"
            else
                print_error "本机未监听 443/tcp（nginx stream 未接管，Reality 对外不可达）"
            fi
        fi
        if [[ -f "$REALITY_STREAM_CONF" ]]; then
            print_success "stream 分流配置存在: $REALITY_STREAM_CONF"
            local _wl_count
            _wl_count=$(reality_coexist_collect_web_domains 2>/dev/null | wc -l | tr -d ' ')
            echo "  真站 SNI 白名单: ${_wl_count} 个域名 → web(${_co_wport:-?})，其余 default → reality(${_co_rport:-?})"
        else
            print_error "stream 分流配置缺失: $REALITY_STREAM_CONF"
        fi
        if command_exists nginx; then
            nginx -t >/dev/null 2>&1 \
                && print_success "nginx 配置校验通过" \
                || print_error "nginx 配置校验失败（run: nginx -t 查看详情）"
        fi
    fi

    # 中转线路诊断：realm 服务 + 各线路监听端口
    if [[ -n "$(reality_relay_route_files)" ]]; then
        echo ""
        if command_exists systemctl; then
            systemctl is-active --quiet realm \
                && print_success "realm 中转服务 active" \
                || print_error "realm 中转服务未运行"
        fi
        local _rf
        while IFS= read -r _rf; do
            [[ -n "$_rf" ]] || continue
            reality_relay_load_route "$_rf" || continue
            validate_port "$RLY_LISTEN_PORT" || continue
            if command_exists ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${RLY_LISTEN_PORT}$"; then
                print_success "中转线路 ${RLY_NAME}: 监听 ${RLY_LISTEN_PORT}/tcp -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
            else
                print_error "中转线路 ${RLY_NAME}: 未监听 ${RLY_LISTEN_PORT}/tcp（realm 可能未启动或端口冲突）"
            fi
        done < <(reality_relay_route_files)
    fi

    echo ""
    if [[ "$mode" == "split" ]]; then
        echo "监听地址: IPv4=${REALITY_LISTEN_HOST_V4:-0.0.0.0}:${REALITY_PORT:-?}  IPv6=[${REALITY_LISTEN_HOST_V6:-::}]:${REALITY_PORT_V6:-?}"
    else
        echo "监听地址: ${REALITY_LISTEN_HOST:-0.0.0.0}$([[ "${REALITY_LISTEN_HOST:-}" == "::" ]] && echo '（双栈 IPv4+IPv6）')"
    fi

    local public_ip6 dns_ip6 has_v4_path=0 has_v6_path=0
    public_ip=$(get_public_ipv4 2>/dev/null || true)
    public_ip6=$(get_public_ipv6 2>/dev/null || true)
    [[ -n "$public_ip" ]] && { echo "本机公网 IPv4: $public_ip"; has_v4_path=1; }
    [[ -n "$public_ip6" ]] && { echo "本机公网 IPv6: $public_ip6"; has_v6_path=1; }
    [[ -z "$public_ip" && -z "$public_ip6" ]] && print_warn "未能获取本机公网 IPv4/IPv6"

    system_dns=$(getent ahostsv4 "$connect_domain" 2>/dev/null | awk '{print $1; exit}' || true)
    local system_dns6; system_dns6=$(getent ahostsv6 "$connect_domain" 2>/dev/null | awk '{print $1; exit}' || true)
    [[ -n "$system_dns" ]] && echo "系统 DNS(A): ${connect_domain} -> ${system_dns}"
    [[ -n "$system_dns6" ]] && echo "系统 DNS(AAAA): ${connect_domain} -> ${system_dns6}"

    dns_ip=$(reality_resolve_public_a "$connect_domain" 2>/dev/null || true)
    dns_ip6=$(reality_resolve_public_aaaa "$connect_domain" 2>/dev/null || true)
    [[ -n "$dns_ip" ]] && echo "Cloudflare DoH(A): ${connect_domain} -> ${dns_ip}"
    [[ -n "$dns_ip6" ]] && echo "Cloudflare DoH(AAAA): ${connect_domain} -> ${dns_ip6}"
    if [[ -z "$dns_ip" && -z "$dns_ip6" ]]; then
        print_warn "公网 DNS 未解析到 ${connect_domain} 的 A/AAAA 记录（DNS 未同步或未创建）"
    fi
    # 一致性：优先按本机可用的协议栈核对
    if [[ -n "$public_ip" && -n "$dns_ip" ]]; then
        [[ "$public_ip" == "$dns_ip" ]] \
            && print_success "IPv4 DNS 解析与本机公网一致" \
            || print_warn "IPv4 DNS 解析与本机公网不一致（DDNS 未同步或处于 NAT/转发环境）"
    fi
    if [[ -n "$public_ip6" && -n "$dns_ip6" ]]; then
        [[ "$public_ip6" == "$dns_ip6" ]] \
            && print_success "IPv6 DNS 解析与本机公网一致" \
            || print_warn "IPv6 DNS 解析与本机公网不一致（DDNS 未同步）"
    fi
    if [[ "$mode" == "split" ]]; then
        local v4_a="" v4_aaaa="" v6_a="" v6_aaaa=""
        v4_a=$(reality_resolve_public_a "${REALITY_NODE_DOMAIN_V4:-}" 2>/dev/null || true)
        v4_aaaa=$(reality_resolve_public_aaaa "${REALITY_NODE_DOMAIN_V4:-}" 2>/dev/null || true)
        v6_a=$(reality_resolve_public_a "${REALITY_NODE_DOMAIN_V6:-}" 2>/dev/null || true)
        v6_aaaa=$(reality_resolve_public_aaaa "${REALITY_NODE_DOMAIN_V6:-}" 2>/dev/null || true)
        [[ -n "$v4_a" ]] && print_success "IPv4 节点 A 记录存在: ${REALITY_NODE_DOMAIN_V4} -> ${v4_a}" || print_warn "IPv4 节点缺少 A 记录: ${REALITY_NODE_DOMAIN_V4}"
        [[ -z "$v4_aaaa" ]] && print_success "IPv4 节点未发现 AAAA 记录（符合 A-only）" || print_warn "IPv4 节点仍存在 AAAA 记录: ${v4_aaaa}"
        [[ -n "$v6_aaaa" ]] && print_success "IPv6 节点 AAAA 记录存在: ${REALITY_NODE_DOMAIN_V6} -> ${v6_aaaa}" || print_warn "IPv6 节点缺少 AAAA 记录: ${REALITY_NODE_DOMAIN_V6}"
        [[ -z "$v6_a" ]] && print_success "IPv6 节点未发现 A 记录（符合 AAAA-only）" || print_warn "IPv6 节点仍存在 A 记录: ${v6_a}"
    fi
    if [[ "$has_v6_path" -eq 1 && "$has_v4_path" -eq 0 ]]; then
        print_info "本机为 IPv6-only：请确认节点域名已有 AAAA 记录、监听地址为 ::、且客户端网络支持 IPv6。"
        [[ "${REALITY_LISTEN_HOST:-}" != "::" ]] && print_warn "当前监听地址非 :: —— IPv6-only 机器需重装落地机(菜单 11→1)使其绑定 ::，否则 IPv6 客户端无法连接。"
    fi

    if [[ -n "${REALITY_SNI:-}" ]]; then
        if reality_verify_sni "$REALITY_SNI"; then
            print_success "SNI TLS/SAN 校验通过: $REALITY_SNI"
            reality_cleanup_sni_check_log
        else
            print_warn "SNI TLS/SAN 校验失败或当前网络不可达: $REALITY_SNI"
            tail -n 5 "${REALITY_SNI_CHECK_LOG:-/dev/null}" 2>/dev/null || true
            reality_cleanup_sni_check_log
        fi
    fi

    if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then
        reality_local_client_self_test || true
    fi

    echo ""
    print_info "外部连通性抓包诊断:"
    echo "  如果本机自测通过但客户端仍不通，通常是云厂商安全组/NAT/端口映射、客户端 DNS Fake-IP、或本地网络路由问题。"
    echo "  可在 VPS 上执行抓包，同时从客户端连接节点，看是否有包到达本机:"
    echo "    sudo timeout 30 tcpdump -nni any tcp port ${connect_port}"
    if command_exists tcpdump && [[ -t 0 ]] && confirm "现在启动 30 秒 tcpdump 抓包? 请同时在客户端发起连接"; then
        timeout 30 tcpdump -nni any "tcp port ${connect_port}" 2>/dev/null | sed -n '1,80p' || true
    elif command_exists tcpdump; then
        print_info "当前为非交互运行或已跳过抓包；需要时可手动执行上面的 tcpdump 命令"
    else
        print_warn "tcpdump 未安装；如需抓包可安装 tcpdump 后重试"
    fi
    pause
}

reality_restart() {
    systemctl restart sing-box 2>/dev/null || true
    systemctl restart realm 2>/dev/null || true
    print_success "已发送重启命令"
    pause
}

reality_rotate_user() {
    reality_load_state || { print_error "未安装落地机配置"; pause; return 1; }
    [[ -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_SHORT_ID:-}" ]] || { print_error "状态文件缺少落地机参数"; pause; return 1; }
    validate_port "$REALITY_PORT" || { print_error "状态文件端口无效: ${REALITY_PORT:-空}"; pause; return 1; }
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    [[ "$mode" != "split" ]] || validate_port "${REALITY_PORT_V6:-}" || { print_error "双节点状态文件 IPv6 端口无效: ${REALITY_PORT_V6:-空}"; pause; return 1; }
    local old_uuid="$REALITY_UUID" new_uuid new_config
    new_uuid=$(reality_generate_uuid) || return 1
    new_config=$(reality_render_singbox_config "$new_uuid" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    REALITY_UUID="$new_uuid"
    if ! reality_apply_singbox_config "$new_config"; then
        REALITY_UUID="$old_uuid"
        pause; return 1
    fi
    reality_write_state; reality_write_client_artifacts
    print_success "UUID 已轮换"
    reality_show_info
}

reality_rotate_key() {
    reality_load_state || { print_error "未安装落地机配置"; pause; return 1; }
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" ]] || { print_error "状态文件缺少落地机参数"; pause; return 1; }
    validate_port "$REALITY_PORT" || { print_error "状态文件端口无效: ${REALITY_PORT:-空}"; pause; return 1; }
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    [[ "$mode" != "split" ]] || validate_port "${REALITY_PORT_V6:-}" || { print_error "双节点状态文件 IPv6 端口无效: ${REALITY_PORT_V6:-空}"; pause; return 1; }
    local old_private_key="$REALITY_PRIVATE_KEY" old_public_key="$REALITY_PUBLIC_KEY" old_short_id="$REALITY_SHORT_ID" keys new_config
    keys=$(reality_generate_keypair) || return 1
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    if ! reality_apply_singbox_config "$new_config"; then
        REALITY_PRIVATE_KEY="$old_private_key"
        REALITY_PUBLIC_KEY="$old_public_key"
        REALITY_SHORT_ID="$old_short_id"
        pause; return 1
    fi
    reality_write_state; reality_write_client_artifacts
    print_success "Reality Key/ShortID 已轮换"
    reality_show_info
}

reality_cf_sync_menu() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local domain="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" token="" mode
    mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    if [[ "$mode" != "split" ]]; then
        [[ -n "$domain" ]] || { print_error "状态文件缺少域名"; pause; return 1; }
    fi
    read -s -r -p "Cloudflare API Token: " token; echo ""
    if [[ "$mode" == "split" ]]; then
        reality_sync_cloudflare_dns_by_state "$token"
    else
        reality_sync_cloudflare_dns "$domain" "$token" "$mode"
    fi
    pause
}

reality_update_node_name() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local old_name new_name
    old_name="$(reality_effective_node_name)"
    new_name=$(reality_prompt_node_name "$old_name") || return 1
    REALITY_NODE_NAME="$new_name"
    if [[ "$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo auto)" == "split" ]]; then
        REALITY_NODE_NAME_V4="$(reality_node_name_with_suffix "$new_name" "-ipv4")"
        REALITY_NODE_NAME_V6="$(reality_node_name_with_suffix "$new_name" "-ipv6")"
    fi
    reality_write_state
    if [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]; then
        reality_write_client_artifacts || true
    fi
    print_success "节点名称已更新: $new_name"
    pause
}

# ── CDN 链路安装/卸载/信息 向导 ──

# 选一个未占用的内部 WS 端口（127.0.0.1，高位随机）
reality_cdn_pick_inner_port() {
    local p
    validate_port "${REALITY_CDN_ORIGIN_PORT:-8443}" || return 1
    for _ in $(seq 1 200); do
        p=$(reality_random_port) || return 1
        [[ "$p" == "${REALITY_PORT:-}" || "$p" == "${REALITY_PORT_V6:-}" ]] && continue
        [[ "$p" == "${REALITY_CDN_ORIGIN_PORT:-8443}" ]] && continue
        # MED-4：避开本项目其他 feature 已保留(含当前停止的 relay/共存)的端口，避免重启后 bind 冲突。
        reality_port_reserved "$p" && continue
        reality_port_in_use "$p" && continue
        echo "$p"; return 0
    done
    return 1
}

# 生成隐秘 WS path（/ + 16 位 hex）
reality_cdn_gen_ws_path() {
    if command_exists openssl; then
        printf '/%s' "$(openssl rand -hex 8)"
    else
        printf '/%s' "$(tr -dc '0-9a-f' < /dev/urandom 2>/dev/null | head -c 16)"
    fi
}

# 为 Reality 节点加挂 CDN 链路（VLESS+WS+TLS 橙云 + 优选 IP）。
# 前置：本机已是 Reality 落地机（有 state、sing-box 在跑）。
reality_cdn_install() {
    print_title "为 Reality 节点加挂 CDN 链路（橙云 + 优选 IP，主打晚高峰）"
    reality_require_supported_os || { pause; return 1; }
    if ! reality_load_state || [[ -z "${REALITY_UUID:-}" || -z "${REALITY_PORT:-}" ]]; then
        print_error "本机尚未安装 Reality 落地机，请先用菜单 1 安装落地机再加挂 CDN 链路。"
        pause; return 1
    fi
    command_exists nginx || { print_error "Nginx 未安装。请先用 Web 菜单「添加域名」安装 nginx/certbot 依赖。"; pause; return 1; }
    command_exists certbot || { print_error "certbot 未安装。请先用 Web 菜单「添加域名」安装依赖。"; pause; return 1; }

    local had_cdn_state=0 old_cdn_state=""
    if [[ -f "$REALITY_CDN_STATE_FILE" ]]; then
        had_cdn_state=1
        old_cdn_state=$(cat "$REALITY_CDN_STATE_FILE" 2>/dev/null || true)
        if reality_cdn_load_state 2>/dev/null && [[ -n "${REALITY_CDN_DOMAIN:-}" ]]; then
            print_warn "检测到已存在 CDN 链路: ${REALITY_CDN_DOMAIN}（覆盖前会保留旧 state，失败自动恢复）"
            confirm "是否覆盖重建 CDN 链路?" || { print_info "已取消"; pause; return 0; }
        else
            print_warn "检测到旧 CDN state 但校验失败；继续会覆盖它。"
            confirm "是否覆盖旧 CDN state?" || { print_info "已取消"; pause; return 0; }
        fi
    fi
    local had_cdn_link=0 old_cdn_link="" had_cdn_client_json=0 old_cdn_client_json=""
    if [[ -f "$REALITY_CDN_LINK_FILE" ]]; then
        had_cdn_link=1
        old_cdn_link=$(cat "$REALITY_CDN_LINK_FILE" 2>/dev/null || true)
    fi
    if [[ -f "$REALITY_CDN_CLIENT_JSON" ]]; then
        had_cdn_client_json=1
        old_cdn_client_json=$(cat "$REALITY_CDN_CLIENT_JSON" 2>/dev/null || true)
    fi

    echo "  说明：Reality 直连链路（灰云）原样保留；这里新增一条 CDN 链路并存。"
    echo "  CDN 链路用 CF 橙云 + 优选 IP，把「国内→落地IP」被干扰的那跳换成「国内→CF边缘→回源」。"
    echo "  回源用真实证书 Full(strict)；因 Reality 已占 443，CDN 回源走独立端口 ${REALITY_CDN_ORIGIN_PORT}（自动建 CF Origin Rule 改写回源端口）。"
    echo ""

    # CF Token
    local cf_token; cf_token=$(reality_prompt_cf_token)
    [[ -n "$cf_token" ]] || { print_error "CDN 链路需要 CF Token（签证书=DNS-01、橙云 DNS、Origin Rule 都要）。"; pause; return 1; }

    # CDN 域名
    local cdn_domain=""
    while [[ -z "$cdn_domain" ]]; do
        echo -e "${C_CYAN}CDN 链路域名说明:${C_RESET}"
        echo "  这是开启橙云（小云朵）的域名，客户端 host/sni 都填它；server 字段后续由优选 IP 替换。"
        echo "  建议用与 Reality 节点不同的新子域，例如 cdn-us-01。"
        cdn_domain=$(reality_prompt_domain_with_zones "CDN 链路" "$cf_token" "$(hostname)-cdn")
        validate_domain "$cdn_domain" || { print_error "域名无效"; cdn_domain=""; }
    done

    local cdn_name; cdn_name=$(reality_prompt_node_name "cdn-${cdn_domain%%.*}")

    # 内部端口 / WS path
    local inner_port ws_path
    inner_port=$(reality_cdn_pick_inner_port) || { print_error "无法分配内部 WS 端口"; pause; return 1; }
    ws_path=$(reality_cdn_gen_ws_path)
    local origin_port="${REALITY_CDN_ORIGIN_PORT:-8443}"
    validate_port "$origin_port" || { print_error "CDN 回源端口无效: ${origin_port}"; pause; return 1; }
    reality_validate_ws_path "$ws_path" || { print_error "生成的 WS path 无效: ${ws_path}"; pause; return 1; }

    draw_line
    echo "CDN 链路配置确认:"
    echo "  CDN 域名      : ${cdn_domain}（CF 橙云 proxied=true）"
    echo "  回源端口      : ${origin_port}（nginx TLS 终止；CF Origin Rule 改写回源到此端口）"
    echo "  WS 隐秘 path  : ${ws_path}"
    echo "  内部 WS 端口  : 127.0.0.1:${inner_port}（sing-box vless-ws 入站，明文）"
    echo "  节点名称      : ${cdn_name}"
    echo "  将自动执行    : DNS-01 签证书 → 渲染 nginx 回源站 → 合并 WS 入站重渲 sing-box → 橙云 DNS → Origin Rule → 放行 ${origin_port}/tcp"
    draw_line
    confirm "确认开始为该节点加挂 CDN 链路?" || { print_info "已取消"; pause; return 0; }

    # 1) DNS-01 签证书（橙云后面必须 DNS-01，HTTP-01 被橙云拦）
    echo -e "\n${C_CYAN}=== [1] 签发证书 (DNS-01) ===${C_RESET}"
    local cert_dir="${CERT_PATH_PREFIX}/${cdn_domain}"
    local cert_snapshot_dir
    cert_snapshot_dir=$(mktemp -d "${REALITY_CONFIG_DIR%/}/.cdn-cert-rollback.XXXXXX") || { print_error "创建证书回滚快照目录失败"; pause; return 1; }
    chmod 700 "$cert_snapshot_dir" 2>/dev/null || true
    local cert_dir_preexisting=0 cf_cred_preexisting=0 hook_preexisting=0 le_live_preexisting=0 cron_preexisting=0
    if [[ -e "$cert_dir" || -L "$cert_dir" ]]; then
        cert_dir_preexisting=1
        cp -a "$cert_dir" "$cert_snapshot_dir/cert-dir" 2>/dev/null || true
    fi
    local cf_cred hook le_live_dir
    cf_cred="$(reality_cdn_cf_cred_path "$cdn_domain")"
    hook="${CERT_HOOKS_DIR}/renew-${cdn_domain}.sh"
    le_live_dir="$(reality_cdn_le_live_dir "$cdn_domain")"
    if [[ -e "$cf_cred" || -L "$cf_cred" ]]; then
        cf_cred_preexisting=1
        cp -a "$cf_cred" "$cert_snapshot_dir/cf-cred" 2>/dev/null || true
    fi
    if [[ -e "$hook" || -L "$hook" ]]; then
        hook_preexisting=1
        cp -a "$hook" "$cert_snapshot_dir/hook" 2>/dev/null || true
    fi
    if [[ -e "$le_live_dir" || -L "$le_live_dir" ]]; then
        le_live_preexisting=1
        cp -a "$le_live_dir" "$cert_snapshot_dir/le-live" 2>/dev/null || true
    fi
    if command_exists crontab && crontab -l 2>/dev/null | grep -Fq "CertRenew_${cdn_domain}"; then
        cron_preexisting=1
        crontab -l 2>/dev/null > "$cert_snapshot_dir/crontab" || true
    fi
    local cleanup_cert_dir=0 cleanup_cred=0 cleanup_hook=0 cleanup_cron=0 cleanup_le=0
    [[ "$cert_dir_preexisting" -eq 0 ]] && cleanup_cert_dir=1
    [[ "$cf_cred_preexisting" -eq 0 ]] && cleanup_cred=1
    [[ "$hook_preexisting" -eq 0 ]] && cleanup_hook=1
    [[ "$le_live_preexisting" -eq 0 ]] && cleanup_le=1
    mkdir -p "$cert_dir" || { print_error "证书目录创建失败"; pause; return 1; }
    write_private_file_atomic "$cf_cred" "dns_cloudflare_api_token = $cf_token" || { print_error "Cloudflare 凭据写入失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" 0 0 0 0 "$cert_snapshot_dir"; pause; return 1; }
    if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/privkey.pem" ]]; then
        print_info "检测到已有证书，复用: ${cert_dir}"
    else
        print_info "正在申请证书 (DNS 验证，可能 1-2 分钟)..."
        if certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$cf_cred" \
            --dns-cloudflare-propagation-seconds 60 -d "$cdn_domain" \
            --email "$EMAIL" --agree-tos --no-eff-email --non-interactive; then
            copy_cert_pair_atomic "${le_live_dir}/fullchain.pem" "${le_live_dir}/privkey.pem" "$cert_dir" || {
                print_error "证书复制失败"
                reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"
                pause; return 1
            }
            print_success "证书签发成功"
            # 续签 hook：复制证书 + reload nginx
            mkdir -p "$CERT_HOOKS_DIR" || { print_error "续签 Hook 目录创建失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"; pause; return 1; }
            write_file_atomic "$hook" "#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LIVE=${le_live_dir}
CERT_DIR=\"${cert_dir}\"
$(render_cert_pair_hook_helper)
copy_cert_pair_atomic \"\$LIVE/fullchain.pem\" \"\$LIVE/privkey.pem\" \"\$CERT_DIR\" || exit 1
systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
"
            chmod +x "$hook" || { print_error "续签 Hook 授权失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" 0 "$cleanup_le" "$cert_snapshot_dir"; pause; return 1; }
            cron_add_job "CertRenew_${cdn_domain}" "$(( $(echo "$cdn_domain" | cksum | cut -d' ' -f1) % 60 )) 3 * * * certbot renew --quiet --cert-name '${cdn_domain}' --deploy-hook '${hook}' # CertRenew_${cdn_domain}" || {
                print_error "自动续签 cron 配置失败"
                reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
                pause; return 1
            }
            cleanup_cron=1
        else
            print_error "证书申请失败，已中止 CDN 安装。请检查 Token 权限(Zone:DNS Edit)与域名。"
            reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"
            pause; return 1
        fi
    fi

    # 2) nginx 回源站
    echo -e "\n${C_CYAN}=== [2] 部署 nginx 回源站 (端口 ${origin_port}) ===${C_RESET}"
    _ensure_ssl_params
    local nginx_conf
    nginx_conf=$(reality_cdn_render_nginx_conf "$cdn_domain" "$origin_port" "$ws_path" "$inner_port" "$cert_dir") || {
        print_error "渲染 nginx 回源站失败，请检查域名/端口/path。"
        reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    }
    local nginx_site
    nginx_site="$(reality_cdn_nginx_site_name "$cdn_domain")"
    if ! _nginx_deploy_conf "$nginx_site" "$nginx_conf"; then
        print_error "nginx 回源站部署失败，已中止。"
        reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    local nginx_deployed=1
    print_success "nginx 回源站已生效"

    # 3) 写 CDN state 并合并重渲 sing-box（WS 入站随 Reality 一并渲染）
    echo -e "\n${C_CYAN}=== [3] 合并渲染 sing-box（Reality + CDN WS 入站）===${C_RESET}"
    REALITY_CDN_DOMAIN="$cdn_domain"
    REALITY_CDN_UUID="$REALITY_UUID"   # 复用落地 UUID，少记一套；WS 入站无 reality/flow
    REALITY_CDN_WS_PATH="$ws_path"
    REALITY_CDN_INNER_PORT="$inner_port"
    REALITY_CDN_ORIGIN_PORT="$origin_port"
    REALITY_CDN_PREFER_IP=""
    REALITY_CDN_NODE_NAME="$cdn_name"
    if ! reality_cdn_write_state; then
        print_error "写入 CDN state 失败，已中止。"
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 0 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    local new_config
    if ! new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID"); then
        print_error "渲染 sing-box 配置失败，已回滚 CDN state/nginx。"
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    if ! reality_apply_singbox_config "$new_config"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "sing-box 应用失败（已回滚原配置）。已恢复安装前 CDN state，避免后续重渲染误带半成品 WS 入站。"
        pause; return 1
    fi
    print_success "sing-box 已合并 CDN WS 入站"

    # 4) 橙云 DNS
    echo -e "\n${C_CYAN}=== [4] 同步 CF 橙云 DNS ===${C_RESET}"
    if ! reality_cdn_sync_dns_orange "$cdn_domain" "$cf_token"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "橙云 DNS 同步失败，已回滚 CDN 本机配置。请修复 Cloudflare DNS 权限或网络后重试。"
        pause; return 1
    fi

    # 5) Origin Rule：回源端口改写到 origin_port
    echo -e "\n${C_CYAN}=== [5] 设置 CF Origin Rule（回源端口 ${origin_port}）===${C_RESET}"
    if ! reality_cdn_apply_origin_rule "$cdn_domain" "$cf_token" "$origin_port"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "Origin Rule 设置失败，已回滚 CDN 本机配置。未设置时 CF 默认回源 443 会撞到 Reality。"
        pause; return 1
    fi

    # 6) 放行回源端口
    echo -e "\n${C_CYAN}=== [6] 防火墙放行 ${origin_port}/tcp ===${C_RESET}"
    local fw_rc=0
    if declare -F firewall_allow_tcp_port >/dev/null 2>&1; then
        firewall_allow_tcp_port "$origin_port" "CDN-origin"
        fw_rc=$?
        case "$fw_rc" in
            0)
                print_success "已放行 ${origin_port}/tcp"
                ;;
            2)
                print_warn "请确认云安全组已放行 ${origin_port}/tcp（CF 回源需要）。"
                ;;
            *)
                reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
                print_error "防火墙放行 ${origin_port}/tcp 失败，已回滚 CDN 本机配置。"
                print_info "请修复 UFW 后重新执行 CDN 安装。"
                pause; return 1
                ;;
        esac
    else
        print_warn "未找到防火墙放行 helper，请手动确认 ${origin_port}/tcp 已放行。"
    fi

    if ! reality_cdn_write_client_artifacts; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "写入 CDN 客户端产物失败，已回滚 CDN 本机配置。"
        pause; return 1
    fi
    # 不要删 $cf_cred —— certbot 续签(renewal conf 的 dns_cloudflare_credentials)长期依赖它;
    # 它已 chmod 600。仅签发失败分支才删,成功后必须保留,否则证书到期无法自动续签。
    rm -rf -- "$cert_snapshot_dir" 2>/dev/null || true
    draw_line
    print_success "CDN 链路加挂完成！"
    echo "  客户端链接（server 暂为域名，优选后由国内机 B+C 自动替换为优选 IP）:"
    [[ -f "$REALITY_CDN_LINK_FILE" ]] && cat "$REALITY_CDN_LINK_FILE"
    echo ""
    echo "  下一步（B/C，在国内机执行）:"
    echo "   - B: 跑 CloudflareSpeedTest 优选 CF 边缘 IP（必须国内侧跑）"
    echo "   - C: 生成本地节点文件；如启用固定入口模式，则只更新独立 entry 域名的 DNS（host/sni 保留 ${cdn_domain}）"
    echo "   仓库已提供脚本：scripts/cdn-preferip/（见同目录 README）"
    draw_line
    log_action "CDN link installed: domain=$cdn_domain origin_port=$origin_port inner=$inner_port"
    pause
}

# 卸载 CDN 链路：移除 WS 入站（重渲 sing-box）、nginx 回源站、state/产物。
# 不动 Reality 直连链路；CF 橙云 DNS/Origin Rule 提示用户手动清理（避免误删）。
reality_cdn_uninstall() {
    print_title "卸载 CDN 链路"
    reality_cdn_load_state || { print_warn "未发现 CDN 链路配置"; pause; return 0; }
    confirm "确认卸载 CDN 链路 ${REALITY_CDN_DOMAIN:-}? Reality 直连链路不受影响。" || return 0
    local cdn_domain="${REALITY_CDN_DOMAIN:-}" origin_port="${REALITY_CDN_ORIGIN_PORT:-8443}"
    local old_cdn_state
    old_cdn_state=$(cat "$REALITY_CDN_STATE_FILE" 2>/dev/null || true)
    # 先删 state，使重渲不再带 WS 入站
    rm -f "$REALITY_CDN_STATE_FILE"
    if reality_load_state && [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" ]]; then
        local cfg
        if ! cfg=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || \
           ! reality_apply_singbox_config "$cfg"; then
            reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$old_cdn_state" || true
            print_error "sing-box 重渲失败，已恢复 CDN state；未删除 nginx 回源站/产物，避免出现“配置仍生效但 state 丢失”。"
            pause; return 1
        fi
    fi
    # 删 nginx 回源站
    if [[ -n "$cdn_domain" ]]; then
        reality_cdn_remove_nginx_conf "$cdn_domain"
        if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
    fi
    # 回收端口
    if command_exists ufw && ufw_is_active; then ufw delete allow "${origin_port}/tcp" >/dev/null 2>&1 || true; fi
    rm -f "$REALITY_CDN_LINK_FILE" "$REALITY_CDN_CLIENT_JSON"
    print_success "CDN 链路已卸载（WS 入站已移除、nginx 回源站已删）。"
    [[ -n "$cdn_domain" ]] && print_info "如不再使用，请到 CF 后台手动删除 ${cdn_domain} 的橙云 DNS 与 Origin Rule（脚本不自动删，避免误删其它规则）。"
    pause
}

reality_delete_node_info() {
    print_title "删除 Reality 节点信息"
    confirm "确认删除本机 Reality/Realm 管理信息? 不会卸载 sing-box 软件包" || return 0
    reality_load_state || true
    firewall_remove_reality_ports
    systemctl disable --now realm 2>/dev/null || true
    rm -f "$(_reality_realm_service_path)"
    systemctl daemon-reload 2>/dev/null || true
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    if [[ -f "$REALITY_SINGBOX_CONFIG" ]]; then
        systemctl disable --now sing-box 2>/dev/null || true
        rm -f "$REALITY_SINGBOX_CONFIG"
    fi
    rm -f "$(_reality_realm_config_path)"
    rm -f "$REALITY_STATE_FILE" "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" \
          "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6"
    # CDN 链路 state/产物（nginx 回源站与 CF 规则由 reality_cdn_uninstall 处理；此处只清本机管理信息）
    rm -f "$REALITY_CDN_STATE_FILE" "$REALITY_CDN_LINK_FILE" "$REALITY_CDN_CLIENT_JSON"
    # 443 共存：移除 stream 分流配置 + nginx.conf include + coexist state，并 reload nginx 释放 443。
    # 复用 disable_internal（它还会尝试把 sing-box 改回直绑，但下面随即删 state/停服，无副作用）。
    if reality_coexist_enabled 2>/dev/null; then
        reality_coexist_disable_internal
    fi
    # 清理多路中转线路（保留 backups 目录，不 rm -rf 整个配置目录）
    rm -f "$REALITY_RELAY_DIR"/relay-*.conf "$REALITY_RELAY_DIR"/relay-*.link.txt "$REALITY_RELAY_DIR"/relay-*.client.json 2>/dev/null || true
    rmdir "$REALITY_RELAY_DIR" 2>/dev/null || true
    print_success "Reality/Realm 节点信息已删除"
    pause
}

reality_uninstall() {
    reality_delete_node_info
}

reality_info_menu() {
    fix_terminal
    while true; do
        print_title "查看/修改节点信息"
        echo "1. 查看节点信息（含客户端链接）"
        echo "2. 修改节点名称/备注"
        echo "3. 删除节点信息"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_show_info ;;
            2) reality_update_node_name ;;
            3) reality_delete_node_info ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

reality_menu() {
    fix_terminal
    while true; do
        print_title "Sing-box Reality 节点"
        echo "1. 安装/重装落地机"
        echo "2. 中转线路管理（多落地中转）"
        echo "3. 查看/修改节点信息"
        echo "4. 检查服务状态"
        echo "5. 重启服务"
        echo "6. 同步 Cloudflare DNS/DDNS"
        echo "7. 轮换 UUID"
        echo "8. 轮换 Reality Key"
        echo "9. 诊断/自检"
        echo "10. 加挂 CDN 链路（橙云+优选IP，治晚高峰）"
        echo "11. 卸载 CDN 链路"
        if reality_coexist_enabled 2>/dev/null; then
            echo "12. 关闭 443 共存模式（nginx stream 分流）★ 已启用"
        else
            echo "12. 启用 443 共存模式（nginx stream 分流，Reality 与真站共用 443）"
        fi
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_install_wizard --landing ;;
            2) reality_relay_menu ;;
            3) reality_info_menu ;;
            4) reality_status ;;
            5) reality_restart ;;
            6) reality_cf_sync_menu ;;
            7) reality_rotate_user ;;
            8) reality_rotate_key ;;
            9) reality_diagnose ;;
            10) reality_cdn_install ;;
            11) reality_cdn_uninstall ;;
            12) if reality_coexist_enabled 2>/dev/null; then reality_coexist_disable; else reality_coexist_enable; fi ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

reality_cli() {
    local cmd="${1:-install}"; shift || true
    case "$cmd" in
        install) reality_install_wizard "$@" ;;
        info|link) reality_show_info ;;
        status) reality_status ;;
        diagnose|check) reality_diagnose ;;
        restart) reality_restart ;;
        cf-sync) reality_cf_sync_menu ;;
        rotate-user) reality_rotate_user ;;
        rotate-key) reality_rotate_key ;;
        cdn-install|cdn) reality_cdn_install ;;
        cdn-uninstall) reality_cdn_uninstall ;;
        coexist-enable|coexist-on) reality_coexist_enable ;;
        coexist-disable|coexist-off) reality_coexist_disable ;;
        delete|uninstall) reality_delete_node_info ;;
        *) print_error "未知 Reality 命令: $cmd"; return 1 ;;
    esac
}
show_main_menu() {
    fix_terminal
    clear
    local W=76
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+22+W)/2)) "$SCRIPT_NAME $VERSION [OpenWrt]"
    else
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+10+W)/2)) "$SCRIPT_NAME $VERSION"
    fi
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    show_dual_column_sysinfo
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    echo -e " ${C_CYAN}[ 安全防护 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "$(echo -e "${C_GRAY}1. 依赖检查与修复 [不可用]${C_RESET}")" "$(echo -e "${C_GRAY}2. UFW 防火墙 [不可用]${C_RESET}")"
        printf "  %-36s %-36s\n" "$(echo -e "${C_GRAY}3. Fail2ban [不可用]${C_RESET}")"       "$(echo -e "${C_GRAY}4. SSH 管理 [不可用]${C_RESET}")"
    else
        printf "  %-36s %-36s\n" "1. 依赖检查与修复" "2. UFW 防火墙管理"
        printf "  %-36s %-36s\n" "3. Fail2ban 入侵防御" "4. SSH 安全配置"
    fi
    echo -e " ${C_CYAN}[ 系统优化 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "5. 系统优化 (BBR/主机名/时区)" "6. 网络工具 (DNS)"
    else
        printf "  %-36s %-36s\n" "5. 系统优化 (BBR/Swap)" "6. 网络工具 (DNS/测速)"
    fi
    echo -e " ${C_CYAN}[ 网络服务 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "7. Web 服务 (SSL+Nginx+DDNS)" "$(echo -e "${C_GRAY}8. Docker [不可用]${C_RESET}")"
    else
        printf "  %-36s %-36s\n" "7. Web 服务 (SSL+Nginx)" "8. Docker 管理"
    fi
    printf "  %-36s %-36s\n" "9. WireGuard VPN" "10. 临时邮箱 (Cloudflare)"
    printf "  %-36s\n" "11. Sing-box Reality 节点"
    echo -e " ${C_CYAN}[ 维护工具 ]${C_RESET}"
    printf "  %-36s\n" "12. 查看操作日志"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf "  %-36s\n" "0. 退出脚本"
}

menu_opt_openwrt() {
    fix_terminal
    while true; do
        print_title "系统优化 (OpenWrt 精简模式)"
        echo "1. 开启 BBR 加速
2. 修改主机名
3. 修改时区"
        echo -e "${C_GRAY}4. 虚拟内存 Swap [不可用]${C_RESET}"
        echo -e "${C_GRAY}5. 系统垃圾清理 [不可用]${C_RESET}"
        echo "0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_hostname ;;
            3) select_timezone || true; pause ;;
            4) feature_blocked "虚拟内存 Swap" ;;
            5) feature_blocked "系统垃圾清理 (apt)" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
menu_net_openwrt() {
    fix_terminal
    while true; do
        print_title "网络管理工具 (OpenWrt 精简模式)"
        echo "1. DNS 配置"
        echo -e "${C_GRAY}2. IPv4/IPv6 优先级 [不可用]${C_RESET}"
        echo -e "${C_GRAY}3. iPerf3 测速 [不可用]${C_RESET}"
        echo "0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) feature_blocked "IPv4/IPv6 优先级 (需要 /etc/gai.conf)" ;;
            3) feature_blocked "iPerf3 测速" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

main() {
    if [[ "${1:-}" == "--reality" ]]; then
        shift
        check_root
        check_os
        if [[ "$PLATFORM" == "openwrt" ]]; then
            feature_blocked "Sing-box Reality 节点"
            exit 1
        fi
        init_environment
        refresh_ssh_port
        reality_cli "$@"
        exit $?
    fi
    check_root
    check_os
    init_environment
    refresh_ssh_port
    
    while true; do
        show_main_menu
        read -e -r -p "请选择功能 [0-12]: " choice
        case $choice in
            1)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "依赖检查与修复 (apt-get)"
                else
                    menu_update
                fi
                ;;
            2)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "UFW 防火墙 (OpenWrt 请用 LuCI 或 fw4)"
                else
                    menu_ufw
                fi
                ;;
            3)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Fail2ban"
                else
                    menu_f2b
                fi
                ;;
            4)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "SSH 完整管理 (OpenWrt 请用 LuCI 或编辑 /etc/config/dropbear)"
                else
                    menu_ssh
                fi
                ;;
            5)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_opt_openwrt
                else
                    menu_opt
                fi
                ;;
            6)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_net_openwrt
                else
                    menu_net
                fi
                ;;
            7) menu_web ;;
            8)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Docker 管理"
                else
                    menu_docker
                fi
                ;;
            9)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    wg_main_menu
                else
                    wg_deb_main_menu
                fi
                ;;
            10)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "临时邮箱 (需要 Cloudflare)"
                else
                    menu_email
                fi
                ;;
            11)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Sing-box Reality 节点"
                else
                    reality_menu
                fi
                ;;
            12)
                print_title "操作日志 (最近 50 条)"
                if [[ -f "$LOG_FILE" ]]; then
                    tail -n 50 "$LOG_FILE"
                else
                    print_warn "日志文件不存在。"
                fi
                pause
                ;;
            0|q|Q)
                echo ""
                print_success "感谢使用 $SCRIPT_NAME！"
                exit 0
                ;;
            *)
                print_error "无效选项，请重新选择。"
                sleep 1
                ;;
        esac
    done
}
main "$@"
