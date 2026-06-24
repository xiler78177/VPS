#!/bin/bash

readonly VERSION="v14.4"
readonly SCRIPT_NAME="server-manage"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
readonly WG_SHARED_DB_DIR="/etc/wireguard/db"
readonly WG_SHARED_DB_FILE="${WG_SHARED_DB_DIR}/wg-data.json"
readonly WG_SHARED_ROLE_FILE="/etc/wireguard/.role"
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

# 统一设置 sshd_config 的某个 directive：命中则替换，未命中则追加
# 用法: _sshd_set_directive <Key> <Value> [file]
_sshd_set_directive() {
    local key="$1" value="$2" file="${3:-$SSHD_CONFIG}"
    [[ -f "$file" ]] || return 1
    # 检查 drop-in 是否已配置同名 directive（OpenSSH 默认 drop-in 优先生效）
    if [[ -d /etc/ssh/sshd_config.d ]]; then
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
    cron_tmp=$(mktemp) || return 1
    crontab -l 2>/dev/null | grep -Fv -- "$pattern" > "$cron_tmp" || true
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        rm -f "$cron_tmp"
        return 1
    fi
    rm -f "$cron_tmp"
}

cron_add_job() {
    local pattern="$1" line="$2"
    local cron_tmp
    cron_tmp=$(mktemp) || return 1
    crontab -l 2>/dev/null | grep -Fv -- "$pattern" > "$cron_tmp" || true
    echo "$line" >> "$cron_tmp"
    if ! crontab "$cron_tmp" 2>/dev/null; then
        print_error "更新 crontab 失败"
        rm -f "$cron_tmp"
        return 1
    fi
    rm -f "$cron_tmp"
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
    local raw="$1" ip=""
    [[ -z "$raw" ]] && return 1
    ip=$(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    [[ -n "$ip" && "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    echo "$ip"
    return 0
}

# 统一公网 IP 获取函数（使用国内可达的 API）
get_public_ipv4() {
    local raw="" ip="" url=""
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
    fi
}

ddns_create_script() {
    mkdir -p "$DDNS_CONFIG_DIR"
    mkdir -p "$(dirname "$DDNS_UPDATE_SCRIPT")"
        cat > "$DDNS_UPDATE_SCRIPT" << 'EOF'
#!/bin/bash
if command -v flock >/dev/null 2>&1; then
    exec 200>/var/lock/ddns-update.lock
    flock -n 200 || exit 0
else
    mkdir /tmp/ddns-update.lock 2>/dev/null || exit 0
    trap 'rmdir /tmp/ddns-update.lock 2>/dev/null' EXIT
fi
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
DDNS_STAMP_DIR="/var/lib/ddns"
mkdir -p "$DDNS_STAMP_DIR" 2>/dev/null || {
    DDNS_STAMP_DIR="/tmp/ddns-state"
    mkdir -p "$DDNS_STAMP_DIR" 2>/dev/null || true
}
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$DDNS_LOG"; }

extract_ipv4() {
    local raw="$1" ip=""
    [[ -z "$raw" ]] && return 1
    ip=$(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    [[ -n "$ip" && "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    echo "$ip"
    return 0
}

get_ip() {
    local raw="" ip="" url=""
    if [[ "$1" == "4" ]]; then
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
    local fown fmode
    fown=$(stat -c '%U' "$conf" 2>/dev/null || echo "")
    fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
    if [[ "$fown" != "root" ]]; then
        log "owner 非 root，跳过: $conf (owner=$fown)"
        return 1
    fi
    if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
        log "权限过宽，跳过: $conf (mode=$fmode)"
        return 1
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL)=\"([^\"\$\`\\]*)\"$ ]]; then
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
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    return 0
}

ddns_should_run() {
    local conf="$1" interval="${DDNS_INTERVAL:-5}" now last="" stamp_name stamp
    [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 1 && "$interval" -le 59 ]] || interval=5
    stamp_name=$(basename "$conf" | sed 's/[^A-Za-z0-9_.-]/_/g')
    stamp="$DDNS_STAMP_DIR/${stamp_name}.stamp"
    now=$(date +%s)
    [[ -f "$stamp" ]] && read -r last < "$stamp" || true
    if [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < interval * 60 )); then
        return 1
    fi
    printf '%s\n' "$now" > "$stamp" 2>/dev/null || true
    return 0
}

for conf in "$DDNS_CONFIG_DIR"/*.conf; do
    [ -f "$conf" ] || continue
    parse_ddns_conf "$conf" || continue
    ddns_should_run "$conf" || continue
    [[ "$DDNS_IPV4" == "true" ]] && { ip=$(get_ip 4); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" A "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
    [[ "$DDNS_IPV6" == "true" ]] && { ip=$(get_ip 6); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" AAAA "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
done
EOF
    chmod +x "$DDNS_UPDATE_SCRIPT"
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
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\""
    write_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    chmod 600 "$DDNS_CONFIG_DIR/${domain}.conf"
    ddns_create_script
    ddns_rebuild_cron
    print_success "DDNS 已启用 (每 ${interval} 分钟检测)"
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

ddns_setup_noninteractive() {
    local domain=$1 token=$2 zone_id=$3 ipv4=${4:-true} ipv6=${5:-false} proxied=${6:-false} interval=${7:-5}
    [[ -z "$domain" || -z "$token" || -z "$zone_id" ]] && return 1
    if [[ ! "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 || "$interval" -gt 59 ]]; then
        interval=5
    fi
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\""
    write_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    chmod 600 "$DDNS_CONFIG_DIR/${domain}.conf"
    ddns_create_script
    ddns_rebuild_cron
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

# 顶层（交互菜单）安全解析 conf：与生成脚本 ddns-update.sh 内嵌的同名解析器逻辑一致，
# 但诊断走顶层的 log_action（heredoc 里的 log 仅存在于生成脚本中）。
# ddns_list / ddns_delete 复用本函数——与本文件 get_public_ipv4(顶层)/get_ip(生成脚本) 的双份模式一致。
parse_ddns_conf() {
    local conf="$1" line key val
    local fown fmode
    fown=$(stat -c '%U' "$conf" 2>/dev/null || echo "")
    fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
    if [[ "$fown" != "root" ]]; then
        log_action "DDNS 解析跳过：owner 非 root: $conf (owner=$fown)"
        return 1
    fi
    if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
        log_action "DDNS 解析跳过：权限过宽: $conf (mode=$fmode)"
        return 1
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL)=\"([^\"\$\`\\]*)\"$ ]]; then
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
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    return 0
}

ddns_list() {
    print_title "DDNS 配置列表"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无 DDNS 配置"; pause; return; }
    printf "${C_CYAN}%-30s %-6s %-6s %-8s %s${C_RESET}\n" "域名" "IPv4" "IPv6" "代理" "间隔"
    draw_line
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID="" DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
        parse_ddns_conf "$conf" || continue
        printf "%-30s %-6s %-6s %-8s %s\n" "$DDNS_DOMAIN" \
            "$([[ "$DDNS_IPV4" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_IPV6" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_PROXIED" == "true" ]] && echo "开启" || echo "关闭")" \
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
        "$DDNS_UPDATE_SCRIPT"
        print_success "更新完成"
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
    local ip="$1" cache_file="$2" lock_file="${cache_file}.lock"
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
ufw_setup() {
    install_package "ufw"
    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行，请先禁用它。"
        return
    fi
    refresh_ssh_port
    local _ssh_port
    for _ssh_port in $CURRENT_SSH_PORTS; do
        validate_port "$_ssh_port" || { print_error "无法确认当前 SSH 端口，拒绝启用 UFW"; pause; return 1; }
    done
    print_info "配置默认规则..."
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    for _ssh_port in $CURRENT_SSH_PORTS; do
        ufw allow "$_ssh_port/tcp" comment "SSH-Access" >/dev/null
    done
    if confirm "启用 UFW 可能导致 SSH 断开(若端口配置错误)，确认启用?"; then
        echo "y" | ufw enable
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
        local _ssh_port
        for _ssh_port in $CURRENT_SSH_PORTS; do
            validate_port "$_ssh_port" || { print_error "无法确认当前 SSH 端口，拒绝重置 UFW"; pause; return 1; }
        done
        echo "y" | ufw disable >/dev/null
        echo "y" | ufw reset >/dev/null
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        for _ssh_port in $CURRENT_SSH_PORTS; do
            ufw allow "$_ssh_port/tcp" comment "SSH-Access" >/dev/null
        done
        echo "y" | ufw enable >/dev/null
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
    GEOIP_MODE="" GEOIP_COUNTRIES="" GEOIP_LAST_UPDATE=""
    [[ -f "$GEOIP_CONF" ]] && validate_conf_file "$GEOIP_CONF" && source "$GEOIP_CONF"
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
    local total_entries=0 total6_entries=0
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
    # Atomic swap
    ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
    if ! ipset swap "$tmp_set" "$set_name"; then
        print_error "GeoIP ipset swap 失败，保留旧集合。"
        ipset destroy "$tmp_set" 2>/dev/null || true
        return 1
    fi
    ipset destroy "$tmp_set" 2>/dev/null || true
    if command_exists ip6tables; then
        ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null || ipset flush "$tmp6_set" || return 1
        for cc in $countries; do
            local f6="${GEOIP_DATA_DIR}/${cc,,}.zone6"
            [[ -f "$f6" ]] || continue
            if ! sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null; then
                print_error "GeoIP 写入 IPv6 ipset 失败: ${cc}"
                ipset destroy "$tmp6_set" 2>/dev/null || true
                return 1
            fi
        done
        ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
        if ! ipset swap "$tmp6_set" "$set6_name"; then
            print_error "GeoIP IPv6 ipset swap 失败，保留旧集合。"
            ipset destroy "$tmp6_set" 2>/dev/null || true
            return 1
        fi
        ipset destroy "$tmp6_set" 2>/dev/null || true
        if [[ "$total6_entries" -le 0 ]]; then
            print_warn "GeoIP IPv6 数据为空；白名单模式将默认拦截公网 IPv6。"
        fi
    fi
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
    # Apply script (runs on boot)
    cat > /usr/local/bin/geoip-apply.sh << 'APPLY_EOF'
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
ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set" || exit 1
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
done
ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
ipset swap "$tmp_set" "$set_name" || { ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
ipset destroy "$tmp_set" 2>/dev/null || true
if command -v ip6tables >/dev/null 2>&1; then
    ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null || ipset flush "$tmp6_set" || exit 1
    for cc in $GEOIP_COUNTRIES; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
        f6="${DATA}/${cc,,}.zone6"
        [ -f "$f6" ] || continue
        sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp6_set" 2>/dev/null || true; exit 1; }
    done
    ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
    ipset swap "$tmp6_set" "$set6_name" || { ipset destroy "$tmp6_set" 2>/dev/null || true; exit 1; }
    ipset destroy "$tmp6_set" 2>/dev/null || true
fi
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
    chmod 700 /usr/local/bin/geoip-apply.sh
    # Update script (cron weekly)
    cat > /usr/local/bin/geoip-update.sh << 'UPDATE_EOF'
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
sed -i "s/^GEOIP_LAST_UPDATE=.*/GEOIP_LAST_UPDATE=\"$(date +%Y-%m-%d)\"/" "$CONF"
UPDATE_EOF
    chmod 700 /usr/local/bin/geoip-update.sh
    # Systemd boot service
    if is_systemd; then
        cat > /etc/systemd/system/geoip-firewall.service << 'SVC_EOF'
[Unit]
Description=GeoIP Firewall Rules
After=network.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/geoip-apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
        systemctl daemon-reload
        systemctl enable geoip-firewall >/dev/null 2>&1
    fi
    # Weekly cron (Sunday 04:00)
    cron_add_job "geoip-update.sh" "0 4 * * 0 /usr/local/bin/geoip-update.sh >/dev/null 2>&1"
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
    mkdir -p "$GEOIP_CONF_DIR"
    cat > "$GEOIP_CONF" << EOF
GEOIP_MODE="$mode"
GEOIP_COUNTRIES="$countries"
GEOIP_LAST_UPDATE="$(date +%Y-%m-%d)"
EOF
    chmod 600 "$GEOIP_CONF"
    _geoip_install_persistence
    print_success "GeoIP 规则已生效！"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单" || echo "黑名单")"
    echo "  国家: $countries"
    echo "  IP段: ${total} 条"
    echo "  自动更新: 每周日 04:00"
    log_action "GeoIP configured: mode=$mode countries=$countries entries=$total"
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
        sed -i "s/^GEOIP_LAST_UPDATE=.*/GEOIP_LAST_UPDATE=\"$(date +%Y-%m-%d)\"/" "$GEOIP_CONF"
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
    rm -f /usr/local/bin/geoip-apply.sh /usr/local/bin/geoip-update.sh
    cron_remove_job "geoip-update.sh"
    if is_systemd; then
        systemctl disable geoip-firewall 2>/dev/null || true
        rm -f /etc/systemd/system/geoip-firewall.service
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
        local old_f2b_rules=$(ufw status numbered 2>/dev/null | grep -ciE "f2b|fail2ban")
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
    write_file_atomic "$FAIL2BAN_JAIL_LOCAL" "$conf_content"
    print_success "配置已写入: $FAIL2BAN_JAIL_LOCAL (banaction=$banaction)"
    
    # 配置预检
    if command_exists fail2ban-client; then
        if ! fail2ban-client -d >/dev/null 2>&1; then
            print_error "Fail2ban 配置校验失败！请检查配置。"
            echo "运行 fail2ban-client -d 查看详情"
            pause; return
        fi
        print_success "配置校验通过"
    fi
    if is_systemd; then
        systemctl enable fail2ban >/dev/null || true
        if systemctl restart fail2ban; then
            print_success "Fail2ban 已启动 (banaction=$banaction)。"
            log_action "Fail2ban configured: port=$port, maxretry=$maxretry, bantime=$bantime, banaction=$banaction"
        else
            print_error "Fail2ban 启动失败！"
            echo "请检查日志: journalctl -u fail2ban -n 20"
            log_action "Fail2ban configuration failed" "ERROR"
        fi
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
    fail2ban-client status "$jail" 2>/dev/null | awk -F: '/Banned IP/ {print $2}' | xargs
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
    local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ')
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
        local status_out=$(fail2ban-client status "$jail" 2>/dev/null)
        local cur_banned=$(echo "$status_out" | grep "Currently banned" | awk '{print $NF}')
        local total_banned=$(echo "$status_out" | grep "Total banned" | awk '{print $NF}')
        local banned_ips=$(echo "$status_out" | grep "Banned IP" | cut -d: -f2 | xargs)
        echo "  当前封禁: ${cur_banned:-0} | 累计封禁: ${total_banned:-0}"
        if [[ -n "$banned_ips" && "$banned_ips" != " " ]]; then
            echo "  封禁 IP: $banned_ips"
        fi
    done
    unset IFS
    # Show ignoreip if configured
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        local ignore=$(grep '^ignoreip' "$FAIL2BAN_JAIL_LOCAL" | cut -d= -f2 | xargs)
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
    local jails_raw=$(fail2ban-client status 2>/dev/null | grep "Jail list" | cut -d: -f2 | tr -d ' ')
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
                local banned_count=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $NF}')
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
        local socket_dropin_dir="/etc/systemd/system/${socket_unit}.d"
        socket_dropin="${socket_dropin_dir}/server-manage-port.conf"
        mkdir -p "$socket_dropin_dir"
        if [[ -f "$socket_dropin" ]]; then
            socket_backup="${socket_dropin}.bak.$(date +%s)"
            cp "$socket_dropin" "$socket_backup"
        else
            socket_created=1
        fi
        cat > "$socket_dropin" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${port}
ListenStream=[::]:${port}
EOF
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 先放行新端口（防止改完连不上）
    local ufw_opened=0 firewall_opened_backends=""
    if ufw_is_active; then
        ufw allow "$port/tcp" comment "SSH-New" >/dev/null
        ufw_opened=1
        print_success "UFW 已放行新端口 $port。"
    else
        if declare -F firewall_prepare_non_ufw_ssh_port >/dev/null; then
            if ! firewall_prepare_non_ufw_ssh_port "$port" "SSH-New"; then
                print_error "无法确认本地防火墙已放行新 SSH 端口，拒绝继续修改以避免失联。"
                print_info "请先手动放行 ${port}/tcp（云安全组 + 本机防火墙），再重试。"
                pause; return
            fi
            firewall_opened_backends="$FIREWALL_SSH_OPEN_BACKENDS"
        else
            print_warn "未找到非 UFW 防火墙检测 helper；请确认云安全组/iptables/nftables 已放行 ${port}/tcp。"
            if ! confirm "仍要继续修改 SSH 端口？"; then
                pause; return
            fi
        fi
    fi

    # 写入端口配置
    if grep -qE "^\s*#?\s*Port\s" "$target_conf"; then
        sed -i -E "s|^\s*#?\s*Port\s+.*|Port ${port}|" "$target_conf"
    else
        printf '\n# server-manage: appended Port\nPort %s\n' "$port" >> "$target_conf"
    fi

    # 校验配置语法
    if ! sshd -t 2>/dev/null; then
        print_error "sshd 配置校验失败！已回滚。"
        mv "$backup_file" "$target_conf"
        if [[ -n "$socket_unit" ]]; then
            if [[ -n "$socket_backup" ]]; then mv "$socket_backup" "$socket_dropin" 2>/dev/null || true; elif [[ $socket_created -eq 1 ]]; then rm -f "$socket_dropin"; fi
            systemctl daemon-reload 2>/dev/null || true
        fi
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        pause; return
    fi

    if ! _restart_sshd; then
        print_error "重启失败！已回滚配置。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        if [[ -n "$socket_unit" ]]; then
            if [[ -n "$socket_backup" ]]; then mv "$socket_backup" "$socket_dropin" 2>/dev/null || true; elif [[ $socket_created -eq 1 ]]; then rm -f "$socket_dropin"; fi
            systemctl daemon-reload 2>/dev/null || true
        fi
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
        if [[ -n "$socket_unit" ]]; then
            if [[ -n "$socket_backup" ]]; then mv "$socket_backup" "$socket_dropin" 2>/dev/null || true; elif [[ $socket_created -eq 1 ]]; then rm -f "$socket_dropin"; fi
            systemctl daemon-reload 2>/dev/null || true
        fi
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
        echo "$key" >> "$dir/authorized_keys"
        chmod 700 "$dir"; chmod 600 "$dir/authorized_keys"
        chown -R "$user:$user" "$dir"
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
                local tmp_ak grep_rc
                tmp_ak=$(mktemp "$(dirname "$ak")/.tmp.server-manage.authorized-keys.XXXXXX") || { print_error "创建临时文件失败"; pause; return; }
                _tmp_register "$tmp_ak"
                grep -Fvx -- "$target_key" "$ak" > "$tmp_ak"
                grep_rc=$?
                if [[ $grep_rc -gt 1 ]]; then
                    rm -f "$tmp_ak"
                    _tmp_unregister "$tmp_ak"
                    print_error "删除失败"
                    pause; return
                fi
                cat "$tmp_ak" > "$ak" || { rm -f "$tmp_ak"; _tmp_unregister "$tmp_ak"; print_error "写入失败"; pause; return; }
                rm -f "$tmp_ak"
                _tmp_unregister "$tmp_ak"
                chmod 600 "$ak"
                chown "$user:$user" "$ak" 2>/dev/null || true
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
                echo "$pub_key" >> "$imp_dir/authorized_keys"
                chmod 700 "$imp_dir"; chmod 600 "$imp_dir/authorized_keys"
                chown -R "$imp_user:$imp_user" "$imp_dir"
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
    local old_name=$(hostname 2>/dev/null)
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
        hostname "$new_name" || { print_error "临时主机名设置失败。"; pause; return 1; }
        echo "$new_name" > /etc/hostname || { print_error "/etc/hostname 写入失败。"; pause; return 1; }
    fi

    # 安全替换 /etc/hosts 中的旧主机名
    if [[ -n "$old_name" && "$old_name" != "$new_name" ]] && grep -qF "$old_name" /etc/hosts 2>/dev/null; then
        local escaped_old=$(printf '%s\n' "$old_name" | sed 's/[.[\*^$/]/\\&/g')
        local escaped_new=$(printf '%s\n' "$new_name" | sed 's/[&/\]/\\&/g')
        sed -i "s/\b${escaped_old}\b/${escaped_new}/g" /etc/hosts
    elif ! grep -q "$new_name" /etc/hosts 2>/dev/null; then
        sed -i "s/^127\.0\.0\.1\s\+localhost.*/127.0.0.1 localhost ${new_name}/" /etc/hosts
    fi
    print_success "主机名已修改为: $new_name"
    log_action "Hostname changed to $new_name"
    pause
}

opt_swap() {
    print_title "Swap 管理"
    local size=$(free -m | awk '/Swap/ {print $2}')
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
        swapoff /swapfile 2>/dev/null || true
        rm -f /swapfile
        # 检测文件系统类型，btrfs 不支持 fallocate 创建 swap
        local fs_type=$(df -T / 2>/dev/null | awk 'NR==2{print $2}')
        if [[ "$fs_type" == "btrfs" ]]; then
            truncate -s 0 /swapfile
            chattr +C /swapfile 2>/dev/null || true
            if ! dd if=/dev/zero of=/swapfile bs=1M count="$s" status=progress; then
                print_error "创建 Swap 文件失败 (磁盘空间不足?)"; rm -f /swapfile; pause; return
            fi
        elif ! fallocate -l "${s}M" /swapfile 2>/dev/null; then
            if ! dd if=/dev/zero of=/swapfile bs=1M count="$s" status=progress; then
                print_error "创建 Swap 文件失败 (磁盘空间不足?)"; rm -f /swapfile; pause; return
            fi
        fi
        chmod 600 /swapfile
        if ! mkswap /swapfile >/dev/null; then
            print_error "mkswap 失败"; rm -f /swapfile; pause; return
        fi
        if ! swapon /swapfile; then
            print_error "swapon 失败"; rm -f /swapfile; pause; return
        fi
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
        print_success "Swap 设置成功。"
        log_action "Swap configured: ${s}MB"
    elif [[ "$c" == "2" ]]; then
        if confirm "确认删除 Swap？"; then
            swapoff -a 2>/dev/null || true
            rm -f /swapfile
            sed -i '/\/swapfile/d' /etc/fstab
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
    echo "当前配置:"
    echo "  拥塞控制: $current_cc"
    echo "  队列算法: $current_qdisc"
    if [[ "$current_cc" == "bbr" ]]; then
        print_success "BBR 已启用。"
        pause; return
    fi
    if confirm "开启 BBR 加速？"; then
        [[ ! -f /etc/sysctl.conf.bak ]] && cp /etc/sysctl.conf /etc/sysctl.conf.bak
        sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
        sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        if sysctl -p >/dev/null 2>&1; then
            local verify_cc
            verify_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
            if [[ "$verify_cc" == "bbr" ]]; then
                print_success "BBR 已开启。"
                log_action "BBR enabled"
            else
                print_error "BBR 未实际生效 (当前: $verify_cc)，请检查内核是否支持。"
                log_action "BBR enable failed: verify_cc=$verify_cc" "ERROR"
            fi
        else
            print_error "sysctl -p 执行失败，BBR 未应用。"
            log_action "BBR enable failed: sysctl -p" "ERROR"
        fi
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

opt_sysctl() {
    print_title "内核参数调优"
    echo -e "${C_CYAN}当前关键参数:${C_RESET}"
    printf "  %-40s %s\n" "net.core.somaxconn" "$(sysctl -n net.core.somaxconn 2>/dev/null)"
    printf "  %-40s %s\n" "fs.file-max" "$(sysctl -n fs.file-max 2>/dev/null)"
    printf "  %-40s %s\n" "net.ipv4.tcp_max_syn_backlog" "$(sysctl -n net.ipv4.tcp_max_syn_backlog 2>/dev/null)"
    printf "  %-40s %s\n" "net.ipv4.tcp_tw_reuse" "$(sysctl -n net.ipv4.tcp_tw_reuse 2>/dev/null)"
    echo ""
    echo -e "${C_CYAN}选择预设方案:${C_RESET}"
    echo "  1. 代理/隧道场景 (WireGuard/Xray 等，高并发连接)"
    echo "  2. Web 服务器场景 (Nginx 反代，优化 HTTP 并发)"
    echo "  3. 保守方案 (仅基础优化，适合小内存机器)"
    echo "  4. 回滚到备份 (恢复修改前的配置)"
    echo "  0. 返回"
    read -e -r -p "选择: " sc
    [[ "$sc" == "0" || -z "$sc" ]] && return
    if [[ "$sc" == "4" ]]; then
        if [[ -f /etc/sysctl.conf.pre-tuning ]]; then
            cp /etc/sysctl.conf.pre-tuning /etc/sysctl.conf
            sysctl -p >/dev/null 2>&1
            print_success "已回滚到调优前的配置。"
            log_action "Sysctl tuning rolled back"
        else
            print_warn "没有找到备份文件。"
        fi
        pause; return
    fi
    # Backup before modifying
    [[ ! -f /etc/sysctl.conf.pre-tuning ]] && cp /etc/sysctl.conf /etc/sysctl.conf.pre-tuning
    local params=""
    local block_start="# BEGIN server-manage sysctl tuning"
    local block_end="# END server-manage sysctl tuning"
    case $sc in
    1)
        params="${block_start}: proxy/tunnel
fs.file-max = 1048576
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_max_tw_buckets = 32768
net.ipv4.tcp_syncookies = 1
net.ipv4.ip_forward = 1
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
${block_end}"
        ;;
    2)
        params="${block_start}: web server
fs.file-max = 524288
net.core.somaxconn = 8192
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_tw_buckets = 65536
${block_end}"
        ;;
    3)
        params="${block_start}: conservative
fs.file-max = 262144
net.core.somaxconn = 2048
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
${block_end}"
        ;;
    *) print_error "无效选择"; pause; return ;;
    esac
    # Remove old tuning block and append new. 旧版本没有 END 标记，保留兼容删除。
    sed -i '/^# BEGIN server-manage sysctl tuning/,/^# END server-manage sysctl tuning/d; /^# server-manage sysctl tuning/,/^$/d' /etc/sysctl.conf
    printf '\n%s\n' "$params" >> /etc/sysctl.conf
    if sysctl -p >/dev/null 2>&1; then
        print_success "内核参数已应用 (无需重启)。"
        log_action "Sysctl tuning applied: preset=$sc"
    else
        print_error "sysctl -p 执行失败，请检查 /etc/sysctl.conf"
    fi
    pause
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
    read -e -r -p "监听端口 [5201]: " port
    port=${port:-5201}
    if ! validate_port "$port"; then
        print_error "端口无效。"
        pause; return
    fi
    local ufw_opened=0
        if ufw_is_active; then
        if ! ufw status 2>/dev/null | grep -q "$port/tcp"; then
            ufw allow "$port/tcp" comment "iPerf3-Temp" >/dev/null
            ufw_opened=1
            print_info "临时放行端口 $port"
        fi
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
    iperf3 -s -p "$port" &
    local iperf_pid=$!
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
        uci delete "network.${dns_iface}.dns" 2>/dev/null || true
        for ip in $dns; do
            uci add_list "network.${dns_iface}.dns=$ip" || { print_error "写入 OpenWrt DNS 失败: $ip"; pause; return 1; }
        done
        uci set "network.${dns_iface}.peerdns=0" || { print_error "设置 OpenWrt peerdns 失败"; pause; return 1; }
        uci commit network || { print_error "提交 OpenWrt network 配置失败"; pause; return 1; }
        /etc/init.d/network reload 2>/dev/null || true
        print_success "DNS 已通过 uci 修改 (接口: ${dns_iface}, 持久化)。"
    elif is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        local res_conf="/etc/systemd/resolved.conf"
        grep -q '^\[Resolve\]' "$res_conf" || echo -e "\n[Resolve]" >> "$res_conf"
        sed -i '/^DNS=/d' "$res_conf"
        sed -i '/^\[Resolve\]/a DNS='"$dns" "$res_conf"
        systemctl restart systemd-resolved
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
                        [[ ! -f /etc/gai.conf ]] && touch /etc/gai.conf
                        sed -i '/^#\?precedence ::ffff:0:0\/96  100/d' /etc/gai.conf
                        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
                        print_success "IPv4 优先。"
                        log_action "IP priority changed: ipv4"
                        pause
                        ;;
                    2)
                        [[ ! -f /etc/gai.conf ]] && touch /etc/gai.conf
                        sed -i '/^#\?precedence ::ffff:0:0\/96  100/d' /etc/gai.conf
                        print_success "IPv6 优先。"
                        log_action "IP priority changed: ipv6"
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

_web_dep_verify() {
    local name="$1" check_cmd="$2"
    if eval "$check_cmd" >/dev/null 2>&1; then
        _web_dep_check_results+=("${C_GREEN}✓${C_RESET} $name")
        return 0
    else
        _web_dep_check_results+=("${C_RED}✗${C_RESET} $name")
        return 1
    fi
}

_web_dep_fix() {
    local name="$1" check_cmd="$2" install_func="$3"
    if ! eval "$check_cmd" >/dev/null 2>&1; then
        print_info "修复: $name ..."
        if eval "$install_func"; then
            if eval "$check_cmd" >/dev/null 2>&1; then
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
        rm -f /usr/bin/certbot /snap/bin/certbot 2>/dev/null || true
        if [[ $(snap list 2>/dev/null | tail -n +2 | wc -l) -eq 0 ]]; then
            print_info "snap 中无其他软件包，清理 snapd..."
            systemctl stop snapd snapd.socket 2>/dev/null || true
            apt-get purge -y snapd 2>/dev/null || true
            rm -rf /snap /var/snap /var/lib/snapd ~/snap 2>/dev/null || true
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

    if [[ -n "$version" ]] && {
        (( major > 1 )) ||
        (( major == 1 && minor > 25 )) ||
        (( major == 1 && minor == 25 && patch >= 1 ))
    }; then
        printf '    listen %s ssl;\n' "$port"
        printf '    listen [::]:%s ssl;\n' "$port"
        printf '    http2 on;\n'
    else
        printf '    listen %s ssl %s;\n' "$port" "http2"
        printf '    listen [::]:%s ssl %s;\n' "$port" "http2"
    fi
}

# Nginx 配置部署（写入 + 测试 + 加载，失败自动回滚）
# 用法: _nginx_deploy_conf "域名" "配置内容" 成功返回0，失败返回1
_nginx_deploy_conf() {
    local domain="$1" conf_content="$2"
    local avail="/etc/nginx/sites-available/${domain}.conf"
    local enabled="/etc/nginx/sites-enabled/${domain}.conf"
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
    ln -sfn "$avail" "$enabled" || { print_error "启用 Nginx 配置失败"; rm -f "$backup_avail" "$backup_enabled"; return 1; }

    if nginx -t >/dev/null 2>&1 && _nginx_reload; then
        rm -f "$backup_avail" "$backup_enabled"
        return 0
    fi

    print_error "Nginx 配置测试或重载失败，正在恢复旧配置！"
    nginx -t 2>&1 | tail -5
    rm -f "$enabled"
    if [[ "$had_enabled" -eq 1 ]]; then
        if [[ "$enabled_was_symlink" -eq 1 && -n "$old_enabled_target" ]]; then
            ln -s "$old_enabled_target" "$enabled"
        elif [[ -n "$backup_enabled" && -e "$backup_enabled" ]]; then
            mv "$backup_enabled" "$enabled"
        fi
    fi
    if [[ "$had_avail" -eq 1 && -n "$backup_avail" && -e "$backup_avail" ]]; then
        mv "$backup_avail" "$avail"
    else
        rm -f "$avail"
    fi
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
        "jq|command_exists jq|install_package jq silent"
        "nginx|command_exists nginx|_install_nginx"
        "nginx 目录结构|_check_nginx_dirs|mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets"
        "certbot|command_exists certbot|_install_certbot"
        "certbot dns-cloudflare 插件|_check_certbot_dns_cf|_install_certbot_dns_cf"
    )

    # 第一轮: 检查
    _web_dep_check_results=()
    local need_fix=0
    for dep in "${deps[@]}"; do
        IFS='|' read -r name check_cmd install_func <<< "$dep"
        if ! _web_dep_verify "$name" "$check_cmd"; then
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
            IFS='|' read -r name check_cmd install_func <<< "$dep"
            if ! _web_dep_fix "$name" "$check_cmd" "$install_func"; then
                fix_failed=1
            fi
        done

        # 第三轮: 最终验证
        if [[ $fix_failed -eq 1 ]]; then
            print_error "部分依赖修复失败，最终验证:"
            local final_ok=1
            for dep in "${deps[@]}"; do
                IFS='|' read -r name check_cmd install_func <<< "$dep"
                if eval "$check_cmd" >/dev/null 2>&1; then
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
    local cleaned=0

    # Certbot 证书
    if certbot certificates 2>/dev/null | grep -q "$domain"; then
        certbot delete --cert-name "$domain" --non-interactive 2>/dev/null && cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "证书已删除"
    fi
    # 本地证书拷贝
    rm -rf "${CERT_PATH_PREFIX:?}/${domain}" 2>/dev/null

    # Nginx 配置
    local ng_en="/etc/nginx/sites-enabled/${domain}.conf"
    local ng_av="/etc/nginx/sites-available/${domain}.conf"
    if [[ -f "$ng_en" || -f "$ng_av" ]]; then
        rm -f "$ng_en" "$ng_av"
        nginx -t >/dev/null 2>&1 && _nginx_reload 2>/dev/null
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "Nginx 配置已删除"
    fi

    # Hook 脚本
    local hook="${CERT_HOOKS_DIR}/renew-${domain}.sh"
    [[ ! -f "$hook" ]] && hook="/root/cert-renew-hook-${domain}.sh"
    if [[ -f "$hook" ]]; then
        rm -f "$hook"; cleaned=$((cleaned+1))
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
    sleep 0.3
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
    local resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
    if ! _cf_api_ok "$resp"; then
        print_error "读取 DNS 记录失败: $(_cf_api_err "$resp")"
        return 1
    fi
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    [[ -n "$rid" ]] || return 0
    _cf_api DELETE "/zones/$zone_id/dns_records/$rid" "$token" >/dev/null
}

# 通用 DNS 记录更新
_cf_update_dns_record() {
    local zone_id="$1" token="$2" domain="$3" type="$4" ip="$5" proxied="$6"
    [[ -z "$ip" ]] && return 0
    print_info "处理 $type 记录 -> $ip (代理: $proxied)"
    local records=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain" "$token")
    if ! _cf_api_ok "$records"; then
        print_error "读取 $type 记录失败: $(_cf_api_err "$records")"
        return 1
    fi
    local record_id=$(jq -r '.result[0].id // empty' <<< "$records")
    local count=$(jq -r '.result | length' <<< "$records")
    [[ "$count" -gt 1 ]] && print_warn "警告: 存在 ${count} 条 $type 记录，仅更新第一条。建议手动清理多余记录。"
    local data=$(jq -n --arg type "$type" --arg name "$domain" --arg content "$ip" --argjson proxied "$proxied" \
        '{type:$type, name:$name, content:$content, ttl:1, proxied:$proxied}')
    local resp
    if [[ -n "$record_id" ]]; then
        resp=$(_cf_api PUT "/zones/$zone_id/dns_records/$record_id" "$token" --data "$data")
    else
        resp=$(_cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$data")
    fi
    if _cf_api_ok "$resp"; then
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
    # 选择 IPv6 但未检测到时给予提示
    if [[ ("$mode" == "2" || "$mode" == "3") && -z "$ipv6" ]]; then
        print_warn "未检测到 IPv6 地址，AAAA 记录将跳过"
    fi
    if [[ ("$mode" == "1" || "$mode" == "3") && -z "$ipv4" ]]; then
        print_warn "未检测到 IPv4 地址，A 记录将跳过"
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
        1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied" ;;
        2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" ;;
        3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied"
           _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" ;;
    esac
    print_success "DNS 配置完成。"
    log_action "Cloudflare DNS updated for $DOMAIN"
    local ddns_v4=$([[ "$mode" == "1" || "$mode" == "3" ]] && echo "true" || echo "false")
    local ddns_v6=$([[ "$mode" == "2" || "$mode" == "3" ]] && echo "true" || echo "false")
    ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_v4" "$ddns_v6" "$proxied"
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
    local payload=$(jq -n \
        --argjson rules "$rules_json" \
        '{ "rules": $rules }')
    local resp=$(curl -s -X PUT "$url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        --data "$payload")
    if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
        return 0
    else
        echo "$resp" | jq -r '.errors[0].message // "未知错误"'
        return 1
    fi
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

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    web_env_check || { pause; return; }

    # 配置收集阶段
    echo -e "\n${C_CYAN}=== 收集配置信息 ===${C_RESET}\n"

    # 1. CF API Token
    local CF_API_TOKEN=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 -> My Profile -> API Tokens -> Create Token${C_RESET}"
    if ! _cf_read_token "CF_API_TOKEN"; then
        pause; return
    fi

    # 2. 选择域名 (自动列出 Token 可管理的域名)
    print_info "获取 Token 可管理的域名列表..."
    local zones_json zone_list=() zone_ids=()
    zones_json=$(_cf_list_zones "$CF_API_TOKEN" "status=active")
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

    # ── DNS 解析 ──
    if [[ "$dns_mode" != "0" ]]; then
        echo -e "\n${C_CYAN}=== [${step}] DNS 解析 ===${C_RESET}"
        case $dns_mode in
            1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied" ;;
            2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
            3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied"
               _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
        esac
        ((step++))
    fi

    # ── SSL 证书 ──
    echo -e "\n${C_CYAN}=== [${step}] SSL 证书申请 ===${C_RESET}"
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    local CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
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
        cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_dir/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir/privkey.pem"
        chmod 644 "$cert_dir/fullchain.pem"
        chmod 600 "$cert_dir/privkey.pem"
        ((step++))

        # ── Nginx 反向代理 ──
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}=== [${step}] Nginx 反向代理 ===${C_RESET}"
            _ensure_ssl_params
            local redir_port=""
            [[ "$NGINX_HTTPS_PORT" != "443" ]] && redir_port=":${NGINX_HTTPS_PORT}"
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
                pause; return
            fi
            print_success "Nginx 配置已生效"
            ((step++))

            # ── 防火墙 ──
            echo -e "\n${C_CYAN}=== [${step}] 防火墙 ===${C_RESET}"
            if ufw_is_active; then
                ufw allow "$NGINX_HTTP_PORT/tcp" comment "Nginx-HTTP" >/dev/null 2>&1 || true
                ufw allow "$NGINX_HTTPS_PORT/tcp" comment "Nginx-HTTPS" >/dev/null 2>&1 || true
                print_success "防火墙规则已更新"
            else
                print_info "UFW 未启用，跳过"
            fi
            ((step++))
        fi

        # ── 证书自动续签 ──
        echo -e "\n${C_CYAN}=== [${step}] 证书自动续签 ===${C_RESET}"
        mkdir -p "$CERT_HOOKS_DIR"
        local DEPLOY_HOOK_SCRIPT="${CERT_HOOKS_DIR}/renew-${DOMAIN}.sh"
        local hook_content="#!/bin/bash
# Auto-generated renewal hook for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=\"$DOMAIN\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"
echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

# Copy certificates
if [[ -f \"\${LETSENCRYPT_LIVE}/fullchain.pem\" ]]; then
    cp -L \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${CERT_DIR}/fullchain.pem\"
    cp -L \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}/privkey.pem\"
    chmod 644 \"\${CERT_DIR}/fullchain.pem\"
    chmod 600 \"\${CERT_DIR}/privkey.pem\"
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
        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content"
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        local cron_tag="CertRenew_${DOMAIN}"
        local cron_minute=$(( $(echo "$DOMAIN" | cksum | cut -d' ' -f1) % 60 ))
        cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${DOMAIN}' --deploy-hook '${DEPLOY_HOOK_SCRIPT}' # ${cron_tag}"
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
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "$config_content"
        ((step++))

        # ── DDNS 动态解析 ──
        if [[ "$dns_mode" != "0" ]]; then
            echo -e "\n${C_CYAN}=== [${step}] DDNS 动态解析 ===${C_RESET}"
            local ddns_ipv4="false" ddns_ipv6="false"
            [[ "$dns_mode" == "1" || "$dns_mode" == "3" ]] && ddns_ipv4="true"
            [[ "$dns_mode" == "2" || "$dns_mode" == "3" ]] && ddns_ipv6="true"
            ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "$dns_proxied"
        fi

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
        rm -f "$CLOUDFLARE_CREDENTIALS"
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
    _web_cleanup_domain "$target_domain"
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
                mkdir -p "$cert_dir"
                cp -L "$custom_cert" "$cert_dir/fullchain.pem"
                cp -L "$custom_key" "$cert_dir/privkey.pem"
                chmod 644 "$cert_dir/fullchain.pem"
                chmod 600 "$cert_dir/privkey.pem"
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
    
    # 确保 SSL 参数文件存在
    _ensure_ssl_params
    local redir_port=""
    [[ "$HTTPS_PORT" != "443" ]] && redir_port=":${HTTPS_PORT}"
    
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
    
    # 防火墙规则
    if ufw_is_active; then
        ufw allow "$HTTP_PORT/tcp" comment "ReverseProxy-HTTP" >/dev/null 2>&1 || true
        ufw allow "$HTTPS_PORT/tcp" comment "ReverseProxy-HTTPS" >/dev/null 2>&1 || true
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
    cp "$target_conf" "${target_conf}.bak"
    local tmp_conf
    tmp_conf=$(mktemp "${target_conf}.tmp.XXXXXX") || { print_error "创建临时配置失败"; pause; return; }
    if ! _replace_proxy_pass_backend "$new_backend" "$target_conf" > "$tmp_conf"; then
        rm -f "$tmp_conf"
        print_error "更新配置失败"
        pause; return
    fi
    mv "$tmp_conf" "$target_conf"
    if nginx -t >/dev/null 2>&1; then
        _nginx_reload
        rm -f "${target_conf}.bak"
        print_success "反向代理后端已更新: ${target_domain}"
        echo -e "  ${current_backend} → ${C_GREEN}${new_backend}${C_RESET}"
    else
        mv "${target_conf}.bak" "$target_conf"
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
    local https_port=""
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
    echo -e "  HTTPS 端口:   ${C_GREEN}${https_port}${C_RESET} (Nginx 对外监听)"
    echo -e "  DDNS 间隔:    ${C_GREEN}${ddns_interval} 分钟${C_RESET}"
    echo -e "  加速模式:     ${C_GREEN}CF CDN 代理${C_RESET} (A 记录 + Proxied)"
    echo ""
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    local auto_step=1
    echo -e "    ${auto_step}. DNS 解析 -> ${full_domain} -> ${public_ip} (CF 代理)"; ((auto_step++))
    echo -e "    ${auto_step}. SSL 证书申请 (Let's Encrypt DNS 验证)"; ((auto_step++))
    echo -e "    ${auto_step}. Nginx 反向代理 (:${https_port} -> ${backend_addr})"; ((auto_step++))
    echo -e "    ${auto_step}. DDNS 自动更新 (每 ${ddns_interval} 分钟)"; ((auto_step++))
    echo -e "    ${auto_step}. 防火墙放行端口 ${https_port}"; ((auto_step++))
    [[ "$https_port" != "443" ]] && { echo -e "    ${auto_step}. CF Origin Rule (用户 :443 -> 回源 :${https_port})"; ((auto_step++)); }
    echo ""
    echo -e "  ${C_YELLOW}[手动操作提醒]${C_RESET}"
    echo -e "  ${C_YELLOW}  请确保路由器 (OpenWrt/爱快等) 已做端口转发:${C_RESET}"
    echo -e "  ${C_YELLOW}  外网 ${https_port}/TCP -> 内网运行 Nginx 的设备IP:${https_port}/TCP${C_RESET}"
    if [[ "$backend_addr" != 127.0.0.1:* ]]; then
        echo -e "  ${C_YELLOW}  后端服务在其他设备 (${backend_addr})，请确保内网互通${C_RESET}"
    fi
    draw_line
    if ! confirm "确认开始执行?"; then
        print_warn "已取消"; pause; return
    fi

    # Phase 2: 自动执行
    local step=1 total_steps=5
    [[ "$https_port" != "443" ]] && total_steps=$((total_steps + 1))

    # Step: DNS 解析
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DNS 解析 ===${C_RESET}"
    # 重新配置时可能残留旧 CNAME，CF 不允许同名 A/CNAME 共存，需先清除
    _cf_dns_delete "$zone_id" "$token" "CNAME" "$full_domain" >/dev/null 2>&1
    print_info "创建 A 记录: ${full_domain} -> ${public_ip} (开启 CF 代理)"
    if ! _cf_update_dns_record "$zone_id" "$token" "$full_domain" "A" "$public_ip" "true"; then
        print_error "DNS 记录创建失败"
        pause; return
    fi
    ((step++))

    # Step: SSL 证书
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] SSL 证书申请 ===${C_RESET}"
    local cert_dir="${CERT_PATH_PREFIX}/${full_domain}"
    mkdir -p "$cert_dir"
    local cf_cred="/root/.cloudflare-${full_domain}.ini"
    write_file_atomic "$cf_cred" "dns_cloudflare_api_token = $token"
    chmod 600 "$cf_cred"
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
        cp -L "/etc/letsencrypt/live/${full_domain}/fullchain.pem" "$cert_dir/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${full_domain}/privkey.pem" "$cert_dir/privkey.pem"
        chmod 644 "$cert_dir/fullchain.pem"
        chmod 600 "$cert_dir/privkey.pem"
        print_success "证书获取成功"
    else
        print_error "证书申请失败！请检查 Token 权限和网络"
        rm -f "$cf_cred"
        pause; return
    fi
    ((step++))

    # Step: Nginx 反向代理
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] Nginx 反向代理 ===${C_RESET}"
    _ensure_ssl_params
    local redir_port=""
    [[ "$https_port" != "443" ]] && redir_port=":${https_port}"
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
        pause; return
    fi
    print_success "Nginx 已部署 (:${https_port} -> ${backend_addr})"
    ((step++))

    # Step: DDNS
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DDNS 动态解析 ===${C_RESET}"
    local ddns_domain="$full_domain"
    local ddns_proxied="true"
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN="${ddns_domain}"
DDNS_TOKEN="${token}"
DDNS_ZONE_ID="${zone_id}"
DDNS_IPV4="true"
DDNS_IPV6="false"
DDNS_PROXIED="${ddns_proxied}"
DDNS_INTERVAL="${ddns_interval}""
    write_file_atomic "$DDNS_CONFIG_DIR/${ddns_domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; pause; return; }
    chmod 600 "$DDNS_CONFIG_DIR/${ddns_domain}.conf"
    ddns_create_script
    ddns_rebuild_cron
    print_success "DDNS 已配置: ${ddns_domain} (每 ${ddns_interval} 分钟)"
    ((step++))

    # Step: 防火墙
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] 防火墙 ===${C_RESET}"
    if ufw_is_active; then
        ufw allow "${https_port}/tcp" comment "HomeExpose-${full_domain}" >/dev/null 2>&1 || true
        print_success "已放行端口 ${https_port}/tcp"
    else
        print_info "UFW 未启用，跳过 (请确保服务器防火墙已放行 ${https_port})"
    fi
    ((step++))

    # Step: Origin Rule (端口非 443 时)
    if [[ "$https_port" != "443" ]]; then
        echo -e "\n${C_CYAN}=== [${step}/${total_steps}] CF Origin Rule (端口回源) ===${C_RESET}"
        print_info "创建回源规则: 用户访问 :443 -> CF 回源 :${https_port}"
        local existing
        if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
            print_warn "Origin Rules 读取失败，已跳过自动创建，避免覆盖该 Zone 的既有回源规则。"
            print_warn "可稍后通过菜单 [10.创建回源规则] 手动添加"
            ((step++))
        else
            local existing_rules="[]"
            if [[ -n "$existing" ]]; then
                existing_rules=$(echo "$existing" | jq '.result.rules // []')
            fi
            # 移除同域名旧规则
        local filtered_rules=$(echo "$existing_rules" | jq --arg d "$full_domain" \
            '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]')
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
            }')
        local final_rules=$(echo "$filtered_rules" | jq --argjson new "$new_rule" '. + [$new]')
        local err
            if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules"); then
                print_warn "Origin Rule 创建失败: $err"
                print_warn "可稍后通过菜单 [10.创建回源规则] 手动添加"
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

if [[ -f \"\${LETSENCRYPT_LIVE}/fullchain.pem\" ]]; then
    cp -L \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${CERT_DIR}/fullchain.pem\"
    cp -L \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}/privkey.pem\"
    chmod 644 \"\${CERT_DIR}/fullchain.pem\"
    chmod 600 \"\${CERT_DIR}/privkey.pem\"
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
    write_file_atomic "$hook_script" "$hook_content"
    chmod +x "$hook_script"

    # Crontab 自动续签
    local cron_tag="CertRenew_${full_domain}"
    local cron_minute=$(( $(echo "$full_domain" | cksum | cut -d' ' -f1) % 60 ))
    cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${full_domain}' --deploy-hook '${hook_script}' # ${cron_tag}"

    # 域名管理配置文件
    cat > "${CONFIG_DIR}/${full_domain}.conf" << CONFEOF
# Domain configuration for ${full_domain}
# Generated by $SCRIPT_NAME $VERSION (web_home_expose)
DOMAIN="${full_domain}"
CERT_PATH="${cert_dir}"
DEPLOY_HOOK_SCRIPT="${hook_script}"
CLOUDFLARE_CREDENTIALS="${cf_cred}"
NGINX_HTTP_PORT="80"
NGINX_HTTPS_PORT="${https_port}"
LOCAL_PROXY_PASS="http://${backend_addr}"
HOME_EXPOSE="true"
CONFEOF

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
    [[ "$https_port" != "443" ]] && \
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
    echo -e "    外网 ${C_GREEN}${https_port}${C_RESET}/TCP -> 运行 Nginx 的设备IP:${C_GREEN}${https_port}${C_RESET}/TCP"
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
# 精确清除: 遍历查找并删除匹配的 domain 条目
idx=0
while uci -q get dhcp.@domain[\$idx] >/dev/null 2>&1; do
    name=\$(uci -q get dhcp.@domain[\$idx].name 2>/dev/null)
    if [ \"\$name\" = '${full_domain}' ]; then
        uci delete dhcp.@domain[\$idx]
    else
        idx=\$((idx + 1))
    fi
done
# 添加新记录
uci add dhcp domain
uci set dhcp.@domain[-1].name='${full_domain}'
uci set dhcp.@domain[-1].ip='${nginx_ip}'
uci commit dhcp
/etc/init.d/dnsmasq restart
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
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "$keyring_dir"
    local docker_gpg="$keyring_dir/docker.gpg"
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local docker_repo_os="${os_id}"
    [[ "$docker_repo_os" != "ubuntu" && "$docker_repo_os" != "debian" ]] && docker_repo_os="debian"
    if [[ ! -f "$docker_gpg" ]]; then
        print_info "添加 Docker GPG 密钥..."
        # 根据实际系统选择正确的官方仓库 OS；非 Debian/Ubuntu 系回退到 debian 时，
        # GPG URL 与 apt source 必须保持一致。
        if ! curl -fsSL "https://download.docker.com/linux/${docker_repo_os}/gpg" | gpg --dearmor -o "$docker_gpg" 2>/dev/null; then
            print_error "GPG 密钥下载失败。"
            pause; return
        fi
        chmod a+r "$docker_gpg"
    fi
    local version_codename=$(grep 'VERSION_CODENAME' /etc/os-release | cut -d= -f2)
    if [[ -z "$version_codename" ]]; then
        version_codename=$(grep 'UBUNTU_CODENAME' /etc/os-release | cut -d= -f2)
    fi
    if [[ -z "$version_codename" ]]; then
        print_error "无法检测系统版本代号，Docker 源配置可能失败。"
        print_info "请手动安装 Docker: https://docs.docker.com/engine/install/"
        pause; return
    fi
    local docker_list="/etc/apt/sources.list.d/docker.list"
    if [[ ! -f "$docker_list" ]]; then
        print_info "添加 Docker 软件源..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=$docker_gpg] https://download.docker.com/linux/${docker_repo_os} $version_codename stable" > "$docker_list"
    fi
    apt-get update -qq 2>/dev/null || true
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then
        print_success "Docker 安装成功。"
        if is_systemd; then
            systemctl enable docker >/dev/null 2>&1 || true
            systemctl start docker || true
        fi
        docker --version
        log_action "Docker installed"
    else
        print_error "Docker 安装失败。"
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
    local tmp_bin tmp_sha hash
    tmp_bin=$(mktemp /tmp/docker-compose.XXXXXX) || { print_error "创建临时文件失败"; pause; return; }
    tmp_sha=$(mktemp /tmp/docker-compose.sha256.XXXXXX) || { rm -f "$tmp_bin"; print_error "创建临时文件失败"; pause; return; }
    if curl -fL --retry 3 "$compose_url" -o "$tmp_bin" 2>/dev/null \
        && curl -fL --retry 3 "${compose_url}.sha256" -o "$tmp_sha" 2>/dev/null \
        && hash=$(awk '{print $1; exit}' "$tmp_sha") \
        && [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] \
        && printf '%s  %s\n' "$hash" "$tmp_bin" | sha256sum -c - >/dev/null; then
        install -m 0755 "$tmp_bin" /usr/local/bin/docker-compose
        print_success "Docker Compose Standalone 安装成功。"
        docker-compose --version
        log_action "Docker Compose standalone installed"
    else
        print_error "下载失败。"
    fi
    rm -f "$tmp_bin" "$tmp_sha"
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
            mkdir -p "$DOCKER_PROXY_DIR"
            local proxy_conf="[Service]
Environment=\"HTTP_PROXY=$proxy\"
Environment=\"HTTPS_PROXY=$proxy\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy\"
Environment=\"https_proxy=$proxy\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
            write_file_atomic "$DOCKER_PROXY_CONF" "$proxy_conf"
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            print_success "Docker 代理已配置。"
            log_action "Docker proxy configured: $proxy"
            ;;
        2)
            rm -f "$DOCKER_PROXY_CONF"
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
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
                docker image prune -a -f
                print_success "清理完成。"
                log_action "Docker unused images pruned"
            fi
            ;;
        3)
            if confirm "删除所有镜像？这将影响所有容器！"; then
                local all_images=$(docker images -q)
                if [[ -n "$all_images" ]]; then
                    docker rmi -f $all_images
                    print_success "所有镜像已删除。"
                    log_action "Docker all images removed"
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
                else
                    print_error "停止失败"
                fi
                log_action "Docker all containers stopped"
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
                else
                    print_error "删除失败"
                fi
                log_action "Docker all containers removed"
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
                    docker rm -f "$target_id" && print_success "已删除: $target_name" || print_error "删除失败"
                    log_action "Docker container removed: $target_name"
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
                        docker system prune -a -f --volumes
                        print_success "清理完成。"
                        log_action "Docker system pruned"
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
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
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

wg_shared_db_init() {
    mkdir -p "$WG_SHARED_DB_DIR"
    [[ -f "$WG_SHARED_DB_FILE" ]] && return 0
    cat > "$WG_SHARED_DB_FILE" << 'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "client": {}
}
WGEOF
    chmod 600 "$WG_SHARED_DB_FILE"
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
            mv "$tmp" "$WG_SHARED_DB_FILE"; chmod 600 "$WG_SHARED_DB_FILE"
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
    echo "$1" > "$WG_SHARED_ROLE_FILE"
    chmod 600 "$WG_SHARED_ROLE_FILE"
    wg_shared_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_db_init() { wg_shared_db_init; }
wg_db_get() { wg_shared_db_get "$@"; }
wg_db_set() { wg_shared_db_set "$@"; }
wg_get_role() { wg_shared_get_role; }
wg_set_role() { wg_shared_set_role "$@"; }

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

    # --- 清除旧 uci peer 条目 ---
    while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
        uci delete network.@wireguard_wg0[0]
    done

    # --- 设置 wg0 接口基本参数 ---
    uci set network.wg0=interface
    uci set network.wg0.proto='wireguard'
    uci set network.wg0.private_key="$priv_key"
    uci -q delete network.wg0.addresses 2>/dev/null
    uci add_list network.wg0.addresses="${server_ip}/${mask}"
    uci set network.wg0.listen_port="$port"
    uci set network.wg0.mtu="$mtu"
    uci set network.wg0.route_allowed_ips='1'

    # --- 遍历 enabled peers，创建 uci wireguard_wg0 section ---
    local pc=$(wg_db_get '.peers | length') i=0
    while [[ $i -lt $pc ]]; do
        if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
            local peer_name=$(wg_db_get ".peers[$i].name")
            local pub_key=$(wg_db_get ".peers[$i].public_key")
            local psk=$(wg_db_get ".peers[$i].preshared_key")
            local peer_ip=$(wg_db_get ".peers[$i].ip")
            local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
            local lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty")

            uci add network wireguard_wg0 >/dev/null
            local idx_uci
            # 获取刚添加的 section 索引（最后一个）
            idx_uci=$(( $(uci show network | grep -c 'wireguard_wg0') / 5 - 1 ))
            [[ $idx_uci -lt 0 ]] && idx_uci=0

            uci set network.@wireguard_wg0[-1].description="$peer_name"
            uci set network.@wireguard_wg0[-1].public_key="$pub_key"
            uci set network.@wireguard_wg0[-1].preshared_key="$psk"
            uci set network.@wireguard_wg0[-1].persistent_keepalive='25'

            # AllowedIPs
            uci -q delete network.@wireguard_wg0[-1].allowed_ips 2>/dev/null
            uci add_list network.@wireguard_wg0[-1].allowed_ips="${peer_ip}/32"
            if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                local IFS=','
                for sub in $lan_sub; do
                    sub=$(echo "$sub" | xargs)
                    [[ -n "$sub" ]] && uci add_list network.@wireguard_wg0[-1].allowed_ips="$sub"
                done
                unset IFS
            fi
        fi
        i=$((i + 1))
    done

    uci commit network

    # --- 非 peer 热应用路径仍允许重启接口；peer 操作传 no_reload 后用 wg syncconf 热同步 ---
    if wg_is_running && [[ "$apply_mode" != "no_reload" ]]; then
        ifdown wg0 2>/dev/null
        sleep 1
        ifup wg0 2>/dev/null
        sleep 1
        wg_sync_peer_routes
    fi
}

wg_apply_runtime_conf() {
    wg_rebuild_conf || return 1
    wg_is_running || return 0
    local tmp
    tmp=$(mktemp "/tmp/${SCRIPT_NAME}-wg-sync.XXXXXX") || return 1
    awk '
        /^\[Interface\]$/ { section="interface"; print; next }
        /^\[Peer\]$/ { section="peer"; print; next }
        section=="interface" && /^(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
        section=="peer" && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
    ' "$WG_CONF" > "$tmp"
    if wg syncconf "$WG_INTERFACE" "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        wg_sync_peer_routes
        return 0
    fi
    rm -f "$tmp"
    return 1
}

# 同步网关 peer 的 LAN 路由到内核路由表
# (部分 OpenWrt 固件的 proto-wireguard 不支持 route_allowed_ips，需手动添加)
wg_sync_peer_routes() {
    wg_is_running || return 0
    local pc=$(wg_db_get '.peers | length') i=0
    while [[ $i -lt ${pc:-0} ]]; do
        if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
            local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
            local lans=$(wg_db_get ".peers[$i].lan_subnets // empty")
            if [[ "$is_gw" == "true" && -n "$lans" && "$lans" != "null" ]]; then
                local IFS_BAK="$IFS"; IFS=','
                for sub in $lans; do
                    sub=$(echo "$sub" | xargs)
                    [[ -n "$sub" ]] && ip route replace "$sub" dev "$WG_INTERFACE" 2>/dev/null || true
                done
                IFS="$IFS_BAK"
            fi
        fi
        i=$((i + 1))
    done
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
    local old_umask _rc
    old_umask=$(umask)
    umask 077
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
    } > "$WG_CONF"
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    chmod 600 "$WG_CONF"
}

wg_regenerate_client_confs() {
    local pc=$(wg_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport sdns mask mtu
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
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
Endpoint = ${sep}:${sport}
AllowedIPs = $(wg_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        write_file_atomic "/etc/wireguard/clients/${name}.conf" "$conf_content"
        chmod 600 "/etc/wireguard/clients/${name}.conf"
        i=$((i + 1))
    done
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

    # ── [3/7] 配置 IP 转发 ──
    print_info "[3/7] 配置 IP 转发..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    print_success "IP 转发已开启"

    # ── [4/7] 配置服务端参数 ──
    print_info "[4/7] 配置服务端参数..."

    local wg_port listen_addr mtu wg_dns wg_endpoint
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
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
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

    # ── [6/7] 写入数据库 + 配置 OpenWrt 网络和防火墙 ──
    print_info "[6/7] 写入配置..."
    wg_db_init
    wg_set_role "server"
    wg_db_set --arg sname "$server_name" \
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
    } | .schema_version = 2'

    # 配置 uci 网络接口
    print_info "配置 OpenWrt 网络接口..."
    local wg_mask
    wg_mask=$(echo "$wg_subnet" | cut -d'/' -f2)
    uci set network.wg0=interface
    uci set network.wg0.proto='wireguard'
    uci set network.wg0.private_key="$server_privkey"
    uci -q delete network.wg0.addresses 2>/dev/null
    uci add_list network.wg0.addresses="${server_ip}/${wg_mask}"
    uci set network.wg0.listen_port="$wg_port"
    uci set network.wg0.mtu="$mtu"
    uci set network.wg0.route_allowed_ips='1'

    # 配置 uci 防火墙 zone + forwarding
    print_info "配置 OpenWrt 防火墙..."
    uci set firewall.wg_zone=zone
    uci set firewall.wg_zone.name='wg'
    uci set firewall.wg_zone.input='ACCEPT'
    uci set firewall.wg_zone.output='ACCEPT'
    uci set firewall.wg_zone.forward='ACCEPT'
    uci set firewall.wg_zone.masq='1'
    uci -q delete firewall.wg_zone.network 2>/dev/null
    uci add_list firewall.wg_zone.network='wg0'
    uci set firewall.wg_fwd_lan=forwarding
    uci set firewall.wg_fwd_lan.src='lan'
    uci set firewall.wg_fwd_lan.dest='wg'
    uci set firewall.wg_fwd_wg=forwarding
    uci set firewall.wg_fwd_wg.src='wg'
    uci set firewall.wg_fwd_wg.dest='lan'

    uci commit network
    uci commit firewall

    # nft 实时放行 WG UDP 端口 (不重启防火墙)
    nft insert rule inet fw4 input_wan udp dport "$wg_port" counter accept comment \"wg_allow_port\" 2>/dev/null || true
    # uci 持久化防火墙端口放行规则
    uci set firewall.wg_allow_port=rule
    uci set firewall.wg_allow_port.name='Allow-WG-UDP'
    uci set firewall.wg_allow_port.src='wan'
    uci set firewall.wg_allow_port.dest_port="$wg_port"
    uci set firewall.wg_allow_port.proto='udp'
    uci set firewall.wg_allow_port.target='ACCEPT'
    uci commit firewall

    # 生成只读快照 wg0.conf
    wg_rebuild_conf

    # ── [7/7] Mihomo bypass + 启动 ──
    print_info "[7/7] 配置 Mihomo bypass 并启动..."
    wg_setup_mihomo_bypass "$wg_subnet"
    ifup wg0 2>/dev/null
    sleep 2
    wg_sync_peer_routes

    # ── 安装结果展示 ──
    draw_line
    if wg_is_running; then
        print_success "WireGuard 服务端安装并启动成功！"
    else
        print_warn "WireGuard 已安装，但启动可能失败，请检查日志"
    fi
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
    local changed=false lan_changed=false

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            wg_db_set --argjson p "$new_port" '.server.port = $p'
            changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
            new_port="$cur_port"
        fi
    fi

    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        wg_db_set --arg d "$new_dns" '.server.dns = $d'
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        wg_db_set --arg e "$new_ep" '.server.endpoint = $e'
        changed=true
        print_info "端点将更改为 ${new_ep}"
    fi

    read -e -r -p "新服务端 LAN 子网 [${cur_lan:-无}]: " new_lan
    new_lan=${new_lan:-$cur_lan}
    if [[ "$new_lan" != "$cur_lan" ]]; then
        if ! validate_cidr_list "$new_lan"; then
            print_warn "LAN 子网格式无效，保持原值"
            new_lan="$cur_lan"
        else
            wg_db_set --arg l "$new_lan" '.server.server_lan_subnet = $l'
            changed=true
            lan_changed=true
            print_info "LAN 子网将更改为 ${new_lan}"
        fi
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi

    if [[ "$lan_changed" == "true" ]]; then
        _wg_update_peer_routes
        wg_mihomo_bypass_rebuild 2>/dev/null || true
    fi

    wg_rebuild_uci_conf
    wg_rebuild_conf
    wg_regenerate_client_confs

    # 端口变更: 更新 nft 防火墙规则 + uci 持久化
    if [[ "$new_port" != "$cur_port" ]]; then
        # 删除旧端口 nft 规则
        local h
        for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
            nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
        done
        # 添加新端口 nft 规则
        nft insert rule inet fw4 input_wan udp dport "$new_port" counter accept comment \"wg_allow_port\" 2>/dev/null || true
        # 更新 uci 持久化
        uci set firewall.wg_allow_port.dest_port="$new_port"
        uci commit firewall
        # 更新 /etc/rc.local
        sed -i '/wg_allow_port/d' /etc/rc.local 2>/dev/null || true
        if grep -q "^exit 0" /etc/rc.local 2>/dev/null; then
            sed -i "/^exit 0/i nft insert rule inet fw4 input_wan udp dport $new_port counter accept comment \\\"wg_allow_port\\\" 2>/dev/null || true" \
                /etc/rc.local 2>/dev/null || true
        else
            echo "nft insert rule inet fw4 input_wan udp dport $new_port counter accept comment \"wg_allow_port\" 2>/dev/null || true" >> /etc/rc.local
        fi
    fi

    # LAN 子网或端口变更都需要重建 bypass (因为 bypass 包含所有子网)
    if [[ "$new_port" != "$cur_port" || "${new_lan:-}" != "${cur_lan:-}" ]]; then
        wg_mihomo_bypass_rebuild
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
    else
        print_error "启动失败，请检查 logread | grep netifd"
        log_action "WireGuard start failed"
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
    else
        print_error "停止失败"
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
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
    fi
}

# ── Mihomo bypass 函数 ──

_wg_rc_local_insert_block() {
    local rc_block="${1:-}" rc_file="${2:-/etc/rc.local}"
    [[ -n "$rc_block" ]] || return 1
    local tmp_block tmp_out
    tmp_block=$(mktemp "/tmp/${SCRIPT_NAME}-wg-rc-block.XXXXXX") || return 1
    tmp_out=$(mktemp "/tmp/${SCRIPT_NAME}-wg-rc-local.XXXXXX") || { rm -f "$tmp_block"; return 1; }
    if [[ ! -f "$rc_file" ]]; then
        printf '#!/bin/sh\nexit 0\n' > "$rc_file" 2>/dev/null || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        chmod +x "$rc_file" 2>/dev/null || true
    fi
    printf '%b\n' "$rc_block" > "$tmp_block"
    if awk '
        FNR == NR { block = block $0 ORS; next }
        /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?$/ && !inserted { printf "%s", block; inserted=1 }
        { print }
        END { if (!inserted) printf "%s", block }
    ' "$tmp_block" "$rc_file" > "$tmp_out"; then
        cat "$tmp_out" > "$rc_file"
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
    local cidr
    for cidr in "${unique_subnets[@]}"; do
        nft insert rule inet fw4 mangle_prerouting ip daddr "$cidr" counter return comment \"wg_bypass_subnet\" 2>/dev/null || true
    done

    # 持久化到 /etc/rc.local
    sed -i '/wg_bypass/d; /WireGuard bypass/d; /wg_peer_route/d' /etc/rc.local 2>/dev/null || true
    local rc_block="# WireGuard bypass Mihomo\nnft insert rule inet fw4 mangle_prerouting iifname \\\"wg0\\\" counter return comment \\\"wg_bypass_iface\\\" 2>/dev/null || true"
    for cidr in "${unique_subnets[@]}"; do
        rc_block="${rc_block}\nnft insert rule inet fw4 mangle_prerouting ip daddr \\\"${cidr}\\\" counter return comment \\\"wg_bypass_subnet\\\" 2>/dev/null || true"
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
    # 清理 wg_allow_port
    for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
    # 清理 /etc/rc.local 中的持久化条目
    sed -i '/wg_bypass/d; /wg_allow_port/d; /wg_peer_route/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null || true
}

wg_mihomo_bypass_rebuild() {
    local wg_subnet wg_port
    wg_subnet=$(wg_db_get '.server.subnet')
    wg_port=$(wg_db_get '.server.port')
    [[ -z "$wg_subnet" || "$wg_subnet" == "null" ]] && return 1

    wg_setup_mihomo_bypass "$wg_subnet"

    # 重建端口放行规则
    if [[ -n "$wg_port" && "$wg_port" != "null" ]]; then
        # 先清理旧的 nft 规则
        local h
        for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
            nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
        done
        nft insert rule inet fw4 input_wan udp dport "$wg_port" counter accept comment \"wg_allow_port\" 2>/dev/null || true
        # 持久化到 /etc/rc.local
        sed -i '/wg_allow_port/d' /etc/rc.local 2>/dev/null || true
        local rc_block="nft insert rule inet fw4 input_wan udp dport ${wg_port} counter accept comment \\\"wg_allow_port\\\" 2>/dev/null || true"
        _wg_rc_local_insert_block "$rc_block" || print_warn "写入 /etc/rc.local 端口放行规则失败"
        # uci 持久化防火墙规则
        if ! uci -q get firewall.wg_allow_port &>/dev/null; then
            uci set firewall.wg_allow_port=rule
            uci set firewall.wg_allow_port.name='Allow-WG-UDP'
            uci set firewall.wg_allow_port.src='wan'
            uci set firewall.wg_allow_port.dest_port="$wg_port"
            uci set firewall.wg_allow_port.proto='udp'
            uci set firewall.wg_allow_port.target='ACCEPT'
            uci commit firewall
        fi
    fi
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
    _wg_ifaces=$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | tr -d ' ')
    if [[ -z "$_wg_ifaces" ]]; then
        _wg_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^wg[0-9_-]|^wg_' | tr -d ' ')
    fi
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
    uci commit network 2>/dev/null || true
    uci commit firewall 2>/dev/null || true

    print_info "[3/6] 清理 Mihomo bypass 和 nft 规则..."
    wg_mihomo_bypass_clean
    # 旧版 prio 100 策略路由没有可验证标记，不能粗暴删除第三方规则。

    print_info "[4/6] 清理看门狗和定时任务..."
    if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
        cron_remove_job "wg-watchdog.sh"
    fi
    rm -f /usr/bin/wg-watchdog.sh /usr/local/bin/wg-watchdog.sh /var/log/wg-watchdog.log 2>/dev/null || true

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
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
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
ifdown wg0 2>/dev/null; true
ifdown wg_mesh 2>/dev/null; true
for iface in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'); do
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
(crontab -l 2>/dev/null | grep -v wg-watchdog) | crontab - 2>/dev/null; true
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
sed -i '/wg_bypass/d; /wg_allow_port/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true

# === 提交配置 ===
uci commit network
uci commit firewall

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
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)

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

    # ── 生成客户端配置文件 ──
    local spub sep sport sdns mask
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')
    mask=$(echo "$server_subnet" | cut -d'/' -f2)
    local dns_line=""
    [[ "$is_gateway" != "true" ]] && dns_line="DNS = ${sdns}"
    local client_conf="[Interface]
PrivateKey = ${peer_privkey}
Address = ${peer_ip}/${mask}
${dns_line}
[Peer]
PublicKey = ${spub}
PresharedKey = ${psk}
Endpoint = ${sep}:${sport}
AllowedIPs = ${client_allowed_ips}
PersistentKeepalive = 25"
    client_conf=$(echo "$client_conf" | sed '/^$/N;/^\n$/d')
    mkdir -p /etc/wireguard/clients
    local conf_file="/etc/wireguard/clients/${peer_name}.conf"
    write_file_atomic "$conf_file" "$client_conf"
    chmod 600 "$conf_file"

    # ── 写入数据库 ──
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    wg_db_set --arg name "$peer_name" \
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
    }]'

    # ── 网关设备: 联动更新其他 peer 的 allowed_ips ──
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        _wg_update_peer_routes
    fi

    # ── 重建配置并应用 ──
    wg_rebuild_uci_conf "no_reload"
    wg_apply_runtime_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
    wg_regenerate_client_confs

    # 网关 peer 添加/删除会改变 LAN 子网列表，需重建 Mihomo bypass
    if [[ "$is_gateway" == "true" ]]; then
        wg_mihomo_bypass_rebuild 2>/dev/null
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
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        elif [[ "$_ptype" == "clash" ]]; then
            # Clash: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        else
            # 标准: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        fi
        _pi=$((_pi + 1))
    done
}

wg_toggle_peer() {
    wg_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name target_pubkey current_state
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")
    current_state=$(wg_db_get ".peers[$target_idx].enabled")
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'
            if wg_is_running; then
                wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
            fi
            wg_rebuild_uci_conf "no_reload"
            wg_apply_runtime_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'
            wg_rebuild_uci_conf "no_reload"
            wg_apply_runtime_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
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
    local target_name target_pubkey
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    if wg_is_running; then
        wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
    fi
    local _del_gw=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_db_get ".peers[$target_idx].lan_subnets // empty")
    wg_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        _wg_update_peer_routes
    fi

    rm -f "/etc/wireguard/clients/${target_name}.conf"
    wg_rebuild_uci_conf "no_reload"
    wg_apply_runtime_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
    wg_regenerate_client_confs

    # 网关 peer 删除后 LAN 子网列表变化，需重建 Mihomo bypass
    if [[ "$_del_gw" == "true" ]]; then
        wg_mihomo_bypass_rebuild 2>/dev/null
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
    local ep_host="$sep"

    local uci_allowed_lines=""
    local IFS_BAK="$IFS"; IFS=','
    for cidr in $client_allowed_ips; do
        cidr=$(echo "$cidr" | xargs)
        [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}'
"
    done
    IFS="$IFS_BAK"

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
    draw_line
    cat << OPENWRT_EOF

# === 清理旧配置 ===
ifdown wg0 2>/dev/null; true
for iface in \$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print \$2}'); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
done
for iface in wg0 wg_mesh wg-mesh; do
    ip link show "\$iface" >/dev/null 2>&1 && { ip link set "\$iface" down; ip link delete "\$iface"; } 2>/dev/null; true
done
rm -f /usr/bin/wg-watchdog.sh 2>/dev/null; true
(crontab -l 2>/dev/null | grep -v wg-watchdog) | crontab - 2>/dev/null; true
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
sed -i '/wg_bypass/d; /WireGuard bypass/d; /ip rule.*prio 100/d' /etc/rc.local 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true

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

# === 配置 WireGuard 接口 ===
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg0.mtu='1420'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
# === 配置防火墙 ===
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall

# === Mihomo/OpenClash bypass: WG endpoint 流量直连 ===
# 关键: 使用外部 DNS 直连解析, 绕过 OpenClash fake-ip 劫持
EP_IP='${ep_host}'
if ! echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$'; then
    # 依次尝试多个外部 DNS 直连解析 (绕过本地 Clash/Mihomo fake-ip)
    for DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
        EP_IP=\$(nslookup '${ep_host}' \$DNS_SRV 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}')
        # 验证不是 fake-ip (198.18.0.0/15)
        if [ -n "\$EP_IP" ]; then
            case "\$EP_IP" in 198.18.*|198.19.*) EP_IP=""; continue ;; esac
            echo "[+] endpoint 解析: ${ep_host} -> \$EP_IP (via \$DNS_SRV)"
            break
        fi
    done
fi
if [ -z "\${EP_IP}" ]; then
    echo '[!] 警告: 无法解析 endpoint 真实 IP, bypass 规则可能无效!'
fi
if [ -n "\${EP_IP}" ]; then
    ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
    ip rule add to "\${EP_IP}" lookup main prio 100
    nft list chain inet fw4 mangle_prerouting &>/dev/null && {
        nft insert rule inet fw4 mangle_prerouting ip daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting iifname \"wg0\" counter return comment \"wg_bypass_iface\" 2>/dev/null; true
    }
    echo "[+] Mihomo bypass 规则已添加: \${EP_IP}"
fi

# 持久化: rc.local 中使用外部 DNS 动态解析 (每次开机重新解析)
sed -i '/wg_bypass/d; /WireGuard bypass/d; /wg_ep_resolve/d; /ip rule.*prio 100/d' /etc/rc.local 2>/dev/null; true
WG_RC_BLOCK="/tmp/wg-rc-block.\$\$"
WG_RC_TMP="\$(mktemp /tmp/rc.local.XXXXXX 2>/dev/null || echo /tmp/rc.local.\$\$)"
cat > "\$WG_RC_BLOCK" << 'WG_RC_EOF'
# WireGuard bypass Mihomo (dynamic resolve, bypass fake-ip) # wg_bypass
WG_EP=\$(nslookup '${ep_host}' 223.5.5.5 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}') # wg_ep_resolve
[ -n "\$WG_EP" ] && { ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true; } # wg_bypass
[ -n "\$WG_EP" ] && nft insert rule inet fw4 mangle_prerouting ip daddr "\$WG_EP" udp dport ${sport} counter return comment "wg_bypass" 2>/dev/null; true # wg_bypass
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true # wg_bypass
WG_RC_EOF
[ -f /etc/rc.local ] || { printf '#!/bin/sh\nexit 0\n' > /etc/rc.local; chmod +x /etc/rc.local 2>/dev/null; }
awk '
    FNR == NR { block = block \$0 ORS; next }
    /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?\$/ && !inserted { printf "%s", block; inserted=1 }
    { print }
    END { if (!inserted) printf "%s", block }
' "\$WG_RC_BLOCK" /etc/rc.local > "\$WG_RC_TMP" && cat "\$WG_RC_TMP" > /etc/rc.local
chmod +x /etc/rc.local 2>/dev/null; true
rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"

# === 开机自恢复服务 ===
cat > /etc/init.d/wg-client << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=0
boot() { start; }
start() {
    if command -v wg >/dev/null 2>&1 && uci -q get network.wg0.proto >/dev/null 2>&1; then
        ifup wg0 2>/dev/null; return 0
    fi
    logger -t wg-client "WireGuard missing, restoring..."
    for _r in 1 2 3; do opkg update && break; sleep 3; done
    opkg install kmod-wireguard wireguard-tools luci-proto-wireguard 2>/dev/null
    /etc/init.d/rpcd restart 2>/dev/null; sleep 1
    uci set network.wg0=interface
    uci set network.wg0.proto='wireguard'
    uci set network.wg0.private_key='${peer_privkey}'
    uci set network.wg0.mtu='1420'
    uci delete network.wg0.addresses 2>/dev/null; true
    uci add_list network.wg0.addresses='${peer_ip}/${mask}'
    uci set network.wg_server=wireguard_wg0
    uci set network.wg_server.public_key='${spub}'
    uci set network.wg_server.preshared_key='${psk}'
    uci set network.wg_server.endpoint_host='${ep_host}'
    uci set network.wg_server.endpoint_port='${sport}'
    uci set network.wg_server.persistent_keepalive='25'
    uci set network.wg_server.route_allowed_ips='1'
    ${uci_allowed_lines}uci set firewall.wg_zone=zone
    uci set firewall.wg_zone.name='wg'
    uci set firewall.wg_zone.input='ACCEPT'
    uci set firewall.wg_zone.output='ACCEPT'
    uci set firewall.wg_zone.forward='ACCEPT'
    uci set firewall.wg_zone.masq='1'
    uci add_list firewall.wg_zone.network='wg0'
    uci set firewall.wg_fwd_lan=forwarding
    uci set firewall.wg_fwd_lan.src='lan'
    uci set firewall.wg_fwd_lan.dest='wg'
    uci set firewall.wg_fwd_wg=forwarding
    uci set firewall.wg_fwd_wg.src='wg'
    uci set firewall.wg_fwd_wg.dest='lan'
    uci commit network
    uci commit firewall
    ifup wg0
    logger -t wg-client "WireGuard restored"
}
INITEOF
chmod 0700 /etc/init.d/wg-client
/etc/init.d/wg-client enable
echo '[+] 开机自恢复服务已安装'

# === 启动接口 ===
ifup wg0

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

# === WireGuard 看门狗 (fake-ip检测 + DNS直连解析 + 完整bypass自恢复 + 握手保活 + 日志持久化) ===
cat > /usr/bin/wg-watchdog.sh << 'WDSCRIPT'
#!/bin/sh
LOG_FILE="/tmp/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    logger -t wg-watchdog "$1"
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    if [ -f "$LOG_FILE" ] && [ $(wc -c < "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]; then
        tail -n 50 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
}

resolve_real() {
    local host="$1" ip=""
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" $dns 2>/dev/null | awk '/^Address:/{a=$2} END{if(a) print a}')
        [ -n "$ip" ] || continue
        case "$ip" in 198.18.*|198.19.*) ip=""; continue ;; esac
        echo "$ip"; return 0
    done
    return 1
}

if ! ifstatus wg0 &>/dev/null; then
    wdlog "wg0 down, restarting"; ifup wg0; exit 0
fi

# resolve endpoint (always set RESOLVED for bypass self-heal)
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

# DNS re-resolve + endpoint update (only for domain endpoints)
if [ -n "$EP_HOST" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    CURRENT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*) FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        wg set wg0 peer "$PUB" endpoint "${RESOLVED}:${PORT}"
        for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
            nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
        done
        nft insert rule inet fw4 mangle_prerouting ip daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        ip rule del to "$RESOLVED" lookup main prio 100 2>/dev/null; true
        ip rule add to "$RESOLVED" lookup main prio 100 2>/dev/null; true
        wdlog "bypass updated -> $RESOLVED"
    fi
fi

# bypass rule self-heal (complete: iface + IP + ip rule)
if nft list chain inet fw4 mangle_prerouting &>/dev/null; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ]; then
        if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
            PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
            nft insert rule inet fw4 mangle_prerouting ip daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wdlog "restored IP bypass -> $RESOLVED"
        fi
    fi
fi
if [ -n "$RESOLVED" ] && ! ip rule show 2>/dev/null | grep -q "$RESOLVED"; then
    ip rule add to "$RESOLVED" lookup main prio 100 2>/dev/null; true
    wdlog "restored ip rule -> $RESOLVED"
fi

# connectivity check (handshake timeout + ping fallback)
LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" &>/dev/null; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
chmod +x /usr/bin/wg-watchdog.sh
(crontab -l 2>/dev/null | grep -v wg-watchdog; echo '* * * * * /usr/bin/wg-watchdog.sh') | crontab -
/etc/init.d/cron restart
echo '[+] 看门狗已安装 (DNS直连 + fake-ip检测 + 完整bypass自恢复 + 握手保活 + 日志持久化)'
WDEOF
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

    # 主机节点
    local primary_name="WG-$(_wg_clash_server_name "$mode")"
    all_proxy_names+=("$primary_name")

    local mtu=$(_wg_clash_db_get "$mode" '.server.mtu // 1420')
    all_proxy_yaml+="  - name: \"${primary_name}\"
    type: wireguard
    server: ${server_endpoint}
    port: ${server_port}
    ip: ${peer_ip}
    private-key: \"${peer_privkey}\"
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
    if [[ "$server_endpoint" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        wg_rules_yaml+="  - IP-CIDR,${server_endpoint}/32,DIRECT
"
    else
        wg_rules_yaml+="  - DOMAIN,${server_endpoint},DIRECT
"
    fi
    for cidr in "${unique_cidrs[@]}"; do
        wg_rules_yaml+="  - IP-CIDR,${cidr},${group_name}
"
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
            local output_file="/tmp/clash-wg-${peer_name}-$(date +%s).yaml"
            local has_proxy_groups=false
            echo "$original_yaml" | grep -qE '^[[:space:]]*proxy-groups:' && has_proxy_groups=true

            # 用 Python/jq 辅助或简单 awk 注入
            # 改进: 追踪缩进层级判断段结束
            local old_umask inject_rc
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
                rm -f "$output_file"
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
                    _tmpf=$(mktemp)
                    if grep -q 'nameserver-policy:' "$output_file"; then
                        awk -v ns="$_inject_ns" '
                            /nameserver-policy:/ { print; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf" && mv "$_tmpf" "$output_file"
                    elif grep -q '^dns:' "$output_file"; then
                        awk -v ns="$_inject_ns" '
                            /^dns:/ { print; print "  nameserver-policy:"; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf" && mv "$_tmpf" "$output_file"
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
    if [[ -z "$auto_mode" ]] && crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
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
                cron_remove_job "wg-watchdog.sh"
                rm -f "$watchdog_script"
                print_success "看门狗已禁用"
                log_action "WireGuard watchdog disabled"
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
        print_title "WireGuard 服务端看门狗"
        echo "看门狗功能:
  • 每分钟检测 wg0 接口状态
  • 接口消失 → 立即拉起
  • wg show 失败 → 重启接口"
        if ! confirm "启用看门狗?"; then pause; return; fi
    fi

    # ── OpenWrt 看门狗 (#!/bin/sh + ifup/ifdown + Mihomo bypass + 路由检查) ──
    cat > "$watchdog_script" << 'WDEOF_OPENWRT'
#!/bin/sh
LOG="logger -t wg-watchdog"
DB="/etc/wireguard/db/wg-data.json"

# 检测接口存活
if ! ifstatus wg0 &>/dev/null; then
    $LOG "wg0 down, restarting"
    ifup wg0
    sleep 2
fi

# 检测 wg show 是否正常
if ! wg show wg0 &>/dev/null; then
    $LOG "wg show failed, restarting"
    ifdown wg0; sleep 1; ifup wg0
    sleep 2
fi

# 检测 Mihomo bypass 规则是否存在
if nft list chain inet fw4 mangle_prerouting &>/dev/null; then
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
                nft insert rule inet fw4 mangle_prerouting ip daddr "$sub" counter return comment "wg_bypass_subnet" 2>/dev/null || true
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
    chmod +x "$watchdog_script"
    cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
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
    peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(mktemp "/tmp/${SCRIPT_NAME}-wg-peers.XXXXXX") || { print_error "无法创建导出文件"; pause; return 1; }
    chmod 600 "$export_file"
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
    else
        print_error "导出失败"
    fi
    log_action "WireGuard peers exported: count=$peer_count file=$export_file"
    pause
}

wg_import_peers() {
    wg_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return
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
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return; }

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
            confirm "确认删除所有现有设备?" || return
            # 先从运行中的接口移除所有 peer
            if wg_is_running; then
                local pc=$(wg_db_get '.peers | length') pi=0
                while [[ $pi -lt $pc ]]; do
                    local pk=$(wg_db_get ".peers[$pi].public_key")
                    wg set "$WG_INTERFACE" peer "$pk" remove 2>/dev/null || true
                    pi=$((pi + 1))
                done
            fi
            wg_db_set '.peers = []'
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

        wg_db_set --arg name "$name" \
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
            }]'
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        wg_rebuild_uci_conf "no_reload"
        wg_apply_runtime_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
        wg_regenerate_client_confs
    fi
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

    local old_umask _rc
    old_umask=$(umask)
    umask 077
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
    } > "$WG_DEB_CONF"
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    chmod 600 "$WG_DEB_CONF"
}

wg_deb_regenerate_client_confs() {
    local pc=$(wg_deb_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport sdns mask mtu
    spub=$(wg_deb_db_get '.server.public_key')
    sep=$(wg_deb_db_get '.server.endpoint')
    sport=$(wg_deb_db_get '.server.port')
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
Endpoint = ${sep}:${sport}
AllowedIPs = $(wg_deb_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        write_file_atomic "${WG_DEB_CLIENT_DIR}/${name}.conf" "$conf_content"
        chmod 600 "${WG_DEB_CLIENT_DIR}/${name}.conf"
        i=$((i + 1))
    done
}

wg_deb_apply_conf() {
    wg_deb_rebuild_conf || return 1
    wg_deb_regenerate_client_confs
    wg_deb_is_running || return 0
    local tmp
    tmp=$(mktemp "/tmp/${SCRIPT_NAME}-wg-deb-sync.XXXXXX") || return 1
    awk '
        /^\[Interface\]$/ { section="interface"; print; next }
        /^\[Peer\]$/ { section="peer"; print; next }
        section=="interface" && /^(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
        section=="peer" && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
    ' "$WG_DEB_CONF" > "$tmp"
    if wg syncconf "$WG_DEB_INTERFACE" "$tmp" >/dev/null 2>&1; then
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp"
    return 1
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
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    print_success "IP 转发已开启"

    # ── [4/7] 配置服务端参数 ──
    print_info "[4/7] 配置服务端参数..."

    local wg_port listen_addr mtu wg_dns wg_endpoint
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
    wg_deb_db_init
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
        pause; return 1
    fi
    wg_deb_set_role "server"

    # 生成 wg0.conf
    wg_deb_rebuild_conf

    # 持久化 IP 转发
    if ! grep -q "^net.ipv4.ip_forward" /etc/sysctl.d/99-wireguard.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
        sysctl --system >/dev/null 2>&1
    fi

    # ── [7/7] 启动服务 ──
    print_info "[7/7] 启动 WireGuard..."
    systemctl enable wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    systemctl start wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2

    # 放行 WG UDP 端口 (ufw 如果启用)
    if ufw_is_active; then
        ufw allow "$wg_port"/udp >/dev/null 2>&1
        print_info "已在 UFW 放行 ${wg_port}/udp"
    fi

    # ── 安装结果展示 ──
    draw_line
    if wg_deb_is_running; then
        print_success "WireGuard 服务端安装并启动成功！"
    else
        print_warn "WireGuard 已安装，但启动可能失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE}"
    fi
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
    wg_deb_setup_watchdog "true"

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
    local changed=false lan_changed=false iface_changed=false

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            if ! wg_deb_db_set --argjson p "$new_port" '.server.port = $p'; then
                print_error "数据库写入失败，端口未修改"
                pause; return 1
            fi
            changed=true
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
            pause; return 1
        fi
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        if ! wg_deb_db_set --arg e "$new_ep" '.server.endpoint = $e'; then
            print_error "数据库写入失败，端点未修改"
            pause; return 1
        fi
        changed=true
        print_info "端点将更改为 ${new_ep}"
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
        pause; return 1
    fi

    wg_deb_rebuild_conf
    wg_deb_regenerate_client_confs

    # UFW 端口变更
    if [[ "$new_port" != "$cur_port" ]] && ufw_is_active; then
        ufw delete allow "$cur_port"/udp >/dev/null 2>&1
        ufw allow "$new_port"/udp >/dev/null 2>&1
    fi

    # 重启服务使配置生效
    systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
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
    else
        print_error "启动失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) start failed"
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
    else
        print_error "停止失败"
    fi
}

wg_deb_restart() {
    print_info "正在重启 WireGuard..."
    systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
    if wg_deb_is_running; then
        print_success "WireGuard 已重启"
        log_action "WireGuard(deb) restarted"
    else
        print_error "重启失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) restart failed"
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
    if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
        cron_remove_job "wg-watchdog.sh"
    fi
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
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
        fi
    fi

    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line
    log_action "WireGuard(deb) uninstalled: role=${role}"
    pause
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
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)

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

    # ── 生成客户端配置文件 ──
    local spub sep sport sdns mask
    spub=$(wg_deb_db_get '.server.public_key')
    sep=$(wg_deb_db_get '.server.endpoint')
    sport=$(wg_deb_db_get '.server.port')
    sdns=$(wg_deb_db_get '.server.dns')
    mask=$(echo "$server_subnet" | cut -d'/' -f2)
    local conf_file="${WG_DEB_CLIENT_DIR}/${peer_name}.conf"

    # ── 写入数据库 ──
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
            print_error "联动更新客户端路由失败"
            pause; return 1
        fi
    fi

    # ── 重建配置并热应用 ──
    wg_deb_apply_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }

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
        [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
        [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

        local _is_gw=$(wg_deb_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_deb_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_deb_db_get ".peers[$_pi].peer_type // \"standard\"")
        local _route_mode=$(wg_deb_db_get ".peers[$_pi].route_mode // empty")
        [[ "$_route_mode" == "custom" ]] && { _pi=$((_pi + 1)); continue; }

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
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            if ! wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            wg_deb_apply_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard(deb) peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            if ! wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            wg_deb_apply_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
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
    if ! wg_deb_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'; then
        print_error "数据库写入失败，设备未删除"
        pause; return 1
    fi

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        if ! _wg_deb_update_peer_routes; then
            print_error "联动更新客户端路由失败"
            pause; return 1
        fi
    fi

    rm -f "${WG_DEB_CLIENT_DIR}/${target_name}.conf"
    wg_deb_apply_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }

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
    if [[ -z "$auto_mode" ]] && crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
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
                cron_remove_job "wg-watchdog.sh"
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

    # ── Debian 看门狗 (systemctl 管理) ──
    {
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
    } > "$watchdog_script"
    chmod +x "$watchdog_script"
    cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo "  检测: 接口存活 → wg show"
    log_action "WireGuard(deb) watchdog enabled"
    [[ -z "$auto_mode" ]] && pause
}

wg_deb_export_peers() {
    wg_deb_check_server || return 1
    print_title "导出 WireGuard 设备配置"
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(mktemp "/tmp/${SCRIPT_NAME}-wg-peers.XXXXXX") || { print_error "无法创建导出文件"; pause; return 1; }
    chmod 600 "$export_file"
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
    else
        print_error "导出失败"
    fi
    log_action "WireGuard(deb) peers exported: count=$peer_count file=$export_file"
    pause
}

wg_deb_import_peers() {
    wg_deb_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return
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
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return; }

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
            confirm "确认删除所有现有设备?" || return
            wg_deb_db_set '.peers = []'
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
            print_error "跳过: $name (数据库写入失败)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        wg_deb_apply_conf || { print_error "WireGuard 运行配置热应用失败"; pause; return 1; }
    fi
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
    local backup tmp
    backup=$(mktemp "/tmp/server-manage-pages-wrangler.XXXXXX") || return 1
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
    local enc_type enc_name resp
    enc_type=$(_email_cf_urlencode "$type")
    enc_name=$(_email_cf_urlencode "$name")
    resp=$(_email_cf_api GET "zones/$zid/dns_records?type=$enc_type&name=$enc_name&per_page=50") || return 1
    echo "$resp" | jq -r '.result[].id'
}

# 删除 zone 下所有匹配 type+name 的记录（idempotent 清理）
_email_cf_dns_purge() {
    local zid="$1" type="$2" name="$3" id
    while IFS= read -r id; do
        [[ -n "$id" ]] && _email_cf_dns_delete "$zid" "$id" || true
    done < <(_email_cf_dns_find_ids "$zid" "$type" "$name")
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
    _email_cf_api PUT "zones/$zid/email/routing/rules/catch_all" "$body" >/dev/null 2>&1 || true
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
            tmp=$(mktemp)
            trap "rm -f \"$tmp\"" EXIT
            curl -fsSL https://deb.nodesource.com/setup_lts.x -o "$tmp"
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
    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<EOF
name = "${EMAIL_WORKER_NAME}"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]

[[d1_databases]]
binding = "DB"
database_name = "${EMAIL_D1_NAME}"
database_id = "${EMAIL_D1_ID}"
EOF
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

    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<EOF
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
    chmod 600 "$EMAIL_INSTALL_DIR/worker/wrangler.toml"
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
            print_warn "RESEND_TOKEN 配置失败 — 可稍后通过管理菜单重试"
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
        print_warn "自定义域名绑定失败（可能已绑定或域名未配置）"
    fi
}

# ── 10. DNS 记录 ──
# 收信关键记录（Frontend CNAME / MX）失败时 return 1，由 email_deploy 阻断完成标记；
# Resend 相关（DKIM/SPF/DMARC）仅 warn，因为发件是可选能力
_email_deploy_dns() {
    print_info "添加 DNS 记录..."
    local zid="$EMAIL_ZONE_ID"
    local _dns_fail=0

    # 前端 CNAME（橙云代理）— 若同名记录已存在，先清理
    _email_cf_dns_purge "$zid" CNAME "$EMAIL_FRONTEND_DOMAIN"
    if _email_cf_dns_create_record_into EMAIL_DNS_FRONTEND_ID "$zid" "CNAME" \
            "$EMAIL_FRONTEND_DOMAIN" "$EMAIL_PAGES_DOMAIN" "" "true"; then
        print_success "CNAME $EMAIL_FRONTEND_PREFIX → $EMAIL_PAGES_DOMAIN"
    else
        print_error "前端 CNAME 添加失败 — 用户将无法通过 ${EMAIL_FRONTEND_DOMAIN} 访问 UI"
        _dns_fail=1
    fi

    # MX 记录到 Cloudflare Email Routing（3 条任一缺失会降级路由，全失败则无法收信）
    _email_cf_dns_purge "$zid" MX "$EMAIL_DOMAIN"
    local _mx_ok=0
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
    if [[ "$_mx_ok" -eq 0 ]]; then
        print_error "MX 记录全部添加失败 — 邮箱将无法收信"
        _dns_fail=1
    elif [[ "$_mx_ok" -lt 3 ]]; then
        print_warn "MX 记录仅创建 ${_mx_ok}/3 — Cloudflare 推荐 3 条，建议 Dashboard 补齐"
    fi

    # Resend 相关（DKIM/SPF/SEND_MX/DMARC）仅 warn — 不影响收信主链路
    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        local send_sub="send.${EMAIL_DOMAIN}"
        _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}"
        _email_cf_dns_purge "$zid" TXT "$send_sub"
        _email_cf_dns_purge "$zid" MX  "$send_sub"
        _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}"

        _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$EMAIL_RESEND_DKIM" \
            && print_success "DKIM (resend._domainkey)" || print_warn "DKIM 失败（发件能力受影响，可后续 Dashboard 补）"
        _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
            && print_success "SPF (send.${EMAIL_DOMAIN})" || print_warn "SPF 失败（发件能力受影响）"
        _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
            && print_success "Send MX" || print_warn "Send MX 失败（发件能力受影响）"
        _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
            && print_success "DMARC" || print_warn "DMARC 失败（发件能力受影响）"
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
    if grep -qE '^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=' "$toml"; then
        ADMIN_PASSWORDS_LINE="$line" awk '
            BEGIN { line = ENVIRON["ADMIN_PASSWORDS_LINE"] }
            /^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=/ { print line; next }
            { print }
        ' "$toml" > "${toml}.tmp" && mv "${toml}.tmp" "$toml"
    else
        ADMIN_PASSWORDS_LINE="$line" awk '
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
        ' "$toml" > "${toml}.tmp" && mv "${toml}.tmp" "$toml"
    fi
    chmod 600 "$toml"
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

    # 替换 DOMAINS 和 DEFAULT_DOMAINS
    sed -i.bak -E "s|^DOMAINS[[:space:]]*=.*$|DOMAINS = ${new_arr}|" "$toml"
    sed -i -E "s|^DEFAULT_DOMAINS[[:space:]]*=.*$|DEFAULT_DOMAINS = ${new_arr}|" "$toml"
    rm -f "${toml}.bak"
    print_success "wrangler.toml 已更新"
    echo "  DOMAINS = $new_arr"

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || { pause; return; }
    if email_run "重新部署 Worker" _email_wrangler deploy; then
        print_success "Worker 已更新，新域名已生效"
        log_action "Email DOMAINS updated: $new_arr"
    else
        print_error "部署失败，wrangler.toml 已修改但 worker 未更新"
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
    email_read_secret "Resend API Token" tok || { print_error "Token 不能为空"; return; }
    print_info "已收到 Token: $(email_mask_token "$tok")"
    read -e -r -p "Resend DKIM (p=MIGfMA0...): " dkim
    [[ -z "$dkim" ]] && { print_error "DKIM 不能为空"; return; }

    if ! email_run "写入 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_error "secret 写入失败"; return
    fi

    local send_sub="send.${EMAIL_DOMAIN}"
    local zid="$EMAIL_ZONE_ID"

    # 清旧记录（按 type+name 全量清，避免脏数据残留）
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}"
    _email_cf_dns_purge "$zid" TXT "$send_sub"
    _email_cf_dns_purge "$zid" MX  "$send_sub"
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}"

    _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$dkim" \
        && print_success "DKIM" || print_warn "DKIM 失败"
    _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
        && print_success "SPF" || print_warn "SPF 失败"
    _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
        && print_success "Send MX" || print_warn "Send MX 失败"
    _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
        && print_success "DMARC" || print_warn "DMARC 失败"

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
    email_read_secret "新 Resend API Token" tok || return
    print_info "已收到 Token: $(email_mask_token "$tok")"
    if email_run "更新 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_success "RESEND_TOKEN 已更新"
        log_action "Email Resend token rotated"
    fi
    unset tok
}

_email_manage_resend_disable() {
    confirm "确认禁用 Resend 并删除相关 DNS 记录?" || return
    local zid="$EMAIL_ZONE_ID"
    _email_cf_dns_delete "$zid" "$EMAIL_DNS_DKIM_ID" && print_success "已删 DKIM" || true
    _email_cf_dns_delete "$zid" "$EMAIL_DNS_SPF_ID"  && print_success "已删 SPF" || true
    _email_cf_dns_delete "$zid" "$EMAIL_DNS_SEND_MX_ID" && print_success "已删 Send MX" || true
    _email_cf_dns_delete "$zid" "$EMAIL_DNS_DMARC_ID" && print_success "已删 DMARC" || true
    # 同步清掉可能的同名脏记录
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}"
    _email_cf_dns_purge "$zid" TXT "send.${EMAIL_DOMAIN}"
    _email_cf_dns_purge "$zid" MX  "send.${EMAIL_DOMAIN}"
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}"

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
    trap '_email_clear_sensitive_env' RETURN
    print_title "完全卸载 Cloudflare Temp Email"

    # 不再硬卡 EMAIL_INSTALLED=1 — 只要 state 文件能加载，即视为有可回收的远端资源（涵盖部署中途失败的场景）
    local has_state=0
    if [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
        _email_state_reset_vars
        # shellcheck disable=SC1090
        source "$EMAIL_STATE_FILE"
        has_state=1
    fi

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

    # 1. 关闭 catch-all
    if [[ "${EMAIL_CATCH_ALL_ENABLED:-0}" == "1" && -n "$EMAIL_ZONE_ID" ]]; then
        if email_run "禁用 Email Routing catch-all" _email_cf_catch_all_disable "$EMAIL_ZONE_ID"; then
            EMAIL_CATCH_ALL_ENABLED=0
        else
            uninstall_failed=1
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
    local _log_domain="${EMAIL_DOMAIN:-unknown}"
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
    _email_cf_dns_purge "$zid" "CNAME" "$EMAIL_FRONTEND_DOMAIN" 2>/dev/null || true
    _email_cf_dns_purge "$zid" "MX"    "$EMAIL_DOMAIN" 2>/dev/null || true
    if [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]]; then
        _email_cf_dns_purge "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "TXT" "send.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "MX"  "send.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" 2>/dev/null || true
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
REALITY_SNI_CACHE_TTL=86400  # 24 小时

# 三级阈值（默认值，用户可在交互菜单中选择）
REALITY_SNI_LATENCY_THRESHOLD_STRICT=50
REALITY_SNI_LATENCY_THRESHOLD_NORMAL=200
REALITY_SNI_LATENCY_THRESHOLD_RELAXED=500

# 测速参数
REALITY_SNI_BATCH_SIZE=15
REALITY_SNI_TEST_TIMEOUT=3

# ============================================================================
# 核心函数：从 bulianglin.com 拉取候选池
# ============================================================================

reality_fetch_bulianglin_pool() {
    local html_content domains_json

    print_info "正在从 bulianglin.com 拉取最新 SNI 候选池..." >&2

    html_content=$(curl -fsSL --max-time 15 "$BULIANGLIN_SNI_POOL_URL" 2>/dev/null)
    if [[ -z "$html_content" ]]; then
        return 1
    fi

    domains_json=$(echo "$html_content" | grep -o 'const domains = \[.*\];' | sed 's/const domains = \[//; s/\];//')

    if [[ -z "$domains_json" ]]; then
        return 1
    fi

    mkdir -p "$REALITY_SNI_CACHE_DIR"
    echo "$domains_json" | sed 's/"//g; s/, /\n/g' | sed 's/^ *//; s/ *$//' | sort -u > "$REALITY_SNI_POOL_FILE"

    local count
    count=$(wc -l < "$REALITY_SNI_POOL_FILE")

    if [[ $count -lt 10 ]]; then
        return 1
    fi

    print_success "成功拉取 $count 个 SNI 候选域名" >&2
    return 0
}

# ============================================================================
# 核心函数：从 v2ray-agent 拉取备用候选池
# ============================================================================

reality_fetch_v2ray_agent_pool() {
    local v2ray_agent_url="https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    local temp_file="/tmp/v2ray-agent-install.sh"

    print_info "正在从 v2ray-agent 拉取备用候选池..." >&2

    if ! curl -fsSL --max-time 15 "$v2ray_agent_url" -o "$temp_file" 2>/dev/null; then
        return 1
    fi

    local domains_content
    domains_content=$(grep -A 100 '_realityDomainList()' "$temp_file" | grep -E '^\s*"[^"]+"\s*$' | sed 's/[" ]//g' | sort -u)

    if [[ -z "$domains_content" ]]; then
        rm -f "$temp_file"
        return 1
    fi

    mkdir -p "$REALITY_SNI_CACHE_DIR"
    echo "$domains_content" > "$REALITY_SNI_POOL_FILE"

    local count
    count=$(wc -l < "$REALITY_SNI_POOL_FILE")

    if [[ $count -lt 10 ]]; then
        rm -f "$temp_file"
        return 1
    fi

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
        local age
        age=$(( $(date +%s) - $(stat -c %Y "$REALITY_SNI_POOL_FILE" 2>/dev/null || echo 0) ))

        if [[ $age -lt $REALITY_SNI_CACHE_TTL ]]; then
            local count
            count=$(wc -l < "$REALITY_SNI_POOL_FILE")
            print_info "使用缓存的候选池（$count 个域名，${age}s 前更新）" >&2
            return 0
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
    printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" > /tmp/reality-fallback-pool.txt
    REALITY_SNI_POOL_FILE="/tmp/reality-fallback-pool.txt"
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
    "ocsp2.apple.com"
    "s0.awsstatic.com"
    "a0.awsstatic.com"
    "apps.mzstatic.com"
    "sisu.xboxlive.com"
    "s.mp.marsflag.com"
    "c.s-microsoft.com"
    "statici.icloud.com"
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
    "is1-ssl.mzstatic.com"
    "intelcorp.scene7.com"
    "cdnssl.clicktale.net"
    "catalog.gamepass.com"
    "consent.trustarc.com"
    "gsp-ssl.ls.apple.com"
    "munchkin.marketo.net"
    "cdn77.api.userway.org"
    "cua-chat-ui.tesla.com"
    "ds-aksb-a.akamaihd.net"
    "static.cloud.coveo.com"
    "devblogs.microsoft.com"
    "s7mbrstream.scene7.com"
    "fpinit.itunes.apple.com"
    "digitalassets.tesla.com"
    "d.impactradius-event.com"
    "downloadmirror.intel.com"
    "iosapps.itunes.apple.com"
    "se-edge.itunes.apple.com"
    "publisher.liveperson.net"
    "tag-logger.demandbase.com"
    "services.digitaleast.mobi"
    "configuration.ls.apple.com"
    "gray-wowt-prod.gtv-cdn.com"
    "visualstudio.microsoft.com"
    "amp-api-edge.apps.apple.com"
    "store-images.s-microsoft.com"
    "github.gallerycdn.vsassets.io"
    "vscjava.gallerycdn.vsassets.io"
    "ms-vscode.gallerycdn.vsassets.io"
    "ms-python.gallerycdn.vsassets.io"
    "gray-config-prod.api.arc-cdn.net"
    "gray.video-player.arcpublishing.com"
    "i7158c100-ds-aksb-a.akamaihd.net"
    "downloaddispatch.itunes.apple.com"
    "img-prod-cms-rt-microsoft-com.akamaized.net"
)

reality_urlencode() {
    local s="$1" out="" i c
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

reality_detect_listen_host() {
    # 决定 sing-box / realm 应绑定的本机地址：
    #   本机存在全局 IPv6 地址 → "::"（双栈监听；bindv6only=0 默认下经 IPv4-mapped 同时覆盖 IPv4），
    #   否则 → "0.0.0.0"（纯 IPv4）。
    # 用本地接口判断而非公网探测，避免网络抖动导致 IPv6-only 机器误绑 0.0.0.0 而对外不可达。
    # 可用 REALITY_LISTEN_HOST 覆盖（测试/特殊网络）。
    if [[ -n "${REALITY_LISTEN_HOST:-}" ]]; then printf '%s' "$REALITY_LISTEN_HOST"; return 0; fi
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

reality_render_singbox_config() {
    local uuid="$1" private_key="$2" port="$3" sni="$4" short_id="$5"
    local listen_host; listen_host="${REALITY_LISTEN_HOST:-$(reality_detect_listen_host)}"
    uuid=$(reality_json_escape "$uuid")
    private_key=$(reality_json_escape "$private_key")
    sni=$(reality_json_escape "$sni")
    short_id=$(reality_json_escape "$short_id")
    if [[ "${REALITY_DNS_MODE:-auto}" == "split" && -n "${REALITY_PORT_V6:-}" ]]; then
        local listen_host_v4="${REALITY_LISTEN_HOST_V4:-0.0.0.0}" listen_host_v6="${REALITY_LISTEN_HOST_V6:-::}" port_v6="${REALITY_PORT_V6}"
        cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-ipv4","listen":"${listen_host_v4}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}},{"type":"vless","tag":"vless-reality-ipv6","listen":"${listen_host_v6}","listen_port":${port_v6},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
        return 0
    fi
    cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"${listen_host}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
}

reality_build_vless_link() {
    local uuid="$1" node="$2" port="$3" sni="$4" public_key="$5" short_id="$6" name="${7:-singbox-reality}"
    local encoded_name
    encoded_name=$(reality_urlencode "$name")
    printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&flow=xtls-rprx-vision#%s\n' \
        "$uuid" "$node" "$port" "$sni" "$public_key" "$short_id" "$encoded_name"
}

reality_parse_vless_link() {
    local link="$1" body user hostport query param key value
    [[ "$link" == vless://* ]] || return 1
    body="${link#vless://}"
    user="${body%@*}"
    body="${body#*@}"
    hostport="${body%%\?*}"
    query="${body#*\?}"
    query="${query%%#*}"
    REALITY_UUID="$user"
    REALITY_NODE_DOMAIN="${hostport%:*}"
    REALITY_PORT="${hostport##*:}"
    while IFS= read -r param; do
        key="${param%%=*}"
        value="${param#*=}"
        case "$key" in
            sni|serverName) REALITY_SNI="$value" ;;
            pbk|publicKey) REALITY_PUBLIC_KEY="$value" ;;
            sid|shortId) REALITY_SHORT_ID="$value" ;;
            flow) REALITY_FLOW="$value" ;;
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
    local listen_host; listen_host="${REALITY_LISTEN_HOST:-$(reality_detect_listen_host)}"
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
    local test_port="${REALITY_SELFTEST_PORT:-19090}" cfg log curl_log pid i
    cfg=$(mktemp /tmp/reality-client-test.XXXXXX.json) || return 1
    log=$(mktemp /tmp/reality-client-test.XXXXXX.log) || { rm -f "$cfg"; return 1; }
    curl_log=$(mktemp /tmp/reality-selftest-curl.XXXXXX.log) || { rm -f "$cfg" "$log"; return 1; }
    chmod 600 "$cfg" "$log" "$curl_log" 2>/dev/null || true
    cat > "$cfg" <<EOF
{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"self-test","server":"127.0.0.1","server_port":${REALITY_PORT},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}],"route":{"final":"self-test"}}
EOF
    ( sing-box run -c "$cfg" > "$log" 2>&1 & echo $! > "${cfg}.pid" )
    pid=$(cat "${cfg}.pid" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if curl -x "socks5h://127.0.0.1:${test_port}" -fsS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace >"$curl_log" 2>&1; then
        print_success "本机协议自测通过: sing-box client -> 127.0.0.1:${REALITY_PORT} -> 外网"
        rm -f "$cfg" "$log" "$curl_log" "${cfg}.pid"
        [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
        return 0
    fi
    print_warn "本机协议自测失败，最近日志:"
    tail -n 20 "$curl_log" 2>/dev/null || true
    sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    rm -f "$cfg" "$log" "$curl_log" "${cfg}.pid"
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

reality_install_singbox_official() {
    reality_require_supported_os || return 1
    install_package "curl" "silent" || return 1
    install_package "ca-certificates" "silent" || return 1
    install_package "gnupg" "silent" || return 1
    install_package "openssl" "silent" || return 1
    install_package "jq" "silent" || true
    if ! command_exists sing-box; then
        print_info "添加 sing-box 官方 APT 源..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc || return 1
        chmod a+r /etc/apt/keyrings/sagernet.asc
        cat > /etc/apt/sources.list.d/sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
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
    local timeout_cmd=""
    command_exists timeout && timeout_cmd="timeout 12"
    REALITY_SNI_CHECK_LOG=$(mktemp /tmp/reality-sni-check.XXXXXX.log) || return 1
    chmod 600 "$REALITY_SNI_CHECK_LOG" 2>/dev/null || true
    $timeout_cmd openssl s_client -connect "${domain}:443" -servername "$domain" -verify_hostname "$domain" -verify_return_error -brief </dev/null >"$REALITY_SNI_CHECK_LOG" 2>&1
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
            echo "$sni"; return 0
        fi
        print_warn "SNI 校验未通过或网络不可达: $sni" >&2
        tail -n 3 "${REALITY_SNI_CHECK_LOG:-/dev/null}" >&2 2>/dev/null || true
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
    cp -a "$file" "$REALITY_BACKUP_DIR/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
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
    cat > "$REALITY_STATE_FILE" <<EOF
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
REALITY_LISTEN_HOST=$(reality_state_quote "${REALITY_LISTEN_HOST:-}")
REALITY_LISTEN_HOST_V4=$(reality_state_quote "${REALITY_LISTEN_HOST_V4:-}")
REALITY_LISTEN_HOST_V6=$(reality_state_quote "${REALITY_LISTEN_HOST_V6:-}")
REALITY_RELAY_DOMAIN=$(reality_state_quote "${REALITY_RELAY_DOMAIN:-}")
REALITY_RELAY_PORT=$(reality_state_quote "${REALITY_RELAY_PORT:-}")
REALITY_RELAY_TARGET_HOST=$(reality_state_quote "${REALITY_RELAY_TARGET_HOST:-}")
REALITY_RELAY_TARGET_PORT=$(reality_state_quote "${REALITY_RELAY_TARGET_PORT:-}")
EOF
    chmod 600 "$REALITY_STATE_FILE"
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
        split) echo "IPv4+IPv6 双节点（A-only + AAAA-only，两端口/两链接）" ;;
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
    json_name=$(reality_json_escape "$name")
    reality_build_vless_link "$REALITY_UUID" "$link_host" "$link_port" "$REALITY_SNI" "$REALITY_PUBLIC_KEY" "$REALITY_SHORT_ID" "$name" > "$link_path"
    cat > "$json_path" <<EOF
{"type":"vless","tag":"${json_name}","server":"${link_host}","server_port":${link_port},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}
EOF
    chmod 600 "$link_path" "$json_path"
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
        cat "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" > "$REALITY_LINK_FILE"
        cp -f "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON"
        chmod 600 "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON"
        return 0
    fi

    local link_host="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" link_port="${REALITY_RELAY_PORT:-$REALITY_PORT}" name
    [[ -n "$link_host" && -n "$link_port" ]] || return 1
    name="$(reality_effective_node_name)"
    reality_write_one_client_artifact "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" "$link_host" "$link_port" "$name"
    rm -f "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6" 2>/dev/null || true
}

reality_detect_ips() {
    REALITY_IPV4="$(get_public_ipv4 2>/dev/null || true)"
    REALITY_IPV6="$(get_public_ipv6 2>/dev/null || true)"
    [[ -n "$REALITY_IPV6" && "$REALITY_IPV6" != *:* ]] && REALITY_IPV6=""
}

reality_cf_delete_dns_type() {
    local domain="$1" token="$2" type="$3" zone_id resp id ids=()
    [[ -z "$domain" || -z "$token" || -z "$type" ]] && return 1
    command_exists jq || install_package "jq" "silent" || return 1
    zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || return 1
    resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain&per_page=100" "$token") || return 1
    _cf_api_ok "$resp" || return 1
    mapfile -t ids < <(jq -r '.result[].id // empty' <<< "$resp" 2>/dev/null)
    for id in "${ids[@]}"; do
        [[ -n "$id" ]] || continue
        _cf_api DELETE "/zones/$zone_id/dns_records/$id" "$token" >/dev/null || return 1
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
    local token="$1" resp
    [[ -z "$token" ]] && return 1
    resp=$(_cf_api GET "/zones?per_page=50" "$token") || return 1
    _cf_api_ok "$resp" || return 1
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
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    if [[ "$dns_mode" == "split" ]]; then
        node_domain_v4="${node_domain_v4:-$node_domain}"
        validate_domain "$node_domain_v4" || { print_error "IPv4 节点域名无效"; return 1; }
        validate_domain "$node_domain_v6" || { print_error "IPv6 节点域名无效"; return 1; }
        [[ "$node_domain_v4" != "$node_domain_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 域名不能相同"; return 1; }
        validate_port "$port_v6" || { print_error "IPv6 端口无效"; return 1; }
        [[ "$port" != "$port_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 监听端口不能相同"; return 1; }
        [[ -z "$node_name_v4" ]] || reality_validate_node_name "$node_name_v4" || { print_error "IPv4 节点名称无效"; return 1; }
        [[ -z "$node_name_v6" ]] || reality_validate_node_name "$node_name_v6" || { print_error "IPv6 节点名称无效"; return 1; }
    else
        validate_domain "$node_domain" || { print_error "节点域名无效"; return 1; }
    fi
    reality_load_state || true
    local had_relay=0
    [[ "${REALITY_ROLE:-}" == *"relay"* ]] && had_relay=1
    reality_install_singbox_official || return 1
    REALITY_UUID=$(reality_generate_uuid) || return 1
    local keys
    keys=$(reality_generate_keypair) || { print_error "生成 Reality keypair 失败"; return 1; }
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
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
        REALITY_LISTEN_HOST="split"
        REALITY_LISTEN_HOST_V4="0.0.0.0"
        REALITY_LISTEN_HOST_V6="::"
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
    local file="$1" checksum_file="$2" asset_name="${3:-$(basename "$file")}" hash line
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
    local arch expected url tmp bin asset_name
    arch=$(reality_realm_arch) || { print_error "Realm 不支持当前架构"; return 1; }
    expected=$(reality_realm_pinned_sha256 "$arch") || { print_error "无内置 Realm ${arch} 校验值，已拒绝安装"; return 1; }
    asset_name="realm-${arch}.tar.gz"
    url="https://github.com/zhboner/realm/releases/download/${REALITY_REALM_VERSION}/${asset_name}"
    tmp=$(mktemp -d)
    curl -fsSL "$url" -o "$tmp/realm.tgz" || { print_error "Realm 发布包下载失败"; rm -rf "$tmp"; return 1; }
    # 用内置校验值生成本地 checksum 文件，复用统一校验 helper（含 sha256sum -c）。
    printf '%s  %s\n' "$expected" "$asset_name" > "$tmp/realm.sha256"
    reality_verify_sha256_file "$tmp/realm.tgz" "$tmp/realm.sha256" "$asset_name" || {
        print_error "Realm 发布包 sha256 校验失败，已拒绝安装"; rm -rf "$tmp"; return 1
    }
    tar -xzf "$tmp/realm.tgz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    bin=$(reality_find_realm_binary "$tmp") || { print_error "Realm 发布包中未找到可安装二进制"; rm -rf "$tmp"; return 1; }
    install -m 0755 "$bin" /usr/local/bin/realm || { rm -rf "$tmp"; return 1; }
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

# 校验并加载一条线路到 RLY_* 全局；校验失败跳过
reality_relay_load_route() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    validate_conf_file "$file" || { print_warn "中转线路文件校验失败，已跳过: $file"; return 1; }
    RLY_NAME=""; RLY_LISTEN_PORT=""; RLY_CONNECT_HOST=""; RLY_TARGET_HOST=""; RLY_TARGET_PORT=""
    RLY_UUID=""; RLY_SNI=""; RLY_PUBLIC_KEY=""; RLY_SHORT_ID=""; RLY_FLOW=""
    # shellcheck disable=SC1090
    source "$file"
}

# 用当前 RLY_* 写出一条线路文件（值经 reality_state_quote，满足 validate_conf_file）
reality_relay_write_route() {
    local port="$1" file
    file="$REALITY_RELAY_DIR/relay-${port}.conf"
    mkdir -p "$REALITY_RELAY_DIR"
    cat > "$file" <<EOF
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
EOF
    chmod 600 "$file"
}

# 用当前 RLY_* 写该线路客户端链接/JSON（身份=落地机，host:port=本机中转入口）
reality_relay_write_client_artifacts() {
    local port="${RLY_LISTEN_PORT:-}" host="${RLY_CONNECT_HOST:-}" name="${RLY_NAME:-relay-${RLY_LISTEN_PORT:-0}}" json_name
    [[ -n "$host" && -n "$port" && -n "${RLY_UUID:-}" && -n "${RLY_SNI:-}" && -n "${RLY_PUBLIC_KEY:-}" && -n "${RLY_SHORT_ID:-}" ]] || return 1
    mkdir -p "$REALITY_RELAY_DIR"
    json_name=$(reality_json_escape "$name")
    reality_build_vless_link "$RLY_UUID" "$host" "$port" "$RLY_SNI" "$RLY_PUBLIC_KEY" "$RLY_SHORT_ID" "$name" > "$REALITY_RELAY_DIR/relay-${port}.link.txt"
    cat > "$REALITY_RELAY_DIR/relay-${port}.client.json" <<EOF
{"type":"vless","tag":"${json_name}","server":"${host}","server_port":${port},"uuid":"${RLY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${RLY_SNI}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${RLY_PUBLIC_KEY}","short_id":"${RLY_SHORT_ID}"}}}
EOF
    chmod 600 "$REALITY_RELAY_DIR/relay-${port}.link.txt" "$REALITY_RELAY_DIR/relay-${port}.client.json"
}

# 由全部线路渲染 realm 多端点配置（保持单端点格式：log.level + [[endpoints]]）
reality_render_realm_config_multi() {
    local f listen_host
    listen_host="${REALITY_LISTEN_HOST:-$(reality_detect_listen_host)}"
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
    cat > /etc/systemd/system/realm.service <<'EOF'
[Unit]
Description=Realm TCP Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
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
    reality_relay_write_route "$RLY_LISTEN_PORT"
    reality_relay_write_client_artifacts || true
    REALITY_RELAY_DOMAIN=""; REALITY_RELAY_PORT=""
    REALITY_RELAY_TARGET_HOST=""; REALITY_RELAY_TARGET_PORT=""
    reality_write_state
}

# 根据 relays 目录重建 realm 配置、放行端口、刷新各线路客户端产物并重启 realm
reality_relay_regenerate() {
    mkdir -p /etc/realm "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR"
    reality_relay_migrate_legacy
    if [[ -z "$(reality_relay_route_files)" ]]; then
        systemctl disable --now realm >/dev/null 2>&1 || true
        rm -f "$REALITY_REALM_CONFIG"
        return 0
    fi
    reality_install_realm_binary || return 1
    reality_backup_file "$REALITY_REALM_CONFIG"
    reality_render_realm_config_multi > "$REALITY_REALM_CONFIG"
    chmod 600 "$REALITY_REALM_CONFIG"
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
    systemctl restart realm || return 1
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
          _s_sni="${REALITY_SNI:-}" _s_pbk="${REALITY_PUBLIC_KEY:-}" _s_sid="${REALITY_SHORT_ID:-}" _s_flow="${REALITY_FLOW:-}"
    reality_parse_vless_link "$link" || { print_error "落地机 vless 链接解析失败"; pause; return 1; }
    RLY_TARGET_HOST="$REALITY_NODE_DOMAIN"; RLY_TARGET_PORT="$REALITY_PORT"
    RLY_UUID="$REALITY_UUID"; RLY_SNI="$REALITY_SNI"; RLY_PUBLIC_KEY="$REALITY_PUBLIC_KEY"
    RLY_SHORT_ID="$REALITY_SHORT_ID"; RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    # 恢复本机落地身份
    REALITY_UUID="$_s_uuid"; REALITY_NODE_DOMAIN="$_s_node"; REALITY_PORT="$_s_port"
    REALITY_SNI="$_s_sni"; REALITY_PUBLIC_KEY="$_s_pbk"; REALITY_SHORT_ID="$_s_sid"; REALITY_FLOW="$_s_flow"
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
    # 监听端口：唯一、未占用、不等于落地端口
    local def_port; def_port=$(reality_random_port 2>/dev/null || echo "")
    RLY_LISTEN_PORT=""
    while true; do
        read -e -r -p "本机中转监听端口 [${def_port}] (0=取消): " RLY_LISTEN_PORT
        RLY_LISTEN_PORT="${RLY_LISTEN_PORT:-$def_port}"
        [[ "$RLY_LISTEN_PORT" == "0" || "$RLY_LISTEN_PORT" == "q" ]] && { print_info "已取消"; pause; return 0; }
        validate_port "$RLY_LISTEN_PORT" || { print_error "端口无效"; continue; }
        if [[ -n "${REALITY_PORT:-}" && "$RLY_LISTEN_PORT" == "${REALITY_PORT}" ]]; then print_error "不能与本机落地端口相同"; continue; fi
        [[ -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.conf" ]] && { print_error "该端口已有中转线路"; continue; }
        if reality_port_in_use "$RLY_LISTEN_PORT"; then print_error "端口已被占用"; continue; fi
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
    local f n=0 st
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        n=$((n+1))
        st="[未监听]"
        if command_exists ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${RLY_LISTEN_PORT}$"; then st="[监听中]"; fi
        echo "${n}. ${RLY_NAME}  本机:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}  ${st}"
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
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    # 同机若已有落地机 state，先加载以保留既有落地参数（纯重装中转、不导入链接的场景）。
    # 但本次若通过导入落地 vless 链接带入了客户端 Reality 身份(公钥/UUID/SNI/ShortID)，
    # 这些导入值必须覆盖磁盘旧值——否则中转客户端链接会错误地沿用本机旧落地身份，
    # 与真实落地机的 Reality 握手参数不匹配，导致节点不通。
    local _imp_uuid="${REALITY_UUID:-}" _imp_sni="${REALITY_SNI:-}" \
          _imp_pbk="${REALITY_PUBLIC_KEY:-}" _imp_sid="${REALITY_SHORT_ID:-}" \
          _imp_node="${REALITY_NODE_DOMAIN:-}" _imp_port="${REALITY_PORT:-}" \
          _imp_pkey="${REALITY_PRIVATE_KEY:-}" _imp_flow="${REALITY_FLOW:-}"
    reality_load_state || true
    if [[ -n "$_imp_pbk" ]]; then
        REALITY_UUID="$_imp_uuid"
        REALITY_SNI="$_imp_sni"
        REALITY_PUBLIC_KEY="$_imp_pbk"
        REALITY_SHORT_ID="$_imp_sid"
        REALITY_NODE_DOMAIN="$_imp_node"
        REALITY_PORT="$_imp_port"
        REALITY_PRIVATE_KEY="$_imp_pkey"
        REALITY_FLOW="$_imp_flow"
    fi
    reality_require_supported_os || return 1
    # 写为一条独立身份的中转线路（relays 目录是 realm 配置的唯一真相源）。
    RLY_NAME="${node_name:-$(reality_effective_node_name)}"
    RLY_LISTEN_PORT="$listen_port"
    RLY_CONNECT_HOST="$relay_domain"
    RLY_TARGET_HOST="$target_host"
    RLY_TARGET_PORT="$target_port"
    RLY_UUID="${REALITY_UUID:-}"; RLY_SNI="${REALITY_SNI:-}"
    RLY_PUBLIC_KEY="${REALITY_PUBLIC_KEY:-}"; RLY_SHORT_ID="${REALITY_SHORT_ID:-}"
    RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    reality_relay_write_route "$listen_port"
    if [[ -n "$cf_token" ]]; then reality_sync_cloudflare_dns "$relay_domain" "$cf_token"; fi
    reality_relay_regenerate || return 1
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
    local prompt="$1" forbidden="${2:-}" port input_port
    while true; do
        port=$(reality_random_port) || { print_error "无法生成可用随机端口"; return 1; }
        [[ -n "$forbidden" && "$port" == "$forbidden" ]] && continue
        read -e -r -p "${prompt} [${port}]: " input_port
        input_port=${input_port:-$port}
        validate_port "$input_port" || { print_error "端口无效"; continue; }
        if [[ -n "$forbidden" && "$input_port" == "$forbidden" ]]; then
            print_error "端口不能与 ${forbidden} 相同"
            continue
        fi
        echo "$input_port"
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
    echo "  4. IPv4+IPv6 双节点：两个域名、两个端口、两条客户端链接（推荐双栈线路对比）" >&2
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
    local role="" node="" node_v4="" node_v6="" dns_mode="" sni="" port="" port_v6="" cf_token="" relay_domain="" relay_port="" target_host="" target_port="" landing_link="" node_name="" node_name_v4="" node_name_v6=""
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
            [[ -z "$port" ]] && port=$(reality_prompt_port "IPv4 Reality 监听端口")
            [[ -z "$port_v6" ]] && port_v6=$(reality_prompt_port "IPv6 Reality 监听端口" "$port")
        else
            [[ -z "$port" ]] && port=$(reality_prompt_port "Reality 监听端口")
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
        [[ -z "$relay_port" ]] && relay_port=$(reality_prompt_port "Realm 中转监听端口")
        if [[ "$role" == "both" ]]; then
            target_host="127.0.0.1"; target_port="$port"
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
        else
            print_warn "SNI TLS/SAN 校验失败或当前网络不可达: $REALITY_SNI"
            tail -n 5 "${REALITY_SNI_CHECK_LOG:-/dev/null}" 2>/dev/null || true
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

reality_delete_node_info() {
    print_title "删除 Reality 节点信息"
    confirm "确认删除本机 Reality/Realm 管理信息? 不会卸载 sing-box 软件包" || return 0
    reality_load_state || true
    firewall_remove_reality_ports
    systemctl disable --now realm 2>/dev/null || true
    rm -f /etc/systemd/system/realm.service
    systemctl daemon-reload 2>/dev/null || true
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    rm -f "$REALITY_REALM_CONFIG"
    rm -f "$REALITY_STATE_FILE" "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" \
          "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6"
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
