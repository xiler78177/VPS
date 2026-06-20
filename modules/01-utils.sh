# modules/01-utils.sh - 通用工具函数
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
