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
print_warn() { echo -e "${C_YELLOW}[!]${C_RESET} $1"; }
print_error() { echo -e "${C_RED}[✗]${C_RESET} $1"; }
log_action() {
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

write_file_atomic() {
    local filepath="$1" content="$2" tmpfile
    mkdir -p "$(dirname "$filepath")"
    tmpfile=$(mktemp "$(dirname "$filepath")/.tmp.server-manage.XXXXXX")
    printf "%s\n" "$content" > "$tmpfile"
    if [[ -f "$filepath" ]]; then
        chmod --reference="$filepath" "$tmpfile" 2>/dev/null || true
        chown --reference="$filepath" "$tmpfile" 2>/dev/null || true
    fi
    if ! mv "$tmpfile" "$filepath"; then
        rm -f "$tmpfile"
        return 1
    fi
}

handle_interrupt() {
    # 仅清理本脚本创建的临时文件，避免误删其他服务的文件
    rm -f /etc/.tmp.server-manage.* 2>/dev/null
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
    is_systemd && { systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; return $?; }
    return 1
}

is_systemd() {
    command_exists systemctl || return 1
    [[ -d /run/systemd/system ]] || return 1
    [[ "$(ps -p 1 -o comm= 2>/dev/null)" == "systemd" ]] || return 1
    return 0
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
    if grep -qE "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+" "$file"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$file"
    else
        printf '\n# server-manage: appended %s\n%s %s\n' "$key" "$key" "$value" >> "$file"
    fi
}

refresh_ssh_port() {
    local p=""
    # 优先用 sshd -T 解析有效配置（覆盖 /etc/ssh/sshd_config + sshd_config.d/*.conf 全部 drop-in）
    if command_exists sshd; then
        p=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')
    fi
    # 回退：grep 主配 + drop-in（按字母序，后者优先）
    if [[ ! "$p" =~ ^[0-9]+$ ]]; then
        local files=("$SSHD_CONFIG") f
        if [[ -d /etc/ssh/sshd_config.d ]]; then
            while IFS= read -r f; do
                files+=("$f")
            done < <(ls /etc/ssh/sshd_config.d/*.conf 2>/dev/null | sort)
        fi
        for f in "${files[@]}"; do
            [[ -f "$f" ]] || continue
            local cand
            cand=$(grep -iE "^\s*Port\s+" "$f" 2>/dev/null | tail -n 1 | awk '{print $2}')
            [[ "$cand" =~ ^[0-9]+$ ]] && p="$cand"
        done
    fi
    if [[ "$p" =~ ^[0-9]+$ ]]; then
        CURRENT_SSH_PORT="$p"
    else
        CURRENT_SSH_PORT=$DEFAULT_SSH_PORT
    fi
}

confirm() {
    local prompt="$1"
    local reply
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
    # IPv6 验证：必须包含冒号，仅允许十六进制和冒号，长度合理，不允许连续3个冒号
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]; then
        [[ ${#ip} -le 39 ]] || return 1
        [[ ! "$ip" == *:::* ]] || return 1
        return 0
    fi
    return 1
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
    crontab -l 2>/dev/null | grep -v "$pattern" > "$cron_tmp" || true
    crontab "$cron_tmp" 2>/dev/null
    rm -f "$cron_tmp"
}

cron_add_job() {
    local pattern="$1" line="$2"
    local cron_tmp
    cron_tmp=$(mktemp) || return 1
    crontab -l 2>/dev/null | grep -v "$pattern" > "$cron_tmp" || true
    echo "$line" >> "$cron_tmp"
    crontab "$cron_tmp" 2>/dev/null
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
