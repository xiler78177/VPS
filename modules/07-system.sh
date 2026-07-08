# modules/07-system.sh - 系统更新、优化、包管理
menu_update() {
    print_title "依赖检查与修复"
    print_info "强制重新检查所有依赖包..."
    local FULL_DEPS="curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iptables iproute2 net-tools procps"
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
    local FULL_DEPS="curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iptables iproute2 net-tools procps"
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
        # Debian 13 等镜像默认不加载 tcp_bbr 模块，导致 available_cc 里没有 bbr。
        # 统一走 _sysctl_ensure_bbr_module（modprobe + 持久化到 modules-load.d），再重读 available_cc。
        _sysctl_ensure_bbr_module || true
        available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
    fi
    if [[ " $available_cc " != *" bbr "* ]]; then
        print_error "当前内核未暴露 bbr 拥塞控制算法，且加载 tcp_bbr 模块失败。"
        print_info "可能是内核未编译 BBR 支持（需内核 ≥ 4.9），请确认内核版本或更换内核。"
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

# 确保 tcp_bbr 内核模块已加载并开机持久化。Debian 13/trixie 等镜像默认不预载该模块，
# 导致 tcp_available_congestion_control 里没有 bbr、被误判为“内核不支持”。
# 幂等：模块已在则直接返回 0。返回 0=bbr 现已可用；1=加载失败/内核无 BBR 支持。
# 所有提示输出到 stderr —— 本函数会被 _sysctl_detect_cc_for_tuning 在 $(...) 命令替换中调用，
# 任何 stdout 都会污染被捕获的算法名。
_sysctl_ensure_bbr_module() {
    local available
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    [[ " $available " == *" bbr "* ]] && return 0
    command_exists modprobe || return 1
    modprobe tcp_bbr 2>/dev/null || return 1
    print_info "已加载 tcp_bbr 内核模块。" >&2
    local bbr_modconf="/etc/modules-load.d/${SCRIPT_NAME}-bbr.conf"
    write_file_atomic "$bbr_modconf" "# ${SCRIPT_NAME}: 开机自动加载 BBR 拥塞控制模块
tcp_bbr" || print_warn "tcp_bbr 已加载，但持久化 ${bbr_modconf} 失败；重启后可能需重新加载。" >&2
    available=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)
    [[ " $available " == *" bbr "* ]]
}

_sysctl_detect_cc_for_tuning() {
    local available
    # 先确保 bbr 模块已加载（Debian 13 默认不预载），避免角色调优静默不写 bbr/fq。
    _sysctl_ensure_bbr_module >/dev/null 2>&1 || true
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
