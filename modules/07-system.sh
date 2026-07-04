# modules/07-system.sh - 系统更新、优化、包管理
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
    echo "当前配置:"
    echo "  拥塞控制: $current_cc"
    echo "  队列算法: $current_qdisc"
    if [[ "$current_cc" == "bbr" ]]; then
        print_success "BBR 已启用。"
        pause; return
    fi
    if confirm "开启 BBR 加速？"; then
        local sysctl_conf sysctl_backup sysctl_dir tmp_candidate verify_cc
        sysctl_conf="$(_sysctl_conf_path)"
        sysctl_backup="$(_sysctl_bbr_backup_path)"
        sysctl_dir="$(dirname "$sysctl_conf")"
        mkdir -p "$sysctl_dir" || { print_error "创建 sysctl 配置目录失败"; pause; return 1; }
        tmp_candidate=$(mktemp "${sysctl_dir}/.tmp.server-manage.bbr.XXXXXX") || { print_error "创建临时 BBR 配置失败"; pause; return 1; }
        _tmp_register "$tmp_candidate"
        if ! _sysctl_render_bbr_conf "$sysctl_conf" "fq" "bbr" > "$tmp_candidate"; then
            rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
            print_error "生成 BBR 配置失败"; pause; return 1
        fi
        if [[ -f "$sysctl_conf" ]]; then
            chmod --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
            chown --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
        else
            chmod 644 "$tmp_candidate" 2>/dev/null || true
        fi
        if ! sysctl -p "$tmp_candidate" >/dev/null 2>&1; then
            rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
            print_error "sysctl -p 执行失败，BBR 未写入正式配置。"
            log_action "BBR enable failed before commit: sysctl -p" "ERROR"
            pause; return 1
        fi
        verify_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
        if [[ "$verify_cc" != "bbr" ]]; then
            rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
            [[ -f "$sysctl_conf" ]] && sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
            print_error "BBR 未实际生效 (当前: $verify_cc)，未写入正式配置。"
            log_action "BBR enable failed before commit: verify_cc=$verify_cc" "ERROR"
            pause; return 1
        fi
        if [[ ! -f "$sysctl_backup" && -f "$sysctl_conf" ]]; then
            if ! cp -a "$sysctl_conf" "$sysctl_backup"; then
                rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
                sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
                print_error "备份 sysctl 配置失败，未写入正式配置。"
                log_action "BBR enable failed before commit: backup" "ERROR"
                pause; return 1
            fi
        fi
        if ! mv "$tmp_candidate" "$sysctl_conf"; then
            rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
            [[ -f "$sysctl_conf" ]] && sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
            print_error "写入 $sysctl_conf 失败"
            pause; return 1
        fi
        _tmp_unregister "$tmp_candidate"
        print_success "BBR 已开启。"
        log_action "BBR enabled"
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
    printf '%s' "/etc/sysctl.conf"
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
    if ! grep -q '^[[:space:]]*net\.ipv4\.ip_forward[[:space:]=]' "$tmp_check"; then
        sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
    fi
    rm -f "$tmp_check"; _tmp_unregister "$tmp_check"
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
    local sysctl_conf sysctl_backup
    sysctl_conf="$(_sysctl_conf_path)"
    sysctl_backup="$(_sysctl_backup_path)"
    if [[ "$sc" == "4" ]]; then
        if [[ -f "$sysctl_backup" ]]; then
            cp "$sysctl_backup" "$sysctl_conf"
            sysctl -p "$sysctl_conf" >/dev/null 2>&1
            print_success "已回滚到调优前的配置。"
            log_action "Sysctl tuning rolled back"
        else
            print_warn "没有找到备份文件。"
        fi
        pause; return
    fi
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
    local sysctl_dir tmp_candidate
    sysctl_dir="$(dirname "$sysctl_conf")"
    mkdir -p "$sysctl_dir" || { print_error "创建 sysctl 配置目录失败"; pause; return 1; }
    tmp_candidate=$(mktemp "${sysctl_dir}/.tmp.server-manage.sysctl.XXXXXX") || { print_error "创建临时 sysctl 配置失败"; pause; return 1; }
    _tmp_register "$tmp_candidate"
    if ! _sysctl_render_tuned_conf "$sysctl_conf" "$params" > "$tmp_candidate"; then
        rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
        print_error "生成 sysctl 配置失败"; pause; return 1
    fi
    if [[ -f "$sysctl_conf" ]]; then
        chmod --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
        chown --reference="$sysctl_conf" "$tmp_candidate" 2>/dev/null || true
    else
        chmod 644 "$tmp_candidate" 2>/dev/null || true
    fi
    if sysctl -p "$tmp_candidate" >/dev/null 2>&1; then
        if [[ ! -f "$sysctl_backup" && -f "$sysctl_conf" ]]; then
            if ! cp -a "$sysctl_conf" "$sysctl_backup"; then
                rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
                sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
                print_error "备份 sysctl 配置失败，未写入正式配置。"
                log_action "Sysctl tuning failed before commit: backup" "ERROR"
                pause; return 1
            fi
        fi
        if ! mv "$tmp_candidate" "$sysctl_conf"; then
            rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
            sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
            print_error "写入 $sysctl_conf 失败"
            pause; return 1
        fi
        _tmp_unregister "$tmp_candidate"
        print_success "内核参数已应用 (无需重启)。"
        log_action "Sysctl tuning applied: preset=$sc"
    else
        rm -f "$tmp_candidate"; _tmp_unregister "$tmp_candidate"
        print_error "sysctl -p 执行失败，未写入正式配置。"
        log_action "Sysctl tuning failed before commit: preset=$sc" "ERROR"
        pause; return 1
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
