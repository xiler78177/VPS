# modules/07-system.sh - 系统更新、优化、包管理
menu_update() {
    print_title "基础依赖安装"
    print_info "正在检查并安装基础依赖..."
    local ufw_was_active=0
    local f2b_was_active=0
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw_was_active=1
    fi
    if systemctl is-active fail2ban &>/dev/null; then
        f2b_was_active=1
    fi
    print_info "1/2 更新软件源..."
    if apt-get update >/dev/null 2>&1; then
        print_success "软件源更新完成"
    else
        print_warn "软件源更新失败，但继续安装"
    fi
    print_info "2/2 安装基础依赖包..."
    local deps="curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iproute2 net-tools procps"
    local installed=0
    local failed=0
    local new_packages=""
    for pkg in $deps; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo "  ✓ $pkg (已安装)"
        else
            echo -n "  → 正在安装 $pkg ... "
            if (DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" >/dev/null 2>&1); then
                echo -e "${C_GREEN}成功${C_RESET}"
                ((installed++)) || true
                new_packages="$new_packages $pkg"
            else
                echo -e "${C_RED}失败${C_RESET}"
                ((failed++)) || true
            fi
        fi
    done
    echo "================================================================================"
    print_success "基础依赖安装完成"
    echo "  新安装: $installed 个"
    [[ $failed -gt 0 ]] && echo -e "  ${C_RED}失败: $failed 个${C_RESET}"
    if [[ "$new_packages" == *"ufw"* ]] || [[ "$new_packages" == *"fail2ban"* ]]; then
        echo -e "${C_YELLOW}提示:${C_RESET} 检测到新安装的安全服务"
        [[ "$new_packages" == *"ufw"* ]] && echo "  - UFW 防火墙: 请通过菜单 [2] 配置后启用"
        [[ "$new_packages" == *"fail2ban"* ]] && echo "  - Fail2ban: 请通过菜单 [3] 配置后启用"
    fi
    if [[ $ufw_was_active -eq 1 ]]; then
        ufw --force enable >/dev/null 2>&1 || true
    fi
    if [[ $f2b_was_active -eq 1 ]]; then
        systemctl start fail2ban >/dev/null 2>&1 || true
    fi
    echo "================================================================================"
    log_action "Basic dependencies installed/checked"
    pause
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
        if command -v "${pkg%%-*}" &>/dev/null 2>&1 || opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
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
auto_deps() {
    local deps="curl wget jq unzip openssl ca-certificates iproute2 net-tools procps"
    for p in $deps; do
        dpkg -s "$p" &> /dev/null || install_package "$p" "silent"
    done
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
    if command_exists hostnamectl; then
        hostnamectl set-hostname "$new_name"
    else
        hostname "$new_name"
        echo "$new_name" > /etc/hostname
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
        sysctl -p >/dev/null
        print_success "BBR 已开启。"
        log_action "BBR enabled"
    fi
    pause
}

select_timezone() {
    echo "1.上海 2.香港 3.东京 4.纽约 5.伦敦 6.UTC"
    read -e -r -p "选择: " t
    local z
    case $t in
        1) z="Asia/Shanghai" ;; 2) z="Asia/Hong_Kong" ;; 3) z="Asia/Tokyo" ;;
        4) z="America/New_York" ;; 5) z="Europe/London" ;; 6) z="UTC" ;;
        *) print_error "无效选择"; return 1 ;;
    esac
    # 优先使用 timedatectl（systemd 系统），回退到软链接
    if command_exists timedatectl; then
        timedatectl set-timezone "$z"
    else
        ln -sf /usr/share/zoneinfo/$z /etc/localtime
    fi
    print_success "时区已设为 $z"
    log_action "Timezone changed to $z"
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
0. 返回
"
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_swap ;;
            3) opt_hostname ;;
            4) opt_cleanup ;;
            5) select_timezone || true; pause ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

