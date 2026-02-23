# modules/05-fail2ban.sh - Fail2ban 管理
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
    draw_line
    echo -e "${C_CYAN}配置摘要:${C_RESET}"
    echo "  SSH 端口:     $port"
    echo "  最大重试:     $maxretry 次"
    echo "  检测窗口:     $findtime"
    echo "  封禁时间:     $bantime"
    echo "  封禁方式:     $ban_backend_info"
    [[ "$bantime" == "-1" ]] && echo -e "  ${C_YELLOW}提示: 永久封禁建议定期检查规则数量${C_RESET}"
    draw_line
    if ! confirm "确认应用此配置?"; then
        print_warn "已取消配置。"
        pause
        return
    fi

    # 迁移：清理旧的 UFW 封禁规则
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        local old_f2b_rules=$(ufw status numbered 2>/dev/null | grep -ciE "f2b|fail2ban" || echo 0)
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
[sshd]
enabled = true
port = $port
maxretry = $maxretry
backend = $backend
logpath = %(sshd_log)s"
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
    local ufw_rules="/etc/ufw/user.rules"
    local ufw_rules6="/etc/ufw/user6.rules"
    local total_removed=0
    for rf in "$ufw_rules" "$ufw_rules6"; do
        [[ -f "$rf" ]] || continue
        cp "$rf" "${rf}.bak.$(date +%s)"
        local before=$(wc -l < "$rf")
        sed -i '/f2b-/d; /Fail2ban/Id' "$rf"
        local after=$(wc -l < "$rf")
        local removed=$((before - after))
        total_removed=$((total_removed + removed))
        [[ $removed -gt 0 ]] && print_info "$(basename "$rf"): 清理 ${removed} 行"
    done
    ufw reload >/dev/null 2>&1 || true
    if [[ $total_removed -gt 0 ]]; then
        print_success "已清理 ${total_removed} 行 UFW 旧规则"
        log_action "Migrated fail2ban: cleaned $total_removed lines from UFW rules, switched to ipset"
    else
        print_info "无需清理"
    fi
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
    echo -e "${C_CYAN}[SSHD Jail 状态]${C_RESET}"
    fail2ban-client status sshd 2>/dev/null || echo "SSHD jail 未启用"
    echo -e "${C_CYAN}[当前封禁的 IP]${C_RESET}"
    local banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2 | xargs)
    if [[ -n "$banned" && "$banned" != "0" ]]; then
        echo "$banned" | tr ' ' '\n' | while read ip; do
            [[ -n "$ip" ]] && echo "  - $ip"
        done
    else
        echo "  (无)"
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
    local banned=$(fail2ban-client status sshd 2>/dev/null | grep "Banned IP" | cut -d: -f2 | xargs)
    if [[ -z "$banned" ]] || [[ "$banned" == "0" ]]; then
        print_warn "当前没有被封禁的 IP。"
        pause
        return
    fi
    echo "$banned" | tr ' ' '\n' | nl -w2 -s'. '
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
            for ip in $banned; do
                fail2ban-client set sshd unbanip "$ip" 2>/dev/null && \
                    print_success "已解封: $ip" || \
                    print_error "解封失败: $ip"
            done
            log_action "Fail2ban: unbanned all IPs"
        fi
    else
        if ! validate_ip "$input"; then
            print_error "无效的 IP 地址格式。"
            pause; return
        fi
        if fail2ban-client set sshd unbanip "$input" 2>/dev/null; then
            print_success "已解封: $input"
            log_action "Fail2ban: unbanned $input"
        else
            print_error "解封失败，请检查 IP 是否正确。"
        fi
    fi
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
4. 查看当前配置
5. 查看日志
6. 启动/停止服务
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) f2b_setup ;;
            2) f2b_status ;;
            3) f2b_unban ;;
            4) f2b_view_config ;;
            5) f2b_logs ;;
            6)
                if ! command_exists fail2ban-client; then
                    print_error "Fail2ban 未安装。"
                    pause
                    continue
                fi
                echo "1. 启动  2. 停止  3. 重启"
                read -e -r -p "选择: " sc
                case $sc in
                    1) systemctl start fail2ban && print_success "已启动" || print_error "启动失败" ;;
                    2) systemctl stop fail2ban && print_success "已停止" || print_error "停止失败" ;;
                    3) systemctl restart fail2ban && print_success "已重启" || print_error "重启失败" ;;
                esac
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

