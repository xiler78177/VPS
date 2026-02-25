# modules/08-network-tools.sh - 网络测试工具
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
        if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
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
        pkill -f "iperf3 -s -p $port" 2>/dev/null || true
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
    echo -e "${C_CYAN}━━━ DNS 预设方案 ━━━${C_RESET}"
    echo -e "  ${C_YELLOW}── 境外通用 ──${C_RESET}"
    echo "  1. Cloudflare          1.1.1.1 1.0.0.1
  2. Google              8.8.8.8 8.8.4.4
  3. Cloudflare + Google 1.1.1.1 8.8.8.8
"
    echo -e "  ${C_YELLOW}── 境内通用 ──${C_RESET}"
    echo "  4. 阿里 DNS            223.5.5.5 223.6.6.6
  5. 腾讯 DNS            119.29.29.29 119.28.28.28
  6. 114 DNS             114.114.114.114 114.114.115.115
"
    echo -e "  ${C_YELLOW}── IPv6 ──${C_RESET}"
    echo "  7. Cloudflare IPv6     2606:4700:4700::1111 2606:4700:4700::1001
  8. Google IPv6         2001:4860:4860::8888 2001:4860:4860::8844
  9. 阿里 IPv6           2400:3200::1 2400:3200:baba::1
"
    echo -e "  ${C_YELLOW}── 混合方案 ──${C_RESET}"
    echo "  10. 境外双栈 (CF v4+v6)       1.1.1.1 2606:4700:4700::1111
  11. 境内双栈 (阿里 v4+v6)     223.5.5.5 2400:3200::1
  12. 境内+境外混合              223.5.5.5 1.1.1.1
  0. 自定义输入
"
    read -e -r -p "选择方案 [0]: " dns_choice
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
        0)
            echo -e "${C_YELLOW}输入 DNS IP (空格隔开)，输入 0 取消${C_RESET}"
            read -e -r -p "DNS: " dns
            [[ -z "$dns" || "$dns" == "0" ]] && return
            ;;
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
        uci delete network.wan.dns 2>/dev/null || true
        for ip in $dns; do
            uci add_list network.wan.dns="$ip"
        done
        uci set network.wan.peerdns='0'
        uci commit network
        /etc/init.d/network reload 2>/dev/null || true
        print_success "DNS 已通过 uci 修改 (持久化)。"
    elif is_systemd && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        local res_conf="/etc/systemd/resolved.conf"
        grep -q '^\[Resolve\]' "$res_conf" || echo -e "\n[Resolve]" >> "$res_conf"
        sed -i '/^DNS=/d' "$res_conf"
        sed -i '/^\[Resolve\]/a DNS='"$dns" "$res_conf"
        systemctl restart systemd-resolved
        print_success "DNS 已修改。"
    else
        local tmp_resolv
        tmp_resolv=$(mktemp /etc/resolv.conf.tmp.XXXXXX)
        for ip in $dns; do
            echo "nameserver $ip" >> "$tmp_resolv"
        done
        mv "$tmp_resolv" /etc/resolv.conf
        print_success "DNS 已修改。"
    fi
    log_action "DNS changed to: $dns"
    pause
}

menu_net() {
    fix_terminal
    while true; do
        print_title "网络管理工具"
        echo "1. DNS 配置
2. IPv4/IPv6 优先级
3. iPerf3 测速
0. 返回
"
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) 
                echo "1. 优先 IPv4  2. 优先 IPv6"
                read -e -r -p "选: " p
                [[ ! -f /etc/gai.conf ]] && touch /etc/gai.conf
                # 先清除已有配置行，再按需添加
                sed -i '/^#\?precedence ::ffff:0:0\/96  100/d' /etc/gai.conf
                if [[ "$p" == "1" ]]; then
                    echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
                    print_success "IPv4 优先。"
                else
                    print_success "IPv6 优先。"
                fi
                log_action "IP priority changed"
                pause ;;
            3) net_iperf3 ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
