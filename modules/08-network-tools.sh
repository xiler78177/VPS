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
