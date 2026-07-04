# modules/08-network-tools.sh - 网络测试工具
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
