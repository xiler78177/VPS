# modules/11c-wireguard-server.sh - WireGuard server install/control/uninstall (OpenWrt)
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
    local changed=false

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
        wg_db_set --arg l "$new_lan" '.server.server_lan_subnet = $l'
        changed=true
        print_info "LAN 子网将更改为 ${new_lan}"
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
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
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
    fi
}

# ── Mihomo bypass 函数 ──

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
    sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null || true
    local rc_block="# WireGuard bypass Mihomo\nnft insert rule inet fw4 mangle_prerouting iifname \\\"wg0\\\" counter return comment \\\"wg_bypass_iface\\\" 2>/dev/null || true"
    for cidr in "${unique_subnets[@]}"; do
        rc_block="${rc_block}\nnft insert rule inet fw4 mangle_prerouting ip daddr \\\"${cidr}\\\" counter return comment \\\"wg_bypass_subnet\\\" 2>/dev/null || true"
    done
    if grep -q "^exit 0" /etc/rc.local 2>/dev/null; then
        sed -i "/^exit 0/i\\
${rc_block}" /etc/rc.local 2>/dev/null || true
    else
        echo -e "$rc_block" >> /etc/rc.local
    fi

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
    sed -i '/wg_bypass/d; /wg_allow_port/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null || true
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
        if grep -q "^exit 0" /etc/rc.local 2>/dev/null; then
            sed -i "/^exit 0/i\\
nft insert rule inet fw4 input_wan udp dport ${wg_port} counter accept comment \\\"wg_allow_port\\\" 2>/dev/null || true" \
                /etc/rc.local 2>/dev/null || true
        else
            echo "nft insert rule inet fw4 input_wan udp dport ${wg_port} counter accept comment \"wg_allow_port\" 2>/dev/null || true" >> /etc/rc.local
        fi
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
    # 清理策略路由
    ip rule del lookup main prio 100 2>/dev/null || true

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
    rm -f /etc/wireguard/*.key 2>/dev/null || true
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
ip rule del lookup main prio 100 2>/dev/null; true
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
