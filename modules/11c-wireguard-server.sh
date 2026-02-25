# modules/11c-wireguard-server.sh - WireGuard server install/control/uninstall
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
    print_info "[1/5] 安装软件包..."
    wg_install_packages || { pause; return 1; }
    print_info "[2/5] 配置 IP 转发..."
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    print_success "IP 转发已开启"
    print_info "[3/5] 配置服务端参数..."
    local wg_port
    while true; do
        read -e -r -p "WireGuard 监听端口 [${WG_DEFAULT_PORT}]: " wg_port
        wg_port=${wg_port:-$WG_DEFAULT_PORT}
        if validate_port "$wg_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done
    local wg_subnet
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
    local wg_dns
    read -e -r -p "客户端 DNS [1.1.1.1, 8.8.8.8]: " wg_dns
    wg_dns=${wg_dns:-"1.1.1.1, 8.8.8.8"}
    local wg_endpoint default_ip
    default_ip=$(get_public_ipv4 || echo "")
    if [[ -n "$default_ip" ]]; then
        read -e -r -p "公网端点 IP/域名 [${default_ip}]: " wg_endpoint
        wg_endpoint=${wg_endpoint:-$default_ip}
    else
        while [[ -z "$wg_endpoint" ]]; do
            read -e -r -p "公网端点 IP/域名: " wg_endpoint
        done
    fi
    print_info "[4/5] 生成服务端密钥..."
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
    print_info "[5/5] 写入配置并启动..."
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
    '.server = {
        name: $sname,
        private_key: $pk,
        public_key: $pub,
        ip: $ip,
        subnet: $sub,
        port: ($port | tonumber),
        dns: $dns,
        endpoint: $ep
    }'
    wg_rebuild_conf
    if [[ "$PLATFORM" == "openwrt" ]]; then
        wg-quick up "$WG_INTERFACE" 2>/dev/null || true
    elif is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${wg_port}/udp" comment "WireGuard" >/dev/null 2>&1
        print_success "UFW 已放行端口 ${wg_port}/udp"
    fi
    draw_line
    if wg_is_running; then
        print_success "WireGuard 服务端安装并启动成功！"
    else
        print_warn "WireGuard 已安装，但启动可能失败，请检查日志"
    fi
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听端口: ${C_GREEN}${wg_port}/udp${C_RESET}"
    echo -e "  内网子网: ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP: ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  公网端点: ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    draw_line
    log_action "WireGuard server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint"

    # 自动安装服务端看门狗
    echo ""
    wg_setup_watchdog "true"

    pause
}

wg_modify_server() {
    wg_check_server || return 1
    print_title "修改 WireGuard 服务端配置"
    local cur_port cur_dns cur_ep
    cur_port=$(wg_db_get '.server.port')
    cur_dns=$(wg_db_get '.server.dns')
    cur_ep=$(wg_db_get '.server.endpoint')
    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
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
    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi
    wg_rebuild_conf
    wg_regenerate_client_confs
    if wg_is_running; then
        wg-quick down "$WG_INTERFACE" 2>/dev/null
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi
    if [[ "$new_port" != "$cur_port" ]]; then
        if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${cur_port}/udp" 2>/dev/null || true
            ufw allow "${new_port}/udp" comment "WireGuard" >/dev/null 2>&1
        fi
    fi
    print_success "服务端配置已更新"
    log_action "WireGuard server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep}"
    pause
}

wg_server_status() {
    wg_check_server || return 1
    print_title "WireGuard 服务端状态"
    local port subnet endpoint dns
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    endpoint=$(wg_db_get '.server.endpoint')
    dns=$(wg_db_get '.server.dns')
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    if wg_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi
    echo -e "  端口:     ${port}/udp"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line
    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "状态" "最近握手" "流量"
        draw_line
        local wg_dump=""
        wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip pubkey enabled
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            pubkey=$(wg_db_get ".peers[$i].public_key")
            enabled=$(wg_db_get ".peers[$i].enabled")
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
            printf "%-4s %-16s %-18s %-8b %-20s %-16s\n" \
                "$((i + 1))" "$name" "$ip" "$status_str" "$handshake_str" "$transfer_str"
            i=$((i + 1))
        done
    else
        print_info "暂无设备"
    fi
    draw_line
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    if [[ "$pf_count" -gt 0 ]]; then
        echo -e "${C_CYAN}端口转发规则 (${pf_count} 条):${C_RESET}"
        draw_line
        local j=0
        while [[ $j -lt $pf_count ]]; do
            local proto ext_port dest_ip dest_port pf_enabled
            proto=$(wg_db_get ".port_forwards[$j].proto")
            ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
            dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
            dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
            pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")
            local pf_status
            [[ "$pf_enabled" == "true" ]] && pf_status="${C_GREEN}●${C_RESET}" || pf_status="${C_RED}○${C_RESET}"
            echo -e "  ${pf_status} ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
            j=$((j + 1))
        done
        draw_line
    fi
    pause
}

wg_start() {
    if wg_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi
    if [[ ! -f "$WG_CONF" ]]; then
        print_error "配置文件不存在: ${WG_CONF}"
        return 1
    fi
    print_info "正在启动 WireGuard..."
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    if is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    fi
    sleep 1
    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已启动"
        log_action "WireGuard started"
    else
        print_error "启动失败"
        log_action "WireGuard start failed"
    fi
}

wg_stop() {
    if ! wg_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi
    print_info "正在停止 WireGuard..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null
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
    wg_is_running && wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1
    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
    fi
}

wg_restore_port_forwards() {
    local role
    role=$(wg_get_role)
    [[ "$role" != "server" ]] && return 0
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 || "$pf_count" == "null" ]] && return 0
    local j=0
    while [[ $j -lt $pf_count ]]; do
        local proto ext_port dest_ip dest_port pf_enabled
        proto=$(wg_db_get ".port_forwards[$j].proto")
        ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
        dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
        dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
        pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")
        if [[ "$pf_enabled" == "true" ]]; then
            _wg_pf_iptables_ensure "$proto" "$ext_port" "$dest_ip" "$dest_port"
        fi
        j=$((j + 1))
    done
}

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
    # 枚举所有 WireGuard 类型的网络接口并逐一清理
    local _wg_ifaces
    _wg_ifaces=$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | tr -d ' ')
    if [[ -z "$_wg_ifaces" ]]; then
        # fallback: 查找名称匹配的接口
        _wg_ifaces=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^wg[0-9_-]|^wg_' | tr -d ' ')
    fi
    # 始终确保 wg0 和 wg_mesh 在清理列表中
    for _must in "$WG_INTERFACE" wg_mesh wg-mesh; do
        if ip link show "$_must" &>/dev/null && ! echo "$_wg_ifaces" | grep -qw "$_must"; then
            _wg_ifaces="${_wg_ifaces:+$_wg_ifaces $_must}"
            [[ -z "$_wg_ifaces" ]] && _wg_ifaces="$_must"
        fi
    done
    for _iface in $_wg_ifaces; do
        print_info "  清理接口: $_iface"
        # 尝试 wg-quick down
        wg-quick down "$_iface" 2>/dev/null || true
        # 如果接口仍存在，强制用 ip link 删除
        if ip link show "$_iface" &>/dev/null; then
            ip link set "$_iface" down 2>/dev/null || true
            ip link delete "$_iface" 2>/dev/null || true
        fi
        # 禁用对应的 systemd 服务
        if is_systemd; then
            systemctl disable "wg-quick@${_iface}" >/dev/null 2>&1 || true
            systemctl stop "wg-quick@${_iface}" >/dev/null 2>&1 || true
        fi
    done
    # 二次确认: 检查是否还有残留的 wireguard 接口
    local _remaining
    _remaining=$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | tr -d ' ')
    if [[ -n "$_remaining" ]]; then
        print_warn "仍有残留接口，强制删除: $_remaining"
        for _r in $_remaining; do
            ip link delete "$_r" 2>/dev/null || true
        done
    fi
    print_info "[2/6] 清理端口转发规则..."
    if [[ "$role" == "server" ]]; then
        local pf_count
        pf_count=$(wg_db_get '.port_forwards | length' 2>/dev/null)
        if [[ -n "$pf_count" && "$pf_count" != "null" && "$pf_count" -gt 0 ]]; then
            local j=0
            while [[ $j -lt $pf_count ]]; do
                local proto ext_port dest_ip dest_port
                proto=$(wg_db_get ".port_forwards[$j].proto")
                ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
                dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
                dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
                _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
                j=$((j + 1))
            done
            wg_save_iptables
        fi
    fi
    print_info "[3/6] 清理防火墙规则..."
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [[ "$role" == "server" ]]; then
            local port
            port=$(wg_db_get '.server.port' 2>/dev/null)
            [[ -n "$port" ]] && ufw delete allow "${port}/udp" 2>/dev/null || true
        fi
        ufw status numbered 2>/dev/null | grep "WG-PF" | awk -F'[][]' '{print $2}' | sort -rn | while read -r num; do
            yes | ufw delete "$num" 2>/dev/null || true
        done
    fi
    print_info "[4/6] 清理所有看门狗和定时任务..."
    # 主看门狗
    if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
        cron_remove_job "wg-watchdog.sh"
    fi
    rm -f /usr/local/bin/wg-watchdog.sh /var/log/wg-watchdog.log 2>/dev/null || true
    # OpenWrt 看门狗（不同路径）
    rm -f /usr/bin/wg-watchdog.sh 2>/dev/null || true
    print_info "[5/6] 删除配置文件和临时文件..."
    rm -f "$WG_CONF" 2>/dev/null || true
    rm -rf /etc/wireguard/clients 2>/dev/null || true
    rm -f "$WG_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DB_DIR" 2>/dev/null || true
    rm -f "$WG_ROLE_FILE" 2>/dev/null || true
    rm -f /etc/wireguard/*.key 2>/dev/null || true
    rmdir /etc/wireguard 2>/dev/null || true
    # 清理所有 /tmp 临时文件
    rm -rf /tmp/.wg-wd-fail /tmp/.wg-watchdog-ping-fail \
           /tmp/.wg-db-tmp.json /tmp/clash-wg-*.yaml \
           /tmp/.wg-watchdog-stale 2>/dev/null || true
    # OpenWrt: 自动清理 uci 配置
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_info "清理 OpenWrt 网络和防火墙配置..."
        ifdown wg0 2>/dev/null || true
        ifdown wg_mesh 2>/dev/null || true
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
        # 清理 OpenClash 绕过规则
        ip rule del lookup main prio 100 2>/dev/null || true
        for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print $NF}'); do
            nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null || true
        done
        sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null || true
        uci commit network 2>/dev/null || true
        uci commit firewall 2>/dev/null || true
    fi
    print_info "[6/6] 卸载软件包..."
    local remove_pkg=true
    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        case $PLATFORM in
            debian|ubuntu)
                apt-get remove -y wireguard wireguard-tools >/dev/null 2>&1 || true
                apt-get autoremove -y >/dev/null 2>&1 || true
                ;;
            centos|rhel|rocky|alma|fedora)
                if command_exists dnf; then
                    dnf remove -y wireguard-tools >/dev/null 2>&1 || true
                else
                    yum remove -y wireguard-tools >/dev/null 2>&1 || true
                fi
                ;;
            alpine)
                apk del wireguard-tools >/dev/null 2>&1 || true
                ;;
            arch|manjaro)
                pacman -Rns --noconfirm wireguard-tools >/dev/null 2>&1 || true
                ;;
            openwrt)
                opkg remove wireguard-tools luci-proto-wireguard >/dev/null 2>&1 || true
                ;;
        esac
    else
        remove_pkg=false
    fi
    # 清理可能残留的 WireGuard iptables 规则
    if command_exists iptables; then
        iptables -S 2>/dev/null | grep -i "wg\|wireguard\|${WG_INTERFACE}" | while read -r rule; do
            iptables $(echo "$rule" | sed 's/^-A/-D/') 2>/dev/null || true
        done
        iptables -t nat -S 2>/dev/null | grep -i "wg\|wireguard\|${WG_INTERFACE}" | while read -r rule; do
            iptables -t nat $(echo "$rule" | sed 's/^-A/-D/') 2>/dev/null || true
        done
        wg_save_iptables 2>/dev/null || true
    fi
    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
        fi
    fi
    draw_line
    print_success "WireGuard 已完全卸载 (所有配置、脚本、定时任务已清理)"
    draw_line
    log_action "WireGuard uninstalled: role=${role} pkg_removed=${remove_pkg}"
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
# 强制删除内核接口 (确保不残留)
for iface in $(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}'); do
    ip link set "$iface" down 2>/dev/null; true
    ip link delete "$iface" 2>/dev/null; true
    echo "[+] 已删除接口: $iface"
done
# 兜底: 按名称匹配
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

# === 删除所有 wireguard peer 配置段 (含匿名段) ===
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done
while uci -q get network.@wireguard_wg_mesh[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg_mesh[0]
done
uci delete network.wg_server 2>/dev/null; true

# === 删除网络接口 ===
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_mesh 2>/dev/null; true

# === 删除防火墙配置 (命名段 + 匿名段) ===
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci delete firewall.wg_mesh_zone 2>/dev/null; true
uci delete firewall.wg_mesh_fwd 2>/dev/null; true
uci delete firewall.wg_mesh_fwd_lan 2>/dev/null; true
# 清理匿名 zone (名称为 wg/wireguard/wg_mesh 的)
i=0
while uci get firewall.@zone[$i] >/dev/null 2>&1; do
    zname=$(uci get firewall.@zone[$i].name 2>/dev/null)
    case "$zname" in
        wg|wireguard|wg_mesh)
            uci delete "firewall.@zone[$i]" 2>/dev/null; true
            echo "[+] 已删除匿名防火墙 zone: $zname"
            continue  # index 不变因为后面的元素前移了
            ;;
    esac
    i=$((i + 1))
done
# 清理匿名 forwarding (src/dest 包含 wg 的)
i=0
while uci get firewall.@forwarding[$i] >/dev/null 2>&1; do
    fsrc=$(uci get firewall.@forwarding[$i].src 2>/dev/null)
    fdest=$(uci get firewall.@forwarding[$i].dest 2>/dev/null)
    case "$fsrc" in wg|wg_mesh) ;; *) case "$fdest" in wg|wg_mesh) ;; *) i=$((i+1)); continue ;; esac ;; esac
    uci delete "firewall.@forwarding[$i]" 2>/dev/null; true
    echo "[+] 已删除匿名防火墙 forwarding: $fsrc -> $fdest"
done

# === 清理 OpenClash 绕过规则 ===
ip rule del lookup main prio 100 2>/dev/null; true
for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print $NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
done
sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true

# === 提交并重载 ===
uci commit network
uci commit firewall
/etc/init.d/firewall restart 2>/dev/null; true
/etc/init.d/network restart 2>/dev/null; true

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

