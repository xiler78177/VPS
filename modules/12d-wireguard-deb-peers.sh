# modules/12d-wireguard-deb-peers.sh - Debian/Ubuntu WireGuard 设备管理
wg_deb_add_peer() {
    wg_deb_check_server || return 1
    print_title "添加 WireGuard 设备 (Peer)"
    local peer_name
    while true; do
        read -e -r -p "设备名称 (如 phone, laptop): " peer_name
        [[ -z "$peer_name" ]] && { print_warn "名称不能为空"; continue; }
        local exists
        exists=$(wg_deb_db_get --arg n "$peer_name" '.peers[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "设备名 '$peer_name' 已存在"; continue; }
        [[ ! "$peer_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母、数字、下划线、连字符"; continue; }
        break
    done
    local peer_ip
    peer_ip=$(wg_deb_next_ip) || { pause; return 1; }
    echo -e "  分配 IP: ${C_GREEN}${peer_ip}${C_RESET}"
    local peer_privkey peer_pubkey psk
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)

    # ── 设备类型选择 ──
    local peer_type="standard"
    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:"
    echo -e "  1. ${C_CYAN}Clash 客户端${C_RESET} (手机/电脑，通过 FlClash/FClash 规则接入)"
    echo -e "  2. ${C_YELLOW}网关设备${C_RESET} (路由器，暴露自身 LAN 子网)"
    echo -e "  3. 标准 WireGuard 客户端 (原生 .conf 配置)"
    read -e -r -p "选择 [1]: " device_type
    device_type=${device_type:-1}

    case "$device_type" in
        1)
            peer_type="clash"
            is_gateway="false"
            ;;
        2)
            peer_type="gateway"
            is_gateway="true"
            echo ""
            print_guide "请输入该网关后面的 LAN 网段 (将被路由到 VPN 中)"
            print_guide "示例: 192.168.123.0/24"
            print_guide "多个网段用逗号分隔: 192.168.1.0/24, 192.168.2.0/24"
            while [[ -z "$lan_subnets" ]]; do
                read -e -r -p "LAN 网段: " lan_subnets
                if [[ -z "$lan_subnets" ]]; then
                    print_warn "网关设备必须指定 LAN 网段"
                elif ! echo "$lan_subnets" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'; then
                    print_warn "格式无效，示例: 192.168.123.0/24"
                    lan_subnets=""
                fi
            done
            ;;
        3)
            peer_type="standard"
            is_gateway="false"
            ;;
        *)
            peer_type="clash"
            is_gateway="false"
            ;;
    esac

    # ── 路由模式 ──
    local client_allowed_ips server_subnet server_lan
    server_subnet=$(wg_deb_db_get '.server.subnet')
    server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')

    # 收集所有网关 LAN 网段
    local all_lan_subnets=""
    local pc=$(wg_deb_db_get '.peers | length') pi=0
    while [[ $pi -lt $pc ]]; do
        local pls=$(wg_deb_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" && "$pls" != "null" ]]; then
            [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
            all_lan_subnets="${all_lan_subnets}${pls}"
        fi
        pi=$((pi + 1))
    done
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
        all_lan_subnets="${all_lan_subnets}${lan_subnets}"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
        echo -e "  Clash 路由模式: ${C_CYAN}VPN 子网 + 所有 LAN 子网${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    elif [[ "$peer_type" == "gateway" ]]; then
        local other_lans=""
        local IFS_BAK="$IFS"; IFS=','
        for cidr in $all_lan_subnets; do
            cidr=$(echo "$cidr" | xargs)
            [[ -z "$cidr" ]] && continue
            local dominated=false
            local IFS2_BAK="$IFS"; IFS=','
            for own in $lan_subnets; do
                own=$(echo "$own" | xargs)
                [[ "$cidr" == "$own" ]] && { dominated=true; break; }
            done
            IFS="$IFS2_BAK"
            [[ "$dominated" != "true" ]] && { [[ -n "$other_lans" ]] && other_lans="${other_lans}, "; other_lans="${other_lans}${cidr}"; }
        done
        IFS="$IFS_BAK"
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$other_lans" ]] && client_allowed_ips="${client_allowed_ips}, ${other_lans}"
        echo -e "  网关路由模式: ${C_YELLOW}VPN 子网 + 服务端 LAN + 其他网关 LAN${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    else
        echo ""
        echo "客户端路由模式:"
        echo "  1. 全局代理 (所有流量走 VPN) - 0.0.0.0/0"
        echo "  2. 仅 VPN 内网 (只访问 VPN 内部设备)"
        echo "  3. VPN 内网 + 所有 LAN 网段 (访问远程内网设备)"
        echo "  4. 自定义路由"
        read -e -r -p "选择 [1]: " route_mode
        route_mode=${route_mode:-1}
        case $route_mode in
            1) client_allowed_ips="0.0.0.0/0, ::/0" ;;
            2) client_allowed_ips="$server_subnet" ;;
            3)
                client_allowed_ips="$server_subnet"
                [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
                [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
                ;;
            4)
                read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
                [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
                ;;
            *) client_allowed_ips="0.0.0.0/0, ::/0" ;;
        esac
    fi

    # ── 生成客户端配置文件 ──
    local spub sep sport sdns mask
    spub=$(wg_deb_db_get '.server.public_key')
    sep=$(wg_deb_db_get '.server.endpoint')
    sport=$(wg_deb_db_get '.server.port')
    sdns=$(wg_deb_db_get '.server.dns')
    mask=$(echo "$server_subnet" | cut -d'/' -f2)
    local dns_line=""
    [[ "$is_gateway" != "true" ]] && dns_line="DNS = ${sdns}"
    local client_conf="[Interface]
PrivateKey = ${peer_privkey}
Address = ${peer_ip}/${mask}
${dns_line}
[Peer]
PublicKey = ${spub}
PresharedKey = ${psk}
Endpoint = ${sep}:${sport}
AllowedIPs = ${client_allowed_ips}
PersistentKeepalive = 25"
    client_conf=$(echo "$client_conf" | sed '/^$/N;/^\n$/d')
    mkdir -p "$WG_DEB_CLIENT_DIR"
    local conf_file="${WG_DEB_CLIENT_DIR}/${peer_name}.conf"
    write_file_atomic "$conf_file" "$client_conf"
    chmod 600 "$conf_file"

    # ── 写入数据库 ──
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    wg_deb_db_set --arg name "$peer_name" \
              --arg ip "$peer_ip" \
              --arg privkey "$peer_privkey" \
              --arg pubkey "$peer_pubkey" \
              --arg psk "$psk" \
              --arg allowed "$client_allowed_ips" \
              --arg created "$now" \
              --arg gw "$is_gateway" \
              --arg lans "$lan_subnets" \
              --arg ptype "$peer_type" \
    '.peers += [{
        name: $name,
        ip: $ip,
        private_key: $privkey,
        public_key: $pubkey,
        preshared_key: $psk,
        client_allowed_ips: $allowed,
        enabled: true,
        created: $created,
        is_gateway: ($gw == "true"),
        lan_subnets: $lans,
        peer_type: $ptype
    }]'

    # ── 网关设备: 联动更新其他 peer 的 allowed_ips ──
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        _wg_deb_update_peer_routes
    fi

    # ── 重建配置并应用 ──
    wg_deb_rebuild_conf
    wg_deb_regenerate_client_confs

    # 重启使新 peer 生效
    if wg_deb_is_running; then
        systemctl restart wg-quick@wg0 >/dev/null 2>&1
        sleep 1
    fi

    # ── 结果展示 ──
    draw_line
    print_success "设备 '${peer_name}' 添加成功！"
    draw_line
    echo -e "  名称: ${C_GREEN}${peer_name}${C_RESET}"
    echo -e "  IP:   ${C_GREEN}${peer_ip}${C_RESET}"
    case "$peer_type" in
        clash)   echo -e "  类型: ${C_CYAN}Clash 客户端${C_RESET}" ;;
        gateway) echo -e "  类型: ${C_YELLOW}网关设备${C_RESET}"; echo -e "  LAN:  ${C_CYAN}${lan_subnets}${C_RESET}" ;;
        *)       echo -e "  类型: 标准客户端" ;;
    esac
    echo -e "  路由: ${C_CYAN}${client_allowed_ips}${C_RESET}"
    echo -e "  配置: ${C_CYAN}${conf_file}${C_RESET}"
    draw_line

    # ── 后续操作提示 ──
    if [[ "$peer_type" == "clash" ]]; then
        echo ""
        read -e -r -p "是否立即生成 Clash/Mihomo 客户端配置? [Y/n]: " _gen_clash
        _gen_clash=${_gen_clash:-Y}
        [[ "$_gen_clash" =~ ^[Yy]$ ]] && wg_generate_clash_config
    elif [[ "$peer_type" == "gateway" ]]; then
        echo -e "\n${C_YELLOW}[网关设备部署提示]${C_RESET}"
        echo "  • LAN 内设备无需安装任何 VPN 客户端，网关自动代理"
        echo "  • 确保 VPN 子网 (${server_subnet}) 与 LAN 子网 (${lan_subnets}) 不冲突"
    fi

    log_action "WireGuard(deb) peer added: ${peer_name} (${peer_ip}) type=${peer_type} gateway=${is_gateway} lan=${lan_subnets}"
    pause
}

# 内部函数: 联动更新所有 peer 的 allowed_ips (当网关 LAN 变动时)
_wg_deb_update_peer_routes() {
    local server_subnet=$(wg_deb_db_get '.server.subnet')
    local server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    local _pc=$(wg_deb_db_get '.peers | length')

    # 收集所有网关的 LAN 网段
    local _all_lans="" _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _pls=$(wg_deb_db_get ".peers[$_pi].lan_subnets // empty")
        [[ -n "$_pls" && "$_pls" != "null" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
        _pi=$((_pi + 1))
    done

    _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _cur=$(wg_deb_db_get ".peers[$_pi].client_allowed_ips")
        [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
        [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

        local _is_gw=$(wg_deb_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_deb_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_deb_db_get ".peers[$_pi].peer_type // \"standard\"")

        if [[ "$_is_gw" == "true" ]]; then
            local _other="" _IFS_BAK="$IFS"; IFS=','
            for _c in $_all_lans; do
                _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                local _skip=false _IFS2="$IFS"; IFS=','
                for _o in $_own; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                IFS="$_IFS2"
                [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
            done; IFS="$_IFS_BAK"
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_other" ]] && _new="${_new}, ${_other}"
            wg_deb_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        else
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_deb_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        fi
        _pi=$((_pi + 1))
    done
}

wg_deb_list_peers() {
    wg_deb_check_server || return 1
    print_title "WireGuard 设备列表"
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi
    local wg_dump=""
    wg_deb_is_running && wg_dump=$(wg show "$WG_DEB_INTERFACE" dump 2>/dev/null | tail -n +2)
    printf "${C_CYAN}%-4s %-14s %-14s %-8s %-8s %-10s %-10s %s${C_RESET}\n" \
        "#" "名称" "IP" "类型" "状态" "↓接收" "↑发送" "最近握手"
    draw_line
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip pubkey enabled peer_type
        name=$(wg_deb_db_get ".peers[$i].name")
        ip=$(wg_deb_db_get ".peers[$i].ip")
        pubkey=$(wg_deb_db_get ".peers[$i].public_key")
        enabled=$(wg_deb_db_get ".peers[$i].enabled")
        peer_type=$(wg_deb_db_get ".peers[$i].peer_type // \"standard\"")
        local type_str
        case "$peer_type" in
            clash)   type_str="${C_CYAN}Clash${C_RESET}" ;;
            gateway) type_str="${C_YELLOW}网关${C_RESET}" ;;
            *)       type_str="标准" ;;
        esac
        local status_str
        if [[ "$enabled" != "true" ]]; then
            status_str="${C_GRAY}禁用${C_RESET}"
        else
            status_str="${C_GREEN}启用${C_RESET}"
        fi
        local rx_bytes="0" tx_bytes="0" last_handshake="从未"
        if [[ -n "$wg_dump" ]]; then
            local peer_line
            peer_line=$(echo "$wg_dump" | grep "^${pubkey}" 2>/dev/null)
            if [[ -n "$peer_line" ]]; then
                rx_bytes=$(echo "$peer_line" | awk '{print $6}')
                tx_bytes=$(echo "$peer_line" | awk '{print $7}')
                local hs_epoch
                hs_epoch=$(echo "$peer_line" | awk '{print $5}')
                if [[ -n "$hs_epoch" && "$hs_epoch" != "0" ]]; then
                    local now_epoch diff
                    now_epoch=$(date +%s)
                    diff=$((now_epoch - hs_epoch))
                    if [[ $diff -lt 60 ]]; then
                        last_handshake="${diff}秒前"
                        status_str="${C_GREEN}在线${C_RESET}"
                    elif [[ $diff -lt 3600 ]]; then
                        last_handshake="$((diff / 60))分前"
                    elif [[ $diff -lt 86400 ]]; then
                        last_handshake="$((diff / 3600))时前"
                    else
                        last_handshake="$((diff / 86400))天前"
                    fi
                fi
            fi
        fi
        printf "%-4s %-14s %-14s %-8b %-8b %-10s %-10s %s\n" \
            "$((i + 1))" "$name" "$ip" "$type_str" "$status_str" \
            "$(wg_deb_format_bytes "$rx_bytes")" "$(wg_deb_format_bytes "$tx_bytes")" "$last_handshake"
        i=$((i + 1))
    done
    echo -e "${C_CYAN}共 ${peer_count} 个设备${C_RESET}"
    # 显示网关 LAN 信息
    local gw_found=0 gi=0
    while [[ $gi -lt $peer_count ]]; do
        local gw_check=$(wg_deb_db_get ".peers[$gi].is_gateway // false")
        if [[ "$gw_check" == "true" ]]; then
            [[ $gw_found -eq 0 ]] && { echo -e "${C_CYAN}网关设备 LAN 网段:${C_RESET}"; gw_found=1; }
            local gw_name=$(wg_deb_db_get ".peers[$gi].name")
            local gw_lans=$(wg_deb_db_get ".peers[$gi].lan_subnets // empty")
            echo -e "  ${gw_name}: ${C_GREEN}${gw_lans:-未设置}${C_RESET}"
        fi
        gi=$((gi + 1))
    done
    pause
}

wg_deb_toggle_peer() {
    wg_deb_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_deb_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name target_pubkey current_state
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_deb_db_get ".peers[$target_idx].public_key")
    current_state=$(wg_deb_db_get ".peers[$target_idx].enabled")
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'
            wg_deb_rebuild_conf
            if wg_deb_is_running; then
                systemctl restart wg-quick@wg0 >/dev/null 2>&1
            fi
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard(deb) peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            wg_deb_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'
            wg_deb_rebuild_conf
            if wg_deb_is_running; then
                systemctl restart wg-quick@wg0 >/dev/null 2>&1
            fi
            print_success "设备 '${target_name}' 已启用"
            log_action "WireGuard(deb) peer enabled: ${target_name}"
        fi
    fi
    pause
}

wg_deb_delete_peer() {
    wg_deb_check_server || return 1
    print_title "删除 WireGuard 设备"
    wg_deb_select_peer "选择要删除的设备序号" true || return
    local target_idx=$REPLY
    local target_name
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    local _del_gw=$(wg_deb_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_deb_db_get ".peers[$target_idx].lan_subnets // empty")
    wg_deb_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        _wg_deb_update_peer_routes
    fi

    rm -f "${WG_DEB_CLIENT_DIR}/${target_name}.conf"
    wg_deb_rebuild_conf
    wg_deb_regenerate_client_confs

    # 重启使配置生效
    if wg_deb_is_running; then
        systemctl restart wg-quick@wg0 >/dev/null 2>&1
    fi

    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard(deb) peer deleted: ${target_name}"
    pause
}

wg_deb_show_peer_conf() {
    wg_deb_check_server || return 1
    print_title "查看设备配置"
    wg_deb_select_peer "选择设备序号" true || return
    local target_idx=$REPLY
    local target_name peer_type
    target_name=$(wg_deb_db_get ".peers[$target_idx].name")
    peer_type=$(wg_deb_db_get ".peers[$target_idx].peer_type // \"standard\"")
    local conf_file="${WG_DEB_CLIENT_DIR}/${target_name}.conf"

    # 确保配置文件存在
    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."
        wg_deb_regenerate_client_confs
        [[ ! -f "$conf_file" ]] && { print_error "配置文件生成失败"; pause; return; }
        print_success "配置文件已重新生成"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        echo -e "  设备类型: ${C_CYAN}Clash 客户端${C_RESET}"
        echo -e "  (Clash 客户端不使用 .conf 文件，请生成 Clash YAML 配置)"
        echo ""
        if confirm "是否生成 Clash/Mihomo 配置?"; then
            wg_generate_clash_config
        fi
    else
        draw_line
        echo -e "${C_CYAN}=== ${target_name} 客户端配置 ===${C_RESET}"
        draw_line
        cat "$conf_file"
        draw_line
        if command_exists qrencode; then
            if confirm "显示二维码 (手机扫码导入)?"; then
                echo -e "${C_CYAN}=== ${target_name} 二维码 ===${C_RESET}"
                qrencode -t ansiutf8 < "$conf_file"
                echo ""
            fi
        fi
    fi

    echo -e "配置文件路径: ${C_CYAN}${conf_file}${C_RESET}"
    echo -e "下载命令: ${C_GRAY}scp root@服务器IP:${conf_file} ./${C_RESET}"
    pause
}
