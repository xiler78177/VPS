# modules/11d-wireguard-peers.sh - WireGuard peer management (OpenWrt)
wg_add_peer() {
    wg_check_server || return 1
    print_title "添加 WireGuard 设备 (Peer)"
    local peer_name
    while true; do
        read -e -r -p "设备名称 (如 phone, laptop): " peer_name
        [[ -z "$peer_name" ]] && { print_warn "名称不能为空"; continue; }
        local exists
        exists=$(wg_db_get --arg n "$peer_name" '.peers[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "设备名 '$peer_name' 已存在"; continue; }
        [[ ! "$peer_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母、数字、下划线、连字符"; continue; }
        break
    done
    local peer_ip
    peer_ip=$(wg_next_ip) || { pause; return 1; }
    echo -e "  分配 IP: ${C_GREEN}${peer_ip}${C_RESET}"
    local peer_privkey peer_pubkey psk
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)

    # ── 设备类型选择 (三种) ──
    local peer_type="standard"
    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:"
    echo -e "  1. ${C_CYAN}Clash 客户端${C_RESET} (手机/电脑，通过 FlClash/FClash 规则接入)"
    echo -e "  2. ${C_YELLOW}网关设备${C_RESET} (OpenWrt 路由器，暴露自身 LAN 子网)"
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
    server_subnet=$(wg_db_get '.server.subnet')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')

    # 收集所有网关 LAN 网段 (含当前新设备)
    local all_lan_subnets=""
    local pc=$(wg_db_get '.peers | length') pi=0
    while [[ $pi -lt $pc ]]; do
        local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
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
        # Clash 客户端: 路由 VPN 子网 + 服务端 LAN + 所有网关 LAN
        client_allowed_ips="$server_subnet"
        [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
        [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
        echo -e "  Clash 路由模式: ${C_CYAN}VPN 子网 + 所有 LAN 子网${C_RESET}"
        echo -e "  AllowedIPs: ${client_allowed_ips}"
    elif [[ "$peer_type" == "gateway" ]]; then
        # 网关设备: VPN 子网 + 服务端 LAN + 其他网关 LAN (排除自己的 LAN)
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
        # 标准客户端: 交互选择
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
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')
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
    mkdir -p /etc/wireguard/clients
    local conf_file="/etc/wireguard/clients/${peer_name}.conf"
    write_file_atomic "$conf_file" "$client_conf"
    chmod 600 "$conf_file"

    # ── 写入数据库 ──
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    wg_db_set --arg name "$peer_name" \
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
        _wg_update_peer_routes
    fi

    # ── 重建配置并应用 ──
    wg_rebuild_uci_conf
    wg_rebuild_conf
    wg_regenerate_client_confs

    # 网关 peer 添加/删除会改变 LAN 子网列表，需重建 Mihomo bypass
    if [[ "$is_gateway" == "true" ]]; then
        wg_mihomo_bypass_rebuild 2>/dev/null
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
        echo ""
        read -e -r -p "是否立即显示 OpenWrt 部署命令? [Y/n]: " _show_cmd
        _show_cmd=${_show_cmd:-Y}
        [[ "$_show_cmd" =~ ^[Yy]$ ]] && _wg_show_openwrt_deploy "$target_idx"
    fi

    log_action "WireGuard peer added: ${peer_name} (${peer_ip}) type=${peer_type} gateway=${is_gateway} lan=${lan_subnets}"
    pause
}

# 内部函数: 联动更新所有 peer 的 allowed_ips (当网关 LAN 变动时)
_wg_update_peer_routes() {
    local server_subnet=$(wg_db_get '.server.subnet')
    local server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    local _pc=$(wg_db_get '.peers | length')

    # 收集所有网关的 LAN 网段
    local _all_lans="" _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
        [[ -n "$_pls" && "$_pls" != "null" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
        _pi=$((_pi + 1))
    done

    _pi=0
    while [[ $_pi -lt $_pc ]]; do
        local _cur=$(wg_db_get ".peers[$_pi].client_allowed_ips")
        # 跳过全局代理和仅 VPN 内网的
        [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
        [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

        local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_db_get ".peers[$_pi].peer_type // \"standard\"")

        if [[ "$_is_gw" == "true" ]]; then
            # 网关: VPN 子网 + 服务端 LAN + 其他网关 LAN (排除自己)
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
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        elif [[ "$_ptype" == "clash" ]]; then
            # Clash: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        else
            # 标准: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
        fi
        _pi=$((_pi + 1))
    done
}

wg_list_peers() {
    wg_check_server || return 1
    print_title "WireGuard 设备列表"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"
        pause; return
    fi
    local wg_dump=""
    wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)
    printf "${C_CYAN}%-4s %-14s %-14s %-8s %-8s %-10s %-10s %s${C_RESET}\n" \
        "#" "名称" "IP" "类型" "状态" "↓接收" "↑发送" "最近握手"
    draw_line
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
            "$(wg_format_bytes "$rx_bytes")" "$(wg_format_bytes "$tx_bytes")" "$last_handshake"
        i=$((i + 1))
    done
    echo -e "${C_CYAN}共 ${peer_count} 个设备${C_RESET}"
    # 显示网关 LAN 信息
    local gw_found=0 gi=0
    while [[ $gi -lt $peer_count ]]; do
        local gw_check=$(wg_db_get ".peers[$gi].is_gateway // false")
        if [[ "$gw_check" == "true" ]]; then
            [[ $gw_found -eq 0 ]] && { echo -e "${C_CYAN}网关设备 LAN 网段:${C_RESET}"; gw_found=1; }
            local gw_name=$(wg_db_get ".peers[$gi].name")
            local gw_lans=$(wg_db_get ".peers[$gi].lan_subnets // empty")
            echo -e "  ${gw_name}: ${C_GREEN}${gw_lans:-未设置}${C_RESET}"
        fi
        gi=$((gi + 1))
    done
    pause
}

wg_toggle_peer() {
    wg_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name target_pubkey current_state
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")
    current_state=$(wg_db_get ".peers[$target_idx].enabled")
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'
            if wg_is_running; then
                wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
            fi
            wg_rebuild_uci_conf
            wg_rebuild_conf
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'
            wg_rebuild_uci_conf
            wg_rebuild_conf
            print_success "设备 '${target_name}' 已启用"
            log_action "WireGuard peer enabled: ${target_name}"
        fi
    fi
    pause
}

wg_delete_peer() {
    wg_check_server || return 1
    print_title "删除 WireGuard 设备"
    wg_select_peer "选择要删除的设备序号" true || return
    local target_idx=$REPLY
    local target_name target_pubkey
    target_name=$(wg_db_get ".peers[$target_idx].name")
    target_pubkey=$(wg_db_get ".peers[$target_idx].public_key")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    if wg_is_running; then
        wg set "$WG_INTERFACE" peer "$target_pubkey" remove 2>/dev/null || true
    fi
    local _del_gw=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_db_get ".peers[$target_idx].lan_subnets // empty")
    wg_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        _wg_update_peer_routes
    fi

    rm -f "/etc/wireguard/clients/${target_name}.conf"
    wg_rebuild_uci_conf
    wg_rebuild_conf
    wg_regenerate_client_confs

    # 网关 peer 删除后 LAN 子网列表变化，需重建 Mihomo bypass
    if [[ "$_del_gw" == "true" ]]; then
        wg_mihomo_bypass_rebuild 2>/dev/null
    fi

    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard peer deleted: ${target_name}"
    pause
}

wg_show_peer_conf() {
    wg_check_server || return 1
    print_title "查看设备配置"
    wg_select_peer "选择设备序号" true || return
    local target_idx=$REPLY
    local target_name peer_type
    target_name=$(wg_db_get ".peers[$target_idx].name")
    peer_type=$(wg_db_get ".peers[$target_idx].peer_type // \"standard\"")
    local conf_file="/etc/wireguard/clients/${target_name}.conf"

    # 确保配置文件存在
    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."
        wg_regenerate_client_confs
        [[ ! -f "$conf_file" ]] && { print_error "配置文件生成失败"; pause; return; }
        print_success "配置文件已重新生成"
    fi

    if [[ "$peer_type" == "clash" ]]; then
        # ── Clash 客户端: 只显示生成 Clash 配置的选项 ──
        echo -e "  设备类型: ${C_CYAN}Clash 客户端${C_RESET}"
        echo -e "  (Clash 客户端不使用 .conf 文件，请生成 Clash YAML 配置)"
        echo ""
        if confirm "是否生成 Clash/Mihomo 配置?"; then
            wg_generate_clash_config
        fi
    elif [[ "$peer_type" == "gateway" ]]; then
        # ── 网关设备: 显示 .conf + OpenWrt 部署命令 ──
        draw_line
        echo -e "${C_CYAN}=== ${target_name} 客户端配置 (网关) ===${C_RESET}"
        draw_line
        cat "$conf_file"
        draw_line
        echo ""
        if confirm "显示 OpenWrt uci 部署命令?"; then
            _wg_show_openwrt_deploy "$target_idx"
        fi
    else
        # ── 标准客户端: 显示 .conf + 二维码 ──
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

# 生成网关 peer 的 OpenWrt uci 一键部署命令
_wg_show_openwrt_deploy() {
    local target_idx="$1"
    [[ -z "$target_idx" ]] && { target_idx=$REPLY; }

    local peer_privkey peer_ip psk client_allowed_ips
    peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
    peer_ip=$(wg_db_get ".peers[$target_idx].ip")
    psk=$(wg_db_get ".peers[$target_idx].preshared_key")
    client_allowed_ips=$(wg_db_get ".peers[$target_idx].client_allowed_ips")

    local spub sep sport ssub mask
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    ssub=$(wg_db_get '.server.subnet')
    mask=$(echo "$ssub" | cut -d'/' -f2)
    local ep_host="$sep"

    local uci_allowed_lines=""
    local IFS_BAK="$IFS"; IFS=','
    for cidr in $client_allowed_ips; do
        cidr=$(echo "$cidr" | xargs)
        [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}'
"
    done
    IFS="$IFS_BAK"

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
    draw_line
    cat << OPENWRT_EOF

# === 清理旧配置 ===
ifdown wg0 2>/dev/null; true
for iface in \$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print \$2}'); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
done
for iface in wg0 wg_mesh wg-mesh; do
    ip link show "\$iface" >/dev/null 2>&1 && { ip link set "\$iface" down; ip link delete "\$iface"; } 2>/dev/null; true
done
rm -f /usr/bin/wg-watchdog.sh 2>/dev/null; true
(crontab -l 2>/dev/null | grep -v wg-watchdog) | crontab - 2>/dev/null; true
/etc/init.d/wg-client disable 2>/dev/null; true
rm -f /etc/init.d/wg-client 2>/dev/null; true
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do uci delete network.@wireguard_wg0[0]; done
uci delete network.wg_server 2>/dev/null; true
uci delete network.wg0 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
i=0; while uci get firewall.@zone[\$i] >/dev/null 2>&1; do
    zname=\$(uci get firewall.@zone[\$i].name 2>/dev/null)
    case "\$zname" in wg|wireguard) uci delete "firewall.@zone[\$i]" 2>/dev/null; true; continue ;; esac
    i=\$((i + 1))
done
# clean ALL ip rules with prio 100 (old fake-ip bypass rules)
while ip rule del prio 100 2>/dev/null; do true; done
for h in \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "\$h" 2>/dev/null; true
done
sed -i '/wg_bypass/d; /WireGuard bypass/d; /ip rule.*prio 100/d' /etc/rc.local 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true

# === 安装 WireGuard 组件 ===
WG_KERNEL=0
[ -d /sys/module/wireguard ] || lsmod 2>/dev/null | grep -q wireguard && WG_KERNEL=1
for _retry in 1 2 3; do
    opkg update && break
    echo "[!] opkg update 失败 (第\${_retry}次), 3秒后重试..."
    sleep 3
done
[ "\$WG_KERNEL" = "0" ] && { opkg install kmod-wireguard 2>/dev/null || echo '[!] kmod-wireguard 安装失败'; }
opkg install wireguard-tools 2>/dev/null || echo '[!] wireguard-tools 安装失败'
opkg install luci-proto-wireguard 2>/dev/null || echo '[!] luci-proto-wireguard 安装失败'
/etc/init.d/rpcd restart 2>/dev/null; true
sleep 1

# === 配置 WireGuard 接口 ===
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg0.mtu='1420'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
# === 配置防火墙 ===
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall

# === Mihomo/OpenClash bypass: WG endpoint 流量直连 ===
# 关键: 使用外部 DNS 直连解析, 绕过 OpenClash fake-ip 劫持
EP_IP='${ep_host}'
if ! echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$'; then
    # 依次尝试多个外部 DNS 直连解析 (绕过本地 Clash/Mihomo fake-ip)
    for DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
        EP_IP=\$(nslookup '${ep_host}' \$DNS_SRV 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}')
        # 验证不是 fake-ip (198.18.0.0/15)
        if [ -n "\$EP_IP" ]; then
            case "\$EP_IP" in 198.18.*|198.19.*) EP_IP=""; continue ;; esac
            echo "[+] endpoint 解析: ${ep_host} -> \$EP_IP (via \$DNS_SRV)"
            break
        fi
    done
fi
if [ -z "\${EP_IP}" ]; then
    echo '[!] 警告: 无法解析 endpoint 真实 IP, bypass 规则可能无效!'
fi
if [ -n "\${EP_IP}" ]; then
    ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
    ip rule add to "\${EP_IP}" lookup main prio 100
    nft list chain inet fw4 mangle_prerouting &>/dev/null && {
        nft insert rule inet fw4 mangle_prerouting ip daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting iifname \"wg0\" counter return comment \"wg_bypass_iface\" 2>/dev/null; true
    }
    echo "[+] Mihomo bypass 规则已添加: \${EP_IP}"
fi

# 持久化: rc.local 中使用外部 DNS 动态解析 (每次开机重新解析)
sed -i '/wg_bypass/d; /WireGuard bypass/d; /wg_ep_resolve/d; /ip rule.*prio 100/d' /etc/rc.local 2>/dev/null; true
if grep -q "^exit 0" /etc/rc.local 2>/dev/null; then
    sed -i "/^exit 0/i # WireGuard bypass Mihomo (dynamic resolve, bypass fake-ip) # wg_bypass\\
WG_EP=\\\$(nslookup '${ep_host}' 223.5.5.5 2>/dev/null | awk '/^Address:/{a=\\\$2} END{if(a) print a}') # wg_ep_resolve\\
[ -n \\\"\\\$WG_EP\\\" ] \&\& { ip rule add to \\\"\\\$WG_EP\\\" lookup main prio 100 2>/dev/null; true; } # wg_bypass\\
[ -n \\\"\\\$WG_EP\\\" ] \&\& nft insert rule inet fw4 mangle_prerouting ip daddr \\\"\\\$WG_EP\\\" udp dport ${sport} counter return comment \\\"wg_bypass\\\" 2>/dev/null; true # wg_bypass\\
nft insert rule inet fw4 mangle_prerouting iifname \\\"wg0\\\" counter return comment \\\"wg_bypass_iface\\\" 2>/dev/null; true # wg_bypass" \\
        /etc/rc.local 2>/dev/null; true
else
    cat >> /etc/rc.local << 'RCEOF'
# WireGuard bypass Mihomo (dynamic resolve) # wg_bypass
WG_EP=\$(nslookup '${ep_host}' 223.5.5.5 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}') # wg_ep_resolve
[ -n "\$WG_EP" ] && { ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true; } # wg_bypass
[ -n "\$WG_EP" ] && nft insert rule inet fw4 mangle_prerouting ip daddr "\$WG_EP" udp dport ${sport} counter return comment "wg_bypass" 2>/dev/null; true # wg_bypass
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true # wg_bypass
RCEOF
fi

# === 开机自恢复服务 ===
cat > /etc/init.d/wg-client << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=0
boot() { start; }
start() {
    if command -v wg >/dev/null 2>&1 && uci -q get network.wg0.proto >/dev/null 2>&1; then
        ifup wg0 2>/dev/null; return 0
    fi
    logger -t wg-client "WireGuard missing, restoring..."
    for _r in 1 2 3; do opkg update && break; sleep 3; done
    opkg install kmod-wireguard wireguard-tools luci-proto-wireguard 2>/dev/null
    /etc/init.d/rpcd restart 2>/dev/null; sleep 1
    uci set network.wg0=interface
    uci set network.wg0.proto='wireguard'
    uci set network.wg0.private_key='${peer_privkey}'
    uci set network.wg0.mtu='1420'
    uci delete network.wg0.addresses 2>/dev/null; true
    uci add_list network.wg0.addresses='${peer_ip}/${mask}'
    uci set network.wg_server=wireguard_wg0
    uci set network.wg_server.public_key='${spub}'
    uci set network.wg_server.preshared_key='${psk}'
    uci set network.wg_server.endpoint_host='${ep_host}'
    uci set network.wg_server.endpoint_port='${sport}'
    uci set network.wg_server.persistent_keepalive='25'
    uci set network.wg_server.route_allowed_ips='1'
    ${uci_allowed_lines}uci set firewall.wg_zone=zone
    uci set firewall.wg_zone.name='wg'
    uci set firewall.wg_zone.input='ACCEPT'
    uci set firewall.wg_zone.output='ACCEPT'
    uci set firewall.wg_zone.forward='ACCEPT'
    uci set firewall.wg_zone.masq='1'
    uci add_list firewall.wg_zone.network='wg0'
    uci set firewall.wg_fwd_lan=forwarding
    uci set firewall.wg_fwd_lan.src='lan'
    uci set firewall.wg_fwd_lan.dest='wg'
    uci set firewall.wg_fwd_wg=forwarding
    uci set firewall.wg_fwd_wg.src='wg'
    uci set firewall.wg_fwd_wg.dest='lan'
    uci commit network
    uci commit firewall
    ifup wg0
    logger -t wg-client "WireGuard restored"
}
INITEOF
chmod 0700 /etc/init.d/wg-client
/etc/init.d/wg-client enable
echo '[+] 开机自恢复服务已安装'

# === 启动接口 ===
ifup wg0

# === 验证 ===
sleep 3
if ifstatus wg0 2>/dev/null | grep -q '"up": true'; then
    echo '[+] wg0 接口启动成功!'
else
    echo '[!] wg0 接口未启动，请检查: logread | grep -i wireguard'
fi
if [ -n "\${EP_IP}" ]; then
    echo "[*] 验证 endpoint: wg show wg0 endpoints"
    wg show wg0 endpoints 2>/dev/null
fi

OPENWRT_EOF

    # 如果 endpoint 是域名，追加看门狗
    if [[ ! "$ep_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        cat << 'WDEOF'

# === WireGuard 看门狗 (fake-ip检测 + DNS直连解析 + 完整bypass自恢复 + 握手保活 + 日志持久化) ===
cat > /usr/bin/wg-watchdog.sh << 'WDSCRIPT'
#!/bin/sh
LOG_FILE="/tmp/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    logger -t wg-watchdog "$1"
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
    if [ -f "$LOG_FILE" ] && [ $(wc -c < "$LOG_FILE" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]; then
        tail -n 50 "$LOG_FILE" > "${LOG_FILE}.tmp" && mv "${LOG_FILE}.tmp" "$LOG_FILE"
    fi
}

resolve_real() {
    local host="$1" ip=""
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" $dns 2>/dev/null | awk '/^Address:/{a=$2} END{if(a) print a}')
        [ -n "$ip" ] || continue
        case "$ip" in 198.18.*|198.19.*) ip=""; continue ;; esac
        echo "$ip"; return 0
    done
    return 1
}

if ! ifstatus wg0 &>/dev/null; then
    wdlog "wg0 down, restarting"; ifup wg0; exit 0
fi

# resolve endpoint (always set RESOLVED for bypass self-heal)
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

# DNS re-resolve + endpoint update (only for domain endpoints)
if [ -n "$EP_HOST" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    CURRENT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*) FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        wg set wg0 peer "$PUB" endpoint "${RESOLVED}:${PORT}"
        for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
            nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
        done
        nft insert rule inet fw4 mangle_prerouting ip daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        while ip rule del prio 100 2>/dev/null; do true; done
        ip rule add to "$RESOLVED" lookup main prio 100 2>/dev/null; true
        wdlog "bypass updated -> $RESOLVED"
    fi
fi

# bypass rule self-heal (complete: iface + IP + ip rule)
if nft list chain inet fw4 mangle_prerouting &>/dev/null; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ]; then
        if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
            PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
            nft insert rule inet fw4 mangle_prerouting ip daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wdlog "restored IP bypass -> $RESOLVED"
        fi
    fi
fi
if [ -n "$RESOLVED" ] && ! ip rule show 2>/dev/null | grep -q "$RESOLVED"; then
    ip rule add to "$RESOLVED" lookup main prio 100 2>/dev/null; true
    wdlog "restored ip rule -> $RESOLVED"
fi

# connectivity check (handshake timeout + ping fallback)
LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" &>/dev/null; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
chmod +x /usr/bin/wg-watchdog.sh
(crontab -l 2>/dev/null | grep -v wg-watchdog; echo '* * * * * /usr/bin/wg-watchdog.sh') | crontab -
/etc/init.d/cron restart
echo '[+] 看门狗已安装 (DNS直连 + fake-ip检测 + 完整bypass自恢复 + 握手保活 + 日志持久化)'
WDEOF
    fi

    draw_line
    echo -e "${C_GREEN}复制以上全部命令到目标 OpenWrt SSH 终端执行即可。${C_RESET}"
    echo -e "${C_CYAN}验证方法:${C_RESET}"
    echo "  1. wg show (确认 endpoint 不是 198.19.x.x)"
    echo "  2. ping $(wg_db_get '.server.ip') (从 LAN 设备 ping VPN 服务端)"
    echo -e "${C_YELLOW}重启保护:${C_RESET}"
    echo "  • rc.local: 开机动态解析 endpoint (绕过 fake-ip)"
    echo "  • 看门狗: 每分钟检测 fake-ip 并自动修正"
    draw_line
}
