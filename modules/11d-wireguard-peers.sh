# modules/11d-wireguard-peers.sh - WireGuard peer management (OpenWrt)
_wg_openwrt_snapshot_db() {
    [[ -f "$WG_DB_FILE" ]] || return 1
    cat "$WG_DB_FILE"
}

_wg_openwrt_restore_peer_snapshot() {
    local snapshot="${1:-}" cleanup_file="${2:-}" rebuild_bypass="${3:-false}"
    [[ -n "$snapshot" ]] || return 1
    wg_write_private_file "$WG_DB_FILE" "$snapshot" || return 1
    wg_rebuild_uci_conf "no_reload" >/dev/null 2>&1 || true
    wg_apply_runtime_conf >/dev/null 2>&1 || true
    wg_regenerate_client_confs >/dev/null 2>&1 || true
    if [[ -n "$cleanup_file" ]]; then
        rm -f -- "$cleanup_file" 2>/dev/null || true
    fi
    if [[ "$rebuild_bypass" == "true" ]]; then
        wg_mihomo_bypass_rebuild >/dev/null 2>&1 || true
    fi
}

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
    peer_privkey=$(wg genkey) || { print_error "生成 peer 私钥失败"; pause; return 1; }
    peer_pubkey=$(printf '%s\n' "$peer_privkey" | wg pubkey) || { print_error "生成 peer 公钥失败"; pause; return 1; }
    psk=$(wg genpsk) || { print_error "生成预共享密钥失败"; pause; return 1; }

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
                elif ! validate_cidr_list "$lan_subnets"; then
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
    local client_allowed_ips server_subnet server_lan route_mode="managed"
    server_subnet=$(wg_db_get '.server.subnet')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')

    # 收集所有网关 LAN 网段 (含当前新设备)
    local all_lan_subnets=""
    local pc=$(wg_db_get '.peers | length') pi=0
    local target_idx="$pc"
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
            1) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
            2) client_allowed_ips="$server_subnet"; route_mode="vpn" ;;
            3)
                route_mode="managed"
                client_allowed_ips="$server_subnet"
                [[ -n "$server_lan" && "$server_lan" != "null" ]] && client_allowed_ips="${client_allowed_ips}, ${server_lan}"
                [[ -n "$all_lan_subnets" ]] && client_allowed_ips="${client_allowed_ips}, ${all_lan_subnets}"
                ;;
            4)
                read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
                [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
                if validate_wg_allowed_ips "$client_allowed_ips"; then
                    route_mode="custom"
                else
                    print_warn "自定义路由格式无效，回退为仅 VPN 内网"
                    client_allowed_ips="$server_subnet"
                    route_mode="vpn"
                fi
                ;;
            *) client_allowed_ips="0.0.0.0/0, ::/0"; route_mode="full" ;;
        esac
    fi

    local conf_file="/etc/wireguard/clients/${peer_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }

    # ── 写入数据库 ──
    local now; now=$(date '+%Y-%m-%d %H:%M:%S')
    if ! wg_db_set --arg name "$peer_name" \
                   --arg ip "$peer_ip" \
                   --arg privkey "$peer_privkey" \
                   --arg pubkey "$peer_pubkey" \
                   --arg psk "$psk" \
                   --arg allowed "$client_allowed_ips" \
                   --arg created "$now" \
                   --arg gw "$is_gateway" \
                   --arg lans "$lan_subnets" \
                   --arg ptype "$peer_type" \
                   --arg route_mode "$route_mode" \
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
        peer_type: $ptype,
        route_mode: $route_mode
    }]'; then
        print_error "数据库写入失败，设备未添加"
        pause; return 1
    fi

    # ── 网关设备: 联动更新其他 peer 的 allowed_ips ──
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" true
            pause; return 1
        fi
    fi

    # ── 重建配置并应用 ──
    if ! wg_rebuild_uci_conf "no_reload"; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi
    if ! wg_apply_runtime_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" "$is_gateway"
        pause; return 1
    fi

    # 网关 peer 添加/删除会改变 LAN 子网列表，需重建 Mihomo bypass
    if [[ "$is_gateway" == "true" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "$conf_file" true
            pause; return 1
        fi
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
        local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
        local _own=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
        local _ptype=$(wg_db_get ".peers[$_pi].peer_type // \"standard\"")
        local _route_mode=$(wg_db_get ".peers[$_pi].route_mode // empty")
        # 跳过用户显式选择的路由模式：custom(自定义)/full(全局)/vpn(仅内网)——这些不应被联动改写
        case "$_route_mode" in
            custom|full|vpn) _pi=$((_pi + 1)); continue ;;
        esac
        # 跳过全局代理
        [[ "$_cur" == *"0.0.0.0/0"* || "$_cur" == *"::/0"* ]] && { _pi=$((_pi + 1)); continue; }
        # 旧数据兼容：无 route_mode 且当前恰为 VPN 子网时视为仅内网，跳过（managed 类不受影响）
        [[ -z "$_route_mode" && "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }

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
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        elif [[ "$_ptype" == "clash" ]]; then
            # Clash: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        else
            # 标准: VPN 子网 + 服务端 LAN + 所有网关 LAN
            local _new="$server_subnet"
            [[ -n "$server_lan" && "$server_lan" != "null" ]] && _new="${_new}, ${server_lan}"
            [[ -n "$_all_lans" ]] && _new="${_new}, ${_all_lans}"
            wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a' || return 1
        fi
        _pi=$((_pi + 1))
    done
    return 0
}

wg_toggle_peer() {
    wg_check_server || return 1
    print_title "启用/禁用 WireGuard 设备"
    wg_select_peer "选择要切换状态的设备序号" true || return
    local target_idx=$REPLY
    local target_name current_state
    target_name=$(wg_db_get ".peers[$target_idx].name")
    current_state=$(wg_db_get ".peers[$target_idx].enabled")
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if [[ "$current_state" == "true" ]]; then
        if confirm "确认禁用设备 '${target_name}'？"; then
            if ! wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = false'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_rebuild_uci_conf "no_reload"; then
                print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            if ! wg_apply_runtime_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            if ! wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'; then
                print_error "数据库写入失败，设备状态未修改"
                pause; return 1
            fi
            if ! wg_rebuild_uci_conf "no_reload"; then
                print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
            if ! wg_apply_runtime_conf; then
                print_error "WireGuard 运行配置热应用失败，正在回滚"
                _wg_openwrt_restore_peer_snapshot "$db_snapshot"
                pause; return 1
            fi
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
    local target_name
    target_name=$(wg_db_get ".peers[$target_idx].name")
    if ! confirm "确认删除设备 '${target_name}'？"; then
        return
    fi
    local _del_gw=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    local _del_lans=$(wg_db_get ".peers[$target_idx].lan_subnets // empty")
    local conf_file="/etc/wireguard/clients/${target_name}.conf"
    local db_snapshot
    db_snapshot=$(_wg_openwrt_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    if ! wg_db_set --argjson idx "$target_idx" 'del(.peers[$idx])'; then
        print_error "数据库写入失败，设备未删除"
        pause; return 1
    fi

    # 网关删除后联动更新其他 peer
    if [[ "$_del_gw" == "true" && -n "$_del_lans" && "$_del_lans" != "null" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "联动更新客户端路由失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" true
            pause; return 1
        fi
    fi

    if ! wg_rebuild_uci_conf "no_reload"; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi
    if ! wg_apply_runtime_conf; then
        print_error "WireGuard 运行配置热应用失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi
    rm -f -- "$conf_file" 2>/dev/null || print_warn "删除客户端配置文件失败: $conf_file"
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" "$_del_gw"
        pause; return 1
    fi

    # 网关 peer 删除后 LAN 子网列表变化，需重建 Mihomo bypass
    if [[ "$_del_gw" == "true" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_restore_peer_snapshot "$db_snapshot" "" true
            pause; return 1
        fi
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
    local ep_host
    ep_host=$(wg_shared_endpoint_host "$sep")

    local uci_allowed_lines=""
    local IFS_BAK="$IFS"; IFS=','
    for cidr in $client_allowed_ips; do
        cidr=$(echo "$cidr" | xargs)
        [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}' || return 1
"
    done
    IFS="$IFS_BAK"

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
    draw_line
    cat << OPENWRT_EOF

# === 清理旧配置 ===
die() { echo "[!] \$*" >&2; exit 1; }
WG_UCI_SNAPSHOT_DIR=""
restore_uci_snapshots() {
    [ -n "\$WG_UCI_SNAPSHOT_DIR" ] || return 0
    if [ -s "\$WG_UCI_SNAPSHOT_DIR/network.uci" ]; then
        uci revert network >/dev/null 2>&1 || true
        uci import network < "\$WG_UCI_SNAPSHOT_DIR/network.uci" >/dev/null 2>&1 || true
        uci commit network >/dev/null 2>&1 || true
    fi
    if [ -s "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" ]; then
        uci revert firewall >/dev/null 2>&1 || true
        uci import firewall < "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" >/dev/null 2>&1 || true
        uci commit firewall >/dev/null 2>&1 || true
    fi
}
cleanup_uci_snapshots() {
    [ -n "\$WG_UCI_SNAPSHOT_DIR" ] && rm -rf "\$WG_UCI_SNAPSHOT_DIR" 2>/dev/null; true
}
die_restore() {
    msg="\$1"
    restore_uci_snapshots
    cleanup_uci_snapshots
    die "\$msg"
}
WG_UCI_SNAPSHOT_DIR="\$(mktemp -d /tmp/server-manage-wg-deploy-uci.XXXXXX 2>/dev/null)" || die "创建 UCI 回滚快照目录失败"
chmod 700 "\$WG_UCI_SNAPSHOT_DIR" 2>/dev/null || true
uci export network > "\$WG_UCI_SNAPSHOT_DIR/network.uci" 2>/dev/null || die_restore "备份 network UCI 失败"
uci export firewall > "\$WG_UCI_SNAPSHOT_DIR/firewall.uci" 2>/dev/null || die_restore "备份 firewall UCI 失败"
list_wg_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=\$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\\/none/ && current != "" {
            print current
            current=""
        }
    '
}
wg_resolve_real() {
    WG_RESOLVE_HOST="\$1"
    WG_RESOLVE_DNS="\$2"
    nslookup "\$WG_RESOLVE_HOST" "\$WG_RESOLVE_DNS" 2>/dev/null | awk '
        /^Name:/ { seen_name=1; next }
        seen_name && /^Address[[:space:]][0-9]+:/ {
            ip=\$3
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
        seen_name && /^Address:/ {
            ip=\$2
            sub(/#.*/, "", ip)
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
    '
}
ifdown wg0 2>/dev/null; true
for iface in \$(list_wg_ifaces); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
done
for iface in wg0 wg_mesh wg-mesh; do
    ip link show "\$iface" >/dev/null 2>&1 && { ip link set "\$iface" down; ip link delete "\$iface"; } 2>/dev/null; true
done
rm -f /usr/bin/wg-watchdog.sh /var/run/server-manage/wg-watchdog.log /var/run/server-manage/.wg-watchdog-log.* /tmp/wg-watchdog.log /tmp/wg-watchdog.log.tmp 2>/dev/null; true
WG_CRON_TMP="\$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null)" && {
    crontab -l 2>/dev/null | awk '\$6 != "/usr/bin/wg-watchdog.sh"' > "\$WG_CRON_TMP"
    mkdir -p /etc/crontabs 2>/dev/null
    cp "\$WG_CRON_TMP" /etc/crontabs/root 2>/dev/null
    chmod 600 /etc/crontabs/root 2>/dev/null
    rm -f "\$WG_CRON_TMP"
}; true
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
# 旧版 prio 100 规则没有可验证标记，不能粗暴删除全部 prio 100（可能属于第三方）。
for h in \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "\$h" 2>/dev/null; true
done
wg_rc_local_cleanup_managed() {
    WG_RC_KIND="\${1:-all}"
    [ -f /etc/rc.local ] || return 0
    WG_RC_CLEAN_TMP="\$(mktemp /etc/.rc.local.clean.XXXXXX 2>/dev/null)" || { echo '[!] 创建 rc.local 清理临时文件失败' >&2; return 1; }
    if awk -v kind="\$WG_RC_KIND" '
        function marker_matches(line) {
            if (kind == "all") return 1
            return index(line, " " kind) > 0
        }
        /^# BEGIN server-manage wireguard / {
            if (marker_matches(\$0)) { skip=1; next }
        }
        /^# END server-manage wireguard / {
            if (skip) { skip=0; next }
        }
        skip { next }
        kind != "allow-port" && /^# WireGuard bypass Mihomo/ { next }
        kind != "allow-port" && /# wg_bypass[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_peer_route[[:space:]]*$/ { next }
        kind != "allow-port" && /# wg_ep_resolve[[:space:]]*$/ { next }
        kind != "bypass" && /# wg_allow_port[[:space:]]*$/ { next }
        kind != "bypass" && /nft insert rule inet fw4 input_wan udp dport .*comment .*wg_allow_port/ { next }
        { print }
    ' /etc/rc.local > "\$WG_RC_CLEAN_TMP"; then
        chmod +x "\$WG_RC_CLEAN_TMP" 2>/dev/null && mv "\$WG_RC_CLEAN_TMP" /etc/rc.local || { rm -f "\$WG_RC_CLEAN_TMP"; return 1; }
        rm -f "\$WG_RC_CLEAN_TMP"
        return 0
    fi
    rm -f "\$WG_RC_CLEAN_TMP"
    return 1
}
wg_rc_local_cleanup_managed all || die_restore "清理 /etc/rc.local 旧 WireGuard 片段失败"
uci commit network >/dev/null 2>&1 || die_restore "提交清理后的 network 配置失败"
uci commit firewall >/dev/null 2>&1 || die_restore "提交清理后的 firewall 配置失败"

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
wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}
wg_ensure_wireguard_proto() {
    wg_proto_registered && return 0
    echo '[*] 重启 network/netifd 以加载 WireGuard 协议处理器...'
    /etc/init.d/network restart >/dev/null 2>&1 || return 1
    sleep 5
    wg_proto_registered
}
wg_ensure_wireguard_proto || die_restore "netifd 未注册 wireguard 协议"

# === 配置 WireGuard 接口 ===
write_wg_uci() {
    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key='${peer_privkey}' || return 1
    uci delete network.wg0.addresses 2>/dev/null; true
    uci add_list network.wg0.addresses='${peer_ip}/${mask}' || return 1
    uci set network.wg0.mtu='1420' || return 1
    uci set network.wg_server=wireguard_wg0 || return 1
    uci set network.wg_server.public_key='${spub}' || return 1
    uci set network.wg_server.preshared_key='${psk}' || return 1
    uci set network.wg_server.endpoint_host='${ep_host}' || return 1
    uci set network.wg_server.endpoint_port='${sport}' || return 1
    uci set network.wg_server.persistent_keepalive='25' || return 1
    uci set network.wg_server.route_allowed_ips='1' || return 1
${uci_allowed_lines}
    # === 配置防火墙 ===
    uci set firewall.wg_zone=zone || return 1
    uci set firewall.wg_zone.name='wg' || return 1
    uci set firewall.wg_zone.input='ACCEPT' || return 1
    uci set firewall.wg_zone.output='ACCEPT' || return 1
    uci set firewall.wg_zone.forward='ACCEPT' || return 1
    uci set firewall.wg_zone.masq='1' || return 1
    uci add_list firewall.wg_zone.network='wg0' || return 1
    uci set firewall.wg_fwd_lan=forwarding || return 1
    uci set firewall.wg_fwd_lan.src='lan' || return 1
    uci set firewall.wg_fwd_lan.dest='wg' || return 1
    uci set firewall.wg_fwd_wg=forwarding || return 1
    uci set firewall.wg_fwd_wg.src='wg' || return 1
    uci set firewall.wg_fwd_wg.dest='lan' || return 1
    uci commit network || return 1
    uci commit firewall || return 1
}
write_wg_uci || die_restore "写入 WireGuard UCI 配置失败"
ubus call network reload >/dev/null 2>&1 || true
sleep 1

# === Mihomo/OpenClash bypass: WG endpoint 流量直连 ===
# 关键: 使用外部 DNS 直连解析, 绕过 OpenClash fake-ip 劫持
EP_IP='${ep_host}'
case "\${EP_IP}" in
    *:*) ;;
    *)
if ! echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$'; then
    # 依次尝试多个外部 DNS 直连解析 (绕过本地 Clash/Mihomo fake-ip)
    for DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
        EP_IP=\$(wg_resolve_real '${ep_host}' "\$DNS_SRV")
        if [ -n "\$EP_IP" ]; then
            echo "[+] endpoint 解析: ${ep_host} -> \$EP_IP (via \$DNS_SRV)"
            break
        fi
    done
fi
        ;;
esac
if [ -z "\${EP_IP}" ]; then
    echo '[!] 警告: 无法解析 endpoint 真实 IP, bypass 规则可能无效!'
fi
if [ -n "\${EP_IP}" ]; then
    case "\${EP_IP}" in
        *:*)
            NFT_FAMILY="ip6"
            ip -6 rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
            ip -6 rule add to "\${EP_IP}" lookup main prio 100
            ;;
        *)
            NFT_FAMILY="ip"
            ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
            ip rule add to "\${EP_IP}" lookup main prio 100
            ;;
    esac
    nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1 && {
        nft insert rule inet fw4 mangle_prerouting "\${NFT_FAMILY}" daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting iifname \"wg0\" counter return comment \"wg_bypass_iface\" 2>/dev/null; true
    }
    echo "[+] Mihomo bypass 规则已添加: \${EP_IP}"
fi

# 持久化: rc.local 中使用外部 DNS 动态解析 (每次开机重新解析)
wg_rc_local_cleanup_managed bypass || die_restore "清理 rc.local 旧 bypass 片段失败"
WG_RC_BLOCK="\$(mktemp /etc/.wg-rc-block.XXXXXX 2>/dev/null)" || die_restore "创建 rc.local 片段临时文件失败"
WG_RC_TMP="\$(mktemp /etc/.rc.local.XXXXXX 2>/dev/null)" || { rm -f "\$WG_RC_BLOCK"; die_restore "创建 rc.local 临时文件失败"; }
if ! cat > "\$WG_RC_BLOCK" << 'WG_RC_EOF'
# BEGIN server-manage wireguard bypass
# WireGuard bypass Mihomo (dynamic resolve, bypass fake-ip) # wg_bypass
wg_resolve_real() {
    WG_RESOLVE_HOST="\$1"
    WG_RESOLVE_DNS="\$2"
    nslookup "\$WG_RESOLVE_HOST" "\$WG_RESOLVE_DNS" 2>/dev/null | awk '
        /^Name:/ { seen_name=1; next }
        seen_name && /^Address[[:space:]][0-9]+:/ {
            ip=\$3
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
        seen_name && /^Address:/ {
            ip=\$2
            sub(/#.*/, "", ip)
            if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
            next
        }
    '
}
case '${ep_host}' in
    *:*) WG_EP='${ep_host}' ;;
    *)
        WG_EP=""
        for WG_DNS_SRV in 223.5.5.5 119.29.29.29 8.8.8.8; do
            WG_EP=\$(wg_resolve_real '${ep_host}' "\$WG_DNS_SRV")
            [ -n "\$WG_EP" ] && break
        done
        ;;
esac # wg_ep_resolve
[ -n "\$WG_EP" ] && case "\$WG_EP" in *:*) WG_NFT_FAMILY=ip6; ip -6 rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true ;; *) WG_NFT_FAMILY=ip; ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null; true ;; esac # wg_bypass
[ -n "\$WG_EP" ] && nft insert rule inet fw4 mangle_prerouting "\$WG_NFT_FAMILY" daddr "\$WG_EP" udp dport ${sport} counter return comment "wg_bypass" 2>/dev/null; true # wg_bypass
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true # wg_bypass
# END server-manage wireguard bypass
WG_RC_EOF
then
    rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"
    die_restore "写入 rc.local 片段失败"
fi
if [ ! -f /etc/rc.local ]; then
    WG_RC_NEW="\$(mktemp /etc/.rc.local.new.XXXXXX 2>/dev/null)" || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"; die_restore "创建 rc.local 初始化临时文件失败"; }
    printf '#!/bin/sh\nexit 0\n' > "\$WG_RC_NEW" || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP" "\$WG_RC_NEW"; die_restore "写入 rc.local 初始化文件失败"; }
    chmod +x "\$WG_RC_NEW" 2>/dev/null && mv "\$WG_RC_NEW" /etc/rc.local || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP" "\$WG_RC_NEW"; die_restore "安装 /etc/rc.local 失败"; }
fi
if awk '
    FNR == NR { block = block \$0 ORS; next }
    /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?\$/ && !inserted { printf "%s", block; inserted=1 }
    { print }
    END { if (!inserted) printf "%s", block }
	' "\$WG_RC_BLOCK" /etc/rc.local > "\$WG_RC_TMP"; then
    chmod +x "\$WG_RC_TMP" 2>/dev/null && mv "\$WG_RC_TMP" /etc/rc.local || { rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"; die_restore "安装 /etc/rc.local 失败"; }
else
    rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"
    die_restore "生成 /etc/rc.local 失败"
fi
chmod +x /etc/rc.local 2>/dev/null; true
rm -f "\$WG_RC_BLOCK" "\$WG_RC_TMP"

# === 开机自恢复服务 ===
WG_CLIENT_TMP="\$(mktemp /etc/init.d/.wg-client.XXXXXX 2>/dev/null)" || die_restore "创建 wg-client init 临时文件失败"
if ! cat > "\$WG_CLIENT_TMP" << 'INITEOF'
#!/bin/sh /etc/rc.common
START=99
USE_PROCD=0
boot() { start; }
wg_is_up() {
    ifstatus wg0 2>/dev/null | grep -q '"up": true'
}
wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}
wg_ensure_wireguard_proto() {
    wg_proto_registered && return 0
    logger -t wg-client "wireguard proto missing, restarting network"
    /etc/init.d/network restart >/dev/null 2>&1 || true
    sleep 5
    wg_proto_registered
}
start() {
    if command -v wg >/dev/null 2>&1 && uci -q get network.wg0.proto >/dev/null 2>&1; then
        wg_ensure_wireguard_proto || logger -t wg-client "wireguard proto still missing after network restart"
        ifup wg0 >/dev/null 2>&1 || true
        sleep 2
        wg_is_up && return 0
        logger -t wg-client "WireGuard configured but not up, restoring"
    else
        logger -t wg-client "WireGuard missing, restoring..."
    fi
    for _r in 1 2 3; do opkg update && break; sleep 3; done
    opkg install kmod-wireguard wireguard-tools luci-proto-wireguard 2>/dev/null
    /etc/init.d/rpcd restart 2>/dev/null; sleep 1
    restore_wg_uci() {
        uci set network.wg0=interface || return 1
        uci set network.wg0.proto='wireguard' || return 1
        uci set network.wg0.private_key='${peer_privkey}' || return 1
        uci set network.wg0.mtu='1420' || return 1
        uci delete network.wg0.addresses 2>/dev/null; true
        uci add_list network.wg0.addresses='${peer_ip}/${mask}' || return 1
        uci set network.wg_server=wireguard_wg0 || return 1
        uci set network.wg_server.public_key='${spub}' || return 1
        uci set network.wg_server.preshared_key='${psk}' || return 1
        uci set network.wg_server.endpoint_host='${ep_host}' || return 1
        uci set network.wg_server.endpoint_port='${sport}' || return 1
        uci set network.wg_server.persistent_keepalive='25' || return 1
        uci set network.wg_server.route_allowed_ips='1' || return 1
${uci_allowed_lines}        uci set firewall.wg_zone=zone || return 1
        uci set firewall.wg_zone.name='wg' || return 1
        uci set firewall.wg_zone.input='ACCEPT' || return 1
        uci set firewall.wg_zone.output='ACCEPT' || return 1
        uci set firewall.wg_zone.forward='ACCEPT' || return 1
        uci set firewall.wg_zone.masq='1' || return 1
        uci add_list firewall.wg_zone.network='wg0' || return 1
        uci set firewall.wg_fwd_lan=forwarding || return 1
        uci set firewall.wg_fwd_lan.src='lan' || return 1
        uci set firewall.wg_fwd_lan.dest='wg' || return 1
        uci set firewall.wg_fwd_wg=forwarding || return 1
        uci set firewall.wg_fwd_wg.src='wg' || return 1
        uci set firewall.wg_fwd_wg.dest='lan' || return 1
        uci commit network || return 1
        uci commit firewall || return 1
    }
    if ! restore_wg_uci; then
        logger -t wg-client "WireGuard restore failed"
        return 1
    fi
    wg_ensure_wireguard_proto || {
        logger -t wg-client "wireguard proto missing before ifup"
        return 1
    }
    ubus call network reload >/dev/null 2>&1 || true
    sleep 1
    ifup wg0 >/dev/null 2>&1 || true
    sleep 2
    if ! wg_is_up; then
        logger -t wg-client "WireGuard restore failed"
        return 1
    fi
    logger -t wg-client "WireGuard restored"
}
INITEOF
then
    rm -f "\$WG_CLIENT_TMP"
    die_restore "写入 wg-client init 失败"
fi
chmod 0700 "\$WG_CLIENT_TMP" && mv "\$WG_CLIENT_TMP" /etc/init.d/wg-client || { rm -f "\$WG_CLIENT_TMP"; die_restore "安装 wg-client init 失败"; }
rm -f "\$WG_CLIENT_TMP"
/etc/init.d/wg-client enable || die_restore "启用 wg-client init 失败"
echo '[+] 开机自恢复服务已安装'

# === 启动接口 ===
ifup wg0 || die_restore "启动 wg0 失败"

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

# === WireGuard 看门狗 (fake-ip检测 + DNS直连解析 + 完整bypass自恢复 + 握手保活 + 安全日志) ===
WG_WATCHDOG_TMP="$(mktemp /usr/bin/.wg-watchdog.XXXXXX 2>/dev/null)" || die_restore "创建 wg-watchdog 临时文件失败"
if ! cat > "$WG_WATCHDOG_TMP" << 'WDSCRIPT'
#!/bin/sh
LOG_DIR="/var/run/server-manage"
LOG_FILE="$LOG_DIR/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    size=0
    tmp=""
    logger -t wg-watchdog "$1"
    if [ -L "$LOG_DIR" ] || { [ -e "$LOG_DIR" ] && [ ! -d "$LOG_DIR" ]; }; then
        return 0
    fi
    mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    chmod 0700 "$LOG_DIR" 2>/dev/null || true
    [ -L "$LOG_FILE" ] && return 0
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || return 0
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        case "$size" in *[!0-9]*|"") size=0 ;; esac
    fi
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        tmp=$(mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX" 2>/dev/null) || tmp=""
        if [ -n "$tmp" ]; then
            tail -n 50 "$LOG_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_FILE"
            rm -f "$tmp" 2>/dev/null || true
        fi
    fi
}

resolve_real() {
    local host="$1" ip=""
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] || continue
        echo "$ip"; return 0
    done
    return 1
}

wg_endpoint_host() {
    local endpoint="$1"
    case "$endpoint" in
        \[*\]:*) echo "$endpoint" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p' ;;
        *:*)     echo "$endpoint" | sed 's/:[0-9][0-9]*$//' ;;
        *)       echo "$endpoint" ;;
    esac
}

wg_format_endpoint() {
    local host="$1" port="$2"
    case "$host" in
        *:*) echo "[${host}]:${port}" ;;
        *)   echo "${host}:${port}" ;;
    esac
}

wg_nft_addr_family() {
    case "$1" in
        *:*) echo "ip6" ;;
        *)   echo "ip" ;;
    esac
}

wg_ip_rule_show() {
    case "$1" in
        *:*) ip -6 rule show 2>/dev/null ;;
        *)   ip rule show 2>/dev/null ;;
    esac
}

wg_ip_rule_del() {
    case "$1" in
        *:*) ip -6 rule del to "$1" lookup main prio 100 2>/dev/null ;;
        *)   ip rule del to "$1" lookup main prio 100 2>/dev/null ;;
    esac
}

wg_ip_rule_add() {
    case "$1" in
        *:*) ip -6 rule add to "$1" lookup main prio 100 2>/dev/null ;;
        *)   ip rule add to "$1" lookup main prio 100 2>/dev/null ;;
    esac
}

wg_is_up() {
    ifstatus wg0 2>/dev/null | grep -q '"up": true'
}

wg_proto_registered() {
    ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'
}

if ! wg_is_up; then
    wdlog "wg0 not up, restarting"
    if ! wg_proto_registered; then
        wdlog "wireguard proto missing, restarting network"
        /etc/init.d/network restart >/dev/null 2>&1 || true
        sleep 5
    fi
    ifup wg0 >/dev/null 2>&1 || true
    exit 0
fi

# resolve endpoint (always set RESOLVED for bypass self-heal)
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif echo "$EP_HOST" | grep -q ':'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

# DNS re-resolve + endpoint update (only for domain endpoints)
if [ -n "$EP_HOST" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && ! echo "$EP_HOST" | grep -q ':'; then
    CURRENT_EP=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | head -1)
    CURRENT=$(wg_endpoint_host "$CURRENT_EP")
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*) FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        WG_ENDPOINT=$(wg_format_endpoint "$RESOLVED" "$PORT")
        NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
        wg set wg0 peer "$PUB" endpoint "$WG_ENDPOINT"
        for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
            nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
        done
        nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        wg_ip_rule_del "$RESOLVED"; true
        wg_ip_rule_add "$RESOLVED"; true
        wdlog "bypass updated -> $RESOLVED"
    fi
fi

# bypass rule self-heal (complete: iface + IP + ip rule)
if nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ]; then
        if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
            PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
            NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
            nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wdlog "restored IP bypass -> $RESOLVED"
        fi
    fi
fi
if [ -n "$RESOLVED" ] && ! wg_ip_rule_show "$RESOLVED" | grep -q "$RESOLVED"; then
    wg_ip_rule_add "$RESOLVED"; true
    wdlog "restored ip rule -> $RESOLVED"
fi

# connectivity check (handshake timeout + ping fallback)
LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" >/dev/null 2>&1; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
then
    rm -f "$WG_WATCHDOG_TMP"
    die_restore "写入 wg-watchdog 失败"
fi
chmod 0700 "$WG_WATCHDOG_TMP" && mv "$WG_WATCHDOG_TMP" /usr/bin/wg-watchdog.sh || { rm -f "$WG_WATCHDOG_TMP"; die_restore "安装 wg-watchdog 失败"; }
rm -f "$WG_WATCHDOG_TMP"
WG_CRON_TMP="$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null)" || die_restore "创建 wg-watchdog cron 临时文件失败"
(crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"'; echo '* * * * * /usr/bin/wg-watchdog.sh') > "$WG_CRON_TMP" || { rm -f "$WG_CRON_TMP"; die_restore "生成 wg-watchdog cron 失败"; }
mkdir -p /etc/crontabs 2>/dev/null || { rm -f "$WG_CRON_TMP"; die_restore "创建 OpenWrt cron 目录失败"; }
cp "$WG_CRON_TMP" /etc/crontabs/root 2>/dev/null || { rm -f "$WG_CRON_TMP"; die_restore "写入 OpenWrt cron 文件失败"; }
chmod 600 /etc/crontabs/root 2>/dev/null || true
rm -f "$WG_CRON_TMP"
awk '$6 == "/usr/bin/wg-watchdog.sh" { found=1 } END { exit !found }' /etc/crontabs/root || die_restore "安装 wg-watchdog cron 失败"
/etc/init.d/cron restart || die_restore "重启 cron 失败"
cleanup_uci_snapshots
echo '[+] 看门狗已安装 (DNS直连 + fake-ip检测 + 完整bypass自恢复 + 握手保活 + 日志持久化)'
WDEOF
    else
        cat << 'NO_WATCHDOG_EOF'
cleanup_uci_snapshots
NO_WATCHDOG_EOF
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

wg_show_openwrt_endpoint_migrate_cmd() {
    wg_check_server || return 1
    print_title "生成 OpenWrt 客户端 endpoint 安全迁移命令"

    local cur_ep cur_port new_ep ep_host server_ip server_lan health_lan=""
    cur_ep=$(wg_db_get '.server.endpoint')
    cur_port=$(wg_db_get '.server.port')
    server_ip=$(wg_db_get '.server.ip')
    server_lan=$(wg_db_get '.server.server_lan_subnet // empty')
    echo -e "  当前服务端 endpoint: ${C_GREEN}${cur_ep}:${cur_port}${C_RESET}"
    read -e -r -p "目标 endpoint 主机名/IP [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if ! ep_host=$(wg_shared_normalize_endpoint_host "$new_ep"); then
        print_error "endpoint 无效"
        pause; return 1
    fi

    if [[ -n "$server_lan" && "$server_lan" != "null" && "$server_lan" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)\.0/24$ ]]; then
        health_lan="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.1"
    fi

    draw_line
    echo -e "${C_CYAN}=== OpenWrt 客户端 endpoint 安全迁移命令 ===${C_RESET}"
    echo -e "${C_YELLOW}在目标 OpenWrt 客户端 SSH 终端执行。脚本会先运行态切换并健康检查，成功后才持久化。${C_RESET}"
    draw_line
    cat << MIGRATE_HEAD
NEW_HOST='${ep_host}'
NEW_PORT='${cur_port}'
HEALTH_WG='${server_ip}'
HEALTH_LAN='${health_lan}'
MIGRATE_HEAD
    cat <<'MIGRATE_BODY'
set -u
WG_IF="wg0"
SNAP_DIR="/root/wg-endpoint-migrate-$(date +%Y%m%d-%H%M%S)"

die() { echo "[!] $*" >&2; exit 1; }
mkdir -p "$SNAP_DIR" || die "创建回滚快照目录失败"
chmod 700 "$SNAP_DIR" 2>/dev/null || true
uci export network > "$SNAP_DIR/network.uci" 2>/dev/null || die "备份 network UCI 失败"
for f in /etc/init.d/wg-client /etc/rc.local /usr/bin/wg-watchdog.sh; do
    [ -e "$f" ] && cp -p "$f" "$SNAP_DIR/$(basename "$f").bak" 2>/dev/null || true
done

OLD_HOST=$(uci -q get network.wg_server.endpoint_host 2>/dev/null || true)
OLD_PORT=$(uci -q get network.wg_server.endpoint_port 2>/dev/null || true)
[ -n "$OLD_HOST" ] || die "未找到 network.wg_server.endpoint_host"
[ -n "$NEW_PORT" ] || NEW_PORT="$OLD_PORT"
[ -n "$NEW_PORT" ] || die "未找到 endpoint_port"
PUB=$(wg show "$WG_IF" peers 2>/dev/null | head -1)
OLD_RUNTIME_EP=$(wg show "$WG_IF" endpoints 2>/dev/null | awk '{print $2}' | head -1)
[ -n "$PUB" ] || die "未找到 WireGuard peer"

restore_all() {
    echo "[!] 回滚 endpoint 迁移" >&2
    [ -s "$SNAP_DIR/network.uci" ] && {
        uci revert network >/dev/null 2>&1 || true
        uci import network < "$SNAP_DIR/network.uci" >/dev/null 2>&1 || true
        uci commit network >/dev/null 2>&1 || true
    }
    [ -f "$SNAP_DIR/wg-client.bak" ] && cp -p "$SNAP_DIR/wg-client.bak" /etc/init.d/wg-client 2>/dev/null || true
    [ -f "$SNAP_DIR/rc.local.bak" ] && cp -p "$SNAP_DIR/rc.local.bak" /etc/rc.local 2>/dev/null || true
    [ -f "$SNAP_DIR/wg-watchdog.sh.bak" ] && cp -p "$SNAP_DIR/wg-watchdog.sh.bak" /usr/bin/wg-watchdog.sh 2>/dev/null || true
    [ -n "${OLD_RUNTIME_EP:-}" ] && wg set "$WG_IF" peer "$PUB" endpoint "$OLD_RUNTIME_EP" 2>/dev/null || true
}

resolve_real() {
    h="$1"
    case "$h" in *:*) echo "$h"; return 0 ;; esac
    echo "$h" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && { echo "$h"; return 0; }
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$h" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    done
    return 1
}

format_endpoint() {
    case "$1" in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac
}

replace_literal() {
    file="$1"; old="$2"; new="$3"
    [ -f "$file" ] || return 0
    old_re=$(printf '%s' "$old" | sed 's/[.[\*^$()+?{}|\\]/\\&/g')
    new_re=$(printf '%s' "$new" | sed 's/[\/&]/\\&/g')
    tmp=$(mktemp "$(dirname "$file")/.endpoint-migrate.XXXXXX") || return 1
    sed "s/${old_re}/${new_re}/g" "$file" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$file" "$tmp" 2>/dev/null || chmod 700 "$tmp" 2>/dev/null || true
    mv "$tmp" "$file" || { rm -f "$tmp"; return 1; }
}

install_rc_local_bypass() {
    host="$1"; port="$2"; rc="/etc/rc.local"
    [ -f "$rc" ] || { printf '#!/bin/sh\nexit 0\n' > "$rc" || return 1; chmod 755 "$rc" 2>/dev/null || true; }
    dir=$(dirname "$rc")
    base=$(mktemp "$dir/.endpoint-migrate-rc-base.XXXXXX") || return 1
    block=$(mktemp "$dir/.endpoint-migrate-rc-block.XXXXXX") || { rm -f "$base"; return 1; }
    tmp=$(mktemp "$dir/.endpoint-migrate-rc.XXXXXX") || { rm -f "$base" "$block"; return 1; }
    awk '
        /^# BEGIN server-manage wireguard bypass$/ { skip=1; next }
        /^# END server-manage wireguard bypass$/ { skip=0; next }
        skip { next }
        /# wg_bypass/ { next }
        /# wg_ep_resolve/ { next }
        { print }
    ' "$rc" > "$base" || { rm -f "$base" "$block" "$tmp"; return 1; }
    cat > "$block" <<RCBLOCK || { rm -f "$base" "$block" "$tmp"; return 1; }
# BEGIN server-manage wireguard bypass
wg_resolve_real() {
    h="\$1"
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=\$(nslookup "\$h" "\$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=\$3
                if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=\$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\\.18\\.|198\\.19\\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "\$ip" ] && { echo "\$ip"; return 0; }
    done
    return 1
}
WG_EP=""
case '$host' in
    *:*) WG_EP='$host' ;;
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) WG_EP='$host' ;;
    *) WG_EP=\$(wg_resolve_real '$host' || true) ;;
esac
if [ -n "\$WG_EP" ]; then
    case "\$WG_EP" in
        *:*) WG_NFT_FAMILY=ip6; ip -6 rule add to "\$WG_EP" lookup main prio 100 2>/dev/null || true ;;
        *) WG_NFT_FAMILY=ip; ip rule add to "\$WG_EP" lookup main prio 100 2>/dev/null || true ;;
    esac
    nft insert rule inet fw4 mangle_prerouting "\$WG_NFT_FAMILY" daddr "\$WG_EP" udp dport $port counter return comment "wg_bypass" 2>/dev/null || true
fi
nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null || true
# END server-manage wireguard bypass
RCBLOCK
    awk -v block="$block" '
        function emit_block() {
            while ((getline line < block) > 0) print line
            close(block)
        }
        BEGIN { inserted=0 }
        {
            if (!inserted && $0 ~ /^[[:space:]]*exit[[:space:]]+0[[:space:]]*($|#)/) {
                emit_block()
                inserted=1
            }
            print
        }
        END {
            if (!inserted) {
                emit_block()
                print "exit 0"
            }
        }
    ' "$base" > "$tmp" || { rm -f "$base" "$block" "$tmp"; return 1; }
    chmod 755 "$tmp" 2>/dev/null || true
    mv "$tmp" "$rc" || { rm -f "$base" "$block" "$tmp"; return 1; }
    rm -f "$base" "$block"
}

install_watchdog() {
    tmp=$(mktemp /usr/bin/.wg-watchdog.XXXXXX 2>/dev/null) || return 1
    cat > "$tmp" <<'WDSCRIPT'
#!/bin/sh
LOG_DIR="/var/run/server-manage"
LOG_FILE="$LOG_DIR/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    size=0
    tmp=""
    logger -t wg-watchdog "$1"
    if [ -L "$LOG_DIR" ] || { [ -e "$LOG_DIR" ] && [ ! -d "$LOG_DIR" ]; }; then return 0; fi
    mkdir -p "$LOG_DIR" 2>/dev/null || return 0
    chmod 0700 "$LOG_DIR" 2>/dev/null || true
    [ -L "$LOG_FILE" ] && return 0
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG_FILE" 2>/dev/null || return 0
    if [ -f "$LOG_FILE" ]; then
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        case "$size" in *[!0-9]*|"") size=0 ;; esac
    fi
    if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
        tmp=$(mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX" 2>/dev/null) || tmp=""
        [ -n "$tmp" ] && tail -n 50 "$LOG_FILE" > "$tmp" 2>/dev/null && mv "$tmp" "$LOG_FILE"
        rm -f "$tmp" 2>/dev/null || true
    fi
}

resolve_real() {
    host="$1"
    for dns in 223.5.5.5 119.29.29.29 8.8.8.8; do
        ip=$(nslookup "$host" "$dns" 2>/dev/null | awk '
            /^Name:/ { seen_name=1; next }
            seen_name && /^Address[[:space:]][0-9]+:/ {
                ip=$3
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
            seen_name && /^Address:/ {
                ip=$2
                sub(/#.*/, "", ip)
                if (ip !~ /^(198\.18\.|198\.19\.)/) { print ip; exit }
                next
            }
        ')
        [ -n "$ip" ] && { echo "$ip"; return 0; }
    done
    return 1
}

wg_endpoint_host() {
    case "$1" in \[*\]:*) echo "$1" | sed -n 's/^\[\(.*\)\]:[0-9][0-9]*$/\1/p' ;; *:*) echo "$1" | sed 's/:[0-9][0-9]*$//' ;; *) echo "$1" ;; esac
}
wg_format_endpoint() { case "$1" in *:*) echo "[$1]:$2" ;; *) echo "$1:$2" ;; esac; }
wg_nft_addr_family() { case "$1" in *:*) echo "ip6" ;; *) echo "ip" ;; esac; }
wg_ip_rule_show() { case "$1" in *:*) ip -6 rule show 2>/dev/null ;; *) ip rule show 2>/dev/null ;; esac; }
wg_ip_rule_del() { case "$1" in *:*) ip -6 rule del to "$1" lookup main prio 100 2>/dev/null ;; *) ip rule del to "$1" lookup main prio 100 2>/dev/null ;; esac; }
wg_ip_rule_add() { case "$1" in *:*) ip -6 rule add to "$1" lookup main prio 100 2>/dev/null ;; *) ip rule add to "$1" lookup main prio 100 2>/dev/null ;; esac; }
wg_is_up() { ifstatus wg0 2>/dev/null | grep -q '"up": true'; }
wg_proto_registered() { ubus call network get_proto_handlers 2>/dev/null | grep -q '"wireguard"'; }

if ! wg_is_up; then
    wdlog "wg0 not up, restarting"
    if ! wg_proto_registered; then
        wdlog "wireguard proto missing, restarting network"
        /etc/init.d/network restart >/dev/null 2>&1 || true
        sleep 5
    fi
    ifup wg0 >/dev/null 2>&1 || true
    exit 0
fi

EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
RESOLVED=""
if echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    RESOLVED="$EP_HOST"
elif echo "$EP_HOST" | grep -q ':'; then
    RESOLVED="$EP_HOST"
elif [ -n "$EP_HOST" ]; then
    RESOLVED=$(resolve_real "$EP_HOST")
fi

if [ -n "$EP_HOST" ] && [ -n "$PORT" ] && ! echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && ! echo "$EP_HOST" | grep -q ':'; then
    CURRENT_EP=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | head -1)
    CURRENT=$(wg_endpoint_host "$CURRENT_EP")
    FAKE_IP=0
    case "$CURRENT" in 198.18.*|198.19.*|"") FAKE_IP=1 ;; esac
    if [ -n "$RESOLVED" ] && { [ "$RESOLVED" != "$CURRENT" ] || [ "$FAKE_IP" = "1" ]; }; then
        PUB=$(wg show wg0 endpoints 2>/dev/null | awk '{print $1}' | head -1)
        if [ -n "$PUB" ]; then
            wdlog "endpoint update: $CURRENT -> $RESOLVED (fake=$FAKE_IP)"
            wg set wg0 peer "$PUB" endpoint "$(wg_format_endpoint "$RESOLVED" "$PORT")" >/dev/null 2>&1 || true
            for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | grep -v 'iface' | awk '{print $NF}'); do
                nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
            done
            NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
            nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
            wg_ip_rule_del "$RESOLVED"; true
            wg_ip_rule_add "$RESOLVED"; true
            wdlog "bypass updated -> $RESOLVED"
        fi
    fi
fi

if nft list chain inet fw4 mangle_prerouting >/dev/null 2>&1; then
    if ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q 'wg_bypass_iface'; then
        nft insert rule inet fw4 mangle_prerouting iifname "wg0" counter return comment "wg_bypass_iface" 2>/dev/null; true
        wdlog "restored wg_bypass_iface rule"
    fi
    if [ -n "$RESOLVED" ] && ! nft list chain inet fw4 mangle_prerouting 2>/dev/null | grep -q "daddr $RESOLVED"; then
        NFT_FAMILY=$(wg_nft_addr_family "$RESOLVED")
        nft insert rule inet fw4 mangle_prerouting "$NFT_FAMILY" daddr "$RESOLVED" udp dport "$PORT" counter return comment "wg_bypass" 2>/dev/null; true
        wdlog "restored IP bypass -> $RESOLVED"
    fi
fi
if [ -n "$RESOLVED" ] && ! wg_ip_rule_show "$RESOLVED" | grep -q "$RESOLVED"; then
    wg_ip_rule_add "$RESOLVED"; true
    wdlog "restored ip rule -> $RESOLVED"
fi

LAST_HS=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}' | head -1)
NOW=$(date +%s)
if [ -n "$LAST_HS" ] && [ "$LAST_HS" != "0" ] && [ $((NOW - LAST_HS)) -gt 180 ]; then
    VIP=$(uci get network.wg0.addresses 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
    VIP=$(echo "$VIP" | awk -F. '{printf "%s.%s.%s.1",$1,$2,$3}')
    if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" >/dev/null 2>&1; then
        wdlog "no handshake for $((NOW - LAST_HS))s + ping failed, restarting"
        ifdown wg0; sleep 2; ifup wg0
    fi
fi
WDSCRIPT
    chmod 0700 "$tmp" && mv "$tmp" /usr/bin/wg-watchdog.sh || { rm -f "$tmp"; return 1; }
    cron_tmp=$(mktemp /tmp/.wg-watchdog-cron.XXXXXX 2>/dev/null) || return 1
    (crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"'; echo '* * * * * /usr/bin/wg-watchdog.sh') > "$cron_tmp" || { rm -f "$cron_tmp"; return 1; }
    mkdir -p /etc/crontabs 2>/dev/null || { rm -f "$cron_tmp"; return 1; }
    cp "$cron_tmp" /etc/crontabs/root 2>/dev/null || { rm -f "$cron_tmp"; return 1; }
    chmod 600 /etc/crontabs/root 2>/dev/null || true
    rm -f "$cron_tmp"
    /etc/init.d/cron restart >/dev/null 2>&1 || return 1
}

NEW_IP=$(resolve_real "$NEW_HOST") || die "解析新 endpoint 失败: $NEW_HOST"
NEW_RUNTIME_EP=$(format_endpoint "$NEW_IP" "$NEW_PORT")
echo "[*] runtime endpoint: ${OLD_RUNTIME_EP:-none} -> $NEW_RUNTIME_EP"
wg set "$WG_IF" peer "$PUB" endpoint "$NEW_RUNTIME_EP" || { restore_all; exit 1; }
sleep 2
ping -c 2 -W 2 "$HEALTH_WG" >/dev/null 2>&1 || { restore_all; die "运行态切换后 VPN 健康检查失败"; }
[ -z "$HEALTH_LAN" ] || ping -c 2 -W 2 "$HEALTH_LAN" >/dev/null 2>&1 || { restore_all; die "运行态切换后 LAN 健康检查失败"; }

uci set network.wg_server.endpoint_host="$NEW_HOST" || { restore_all; exit 1; }
uci set network.wg_server.endpoint_port="$NEW_PORT" || { restore_all; exit 1; }
uci commit network || { restore_all; exit 1; }
replace_literal /etc/init.d/wg-client "$OLD_HOST" "$NEW_HOST" || { restore_all; exit 1; }
install_rc_local_bypass "$NEW_HOST" "$NEW_PORT" || { restore_all; exit 1; }
install_watchdog || { restore_all; die "安装新版 wg-watchdog 失败"; }
/usr/bin/wg-watchdog.sh >/dev/null 2>&1 || true
sleep 2
ping -c 2 -W 2 "$HEALTH_WG" >/dev/null 2>&1 || { restore_all; die "持久化后 VPN 健康检查失败"; }
[ -z "$HEALTH_LAN" ] || ping -c 2 -W 2 "$HEALTH_LAN" >/dev/null 2>&1 || { restore_all; die "持久化后 LAN 健康检查失败"; }
echo "[+] endpoint 已迁移: $NEW_HOST:$NEW_PORT"
echo "[+] 快照目录: $SNAP_DIR"
wg show "$WG_IF" endpoints 2>/dev/null || true
MIGRATE_BODY
    draw_line
    pause
}
