# modules/11f-wireguard-portfwd.sh - WireGuard port forwarding
wg_port_forward_menu() {
    wg_check_server || return 1

    while true; do
        print_title "WireGuard 端口转发管理"
        local pf_count
        pf_count=$(wg_db_get '.port_forwards | length')
        if [[ "$pf_count" != "null" && -n "$pf_count" && "$pf_count" -gt 0 ]]; then
            printf "${C_CYAN}%-4s %-10s %-14s %-24s %-8s${C_RESET}\n" \
                "#" "协议" "外部端口" "转发目标" "状态"
            draw_line
            local i=0
            while [[ $i -lt $pf_count ]]; do
                local proto ext_port dest_ip dest_port enabled
                proto=$(wg_db_get ".port_forwards[$i].proto")
                ext_port=$(wg_db_get ".port_forwards[$i].ext_port")
                dest_ip=$(wg_db_get ".port_forwards[$i].dest_ip")
                dest_port=$(wg_db_get ".port_forwards[$i].dest_port")
                enabled=$(wg_db_get ".port_forwards[$i].enabled")
                local status_str
                [[ "$enabled" == "true" ]] && status_str="${C_GREEN}启用${C_RESET}" || status_str="${C_RED}禁用${C_RESET}"
                printf "%-4s %-10s %-14s %-24s %-8b\n" \
                    "$((i + 1))" "$proto" "$ext_port" "${dest_ip}:${dest_port}" "$status_str"
                i=$((i + 1))
            done
        else
            print_info "暂无端口转发规则"
        fi
        echo "  1. 添加端口转发
  2. 删除端口转发
  3. 启用/禁用端口转发
  0. 返回
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" pf_choice
        case $pf_choice in
            1) wg_add_port_forward ;;
            2) wg_delete_port_forward ;;
            3) wg_toggle_port_forward ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_add_port_forward() {
    print_info "添加端口转发规则"
    echo "  1. TCP
  2. UDP
  3. TCP+UDP"
    read -e -r -p "协议 [1]: " proto_choice
    proto_choice=${proto_choice:-1}
    local proto
    case $proto_choice in
        1) proto="tcp" ;;
        2) proto="udp" ;;
        3) proto="tcp+udp" ;;
        *) proto="tcp" ;;
    esac
    local ext_port
    while true; do
        read -e -r -p "外部端口 (本机监听): " ext_port
        validate_port "$ext_port" && break
        print_warn "端口无效 (1-65535)"
    done
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    local dest_ip
    if [[ "$peer_count" -gt 0 ]]; then
        echo "选择目标设备:"
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            echo "  $((i + 1)). ${name} (${ip})"
            i=$((i + 1))
        done
        echo "  0. 手动输入 IP"
        read -e -r -p "选择: " dev_choice
        if [[ "$dev_choice" == "0" || -z "$dev_choice" ]]; then
            read -e -r -p "目标 IP: " dest_ip
        elif [[ "$dev_choice" =~ ^[0-9]+$ ]] && [[ "$dev_choice" -ge 1 && "$dev_choice" -le "$peer_count" ]]; then
            dest_ip=$(wg_db_get ".peers[$((dev_choice - 1))].ip")
        else
            print_error "无效选择"; return
        fi
    else
        read -e -r -p "目标 IP: " dest_ip
    fi
    [[ -z "$dest_ip" ]] && { print_error "目标 IP 不能为空"; return; }
    local dest_port
    read -e -r -p "目标端口 [${ext_port}]: " dest_port
    dest_port=${dest_port:-$ext_port}
    validate_port "$dest_port" || { print_error "端口无效"; return; }
    _wg_pf_iptables -A "$proto" "$ext_port" "$dest_ip" "$dest_port"
    wg_save_iptables
    wg_db_set --arg proto "$proto" \
              --arg ext "$ext_port" \
              --arg dip "$dest_ip" \
              --arg dport "$dest_port" \
    '.port_forwards += [{
        proto: $proto,
        ext_port: ($ext | tonumber),
        dest_ip: $dip,
        dest_port: ($dport | tonumber),
        enabled: true
    }]'
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [[ "$proto" == "tcp+udp" ]]; then
            ufw allow "$ext_port" comment "WG-PF" >/dev/null 2>&1
        else
            ufw allow "${ext_port}/${proto}" comment "WG-PF" >/dev/null 2>&1
        fi
    fi
    print_success "端口转发已添加: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
    log_action "WireGuard port forward added: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
    # 联动: 提示配置域名反代
    if [[ "$proto" == *"tcp"* ]] && command_exists nginx; then
        echo ""
        print_guide "已在本机 ${ext_port} 端口监听，可通过域名反代 (HTTPS) 对外提供服务"
        if confirm "是否为此端口配置域名反代 (Nginx + SSL)?"; then
            web_reverse_proxy_site "127.0.0.1:${ext_port}"
        fi
    fi
}

wg_delete_port_forward() {
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 ]] && { print_warn "暂无规则"; return; }
    read -e -r -p "选择要删除的规则序号: " idx
    [[ -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$pf_count" ]]; then
        print_error "无效序号"; return
    fi
    local target_idx=$((idx - 1))
    local proto ext_port dest_ip dest_port
    proto=$(wg_db_get ".port_forwards[$target_idx].proto")
    ext_port=$(wg_db_get ".port_forwards[$target_idx].ext_port")
    dest_ip=$(wg_db_get ".port_forwards[$target_idx].dest_ip")
    dest_port=$(wg_db_get ".port_forwards[$target_idx].dest_port")
    _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
    wg_save_iptables
    wg_db_set --argjson idx "$target_idx" 'del(.port_forwards[$idx])'
    print_success "端口转发规则已删除"
    log_action "WireGuard port forward deleted: ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
}

wg_toggle_port_forward() {
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 ]] && { print_warn "暂无规则"; return; }
    read -e -r -p "选择要切换状态的规则序号: " idx
    [[ -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$pf_count" ]]; then
        print_error "无效序号"; return
    fi
    local target_idx=$((idx - 1))
    local proto ext_port dest_ip dest_port current_state
    proto=$(wg_db_get ".port_forwards[$target_idx].proto")
    ext_port=$(wg_db_get ".port_forwards[$target_idx].ext_port")
    dest_ip=$(wg_db_get ".port_forwards[$target_idx].dest_ip")
    dest_port=$(wg_db_get ".port_forwards[$target_idx].dest_port")
    current_state=$(wg_db_get ".port_forwards[$target_idx].enabled")
    if [[ "$current_state" == "true" ]]; then
        _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
        wg_db_set --argjson idx "$target_idx" '.port_forwards[$idx].enabled = false'
        print_success "端口转发已禁用: ${ext_port}/${proto}"
    else
        _wg_pf_iptables -A "$proto" "$ext_port" "$dest_ip" "$dest_port"
        wg_db_set --argjson idx "$target_idx" '.port_forwards[$idx].enabled = true'
        print_success "端口转发已启用: ${ext_port}/${proto}"
    fi
    wg_save_iptables
}

