# modules/12e-wireguard-deb-extra.sh - Debian/Ubuntu WireGuard 看门狗/导入导出/菜单
wg_deb_setup_watchdog() {
    wg_deb_check_installed || return 1
    local watchdog_script="/usr/local/bin/wg-watchdog.sh"
    local watchdog_log="/var/log/wg-watchdog.log"
    local auto_mode="${1:-}"

    # 已启用时的管理界面
    if [[ -z "$auto_mode" ]] && cron_has_job_command "$watchdog_script"; then
        print_title "WireGuard 看门狗"
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
        echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
        echo "  1. 禁用看门狗
  2. 查看日志
  3. 手动触发一次检测
  0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1)
                cron_remove_job_command "$watchdog_script"
                rm -f "$watchdog_script"
                print_success "看门狗已禁用"
                log_action "WireGuard(deb) watchdog disabled"
                ;;
            2) echo ""; tail -n 30 "$watchdog_log" 2>/dev/null || print_warn "无日志" ;;
            3)
                if [[ -x "$watchdog_script" ]]; then
                    bash "$watchdog_script"
                    print_success "检测完成"
                    echo ""; tail -n 5 "$watchdog_log" 2>/dev/null
                else
                    print_warn "看门狗脚本不存在"
                fi
                ;;
        esac
        pause; return
    fi

    if [[ -z "$auto_mode" ]]; then
        print_title "WireGuard 服务端看门狗 (Debian)"
        echo "看门狗功能:
  • 每分钟检测 ${WG_DEB_INTERFACE} 接口状态
  • 接口消失 → 自动 systemctl restart
  • wg show 失败 → 自动重启"
        if ! confirm "启用看门狗?"; then pause; return; fi
    fi

    mkdir -p "$(dirname "$watchdog_script")" || { print_error "创建看门狗目录失败"; [[ -z "$auto_mode" ]] && pause; return 1; }
    local watchdog_tmp
    watchdog_tmp=$(mktemp "$(dirname "$watchdog_script")/.tmp.server-manage.wg-watchdog.XXXXXX") || {
        print_error "创建看门狗临时脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    }
    _tmp_register "$watchdog_tmp"

    # ── Debian 看门狗 (systemctl 管理) ──
    if ! {
        cat << 'WDEOF_DEB'
#!/bin/bash
WDEOF_DEB
        printf 'WG_DEB_INTERFACE=%q\n' "$WG_DEB_INTERFACE"
        cat << 'WDEOF_DEB'
LOG="/var/log/wg-watchdog.log"
MAX_LOG_SIZE=32768

wdlog() {
    logger -t wg-watchdog "$1"
    echo "$(date '+%m-%d %H:%M:%S') $1" >> "$LOG"
    if [[ -f "$LOG" ]] && [[ $(wc -c < "$LOG" 2>/dev/null || echo 0) -gt $MAX_LOG_SIZE ]]; then
        tail -n 50 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
}

# 检测接口存活
if ! ip link show "$WG_DEB_INTERFACE" &>/dev/null; then
    wdlog "${WG_DEB_INTERFACE} down, restarting via systemctl"
    systemctl restart "wg-quick@${WG_DEB_INTERFACE}"
    exit 0
fi

# 检测 wg show 是否正常
if ! wg show "$WG_DEB_INTERFACE" &>/dev/null; then
    wdlog "wg show ${WG_DEB_INTERFACE} failed, restarting"
    systemctl restart "wg-quick@${WG_DEB_INTERFACE}"
    exit 0
fi
WDEOF_DEB
    } > "$watchdog_tmp"; then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "写入看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    chmod 0755 "$watchdog_tmp" 2>/dev/null || true
    if ! mv "$watchdog_tmp" "$watchdog_script"; then
        rm -f "$watchdog_tmp" 2>/dev/null || true
        _tmp_unregister "$watchdog_tmp"
        print_error "安装看门狗脚本失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    _tmp_unregister "$watchdog_tmp"
    if ! cron_add_job_command "$watchdog_script" "* * * * * $watchdog_script >/dev/null 2>&1"; then
        rm -f "$watchdog_script" 2>/dev/null || true
        print_error "安装看门狗 cron 任务失败"
        [[ -z "$auto_mode" ]] && pause
        return 1
    fi
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo "  检测: 接口存活 → wg show"
    log_action "WireGuard(deb) watchdog enabled"
    [[ -z "$auto_mode" ]] && pause
    return 0
}

wg_deb_export_peers() {
    wg_deb_check_server || return 1
    print_title "导出 WireGuard 设备配置"
    local peer_count
    if ! peer_count=$(wg_deb_db_get '.peers | length') || [[ ! "$peer_count" =~ ^[0-9]+$ ]]; then
        print_error "读取设备数量失败"
        pause; return 1
    fi
    if [[ "$peer_count" -eq 0 ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(wg_shared_export_file) || { print_error "无法创建导出文件"; pause; return 1; }
    if jq '{
        export_version: 2,
        export_date: (now | todate),
        server: {
            endpoint: .server.endpoint,
            port: .server.port,
            subnet: .server.subnet,
            dns: .server.dns,
            public_key: .server.public_key,
            server_lan_subnet: .server.server_lan_subnet
        },
        peers: .peers
    }' "$WG_DEB_DB_FILE" > "$export_file" 2>/dev/null; then
        print_success "已导出 $peer_count 个设备到:"
        echo -e "  ${C_CYAN}${export_file}${C_RESET}"
        local fsize=$(du -h "$export_file" 2>/dev/null | awk '{print $1}')
        echo "  文件大小: $fsize"
        echo ""
        print_warn "该文件包含私钥等敏感信息，请妥善保管！"
        echo "可使用 [导入设备配置] 在其他服务器恢复。"
        log_action "WireGuard(deb) peers exported: count=$peer_count file=$export_file"
    else
        print_error "导出失败"
        rm -f "$export_file" 2>/dev/null || true
        pause; return 1
    fi
    pause
}

_wg_deb_import_snapshot_clients() {
    local backup_dir="$1"
    mkdir -p "$(dirname "$backup_dir")" || return 1
    rm -rf "$backup_dir" 2>/dev/null || true
    if [[ -d "$WG_DEB_CLIENT_DIR" ]]; then
        cp -a "$WG_DEB_CLIENT_DIR" "$backup_dir" || return 1
    else
        mkdir -p "$backup_dir" || return 1
    fi
}

_wg_deb_import_restore_snapshot() {
    local db_snapshot="${1:-}" client_backup="${2:-}"
    [[ -n "$db_snapshot" ]] && wg_write_private_file "$WG_DEB_DB_FILE" "$db_snapshot" >/dev/null 2>&1 || true
    if [[ -n "$client_backup" && -d "$client_backup" ]]; then
        rm -rf "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
        mkdir -p "$(dirname "$WG_DEB_CLIENT_DIR")" 2>/dev/null || true
        cp -a "$client_backup" "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
    fi
    wg_deb_rebuild_conf >/dev/null 2>&1 || true
    wg_deb_regenerate_client_confs >/dev/null 2>&1 || true
    wg_deb_is_running && wg_deb_apply_conf >/dev/null 2>&1 || true
}

wg_deb_import_peers() {
    wg_deb_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return 1
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return 1
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return 1
    fi
    echo -e "发现 ${C_CYAN}${import_count}${C_RESET} 个设备:"
    jq -r '.peers[] | "  - \(.name) (\(.ip))"' "$import_file" 2>/dev/null
    echo ""
    echo "导入模式:
  1. 完整导入 (保留原始密钥，适用于服务器迁移/endpoint 不变)
  2. 重新生成密钥 (适用于新服务器，需重新下发客户端配置)
  0. 返回
"
    read -e -r -p "选择: " mode
    [[ "$mode" == "0" || -z "$mode" ]] && return
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return 1; }

    local db_snapshot client_backup
    db_snapshot=$(_wg_deb_snapshot_db) || { print_error "读取 WireGuard 数据库快照失败"; pause; return 1; }
    client_backup=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-deb-import-clients.XXXXXX") || {
        print_error "创建客户端配置快照目录失败"; pause; return 1;
    }
    chmod 700 "$client_backup" 2>/dev/null || true
    if ! _wg_deb_import_snapshot_clients "$client_backup/clients"; then
        rm -rf "$client_backup" 2>/dev/null || true
        print_error "备份客户端配置失败"; pause; return 1
    fi

    local existing_count
    existing_count=$(wg_deb_db_get '.peers | length')
    local merge_mode="1"
    if [[ "$existing_count" -gt 0 ]]; then
        print_warn "当前已有 $existing_count 个设备。"
        echo "  1. 追加 (跳过同名/同IP设备)
  2. 覆盖 (删除所有现有设备后导入)"
        read -e -r -p "选择 [1]: " merge_mode
        merge_mode=${merge_mode:-1}
        if [[ "$merge_mode" == "2" ]]; then
            if ! confirm "确认删除所有现有设备?"; then
                rm -rf "$client_backup" 2>/dev/null || true
                return
            fi
            if ! wg_deb_db_set '.peers = []'; then
                _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
                rm -rf "$client_backup" 2>/dev/null || true
                print_error "清空现有设备失败，已恢复原配置"
                pause; return 1
            fi
            rm -f "${WG_DEB_CLIENT_DIR}"/*.conf 2>/dev/null
        fi
    fi

    local imported=0 skipped=0
    local i=0
    while [[ $i -lt $import_count ]]; do
        local name ip privkey pubkey psk allowed enabled is_gw lans created peer_type route_mode
        name=$(jq -r ".peers[$i].name" "$import_file")
        ip=$(jq -r ".peers[$i].ip" "$import_file")
        privkey=$(jq -r ".peers[$i].private_key" "$import_file")
        pubkey=$(jq -r ".peers[$i].public_key" "$import_file")
        psk=$(jq -r ".peers[$i].preshared_key" "$import_file")
        allowed=$(jq -r ".peers[$i].client_allowed_ips" "$import_file")
        enabled=$(jq -r ".peers[$i].enabled // true" "$import_file")
        is_gw=$(jq -r ".peers[$i].is_gateway // false" "$import_file")
        lans=$(jq -r ".peers[$i].lan_subnets // empty" "$import_file")
        created=$(jq -r ".peers[$i].created // empty" "$import_file")
        peer_type=$(jq -r ".peers[$i].peer_type // empty" "$import_file")
        route_mode=$(jq -r ".peers[$i].route_mode // empty" "$import_file")
        if [[ -z "$peer_type" || "$peer_type" == "null" ]]; then
            [[ "$is_gw" == "true" ]] && peer_type="gateway" || peer_type="standard"
        fi
        [[ -z "$route_mode" || "$route_mode" == "null" ]] && route_mode="managed"
        [[ "$enabled" == "true" || "$enabled" == "false" ]] || enabled=true
        [[ "$is_gw" == "true" || "$is_gw" == "false" ]] || is_gw=false

        if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
            print_warn "跳过: $name (名称格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_ip "$ip"; then
            print_warn "跳过: $name (IP 格式无效: $ip)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if [[ -z "$allowed" || "$allowed" == "null" ]] || ! validate_cidr_list "$allowed"; then
            print_warn "跳过: $name (AllowedIPs 格式无效: $allowed)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_cidr_list "$lans"; then
            print_warn "跳过: $name (LAN 网段格式无效: $lans)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        case "$peer_type" in
            standard|gateway) ;;
            *) print_warn "跳过: $name (设备类型无效: $peer_type)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac
        case "$route_mode" in
            managed|custom|full|vpn) ;;
            *) print_warn "跳过: $name (路由模式无效: $route_mode)"; skipped=$((skipped + 1)); i=$((i + 1)); continue ;;
        esac

        # 检查重名
        local exists
        exists=$(wg_deb_db_get --arg n "$name" '.peers[] | select(.name == $n) | .name')
        if [[ -n "$exists" ]]; then
            print_warn "跳过: $name (名称已存在)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        # 检查 IP 冲突
        local ip_exists
        ip_exists=$(wg_deb_db_get --arg ip "$ip" '.peers[] | select(.ip == $ip) | .ip')
        if [[ -n "$ip_exists" ]]; then
            print_warn "跳过: $name (IP $ip 已被使用)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        if [[ "$mode" == "2" ]]; then
            privkey=$(wg genkey)
            pubkey=$(echo "$privkey" | wg pubkey)
            psk=$(wg genpsk)
        fi
        if ! validate_wg_key "$privkey"; then
            print_warn "跳过: $name (私钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$pubkey"; then
            print_warn "跳过: $name (公钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        if ! validate_wg_key "$psk"; then
            print_warn "跳过: $name (预共享密钥格式无效)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        [[ -z "$created" || "$created" == "null" ]] && created=$(date '+%Y-%m-%d %H:%M:%S')

        if ! wg_deb_db_set --arg name "$name" \
                  --arg ip "$ip" \
                  --arg privkey "$privkey" \
                  --arg pubkey "$pubkey" \
                  --arg psk "$psk" \
                  --arg allowed "$allowed" \
                  --argjson enabled "$enabled" \
                  --arg created "$created" \
                  --arg gw "$is_gw" \
                  --arg lans "$lans" \
                  --arg ptype "$peer_type" \
                  --arg route_mode "$route_mode" \
            '.peers += [{
                name: $name,
                ip: $ip,
                private_key: $privkey,
                public_key: $pubkey,
                preshared_key: $psk,
                client_allowed_ips: $allowed,
                enabled: $enabled,
                created: $created,
                is_gateway: ($gw == "true"),
                lan_subnets: $lans,
                peer_type: $ptype,
                route_mode: $route_mode
            }]'; then
            _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "导入 $name 时数据库写入失败，已恢复原配置"
            pause; return 1
        fi
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        if ! wg_deb_apply_conf; then
            _wg_deb_import_restore_snapshot "$db_snapshot" "$client_backup/clients"
            rm -rf "$client_backup" 2>/dev/null || true
            print_error "WireGuard 运行配置热应用失败，已恢复原配置"
            pause; return 1
        fi
    fi
    rm -rf "$client_backup" 2>/dev/null || true
    echo ""
    print_success "导入完成: 成功 ${imported}, 跳过 ${skipped}"
    [[ "$mode" == "2" ]] && print_warn "已重新生成密钥，请重新下发所有客户端配置。"
    log_action "WireGuard(deb) peers imported: imported=$imported skipped=$skipped mode=$mode"
    pause
}

wg_deb_server_menu() {
    while true; do
        print_title "WireGuard 服务端管理 (Debian/Ubuntu)"
        local srv_name=$(wg_deb_get_server_name)
        if wg_deb_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        fi
        local peer_count=$(wg_deb_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"
        echo "  [设备管理]
  1. 查看状态
  2. 添加设备
  3. 删除设备
  4. 启用/禁用设备
  5. 查看设备配置/二维码
  6. 生成 Clash/OpenClash 配置
  [服务控制]
  7. 启动 WireGuard
  8. 停止 WireGuard
  9. 重启 WireGuard
  10. 修改服务端配置
  11. 修改服务器名称
  12. 卸载 WireGuard
  13. 服务端看门狗 (自动重启保活)
  [数据管理]
  14. 导出设备配置 (JSON)
  15. 导入设备配置 (JSON)
  0. 返回上级菜单
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice
        case $choice in
            1) wg_deb_server_status ;;
            2) wg_deb_add_peer ;;
            3) wg_deb_delete_peer ;;
            4) wg_deb_toggle_peer ;;
            5) wg_deb_show_peer_conf ;;
            6) wg_deb_generate_clash_config ;;
            7) wg_deb_start; pause ;;
            8) wg_deb_stop; pause ;;
            9) wg_deb_restart; pause ;;
            10) wg_deb_modify_server ;;
            11) wg_deb_rename_server ;;
            12) wg_deb_uninstall; return ;;
            13) wg_deb_setup_watchdog ;;
            14) wg_deb_export_peers ;;
            15) wg_deb_import_peers ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_deb_install_menu() {
    wg_deb_server_install
}

wg_deb_main_menu() {
    while true; do
        if wg_deb_is_installed; then
            local role
            role=$(wg_deb_get_role)
            local server_private_key=""
            server_private_key=$(wg_deb_db_get '.server.private_key // empty')
            if [[ "$role" == "server" ]] || { [[ "$role" == "none" || -z "$role" ]] && [[ -f "$WG_DEB_CONF" ]] && [[ -n "$server_private_key" && "$server_private_key" != "null" ]]; }; then
                [[ "$role" == "server" ]] || wg_deb_set_role "server"
                print_title "WireGuard VPN"
                local srv_name
                srv_name=$(wg_deb_get_server_name)
                if wg_deb_is_running; then
                    echo -e "  状态: ${C_GREEN}运行中${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                else
                    echo -e "  状态: ${C_RED}已停止${C_RESET}    接口: ${C_CYAN}${WG_DEB_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
                fi
                echo ""
                echo "1. 服务端管理"
                echo "2. 卸载 WireGuard"
                echo "0. 返回主菜单"
                read -e -r -p "选择: " c
                case "$c" in
                    1) wg_deb_server_menu ;;
                    2) wg_deb_uninstall ;;
                    0|q|Q|"") return ;;
                    *) print_warn "无效选项"; pause ;;
                esac
            else
                print_warn "WireGuard 已安装但无配置文件"
                echo "  1. 重新安装服务端
  2. 卸载
  0. 返回"
                read -e -r -p "选择: " rc
                case $rc in
                    1) wg_deb_server_install; continue ;;
                    2) wg_deb_uninstall; continue ;;
                    *) return ;;
                esac
            fi
        else
            print_title "WireGuard VPN"
            echo -e "  状态: ${C_YELLOW}未安装${C_RESET}"
            echo ""
            echo "1. 安装 WireGuard 服务端"
            echo "0. 返回主菜单"
            read -e -r -p "选择: " c
            case "$c" in
                1) wg_deb_server_install ;;
                0|q|Q|"") return ;;
                *) print_warn "无效选项"; pause ;;
            esac
        fi
    done
}
