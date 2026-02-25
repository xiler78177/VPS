# modules/11g-wireguard-extra.sh - WireGuard watchdog/import-export/menus
wg_setup_watchdog() {
    wg_check_installed || return 1
    local watchdog_script="/usr/local/bin/wg-watchdog.sh"
    local watchdog_log="/var/log/wg-watchdog.log"

    # 已启用时的管理界面
    if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
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
                cron_remove_job "wg-watchdog.sh"
                rm -f "$watchdog_script"
                print_success "看门狗已禁用"
                log_action "WireGuard watchdog disabled"
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

    print_title "WireGuard 服务端看门狗"
    echo "看门狗功能:
  • 每分钟检测 wg0 接口状态
  • 接口消失 → 立即拉起
  • wg show 失败 → 重启接口"
    if ! confirm "启用看门狗?"; then pause; return; fi

    # ── OpenWrt 平台: 生成专用看门狗 (#!/bin/sh + ifup/ifdown) ──
    if [[ "$PLATFORM" == "openwrt" ]]; then
        cat > "$watchdog_script" << 'WDEOF_OPENWRT'
#!/bin/sh
LOG="logger -t wg-watchdog"

# 检测接口存活
if ! ifstatus wg0 &>/dev/null; then
    $LOG "wg0 down, restarting"
    ifup wg0
    exit 0
fi

# 检测 wg show 是否正常
if ! wg show wg0 &>/dev/null; then
    $LOG "wg show failed, restarting"
    ifdown wg0; sleep 1; ifup wg0
    exit 0
fi
WDEOF_OPENWRT
        chmod +x "$watchdog_script"
        cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
        echo ""
        print_success "看门狗已启用 (每分钟检测)"
        echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
        echo "  检测: 接口存活 → wg show"
        log_action "WireGuard watchdog enabled (platform=openwrt)"
        pause
        return 0
    fi

    # ── 标准 Linux 平台 ──
    cat > "$watchdog_script" << 'WDEOF_SERVER'
#!/bin/bash
LOG="/var/log/wg-watchdog.log"
WG_INTERFACE="wg0"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

if ! ip link show "$WG_INTERFACE" &>/dev/null; then
    log "WARN: $WG_INTERFACE missing, restarting..."
    wg-quick up "$WG_INTERFACE" 2>>"$LOG"
    sleep 2
    ip link show "$WG_INTERFACE" &>/dev/null && log "OK: recovered" || log "ERROR: restart failed"
    exit 0
fi

if ! wg show "$WG_INTERFACE" &>/dev/null; then
    log "WARN: wg show failed, restarting..."
    wg-quick down "$WG_INTERFACE" 2>>"$LOG"; sleep 1
    wg-quick up "$WG_INTERFACE" 2>>"$LOG"
    sleep 2
    wg show "$WG_INTERFACE" &>/dev/null && log "OK: recovered" || log "ERROR: restart failed"
    exit 0
fi

# 日志轮转
if [[ -f "$LOG" ]] && [[ $(wc -l < "$LOG") -gt 500 ]]; then
    tail -n 300 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
fi
WDEOF_SERVER
    chmod +x "$watchdog_script"
    cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
    echo "  检测: 接口存活 → wg show"
    log_action "WireGuard watchdog enabled (platform=linux)"
    pause
}

wg_export_peers() {
    wg_check_server || return 1
    print_title "导出 WireGuard 设备配置"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备可导出"
        pause; return
    fi
    local export_file
    export_file=$(mktemp "/tmp/${SCRIPT_NAME}-wg-peers-XXXXXX.json")
    chmod 600 "$export_file"
    if jq '{
        export_version: 1,
        export_date: (now | todate),
        server: {
            endpoint: .server.endpoint,
            port: .server.port,
            subnet: .server.subnet,
            dns: .server.dns,
            public_key: .server.public_key
        },
        peers: .peers
    }' "$WG_DB_FILE" > "$export_file" 2>/dev/null; then
        print_success "已导出 $peer_count 个设备到:"
        echo -e "  ${C_CYAN}${export_file}${C_RESET}"
        local fsize=$(du -h "$export_file" 2>/dev/null | awk '{print $1}')
        echo "  文件大小: $fsize"
        echo ""
        print_warn "该文件包含私钥等敏感信息，请妥善保管！"
        echo "可使用 [导入设备配置] 在其他服务器恢复。"
    else
        print_error "导出失败"
    fi
    log_action "WireGuard peers exported: count=$peer_count file=$export_file"
    pause
}

wg_import_peers() {
    wg_check_server || return 1
    print_title "导入 WireGuard 设备配置"
    read -e -r -p "导入文件路径 (JSON): " import_file
    [[ -z "$import_file" ]] && return
    if [[ ! -f "$import_file" ]]; then
        print_error "文件不存在: $import_file"
        pause; return
    fi
    if ! jq empty "$import_file" 2>/dev/null; then
        print_error "文件不是有效的 JSON 格式"
        pause; return
    fi
    local import_count
    import_count=$(jq '.peers | length' "$import_file" 2>/dev/null)
    if [[ -z "$import_count" || "$import_count" -eq 0 ]]; then
        print_warn "文件中无设备数据"
        pause; return
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
    [[ "$mode" != "1" && "$mode" != "2" ]] && { print_error "无效选项"; pause; return; }

    local existing_count
    existing_count=$(wg_db_get '.peers | length')
    local merge_mode="1"
    if [[ "$existing_count" -gt 0 ]]; then
        print_warn "当前已有 $existing_count 个设备。"
        echo "  1. 追加 (跳过同名/同IP设备)
  2. 覆盖 (删除所有现有设备后导入)"
        read -e -r -p "选择 [1]: " merge_mode
        merge_mode=${merge_mode:-1}
        if [[ "$merge_mode" == "2" ]]; then
            confirm "确认删除所有现有设备?" || return
            # 先从运行中的接口移除所有 peer
            if wg_is_running; then
                local pc=$(wg_db_get '.peers | length') pi=0
                while [[ $pi -lt $pc ]]; do
                    local pk=$(wg_db_get ".peers[$pi].public_key")
                    wg set "$WG_INTERFACE" peer "$pk" remove 2>/dev/null || true
                    pi=$((pi + 1))
                done
            fi
            wg_db_set '.peers = []'
            rm -f /etc/wireguard/clients/*.conf 2>/dev/null
        fi
    fi

    local imported=0 skipped=0
    local i=0
    while [[ $i -lt $import_count ]]; do
        local name ip privkey pubkey psk allowed enabled is_gw lans created
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

        # 检查重名
        local exists
        exists=$(wg_db_get --arg n "$name" '.peers[] | select(.name == $n) | .name')
        if [[ -n "$exists" ]]; then
            print_warn "跳过: $name (名称已存在)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi
        # 检查 IP 冲突
        local ip_exists
        ip_exists=$(wg_db_get --arg ip "$ip" '.peers[] | select(.ip == $ip) | .ip')
        if [[ -n "$ip_exists" ]]; then
            print_warn "跳过: $name (IP $ip 已被使用)"
            skipped=$((skipped + 1)); i=$((i + 1)); continue
        fi

        if [[ "$mode" == "2" ]]; then
            privkey=$(wg genkey)
            pubkey=$(echo "$privkey" | wg pubkey)
            psk=$(wg genpsk)
        fi

        [[ -z "$created" || "$created" == "null" ]] && created=$(date '+%Y-%m-%d %H:%M:%S')

        wg_db_set --arg name "$name" \
                  --arg ip "$ip" \
                  --arg privkey "$privkey" \
                  --arg pubkey "$pubkey" \
                  --arg psk "$psk" \
                  --arg allowed "$allowed" \
                  --argjson enabled "$enabled" \
                  --arg created "$created" \
                  --arg gw "$is_gw" \
                  --arg lans "$lans" \
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
                lan_subnets: $lans
            }]'
        imported=$((imported + 1))
        i=$((i + 1))
    done

    if [[ $imported -gt 0 ]]; then
        wg_rebuild_conf
        wg_regenerate_client_confs
        wg_is_running && wg_restart
    fi
    echo ""
    print_success "导入完成: 成功 ${imported}, 跳过 ${skipped}"
    [[ "$mode" == "2" ]] && print_warn "已重新生成密钥，请重新下发所有客户端配置。"
    log_action "WireGuard peers imported: imported=$imported skipped=$skipped mode=$mode"
    pause
}

wg_server_menu() {
    while true; do
        print_title "WireGuard 服务端管理"
        local srv_name=$(wg_get_server_name)
        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}    名称: ${C_CYAN}${srv_name}${C_RESET}"
        fi
        local peer_count=$(wg_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"
        echo "  ── 设备管理 ──────────────────
  1. 查看状态
  2. 添加设备
  3. 删除设备
  4. 启用/禁用设备
  5. 查看设备配置/二维码
  6. 生成 Clash/OpenClash 配置
  ── 服务控制 ──────────────────
  7. 启动 WireGuard
  8. 停止 WireGuard
  9. 重启 WireGuard
  10. 修改服务端配置
  11. 修改服务器名称
  12. 卸载 WireGuard
  13. 生成 OpenWrt 清空 WG 配置命令
  14. 服务端看门狗 (自动重启保活)
  ── 数据管理 ──────────────────
  15. 导出设备配置 (JSON)
  16. 导入设备配置 (JSON)
  0. 返回上级菜单
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice
        case $choice in
            1) wg_server_status ;;
            2) wg_add_peer ;;
            3) wg_delete_peer ;;
            4) wg_toggle_peer ;;
            5) wg_show_peer_conf ;;
            6) wg_generate_clash_config ;;
            7) wg_start; pause ;;
            8) wg_stop; pause ;;
            9) wg_restart; pause ;;
            10) wg_modify_server ;;
            11) wg_rename_server ;;
            12) wg_uninstall; return ;;
            13) wg_openwrt_clean_cmd ;;
            14) wg_setup_watchdog ;;
            15) wg_export_peers ;;
            16) wg_import_peers ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}


wg_install_menu() {
    wg_server_install
}

wg_main_menu() {
    while true; do
        if wg_is_installed; then
            local role
            role=$(wg_get_role)
            if [[ "$role" == "server" ]]; then
                wg_server_menu; return
            elif [[ -f "$WG_CONF" ]]; then
                wg_set_role "server"; continue
            else
                print_warn "WireGuard 已安装但无配置文件"
                echo "  1. 重新安装服务端
  2. 卸载
  0. 返回"
                read -e -r -p "选择: " rc
                case $rc in
                    1) wg_server_install; continue ;;
                    2) wg_uninstall; continue ;;
                    *) return ;;
                esac
            fi
        else
            wg_server_install
            wg_is_installed || return
        fi
    done
}

