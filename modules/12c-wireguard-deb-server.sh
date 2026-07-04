# modules/12c-wireguard-deb-server.sh - Debian/Ubuntu WireGuard 服务端安装/控制/卸载
_wg_deb_ufw_has_udp_allow() {
    local port="${1:-}"
    validate_port "$port" || return 1
    command_exists ufw || return 1
    LANG=C ufw show added 2>/dev/null | awk -v rule="${port}/udp" '
        $1 == "ufw" && $2 == "allow" && $3 == rule { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_wg_deb_rollback_new_udp_allow() {
    local port="${1:-}" added="${2:-false}" non_ufw_backends="${3:-}"
    validate_port "$port" || return 0
    if [[ "$added" == "true" ]] && command_exists ufw && ufw_is_active; then
        ufw delete allow "$port"/udp >/dev/null 2>&1 || true
    fi
    if [[ -n "$non_ufw_backends" ]] && declare -F firewall_rollback_udp_port >/dev/null; then
        firewall_rollback_udp_port "$port" "$non_ufw_backends" "WireGuard-Debian"
    fi
}

_wg_deb_rollback_server_port_change() {
    local cur_port="${1:-}" new_port="${2:-}" added="${3:-false}" rebuild="${4:-false}" non_ufw_backends="${5:-}"
    if validate_port "$cur_port"; then
        if ! wg_deb_db_set --argjson p "$cur_port" '.server.port = $p' >/dev/null 2>&1; then
            print_warn "端口回滚写入数据库失败，请手动检查 WireGuard 配置。"
        elif [[ "$rebuild" == "true" ]]; then
            wg_deb_rebuild_conf >/dev/null 2>&1 || print_warn "端口回滚后重建服务端配置失败，请手动检查。"
            wg_deb_regenerate_client_confs >/dev/null 2>&1 || print_warn "端口回滚后重建客户端配置失败，请手动检查。"
        fi
    fi
    _wg_deb_rollback_new_udp_allow "$new_port" "$added" "$non_ufw_backends"
}

_wg_deb_rollback_server_modify() {
    local snapshot="${1:-}" cur_port="${2:-}" new_port="${3:-}" added="${4:-false}" rebuild="${5:-false}" non_ufw_backends="${6:-}"
    if [[ -n "$snapshot" ]]; then
        if ! wg_write_private_file "$WG_DEB_DB_FILE" "$snapshot" >/dev/null 2>&1; then
            print_warn "服务端配置回滚写入数据库失败，请手动检查 WireGuard 配置。"
        elif [[ "$rebuild" == "true" ]]; then
            wg_deb_rebuild_conf >/dev/null 2>&1 || print_warn "服务端配置回滚后重建服务端配置失败，请手动检查。"
            wg_deb_regenerate_client_confs >/dev/null 2>&1 || print_warn "服务端配置回滚后重建客户端配置失败，请手动检查。"
        fi
    else
        _wg_deb_rollback_server_port_change "$cur_port" "$new_port" "$added" "$rebuild" "$non_ufw_backends"
        return
    fi
    _wg_deb_rollback_new_udp_allow "$new_port" "$added" "$non_ufw_backends"
}

_wg_deb_rollback_server_install() {
    local wg_port="${1:-}" wg_udp_rule_added="${2:-false}" snapshot_dir="${3:-}"
    local db_existed="${4:-false}" role_existed="${5:-false}" conf_existed="${6:-false}"
    local non_ufw_backends="${7:-}"

    systemctl stop "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1 || true
    systemctl disable "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1 || true

    if [[ "$db_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/db" ]]; then
        mkdir -p "$(dirname "$WG_DEB_DB_FILE")" 2>/dev/null || true
        cp -p "${snapshot_dir}/db" "$WG_DEB_DB_FILE" 2>/dev/null || print_warn "恢复 WireGuard 数据库失败，请手动检查。"
    else
        rm -f "$WG_DEB_DB_FILE" 2>/dev/null || print_warn "删除新建 WireGuard 数据库失败，请手动检查。"
    fi

    if [[ "$role_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/role" ]]; then
        mkdir -p "$(dirname "$WG_DEB_ROLE_FILE")" 2>/dev/null || true
        cp -p "${snapshot_dir}/role" "$WG_DEB_ROLE_FILE" 2>/dev/null || print_warn "恢复 WireGuard 角色文件失败，请手动检查。"
    else
        rm -f "$WG_DEB_ROLE_FILE" 2>/dev/null || print_warn "删除新建 WireGuard 角色文件失败，请手动检查。"
    fi

    if [[ "$conf_existed" == "true" && -n "$snapshot_dir" && -f "${snapshot_dir}/conf" ]]; then
        mkdir -p "$(dirname "$WG_DEB_CONF")" 2>/dev/null || true
        cp -p "${snapshot_dir}/conf" "$WG_DEB_CONF" 2>/dev/null || print_warn "恢复 WireGuard 配置文件失败，请手动检查。"
    else
        rm -f "$WG_DEB_CONF" 2>/dev/null || print_warn "删除新建 WireGuard 配置文件失败，请手动检查。"
    fi

    _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$non_ufw_backends"
}

wg_deb_server_install() {
    print_title "安装 WireGuard 服务端 (Debian/Ubuntu)"
    if wg_deb_is_installed && [[ "$(wg_deb_get_role)" == "server" ]]; then
        print_warn "WireGuard 服务端已安装。"
        wg_deb_is_running && echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}" || echo -e "  状态: ${C_RED}● 已停止${C_RESET}"
        pause; return 0
    fi

    # ── [1/7] 环境检测 ──
    print_info "[1/7] Debian/Ubuntu 环境检测..."
    wg_deb_check_compat || { pause; return 1; }

    # ── [2/7] 安装软件包 ──
    print_info "[2/7] 安装软件包..."
    wg_deb_install_packages || { pause; return 1; }

    # ── [3/7] 配置 IP 转发 ──
    print_info "[3/7] 配置 IP 转发..."
    _sysctl_enable_wireguard_forward || { print_error "IP 转发配置失败"; pause; return 1; }
    print_success "IP 转发已开启"

    # ── [4/7] 配置服务端参数 ──
    print_info "[4/7] 配置服务端参数..."

    local wg_port listen_addr mtu wg_dns wg_endpoint=""
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
    read -e -r -p "客户端 DNS [8.8.8.8, 1.1.1.1]: " wg_dns
    wg_dns=${wg_dns:-"8.8.8.8, 1.1.1.1"}

    # 服务端 LAN 子网 (自动检测)
    local server_lan_subnet=""
    local def_iface
    def_iface=$(wg_deb_detect_default_iface)
    if [[ -n "$def_iface" ]]; then
        local lan_addr
        lan_addr=$(ip -4 addr show "$def_iface" 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
        if [[ -n "$lan_addr" ]]; then
            local lan_ip lan_mask lan_prefix
            lan_ip=$(echo "$lan_addr" | cut -d'/' -f1)
            lan_mask=$(echo "$lan_addr" | cut -d'/' -f2)
            lan_prefix=$(echo "$lan_ip" | cut -d'.' -f1-3)
            local default_lan="${lan_prefix}.0/${lan_mask}"
            # 只有内网 IP 才提示 LAN 子网映射
            if _wg_is_private_ip "$lan_ip"; then
                echo -e "  检测到 ${def_iface} 网段: ${C_CYAN}${default_lan}${C_RESET}"
                read -e -r -p "服务端 LAN 子网 (映射到 WG 网络) [${default_lan}]: " server_lan_subnet
                server_lan_subnet=${server_lan_subnet:-$default_lan}
            fi
        fi
    fi
    if [[ -z "$server_lan_subnet" ]]; then
        read -e -r -p "服务端 LAN 子网 (留空跳过，VPS 一般不需要): " server_lan_subnet
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
    if ! wg_endpoint=$(wg_shared_normalize_endpoint_host "$wg_endpoint"); then
        print_error "公网端点无效，仅支持 IP 或域名"
        pause; return 1
    fi

    print_info "预检 WireGuard UDP 端口..."
    local wg_udp_rule_added=false
    local wg_non_ufw_open_backends=""
    local fw_rc=0 had_wg_udp_rule=false
    _wg_deb_ufw_has_udp_allow "$wg_port" && had_wg_udp_rule=true
    firewall_allow_udp_port "$wg_port" "WireGuard-Debian"
    fw_rc=$?
    case "$fw_rc" in
        0)
            if [[ "$had_wg_udp_rule" != "true" ]] && _wg_deb_ufw_has_udp_allow "$wg_port"; then
                wg_udp_rule_added=true
            fi
            print_info "已预先放行 ${wg_port}/udp"
            ;;
        2)
            if declare -F firewall_prepare_non_ufw_udp_port >/dev/null; then
                if ! firewall_prepare_non_ufw_udp_port "$wg_port" "WireGuard-Debian"; then
                    print_error "本机防火墙未放行 WireGuard UDP 端口，已中止安装"
                    pause; return 1
                fi
                wg_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"
                [[ -n "$wg_non_ufw_open_backends" ]] && print_info "已通过非 UFW 本地防火墙放行 ${wg_port}/udp"
            fi
            print_warn "请确认云安全组或上游防火墙已放行 ${wg_port}/udp"
            ;;
        *)
            print_error "放行 WireGuard UDP 端口失败，已中止安装"
            pause; return 1
            ;;
    esac

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

    # 检测默认出口网卡
    [[ -z "$def_iface" ]] && def_iface="eth0"

    # ── [6/7] 写入数据库 + 生成配置 ──
    print_info "[6/7] 写入配置..."
    local wg_install_snapshot_dir=""
    local wg_db_existed=false wg_role_existed=false wg_conf_existed=false
    wg_install_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-deb-install.XXXXXX") || {
        print_error "创建安装回滚快照失败，已中止安装"
        _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
        pause; return 1
    }
    if [[ -f "$WG_DEB_DB_FILE" ]]; then
        wg_db_existed=true
        cp -p "$WG_DEB_DB_FILE" "${wg_install_snapshot_dir}/db" || {
            print_error "备份 WireGuard 数据库失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi
    if [[ -f "$WG_DEB_ROLE_FILE" ]]; then
        wg_role_existed=true
        cp -p "$WG_DEB_ROLE_FILE" "${wg_install_snapshot_dir}/role" || {
            print_error "备份 WireGuard 角色文件失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi
    if [[ -f "$WG_DEB_CONF" ]]; then
        wg_conf_existed=true
        cp -p "$WG_DEB_CONF" "${wg_install_snapshot_dir}/conf" || {
            print_error "备份 WireGuard 配置文件失败，已中止安装"
            rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
            _wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"
            pause; return 1
        }
    fi

    if ! wg_deb_db_init; then
        print_error "初始化数据库失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_deb_db_set --arg sname "$server_name" \
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
              --arg iface "$def_iface" \
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
        server_lan_subnet: $lan,
        default_iface: $iface
    } | .schema_version = 2'; then
        print_error "数据库写入失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_deb_set_role "server"; then
        print_error "角色写入失败，已中止安装"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # 生成 wg0.conf
    if ! wg_deb_rebuild_conf; then
        print_error "生成 WireGuard 服务端配置失败"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [7/7] 启动服务 ──
    print_info "[7/7] 启动 WireGuard..."
    if ! systemctl enable "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1; then
        print_error "启用 WireGuard 服务失败，请检查 systemd 状态"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! systemctl start "wg-quick@${WG_DEB_INTERFACE}" >/dev/null 2>&1; then
        print_error "启动 WireGuard 服务失败，请检查 journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    sleep 2
    if ! wg_deb_is_running; then
        print_error "WireGuard 启动后未运行，请检查 journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true

    # ── 安装结果展示 ──
    draw_line
    print_success "WireGuard 服务端安装并启动成功！"
    echo -e "  角色:       ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听地址:   ${C_GREEN}${listen_addr}:${wg_port}/udp${C_RESET}"
    echo -e "  MTU:        ${C_GREEN}${mtu}${C_RESET}"
    echo -e "  内网子网:   ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP:  ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  出口网卡:   ${C_GREEN}${def_iface}${C_RESET}"
    [[ -n "$server_lan_subnet" ]] && echo -e "  服务端 LAN: ${C_GREEN}${server_lan_subnet}${C_RESET}"
    if [[ -n "${ddns_domain:-}" ]]; then
        echo -e "  公网端点:   ${C_GREEN}${ddns_domain}:${wg_port}${C_RESET} (DDNS)"
    else
        echo -e "  公网端点:   ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    fi
    draw_line

    log_action "WireGuard(deb) server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint mtu=$mtu iface=$def_iface lan=${server_lan_subnet:-none}"

    # 自动安装服务端看门狗
    echo ""
    wg_deb_setup_watchdog "true" || print_warn "WireGuard 看门狗安装失败，服务端已安装并运行，请稍后手动配置。"

    pause
}

wg_deb_modify_server() {
    wg_deb_check_server || return 1
    print_title "修改 WireGuard 服务端配置"
    local cur_port cur_dns cur_ep cur_lan cur_iface cur_subnet
    cur_port=$(wg_deb_db_get '.server.port')
    cur_dns=$(wg_deb_db_get '.server.dns')
    cur_ep=$(wg_deb_db_get '.server.endpoint')
    cur_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    cur_iface=$(wg_deb_db_get '.server.default_iface // empty')
    cur_subnet=$(wg_deb_db_get '.server.subnet')
    [[ -z "$cur_iface" || "$cur_iface" == "null" ]] && cur_iface=$(wg_deb_detect_default_iface)
    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
    echo -e "  出口网卡:   ${C_GREEN}${cur_iface}${C_RESET}"
    [[ -n "$cur_lan" && "$cur_lan" != "null" ]] && echo -e "  当前 LAN:   ${C_GREEN}${cur_lan}${C_RESET}"
    local changed=false lan_changed=false iface_changed=false port_changed=false
    local new_udp_rule_added=false
    local new_non_ufw_open_backends=""
    local server_snapshot=""
    [[ -f "$WG_DEB_DB_FILE" ]] && server_snapshot=$(cat "$WG_DEB_DB_FILE" 2>/dev/null || true)

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            local fw_rc=0 had_new_udp_rule=false
            _wg_deb_ufw_has_udp_allow "$new_port" && had_new_udp_rule=true
            firewall_allow_udp_port "$new_port" "WireGuard-Debian"
            fw_rc=$?
            case "$fw_rc" in
                0)
                    if [[ "$had_new_udp_rule" != "true" ]] && _wg_deb_ufw_has_udp_allow "$new_port"; then
                        new_udp_rule_added=true
                    fi
                    print_info "已预先放行新端口 ${new_port}/udp"
                    ;;
                2)
                    if declare -F firewall_prepare_non_ufw_udp_port >/dev/null; then
                        if ! firewall_prepare_non_ufw_udp_port "$new_port" "WireGuard-Debian"; then
                            print_error "本机防火墙未放行新 WireGuard UDP 端口，端口未修改"
                            pause; return 1
                        fi
                        new_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"
                        [[ -n "$new_non_ufw_open_backends" ]] && print_info "已通过非 UFW 本地防火墙放行新端口 ${new_port}/udp"
                    fi
                    print_warn "请确认云安全组或上游防火墙已放行 ${new_port}/udp"
                    ;;
                *)
                    print_error "放行新 WireGuard UDP 端口失败，端口未修改"
                    pause; return 1
                    ;;
            esac
            if ! wg_deb_db_set --argjson p "$new_port" '.server.port = $p'; then
                print_error "数据库写入失败，端口未修改"
                _wg_deb_rollback_new_udp_allow "$new_port" "$new_udp_rule_added" "$new_non_ufw_open_backends"
                pause; return 1
            fi
            changed=true
            port_changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
            new_port="$cur_port"
        fi
    fi

    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        if ! wg_deb_db_set --arg d "$new_dns" '.server.dns = $d'; then
            print_error "数据库写入失败，DNS 未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
            print_warn "端点无效，保持原值"
            new_ep="$cur_ep"
        else
        if ! wg_deb_db_set --arg e "$new_ep" '.server.endpoint = $e'; then
            print_error "数据库写入失败，端点未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        print_info "端点将更改为 ${new_ep}"
        fi
    fi

    read -e -r -p "新服务端 LAN 子网 [${cur_lan:-无}]: " new_lan
    new_lan=${new_lan:-$cur_lan}
    if [[ "$new_lan" != "$cur_lan" ]]; then
        if ! validate_cidr_list "$new_lan"; then
            print_warn "LAN 子网格式无效，保持原值"
            new_lan="$cur_lan"
        else
            if ! wg_deb_db_set --arg l "$new_lan" '.server.server_lan_subnet = $l'; then
                print_error "数据库写入失败，LAN 子网未修改"
                _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
                pause; return 1
            fi
            changed=true
            lan_changed=true
            print_info "LAN 子网将更改为 ${new_lan}"
        fi
    fi

    read -e -r -p "出口网卡 [${cur_iface}]: " new_iface
    new_iface=${new_iface:-$cur_iface}
    if [[ "$new_iface" != "$cur_iface" ]]; then
        if ! wg_deb_db_set --arg i "$new_iface" '.server.default_iface = $i'; then
            print_error "数据库写入失败，出口网卡未修改"
            _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
            pause; return 1
        fi
        changed=true
        iface_changed=true
        print_info "出口网卡将更改为 ${new_iface}"
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi

    if [[ "$lan_changed" == "true" ]] && ! _wg_deb_update_peer_routes; then
        print_error "联动更新客户端路由失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    if ! wg_deb_rebuild_conf; then
        print_error "重建服务端配置失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "false" "$new_non_ufw_open_backends"
        pause; return 1
    fi
    if ! wg_deb_regenerate_client_confs; then
        print_error "重建客户端配置失败"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    # 重启服务使配置生效
    if ! systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1; then
        print_error "WireGuard 重启失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi
    sleep 2
    if ! wg_deb_is_running; then
        print_error "WireGuard 重启后未运行，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        _wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added" "true" "$new_non_ufw_open_backends"
        pause; return 1
    fi

    # 新端口已放行且服务已切换后，再尽量清理旧端口规则。
    if [[ "$port_changed" == "true" ]] && ufw_is_active; then
        if ufw delete allow "$cur_port"/udp >/dev/null 2>&1; then
            print_info "已清理旧 UFW 端口 ${cur_port}/udp"
        else
            print_warn "旧 UFW 端口 ${cur_port}/udp 删除失败或规则不存在，请手动检查"
        fi
    fi
    [[ "$iface_changed" == "true" ]] && _wg_deb_cleanup_nat_iface "$cur_subnet" "$cur_iface"

    print_success "服务端配置已更新"
    log_action "WireGuard(deb) server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep} lan=${new_lan:-none} iface=${new_iface}"
    pause
}

wg_deb_server_status() {
    wg_deb_check_server || return 1
    print_title "WireGuard 服务端状态"
    local port subnet endpoint dns mtu server_lan def_iface
    port=$(wg_deb_db_get '.server.port')
    subnet=$(wg_deb_db_get '.server.subnet')
    endpoint=$(wg_deb_db_get '.server.endpoint')
    dns=$(wg_deb_db_get '.server.dns')
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    server_lan=$(wg_deb_db_get '.server.server_lan_subnet // empty')
    def_iface=$(wg_deb_db_get '.server.default_iface // empty')
    echo -e "  角色:     ${C_GREEN}服务端 (Server) [Debian]${C_RESET}"
    if wg_deb_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi
    echo -e "  端口:     ${port}/udp"
    [[ -n "$mtu" && "$mtu" != "null" ]] && echo -e "  MTU:      ${mtu}"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    [[ -n "$def_iface" && "$def_iface" != "null" ]] && echo -e "  出口网卡: ${C_CYAN}${def_iface}${C_RESET}"
    [[ -n "$server_lan" && "$server_lan" != "null" ]] && echo -e "  服务端 LAN: ${C_CYAN}${server_lan}${C_RESET}"
    local ddns_domain=$(wg_deb_db_get '.server.ddns_domain // empty')
    [[ -n "$ddns_domain" && "$ddns_domain" != "null" ]] && echo -e "  DDNS:     ${C_CYAN}${ddns_domain}${C_RESET}"

    # systemd 服务状态
    echo ""
    local svc_status
    svc_status=$(systemctl is-active wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || echo "unknown")
    local svc_enabled
    svc_enabled=$(systemctl is-enabled wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || echo "unknown")
    echo -e "  systemd:  active=${C_CYAN}${svc_status}${C_RESET}  enabled=${C_CYAN}${svc_enabled}${C_RESET}"

    echo ""
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line
    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "类型" "状态" "最近握手" "流量"
        draw_line
        local wg_dump=""
        wg_deb_is_running && wg_dump=$(wg show "$WG_DEB_INTERFACE" dump 2>/dev/null | tail -n +2)
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
                    transfer_str="↓$(wg_deb_format_bytes "$rx") ↑$(wg_deb_format_bytes "$tx")"
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

wg_deb_start() {
    if wg_deb_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi
    print_info "正在启动 WireGuard..."
    systemctl start wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
    if wg_deb_is_running; then
        print_success "WireGuard 已启动"
        log_action "WireGuard(deb) started"
        return 0
    else
        print_error "启动失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) start failed"
        return 1
    fi
}

wg_deb_stop() {
    if ! wg_deb_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi
    print_info "正在停止 WireGuard..."
    systemctl stop wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 1
    if ! wg_deb_is_running; then
        print_success "WireGuard 已停止"
        log_action "WireGuard(deb) stopped"
        return 0
    else
        print_error "停止失败"
        log_action "WireGuard(deb) stop failed"
        return 1
    fi
}

wg_deb_restart() {
    print_info "正在重启 WireGuard..."
    systemctl restart wg-quick@${WG_DEB_INTERFACE} >/dev/null 2>&1
    sleep 2
    if wg_deb_is_running; then
        print_success "WireGuard 已重启"
        log_action "WireGuard(deb) restarted"
        return 0
    else
        print_error "重启失败，请检查: journalctl -u wg-quick@${WG_DEB_INTERFACE} -n 20"
        log_action "WireGuard(deb) restart failed"
        return 1
    fi
}

# ── 卸载 ──

wg_deb_uninstall() {
    print_title "卸载 WireGuard"
    if ! wg_deb_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return 0
    fi
    local role
    role=$(wg_deb_get_role)
    echo -e "  当前角色: ${C_GREEN}${role:-未知}${C_RESET}"
    print_warn "此操作将完全卸载 WireGuard，包括所有配置和密钥！"
    if ! confirm "确认卸载 WireGuard?"; then
        return
    fi
    if ! confirm "再次确认: 所有配置将被永久删除，是否继续?"; then
        return
    fi

    print_info "[1/5] 停止 WireGuard 服务..."
    systemctl stop wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || true
    systemctl disable wg-quick@${WG_DEB_INTERFACE} 2>/dev/null || true
    # 确保接口已删除
    ip link set "$WG_DEB_INTERFACE" down 2>/dev/null || true
    ip link delete "$WG_DEB_INTERFACE" 2>/dev/null || true

    print_info "[2/5] 清理防火墙规则..."
    if ufw_is_active; then
        local wg_port
        wg_port=$(wg_deb_db_get '.server.port' 2>/dev/null)
        [[ -n "$wg_port" && "$wg_port" != "null" ]] && ufw delete allow "$wg_port"/udp >/dev/null 2>&1
    fi

    print_info "[3/5] 清理看门狗和定时任务..."
    cron_remove_job_command "/usr/local/bin/wg-watchdog.sh" 2>/dev/null || true
    rm -f /usr/local/bin/wg-watchdog.sh /var/log/wg-watchdog.log 2>/dev/null || true

    print_info "[4/5] 删除配置文件..."
    rm -f "$WG_DEB_CONF" 2>/dev/null || true
    rm -rf "$WG_DEB_CLIENT_DIR" 2>/dev/null || true
    rm -f "$WG_DEB_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DEB_DB_DIR" 2>/dev/null || true
    rm -f "$WG_DEB_ROLE_FILE" 2>/dev/null || true
    rm -f /etc/sysctl.d/99-wireguard.conf 2>/dev/null || true
    rmdir /etc/wireguard 2>/dev/null || true

    print_info "[5/5] 卸载软件包..."
    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        apt-get remove -y wireguard wireguard-tools 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
    fi

    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            _sysctl_disable_wireguard_forward || print_warn "恢复 IP 转发设置失败，请手动检查 /etc/sysctl.conf"
        fi
    fi

    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line
    log_action "WireGuard(deb) uninstalled: role=${role}"
    pause
}
