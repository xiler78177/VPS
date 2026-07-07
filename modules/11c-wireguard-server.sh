# modules/11c-wireguard-server.sh - WireGuard server install/control/uninstall (OpenWrt)
_wg_openwrt_rc_local_path() {
    printf '%s' "${WG_OPENWRT_RC_LOCAL_FILE:-/etc/rc.local}"
}

_wg_openwrt_delete_allow_port_rules() {
    local h
    for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
}

_wg_openwrt_delete_allow_port_rules_matching() {
    local want="${1:-}" mode="${2:-match}" h
    validate_port "$want" || return 1
    for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | awk -v want="$want" -v mode="$mode" '
        /wg_allow_port/ {
            dport = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "dport") dport = $(i + 1)
            }
            if ((mode == "match" && dport == want) || (mode == "except" && dport != want)) print $NF
        }
    '); do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
}

_wg_openwrt_list_wireguard_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\/none/ && current != "" {
            print current
            current=""
        }
    '
}

_wg_openwrt_allow_port_handles() {
    local want="${1:-}"
    validate_port "$want" || return 1
    nft -a list chain inet fw4 input_wan 2>/dev/null | awk -v want="$want" '
        /wg_allow_port/ {
            dport = ""
            for (i = 1; i <= NF; i++) {
                if ($i == "dport") dport = $(i + 1)
            }
            if (dport == want) print $NF
        }
    '
}

_wg_openwrt_persist_allow_port() {
    local port="${1:-}"
    validate_port "$port" || { print_error "WireGuard UDP 端口无效: $port"; return 1; }
    local snapshot_dir snapshot
    snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-fw.XXXXXX") || {
        print_error "创建 OpenWrt firewall UCI 快照目录失败"
        return 1
    }
    chmod 700 "$snapshot_dir" 2>/dev/null || true
    snapshot="${snapshot_dir}/firewall.uci"
    if ! uci export firewall > "$snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    if ! _wg_openwrt_write_allow_port_uci "$port"; then
        print_error "OpenWrt 防火墙持久化放行 ${port}/udp 失败"
        _wg_openwrt_restore_uci_package firewall "$snapshot" || true
        rm -rf "$snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$snapshot_dir" 2>/dev/null || true
}

_wg_openwrt_write_allow_port_uci() {
    local port="${1:-}"
    validate_port "$port" || return 1
    uci set firewall.wg_allow_port=rule || return 1
    uci set firewall.wg_allow_port.name='Allow-WG-UDP' || return 1
    uci set firewall.wg_allow_port.src='wan' || return 1
    uci set firewall.wg_allow_port.dest_port="$port" || return 1
    uci set firewall.wg_allow_port.proto='udp' || return 1
    uci set firewall.wg_allow_port.target='ACCEPT' || return 1
    uci commit firewall || return 1
}

_wg_openwrt_write_allow_port_rc_local() {
    local port="${1:-}" rc_block rc_file
    validate_port "$port" || return 1
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_rc_local_cleanup_managed_entries allow-port "$rc_file" || return 1
    rc_block="# BEGIN server-manage wireguard allow-port\nnft insert rule inet fw4 input_wan udp dport ${port} counter accept comment \\\"wg_allow_port\\\" 2>/dev/null || true # wg_allow_port\n# END server-manage wireguard allow-port"
    _wg_rc_local_insert_block "$rc_block" "$rc_file"
}

_wg_openwrt_apply_allow_port() {
    local port="${1:-}" before_handles after_handles h
    validate_port "$port" || { print_error "WireGuard UDP 端口无效: $port"; return 1; }
    if ! nft list chain inet fw4 input_wan >/dev/null 2>&1; then
        print_error "OpenWrt fw4 input_wan 链不存在，无法实时放行 ${port}/udp"
        return 1
    fi
    before_handles=$(_wg_openwrt_allow_port_handles "$port" 2>/dev/null || true)
    if ! nft insert rule inet fw4 input_wan udp dport "$port" counter accept comment "wg_allow_port" 2>/dev/null; then
        print_error "OpenWrt nft 实时放行 ${port}/udp 失败"
        return 1
    fi
    if ! _wg_openwrt_persist_allow_port "$port"; then
        after_handles=$(_wg_openwrt_allow_port_handles "$port" 2>/dev/null || true)
        for h in $after_handles; do
            printf '%s\n' "$before_handles" | grep -Fxq -- "$h" || nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
        done
        return 1
    fi
    for h in $before_handles; do
        nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null || true
    done
    _wg_openwrt_delete_allow_port_rules_matching "$port" except
    _wg_openwrt_write_allow_port_rc_local "$port" || print_warn "写入 /etc/rc.local 端口放行规则失败"
    return 0
}

_wg_openwrt_rollback_server_modify() {
    local old_port="${1:-}" old_dns="${2:-}" old_ep="${3:-}" old_lan="${4:-}" port_firewall_changed="${5:-false}"
    validate_port "$old_port" || return 1
    if [[ "$port_firewall_changed" == "true" ]]; then
        _wg_openwrt_apply_allow_port "$old_port" >/dev/null 2>&1 || print_warn "回滚 OpenWrt 防火墙端口到 ${old_port}/udp 失败，请手动检查"
    fi
    if ! wg_db_set --argjson p "$old_port" \
                  --arg d "$old_dns" \
                  --arg e "$old_ep" \
                  --arg l "${old_lan:-}" \
                  '.server.port = $p | .server.dns = $d | .server.endpoint = $e | .server.server_lan_subnet = $l' >/dev/null 2>&1; then
        print_warn "回滚 WireGuard 服务端数据库失败，请手动检查"
        return 1
    fi
    _wg_update_peer_routes >/dev/null 2>&1 || true
    wg_rebuild_uci_conf >/dev/null 2>&1 || true
    wg_rebuild_conf >/dev/null 2>&1 || true
    wg_regenerate_client_confs >/dev/null 2>&1 || true
}

wg_update_server_endpoint_metadata() {
    wg_check_server || return 1
    local new_ep="${1:-}" new_ddns="${2:-}" old_ep old_ddns snapshot
    local clients_dir="/etc/wireguard/clients" clients_snapshot_dir="" clients_existed=false
    if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
        print_error "公网端点无效，仅支持 IP 或域名"
        return 1
    fi
    if [[ -n "$new_ddns" ]]; then
        if ! new_ddns=$(wg_shared_normalize_endpoint_host "$new_ddns"); then
            print_error "DDNS 域名无效"
            return 1
        fi
    fi

    old_ep=$(wg_db_get '.server.endpoint // empty')
    old_ddns=$(wg_db_get '.server.ddns_domain // empty')
    snapshot=$(cat "$WG_DB_FILE" 2>/dev/null) || {
        print_error "读取 WireGuard 数据库失败"
        return 1
    }
    clients_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-clients.XXXXXX") || {
        print_error "创建客户端配置快照目录失败"
        return 1
    }
    chmod 700 "$clients_snapshot_dir" 2>/dev/null || true
    if [[ -d "$clients_dir" ]]; then
        clients_existed=true
        cp -p "$clients_dir"/* "$clients_snapshot_dir"/ 2>/dev/null || true
    fi

    if ! wg_db_set --arg e "$new_ep" \
                  --arg d "${new_ddns:-}" \
                  '.server.endpoint = $e | .server.ddns_domain = $d'; then
        print_error "WireGuard 数据库写入失败"
        rm -rf "$clients_snapshot_dir" 2>/dev/null || true
        return 1
    fi

    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚 endpoint 元数据"
        wg_write_private_file "$WG_DB_FILE" "$snapshot" >/dev/null 2>&1 || print_warn "回滚 WireGuard 数据库失败，请手动检查"
        rm -rf "$clients_dir" 2>/dev/null || true
        if [[ "$clients_existed" == "true" ]]; then
            mkdir -p "$clients_dir" 2>/dev/null || true
            cp -p "$clients_snapshot_dir"/* "$clients_dir"/ 2>/dev/null || true
        fi
        rm -rf "$clients_snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$clients_snapshot_dir" 2>/dev/null || true

    log_action "WireGuard server endpoint metadata updated: ${old_ep:-none} -> ${new_ep} ddns=${new_ddns:-none}"
    [[ "${old_ep:-}" != "$new_ep" ]] && print_success "服务端 endpoint 元数据已更新: ${old_ep:-无} -> ${new_ep}"
    [[ "${old_ddns:-}" != "${new_ddns:-}" ]] && print_info "DDNS 元数据: ${old_ddns:-无} -> ${new_ddns:-无}"
    print_info "已重生成 /etc/wireguard/clients/*.conf，未重载服务端 wg0/UCI。"
    return 0
}

wg_modify_server_endpoint_only() {
    wg_check_server || return 1
    print_title "仅修改 WireGuard 服务端公网端点"
    local cur_ep cur_ddns new_ep
    cur_ep=$(wg_db_get '.server.endpoint')
    cur_ddns=$(wg_db_get '.server.ddns_domain // empty')
    echo -e "  当前端点: ${C_GREEN}${cur_ep}${C_RESET}"
    [[ -n "$cur_ddns" && "$cur_ddns" != "null" ]] && echo -e "  当前 DDNS: ${C_CYAN}${cur_ddns}${C_RESET}"
    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" == "$cur_ep" ]]; then
        print_info "未做任何更改"
        pause; return 0
    fi
    local endpoint_ddns=""
    validate_ip "$new_ep" || endpoint_ddns="$new_ep"
    wg_update_server_endpoint_metadata "$new_ep" "$endpoint_ddns"
    local rc=$?
    pause
    return "$rc"
}

_wg_openwrt_configure_server_uci() {
    local server_privkey="${1:-}" server_ip="${2:-}" wg_mask="${3:-}" wg_port="${4:-}" mtu="${5:-}"
    local snapshot_dir network_snapshot firewall_snapshot
    snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-server-uci.XXXXXX") || {
        print_error "创建 OpenWrt UCI 配置快照目录失败"
        return 1
    }
    chmod 700 "$snapshot_dir" 2>/dev/null || true
    network_snapshot="${snapshot_dir}/network.uci"
    firewall_snapshot="${snapshot_dir}/firewall.uci"
    if ! uci export network > "$network_snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi
    if ! uci export firewall > "$firewall_snapshot" 2>/dev/null; then
        rm -rf "$snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    if ! _wg_openwrt_write_server_uci "$server_privkey" "$server_ip" "$wg_mask" "$wg_port" "$mtu"; then
        print_error "OpenWrt 网络/防火墙 UCI 配置提交失败"
        _wg_openwrt_restore_uci_package network "$network_snapshot" || true
        _wg_openwrt_restore_uci_package firewall "$firewall_snapshot" || true
        rm -rf "$snapshot_dir" 2>/dev/null || true
        return 1
    fi
    rm -rf "$snapshot_dir" 2>/dev/null || true
}

_wg_openwrt_write_server_uci() {
    local server_privkey="${1:-}" server_ip="${2:-}" wg_mask="${3:-}" wg_port="${4:-}" mtu="${5:-}"
    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key="$server_privkey" || return 1
    uci -q delete network.wg0.addresses 2>/dev/null || true
    uci add_list network.wg0.addresses="${server_ip}/${wg_mask}" || return 1
    uci set network.wg0.listen_port="$wg_port" || return 1
    uci set network.wg0.mtu="$mtu" || return 1
    uci set network.wg0.route_allowed_ips='1' || return 1

    uci set firewall.wg_zone=zone || return 1
    uci set firewall.wg_zone.name='wg' || return 1
    uci set firewall.wg_zone.input='ACCEPT' || return 1
    uci set firewall.wg_zone.output='ACCEPT' || return 1
    uci set firewall.wg_zone.forward='ACCEPT' || return 1
    uci set firewall.wg_zone.masq='1' || return 1
    uci -q delete firewall.wg_zone.network 2>/dev/null || true
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

_wg_openwrt_snapshot_file() {
    local src="${1:-}" dst="${2:-}" marker="${3:-}"
    [[ -n "$src" && -n "$dst" && -n "$marker" ]] || return 1
    [[ -e "$src" ]] || return 0
    mkdir -p "$(dirname "$dst")" || return 1
    cp -p "$src" "$dst" || return 1
    : > "$marker"
}

_wg_openwrt_restore_snapshot_file() {
    local dst="${1:-}" snap="${2:-}" marker="${3:-}"
    [[ -n "$dst" && -n "$snap" && -n "$marker" ]] || return 0
    if [[ -f "$marker" ]]; then
        mkdir -p "$(dirname "$dst")" 2>/dev/null || true
        cp -p "$snap" "$dst" 2>/dev/null || print_warn "恢复 $dst 失败，请手动检查。"
    else
        rm -f "$dst" 2>/dev/null || print_warn "删除新建文件 $dst 失败，请手动检查。"
    fi
}

_wg_openwrt_snapshot_server_install() {
    local snapshot_dir="${1:-}" rc_file sysctl_conf
    [[ -n "$snapshot_dir" ]] || return 1
    mkdir -p "$snapshot_dir" || return 1
    if ! uci export network > "${snapshot_dir}/network.uci" 2>/dev/null; then
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi
    if ! uci export firewall > "${snapshot_dir}/firewall.uci" 2>/dev/null; then
        print_error "备份 OpenWrt firewall UCI 配置失败"
        return 1
    fi
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_openwrt_snapshot_file "$WG_DB_FILE" "${snapshot_dir}/db" "${snapshot_dir}/db.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_ROLE_FILE" "${snapshot_dir}/role" "${snapshot_dir}/role.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_CONF" "${snapshot_dir}/conf" "${snapshot_dir}/conf.exists" || return 1
    _wg_openwrt_snapshot_file "$WG_SHARED_ROUTE_STATE_FILE" "${snapshot_dir}/routes" "${snapshot_dir}/routes.exists" || return 1
    _wg_openwrt_snapshot_file "$rc_file" "${snapshot_dir}/rc.local" "${snapshot_dir}/rc.local.exists" || return 1
    sysctl_conf="$(_sysctl_conf_path)"
    _wg_openwrt_snapshot_file "$sysctl_conf" "${snapshot_dir}/sysctl.conf" "${snapshot_dir}/sysctl.exists" || return 1
    sysctl -n net.ipv4.ip_forward > "${snapshot_dir}/ip_forward.runtime" 2>/dev/null || true
}

_wg_openwrt_restore_uci_package() {
    local pkg="${1:-}" snapshot="${2:-}"
    [[ -n "$pkg" && -s "$snapshot" ]] || return 0
    uci revert "$pkg" >/dev/null 2>&1 || true
    if ! uci import "$pkg" < "$snapshot" >/dev/null 2>&1; then
        print_warn "恢复 OpenWrt ${pkg} UCI 配置失败，请手动检查。"
        return 1
    fi
    if ! uci commit "$pkg" >/dev/null 2>&1; then
        print_warn "提交恢复后的 OpenWrt ${pkg} UCI 配置失败，请手动检查。"
        return 1
    fi
}

_wg_openwrt_rollback_server_install() {
    local snapshot_dir="${1:-}" rollback_forward="${2:-false}" rc_file sysctl_conf ip_forward_runtime
    [[ -n "$snapshot_dir" ]] || return 0
    ifdown wg0 2>/dev/null || true
    wg_mihomo_bypass_clean >/dev/null 2>&1 || true
    _wg_openwrt_delete_allow_port_rules >/dev/null 2>&1 || true
    rc_file="$(_wg_openwrt_rc_local_path)"
    _wg_rc_local_cleanup_managed_entries all "$rc_file" >/dev/null 2>&1 || true

    _wg_openwrt_restore_uci_package network "${snapshot_dir}/network.uci" || true
    _wg_openwrt_restore_uci_package firewall "${snapshot_dir}/firewall.uci" || true
    /etc/init.d/network reload >/dev/null 2>&1 || true
    /etc/init.d/firewall reload >/dev/null 2>&1 || true

    _wg_openwrt_restore_snapshot_file "$WG_DB_FILE" "${snapshot_dir}/db" "${snapshot_dir}/db.exists"
    _wg_openwrt_restore_snapshot_file "$WG_ROLE_FILE" "${snapshot_dir}/role" "${snapshot_dir}/role.exists"
    _wg_openwrt_restore_snapshot_file "$WG_CONF" "${snapshot_dir}/conf" "${snapshot_dir}/conf.exists"
    _wg_openwrt_restore_snapshot_file "$WG_SHARED_ROUTE_STATE_FILE" "${snapshot_dir}/routes" "${snapshot_dir}/routes.exists"
    _wg_openwrt_restore_snapshot_file "$rc_file" "${snapshot_dir}/rc.local" "${snapshot_dir}/rc.local.exists"
    if [[ "$rollback_forward" == "true" ]]; then
        sysctl_conf="$(_sysctl_conf_path)"
        _wg_openwrt_restore_snapshot_file "$sysctl_conf" "${snapshot_dir}/sysctl.conf" "${snapshot_dir}/sysctl.exists"
        ip_forward_runtime=$(cat "${snapshot_dir}/ip_forward.runtime" 2>/dev/null || true)
        if [[ "$ip_forward_runtime" =~ ^[01]$ ]]; then
            sysctl -w "net.ipv4.ip_forward=${ip_forward_runtime}" >/dev/null 2>&1 || true
        elif [[ -f "$sysctl_conf" ]]; then
            sysctl -p "$sysctl_conf" >/dev/null 2>&1 || true
        fi
    fi
    rmdir "$(dirname "$WG_CONF")" 2>/dev/null || true
}

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

    local wg_install_snapshot_dir=""
    local wg_forward_changed=false
    wg_install_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-openwrt-install.XXXXXX") || {
        print_error "创建 OpenWrt 安装回滚快照目录失败"
        pause; return 1
    }
    if ! _wg_openwrt_snapshot_server_install "$wg_install_snapshot_dir"; then
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [3/7] 配置 IP 转发 ──
    print_info "[3/7] 配置 IP 转发..."
    if ! _sysctl_enable_wireguard_forward; then
        print_error "IP 转发配置失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    wg_forward_changed=true
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
    read -e -r -p "客户端 DNS [223.5.5.5, 114.114.114.114]: " wg_dns
    wg_dns=${wg_dns:-"223.5.5.5, 114.114.114.114"}

    # 服务端 LAN 子网 (自动检测 br-lan)
    local server_lan_subnet=""
    local br_lan_addr
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | awk '/^[[:space:]]*inet[[:space:]]/ { print $2; exit }')
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
    # 校验 LAN 子网格式（留空则跳过），畸形值会污染 client AllowedIPs / bypass 规则 / rc.local 持久化块
    while [[ -n "$server_lan_subnet" ]] && ! validate_cidr_list "$server_lan_subnet"; do
        print_error "LAN 子网格式无效: ${server_lan_subnet}（示例 192.168.1.0/24，多个用逗号分隔）"
        read -e -r -p "重新输入服务端 LAN 子网 (留空跳过): " server_lan_subnet
    done

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
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [5/7] 生成密钥 ──
    print_info "[5/7] 生成服务端密钥..."
    local server_privkey server_pubkey
    server_privkey=$(wg genkey)
    server_pubkey=$(echo "$server_privkey" | wg pubkey)
    if [[ -z "$server_privkey" || -z "$server_pubkey" ]]; then
        print_error "WireGuard 服务端密钥生成失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    print_success "密钥已生成"

    # 服务器名称
    local server_name=""
    local default_name=$(hostname -s 2>/dev/null)
    [[ -z "$default_name" ]] && default_name="server"
    read -e -r -p "服务器名称 [${default_name}]: " server_name
    server_name=${server_name:-$default_name}

    # ── [6/7] 写入数据库 + 配置 OpenWrt 网络和防火墙 ──
    print_info "[6/7] 写入配置..."
    # 配置 uci 网络接口
    print_info "配置 OpenWrt 网络接口..."
    local wg_mask
    wg_mask=$(echo "$wg_subnet" | cut -d'/' -f2)
    if ! _wg_openwrt_configure_server_uci "$server_privkey" "$server_ip" "$wg_mask" "$wg_port" "$mtu"; then
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    print_info "配置 OpenWrt 防火墙端口..."
    if ! _wg_openwrt_apply_allow_port "$wg_port"; then
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    if ! wg_db_init; then
        print_error "WireGuard 数据库初始化失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_db_set --arg sname "$server_name" \
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
    } | .schema_version = 2'; then
        print_error "WireGuard 数据库写入失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! wg_set_role "server"; then
        print_error "WireGuard 角色写入失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # 生成只读快照 wg0.conf
    if ! wg_rebuild_conf; then
        print_error "生成 WireGuard 配置快照失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi

    # ── [7/7] Mihomo bypass + 启动 ──
    print_info "[7/7] 配置 Mihomo bypass 并启动..."
    if ! wg_setup_mihomo_bypass "$wg_subnet"; then
        print_error "Mihomo bypass 配置失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    if ! ifup wg0 2>/dev/null; then
        print_error "启动 wg0 失败"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    sleep 2
    wg_sync_peer_routes

    # ── 安装结果展示 ──
    draw_line
    if ! wg_is_running; then
        print_error "wg0 未运行，请检查 logread | grep netifd"
        _wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"
        rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
        pause; return 1
    fi
    rm -rf "$wg_install_snapshot_dir" 2>/dev/null || true
    print_success "WireGuard 服务端安装并启动成功！"
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
    local changed=false lan_changed=false port_changed=false dns_changed=false endpoint_changed=false port_firewall_changed=false

    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
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
        changed=true
        dns_changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi

    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        if ! new_ep=$(wg_shared_normalize_endpoint_host "$new_ep"); then
            print_warn "端点无效，保持原值"
            new_ep="$cur_ep"
        else
            changed=true
            endpoint_changed=true
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
            changed=true
            lan_changed=true
            print_info "LAN 子网将更改为 ${new_lan}"
        fi
    fi

    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return 0
    fi

    if [[ "$endpoint_changed" == "true" && "$port_changed" != "true" && "$dns_changed" != "true" && "$lan_changed" != "true" ]]; then
        local endpoint_ddns=""
        validate_ip "$new_ep" || endpoint_ddns="$new_ep"
        if wg_update_server_endpoint_metadata "$new_ep" "$endpoint_ddns"; then
            pause; return 0
        fi
        pause; return 1
    fi

    if [[ "$port_changed" == "true" ]]; then
        if ! _wg_openwrt_apply_allow_port "$new_port"; then
            print_error "新 WireGuard UDP 端口未放行，已取消修改"
            pause; return 1
        fi
        port_firewall_changed=true
    fi

    if ! wg_db_set --argjson p "$new_port" \
                  --arg d "$new_dns" \
                  --arg e "$new_ep" \
                  --arg l "${new_lan:-}" \
                  '.server.port = $p | .server.dns = $d | .server.endpoint = $e | .server.server_lan_subnet = $l'; then
        print_error "WireGuard 数据库写入失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi

    if [[ "$lan_changed" == "true" ]]; then
        if ! _wg_update_peer_routes; then
            print_error "更新 peer 路由失败，正在回滚"
            _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
            pause; return 1
        fi
    fi

    if ! wg_rebuild_uci_conf; then
        print_error "重建 OpenWrt WireGuard UCI 配置失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi
    if ! wg_rebuild_conf; then
        print_error "生成 WireGuard 配置快照失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi
    if ! wg_regenerate_client_confs; then
        print_error "重生成客户端配置失败，正在回滚"
        _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
        pause; return 1
    fi

    # LAN 子网或端口变更都需要重建 bypass (因为 bypass 包含所有子网)
    if [[ "$new_port" != "$cur_port" || "${new_lan:-}" != "${cur_lan:-}" ]]; then
        if ! wg_mihomo_bypass_rebuild; then
            print_error "重建 Mihomo bypass/端口规则失败，正在回滚"
            _wg_openwrt_rollback_server_modify "$cur_port" "$cur_dns" "$cur_ep" "$cur_lan" "$port_firewall_changed"
            pause; return 1
        fi
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
        wg_sync_peer_routes
        print_success "WireGuard 已启动"
        log_action "WireGuard started"
        return 0
    else
        print_error "启动失败，请检查 logread | grep netifd"
        log_action "WireGuard start failed"
        return 1
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
        return 0
    else
        print_error "停止失败"
        log_action "WireGuard stop failed"
        return 1
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
        wg_sync_peer_routes
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
        return 0
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
        return 1
    fi
}

# ── Mihomo bypass 函数 ──

_wg_rc_local_cleanup_managed_entries() {
    local kind="${1:-all}" rc_file="${2:-/etc/rc.local}" tmp_out rc_dir
    case "$kind" in all|bypass|allow-port) ;; *) return 1 ;; esac
    [[ -f "$rc_file" ]] || return 0
    rc_dir="$(dirname "$rc_file")"
    tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-clean.XXXXXX") || return 1
    if awk -v kind="$kind" '
        function marker_matches(line) {
            if (kind == "all") return 1
            return index(line, " " kind) > 0
        }
        /^# BEGIN server-manage wireguard / {
            if (marker_matches($0)) { skip=1; next }
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
    ' "$rc_file" > "$tmp_out"; then
        chmod +x "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_out"; return 1; }
        chmod +x "$rc_file" 2>/dev/null || true
        rm -f "$tmp_out"
        return 0
    fi
    rm -f "$tmp_out"
    return 1
}

_wg_rc_local_insert_block() {
    local rc_block="${1:-}" rc_file="${2:-/etc/rc.local}"
    [[ -n "$rc_block" ]] || return 1
    local tmp_block tmp_out rc_dir
    rc_dir="$(dirname "$rc_file")"
    tmp_block=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-block.XXXXXX") || return 1
    tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-local.XXXXXX") || { rm -f "$tmp_block"; return 1; }
    if [[ ! -f "$rc_file" ]]; then
        printf '#!/bin/sh\nexit 0\n' > "$tmp_out" 2>/dev/null || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        chmod 755 "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        tmp_out=$(mktemp "${rc_dir}/.${SCRIPT_NAME}-wg-rc-local.XXXXXX") || { rm -f "$tmp_block"; return 1; }
    fi
    printf '%b\n' "$rc_block" > "$tmp_block"
    if awk '
        FNR == NR { block = block $0 ORS; next }
        /^[[:space:]]*exit[[:space:]]+0([[:space:]]*(#.*)?)?$/ && !inserted { printf "%s", block; inserted=1 }
        { print }
        END { if (!inserted) printf "%s", block }
    ' "$tmp_block" "$rc_file" > "$tmp_out"; then
        chmod +x "$tmp_out" 2>/dev/null || true
        mv "$tmp_out" "$rc_file" || { rm -f "$tmp_block" "$tmp_out"; return 1; }
        chmod +x "$rc_file" 2>/dev/null || true
        rm -f "$tmp_block" "$tmp_out"
        return 0
    fi
    rm -f "$tmp_block" "$tmp_out"
    return 1
}

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
    local cidr nft_family
    for cidr in "${unique_subnets[@]}"; do
        nft_family=$(nft_addr_family_for_cidr "$cidr")
        nft insert rule inet fw4 mangle_prerouting "$nft_family" daddr "$cidr" counter return comment \"wg_bypass_subnet\" 2>/dev/null || true
    done

    # 持久化到 /etc/rc.local
    _wg_rc_local_cleanup_managed_entries bypass || print_warn "清理 /etc/rc.local 旧 bypass 规则失败"
    local rc_block="# BEGIN server-manage wireguard bypass\n# WireGuard bypass Mihomo\nnft insert rule inet fw4 mangle_prerouting iifname \\\"wg0\\\" counter return comment \\\"wg_bypass_iface\\\" 2>/dev/null || true # wg_bypass"
    for cidr in "${unique_subnets[@]}"; do
        nft_family=$(nft_addr_family_for_cidr "$cidr")
        rc_block="${rc_block}\nnft insert rule inet fw4 mangle_prerouting ${nft_family} daddr \\\"${cidr}\\\" counter return comment \\\"wg_bypass_subnet\\\" 2>/dev/null || true"
    done
    # 网关 peer LAN 路由持久化 (proto-wireguard 不一定自动创建)
    local pc=$(wg_db_get '.peers | length' 2>/dev/null) pi=0
    while [[ $pi -lt ${pc:-0} ]]; do
        if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" && "$(wg_db_get ".peers[$pi].is_gateway // false")" == "true" ]]; then
            local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
            if [[ -n "$pls" && "$pls" != "null" ]]; then
                local IFS_BAK="$IFS"; IFS=','
                for sub in $pls; do
                    sub=$(echo "$sub" | xargs)
                    [[ -n "$sub" ]] && rc_block="${rc_block}\nip route replace ${sub} dev wg0 2>/dev/null || true # wg_peer_route"
                done
                IFS="$IFS_BAK"
            fi
        fi
        pi=$((pi + 1))
    done
    rc_block="${rc_block}\n# END server-manage wireguard bypass"
    _wg_rc_local_insert_block "$rc_block" || print_warn "写入 /etc/rc.local 持久化规则失败"

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
    # 清理 /etc/rc.local 中的持久化条目
    _wg_rc_local_cleanup_managed_entries bypass || true
}

wg_mihomo_bypass_rebuild() {
    local wg_subnet wg_port
    wg_subnet=$(wg_db_get '.server.subnet')
    wg_port=$(wg_db_get '.server.port')
    [[ -z "$wg_subnet" || "$wg_subnet" == "null" ]] && return 1

    wg_setup_mihomo_bypass "$wg_subnet" || return 1

    # 重建端口放行规则
    if [[ -n "$wg_port" && "$wg_port" != "null" ]]; then
        _wg_openwrt_apply_allow_port "$wg_port" || return 1
    fi
    return 0
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
    _wg_ifaces=$(_wg_openwrt_list_wireguard_ifaces | tr '\n' ' ')
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
    if ! uci commit network; then
        print_error "提交 OpenWrt network 清理失败，已中止卸载。请修复 UCI 后重试，避免本地状态先被删除。"
        pause; return 1
    fi
    if ! uci commit firewall; then
        print_error "提交 OpenWrt firewall 清理失败，已中止卸载。请修复 UCI 后重试，避免本地状态先被删除。"
        pause; return 1
    fi

    print_info "[3/6] 清理 Mihomo bypass 和 nft 规则..."
    wg_mihomo_bypass_clean
    # 旧版 prio 100 策略路由没有可验证标记，不能粗暴删除第三方规则。

    print_info "[4/6] 清理看门狗和定时任务..."
    cron_remove_job_command "/usr/bin/wg-watchdog.sh" 2>/dev/null || true
    cron_remove_job_command "/usr/local/bin/wg-watchdog.sh" 2>/dev/null || true
    rm -f /usr/bin/wg-watchdog.sh /usr/local/bin/wg-watchdog.sh \
          /var/log/wg-watchdog.log /var/run/server-manage/wg-watchdog.log \
          /var/run/server-manage/.wg-watchdog-log.* \
          /tmp/wg-watchdog.log /tmp/wg-watchdog.log.tmp 2>/dev/null || true

    print_info "[5/6] 删除配置文件..."
    rm -f "$WG_CONF" 2>/dev/null || true
    rm -rf /etc/wireguard/clients 2>/dev/null || true
    rm -f "$WG_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DB_DIR" 2>/dev/null || true
    rm -f "$WG_ROLE_FILE" 2>/dev/null || true
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
            _sysctl_disable_wireguard_forward || print_warn "恢复 IP 转发设置失败，请手动检查 /etc/sysctl.conf"
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
die() { echo "[!] $*" >&2; exit 1; }
list_wg_ifaces() {
    ip link show type wireguard 2>/dev/null | awk '
        /^[0-9]+:/ {
            name=$0
            sub(/^[0-9]+:[[:space:]]*/, "", name)
            sub(/:.*/, "", name)
            sub(/@.*/, "", name)
            current=name
            next
        }
        /link\/none/ && current != "" {
            print current
            current=""
        }
    '
}
ifdown wg0 2>/dev/null; true
ifdown wg_mesh 2>/dev/null; true
for iface in $(list_wg_ifaces); do
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
(crontab -l 2>/dev/null | awk '$6 != "/usr/bin/wg-watchdog.sh"') | crontab - 2>/dev/null; true
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
# 旧版 prio 100 策略路由没有可验证标记，不能粗暴删除第三方规则。
for h in $(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print $NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "$h" 2>/dev/null; true
done
for h in $(nft -a list chain inet fw4 input_wan 2>/dev/null | grep 'wg_allow_port' | awk '{print $NF}'); do
    nft delete rule inet fw4 input_wan handle "$h" 2>/dev/null; true
done
if [ -f /etc/rc.local ]; then
    WG_RC_TMP="$(mktemp /etc/.rc.local.clean.XXXXXX 2>/dev/null)" || { echo '[!] 创建 rc.local 清理临时文件失败' >&2; exit 1; }
    if awk '
        /^# BEGIN server-manage wireguard / { skip=1; next }
        /^# END server-manage wireguard / { skip=0; next }
        skip { next }
        /^# WireGuard bypass Mihomo/ { next }
        /# wg_bypass[[:space:]]*$/ { next }
        /# wg_peer_route[[:space:]]*$/ { next }
        /# wg_ep_resolve[[:space:]]*$/ { next }
        /# wg_allow_port[[:space:]]*$/ { next }
        /nft insert rule inet fw4 input_wan udp dport .*comment .*wg_allow_port/ { next }
        { print }
    ' /etc/rc.local > "$WG_RC_TMP"; then
        chmod +x "$WG_RC_TMP" 2>/dev/null && mv "$WG_RC_TMP" /etc/rc.local || { rm -f "$WG_RC_TMP"; die "安装清理后的 /etc/rc.local 失败"; }
    else
        rm -f "$WG_RC_TMP"
        die "生成清理后的 /etc/rc.local 失败"
    fi
    rm -f "$WG_RC_TMP"
fi

# === 提交配置 ===
uci commit network || die "提交 network 清理失败"
uci commit firewall || die "提交 firewall 清理失败"

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
