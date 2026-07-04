# modules/11-wireguard.sh - WireGuard 完整模块 (OpenWrt 专用)
# Sub-modules (loaded via build.sh concatenation):
#   11a -> OpenWrt 环境兼容性检测
#   11  -> constants + db + utilities (this file)
#   11c -> server install/control/uninstall
#   11d -> peer management
#   11e -> Clash/OpenClash config
#   11g -> watchdog + import/export + menus
readonly WG_INTERFACE="wg0"
readonly WG_DB_DIR="${WG_SHARED_DB_DIR}"
readonly WG_DB_FILE="${WG_SHARED_DB_FILE}"
readonly WG_CONF="/etc/wireguard/${WG_INTERFACE}.conf"
readonly WG_ROLE_FILE="${WG_SHARED_ROLE_FILE}"

wg_write_private_file() {
    local file="$1" content="$2" dir tmp old_umask _rc
    dir="$(dirname "$file")"
    mkdir -p "$dir" || return 1
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/.tmp.server-manage.wg.XXXXXX")
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    if declare -F _tmp_register >/dev/null 2>&1; then _tmp_register "$tmp"; fi
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    chown root:root "$tmp" 2>/dev/null || true
    if ! mv -f "$tmp" "$file"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
    return 0
}

wg_shared_export_file() {
    local dir="${WG_EXPORT_DIR:-/root/wireguard-exports}" tmp old_umask _rc
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" 2>/dev/null || true
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp "${dir}/${SCRIPT_NAME}-wg-peers.XXXXXX")
    _rc=$?
    umask "$old_umask"
    [[ $_rc -eq 0 ]] || return 1
    chmod 600 "$tmp" 2>/dev/null || true
    chown root:root "$tmp" 2>/dev/null || true
    printf '%s\n' "$tmp"
}

wg_shared_db_init() {
    mkdir -p "$WG_SHARED_DB_DIR"
    [[ -f "$WG_SHARED_DB_FILE" ]] && return 0
    local content
    content=$(cat <<'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "client": {}
}
WGEOF
)
    wg_write_private_file "$WG_SHARED_DB_FILE" "$content"
}

wg_shared_db_get() { jq -r "$@" "$WG_SHARED_DB_FILE" 2>/dev/null; }

wg_shared_db_set() {
    local tmp
    tmp=$(mktemp "${WG_SHARED_DB_DIR}/.tmp.XXXXXX") || { print_error "无法创建临时文件"; return 1; }
    (
        if [[ "$PLATFORM" == "openwrt" ]]; then
            local _retry=0
            while ! flock -n 200 2>/dev/null; do
                _retry=$((_retry+1))
                [[ $_retry -ge 10 ]] && { rm -f "$tmp"; print_error "无法获取数据库锁"; return 1; }
                sleep 0.5
            done
        else
            flock -w 5 200 || { rm -f "$tmp"; print_error "无法获取数据库锁"; return 1; }
        fi
        if jq "$@" "$WG_SHARED_DB_FILE" > "$tmp" 2>/dev/null; then
            chmod 600 "$tmp" 2>/dev/null || true
            chown root:root "$tmp" 2>/dev/null || true
            mv "$tmp" "$WG_SHARED_DB_FILE"
        else
            rm -f "$tmp"; print_error "数据库写入失败"; return 1
        fi
    ) 200>"${WG_SHARED_DB_FILE}.lock"
}

wg_shared_get_role() {
    local role=""
    [[ -f "$WG_SHARED_ROLE_FILE" ]] && role=$(cat "$WG_SHARED_ROLE_FILE" 2>/dev/null)
    [[ -z "$role" && -f "$WG_SHARED_DB_FILE" ]] && role=$(wg_shared_db_get '.role // empty')
    if [[ -z "$role" && -f "$WG_SHARED_DB_FILE" ]]; then
        local spk
        spk=$(wg_shared_db_get '.server.private_key // empty')
        [[ -n "$spk" ]] && role="server"
    fi
    echo "${role:-none}"
}

wg_shared_set_role() {
    mkdir -p /etc/wireguard
    wg_write_private_file "$WG_SHARED_ROLE_FILE" "$1" || return 1
    wg_shared_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_shared_gateway_lans() {
    local get_fn="${1:-}"
    declare -F "$get_fn" >/dev/null 2>&1 || return 1
    local pc
    pc=$("$get_fn" '.peers | length' 2>/dev/null)
    [[ "$pc" =~ ^[0-9]+$ ]] || pc=0

    local i=0 seen="" result="" enabled is_gw lans IFS_BAK sub
    while [[ $i -lt $pc ]]; do
        enabled=$("$get_fn" ".peers[$i].enabled" 2>/dev/null)
        is_gw=$("$get_fn" ".peers[$i].is_gateway // false" 2>/dev/null)
        lans=$("$get_fn" ".peers[$i].lan_subnets // empty" 2>/dev/null)
        if [[ "$enabled" == "true" && "$is_gw" == "true" && -n "$lans" && "$lans" != "null" ]]; then
            IFS_BAK="$IFS"; IFS=','
            for sub in $lans; do
                sub=$(echo "$sub" | xargs)
                [[ -n "$sub" ]] || continue
                validate_cidr "$sub" || continue
                case "$seen" in
                    *"|$sub|"*) ;;
                    *)
                        seen="${seen}|${sub}|"
                        [[ -n "$result" ]] && result="${result}"$'\n'
                        result="${result}${sub}"
                        ;;
                esac
            done
            IFS="$IFS_BAK"
        fi
        i=$((i + 1))
    done
    printf '%s\n' "$result" | sed '/^$/d'
}

wg_shared_sync_gateway_routes() {
    local get_fn="${1:-}" iface="${2:-}" state_file="${3:-$WG_SHARED_ROUTE_STATE_FILE}"
    [[ -n "$iface" ]] || return 1
    command_exists ip || return 1

    local current old rc=0
    current=$(wg_shared_gateway_lans "$get_fn") || return 1

    if [[ -f "$state_file" ]]; then
        while IFS= read -r old || [[ -n "$old" ]]; do
            old=$(echo "$old" | xargs)
            [[ -n "$old" ]] || continue
            validate_cidr "$old" || continue
            if ! printf '%s\n' "$current" | grep -Fxq -- "$old"; then
                if [[ "$old" == *:* ]]; then
                    ip -6 route del "$old" dev "$iface" >/dev/null 2>&1 || true
                else
                    ip route del "$old" dev "$iface" >/dev/null 2>&1 || true
                fi
            fi
        done < "$state_file"
    fi

    while IFS= read -r old || [[ -n "$old" ]]; do
        old=$(echo "$old" | xargs)
        [[ -n "$old" ]] || continue
        if [[ "$old" == *:* ]]; then
            ip -6 route replace "$old" dev "$iface" >/dev/null 2>&1 || rc=1
        elif ! ip route replace "$old" dev "$iface" >/dev/null 2>&1; then
            rc=1
        fi
    done <<< "$current"
    [[ "$rc" -eq 0 ]] || return 1

    if [[ -n "$current" ]]; then
        wg_write_private_file "$state_file" "$current" || return 1
    else
        rm -f -- "$state_file" 2>/dev/null || return 1
    fi
    return 0
}

wg_db_init() { wg_shared_db_init; }
wg_db_get() { wg_shared_db_get "$@"; }
wg_db_set() { wg_shared_db_set "$@"; }
wg_get_role() { wg_shared_get_role; }
wg_set_role() { wg_shared_set_role "$@"; }

wg_shared_endpoint_host() {
    local host="${1:-}"
    if [[ "$host" =~ ^\[(.*)\]:[0-9]+$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "$host" =~ ^\[(.*)\]$ ]]; then
        host="${BASH_REMATCH[1]}"
    elif [[ "$host" =~ ^([^:]+):[0-9]+$ ]]; then
        host="${BASH_REMATCH[1]}"
    fi
    printf '%s\n' "$host"
}

wg_shared_normalize_endpoint_host() {
    local endpoint="${1:-}" host
    host=$(wg_shared_endpoint_host "$endpoint")
    validate_host "$host" || return 1
    printf '%s\n' "$host"
}

wg_shared_format_endpoint() {
    local host port
    host=$(wg_shared_endpoint_host "${1:-}")
    port="${2:-}"
    if [[ "$host" == *:* ]]; then
        printf '[%s]:%s\n' "$host" "$port"
    else
        printf '%s:%s\n' "$host" "$port"
    fi
}

wg_is_installed() { command_exists wg && [[ -f "$WG_DB_FILE" ]]; }
wg_is_running()   { ip link show "$WG_INTERFACE" &>/dev/null; }

wg_get_server_name() {
    local name
    name=$(wg_db_get '.server.name // empty')
    if [[ -z "$name" || "$name" == "null" ]]; then
        name=$(hostname -s 2>/dev/null)
        [[ -z "$name" ]] && name="server"
    fi
    echo "$name"
}

wg_rename_server() {
    print_title "修改服务器名称"
    local current_name=$(wg_get_server_name)
    echo -e "  当前名称: ${C_CYAN}${current_name}${C_RESET}"
    local new_name=""
    read -e -r -p "新名称 [${current_name}]: " new_name
    new_name=${new_name:-$current_name}
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "名称只能包含字母、数字、下划线、连字符"
        pause; return
    fi
    wg_db_set --arg n "$new_name" '.server.name = $n'
    print_success "服务器名称已更新为: ${new_name}"
    log_action "WireGuard server renamed: ${current_name} -> ${new_name}"
    pause
}

wg_check_installed() {
    if ! wg_is_installed; then
        print_error "WireGuard 未安装，请先执行安装。"
        pause; return 1
    fi
    return 0
}

wg_check_server() {
    wg_check_installed || return 1
    if [[ "$(wg_get_role)" != "server" ]]; then
        print_error "当前不是服务端模式，此功能仅服务端可用。"
        pause; return 1
    fi
    return 0
}

wg_select_peer() {
    local prompt="${1:-选择设备序号}" show_status="${2:-false}"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"; pause; return 1
    fi
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip mark=""
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        if [[ "$show_status" == "true" ]]; then
            local enabled
            enabled=$(wg_db_get ".peers[$i].enabled")
            [[ "$enabled" == "true" ]] && mark=" ${C_GREEN}(已启用)${C_RESET}" || mark=" ${C_RED}(已禁用)${C_RESET}"
        fi
        local is_gw
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        [[ "$is_gw" == "true" ]] && mark+=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i + 1)). ${name} (${ip})${mark}"
        i=$((i + 1))
    done
    echo "  0. 返回
"
    local idx
    read -e -r -p "${prompt}: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return 1
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return 1
    fi
    REPLY=$((idx - 1))
    return 0
}


wg_install_packages() {
    print_info "安装 WireGuard 软件包..."
    opkg update >/dev/null 2>&1
    local essential_pkgs=(wireguard-tools kmod-wireguard luci-proto-wireguard jq)
    local optional_pkgs=(qrencode)
    for pkg in "${essential_pkgs[@]}"; do
        install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
    done
    for pkg in "${optional_pkgs[@]}"; do
        install_package "$pkg" "silent" || print_warn "安装 $pkg 失败（不影响核心功能）"
    done
    # 重启 rpcd 使 LuCI 识别 wireguard 协议
    /etc/init.d/rpcd restart 2>/dev/null || true
    print_success "软件包安装完成"
    return 0
}

wg_next_ip() {
    local subnet prefix
    subnet=$(wg_db_get '.server.subnet')
    prefix=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    # 一次性获取所有已用 IP，避免 N+1 次 jq 调用
    local used_ips
    used_ips=$(wg_db_get '[.server.ip] + [.peers[].ip] | join(" ")')
    local next
    for next in $(seq 2 254); do
        local candidate="${prefix}.${next}"
        printf '%s\n' $used_ips | grep -Fxq -- "$candidate" || { echo "$candidate"; return 0; }
    done
    print_error "子网 IP 已耗尽"; return 1
}

wg_format_bytes() {
    local bytes=$1
    [[ -z "$bytes" || "$bytes" == "0" ]] && { echo "0 B"; return; }
    awk -v b="$bytes" 'BEGIN {
        if (b>=1073741824) printf "%.2f GB",b/1073741824
        else if (b>=1048576) printf "%.2f MB",b/1048576
        else if (b>=1024) printf "%.2f KB",b/1024
        else printf "%d B",b
    }'
}

_wg_openwrt_restore_network_uci_snapshot() {
    local snapshot="${1:-}"
    [[ -s "$snapshot" ]] || return 0
    uci revert network >/dev/null 2>&1 || true
    if ! uci import network < "$snapshot" >/dev/null 2>&1; then
        print_warn "恢复 OpenWrt network UCI 配置失败，请手动检查。"
        return 1
    fi
    if ! uci commit network >/dev/null 2>&1; then
        print_warn "提交恢复后的 OpenWrt network UCI 配置失败，请手动检查。"
        return 1
    fi
}

_wg_openwrt_write_network_uci_from_db() {
    local priv_key="${1:-}" port="${2:-}" server_ip="${3:-}" mask="${4:-}" mtu="${5:-}"
    local pc i

    while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
        uci delete network.@wireguard_wg0[0] || return 1
    done

    uci set network.wg0=interface || return 1
    uci set network.wg0.proto='wireguard' || return 1
    uci set network.wg0.private_key="$priv_key" || return 1
    uci -q delete network.wg0.addresses 2>/dev/null || true
    uci add_list network.wg0.addresses="${server_ip}/${mask}" || return 1
    uci set network.wg0.listen_port="$port" || return 1
    uci set network.wg0.mtu="$mtu" || return 1
    uci set network.wg0.route_allowed_ips='1' || return 1

    pc=$(wg_db_get '.peers | length') || return 1
    i=0
    while [[ $i -lt $pc ]]; do
        if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
            local peer_name pub_key psk peer_ip is_gw lan_sub sub IFS_BAK
            peer_name=$(wg_db_get ".peers[$i].name") || return 1
            pub_key=$(wg_db_get ".peers[$i].public_key") || return 1
            psk=$(wg_db_get ".peers[$i].preshared_key") || return 1
            peer_ip=$(wg_db_get ".peers[$i].ip") || return 1
            is_gw=$(wg_db_get ".peers[$i].is_gateway // false") || return 1
            lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty") || return 1

            uci add network wireguard_wg0 >/dev/null || return 1
            uci set network.@wireguard_wg0[-1].description="$peer_name" || return 1
            uci set network.@wireguard_wg0[-1].public_key="$pub_key" || return 1
            uci set network.@wireguard_wg0[-1].preshared_key="$psk" || return 1
            uci set network.@wireguard_wg0[-1].persistent_keepalive='25' || return 1

            uci -q delete network.@wireguard_wg0[-1].allowed_ips 2>/dev/null || true
            uci add_list network.@wireguard_wg0[-1].allowed_ips="${peer_ip}/32" || return 1
            if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                IFS_BAK="$IFS"; IFS=','
                for sub in $lan_sub; do
                    sub=$(echo "$sub" | xargs)
                    if [[ -n "$sub" ]]; then
                        uci add_list network.@wireguard_wg0[-1].allowed_ips="$sub" || {
                            IFS="$IFS_BAK"
                            return 1
                        }
                    fi
                done
                IFS="$IFS_BAK"
            fi
        fi
        i=$((i + 1))
    done

    uci commit network || return 1
}


wg_rebuild_uci_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local apply_mode="${1:-reload}"
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT

    local uci_snapshot_dir uci_snapshot
    uci_snapshot_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-uci.XXXXXX") || {
        print_error "创建 OpenWrt network UCI 快照目录失败"
        return 1
    }
    chmod 700 "$uci_snapshot_dir" 2>/dev/null || true
    uci_snapshot="${uci_snapshot_dir}/network.uci"
    if ! uci export network > "$uci_snapshot" 2>/dev/null; then
        rm -rf "$uci_snapshot_dir" 2>/dev/null || true
        print_error "备份 OpenWrt network UCI 配置失败"
        return 1
    fi

    _wg_openwrt_write_network_uci_from_db "$priv_key" "$port" "$server_ip" "$mask" "$mtu"
    local uci_rc=$?
    if [[ $uci_rc -ne 0 ]]; then
        print_error "OpenWrt network UCI 配置提交失败"
        _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
        rm -rf "$uci_snapshot_dir" 2>/dev/null || true
        return 1
    fi

    # --- 非 peer 热应用路径仍允许重启接口；peer 操作传 no_reload 后用 wg syncconf 热同步 ---
    if wg_is_running && [[ "$apply_mode" != "no_reload" ]]; then
        ifdown wg0 2>/dev/null || true
        sleep 1
        if ! ifup wg0 2>/dev/null; then
            print_error "OpenWrt wg0 接口重载失败"
            _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
            rm -rf "$uci_snapshot_dir" 2>/dev/null || true
            return 1
        fi
        sleep 1
        if ! wg_sync_peer_routes; then
            print_error "OpenWrt WireGuard 路由同步失败"
            _wg_openwrt_restore_network_uci_snapshot "$uci_snapshot" || true
            rm -rf "$uci_snapshot_dir" 2>/dev/null || true
            return 1
        fi
    fi
    rm -rf "$uci_snapshot_dir" 2>/dev/null || true
    return 0
}

wg_apply_runtime_conf() {
    wg_rebuild_conf || return 1
    wg_is_running || return 0
    local tmp_dir tmp
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/${SCRIPT_NAME}-wg-sync.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    tmp="${tmp_dir}/sync.conf"
    awk '
        /^\[Interface\]$/ { section="interface"; print; next }
        /^\[Peer\]$/ { section="peer"; print; next }
        section=="interface" && /^(PrivateKey|ListenPort|FwMark)[[:space:]]*=/ { print; next }
        section=="peer" && /^(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)[[:space:]]*=/ { print; next }
    ' "$WG_CONF" > "$tmp" || { rm -rf "$tmp_dir"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true
    if wg syncconf "$WG_INTERFACE" "$tmp" >/dev/null 2>&1; then
        rm -rf "$tmp_dir"
        wg_sync_peer_routes || return 1
        return 0
    fi
    rm -rf "$tmp_dir"
    return 1
}

# 同步网关 peer 的 LAN 路由到内核路由表
# (部分 OpenWrt 固件的 proto-wireguard 不支持 route_allowed_ips，需手动添加)
wg_sync_peer_routes() {
    wg_is_running || return 0
    wg_shared_sync_gateway_routes wg_db_get "$WG_INTERFACE"
}

# 生成 wg0.conf 只读快照（供导出/备份/查看用，不用于运行）
wg_rebuild_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        log_action "wg_rebuild_conf failed: missing fields" "ERROR"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    local conf_content
    conf_content=$(
    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "MTU = ${mtu}"
        local pc=$(wg_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo ""
                echo "[Peer]"
                echo "PublicKey = $(wg_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_db_get ".peers[$i].ip")
                local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
            fi
            i=$((i + 1))
        done
    }
)
    wg_write_private_file "$WG_CONF" "$conf_content"
}

wg_regenerate_client_confs() {
    local pc=$(wg_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport endpoint sdns mask mtu
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    endpoint=$(wg_shared_format_endpoint "$sep" "$sport")
    sdns=$(wg_db_get '.server.dns')
    mask=$(echo "$(wg_db_get '.server.subnet')" | cut -d'/' -f2)
    mtu=$(wg_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    mkdir -p /etc/wireguard/clients
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_db_get ".peers[$i].name")
        local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local conf_content="[Interface]
PrivateKey = $(wg_db_get ".peers[$i].private_key")
Address = $(wg_db_get ".peers[$i].ip")/${mask}
MTU = ${mtu}"
        [[ "$is_gw" != "true" ]] && conf_content+=$'\n'"DNS = ${sdns}"
        conf_content+="
[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_db_get ".peers[$i].preshared_key")
Endpoint = ${endpoint}
AllowedIPs = $(wg_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        wg_write_private_file "/etc/wireguard/clients/${name}.conf" "$conf_content" || return 1
        i=$((i + 1))
    done
}
