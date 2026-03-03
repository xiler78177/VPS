# modules/12b-wireguard-deb.sh - Debian/Ubuntu WireGuard 核心模块 (常量/DB/工具)
# 使用 wg_deb_ 前缀，与 OpenWrt 版 (wg_) 完全隔离

readonly WG_DEB_INTERFACE="wg0"
readonly WG_DEB_DB_DIR="/etc/wireguard/db"
readonly WG_DEB_DB_FILE="${WG_DEB_DB_DIR}/wg-data.json"
readonly WG_DEB_CONF="/etc/wireguard/${WG_DEB_INTERFACE}.conf"
readonly WG_DEB_ROLE_FILE="/etc/wireguard/.role"
readonly WG_DEB_CLIENT_DIR="/etc/wireguard/clients"

wg_deb_db_init() {
    mkdir -p "$WG_DEB_DB_DIR"
    [[ -f "$WG_DEB_DB_FILE" ]] && return 0
    cat > "$WG_DEB_DB_FILE" << 'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "client": {}
}
WGEOF
    chmod 600 "$WG_DEB_DB_FILE"
}

wg_deb_db_migrate() {
    [[ ! -f "$WG_DEB_DB_FILE" ]] && return 0
    local ver
    ver=$(wg_deb_db_get '.schema_version // 0')
    [[ "$ver" -ge 2 ]] && return 0
    print_info "数据库迁移: v${ver} → v2 ..."
    local pc i=0
    pc=$(wg_deb_db_get '.peers | length')
    while [[ $i -lt ${pc:-0} ]]; do
        local existing_type
        existing_type=$(wg_deb_db_get ".peers[$i].peer_type // empty")
        if [[ -z "$existing_type" || "$existing_type" == "null" ]]; then
            local is_gw
            is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
            if [[ "$is_gw" == "true" ]]; then
                wg_deb_db_set --argjson idx "$i" '.peers[$idx].peer_type = "gateway"'
            else
                wg_deb_db_set --argjson idx "$i" '.peers[$idx].peer_type = "standard"'
            fi
        fi
        i=$((i + 1))
    done
    wg_deb_db_set '.schema_version = 2'
    print_success "数据库迁移完成"
}

wg_deb_db_get() { jq -r "$@" "$WG_DEB_DB_FILE" 2>/dev/null; }

wg_deb_db_set() {
    local tmp
    tmp=$(mktemp "${WG_DEB_DB_DIR}/.tmp.XXXXXX") || { print_error "无法创建临时文件"; return 1; }
    (
        flock -w 5 200 || { rm -f "$tmp"; print_error "无法获取数据库锁"; return 1; }
        if jq "$@" "$WG_DEB_DB_FILE" > "$tmp" 2>/dev/null; then
            mv "$tmp" "$WG_DEB_DB_FILE"; chmod 600 "$WG_DEB_DB_FILE"
        else
            rm -f "$tmp"; print_error "数据库写入失败"; return 1
        fi
    ) 200>"${WG_DEB_DB_FILE}.lock"
}

wg_deb_get_role() {
    local role=""
    [[ -f "$WG_DEB_ROLE_FILE" ]] && role=$(cat "$WG_DEB_ROLE_FILE" 2>/dev/null)
    [[ -z "$role" && -f "$WG_DEB_DB_FILE" ]] && role=$(wg_deb_db_get '.role // empty')
    if [[ -z "$role" && -f "$WG_DEB_DB_FILE" ]]; then
        local spk=$(wg_deb_db_get '.server.private_key // empty')
        [[ -n "$spk" ]] && role="server"
    fi
    echo "${role:-none}"
}

wg_deb_set_role() {
    mkdir -p /etc/wireguard
    echo "$1" > "$WG_DEB_ROLE_FILE"
    chmod 600 "$WG_DEB_ROLE_FILE"
    wg_deb_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_deb_is_installed() { command_exists wg && [[ -f "$WG_DEB_DB_FILE" ]]; }
wg_deb_is_running()   { ip link show "$WG_DEB_INTERFACE" &>/dev/null; }

wg_deb_get_server_name() {
    local name
    name=$(wg_deb_db_get '.server.name // empty')
    if [[ -z "$name" || "$name" == "null" ]]; then
        name=$(hostname -s 2>/dev/null)
        [[ -z "$name" ]] && name="server"
    fi
    echo "$name"
}

wg_deb_rename_server() {
    print_title "修改服务器名称"
    local current_name=$(wg_deb_get_server_name)
    echo -e "  当前名称: ${C_CYAN}${current_name}${C_RESET}"
    local new_name=""
    read -e -r -p "新名称 [${current_name}]: " new_name
    new_name=${new_name:-$current_name}
    if [[ ! "$new_name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        print_error "名称只能包含字母、数字、下划线、连字符"
        pause; return
    fi
    wg_deb_db_set --arg n "$new_name" '.server.name = $n'
    print_success "服务器名称已更新为: ${new_name}"
    log_action "WireGuard(deb) server renamed: ${current_name} -> ${new_name}"
    pause
}

wg_deb_check_installed() {
    if ! wg_deb_is_installed; then
        print_error "WireGuard 未安装，请先执行安装。"
        pause; return 1
    fi
    return 0
}

wg_deb_check_server() {
    wg_deb_check_installed || return 1
    if [[ "$(wg_deb_get_role)" != "server" ]]; then
        print_error "当前不是服务端模式，此功能仅服务端可用。"
        pause; return 1
    fi
    return 0
}

wg_deb_select_peer() {
    local prompt="${1:-选择设备序号}" show_status="${2:-false}"
    local peer_count
    peer_count=$(wg_deb_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 || "$peer_count" == "null" ]]; then
        print_warn "暂无设备"; pause; return 1
    fi
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip mark=""
        name=$(wg_deb_db_get ".peers[$i].name")
        ip=$(wg_deb_db_get ".peers[$i].ip")
        if [[ "$show_status" == "true" ]]; then
            local enabled
            enabled=$(wg_deb_db_get ".peers[$i].enabled")
            [[ "$enabled" == "true" ]] && mark=" ${C_GREEN}(已启用)${C_RESET}" || mark=" ${C_RED}(已禁用)${C_RESET}"
        fi
        local is_gw
        is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
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

wg_deb_install_packages() {
    print_info "安装 WireGuard 软件包..."
    apt-get update -qq >/dev/null 2>&1
    local essential_pkgs=(wireguard wireguard-tools jq iptables)
    local optional_pkgs=(qrencode)
    for pkg in "${essential_pkgs[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            apt-get install -y -qq "$pkg" >/dev/null 2>&1 || { print_error "安装 $pkg 失败"; return 1; }
        fi
    done
    for pkg in "${optional_pkgs[@]}"; do
        if ! dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
            apt-get install -y -qq "$pkg" >/dev/null 2>&1 || print_warn "安装 $pkg 失败（不影响核心功能）"
        fi
    done
    print_success "软件包安装完成"
    return 0
}

wg_deb_next_ip() {
    local subnet prefix
    subnet=$(wg_deb_db_get '.server.subnet')
    prefix=$(echo "$subnet" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local used_ips
    used_ips=$(wg_deb_db_get '[.server.ip] + [.peers[].ip] | join(" ")')
    local next
    for next in $(seq 2 254); do
        local candidate="${prefix}.${next}"
        echo "$used_ips" | grep -qw "$candidate" || { echo "$candidate"; return 0; }
    done
    print_error "子网 IP 已耗尽"; return 1
}

wg_deb_format_bytes() {
    local bytes=$1
    [[ -z "$bytes" || "$bytes" == "0" ]] && { echo "0 B"; return; }
    awk -v b="$bytes" 'BEGIN {
        if (b>=1073741824) printf "%.2f GB",b/1073741824
        else if (b>=1048576) printf "%.2f MB",b/1048576
        else if (b>=1024) printf "%.2f KB",b/1024
        else printf "%d B",b
    }'
}

# 检测默认出口网卡
wg_deb_detect_default_iface() {
    ip route show default 2>/dev/null | grep -oP 'dev \K\S+' | head -1
}

# 生成 /etc/wireguard/wg0.conf (Debian 的运行配置)
wg_deb_rebuild_conf() {
    [[ "$(wg_deb_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask mtu
    priv_key=$(wg_deb_db_get '.server.private_key')
    port=$(wg_deb_db_get '.server.port')
    subnet=$(wg_deb_db_get '.server.subnet')
    server_ip=$(wg_deb_db_get '.server.ip')
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        log_action "wg_deb_rebuild_conf failed: missing fields" "ERROR"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT

    # 检测默认出口网卡
    local def_iface
    def_iface=$(wg_deb_db_get '.server.default_iface // empty')
    [[ -z "$def_iface" || "$def_iface" == "null" ]] && def_iface=$(wg_deb_detect_default_iface)
    [[ -z "$def_iface" ]] && def_iface="eth0"

    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "MTU = ${mtu}"
        echo ""
        echo "# NAT + 转发规则"
        echo "PostUp = sysctl -qw net.ipv4.ip_forward=1"
        echo "PostUp = iptables -t nat -A POSTROUTING -s ${subnet} -o ${def_iface} -j MASQUERADE"
        echo "PostUp = iptables -A FORWARD -i ${WG_DEB_INTERFACE} -j ACCEPT"
        echo "PostUp = iptables -A FORWARD -o ${WG_DEB_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT"
        echo "PostDown = iptables -t nat -D POSTROUTING -s ${subnet} -o ${def_iface} -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i ${WG_DEB_INTERFACE} -j ACCEPT"
        echo "PostDown = iptables -D FORWARD -o ${WG_DEB_INTERFACE} -m state --state RELATED,ESTABLISHED -j ACCEPT"

        local pc=$(wg_deb_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_deb_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo ""
                echo "[Peer]"
                echo "# $(wg_deb_db_get ".peers[$i].name")"
                echo "PublicKey = $(wg_deb_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_deb_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_deb_db_get ".peers[$i].ip")
                local is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_deb_db_get ".peers[$i].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" && "$lan_sub" != "null" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
                echo "PersistentKeepalive = 25"
            fi
            i=$((i + 1))
        done
    } > "$WG_DEB_CONF"
    chmod 600 "$WG_DEB_CONF"
}

wg_deb_regenerate_client_confs() {
    local pc=$(wg_deb_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport sdns mask mtu
    spub=$(wg_deb_db_get '.server.public_key')
    sep=$(wg_deb_db_get '.server.endpoint')
    sport=$(wg_deb_db_get '.server.port')
    sdns=$(wg_deb_db_get '.server.dns')
    mask=$(echo "$(wg_deb_db_get '.server.subnet')" | cut -d'/' -f2)
    mtu=$(wg_deb_db_get '.server.mtu // empty')
    [[ -z "$mtu" || "$mtu" == "null" ]] && mtu=$WG_MTU_DIRECT
    mkdir -p "$WG_DEB_CLIENT_DIR"
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_deb_db_get ".peers[$i].name")
        local is_gw=$(wg_deb_db_get ".peers[$i].is_gateway // false")
        local conf_content="[Interface]
PrivateKey = $(wg_deb_db_get ".peers[$i].private_key")
Address = $(wg_deb_db_get ".peers[$i].ip")/${mask}
MTU = ${mtu}"
        [[ "$is_gw" != "true" ]] && conf_content+=$'\n'"DNS = ${sdns}"
        conf_content+="
[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_deb_db_get ".peers[$i].preshared_key")
Endpoint = ${sep}:${sport}
AllowedIPs = $(wg_deb_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        write_file_atomic "${WG_DEB_CLIENT_DIR}/${name}.conf" "$conf_content"
        chmod 600 "${WG_DEB_CLIENT_DIR}/${name}.conf"
        i=$((i + 1))
    done
}
