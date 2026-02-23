# modules/11-wireguard.sh - WireGuard 完整模块
readonly WG_INTERFACE="wg0"
readonly WG_DB_DIR="/etc/wireguard/db"
readonly WG_DB_FILE="${WG_DB_DIR}/wg-data.json"
readonly WG_CONF="/etc/wireguard/${WG_INTERFACE}.conf"
readonly WG_ROLE_FILE="/etc/wireguard/.role"

wg_db_init() {
    mkdir -p "$WG_DB_DIR"
    [[ -f "$WG_DB_FILE" ]] && return 0
    cat > "$WG_DB_FILE" << 'WGEOF'
{
  "role": "",
  "server": {},
  "peers": [],
  "port_forwards": [],
  "client": {}
}
WGEOF
    chmod 600 "$WG_DB_FILE"
}

wg_db_get() { jq -r "$@" "$WG_DB_FILE" 2>/dev/null; }

wg_db_set() {
    local tmp
    tmp=$(mktemp "${WG_DB_DIR}/.tmp.XXXXXX") || { print_error "无法创建临时文件"; return 1; }
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
        if jq "$@" "$WG_DB_FILE" > "$tmp" 2>/dev/null; then
            mv "$tmp" "$WG_DB_FILE"; chmod 600 "$WG_DB_FILE"
        else
            rm -f "$tmp"; print_error "数据库写入失败"; return 1
        fi
    ) 200>"${WG_DB_FILE}.lock"
}

wg_get_role() {
    local role=""
    [[ -f "$WG_ROLE_FILE" ]] && role=$(cat "$WG_ROLE_FILE" 2>/dev/null)
    [[ -z "$role" && -f "$WG_DB_FILE" ]] && role=$(wg_db_get '.role // empty')
    if [[ -z "$role" && -f "$WG_DB_FILE" ]]; then
        local spk=$(wg_db_get '.server.private_key // empty')
        [[ -n "$spk" ]] && role="server"
    fi
    echo "${role:-none}"
}

wg_set_role() {
    mkdir -p /etc/wireguard
    echo "$1" > "$WG_ROLE_FILE"
    chmod 600 "$WG_ROLE_FILE"
    wg_db_set --arg r "$1" '.role = $r' 2>/dev/null || true
}

wg_is_installed() { command_exists wg && [[ -f "$WG_DB_FILE" ]]; }
wg_is_running()   { ip link show "$WG_INTERFACE" &>/dev/null; }

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

wg_ssh_opts() {
    local port="${1:?}" timeout="${2:-10}"
    echo "-o StrictHostKeyChecking=accept-new -o ConnectTimeout=${timeout} -p ${port}"
}

# SSH ControlMaster 连接复用 —— 一次认证，多次使用
wg_ssh_cm_start() {
    local host="${1:?}" port="${2:-22}" user="${3:-root}"
    local cm_dir="/tmp/.wg-ssh-cm"
    mkdir -p "$cm_dir" 2>/dev/null && chmod 700 "$cm_dir" 2>/dev/null
    local cm_socket="${cm_dir}/${user}_${host}_${port}"
    # 检查是否已有活跃的 ControlMaster
    if ssh -o ControlPath="$cm_socket" -O check "${user}@${host}" 2>/dev/null; then
        echo "$cm_socket"
        return 0
    fi
    # 建立新的 ControlMaster（用户仅在此处认证一次）
    ssh -o StrictHostKeyChecking=accept-new \
        -o ControlMaster=yes \
        -o ControlPath="$cm_socket" \
        -o ControlPersist=600 \
        -o ConnectTimeout=15 \
        -p "$port" \
        -fN "${user}@${host}"
    if [[ $? -eq 0 ]]; then
        echo "$cm_socket"
        return 0
    fi
    return 1
}

wg_ssh_cm_stop() {
    local cm_socket="${1:-}"
    [[ -z "$cm_socket" || ! -e "$cm_socket" ]] && return
    ssh -o ControlPath="$cm_socket" -O exit dummy 2>/dev/null || true
    rm -f "$cm_socket" 2>/dev/null || true
}

# 自动部署 SSH 密钥到远程主机（使用已建立的 CM，无需再次认证）
wg_setup_ssh_key_auth() {
    local ssh_opts="$1" ssh_target="$2"
    # 确保本机有密钥
    if [[ ! -f ~/.ssh/id_ed25519.pub && ! -f ~/.ssh/id_rsa.pub ]]; then
        ssh-keygen -t ed25519 -N "" -f ~/.ssh/id_ed25519 -q 2>/dev/null || return 1
    fi
    local pubkey_file
    [[ -f ~/.ssh/id_ed25519.pub ]] && pubkey_file=~/.ssh/id_ed25519.pub || pubkey_file=~/.ssh/id_rsa.pub
    local pubkey_content
    pubkey_content=$(cat "$pubkey_file" 2>/dev/null) || return 1
    ssh $ssh_opts "$ssh_target" "
        mkdir -p ~/.ssh && chmod 700 ~/.ssh
        touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys
        grep -qF '${pubkey_content}' ~/.ssh/authorized_keys 2>/dev/null || echo '${pubkey_content}' >> ~/.ssh/authorized_keys
    " 2>/dev/null
}

wg_install_packages() {
    print_info "安装 WireGuard 软件包..."
    if [[ "$PLATFORM" == "openwrt" ]]; then
        opkg update >/dev/null 2>&1
        for pkg in wireguard-tools qrencode; do
            install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
        done
    else
        update_apt_cache
        for pkg in wireguard wireguard-tools qrencode; do
            install_package "$pkg" "silent" || { print_error "安装 $pkg 失败"; return 1; }
        done
    fi
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
        echo "$used_ips" | grep -qw "$candidate" || { echo "$candidate"; return 0; }
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

wg_save_iptables() {
    if command_exists netfilter-persistent; then
        netfilter-persistent save 2>/dev/null
    elif command_exists iptables-save; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
        iptables-save > /etc/iptables.rules 2>/dev/null
    fi
}

_wg_pf_iptables() {
    local action=$1 proto=$2 ext_port=$3 dest_ip=$4 dest_port=$5
    local iface=$(ip route show default | awk '{print $5; exit}')
    _pf_one() {
        iptables -t nat "$action" PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || true
        iptables "$action" FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || true
    }
    if [[ "$proto" == "tcp+udp" ]]; then _pf_one tcp; _pf_one udp; else _pf_one "$proto"; fi
}

_wg_pf_iptables_ensure() {
    local proto=$1 ext_port=$2 dest_ip=$3 dest_port=$4
    local iface=$(ip route show default | awk '{print $5; exit}')
    _pf_ensure_one() {
        iptables -t nat -C PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || \
        iptables -t nat -A PREROUTING -i "$iface" -p "$1" --dport "$ext_port" \
            -j DNAT --to-destination "${dest_ip}:${dest_port}" 2>/dev/null || true
        iptables -C FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || \
        iptables -A FORWARD -i "$iface" -o "$WG_INTERFACE" -p "$1" \
            --dport "$dest_port" -d "$dest_ip" -j ACCEPT 2>/dev/null || true
    }
    if [[ "$proto" == "tcp+udp" ]]; then _pf_ensure_one tcp; _pf_ensure_one udp; else _pf_ensure_one "$proto"; fi
}

wg_rebuild_conf() {
    [[ "$(wg_get_role)" != "server" ]] && return 1
    local priv_key port subnet server_ip mask main_iface
    priv_key=$(wg_db_get '.server.private_key')
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    server_ip=$(wg_db_get '.server.ip')
    # 关键字段校验
    if [[ -z "$priv_key" || -z "$port" || -z "$subnet" || -z "$server_ip" ]]; then
        print_error "WireGuard 数据库关键字段缺失，无法生成配置"
        log_action "wg_rebuild_conf failed: missing fields (key=${#priv_key} port=$port subnet=$subnet ip=$server_ip)" "ERROR"
        return 1
    fi
    mask=$(echo "$subnet" | cut -d'/' -f2)
    main_iface=$(ip route show default | awk '{print $5; exit}')
    if [[ -z "$main_iface" ]]; then
        print_warn "未检测到默认网关接口，NAT 转发可能无法工作"
        main_iface="eth0"
    fi
    {
        echo "[Interface]"
        echo "PrivateKey = ${priv_key}"
        echo "Address = ${server_ip}/${mask}"
        echo "ListenPort = ${port}"
        echo "PostUp = iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 2 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${subnet} -o ${main_iface} -j MASQUERADE"
        echo "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${subnet} -o ${main_iface} -j MASQUERADE"
        local pc=$(wg_db_get '.peers | length') i=0
        while [[ $i -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$i].enabled")" == "true" ]]; then
                echo "[Peer]"
                echo "PublicKey = $(wg_db_get ".peers[$i].public_key")"
                echo "PresharedKey = $(wg_db_get ".peers[$i].preshared_key")"
                local peer_ip=$(wg_db_get ".peers[$i].ip")
                local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
                local lan_sub=$(wg_db_get ".peers[$i].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" ]]; then
                    echo "AllowedIPs = ${peer_ip}/32, ${lan_sub}"
                else
                    echo "AllowedIPs = ${peer_ip}/32"
                fi
            fi
            i=$((i + 1))
        done
    } > "$WG_CONF"
    chmod 600 "$WG_CONF"
}

wg_regenerate_client_confs() {
    local pc=$(wg_db_get '.peers | length')
    [[ "$pc" -eq 0 ]] && return
    local spub sep sport sdns mask
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')
    mask=$(echo "$(wg_db_get '.server.subnet')" | cut -d'/' -f2)
    mkdir -p /etc/wireguard/clients
    local i=0
    while [[ $i -lt $pc ]]; do
        local name=$(wg_db_get ".peers[$i].name")
        local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        # 条件拼接避免空行问题
        local conf_content="[Interface]
PrivateKey = $(wg_db_get ".peers[$i].private_key")
Address = $(wg_db_get ".peers[$i].ip")/${mask}"
        [[ "$is_gw" != "true" ]] && conf_content+=$'\n'"DNS = ${sdns}"
        conf_content+="
[Peer]
PublicKey = ${spub}
PresharedKey = $(wg_db_get ".peers[$i].preshared_key")
Endpoint = ${sep}:${sport}
AllowedIPs = $(wg_db_get ".peers[$i].client_allowed_ips")
PersistentKeepalive = 25"
        write_file_atomic "/etc/wireguard/clients/${name}.conf" "$conf_content"
        chmod 600 "/etc/wireguard/clients/${name}.conf"
        i=$((i + 1))
    done
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
    print_info "[1/5] 安装软件包..."
    wg_install_packages || { pause; return 1; }
    print_info "[2/5] 配置 IP 转发..."
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
        sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    print_success "IP 转发已开启"
    print_info "[3/5] 配置服务端参数..."
    local wg_port
    while true; do
        read -e -r -p "WireGuard 监听端口 [${WG_DEFAULT_PORT}]: " wg_port
        wg_port=${wg_port:-$WG_DEFAULT_PORT}
        if validate_port "$wg_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done
    local wg_subnet
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
    local wg_dns
    read -e -r -p "客户端 DNS [1.1.1.1, 8.8.8.8]: " wg_dns
    wg_dns=${wg_dns:-"1.1.1.1, 8.8.8.8"}
    local wg_endpoint default_ip
    default_ip=$(get_public_ipv4 || echo "")
    if [[ -n "$default_ip" ]]; then
        read -e -r -p "公网端点 IP/域名 [${default_ip}]: " wg_endpoint
        wg_endpoint=${wg_endpoint:-$default_ip}
    else
        while [[ -z "$wg_endpoint" ]]; do
            read -e -r -p "公网端点 IP/域名: " wg_endpoint
        done
    fi
    print_info "[4/5] 生成服务端密钥..."
    local server_privkey server_pubkey
    server_privkey=$(wg genkey)
    server_pubkey=$(echo "$server_privkey" | wg pubkey)
    print_success "密钥已生成"
    print_info "[5/5] 写入配置并启动..."
    wg_db_init
    wg_set_role "server"
    wg_db_set --arg pk "$server_privkey" \
              --arg pub "$server_pubkey" \
              --arg ip "$server_ip" \
              --arg sub "$wg_subnet" \
              --arg port "$wg_port" \
              --arg dns "$wg_dns" \
              --arg ep "$wg_endpoint" \
    '.server = {
        private_key: $pk,
        public_key: $pub,
        ip: $ip,
        subnet: $sub,
        port: ($port | tonumber),
        dns: $dns,
        endpoint: $ep
    }'
    wg_rebuild_conf
    if [[ "$PLATFORM" == "openwrt" ]]; then
        wg-quick up "$WG_INTERFACE" 2>/dev/null || true
    elif is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${wg_port}/udp" comment "WireGuard" >/dev/null 2>&1
        print_success "UFW 已放行端口 ${wg_port}/udp"
    fi
    draw_line
    if wg_is_running; then
        print_success "WireGuard 服务端安装并启动成功！"
    else
        print_warn "WireGuard 已安装，但启动可能失败，请检查日志"
    fi
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    echo -e "  监听端口: ${C_GREEN}${wg_port}/udp${C_RESET}"
    echo -e "  内网子网: ${C_GREEN}${wg_subnet}${C_RESET}"
    echo -e "  服务端 IP: ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  公网端点: ${C_GREEN}${wg_endpoint}:${wg_port}${C_RESET}"
    draw_line
    log_action "WireGuard server installed: port=$wg_port subnet=$wg_subnet endpoint=$wg_endpoint"

    # 自动安装服务端看门狗
    echo ""
    wg_setup_watchdog "true"

    pause
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
    peer_privkey=$(wg genkey)
    peer_pubkey=$(echo "$peer_privkey" | wg pubkey)
    psk=$(wg genpsk)
    local is_gateway="false"
    local lan_subnets=""
    echo ""
    echo "设备类型:
  1. 普通设备 (手机/电脑/服务器)
  2. 网关设备 (路由器/OpenWrt，需要让其 LAN 内所有设备接入 VPN)"
    read -e -r -p "选择 [1]: " device_type
    device_type=${device_type:-1}
    if [[ "$device_type" == "2" ]]; then
        is_gateway="true"
        echo ""
        print_guide "请输入该网关后面的 LAN 网段 (将被路由到 VPN 中)"
        print_guide "示例: 192.168.1.0/24 或 10.10.100.0/24"
        print_guide "多个网段用逗号分隔: 192.168.1.0/24, 192.168.2.0/24"
        while [[ -z "$lan_subnets" ]]; do
            read -e -r -p "LAN 网段: " lan_subnets
            if [[ -z "$lan_subnets" ]]; then
                print_warn "网关设备必须指定 LAN 网段"
            elif ! echo "$lan_subnets" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+'; then
                print_warn "格式无效，示例: 10.10.100.0/24"
                lan_subnets=""
            fi
        done
    fi
    echo "客户端路由模式:
  1. 全局代理 (所有流量走 VPN) - 0.0.0.0/0
  2. 仅 VPN 内网 (只访问 VPN 内部设备)"
    if [[ "$is_gateway" == "true" ]]; then
        echo "  3. VPN 内网 + 所有网关 LAN 网段 (推荐网关设备)"
    else
        echo "  3. VPN 内网 + 指定 LAN 网段 (访问远程内网设备)"
    fi
    echo "  4. 自定义路由"
    read -e -r -p "选择 [1]: " route_mode
    route_mode=${route_mode:-1}
    local client_allowed_ips server_subnet
    server_subnet=$(wg_db_get '.server.subnet')
        case $route_mode in
        1) client_allowed_ips="0.0.0.0/0, ::/0" ;;
        2) client_allowed_ips="$server_subnet" ;;
        3)
            # 收集所有已有网关的 LAN 网段
            local all_lan_subnets=""
            local pc=$(wg_db_get '.peers | length')
            local pi=0
            while [[ $pi -lt $pc ]]; do
                local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
                if [[ -n "$pls" ]]; then
                    [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
                    all_lan_subnets="${all_lan_subnets}${pls}"
                fi
                pi=$((pi + 1))
            done
            # 当前新设备自己的 LAN 也加入（如果是网关）
            if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
                [[ -n "$all_lan_subnets" ]] && all_lan_subnets="${all_lan_subnets}, "
                all_lan_subnets="${all_lan_subnets}${lan_subnets}"
            fi
            # 去掉自己的 LAN（网关不需要路由自己的 LAN 回隧道）
            if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
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
                    if [[ "$dominated" != "true" ]]; then
                        [[ -n "$other_lans" ]] && other_lans="${other_lans}, "
                        other_lans="${other_lans}${cidr}"
                    fi
                done
                IFS="$IFS_BAK"
                if [[ -n "$other_lans" ]]; then
                    client_allowed_ips="${server_subnet}, ${other_lans}"
                else
                    client_allowed_ips="$server_subnet"
                fi
            else
                if [[ -n "$all_lan_subnets" ]]; then
                    client_allowed_ips="${server_subnet}, ${all_lan_subnets}"
                else
                    print_warn "当前无网关设备注册 LAN 网段，仅路由 VPN 内网"
                    client_allowed_ips="$server_subnet"
                fi
            fi
            ;;
        4)
            read -e -r -p "输入允许的 IP 范围 (逗号分隔): " client_allowed_ips
            [[ -z "$client_allowed_ips" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
            ;;
        *) client_allowed_ips="0.0.0.0/0, ::/0" ;;
    esac
    local spub sep sport sdns
    spub=$(wg_db_get '.server.public_key')
    sep=$(wg_db_get '.server.endpoint')
    sport=$(wg_db_get '.server.port')
    sdns=$(wg_db_get '.server.dns')
    local mask
    mask=$(echo "$server_subnet" | cut -d'/' -f2)
    local dns_line=""
    if [[ "$is_gateway" != "true" ]]; then
        dns_line="DNS = ${sdns}"
    fi
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
        lan_subnets: $lans
    }]'
    if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
        local _pc=$(wg_db_get '.peers | length')
        local _all_lans="" _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            [[ -n "$_pls" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
            _pi=$((_pi + 1))
        done
        _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pname=$(wg_db_get ".peers[$_pi].name")
            [[ "$_pname" == "$peer_name" ]] && { _pi=$((_pi + 1)); continue; }
            local _cur_allowed=$(wg_db_get ".peers[$_pi].client_allowed_ips")
            [[ "$_cur_allowed" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
            local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
            local _own_lans=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            if [[ "$_is_gw" != "true" && "$_cur_allowed" == "$server_subnet" ]]; then
                _pi=$((_pi + 1)); continue
            fi
            if [[ "$_is_gw" == "true" ]]; then
                local _other="" _IFS_BAK="$IFS"; IFS=','
                for _c in $_all_lans; do
                    _c=$(echo "$_c" | xargs); [[ -z "$_c" ]] && continue
                    local _skip=false _IFS2="$IFS"; IFS=','
                    for _o in $_own_lans; do _o=$(echo "$_o" | xargs); [[ "$_c" == "$_o" ]] && { _skip=true; break; }; done
                    IFS="$_IFS2"
                    [[ "$_skip" != "true" ]] && { [[ -n "$_other" ]] && _other="${_other}, "; _other="${_other}${_c}"; }
                done; IFS="$_IFS_BAK"
                local _new="${server_subnet}"
                [[ -n "$_other" ]] && _new="${server_subnet}, ${_other}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            else
                local _new="${server_subnet}, ${_all_lans}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            fi
            _pi=$((_pi + 1))
        done
    fi
    wg_rebuild_conf
    if wg_is_running; then
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") 2>/dev/null || {
            print_warn "热加载失败，尝试重启接口..."
            wg-quick down "$WG_INTERFACE" 2>/dev/null
            wg-quick up "$WG_INTERFACE" 2>/dev/null
        }
        if [[ "$is_gateway" == "true" && -n "$lan_subnets" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $lan_subnets; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && ip route replace "$cidr" dev "$WG_INTERFACE" 2>/dev/null && \
                    print_info "已添加路由: $cidr -> $WG_INTERFACE"
            done
            IFS="$IFS_BAK"
        fi
    fi
    wg_regenerate_client_confs
    draw_line
    print_success "设备 '${peer_name}' 添加成功！"
    draw_line
    echo -e "  名称: ${C_GREEN}${peer_name}${C_RESET}"
    echo -e "  IP:   ${C_GREEN}${peer_ip}${C_RESET}"
    if [[ "$is_gateway" == "true" ]]; then
        echo -e "  类型: ${C_YELLOW}网关设备${C_RESET}"
        echo -e "  LAN:  ${C_CYAN}${lan_subnets}${C_RESET}"
    else
        echo -e "  类型: 普通设备"
    fi
    echo -e "  路由: ${C_CYAN}${client_allowed_ips}${C_RESET}"
    echo -e "  配置: ${C_CYAN}${conf_file}${C_RESET}"
    draw_line
    if [[ "$is_gateway" == "true" ]]; then
        echo -e "${C_YELLOW}[网关设备部署指南]${C_RESET}"
        echo "请选择该网关设备的部署方式:
  1. OpenWrt (uci 命令部署)
  2. 普通 Linux 路由器 (wg-quick)
  3. 跳过，稍后手动部署"
        read -e -r -p "选择 [1]: " gw_deploy
        gw_deploy=${gw_deploy:-1}
        if [[ "$gw_deploy" == "1" ]]; then
            local ep_host="$sep"
            draw_line
            echo -e "${C_CYAN}=== OpenWrt 部署命令 ===${C_RESET}"
            echo -e "${C_YELLOW}在 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
            draw_line
            local uci_allowed_lines=""
            local IFS_BAK="$IFS"
            IFS=','
            for cidr in $client_allowed_ips; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && uci_allowed_lines="${uci_allowed_lines}uci add_list network.wg_server.allowed_ips='${cidr}'
"
            done
            IFS="$IFS_BAK"
                        cat << OPENWRT_EOF

uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
ifdown wg0 2>/dev/null; true
if ! lsmod | grep -q wireguard; then
    opkg update
    opkg install kmod-wireguard || echo '[!] kmod 安装失败，请确认固件已内置 WireGuard 或内核版本匹配'
fi
opkg update
opkg install wireguard-tools luci-proto-wireguard
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'

# LAN -> WG 转发 (LAN 设备访问 VPN 网络)
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'

# WG -> LAN 转发 (VPN 对端访问本地 LAN 设备)
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

OPENWRT_EOF

            # 如果 endpoint 是域名，追加看门狗
            if [[ ! "$ep_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                cat << 'WDEOF'

# === WireGuard 看门狗 (DNS重解析 + 连通性保活) ===
cat > /usr/bin/wg-watchdog.sh << 'WDSCRIPT'
#!/bin/sh
LOG="logger -t wg-watchdog"
if ! ifstatus wg0 &>/dev/null; then
    $LOG "wg0 down, restarting"; ifup wg0; exit 0
fi
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && EP_HOST=""
if [ -n "$EP_HOST" ]; then
    RESOLVED=$(nslookup "$EP_HOST" 2>/dev/null | awk '/^Address:/{a=$2} END{if(a) print a}')
    CURRENT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$CURRENT" ]; then
        $LOG "DNS changed: $CURRENT -> $RESOLVED"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        wg set wg0 peer "$PUB" endpoint "${RESOLVED}:${PORT}"
    fi
fi
VIP=$(uci get network.wg_server.allowed_ips 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
VIP=$(echo "$VIP" | awk -F. '{print $1"."$2"."$3".1"}')
if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" &>/dev/null; then
    if [ -f /tmp/.wg-wd-fail ]; then
        $LOG "ping $VIP failed twice, restarting"
        ifdown wg0; sleep 1; ifup wg0
        rm -f /tmp/.wg-wd-fail
    else
        touch /tmp/.wg-wd-fail
    fi
else
    rm -f /tmp/.wg-wd-fail 2>/dev/null
fi
WDSCRIPT
chmod +x /usr/bin/wg-watchdog.sh
(crontab -l 2>/dev/null | grep -v wg-watchdog; echo '* * * * * /usr/bin/wg-watchdog.sh') | crontab -
/etc/init.d/cron restart
echo '[+] WireGuard 看门狗已安装 (每分钟检测DNS+连通性)'
WDEOF
            fi
            draw_line
            echo -e "${C_GREEN}复制以上全部命令到 OpenWrt SSH 终端执行即可。${C_RESET}"
            echo -e "${C_CYAN}验证方法:${C_RESET}"
            echo "  1. OpenWrt 上执行: wg show
  2. LuCI 界面: Network -> Interfaces 查看 wg0 状态"
            echo "  3. LAN 设备 ping VPN 服务端: ping $(wg_db_get '.server.ip')"
            draw_line
        elif [[ "$gw_deploy" == "2" ]]; then
            draw_line
            echo -e "${C_CYAN}=== Linux 路由器部署步骤 ===${C_RESET}"
            draw_line
            echo "  1. 安装 WireGuard:
     apt install wireguard  # 或对应包管理器
  2. 复制配置文件到路由器:"
            echo "     scp root@$(wg_db_get '.server.endpoint'):${conf_file} /etc/wireguard/wg0.conf"
            echo ""
            echo "  3. 开启 IP 转发:
     echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf && sysctl -p
  4. 启动并设置开机自启:
     wg-quick up wg0
     systemctl enable wg-quick@wg0
  5. 添加 iptables 转发规则 (允许 LAN 流量走 VPN):
     iptables -I FORWARD 1 -i eth0 -o wg0 -j ACCEPT
     iptables -I FORWARD 2 -i wg0 -o eth0 -j ACCEPT
     iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE"
            draw_line
        fi
        echo -e "${C_YELLOW}[通用注意事项]${C_RESET}"
        echo "  • LAN 内设备无需安装任何 VPN 客户端，网关自动代理"
        echo "  • 确保 VPN 子网 ($(wg_db_get '.server.subnet')) 与 LAN 子网 (${lan_subnets}) 不冲突"
        echo "  • 其他 VPN 设备如需访问此网关的 LAN，路由模式选 3 即可
"
    fi
    if confirm "是否显示客户端二维码 (手机扫码导入)?"; then
        echo -e "${C_CYAN}=== ${peer_name} 二维码 ===${C_RESET}"
        qrencode -t ansiutf8 < "$conf_file"
        echo ""
    fi
    if confirm "是否显示客户端配置文本?"; then
        echo -e "${C_CYAN}=== ${peer_name} 配置文件 ===${C_RESET}"
        cat "$conf_file"
        echo ""
    fi
    
    # 集群自动同步提示
    wg_cluster_init_db
    local _cluster_enabled=$(wg_db_get '.cluster.enabled // false')
    local _node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$_cluster_enabled" == "true" && "$_node_count" -gt 0 ]]; then
        echo -e "${C_YELLOW}[集群提示]${C_RESET} 检测到 ${_node_count} 个集群节点"
        if confirm "是否立即同步新设备到所有节点?"; then
            log_action "WireGuard peer added: ${peer_name} (${peer_ip}) gateway=${is_gateway} lan=${lan_subnets}"
            wg_cluster_sync
            return
        fi
    fi
    log_action "WireGuard peer added: ${peer_name} (${peer_ip}) gateway=${is_gateway} lan=${lan_subnets}"
    pause
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
    printf "${C_CYAN}%-4s %-14s %-14s %-6s %-8s %-10s %-10s %s${C_RESET}\n" \
        "#" "名称" "IP" "类型" "状态" "↓接收" "↑发送" "最近握手"
    draw_line
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name ip pubkey enabled is_gw lan_sub
        name=$(wg_db_get ".peers[$i].name")
        ip=$(wg_db_get ".peers[$i].ip")
        pubkey=$(wg_db_get ".peers[$i].public_key")
        enabled=$(wg_db_get ".peers[$i].enabled")
        is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local type_str="普通"
        [[ "$is_gw" == "true" ]] && type_str="${C_YELLOW}网关${C_RESET}"
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
        printf "%-4s %-14s %-14s %-6b %-8b %-10s %-10s %s\n" \
            "$((i + 1))" "$name" "$ip" "$type_str" "$status_str" \
            "$(wg_format_bytes "$rx_bytes")" "$(wg_format_bytes "$tx_bytes")" "$last_handshake"
        i=$((i + 1))
    done
    echo -e "${C_CYAN}共 ${peer_count} 个设备${C_RESET}"
    local gw_found=0
    local gi=0
    while [[ $gi -lt $peer_count ]]; do
        local gw_check=$(wg_db_get ".peers[$gi].is_gateway // false")
        if [[ "$gw_check" == "true" ]]; then
            if [[ $gw_found -eq 0 ]]; then
                echo -e "${C_CYAN}网关设备 LAN 网段:${C_RESET}"
                gw_found=1
            fi
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
            wg_rebuild_conf
            print_success "设备 '${target_name}' 已禁用"
            log_action "WireGuard peer disabled: ${target_name}"
        fi
    else
        if confirm "确认启用设备 '${target_name}'？"; then
            wg_db_set --argjson idx "$target_idx" '.peers[$idx].enabled = true'
            wg_rebuild_conf
            if wg_is_running; then
                wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE") 2>/dev/null || {
                    wg-quick down "$WG_INTERFACE" 2>/dev/null
                    wg-quick up "$WG_INTERFACE" 2>/dev/null
                }
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
    if [[ "$_del_gw" == "true" && -n "$_del_lans" ]]; then
        local _pc=$(wg_db_get '.peers | length')
        local _all_lans="" _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _pls=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
            [[ -n "$_pls" ]] && { [[ -n "$_all_lans" ]] && _all_lans="${_all_lans}, "; _all_lans="${_all_lans}${_pls}"; }
            _pi=$((_pi + 1))
        done
        local server_subnet=$(wg_db_get '.server.subnet')
        _pi=0
        while [[ $_pi -lt $_pc ]]; do
            local _cur=$(wg_db_get ".peers[$_pi].client_allowed_ips")
            [[ "$_cur" == *"0.0.0.0/0"* ]] && { _pi=$((_pi + 1)); continue; }
            [[ "$_cur" == "$server_subnet" ]] && { _pi=$((_pi + 1)); continue; }
            local _is_gw=$(wg_db_get ".peers[$_pi].is_gateway // false")
            local _own=$(wg_db_get ".peers[$_pi].lan_subnets // empty")
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
                [[ -n "$_other" ]] && _new="${server_subnet}, ${_other}"
                wg_db_set --argjson idx "$_pi" --arg a "$_new" '.peers[$idx].client_allowed_ips = $a'
            else
                if [[ -n "$_all_lans" ]]; then
                    wg_db_set --argjson idx "$_pi" --arg a "${server_subnet}, ${_all_lans}" '.peers[$idx].client_allowed_ips = $a'
                else
                    wg_db_set --argjson idx "$_pi" --arg a "$server_subnet" '.peers[$idx].client_allowed_ips = $a'
                fi
            fi
            _pi=$((_pi + 1))
        done
    fi
    rm -f "/etc/wireguard/clients/${target_name}.conf"
    wg_rebuild_conf
    wg_regenerate_client_confs

    # 集群同步提示
    wg_cluster_init_db
    local _cluster_enabled=$(wg_db_get '.cluster.enabled // false')
    local _node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$_cluster_enabled" == "true" && "$_node_count" -gt 0 ]]; then
        if confirm "是否同步删除操作到所有节点?"; then
            print_success "设备 '${target_name}' 已删除"
            log_action "WireGuard peer deleted: ${target_name}"
            wg_cluster_sync
            return
        fi
    fi
    print_success "设备 '${target_name}' 已删除"
    log_action "WireGuard peer deleted: ${target_name}"
    pause
}

wg_show_peer_conf() {
    wg_check_server || return 1
    print_title "查看设备配置 / 二维码"
    wg_select_peer "选择设备序号" true || return
    local target_idx=$REPLY
    local target_name
    target_name=$(wg_db_get ".peers[$target_idx].name")
    local conf_file="/etc/wireguard/clients/${target_name}.conf"
    if [[ ! -f "$conf_file" ]]; then
        print_warn "配置文件不存在，正在从数据库重新生成..."
        local peer_privkey peer_ip peer_psk client_allowed_ips
        peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
        peer_ip=$(wg_db_get ".peers[$target_idx].ip")
        peer_psk=$(wg_db_get ".peers[$target_idx].preshared_key")
        client_allowed_ips=$(wg_db_get ".peers[$target_idx].client_allowed_ips")
        local spub sep sport sdns ssub mask
        spub=$(wg_db_get '.server.public_key')
        sep=$(wg_db_get '.server.endpoint')
        sport=$(wg_db_get '.server.port')
        sdns=$(wg_db_get '.server.dns')
        ssub=$(wg_db_get '.server.subnet')
        mask=$(echo "$ssub" | cut -d'/' -f2)
        local is_gw_check=$(wg_db_get ".peers[$target_idx].is_gateway // false")
        local dns_line="DNS = ${sdns}"
        [[ "$is_gw_check" == "true" ]] && dns_line=""
        local regen_content="[Interface]
PrivateKey = ${peer_privkey}
Address = ${peer_ip}/${mask}
${dns_line}
[Peer]
PublicKey = ${spub}
PresharedKey = ${peer_psk}
Endpoint = ${sep}:${sport}
AllowedIPs = ${client_allowed_ips}
PersistentKeepalive = 25"
        regen_content=$(echo "$regen_content" | sed '/^$/N;/^\n$/d')
        mkdir -p /etc/wireguard/clients
        write_file_atomic "$conf_file" "$regen_content"
        chmod 600 "$conf_file"
        print_success "配置文件已重新生成"
    fi
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
    local is_gateway
    is_gateway=$(wg_db_get ".peers[$target_idx].is_gateway // false")
    if [[ "$is_gateway" == "true" ]]; then
        if confirm "显示 OpenWrt uci 部署命令?"; then
            local peer_privkey peer_ip peer_psk client_allowed_ips
            peer_privkey=$(wg_db_get ".peers[$target_idx].private_key")
            peer_ip=$(wg_db_get ".peers[$target_idx].ip")
            peer_psk=$(wg_db_get ".peers[$target_idx].preshared_key")
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
            echo -e "${C_YELLOW}在 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
            draw_line
            cat << OPENWRT_EOF

uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
ifdown wg0 2>/dev/null; true
if ! lsmod | grep -q wireguard; then
    opkg update
    opkg install kmod-wireguard || echo '[!] kmod 安装失败，请确认固件已内置 WireGuard 或内核版本匹配'
fi
opkg update
opkg install wireguard-tools luci-proto-wireguard
uci set network.wg0=interface
uci set network.wg0.proto='wireguard'
uci set network.wg0.private_key='${peer_privkey}'
uci delete network.wg0.addresses 2>/dev/null; true
uci add_list network.wg0.addresses='${peer_ip}/${mask}'
uci set network.wg_server=wireguard_wg0
uci set network.wg_server.public_key='${spub}'
uci set network.wg_server.preshared_key='${peer_psk}'
uci set network.wg_server.endpoint_host='${ep_host}'
uci set network.wg_server.endpoint_port='${sport}'
uci set network.wg_server.persistent_keepalive='25'
uci set network.wg_server.route_allowed_ips='1'
${uci_allowed_lines}
uci set firewall.wg_zone=zone
uci set firewall.wg_zone.name='wg'
uci set firewall.wg_zone.input='ACCEPT'
uci set firewall.wg_zone.output='ACCEPT'
uci set firewall.wg_zone.forward='ACCEPT'
uci set firewall.wg_zone.masq='1'
uci add_list firewall.wg_zone.network='wg0'

# LAN -> WG 转发 (LAN 设备访问 VPN 网络)
uci set firewall.wg_fwd_lan=forwarding
uci set firewall.wg_fwd_lan.src='lan'
uci set firewall.wg_fwd_lan.dest='wg'

# WG -> LAN 转发 (VPN 对端访问本地 LAN 设备)
uci set firewall.wg_fwd_wg=forwarding
uci set firewall.wg_fwd_wg.src='wg'
uci set firewall.wg_fwd_wg.dest='lan'
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

OPENWRT_EOF

            # 如果 endpoint 是域名，追加看门狗
            if [[ ! "$ep_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                cat << 'WDEOF'

# === WireGuard 看门狗 (DNS重解析 + 连通性保活) ===
cat > /usr/bin/wg-watchdog.sh << 'WDSCRIPT'
#!/bin/sh
LOG="logger -t wg-watchdog"
if ! ifstatus wg0 &>/dev/null; then
    $LOG "wg0 down, restarting"; ifup wg0; exit 0
fi
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && EP_HOST=""
if [ -n "$EP_HOST" ]; then
    RESOLVED=$(nslookup "$EP_HOST" 2>/dev/null | awk '/^Address:/{a=$2} END{if(a) print a}')
    CURRENT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$CURRENT" ]; then
        $LOG "DNS changed: $CURRENT -> $RESOLVED"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        wg set wg0 peer "$PUB" endpoint "${RESOLVED}:${PORT}"
    fi
fi
VIP=$(uci get network.wg_server.allowed_ips 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
VIP=$(echo "$VIP" | awk -F. '{print $1"."$2"."$3".1"}')
if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" &>/dev/null; then
    if [ -f /tmp/.wg-wd-fail ]; then
        $LOG "ping $VIP failed twice, restarting"
        ifdown wg0; sleep 1; ifup wg0
        rm -f /tmp/.wg-wd-fail
    else
        touch /tmp/.wg-wd-fail
    fi
else
    rm -f /tmp/.wg-wd-fail 2>/dev/null
fi
WDSCRIPT
chmod +x /usr/bin/wg-watchdog.sh
(crontab -l 2>/dev/null | grep -v wg-watchdog; echo '* * * * * /usr/bin/wg-watchdog.sh') | crontab -
/etc/init.d/cron restart
echo '[+] WireGuard 看门狗已安装 (每分钟检测DNS+连通性)'
WDEOF
            fi
            draw_line
            echo -e "${C_GREEN}复制以上全部命令到 OpenWrt SSH 终端执行即可。${C_RESET}"
            echo -e "${C_CYAN}验证方法:${C_RESET}"
            echo "  1. OpenWrt 上执行: wg show
  2. LuCI 界面: Network -> Interfaces 查看 wg0 状态"
            echo "  3. LAN 设备 ping VPN 服务端: ping $(wg_db_get '.server.ip')"
            draw_line
        fi
    fi
    echo -e "配置文件路径: ${C_CYAN}${conf_file}${C_RESET}"
    echo -e "下载命令: ${C_GRAY}scp root@服务器IP:${conf_file} ./${C_RESET}"
    pause
}

wg_cluster_init_db() {
    # 确保 DB 中有 cluster 字段
    local has_cluster=$(wg_db_get '.cluster // empty')
    [[ -n "$has_cluster" && "$has_cluster" != "null" ]] && return 0
    wg_db_set '.cluster = {"enabled": false, "nodes": []}' 2>/dev/null
}

wg_cluster_add_node() {
    wg_check_server || return 1
    wg_cluster_init_db
    print_title "添加集群节点"
    local node_name="" node_endpoint="" node_port="" node_ssh_host="" node_ssh_port="" node_ssh_user="" node_ip=""
    while [[ -z "$node_name" ]]; do
        read -e -r -p "节点名称 (如 jp-node, hk-node): " node_name
        [[ ! "$node_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母数字下划线连字符"; node_name=""; }
        local exists=$(wg_db_get --arg n "$node_name" '.cluster.nodes[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "节点名 '$node_name' 已存在"; node_name=""; }
    done
    while [[ -z "$node_endpoint" ]]; do
        read -e -r -p "节点公网 IP 或域名 (如 1.2.3.4 或 jp.example.com): " node_endpoint
    done
    local server_port=$(wg_db_get '.server.port')
    read -e -r -p "节点 WG 端口 [${server_port}]: " node_port
    node_port=${node_port:-$server_port}
    if ! [[ "$node_port" =~ ^[0-9]+$ ]] || ! validate_port "$node_port"; then
        print_error "端口无效，使用默认值 ${server_port}"
        node_port=$server_port
    fi
    echo "节点 VPN 内网 IP 分配:
  本机为 .1，建议其他节点用 .101 .201 等高位段"
    local subnet_prefix=$(wg_db_get '.server.subnet' | cut -d'.' -f1-3)
    while [[ -z "$node_ip" ]]; do
        read -e -r -p "节点 VPN IP [如 ${subnet_prefix}.101]: " node_ip
        if [[ ! "$node_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            print_warn "IP 格式无效"; node_ip=""
        fi
    done
    print_info "SSH 连接信息 (用于同步 Peers 配置)"
    read -e -r -p "SSH 主机 [${node_endpoint}]: " node_ssh_host
    node_ssh_host=${node_ssh_host:-$node_endpoint}
    read -e -r -p "SSH 端口 [22]: " node_ssh_port
    node_ssh_port=${node_ssh_port:-22}
    read -e -r -p "SSH 用户 [root]: " node_ssh_user
    node_ssh_user=${node_ssh_user:-root}
    draw_line
    echo -e "${C_CYAN}节点信息确认:${C_RESET}"
    echo "  名称:       $node_name"
    echo "  Endpoint:   $node_endpoint:$node_port"
    echo "  VPN IP:     $node_ip"
    echo "  SSH:        ${node_ssh_user}@${node_ssh_host}:${node_ssh_port}"
    draw_line
    if ! confirm "确认添加?"; then return; fi
    wg_db_set --arg name "$node_name" \
              --arg ep "$node_endpoint" \
              --argjson port "$node_port" \
              --arg ip "$node_ip" \
              --arg ssh_host "$node_ssh_host" \
              --argjson ssh_port "$node_ssh_port" \
              --arg ssh_user "$node_ssh_user" \
    '.cluster.enabled = true | .cluster.nodes += [{
        name: $name,
        endpoint: $ep,
        port: $port,
        ip: $ip,
        ssh_host: $ssh_host,
        ssh_port: $ssh_port,
        ssh_user: $ssh_user
    }]'
    print_success "集群节点 '${node_name}' 已添加"
    echo -e "${C_YELLOW}[下一步]${C_RESET}"
    echo "  1. 在新节点上运行本脚本，使用 '加入已有集群 (Join)' 功能加入集群"
    echo "  2. 或使用 '一键部署新节点' 功能自动部署 (会自动生成该节点的独立密钥对)"
    echo "  提示: 独立密钥对对于 Clash 多节点同时工作是必须的"
    log_action "WG cluster node added: $node_name ($node_endpoint:$node_port)"
    pause
}

wg_cluster_remove_node() {
    wg_check_server || return 1
    wg_cluster_init_db
    print_title "移除集群节点"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$node_count" -eq 0 ]]; then
        print_warn "暂无集群节点"
        pause; return
    fi
    local i=0
    while [[ $i -lt $node_count ]]; do
        local name=$(wg_db_get ".cluster.nodes[$i].name")
        local ep=$(wg_db_get ".cluster.nodes[$i].endpoint")
        local port=$(wg_db_get ".cluster.nodes[$i].port")
        echo "  $((i+1)). ${name} (${ep}:${port})"
        i=$((i+1))
    done
    echo "  0. 返回"
    read -e -r -p "选择要移除的节点: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$node_count" ]]; then
        print_error "无效序号"; pause; return
    fi
    local ti=$((idx-1))
    local del_name=$(wg_db_get ".cluster.nodes[$ti].name")
    if confirm "确认移除节点 '${del_name}'?"; then
        wg_db_set --argjson idx "$ti" 'del(.cluster.nodes[$idx])'
        local remaining=$(wg_db_get '.cluster.nodes | length')
        [[ "$remaining" -eq 0 ]] && wg_db_set '.cluster.enabled = false'
        print_success "节点 '${del_name}' 已移除"
        log_action "WG cluster node removed: $del_name"
    fi
    pause
}

wg_cluster_sync() {
    wg_check_server || return 1
    wg_cluster_init_db
    print_title "同步 Peers 到所有节点"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$node_count" -eq 0 ]]; then
        print_warn "暂无集群节点"
        pause; return
    fi
    echo "将同步以下内容到所有节点:
  • 所有 Peer 配置 (各节点保留自己的独立密钥，不覆盖)
  • WireGuard 配置文件 (Interface 段密钥来自各节点自身)
  • 数据库文件 (含 public_key + cluster 信息)
"
    if ! confirm "开始同步?"; then return; fi
    local server_pubkey=$(wg_db_get '.server.public_key')
    local server_port=$(wg_db_get '.server.port')
    local server_subnet=$(wg_db_get '.server.subnet')
    local server_dns=$(wg_db_get '.server.dns // "1.1.1.1,8.8.8.8"')
    local my_endpoint=$(wg_db_get '.server.endpoint')
    local my_ip=$(wg_db_get '.server.ip')
    local my_port=$(wg_db_get '.server.port')
    local mask=$(echo "$server_subnet" | cut -d'/' -f2)
    local i=0
    while [[ $i -lt $node_count ]]; do
        local name=$(wg_db_get ".cluster.nodes[$i].name")
        local ssh_host=$(wg_db_get ".cluster.nodes[$i].ssh_host")
        local ssh_port=$(wg_db_get ".cluster.nodes[$i].ssh_port")
        local ssh_user=$(wg_db_get ".cluster.nodes[$i].ssh_user")
        local node_ip=$(wg_db_get ".cluster.nodes[$i].ip")
        local node_ep=$(wg_db_get ".cluster.nodes[$i].endpoint")
        local node_port_db=$(wg_db_get ".cluster.nodes[$i].port")
        echo ""
        print_info "同步到 ${name} (${ssh_user}@${ssh_host}:${ssh_port})..."

        # 生成 peers 段
        local peers_block=""
        local pc=$(wg_db_get '.peers | length') pi=0
        while [[ $pi -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" ]]; then
                peers_block+="\n[Peer]\n"
                peers_block+="PublicKey = $(wg_db_get ".peers[$pi].public_key")\n"
                peers_block+="PresharedKey = $(wg_db_get ".peers[$pi].preshared_key")\n"
                local peer_ip=$(wg_db_get ".peers[$pi].ip")
                local is_gw=$(wg_db_get ".peers[$pi].is_gateway // false")
                local lan_sub=$(wg_db_get ".peers[$pi].lan_subnets // empty")
                if [[ "$is_gw" == "true" && -n "$lan_sub" ]]; then
                    peers_block+="AllowedIPs = ${peer_ip}/32, ${lan_sub}\n"
                else
                    peers_block+="AllowedIPs = ${peer_ip}/32\n"
                fi
            fi
            pi=$((pi+1))
        done

        # 先建立 SSH 连接，再读取目标节点自己的私钥
        local _cm=""
        _cm=$(wg_ssh_cm_start "$ssh_host" "$ssh_port" "$ssh_user" 2>/dev/null) || true
        if [[ -n "$_cm" ]]; then
            local ssh_opts="-o ControlPath=${_cm} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${ssh_port}"
        else
            local ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${ssh_port}"
        fi
        if ssh $ssh_opts "${ssh_user}@${ssh_host}" "mkdir -p /etc/wireguard" 2>/dev/null; then
            # 检测远程节点系统类型（优先从 DB 读取，否则 SSH 检测）
            local remote_os=$(wg_db_get ".cluster.nodes[$i].os // empty")
            if [[ -z "$remote_os" || "$remote_os" == "null" ]]; then
                remote_os=$(ssh $ssh_opts "${ssh_user}@${ssh_host}" '
                    if [ -f /etc/openwrt_release ]; then echo "openwrt"
                    elif [ -f /etc/os-release ]; then . /etc/os-release; echo "$ID"
                    else echo "unknown"; fi
                ' 2>/dev/null)
                # 回写 DB 缓存
                [[ -n "$remote_os" && "$remote_os" != "null" ]] && \
                    wg_db_set --argjson idx "$i" --arg os "$remote_os" '.cluster.nodes[$idx].os = $os' 2>/dev/null || true
            fi

            # 读取目标节点自己的私钥（各节点保留独立密钥，避免 FlClash 会话冲突）
            local target_privkey
            target_privkey=$(ssh $ssh_opts "${ssh_user}@${ssh_host}" \
                "jq -r '.server.private_key // empty' /etc/wireguard/db/wg-data.json 2>/dev/null" 2>/dev/null)
            # 兼容旧部署（无独立密钥或无数据库时，从当前节点的 wg0.conf 中提取）
            if [[ -z "$target_privkey" || "$target_privkey" == "null" ]]; then
                target_privkey=$(ssh $ssh_opts "${ssh_user}@${ssh_host}" \
                    "grep -m1 '^PrivateKey' /etc/wireguard/wg0.conf 2>/dev/null | awk '{print \$3}'" 2>/dev/null)
            fi
            # OpenWrt: 从 uci 读取私钥
            if [[ -z "$target_privkey" || "$target_privkey" == "null" ]] && [[ "$remote_os" == "openwrt" ]]; then
                target_privkey=$(ssh $ssh_opts "${ssh_user}@${ssh_host}" \
                    "uci get network.wg0.private_key 2>/dev/null" 2>/dev/null)
            fi
            # 最终回退到主机密钥（兼容极端情况）
            [[ -z "$target_privkey" || "$target_privkey" == "null" ]] && \
                target_privkey=$(wg_db_get '.server.private_key')

            # 获取目标节点的公钥（从记录或计算）
            local node_pubkey_sync=$(wg_db_get ".cluster.nodes[$i].public_key")
            if [[ -z "$node_pubkey_sync" || "$node_pubkey_sync" == "null" ]]; then
                node_pubkey_sync=$(printf '%s' "$target_privkey" | wg pubkey 2>/dev/null || echo "$server_pubkey")
            fi

            # ── 部署 WireGuard 配置 ──
            local sync_ok="false"
            if [[ "$remote_os" == "openwrt" ]]; then
                # ── OpenWrt: 通过 uci 配置 ──
                local uci_peers_cmds=""
                pi=0
                local peer_idx=0
                while [[ $pi -lt $pc ]]; do
                    if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" ]]; then
                        local p_name=$(wg_db_get ".peers[$pi].name")
                        local p_pubkey=$(wg_db_get ".peers[$pi].public_key")
                        local p_psk=$(wg_db_get ".peers[$pi].preshared_key")
                        local p_ip=$(wg_db_get ".peers[$pi].ip")
                        local p_is_gw=$(wg_db_get ".peers[$pi].is_gateway // false")
                        local p_lan=$(wg_db_get ".peers[$pi].lan_subnets // empty")
                        local peer_section="wg_peer${peer_idx}"
                        uci_peers_cmds+="uci set network.${peer_section}=wireguard_wg0
uci set network.${peer_section}.description='${p_name}'
uci set network.${peer_section}.public_key='${p_pubkey}'
uci set network.${peer_section}.preshared_key='${p_psk}'
uci delete network.${peer_section}.allowed_ips 2>/dev/null; true
uci add_list network.${peer_section}.allowed_ips='${p_ip}/32'
"
                        if [[ "$p_is_gw" == "true" && -n "$p_lan" ]]; then
                            local IFS_BAK="$IFS"; IFS=','
                            for cidr in $p_lan; do
                                cidr=$(echo "$cidr" | xargs)
                                [[ -n "$cidr" ]] && uci_peers_cmds+="uci add_list network.${peer_section}.allowed_ips='${cidr}'
"
                            done
                            IFS="$IFS_BAK"
                        fi
                        uci_peers_cmds+="uci set network.${peer_section}.route_allowed_ips='1'
uci set network.${peer_section}.persistent_keepalive='25'
"
                        peer_idx=$((peer_idx+1))
                    fi
                    pi=$((pi+1))
                done

                ssh $ssh_opts "${ssh_user}@${ssh_host}" "
                    uci delete network.wg0 2>/dev/null; true
                    while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
                        uci delete network.@wireguard_wg0[0] 2>/dev/null; true
                    done
                    uci set network.wg0=interface
                    uci set network.wg0.proto='wireguard'
                    uci set network.wg0.private_key='${target_privkey}'
                    uci set network.wg0.listen_port='${node_port_db:-${server_port}}'
                    uci delete network.wg0.addresses 2>/dev/null; true
                    uci add_list network.wg0.addresses='${node_ip}/${mask}'
                    ${uci_peers_cmds}
                    uci commit network
                    ifdown wg0 2>/dev/null; true
                    /etc/init.d/network reload 2>/dev/null
                    sleep 2
                    ifup wg0 2>/dev/null
                " 2>/dev/null && sync_ok="true" || print_error "${name}: uci 配置失败"
                # wg0.conf 备份（方便私钥读取）
                local tmp_conf=$(mktemp)
                cat > "$tmp_conf" << WGCONF_EOF
[Interface]
PrivateKey = ${target_privkey}
Address = ${node_ip}/${mask}
ListenPort = ${node_port_db:-${server_port}}
$(printf '%b' "$peers_block")
WGCONF_EOF
                scp ${_cm:+-o ControlPath=${_cm}} -P "${ssh_port}" -o StrictHostKeyChecking=accept-new \
                    "$tmp_conf" "${ssh_user}@${ssh_host}:/etc/wireguard/wg0.conf" 2>/dev/null || true
            else
                # ── 标准 Linux: wg-quick 配置 ──
                local tmp_conf=$(mktemp)
                cat > "$tmp_conf" << WGCONF_EOF
[Interface]
PrivateKey = ${target_privkey}
Address = ${node_ip}/${mask}
ListenPort = ${server_port}
PostUp = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 2 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
PostDown = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
$(printf '%b' "$peers_block")
WGCONF_EOF
                if scp ${_cm:+-o ControlPath=${_cm}} -P "${ssh_port}" -o StrictHostKeyChecking=accept-new "$tmp_conf" \
                    "${ssh_user}@${ssh_host}:/etc/wireguard/wg0.conf" 2>/dev/null; then
                    ssh $ssh_opts "${ssh_user}@${ssh_host}" "
                        chmod 600 /etc/wireguard/wg0.conf
                        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
                        grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
                        if ip link show wg0 &>/dev/null; then
                            wg-quick down wg0 2>/dev/null
                            wg-quick up wg0 2>/dev/null
                        else
                            wg-quick up wg0 2>/dev/null
                            systemctl enable wg-quick@wg0 2>/dev/null || true
                        fi
                    " 2>/dev/null && sync_ok="true"
                else
                    print_error "${name}: SCP 上传失败"
                fi
            fi

            # ── 同步数据库到节点（两种路径通用）──
            if [[ "$sync_ok" == "true" ]]; then
                local target_cluster_nodes
                target_cluster_nodes=$(wg_db_get --arg skip_name "$name" \
                    '[.cluster.nodes[] | select(.name != $skip_name)]')
                local my_node_json
                my_node_json=$(jq -n \
                    --arg name "$(hostname -s)" \
                    --arg ep "$my_endpoint" \
                    --argjson port "$my_port" \
                    --arg ip "$my_ip" \
                    --arg pubkey "$server_pubkey" \
                    --arg ssh_host "$my_endpoint" \
                    --argjson ssh_port 22 \
                    --arg ssh_user "root" \
                    '{name:$name, endpoint:$ep, port:$port, ip:$ip, public_key:$pubkey, ssh_host:$ssh_host, ssh_port:$ssh_port, ssh_user:$ssh_user}')
                target_cluster_nodes=$(echo "$target_cluster_nodes" | jq --argjson me "$my_node_json" '. + [$me]')

                local backup_db_content
                backup_db_content=$(jq -n \
                    --arg role "server" \
                    --arg privkey "$target_privkey" \
                    --arg pubkey "$node_pubkey_sync" \
                    --arg subnet "$server_subnet" \
                    --argjson port "${node_port_db:-$server_port}" \
                    --arg ip "$node_ip" \
                    --arg ep "${node_ep}" \
                    --arg dns "$server_dns" \
                    --argjson peers "$(wg_db_get '.peers')" \
                    --argjson pf "$(wg_db_get '.port_forwards // []')" \
                    --argjson cluster_nodes "$target_cluster_nodes" \
                    '{
                        role: $role,
                        server: {
                            private_key: $privkey,
                            public_key: $pubkey,
                            subnet: $subnet,
                            port: $port,
                            ip: $ip,
                            endpoint: $ep,
                            dns: $dns
                        },
                        peers: $peers,
                        port_forwards: $pf,
                        cluster: {
                            enabled: true,
                            nodes: $cluster_nodes
                        }
                    }')
                local tmp_db=$(mktemp)
                echo "$backup_db_content" > "$tmp_db"
                ssh $ssh_opts "${ssh_user}@${ssh_host}" "mkdir -p /etc/wireguard/db" 2>/dev/null || true
                scp ${_cm:+-o ControlPath=${_cm}} -P "${ssh_port}" -o StrictHostKeyChecking=accept-new \
                    "$tmp_db" "${ssh_user}@${ssh_host}:/etc/wireguard/db/wg-data.json" 2>/dev/null || \
                    print_warn "${name}: 数据库同步失败 (不影响运行)"
                ssh $ssh_opts "${ssh_user}@${ssh_host}" "chmod 600 /etc/wireguard/db/wg-data.json 2>/dev/null || true" 2>/dev/null
                rm -f "$tmp_db"
                print_success "${name}: 同步成功 (配置+数据库+集群信息)"
            fi
        else
            print_error "${name}: SSH 连接失败"
        fi
        [[ -n "${tmp_conf:-}" ]] && rm -f "$tmp_conf"; unset tmp_conf
        i=$((i+1))
    done
    print_success "同步完成"
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled // false')
    if [[ "$mesh_enabled" == "true" ]]; then
        echo -e "${C_YELLOW}[Mesh 提示]${C_RESET} Mesh 互联 (wg-mesh) 不受 wg0 同步影响"
        echo "  如需更新 Mesh 配置，请使用 '部署 Mesh 全互联' 重新部署"
    fi
    log_action "WG cluster peers synced to $node_count nodes"
    pause
}

wg_cluster_join() {
    print_title "加入已有集群 (Join)"
    if wg_is_installed && wg_is_running; then
        print_warn "本机已安装并运行 WireGuard"
        if ! confirm "继续将覆盖现有配置，是否继续?"; then return; fi
    fi
    echo -e "${C_CYAN}此功能将从已有集群节点拉取配置并加入集群${C_RESET}"
    echo "  1. 通过 SSH 连接到已有节点
  2. 拉取共享密钥和 Peers 配置
  3. 初始化本机 WireGuard
  4. 注册本机到所有已有节点
"

    # ── 收集已有节点的 SSH 信息 ──
    local remote_ssh_host="" remote_ssh_port="" remote_ssh_user=""
    while [[ -z "$remote_ssh_host" ]]; do
        read -e -r -p "已有节点的 SSH 地址 (IP 或域名): " remote_ssh_host
    done
    read -e -r -p "SSH 端口 [22]: " remote_ssh_port
    remote_ssh_port=${remote_ssh_port:-22}
    read -e -r -p "SSH 用户 [root]: " remote_ssh_user
    remote_ssh_user=${remote_ssh_user:-root}

    # ── 收集本机信息 ──
    local my_name="" my_endpoint="" my_port="" my_ip=""
    while [[ -z "$my_name" ]]; do
        read -e -r -p "本机节点名称 (如 hk-node, us-node): " my_name
        [[ ! "$my_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母数字下划线连字符"; my_name=""; }
    done
    while [[ -z "$my_endpoint" ]]; do
        read -e -r -p "本机公网 IP 或域名: " my_endpoint
    done
    read -e -r -p "本机 WG 端口 [50000]: " my_port
    my_port=${my_port:-50000}
    while [[ -z "$my_ip" ]]; do
        read -e -r -p "本机 VPN 内网 IP (如 10.66.66.101): " my_ip
        [[ ! "$my_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { print_warn "IP 格式无效"; my_ip=""; }
    done

    draw_line
    echo -e "${C_CYAN}确认信息:${C_RESET}"
    echo "  远程节点:   ${remote_ssh_user}@${remote_ssh_host}:${remote_ssh_port}"
    echo "  本机名称:   $my_name"
    echo "  本机 Endpoint: $my_endpoint:$my_port"
    echo "  本机 VPN IP:   $my_ip"
    draw_line
    if ! confirm "开始加入集群?"; then return; fi

    # ── Step 1: SSH 连接 ──
    print_info "[1/5] 建立 SSH 连接..."
    local cm_socket
    cm_socket=$(wg_ssh_cm_start "$remote_ssh_host" "$remote_ssh_port" "$remote_ssh_user")
    if [[ $? -ne 0 || -z "$cm_socket" ]]; then
        print_error "SSH 连接失败"
        pause; return 1
    fi
    local ssh_opts="-o ControlPath=${cm_socket} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p ${remote_ssh_port}"
    local ssh_target="${remote_ssh_user}@${remote_ssh_host}"
    print_success "SSH 连接成功"

    # ── Step 2: 拉取远程数据库 ──
    print_info "[2/5] 拉取集群数据..."
    local remote_db
    remote_db=$(ssh $ssh_opts "$ssh_target" "cat /etc/wireguard/db/wg-data.json 2>/dev/null" 2>/dev/null)
    if [[ -z "$remote_db" ]] || ! echo "$remote_db" | jq '.' >/dev/null 2>&1; then
        print_error "无法读取远程节点数据库 (/etc/wireguard/db/wg-data.json)"
        pause; return 1
    fi
    local server_subnet=$(echo "$remote_db" | jq -r '.server.subnet')
    local server_dns=$(echo "$remote_db" | jq -r '.server.dns // "1.1.1.1,8.8.8.8"')
    local remote_pubkey=$(echo "$remote_db" | jq -r '.server.public_key')
    # 注意：不从远程数据库复制 private_key，本机保留自己的独立密钥对（避免 FlClash 会话冲突）
    if [[ -z "$server_subnet" || "$server_subnet" == "null" ]]; then
        print_error "远程数据库中没有有效的子网信息"
        pause; return 1
    fi
    print_success "数据拉取成功"

    # ── Step 3: 初始化本机 WireGuard ──
    print_info "[3/5] 初始化本机 WireGuard..."
    # 使用本机独立密钥对（如已有则复用，否则生成新的）
    local my_privkey my_pubkey
    if [[ -f /etc/wireguard/wg0.conf ]]; then
        my_privkey=$(grep -m1 '^PrivateKey' /etc/wireguard/wg0.conf | awk '{print $3}')
    fi
    if [[ -z "$my_privkey" ]]; then
        my_privkey=$(wg genkey)
        print_info "已为本机生成新的独立 WireGuard 密钥对"
    else
        print_info "复用本机现有 WireGuard 私钥"
    fi
    my_pubkey=$(printf '%s' "$my_privkey" | wg pubkey)
    print_success "本机公钥: ${my_pubkey:0:20}..."
    # 安装 WireGuard（如果未安装）
    if ! command_exists wg; then
        print_info "安装 WireGuard..."
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            case "$ID" in
                ubuntu|debian)
                    export DEBIAN_FRONTEND=noninteractive
                    apt-get update -qq >/dev/null 2>&1
                    apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
                    ;;
                centos|rhel|rocky|alma)
                    if command_exists dnf; then
                        dnf install -y epel-release >/dev/null 2>&1 || true
                        dnf install -y wireguard-tools >/dev/null 2>&1
                    else
                        yum install -y epel-release >/dev/null 2>&1 || true
                        yum install -y wireguard-tools >/dev/null 2>&1
                    fi
                    ;;
                fedora)
                    dnf install -y wireguard-tools >/dev/null 2>&1
                    ;;
                alpine)
                    apk add wireguard-tools >/dev/null 2>&1
                    ;;
                *)
                    print_error "不支持的系统: $ID"
                    pause; return 1
                    ;;
            esac
        fi
        if ! command_exists wg; then
            print_error "WireGuard 安装失败"
            pause; return 1
        fi
    fi

    local mask=$(echo "$server_subnet" | cut -d'/' -f2)
    # 生成 peers 段
    local peers_block=""
    local pc=$(echo "$remote_db" | jq '.peers | length') pi=0
    while [[ $pi -lt $pc ]]; do
        local p_enabled=$(echo "$remote_db" | jq -r ".peers[$pi].enabled")
        if [[ "$p_enabled" == "true" ]]; then
            peers_block+="\n[Peer]\n"
            peers_block+="PublicKey = $(echo "$remote_db" | jq -r ".peers[$pi].public_key")\n"
            peers_block+="PresharedKey = $(echo "$remote_db" | jq -r ".peers[$pi].preshared_key")\n"
            local p_ip=$(echo "$remote_db" | jq -r ".peers[$pi].ip")
            local p_gw=$(echo "$remote_db" | jq -r ".peers[$pi].is_gateway // false")
            local p_lan=$(echo "$remote_db" | jq -r ".peers[$pi].lan_subnets // empty")
            if [[ "$p_gw" == "true" && -n "$p_lan" ]]; then
                peers_block+="AllowedIPs = ${p_ip}/32, ${p_lan}\n"
            else
                peers_block+="AllowedIPs = ${p_ip}/32\n"
            fi
        fi
        pi=$((pi+1))
    done

    mkdir -p /etc/wireguard
    cat > /etc/wireguard/wg0.conf << WGCONF_EOF
[Interface]
PrivateKey = ${my_privkey}
Address = ${my_ip}/${mask}
ListenPort = ${my_port}
PostUp = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 2 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
PostDown = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
$(printf '%b' "$peers_block")
WGCONF_EOF
    chmod 600 /etc/wireguard/wg0.conf

    # 开启 IP 转发
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf 2>/dev/null || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

    # 构建本机的 cluster.nodes（远程节点 + 远程节点的所有其他节点）
    local remote_endpoint=$(echo "$remote_db" | jq -r '.server.endpoint')
    local remote_port=$(echo "$remote_db" | jq -r '.server.port')
    local remote_ip=$(echo "$remote_db" | jq -r '.server.ip')
    local remote_name
    remote_name=$(ssh $ssh_opts "$ssh_target" "hostname -s" 2>/dev/null)
    [[ -z "$remote_name" ]] && remote_name="remote-node"

    # 本机的 cluster.nodes = 远程节点信息 + 远程节点已有的其他 cluster nodes
    local remote_cluster_nodes=$(echo "$remote_db" | jq '.cluster.nodes // []')
    local remote_node_json
    remote_node_json=$(jq -n \
        --arg name "$remote_name" \
        --arg ep "$remote_endpoint" \
        --argjson port "$remote_port" \
        --arg ip "$remote_ip" \
        --arg pubkey "$remote_pubkey" \
        --arg ssh_host "$remote_ssh_host" \
        --argjson ssh_port "$remote_ssh_port" \
        --arg ssh_user "$remote_ssh_user" \
        '{name:$name, endpoint:$ep, port:$port, ip:$ip, public_key:$pubkey, ssh_host:$ssh_host, ssh_port:$ssh_port, ssh_user:$ssh_user}')
    local my_cluster_nodes
    my_cluster_nodes=$(echo "$remote_cluster_nodes" | jq --argjson rn "$remote_node_json" '. + [$rn]')

    # 初始化本机数据库（使用本机独立密钥对）
    mkdir -p /etc/wireguard/db
    jq -n \
        --arg role "server" \
        --arg privkey "$my_privkey" \
        --arg pubkey "$my_pubkey" \
        --arg subnet "$server_subnet" \
        --argjson port "$my_port" \
        --arg ip "$my_ip" \
        --arg ep "$my_endpoint" \
        --arg dns "$server_dns" \
        --argjson peers "$(echo "$remote_db" | jq '.peers // []')" \
        --argjson pf "$(echo "$remote_db" | jq '.port_forwards // []')" \
        --argjson cluster_nodes "$my_cluster_nodes" \
        '{
            role: $role,
            server: {
                private_key: $privkey,
                public_key: $pubkey,
                subnet: $subnet,
                port: $port,
                ip: $ip,
                endpoint: $ep,
                dns: $dns
            },
            peers: $peers,
            port_forwards: $pf,
            cluster: {
                enabled: true,
                nodes: $cluster_nodes
            }
        }' > /etc/wireguard/db/wg-data.json
    chmod 600 /etc/wireguard/db/wg-data.json
    echo 'server' > /etc/wireguard/.role
    chmod 600 /etc/wireguard/.role
    print_success "本机 WireGuard 配置完成"

    # ── Step 4: 启动 WireGuard ──
    print_info "[4/5] 启动 WireGuard..."
    ip link show wg0 &>/dev/null && wg-quick down wg0 2>/dev/null || true
    wg-quick up wg0 2>/dev/null
    systemctl enable wg-quick@wg0 2>/dev/null || true
    if ip link show wg0 &>/dev/null; then
        print_success "WireGuard 已启动"
    else
        print_error "WireGuard 启动失败"
        echo "  请检查: journalctl -u wg-quick@wg0"
    fi

    # ── Step 5: 注册本机到所有已有节点 ──
    print_info "[5/5] 注册本机到所有已有节点..."
    local my_node_json
    my_node_json=$(jq -n \
        --arg name "$my_name" \
        --arg ep "$my_endpoint" \
        --argjson port "$my_port" \
        --arg ip "$my_ip" \
        --arg pubkey "$my_pubkey" \
        --arg ssh_host "$my_endpoint" \
        --argjson ssh_port 22 \
        --arg ssh_user "root" \
        '{name:$name, endpoint:$ep, port:$port, ip:$ip, public_key:$pubkey, ssh_host:$ssh_host, ssh_port:$ssh_port, ssh_user:$ssh_user}')

    # 注册到远程节点（含本机公钥，供远程节点生成 Clash 配置时使用）
    local add_cmd="
        if [ -f /etc/wireguard/db/wg-data.json ]; then
            jq --arg name '${my_name}' \
               --arg ep '${my_endpoint}' \
               --argjson port ${my_port} \
               --arg ip '${my_ip}' \
               --arg pubkey '${my_pubkey}' \
               --arg ssh_host '${my_endpoint}' \
               --argjson ssh_port 22 \
               --arg ssh_user 'root' \
               '.cluster.enabled = true | .cluster.nodes += [{name:\$name,endpoint:\$ep,port:\$port,ip:\$ip,public_key:\$pubkey,ssh_host:\$ssh_host,ssh_port:\$ssh_port,ssh_user:\$ssh_user}]' \
               /etc/wireguard/db/wg-data.json > /tmp/.wg-db-tmp.json && \
            mv /tmp/.wg-db-tmp.json /etc/wireguard/db/wg-data.json && \
            chmod 600 /etc/wireguard/db/wg-data.json && echo 'NODE_ADDED'
        else
            echo 'NO_DB'
        fi
    "
    local result
    result=$(ssh $ssh_opts "$ssh_target" "$add_cmd" 2>/dev/null) || true
    if [[ "$result" == *"NODE_ADDED"* ]]; then
        print_success "  ${remote_name}: 已注册"
    else
        print_warn "  ${remote_name}: 注册失败 (${result:-SSH连接失败})"
    fi

    # 注册到远程节点的其他集群节点
    local other_count=$(echo "$remote_cluster_nodes" | jq 'length')
    local oi=0
    while [[ $oi -lt $other_count ]]; do
        local o_name=$(echo "$remote_cluster_nodes" | jq -r ".[$oi].name")
        local o_ssh_host=$(echo "$remote_cluster_nodes" | jq -r ".[$oi].ssh_host")
        local o_ssh_port=$(echo "$remote_cluster_nodes" | jq -r ".[$oi].ssh_port")
        local o_ssh_user=$(echo "$remote_cluster_nodes" | jq -r ".[$oi].ssh_user")
        local _ocm=""
        _ocm=$(wg_ssh_cm_start "$o_ssh_host" "$o_ssh_port" "$o_ssh_user" 2>/dev/null) || true
        local o_ssh_opts=""
        if [[ -n "$_ocm" ]]; then
            o_ssh_opts="-o ControlPath=${_ocm} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${o_ssh_port}"
        else
            o_ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${o_ssh_port}"
        fi
        local o_add_cmd="
            if [ -f /etc/wireguard/db/wg-data.json ]; then
                jq --arg name '${my_name}' \
                   --arg ep '${my_endpoint}' \
                   --argjson port ${my_port} \
                   --arg ip '${my_ip}' \
                   --arg pubkey '${my_pubkey}' \
                   --arg ssh_host '${my_endpoint}' \
                   --argjson ssh_port 22 \
                   --arg ssh_user 'root' \
                   '.cluster.enabled = true | .cluster.nodes += [{name:\$name,endpoint:\$ep,port:\$port,ip:\$ip,public_key:\$pubkey,ssh_host:\$ssh_host,ssh_port:\$ssh_port,ssh_user:\$ssh_user}]' \
                   /etc/wireguard/db/wg-data.json > /tmp/.wg-db-tmp.json && \
                mv /tmp/.wg-db-tmp.json /etc/wireguard/db/wg-data.json && \
                chmod 600 /etc/wireguard/db/wg-data.json && echo 'NODE_ADDED'
            else
                echo 'NO_DB'
            fi
        "
        local o_result
        o_result=$(ssh $o_ssh_opts "${o_ssh_user}@${o_ssh_host}" "$o_add_cmd" 2>/dev/null) || true
        if [[ "$o_result" == *"NODE_ADDED"* ]]; then
            print_success "  ${o_name}: 已注册"
        else
            print_warn "  ${o_name}: 注册失败 (${o_result:-SSH连接失败})"
        fi
        [[ -n "$_ocm" ]] && ssh -O exit -o ControlPath="${_ocm}" "${o_ssh_user}@${o_ssh_host}" 2>/dev/null || true
        oi=$((oi+1))
    done

    # 关闭 SSH 连接
    ssh -O exit -o ControlPath="${cm_socket}" "$ssh_target" 2>/dev/null || true

    draw_line
    print_success "成功加入集群！"
    draw_line
    echo -e "  ${C_CYAN}后续操作:${C_RESET}"
    echo "  • 使用 '同步 Peers' 确保所有节点配置一致
  • 使用 '部署 Mesh' 建立节点间互通
  • 使用 '集群健康仪表盘' 监控所有节点"
    log_action "WG cluster joined via ${remote_ssh_host}, node=${my_name} ip=${my_ip}"
    pause
}

wg_generate_clash_config() {
    wg_check_server || return 1
    print_title "生成 Clash (OpenClash) WireGuard 配置"
    local peer_count=$(wg_db_get '.peers | length')
    if [[ "$peer_count" -eq 0 ]]; then
        print_warn "暂无设备，请先添加 Peer"
        pause; return
    fi

    # 选择设备
    echo "选择要生成 Clash 配置的设备:"
    local i=0
    while [[ $i -lt $peer_count ]]; do
        local name=$(wg_db_get ".peers[$i].name")
        local ip=$(wg_db_get ".peers[$i].ip")
        local is_gw=$(wg_db_get ".peers[$i].is_gateway // false")
        local mark=""
        [[ "$is_gw" == "true" ]] && mark=" ${C_YELLOW}(网关)${C_RESET}"
        echo -e "  $((i+1)). ${name} (${ip})${mark}"
        i=$((i+1))
    done
    echo "  0. 返回"
    read -e -r -p "选择设备序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt "$peer_count" ]]; then
        print_error "无效序号"; pause; return
    fi
    local ti=$((idx-1))
    local peer_name=$(wg_db_get ".peers[$ti].name")
    local peer_ip=$(wg_db_get ".peers[$ti].ip")
    local peer_privkey=$(wg_db_get ".peers[$ti].private_key")
    local peer_psk=$(wg_db_get ".peers[$ti].preshared_key")
    local server_pubkey=$(wg_db_get '.server.public_key')
    local server_endpoint=$(wg_db_get '.server.endpoint')
    local server_port=$(wg_db_get '.server.port')
    local server_subnet=$(wg_db_get '.server.subnet')
    local server_dns=$(wg_db_get '.server.dns' | cut -d',' -f1 | xargs)
    local mask=$(echo "$server_subnet" | cut -d'/' -f2)

    # 收集所有 VPN 路由网段
    local vpn_cidrs=("$server_subnet")
    local pi=0
    while [[ $pi -lt $peer_count ]]; do
        local pls=$(wg_db_get ".peers[$pi].lan_subnets // empty")
        if [[ -n "$pls" ]]; then
            local IFS_BAK="$IFS"; IFS=','
            for cidr in $pls; do
                cidr=$(echo "$cidr" | xargs)
                [[ -n "$cidr" ]] && vpn_cidrs+=("$cidr")
            done
            IFS="$IFS_BAK"
        fi
        pi=$((pi+1))
    done
        # 收集 mesh 节点 LAN 网段
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled // false')
    if [[ "$mesh_enabled" == "true" ]]; then
        local mnc=$(wg_db_get '.cluster.mesh.nodes | length')
        local mi=0
        while [[ $mi -lt $mnc ]]; do
            local mlan=$(wg_db_get ".cluster.mesh.nodes[$mi].lan // empty")
            [[ -n "$mlan" ]] && vpn_cidrs+=("$mlan")
            mi=$((mi+1))
        done
    fi
    local -a unique_cidrs
    mapfile -t unique_cidrs < <(printf '%s\n' "${vpn_cidrs[@]}" | sort -u)

    # 检测集群节点
    wg_cluster_init_db
    local cluster_enabled=$(wg_db_get '.cluster.enabled')
    local node_count=$(wg_db_get '.cluster.nodes | length')
    local has_cluster=false
    [[ "$cluster_enabled" == "true" && "$node_count" -gt 0 ]] && has_cluster=true
    if [[ "$has_cluster" == "true" ]]; then
        echo -e "${C_GREEN}检测到集群配置 (${node_count} 个节点)${C_RESET}"
        echo "Clash 代理组模式:
  1. url-test (自动选最低延迟，推荐)
  2. fallback (故障自动切换)
  3. select (手动选择)
  4. 单节点 (不使用集群，仅本机)"
        read -e -r -p "选择 [1]: " group_mode
        group_mode=${group_mode:-1}
    else
        group_mode=4
    fi
    local tolerance=50 interval=15
    if [[ "$group_mode" == "1" ]]; then
        read -e -r -p "延迟容差 ms (差值超过此值才切换) [50]: " tolerance
        tolerance=${tolerance:-50}
        read -e -r -p "测速间隔 秒 [15]: " interval
        interval=${interval:-15}
    elif [[ "$group_mode" == "2" ]]; then
        read -e -r -p "检测间隔 秒 [15]: " interval
        interval=${interval:-15}
    fi

    # ── 构建 proxy 节点列表 ──
    local all_proxy_names=()
    local all_proxy_yaml=""

    # 主机节点
    local primary_name="WG-本机"
    all_proxy_names+=("$primary_name")
    all_proxy_yaml+="  - name: \"${primary_name}\"
    type: wireguard
    server: ${server_endpoint}
    port: ${server_port}
    ip: ${peer_ip}
    private-key: \"${peer_privkey}\"
    public-key: \"${server_pubkey}\"
    pre-shared-key: \"${peer_psk}\"
    reserved: [0, 0, 0]
    udp: true
    mtu: 1280
    remote-dns-resolve: false
    dns:
      - ${server_dns}
"

    # 其他节点（每个节点有独立公钥，避免 FlClash/mihomo 将相同 public-key 的多个 proxy 视为同一 peer 而产生会话冲突）
    if [[ "$has_cluster" == "true" && "$group_mode" != "4" ]]; then
        local ni=0
        while [[ $ni -lt $node_count ]]; do
            local nname=$(wg_db_get ".cluster.nodes[$ni].name")
            local nep=$(wg_db_get ".cluster.nodes[$ni].endpoint")
            local nport=$(wg_db_get ".cluster.nodes[$ni].port")
            local npubkey=$(wg_db_get ".cluster.nodes[$ni].public_key")
            # 兼容旧数据（未记录 public_key 的历史节点）：回退到本机公钥，但会有会话冲突
            if [[ -z "$npubkey" || "$npubkey" == "null" ]]; then
                npubkey="$server_pubkey"
                print_warn "节点 ${nname} 未记录独立公钥，使用共享公钥（可能导致 FlClash 会话冲突）"
                echo "  → 建议重新部署该节点以生成独立密钥对"
            fi
            local proxy_name="WG-${nname}"
            all_proxy_names+=("$proxy_name")
            all_proxy_yaml+="
  - name: \"${proxy_name}\"
    type: wireguard
    server: ${nep}
    port: ${nport}
    ip: ${peer_ip}
    private-key: \"${peer_privkey}\"
    public-key: \"${npubkey}\"
    pre-shared-key: \"${peer_psk}\"
    reserved: [0, 0, 0]
    udp: true
    mtu: 1280
    remote-dns-resolve: false
    dns:
      - ${server_dns}
"
            ni=$((ni+1))
        done
    fi

    # ── 构建 proxy-group ──
    local group_name="WireGuard-VPN"
    local proxy_list_yaml=""
    for pn in "${all_proxy_names[@]}"; do
        proxy_list_yaml+="      - ${pn}
"
    done
    local wg_group_yaml=""
    case $group_mode in
        1)
            wg_group_yaml="  - name: ${group_name}
    type: url-test
    proxies:
${proxy_list_yaml}    url: http://www.gstatic.com/generate_204
    interval: ${interval}
    tolerance: ${tolerance}"
            ;;
        2)
            wg_group_yaml="  - name: ${group_name}
    type: fallback
    proxies:
${proxy_list_yaml}    url: http://www.gstatic.com/generate_204
    interval: ${interval}"
            ;;
        3)
            wg_group_yaml="  - name: ${group_name}
    type: select
    proxies:
${proxy_list_yaml}      - DIRECT"
            ;;
        4)
            # 单节点模式
            wg_group_yaml="  - name: ${group_name}
    type: select
    proxies:
      - ${all_proxy_names[0]}
      - DIRECT"
            ;;
    esac

    # ── 构建 rules ──
    local wg_rules_yaml=""
    # 所有服务器 endpoint 走 DIRECT（防止死循环）
    if [[ "$server_endpoint" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        wg_rules_yaml+="  - IP-CIDR,${server_endpoint}/32,DIRECT
"
    else
        wg_rules_yaml+="  - DOMAIN,${server_endpoint},DIRECT
"
    fi
    if [[ "$has_cluster" == "true" && "$group_mode" != "4" ]]; then
        local ni=0
        while [[ $ni -lt $node_count ]]; do
            local nep=$(wg_db_get ".cluster.nodes[$ni].endpoint")
            if [[ "$nep" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                wg_rules_yaml+="  - IP-CIDR,${nep}/32,DIRECT
"
            else
                wg_rules_yaml+="  - DOMAIN,${nep},DIRECT
"
            fi
            ni=$((ni+1))
        done
    fi
    for cidr in "${unique_cidrs[@]}"; do
        wg_rules_yaml+="  - IP-CIDR,${cidr},${group_name}
"
    done

    # ── 输出 ──
    draw_line
    echo -e "${C_CYAN}设备: ${peer_name} | 节点数: ${#all_proxy_names[@]}${C_RESET}"
    if [[ "$has_cluster" == "true" && "$group_mode" != "4" ]]; then
        local mode_str="url-test"
        [[ "$group_mode" == "2" ]] && mode_str="fallback"
        [[ "$group_mode" == "3" ]] && mode_str="select"
        echo -e "  模式: ${C_GREEN}${mode_str}${C_RESET}"
        echo -e "  节点: ${all_proxy_names[*]}"
    fi
    draw_line
    echo ""
    echo "请选择操作方式:
  1. 生成 YAML 片段 (手动合并到现有配置)
  2. 粘贴现有 YAML，自动注入 WireGuard 规则
  0. 返回"
    read -e -r -p "选择 [1]: " gen_mode
    gen_mode=${gen_mode:-1}
    case $gen_mode in
        1)
            draw_line
            echo -e "${C_CYAN}=== 需要添加到 YAML 的内容 ===${C_RESET}"
            draw_line
            echo -e "${C_YELLOW}# ━━━ 第1步: 在 proxies: 段末尾添加 ━━━${C_RESET}"
            echo "$all_proxy_yaml"
            echo -e "${C_YELLOW}# ━━━ 第2步: 在 proxy-groups: 段末尾添加 ━━━${C_RESET}"
            echo "$wg_group_yaml"
            echo -e "${C_YELLOW}# ━━━ 第3步: 在 rules: 段最前面添加 ━━━${C_RESET}"
            echo -n "$wg_rules_yaml"
            draw_line
            if [[ ${#all_proxy_names[@]} -gt 1 ]]; then
                echo -e "${C_CYAN}[多节点说明]${C_RESET}"
                echo "  • 所有节点共享同一密钥，客户端 IP 相同"
                echo "  • Clash 自动在 ${#all_proxy_names[@]} 个节点间选择最优"
                echo "  • 服务器 Endpoint 全部走 DIRECT 防止死循环
"
            fi
                        echo -e "${C_YELLOW}要求: Clash Meta (mihomo) 内核 1.14.0+${C_RESET}"
            echo -e "${C_YELLOW}OpenClash 请在设置中切换到 Meta 内核${C_RESET}"
            echo ""
            echo -e "${C_YELLOW}[DNS 提示] 如果使用 proxy-providers 订阅，请在 dns.nameserver-policy 中添加:${C_RESET}"
            echo -e "  nameserver-policy:"
            echo -e "    \"+.你的订阅域名\": [223.5.5.5, 114.114.114.114]"
            echo -e "  ${C_DIM}(避免 DNS 鸡蛋问题: fallback DNS 需代理，但代理尚未建立)${C_RESET}"
            draw_line
            ;;
        2)
            echo -e "${C_CYAN}请粘贴你现有的完整 YAML 配置 (粘贴完成后按 Ctrl+D):${C_RESET}"
            local original_yaml
            original_yaml=$(cat)
            if [[ -z "$original_yaml" ]]; then
                print_error "内容为空"; pause; return
            fi
            if ! echo "$original_yaml" | grep -qE '^[[:space:]]*proxies:'; then
                print_error "YAML 中未找到 'proxies:' 段"
                pause; return
            fi
            local output_file="/tmp/clash-wg-${peer_name}-$(date +%s).yaml"

            # 用 Python/jq 辅助或简单 awk 注入
            # 改进: 追踪缩进层级判断段结束
            awk \
                -v proxy_nodes="$all_proxy_yaml" \
                -v proxy_group="$wg_group_yaml" \
                -v rules="$wg_rules_yaml" \
            '
            BEGIN { state="init"; proxy_done=0; group_done=0; rule_done=0 }

            # 检测顶级 key (行首非空格开头，含冒号)
            function is_top_key(line) {
                return (line ~ /^[a-zA-Z_-]+:/)
            }
            /^proxies:/ { state="proxies"; print; next }
            /^proxy-groups:/ {
                if(state=="proxies" && !proxy_done) {
                    print ""; print proxy_nodes;
                    proxy_done=1
                }
                state="groups"; print; next
            }
            /^rules:/ {
                if(state=="groups" && !group_done) {
                    print ""; print proxy_group; print "";
                    group_done=1
                }
                print $0
                print "  # === WireGuard VPN 路由规则 (自动生成) ==="
                printf "%s", rules
                rule_done=1
                state="rules"
                next
            }

            # 其他顶级 key 触发前一个段的注入
            is_top_key($0) && state=="proxies" && !proxy_done {
                print ""; print proxy_nodes; proxy_done=1; state="init"
            }
            is_top_key($0) && state=="groups" && !group_done {
                print ""; print proxy_group; print ""; group_done=1; state="init"
            }
            { print }
            END {
                if(!proxy_done) { print ""; print proxy_nodes }
                if(!group_done) { print ""; print proxy_group }
                if(!rule_done) { print ""; print "rules:"; print "  # === WireGuard VPN 路由规则 ==="; printf "%s", rules }
            }
            ' <<< "$original_yaml" > "$output_file"

            # ── 自动注入 nameserver-policy: 订阅域名走国内 DNS 直连解析 ──
            # 避免 DNS 鸡蛋问题: fallback DNS (Google/Cloudflare DoH) 需要代理才能访问
            # 但此时代理尚未建立，订阅 URL 无法解析 → 节点拉取失败
            local _prov_block=""
            _prov_block=$(awk '/^proxy-providers:/,/^[a-zA-Z_-]+:/' "$output_file" 2>/dev/null || true)
            if [[ -n "$_prov_block" ]]; then
                local _inject_ns=""
                while IFS= read -r _purl; do
                    [[ -z "$_purl" ]] && continue
                    local _host
                    _host=$(echo "$_purl" | sed 's|https\?://||;s|/.*||')
                    [[ -z "$_host" ]] && continue
                    # 提取根域名 (sub.example.com -> example.com)
                    local _root
                    _root=$(echo "$_host" | awk -F. '{if(NF>=2) print $(NF-1)"."$NF; else print}')
                    case "$_root" in
                        github.com|githubusercontent.com|gstatic.com|cloudflare.com) continue ;;
                    esac
                    if ! grep -qF "+.${_root}" "$output_file" 2>/dev/null; then
                        _inject_ns="${_inject_ns}    \"+.${_root}\": [223.5.5.5, 114.114.114.114]\n"
                    fi
                done < <(echo "$_prov_block" | grep -oE "https?://[^\"' ]+" | sort -u)
                if [[ -n "$_inject_ns" ]]; then
                    local _tmpf
                    _tmpf=$(mktemp)
                    if grep -q 'nameserver-policy:' "$output_file"; then
                        awk -v ns="$_inject_ns" '
                            /nameserver-policy:/ { print; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf" && mv "$_tmpf" "$output_file"
                    elif grep -q '^dns:' "$output_file"; then
                        awk -v ns="$_inject_ns" '
                            /^dns:/ { print; print "  nameserver-policy:"; printf "%s", ns; next }
                            { print }
                        ' "$output_file" > "$_tmpf" && mv "$_tmpf" "$output_file"
                    else
                        rm -f "$_tmpf"
                    fi
                fi
            fi

            draw_line
            print_success "配置已生成!"
            draw_line
            echo -e "文件路径: ${C_CYAN}${output_file}${C_RESET}"
            echo "查看方式:
  1. 在终端显示完整配置
  2. 仅显示注入的部分
  3. 跳过"
            read -e -r -p "选择 [3]: " view_mode
            view_mode=${view_mode:-3}
            case $view_mode in
                1) echo ""; cat "$output_file"; echo "" ;;
                2)
                    echo -e "${C_CYAN}=== WireGuard 节点 ===${C_RESET}"
                    echo "$all_proxy_yaml"
                    echo -e "${C_CYAN}=== VPN 分组 ===${C_RESET}"
                    echo "$wg_group_yaml"
                    echo -e "${C_CYAN}=== 路由规则 ===${C_RESET}"
                    echo -n "$wg_rules_yaml"
                    echo ""
                    ;;
            esac
            echo -e "${C_CYAN}下载命令:${C_RESET}"
            echo "  scp root@$(wg_db_get '.server.endpoint'):${output_file} ./clash-config.yaml"
            draw_line
            ;;
        0|"") return ;;
        *) print_error "无效选项" ;;
    esac
    echo -e "${C_YELLOW}[重要提示]${C_RESET}"
    echo "  • 需要 Clash Meta (mihomo) 内核 1.14.0+
  • OpenClash 设置中需切换到 Meta 内核"
    if [[ ${#all_proxy_names[@]} -gt 1 ]]; then
        echo "  • 多节点模式下，所有服务器必须已同步相同的 peers 配置
  • 使用 '同步 Peers 到所有节点' 确保配置一致"
    fi
    log_action "Clash WireGuard config generated: ${peer_name} nodes=${#all_proxy_names[@]}"
    pause
}

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

wg_modify_server() {
    wg_check_server || return 1
    print_title "修改 WireGuard 服务端配置"
    local cur_port cur_dns cur_ep
    cur_port=$(wg_db_get '.server.port')
    cur_dns=$(wg_db_get '.server.dns')
    cur_ep=$(wg_db_get '.server.endpoint')
    echo -e "  当前端口:   ${C_GREEN}${cur_port}${C_RESET}"
    echo -e "  当前 DNS:   ${C_GREEN}${cur_dns}${C_RESET}"
    echo -e "  当前端点:   ${C_GREEN}${cur_ep}${C_RESET}"
    local changed=false
    read -e -r -p "新监听端口 [${cur_port}]: " new_port
    new_port=${new_port:-$cur_port}
    if [[ "$new_port" != "$cur_port" ]]; then
        if validate_port "$new_port"; then
            wg_db_set --argjson p "$new_port" '.server.port = $p'
            changed=true
            print_info "端口将更改为 ${new_port}"
        else
            print_warn "端口无效，保持原值"
        fi
    fi
    read -e -r -p "新客户端 DNS [${cur_dns}]: " new_dns
    new_dns=${new_dns:-$cur_dns}
    if [[ "$new_dns" != "$cur_dns" ]]; then
        wg_db_set --arg d "$new_dns" '.server.dns = $d'
        changed=true
        print_info "DNS 将更改为 ${new_dns}"
    fi
    read -e -r -p "新公网端点 [${cur_ep}]: " new_ep
    new_ep=${new_ep:-$cur_ep}
    if [[ "$new_ep" != "$cur_ep" ]]; then
        wg_db_set --arg e "$new_ep" '.server.endpoint = $e'
        changed=true
        print_info "端点将更改为 ${new_ep}"
    fi
    if [[ "$changed" != "true" ]]; then
        print_info "未做任何更改"
        pause; return
    fi
    wg_rebuild_conf
    wg_regenerate_client_confs
    if wg_is_running; then
        wg-quick down "$WG_INTERFACE" 2>/dev/null
        wg-quick up "$WG_INTERFACE" 2>/dev/null
    fi
    if [[ "$new_port" != "$cur_port" ]]; then
        if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw delete allow "${cur_port}/udp" 2>/dev/null || true
            ufw allow "${new_port}/udp" comment "WireGuard" >/dev/null 2>&1
        fi
    fi
    print_success "服务端配置已更新"
    log_action "WireGuard server config modified: port=${new_port} dns=${new_dns} endpoint=${new_ep}"
    pause
}

wg_client_install() {
    print_title "安装 WireGuard 客户端"
    if wg_is_installed && [[ "$(wg_get_role)" == "client" ]]; then
        print_warn "WireGuard 客户端已安装。"
        wg_is_running && echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}" || echo -e "  状态: ${C_RED}● 未连接${C_RESET}"
        pause; return 0
    fi
    if wg_is_installed && [[ "$(wg_get_role)" == "server" ]]; then
        print_error "当前已安装为服务端模式。如需切换为客户端，请先卸载。"
        pause; return 1
    fi
    print_info "[1/3] 安装软件包..."
    wg_install_packages || { pause; return 1; }
    print_info "[2/3] 导入客户端配置..."
    echo "请选择导入方式:
  1. 粘贴配置内容
  2. 指定配置文件路径
"
    read -e -r -p "选择 [1]: " import_mode
    import_mode=${import_mode:-1}
    local conf_content=""
    case $import_mode in
        1)
            echo -e "${C_CYAN}请粘贴客户端配置内容 (粘贴完成后按 Ctrl+D):${C_RESET}"
            conf_content=$(cat)
            ;;
        2)
            read -e -r -p "配置文件路径: " conf_path
            if [[ ! -f "$conf_path" ]]; then
                print_error "文件不存在: ${conf_path}"
                pause; return 1
            fi
            conf_content=$(cat "$conf_path")
            ;;
        *)
            print_error "无效选择"
            pause; return 1
            ;;
    esac
    if [[ -z "$conf_content" ]]; then
        print_error "配置内容为空"
        pause; return 1
    fi
    if ! echo "$conf_content" | grep -q "\[Interface\]"; then
        print_error "配置格式无效: 缺少 [Interface] 段"
        pause; return 1
    fi
    if ! echo "$conf_content" | grep -q "\[Peer\]"; then
        print_error "配置格式无效: 缺少 [Peer] 段"
        pause; return 1
    fi
    if ! echo "$conf_content" | grep -qi "PrivateKey"; then
        print_error "配置格式无效: 缺少 PrivateKey"
        pause; return 1
    fi
    write_file_atomic "$WG_CONF" "$conf_content"
    chmod 600 "$WG_CONF"
    print_info "[3/3] 保存配置信息..."
    wg_db_init
    wg_set_role "client"
    local client_addr client_dns server_pubkey server_endpoint server_allowed
    client_addr=$(echo "$conf_content" | grep -i "^Address" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    client_dns=$(echo "$conf_content" | grep -i "^DNS" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_pubkey=$(echo "$conf_content" | sed -n '/\[Peer\]/,/^$/p' | grep -i "^PublicKey" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_endpoint=$(echo "$conf_content" | grep -i "^Endpoint" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_allowed=$(echo "$conf_content" | grep -i "^AllowedIPs" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    wg_db_set --arg addr "${client_addr:-unknown}" \
              --arg dns "${client_dns:-}" \
              --arg spub "${server_pubkey:-}" \
              --arg ep "${server_endpoint:-}" \
              --arg allowed "${server_allowed:-}" \
    '.client = {
        address: $addr,
        dns: $dns,
        server_pubkey: $spub,
        server_endpoint: $ep,
        allowed_ips: $allowed
    }'
    draw_line
    print_success "WireGuard 客户端安装完成！"
    echo -e "  角色:     ${C_GREEN}客户端 (Client)${C_RESET}"
    echo -e "  地址:     ${C_GREEN}${client_addr:-未知}${C_RESET}"
    echo -e "  服务端:   ${C_GREEN}${server_endpoint:-未知}${C_RESET}"
    draw_line
    if confirm "是否立即连接?"; then
        wg_client_connect
    fi
    log_action "WireGuard client installed: addr=${client_addr} endpoint=${server_endpoint}"

    # 自动安装客户端看门狗
    echo ""
    wg_setup_watchdog "true"

    pause
}

wg_client_connect() {
    if wg_is_running; then
        print_warn "WireGuard 已连接"
        return 0
    fi
    print_info "正在连接..."
    is_systemd && systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1
    if wg_is_running; then
        print_success "WireGuard 已连接"
        log_action "WireGuard client connected"
    else
        print_error "连接失败，请检查配置"
        log_action "WireGuard client connect failed"
    fi
}

wg_client_disconnect() {
    if ! wg_is_running; then
        print_warn "WireGuard 未连接"
        return 0
    fi
    print_info "正在断开..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null
    if is_systemd; then
        systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    fi
    sleep 1
    if ! wg_is_running; then
        print_success "WireGuard 已断开"
        log_action "WireGuard client disconnected"
    else
        print_error "断开失败"
    fi
}

wg_client_reconnect() {
    print_info "正在重新连接..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1
    if wg_is_running; then
        print_success "WireGuard 已重新连接"
    else
        print_error "重新连接失败"
    fi
}

wg_client_status() {
    print_title "WireGuard 客户端状态"
    if ! wg_is_installed; then
        print_warn "WireGuard 未安装"
        pause; return
    fi
    local role
    role=$(wg_get_role)
    echo -e "  角色: ${C_GREEN}${role:-未知}${C_RESET}"
    if wg_is_running; then
        echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}"
    else
        echo -e "  状态: ${C_RED}● 未连接${C_RESET}"
        pause; return
    fi
    draw_line
    local wg_output
    wg_output=$(wg show "$WG_INTERFACE" 2>/dev/null)
    if [[ -n "$wg_output" ]]; then
        echo "$wg_output" | while IFS= read -r line; do
            case "$line" in
                *"public key:"*)
                    echo -e "  本机公钥:   ${C_CYAN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"listening port:"*)
                    echo -e "  监听端口:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"endpoint:"*)
                    echo -e "  服务端端点: ${C_GREEN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"allowed ips:"*)
                    echo -e "  允许 IP:    $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"latest handshake:"*)
                    echo -e "  最近握手:   ${C_GREEN}$(echo "$line" | awk -F': ' '{print $2}')${C_RESET}" ;;
                *"transfer:"*)
                    echo -e "  流量统计:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
                *"persistent keepalive:"*)
                    echo -e "  保活间隔:   $(echo "$line" | awk -F': ' '{print $2}')" ;;
            esac
        done
    fi
    draw_line
    if [[ "$role" == "client" ]]; then
        local client_info
        client_info=$(wg_db_get '.client // empty')
        if [[ -n "$client_info" ]]; then
            local addr ep
            addr=$(wg_db_get '.client.address')
            ep=$(wg_db_get '.client.server_endpoint')
            echo -e "  本机地址:   ${C_GREEN}${addr}${C_RESET}"
            echo -e "  服务端:     ${C_GREEN}${ep}${C_RESET}"
        fi
        print_info "连通性测试..."
        local server_vip
        server_vip=$(echo "$wg_output" | grep "allowed ips" | head -1 | awk -F': ' '{print $2}' | cut -d'/' -f1 | cut -d',' -f1 | xargs)
        if [[ "$server_vip" == "0.0.0.0" || -z "$server_vip" ]]; then
            local client_ip_base
            client_ip_base=$(wg_db_get '.client.address' | cut -d'/' -f1)
            if [[ -n "$client_ip_base" ]]; then
                server_vip=$(echo "$client_ip_base" | awk -F'.' '{print $1"."$2"."$3".1"}')
            fi
        fi
        if [[ -n "$server_vip" ]]; then
            if ping -c 2 -W 3 "$server_vip" >/dev/null 2>&1; then
                echo -e "  Ping ${server_vip}: ${C_GREEN}✓ 可达${C_RESET}"
            else
                echo -e "  Ping ${server_vip}: ${C_RED}✗ 不可达${C_RESET}"
            fi
        fi
    fi
    pause
}

wg_client_reconfig() {
    if [[ "$(wg_get_role)" != "client" ]]; then
        print_error "当前不是客户端模式"
        pause; return 1
    fi
    print_title "更换客户端配置"
    print_warn "这将替换当前的 WireGuard 配置"
    if ! confirm "确认继续?"; then
        return
    fi
    wg_is_running && wg-quick down "$WG_INTERFACE" 2>/dev/null
    echo ""
    echo "请选择导入方式:
  1. 粘贴配置内容
  2. 指定配置文件路径
"
    read -e -r -p "选择 [1]: " import_mode
    import_mode=${import_mode:-1}
    local conf_content=""
    case $import_mode in
        1)
            echo -e "${C_CYAN}请粘贴新的客户端配置 (粘贴完成后按 Ctrl+D):${C_RESET}"
            conf_content=$(cat)
            ;;
        2)
            read -e -r -p "配置文件路径: " conf_path
            if [[ ! -f "$conf_path" ]]; then
                print_error "文件不存在: ${conf_path}"
                pause; return 1
            fi
            conf_content=$(cat "$conf_path")
            ;;
    esac
    if [[ -z "$conf_content" ]] || ! echo "$conf_content" | grep -q "\[Interface\]"; then
        print_error "配置内容无效"
        pause; return 1
    fi
    cp "$WG_CONF" "${WG_CONF}.bak.$(date +%s)" 2>/dev/null || true
    write_file_atomic "$WG_CONF" "$conf_content"
    chmod 600 "$WG_CONF"
    local client_addr server_endpoint
    client_addr=$(echo "$conf_content" | grep -i "^Address" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    server_endpoint=$(echo "$conf_content" | grep -i "^Endpoint" | head -1 | sed 's/^[^=]*=[[:space:]]*//')
    wg_db_set --arg addr "${client_addr:-unknown}" \
              --arg ep "${server_endpoint:-}" \
    '.client.address = $addr | .client.server_endpoint = $ep'
    print_success "配置已更新"
    if confirm "是否立即连接?"; then
        wg_client_connect
    fi
    log_action "WireGuard client reconfigured: addr=${client_addr} endpoint=${server_endpoint}"
    pause
}

wg_server_status() {
    wg_check_server || return 1
    print_title "WireGuard 服务端状态"
    local port subnet endpoint dns
    port=$(wg_db_get '.server.port')
    subnet=$(wg_db_get '.server.subnet')
    endpoint=$(wg_db_get '.server.endpoint')
    dns=$(wg_db_get '.server.dns')
    echo -e "  角色:     ${C_GREEN}服务端 (Server)${C_RESET}"
    if wg_is_running; then
        echo -e "  状态:     ${C_GREEN}● 运行中${C_RESET}"
    else
        echo -e "  状态:     ${C_RED}● 已停止${C_RESET}"
    fi
    echo -e "  端口:     ${port}/udp"
    echo -e "  子网:     ${subnet}"
    echo -e "  端点:     ${endpoint}"
    echo -e "  DNS:      ${dns}"
    local peer_count
    peer_count=$(wg_db_get '.peers | length')
    echo -e "${C_CYAN}设备列表 (${peer_count} 个):${C_RESET}"
    draw_line
    if [[ "$peer_count" -gt 0 ]]; then
        printf "${C_CYAN}%-4s %-16s %-18s %-8s %-20s %-16s${C_RESET}\n" \
            "#" "名称" "IP" "状态" "最近握手" "流量"
        draw_line
        local wg_dump=""
        wg_is_running && wg_dump=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)
        local i=0
        while [[ $i -lt $peer_count ]]; do
            local name ip pubkey enabled
            name=$(wg_db_get ".peers[$i].name")
            ip=$(wg_db_get ".peers[$i].ip")
            pubkey=$(wg_db_get ".peers[$i].public_key")
            enabled=$(wg_db_get ".peers[$i].enabled")
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
            printf "%-4s %-16s %-18s %-8b %-20s %-16s\n" \
                "$((i + 1))" "$name" "$ip" "$status_str" "$handshake_str" "$transfer_str"
            i=$((i + 1))
        done
    else
        print_info "暂无设备"
    fi
    draw_line
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    if [[ "$pf_count" -gt 0 ]]; then
        echo -e "${C_CYAN}端口转发规则 (${pf_count} 条):${C_RESET}"
        draw_line
        local j=0
        while [[ $j -lt $pf_count ]]; do
            local proto ext_port dest_ip dest_port pf_enabled
            proto=$(wg_db_get ".port_forwards[$j].proto")
            ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
            dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
            dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
            pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")
            local pf_status
            [[ "$pf_enabled" == "true" ]] && pf_status="${C_GREEN}●${C_RESET}" || pf_status="${C_RED}○${C_RESET}"
            echo -e "  ${pf_status} ${ext_port}/${proto} -> ${dest_ip}:${dest_port}"
            j=$((j + 1))
        done
        draw_line
    fi
    wg_cluster_init_db
    local cluster_enabled=$(wg_db_get '.cluster.enabled')
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$cluster_enabled" == "true" && "$node_count" -gt 0 ]]; then
        echo -e "${C_CYAN}集群节点 (${node_count} 台):${C_RESET}"
        draw_line
        printf "${C_CYAN}%-4s %-16s %-28s %-16s %-8s${C_RESET}\n" "#" "名称" "Endpoint" "VPN IP" "状态"
        draw_line
        local ci=0
        while [[ $ci -lt $node_count ]]; do
            local cname=$(wg_db_get ".cluster.nodes[$ci].name")
            local cep=$(wg_db_get ".cluster.nodes[$ci].endpoint")
            local cport=$(wg_db_get ".cluster.nodes[$ci].port")
            local cip=$(wg_db_get ".cluster.nodes[$ci].ip")
            local cstatus="${C_YELLOW}未知${C_RESET}"
            if ping -c 1 -W 2 "$cep" &>/dev/null; then
                cstatus="${C_GREEN}可达${C_RESET}"
            else
                cstatus="${C_RED}不可达${C_RESET}"
            fi
            printf "%-4s %-16s %-28s %-16s %-8b\n" "$((ci+1))" "$cname" "${cep}:${cport}" "$cip" "$cstatus"
            ci=$((ci+1))
        done
        draw_line
    fi
    pause
}

wg_start() {
    if wg_is_running; then
        print_warn "WireGuard 已在运行"
        return 0
    fi
    if [[ ! -f "$WG_CONF" ]]; then
        print_error "配置文件不存在: ${WG_CONF}"
        return 1
    fi
    print_info "正在启动 WireGuard..."
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    if is_systemd; then
        systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1
    fi
    sleep 1
    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已启动"
        log_action "WireGuard started"
    else
        print_error "启动失败"
        log_action "WireGuard start failed"
    fi
}

wg_stop() {
    if ! wg_is_running; then
        print_warn "WireGuard 未在运行"
        return 0
    fi
    print_info "正在停止 WireGuard..."
    wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    if ! wg_is_running; then
        print_success "WireGuard 已停止"
        log_action "WireGuard stopped"
    else
        print_error "停止失败"
    fi
}

wg_restart() {
    print_info "正在重启 WireGuard..."
    wg_is_running && wg-quick down "$WG_INTERFACE" 2>/dev/null
    sleep 1
    wg-quick up "$WG_INTERFACE" 2>/dev/null
    sleep 1
    if wg_is_running; then
        wg_restore_port_forwards
        print_success "WireGuard 已重启"
        log_action "WireGuard restarted"
    else
        print_error "重启失败"
        log_action "WireGuard restart failed"
    fi
}

wg_restore_port_forwards() {
    local role
    role=$(wg_get_role)
    [[ "$role" != "server" ]] && return 0
    local pf_count
    pf_count=$(wg_db_get '.port_forwards | length')
    [[ "$pf_count" -eq 0 || "$pf_count" == "null" ]] && return 0
    local j=0
    while [[ $j -lt $pf_count ]]; do
        local proto ext_port dest_ip dest_port pf_enabled
        proto=$(wg_db_get ".port_forwards[$j].proto")
        ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
        dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
        dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
        pf_enabled=$(wg_db_get ".port_forwards[$j].enabled")
        if [[ "$pf_enabled" == "true" ]]; then
            _wg_pf_iptables_ensure "$proto" "$ext_port" "$dest_ip" "$dest_port"
        fi
        j=$((j + 1))
    done
}

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
    print_info "[1/5] 停止 WireGuard..."
    if wg_is_running; then
        wg-quick down "$WG_INTERFACE" 2>/dev/null || true
    fi
    if is_systemd; then
        systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    fi

        # 清理 Mesh 接口
    if ip link show wg-mesh &>/dev/null; then
        print_info "停止 Mesh 接口..."
        wg-quick down wg-mesh 2>/dev/null || true
        systemctl disable "wg-quick@wg-mesh" 2>/dev/null || true
        rm -f /etc/wireguard/wg-mesh.conf
    fi
    print_info "[2/5] 清理端口转发规则..."
    if [[ "$role" == "server" ]]; then
        local pf_count
        pf_count=$(wg_db_get '.port_forwards | length' 2>/dev/null)
        if [[ -n "$pf_count" && "$pf_count" != "null" && "$pf_count" -gt 0 ]]; then
            local j=0
            while [[ $j -lt $pf_count ]]; do
                local proto ext_port dest_ip dest_port
                proto=$(wg_db_get ".port_forwards[$j].proto")
                ext_port=$(wg_db_get ".port_forwards[$j].ext_port")
                dest_ip=$(wg_db_get ".port_forwards[$j].dest_ip")
                dest_port=$(wg_db_get ".port_forwards[$j].dest_port")
                _wg_pf_iptables -D "$proto" "$ext_port" "$dest_ip" "$dest_port"
                j=$((j + 1))
            done
            wg_save_iptables
        fi
    fi
    print_info "[3/5] 清理防火墙规则..."
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        if [[ "$role" == "server" ]]; then
            local port
            port=$(wg_db_get '.server.port' 2>/dev/null)
            [[ -n "$port" ]] && ufw delete allow "${port}/udp" 2>/dev/null || true
        fi
        ufw status numbered 2>/dev/null | grep "WG-PF" | awk -F'[][]' '{print $2}' | sort -rn | while read -r num; do
            yes | ufw delete "$num" 2>/dev/null || true
        done
    fi
    print_info "[3.5/5] 清理看门狗..."
    if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
        cron_remove_job "wg-watchdog.sh"
    fi
    rm -f /usr/local/bin/wg-watchdog.sh /var/log/wg-watchdog.log /tmp/.wg-watchdog-stale 2>/dev/null || true
    print_info "[4/5] 删除配置文件..."
    rm -f "$WG_CONF" 2>/dev/null || true
    rm -rf /etc/wireguard/clients 2>/dev/null || true
    rm -f "$WG_DB_FILE" 2>/dev/null || true
    rm -rf "$WG_DB_DIR" 2>/dev/null || true          
    rm -f "$WG_ROLE_FILE" 2>/dev/null || true         
    rm -f /etc/wireguard/*.key 2>/dev/null || true
    rmdir /etc/wireguard 2>/dev/null || true
    print_info "[5/5] 卸载软件包..."
    local remove_pkg=true
    if confirm "是否卸载 WireGuard 软件包? (选 N 仅删除配置)"; then
        case $PLATFORM in
            debian|ubuntu)
                apt-get remove -y wireguard wireguard-tools >/dev/null 2>&1 || true
                apt-get autoremove -y >/dev/null 2>&1 || true
                ;;
            centos|rhel|rocky|alma|fedora)
                if command_exists dnf; then
                    dnf remove -y wireguard-tools >/dev/null 2>&1 || true
                else
                    yum remove -y wireguard-tools >/dev/null 2>&1 || true
                fi
                ;;
            alpine)
                apk del wireguard-tools >/dev/null 2>&1 || true
                ;;
            arch|manjaro)
                pacman -Rns --noconfirm wireguard-tools >/dev/null 2>&1 || true
                ;;
            openwrt)
                opkg remove wireguard-tools luci-proto-wireguard >/dev/null 2>&1 || true
                ;;
        esac
    else
        remove_pkg=false
    fi
    if [[ "$role" == "server" ]]; then
        if confirm "是否恢复 IP 转发设置? (如果其他服务需要转发请选 N)"; then
            sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf 2>/dev/null || true
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
        fi
    fi
    draw_line
    print_success "WireGuard 已完全卸载"
    draw_line
    log_action "WireGuard uninstalled: role=${role} pkg_removed=${remove_pkg}"
    pause
}

wg_openwrt_clean_cmd() {
    print_title "OpenWrt 清空 WireGuard 配置"
    echo -e "${C_YELLOW}复制以下命令到 OpenWrt SSH 终端执行:${C_RESET}"
    draw_line
    cat << 'CLEANEOF'
# 停止 WireGuard 接口
ifdown wg0 2>/dev/null; true

# 删除网络配置
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_server 2>/dev/null; true

# 删除防火墙配置
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true

# 提交并重载
uci commit network
uci commit firewall
/etc/init.d/firewall reload
/etc/init.d/network reload

echo "[✓] WireGuard 配置已清空"
CLEANEOF
    draw_line
    echo -e "${C_CYAN}执行后可在 LuCI -> Network -> Interfaces 确认 wg0 已消失${C_RESET}"
    pause
}

wg_setup_watchdog() {
    local auto_mode="${1:-false}"
    wg_check_installed || return 1
    local role=$(wg_get_role)
    local watchdog_script="/usr/local/bin/wg-watchdog.sh"
    local watchdog_log="/var/log/wg-watchdog.log"

    # 自动模式：已安装则跳过
    if [[ "$auto_mode" == "true" ]]; then
        if crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
            return 0
        fi
    else
        print_title "WireGuard 看门狗 (${role})"
    fi

    # 已启用时的管理界面（仅交互模式）
    if [[ "$auto_mode" != "true" ]] && crontab -l 2>/dev/null | grep -q "wg-watchdog.sh"; then
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        echo -e "  角色: ${C_CYAN}${role}${C_RESET}"
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

    # 功能描述（仅交互模式）
    if [[ "$auto_mode" != "true" ]]; then
        if [[ "$role" == "server" ]]; then
            echo "服务端看门狗功能:
  • 每分钟检测 wg0 接口状态
  • 接口消失 → 立即拉起
  • wg show 失败 → 重启接口
  • 所有 peer 超 10 分钟无握手 → 连续两次确认后重启"
        else
            echo "客户端看门狗功能:
  • 每分钟检测 wg0 接口状态和连通性
  • 自动重解析服务端 Endpoint DNS
  • Ping 服务端失败 → 重启接口"
            # 检查是否有 failover endpoints
            local failover_eps=$(wg_db_get '.client.failover_endpoints // empty' 2>/dev/null)
            if [[ -n "$failover_eps" && "$failover_eps" != "null" ]]; then
                echo -e "  • ${C_GREEN}Failover: 自动切换到延迟最低的服务端${C_RESET}"
            else
                echo -e "  • ${C_YELLOW}提示: 可配置 failover endpoints 实现多服务器自动切换${C_RESET}"
            fi
        fi
        if ! confirm "启用看门狗?"; then pause; return; fi
    fi
    local failover_endpoints=""
    local failover_threshold=100
    if [[ "$role" == "client" ]]; then
        if [[ "$auto_mode" == "true" ]]; then
            # 自动模式：从 DB 加载已有配置，或自动检测集群节点
            local saved_eps=$(wg_db_get '.client.failover_endpoints // empty' 2>/dev/null)
            if [[ -n "$saved_eps" && "$saved_eps" != "null" && "$saved_eps" != "[]" ]]; then
                failover_endpoints=$(echo "$saved_eps" | jq -r '.[]' 2>/dev/null)
                failover_threshold=$(wg_db_get '.client.failover_threshold_ms // 100' 2>/dev/null)
            fi
        else
            if confirm "是否配置多服务器 failover (高可用自动切换)?"; then
                print_guide "输入备用服务器 Endpoint 列表 (每行一个，格式: IP:端口 或 域名:端口)"
                print_guide "输入完成后按 Enter 空行结束"
                local eps=()
                while true; do
                    read -e -r -p "  备用 Endpoint (空行结束): " ep_input
                    [[ -z "$ep_input" ]] && break
                    eps+=("$ep_input")
                done
                if [[ ${#eps[@]} -gt 0 ]]; then
                    failover_endpoints=$(printf '%s\n' "${eps[@]}")
                    read -e -r -p "延迟阈值 ms (超过此值触发切换) [100]: " failover_threshold
                    failover_threshold=${failover_threshold:-100}
                    # 保存到 DB
                    local eps_json=$(printf '%s\n' "${eps[@]}" | jq -R . | jq -s .)
                    wg_db_set --argjson eps "$eps_json" --argjson th "$failover_threshold" \
                        '.client.failover_endpoints = $eps | .client.failover_threshold_ms = $th'
                    print_success "已配置 ${#eps[@]} 个备用 Endpoint"
                fi
            else
                # 从 DB 加载已有配置
                local saved_eps=$(wg_db_get '.client.failover_endpoints // empty' 2>/dev/null)
                if [[ -n "$saved_eps" && "$saved_eps" != "null" && "$saved_eps" != "[]" ]]; then
                    failover_endpoints=$(echo "$saved_eps" | jq -r '.[]' 2>/dev/null)
                    failover_threshold=$(wg_db_get '.client.failover_threshold_ms // 100' 2>/dev/null)
                    print_info "使用已保存的 failover 配置"
                fi
            fi
        fi
    fi

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
        if [[ "$role" == "server" ]]; then
            # 服务端: peer 僵死检测
            cat >> "$watchdog_script" << 'WDEOF_OWT_SVR'

# 服务端: peer 僵死检测
STALE_THRESHOLD=600
PEER_COUNT=$(wg show wg0 dump 2>/dev/null | tail -n +2 | wc -l)
if [ "$PEER_COUNT" -gt 0 ]; then
    NOW=$(date +%s)
    ANY_ALIVE=0
    wg show wg0 dump 2>/dev/null | tail -n +2 | while IFS='	' read _ _ _ _ LAST_HS _; do
        [ "$LAST_HS" = "0" ] && continue
        AGE=$((NOW - LAST_HS))
        [ "$AGE" -lt "$STALE_THRESHOLD" ] && { ANY_ALIVE=1; break; }
    done
    if [ "$ANY_ALIVE" -eq 0 ] 2>/dev/null; then
        if [ -f /tmp/.wg-watchdog-stale ]; then
            $LOG "all peers stale 2x, restarting"
            ifdown wg0; sleep 1; ifup wg0
            rm -f /tmp/.wg-watchdog-stale
        else
            $LOG "all peers stale, flagging"
            touch /tmp/.wg-watchdog-stale
        fi
    else
        rm -f /tmp/.wg-watchdog-stale 2>/dev/null
    fi
fi
WDEOF_OWT_SVR
        else
            # 客户端: DNS 重解析 + ping 保活
            cat >> "$watchdog_script" << 'WDEOF_OWT_CLI'

# 客户端: DNS 重解析
EP_HOST=$(uci get network.wg_server.endpoint_host 2>/dev/null)
echo "$EP_HOST" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' && EP_HOST=""
if [ -n "$EP_HOST" ]; then
    RESOLVED=$(nslookup "$EP_HOST" 2>/dev/null | awk '/^Address:/{a=$2} END{if(a) print a}')
    CURRENT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1 | head -1)
    if [ -n "$RESOLVED" ] && [ "$RESOLVED" != "$CURRENT" ]; then
        $LOG "DNS changed: $CURRENT -> $RESOLVED"
        PUB=$(wg show wg0 endpoints | awk '{print $1}' | head -1)
        PORT=$(uci get network.wg_server.endpoint_port 2>/dev/null)
        wg set wg0 peer "$PUB" endpoint "${RESOLVED}:${PORT}"
    fi
fi

# 客户端: ping 保活
VIP=$(uci get network.wg_server.allowed_ips 2>/dev/null | awk '{print $1}' | cut -d/ -f1)
VIP=$(echo "$VIP" | awk -F. '{print $1"."$2"."$3".1"}')
if [ -n "$VIP" ] && ! ping -c 2 -W 3 "$VIP" &>/dev/null; then
    if [ -f /tmp/.wg-wd-fail ]; then
        $LOG "ping $VIP failed twice, restarting"
        ifdown wg0; sleep 1; ifup wg0
        rm -f /tmp/.wg-wd-fail
    else
        touch /tmp/.wg-wd-fail
    fi
else
    rm -f /tmp/.wg-wd-fail 2>/dev/null
fi
WDEOF_OWT_CLI
        fi
        chmod +x "$watchdog_script"
        cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
        echo ""
        print_success "看门狗已启用 (每分钟检测)"
        echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
        echo -e "  角色: ${C_CYAN}${role}${C_RESET}"
        if [[ "$role" == "server" ]]; then
            echo "  检测: 接口存活 → wg show → peer 僵死检测"
        else
            echo "  检测: 接口存活 → DNS重解析 → ping 保活"
        fi
        log_action "WireGuard watchdog enabled (role=$role platform=openwrt)"
        [[ "$auto_mode" != "true" ]] && pause
        return 0
    fi

    # 客户端 endpoint 域名
    local endpoint_host=""
    if [[ "$role" == "client" ]]; then
        endpoint_host=$(grep -i "^Endpoint" "$WG_CONF" 2>/dev/null | head -1 | sed 's/^[^=]*=[[:space:]]*//' | cut -d: -f1)
        if [[ "$endpoint_host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            endpoint_host=""
        fi
    fi

    # ── 生成看门狗脚本 ──
    # 通用头部
    cat > "$watchdog_script" << 'WDEOF_COMMON'
#!/bin/bash
LOG="/var/log/wg-watchdog.log"
WG_INTERFACE="wg0"
STALE_THRESHOLD=600
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
WDEOF_COMMON
    if [[ "$role" == "server" ]]; then
        # 服务端逻辑（保持不变）
        cat >> "$watchdog_script" << 'WDEOF_SERVER'

peer_count=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2 | wc -l)
if [[ "$peer_count" -gt 0 ]]; then
    now=$(date +%s)
    any_alive=0
    while IFS=$'\t' read -r _ _ _ _ last_hs _; do
        [[ "$last_hs" == "0" ]] && continue
        age=$((now - last_hs))
        [[ $age -lt $STALE_THRESHOLD ]] && { any_alive=1; break; }
    done < <(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2)

    if [[ $any_alive -eq 0 ]]; then
        if [[ -f /tmp/.wg-watchdog-stale ]]; then
            log "WARN: all peers stale 2x, restarting..."
            wg-quick down "$WG_INTERFACE" 2>>"$LOG"; sleep 1
            wg-quick up "$WG_INTERFACE" 2>>"$LOG"
            rm -f /tmp/.wg-watchdog-stale
        else
            log "NOTICE: all peers stale, flagging"
            touch /tmp/.wg-watchdog-stale
        fi
    else
        rm -f /tmp/.wg-watchdog-stale 2>/dev/null
    fi
fi
WDEOF_SERVER
    else
        if [[ -n "$endpoint_host" ]]; then
            cat >> "$watchdog_script" << WDEOF_DNS

ENDPOINT_HOST="${endpoint_host}"
resolve_ip() {
    local ip=""
    if command -v dig &>/dev/null; then
        ip=\$(dig +short "\$1" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    elif command -v nslookup &>/dev/null; then
        ip=\$(nslookup "\$1" 2>/dev/null | awk '/^Address: / && !/127\.0\.0/ {print \$2; exit}')
    elif command -v getent &>/dev/null; then
        ip=\$(getent ahosts "\$1" 2>/dev/null | awk '/STREAM/ {print \$1; exit}')
    fi
    echo "\$ip"
}

resolved=\$(resolve_ip "\$ENDPOINT_HOST")
if [[ -n "\$resolved" ]]; then
    wg show "\$WG_INTERFACE" endpoints 2>/dev/null | while read -r pub ep; do
        [[ -z "\$ep" || "\$ep" == "(none)" ]] && continue
        current_ip=\$(echo "\$ep" | sed 's/\[//;s/\]//' | rev | cut -d: -f2- | rev)
        current_port=\$(echo "\$ep" | rev | cut -d: -f1 | rev)
        if [[ "\$resolved" != "\$current_ip" ]]; then
            log "DNS changed: \$current_ip -> \$resolved"
            wg set "\$WG_INTERFACE" peer "\$pub" endpoint "\${resolved}:\${current_port}" 2>>"\$LOG" && \
                log "OK: endpoint updated" || log "ERROR: endpoint update failed"
        fi
    done
fi
WDEOF_DNS
        fi
        if [[ -n "$failover_endpoints" ]]; then
            # 把主 endpoint 也加入列表
            local primary_ep=$(grep -i "^Endpoint" "$WG_CONF" 2>/dev/null | head -1 | sed 's/^[^=]*=[[:space:]]*//')
            cat >> "$watchdog_script" << WDEOF_FAILOVER

# === Failover: 多服务器自动切换 ===
FAILOVER_THRESHOLD_MS=${failover_threshold}
PRIMARY_ENDPOINT="${primary_ep}"
FAILOVER_ENDPOINTS=(
WDEOF_FAILOVER

            # 写入所有备用 endpoint
            echo "$failover_endpoints" | while IFS= read -r ep; do
                [[ -n "$ep" ]] && echo "    \"${ep}\"" >> "$watchdog_script"
            done
            cat >> "$watchdog_script" << 'WDEOF_FAILOVER2'
)

# 获取当前 peer 公钥和 endpoint
CURRENT_PUB=$(wg show "$WG_INTERFACE" endpoints 2>/dev/null | awk '{print $1}' | head -1)
CURRENT_EP=$(wg show "$WG_INTERFACE" endpoints 2>/dev/null | awk '{print $2}' | head -1)

# 从 endpoint 提取 host
ep_to_host() { echo "$1" | sed 's/\[//;s/\]//' | rev | cut -d: -f2- | rev; }

# 测量到某个 host 的延迟 (ms)，失败返回 9999
measure_latency() {
    local host=$(echo "$1" | cut -d: -f1)
    # 如果是域名先解析
    if [[ ! "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if command -v dig &>/dev/null; then
            host=$(dig +short "$host" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
        elif command -v getent &>/dev/null; then
            host=$(getent ahosts "$host" 2>/dev/null | awk '/STREAM/ {print $1; exit}')
        fi
    fi
    [[ -z "$host" ]] && { echo 9999; return; }
    local avg=$(ping -c 2 -W 2 "$host" 2>/dev/null | awk -F'/' '/avg/{print int($5)}')
    echo "${avg:-9999}"
}

# 测量当前连接的服务端 VPN IP 延迟
server_vip=""
my_addr=$(ip -4 addr show "$WG_INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1)
[[ -n "$my_addr" ]] && server_vip=$(echo "$my_addr" | awk -F'.' '{print $1"."$2"."$3".1"}')

current_latency=9999
if [[ -n "$server_vip" ]]; then
    current_latency=$(ping -c 2 -W 2 "$server_vip" 2>/dev/null | awk -F'/' '/avg/{print int($5)}')
    current_latency=${current_latency:-9999}
fi

need_switch=false
if [[ "$current_latency" -ge 9999 ]]; then
    log "WARN: current endpoint unreachable (latency=timeout)"
    need_switch=true
elif [[ "$current_latency" -gt "$FAILOVER_THRESHOLD_MS" ]]; then
    log "NOTICE: current latency ${current_latency}ms > threshold ${FAILOVER_THRESHOLD_MS}ms"
    need_switch=true
fi

if [[ "$need_switch" == "true" && -n "$CURRENT_PUB" ]]; then
    # 测试所有候选 endpoint，选最优
    best_ep=""
    best_latency=9999

    # 先测主 endpoint
    lat=$(measure_latency "$PRIMARY_ENDPOINT")
    if [[ "$lat" -lt "$best_latency" ]]; then
        best_latency=$lat; best_ep="$PRIMARY_ENDPOINT"
    fi

    # 测备用 endpoints
    for ep in "${FAILOVER_ENDPOINTS[@]}"; do
        lat=$(measure_latency "$ep")
        if [[ "$lat" -lt "$best_latency" ]]; then
            best_latency=$lat; best_ep="$ep"
        fi
    done

    if [[ -n "$best_ep" && "$best_latency" -lt 9999 ]]; then
        # 只有当最优节点不是当前节点时才切换
        best_host=$(ep_to_host "$best_ep")
        current_host=$(ep_to_host "$CURRENT_EP")
        if [[ "$best_host" != "$current_host" ]]; then
            log "FAILOVER: switching to $best_ep (latency=${best_latency}ms, was ${current_latency}ms)"
            wg set "$WG_INTERFACE" peer "$CURRENT_PUB" endpoint "$best_ep" 2>>"$LOG" && \
                log "OK: switched to $best_ep" || log "ERROR: switch failed"
        elif [[ "$current_latency" -ge 9999 ]]; then
            # 当前节点不通但它又是最优的（其他也不通），重启接口
            if [[ -f /tmp/.wg-watchdog-ping-fail ]]; then
                log "WARN: all endpoints poor, restarting interface"
                wg-quick down "$WG_INTERFACE" 2>>"$LOG"; sleep 1
                wg-quick up "$WG_INTERFACE" 2>>"$LOG"
                rm -f /tmp/.wg-watchdog-ping-fail
            else
                touch /tmp/.wg-watchdog-ping-fail
            fi
        fi
    else
        log "WARN: no reachable endpoint found"
        if [[ -f /tmp/.wg-watchdog-ping-fail ]]; then
            log "WARN: 2x fail, restarting interface"
            wg-quick down "$WG_INTERFACE" 2>>"$LOG"; sleep 1
            wg-quick up "$WG_INTERFACE" 2>>"$LOG"
            rm -f /tmp/.wg-watchdog-ping-fail
        else
            touch /tmp/.wg-watchdog-ping-fail
        fi
    fi
else
    rm -f /tmp/.wg-watchdog-ping-fail 2>/dev/null
fi

# 如果当前连的不是主 endpoint，定期回探主机
if [[ -n "$CURRENT_EP" && -n "$PRIMARY_ENDPOINT" && -n "$CURRENT_PUB" ]]; then
    pri_host=$(ep_to_host "$PRIMARY_ENDPOINT")
    cur_host=$(ep_to_host "$CURRENT_EP")
    if [[ "$pri_host" != "$cur_host" ]]; then
        pri_lat=$(measure_latency "$PRIMARY_ENDPOINT")
        if [[ "$pri_lat" -lt "$FAILOVER_THRESHOLD_MS" ]]; then
            log "PRIMARY recovered: latency=${pri_lat}ms, switching back"
            wg set "$WG_INTERFACE" peer "$CURRENT_PUB" endpoint "$PRIMARY_ENDPOINT" 2>>"$LOG" && \
                log "OK: back to primary" || log "ERROR: switch back failed"
        fi
    fi
fi
WDEOF_FAILOVER2
        else
            # 无 failover 的简单 ping 检测（保持原逻辑）
            cat >> "$watchdog_script" << 'WDEOF_PING'

server_vip=""
my_addr=$(ip -4 addr show "$WG_INTERFACE" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1)
[[ -n "$my_addr" ]] && server_vip=$(echo "$my_addr" | awk -F'.' '{print $1"."$2"."$3".1"}')

if [[ -n "$server_vip" ]]; then
    if ! ping -c 2 -W 3 "$server_vip" &>/dev/null; then
        if [[ -f /tmp/.wg-watchdog-ping-fail ]]; then
            log "WARN: ping $server_vip failed 2x, restarting..."
            wg-quick down "$WG_INTERFACE" 2>>"$LOG"; sleep 1
            wg-quick up "$WG_INTERFACE" 2>>"$LOG"
            rm -f /tmp/.wg-watchdog-ping-fail
        else
            log "NOTICE: ping $server_vip failed, flagging"
            touch /tmp/.wg-watchdog-ping-fail
        fi
    else
        rm -f /tmp/.wg-watchdog-ping-fail 2>/dev/null
    fi
fi
WDEOF_PING
        fi
    fi

    # 日志轮转
    cat >> "$watchdog_script" << 'WDEOF_TAIL'

# 日志轮转
if [[ -f "$LOG" ]] && [[ $(wc -l < "$LOG") -gt 500 ]]; then
    tail -n 300 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
fi
WDEOF_TAIL
    chmod +x "$watchdog_script"
    cron_add_job "wg-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
    echo ""
    print_success "看门狗已启用 (每分钟检测)"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
    echo -e "  角色: ${C_CYAN}${role}${C_RESET}"
    if [[ "$role" == "server" ]]; then
        echo "  检测: 接口存活 → wg show → peer 僵死检测"
    else
        echo "  检测: 接口存活 → wg show → DNS重解析"
        if [[ -n "$failover_endpoints" ]]; then
            local ep_count=$(echo "$failover_endpoints" | wc -l)
            echo -e "  Failover: ${C_GREEN}${ep_count} 个备用节点, 阈值 ${failover_threshold}ms${C_RESET}"
            echo "  逻辑: 延迟超阈值或不通 → 测试所有节点 → 切到最优
  回切: 主节点恢复且延迟低于阈值 → 自动切回"
        else
            echo "  Ping 服务端失败 → 连续 2 次确认后重启"
        fi
    fi
    log_action "WireGuard watchdog enabled (role=$role failover=$([ -n "$failover_endpoints" ] && echo yes || echo no))"
    [[ "$auto_mode" != "true" ]] && pause
}

wg_cluster_failover_setup() {
    wg_check_server || return 1
    wg_cluster_init_db
    print_title "集群自动故障转移"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$node_count" -eq 0 ]]; then
        print_warn "至少需要 1 个集群节点"
        pause; return
    fi
    local failover_enabled=$(wg_db_get '.cluster.failover.enabled // false')
    if [[ "$failover_enabled" == "true" ]]; then
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        local fo_mode=$(wg_db_get '.cluster.failover.mode // "dns"')
        local fo_domain=$(wg_db_get '.cluster.failover.domain // empty')
        local fo_interval=$(wg_db_get '.cluster.failover.interval // 30')
        echo -e "  模式: ${C_CYAN}${fo_mode}${C_RESET}"
        [[ -n "$fo_domain" ]] && echo -e "  域名: ${C_CYAN}${fo_domain}${C_RESET}"
        echo -e "  间隔: ${fo_interval}s"
        echo "  1. 禁用故障转移
  2. 查看日志
  3. 手动触发检测
  4. 模拟故障 (测试切换)
  0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1)
                wg_db_set '.cluster.failover.enabled = false'
                # 清理所有节点的 failover cron
                cron_remove_job "wg-failover.sh"
                rm -f /usr/local/bin/wg-failover.sh
                local fi2=0
                while [[ $fi2 -lt $node_count ]]; do
                    local ssh_host=$(wg_db_get ".cluster.nodes[$fi2].ssh_host")
                    local ssh_port=$(wg_db_get ".cluster.nodes[$fi2].ssh_port")
                    local ssh_user=$(wg_db_get ".cluster.nodes[$fi2].ssh_user")
                    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -p "$ssh_port" \
                        "${ssh_user}@${ssh_host}" "
                        (crontab -l 2>/dev/null | grep -v wg-failover; true) | crontab -
                        rm -f /usr/local/bin/wg-failover.sh
                    " 2>/dev/null || true
                    fi2=$((fi2+1))
                done
                print_success "故障转移已禁用"
                log_action "Cluster failover disabled"
                ;;
            2) tail -n 30 /var/log/wg-failover.log 2>/dev/null || print_warn "无日志" ;;
            3) [[ -x /usr/local/bin/wg-failover.sh ]] && bash /usr/local/bin/wg-failover.sh && print_success "检测完成" ;;
            4)
                echo ""
                print_warn "模拟故障: 将临时停止主机 wg0 (30秒后自动恢复)"
                if confirm "确认模拟?"; then
                    wg-quick down wg0 2>/dev/null
                    print_info "wg0 已停止，等待其他节点检测并接管..."
                    print_info "30秒后自动恢复..."
                    sleep 30
                    wg-quick up wg0 2>/dev/null
                    print_success "wg0 已恢复"
                fi
                ;;
        esac
        pause; return
    fi
    echo -e "${C_CYAN}故障转移原理:${C_RESET}"
    echo "  方案 A: DNS 故障转移 (推荐)
    • 其他节点定期 ping 本机 VPN IP
    • 本机不通 → 其他节点通过 CF API 将 endpoint 域名指向自己
    • 本机恢复 → 自动切回
    • 要求: endpoint 使用域名 + CF API Token
  方案 B: 客户端 Failover (无需域名)
    • 依赖客户端看门狗的 failover 功能
    • 客户端自动测试所有 endpoint 选最优
    • 已在看门狗中实现，此处仅做配置辅助
"
    echo "  1. DNS 故障转移 (方案 A)
  2. 客户端 Failover 辅助配置 (方案 B)
  0. 返回"
    read -e -r -p "选择: " fo_mode
    [[ "$fo_mode" == "0" || -z "$fo_mode" ]] && return
    if [[ "$fo_mode" == "2" ]]; then
        _wg_failover_client_helper
        return
    fi

    # ── 方案 A: DNS 故障转移 ──
    echo ""
    print_info "配置 DNS 故障转移"
    local ep_domain=$(wg_db_get '.server.endpoint')
    if [[ "$ep_domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        print_error "当前 endpoint 是 IP 地址 ($ep_domain)，DNS 故障转移需要域名"
        echo "  请先修改服务端 endpoint 为域名 (菜单 11)"
        pause; return
    fi
    echo -e "  Endpoint 域名: ${C_GREEN}${ep_domain}${C_RESET}"
    local cf_token=""
    while [[ -z "$cf_token" ]]; do
        read -s -r -p "Cloudflare API Token (需 DNS 编辑权限): " cf_token; echo ""
    done

    # 验证 token
    print_info "验证 Token..."
    local vr=$(_cf_api GET "/user/tokens/verify" "$cf_token")
    if ! _cf_api_ok "$vr"; then
        print_error "Token 验证失败"; pause; return
    fi
    local zone_id=$(_cf_get_zone_id "$ep_domain" "$cf_token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID"; pause; return
    fi
    print_success "Token 有效, Zone: $zone_id"
    local check_interval=30
    read -e -r -p "检测间隔秒 [30]: " check_interval
    check_interval=${check_interval:-30}
    local fail_threshold=3
    read -e -r -p "连续失败几次触发切换 [3]: " fail_threshold
    fail_threshold=${fail_threshold:-3}

    # 收集所有节点的公网 IP
    local primary_ip=$(get_public_ipv4)
    echo -e "  主机公网 IP: ${C_GREEN}${primary_ip}${C_RESET}"
    local -a node_names_arr=() node_ips_arr=()
    local ni=0
    while [[ $ni -lt $node_count ]]; do
        local nname=$(wg_db_get ".cluster.nodes[$ni].name")
        local nep=$(wg_db_get ".cluster.nodes[$ni].endpoint")
        node_names_arr+=("$nname")
        node_ips_arr+=("$nep")
        echo -e "  ${nname} 公网: ${C_GREEN}${nep}${C_RESET}"
        ni=$((ni+1))
    done
    local primary_vpn_ip=$(wg_db_get '.server.ip')
    draw_line
    echo -e "${C_CYAN}故障转移配置:${C_RESET}"
    echo "  域名:       $ep_domain"
    echo "  主机 IP:    $primary_ip"
    echo "  检测间隔:   ${check_interval}s"
    echo "  失败阈值:   连续 ${fail_threshold} 次"
    echo "  切换动作:   修改 $ep_domain A 记录指向其他节点"
    draw_line
    if ! confirm "确认部署?"; then pause; return; fi

    # 保存配置
    wg_db_set --arg mode "dns" \
              --arg domain "$ep_domain" \
              --arg token "$cf_token" \
              --arg zone "$zone_id" \
              --arg pip "$primary_ip" \
              --arg pvip "$primary_vpn_ip" \
              --argjson interval "$check_interval" \
              --argjson threshold "$fail_threshold" \
    '.cluster.failover = {
        enabled: true, mode: $mode, domain: $domain,
        cf_token: $token, zone_id: $zone, primary_ip: $pip,
        primary_vpn_ip: $pvip,
        interval: $interval, threshold: $threshold
    }'

    # 生成 failover 脚本 (部署到每个节点)
    local ni2=0
    while [[ $ni2 -lt $node_count ]]; do
        local nname=$(wg_db_get ".cluster.nodes[$ni2].name")
        local nep=$(wg_db_get ".cluster.nodes[$ni2].endpoint")
        local ssh_host=$(wg_db_get ".cluster.nodes[$ni2].ssh_host")
        local ssh_port=$(wg_db_get ".cluster.nodes[$ni2].ssh_port")
        local ssh_user=$(wg_db_get ".cluster.nodes[$ni2].ssh_user")
        local ssh_opts=$(wg_ssh_opts "$ssh_port")
        local ssh_target="${ssh_user}@${ssh_host}"
        print_info "部署 failover 到 ${nname}..."
        local fo_script=$(mktemp)
        cat > "$fo_script" << FOSCRIPT
#!/bin/bash
# WireGuard DNS Failover - deployed on ${nname}
LOG="/var/log/wg-failover.log"
DOMAIN="${ep_domain}"
CF_TOKEN="${cf_token}"
ZONE_ID="${zone_id}"
PRIMARY_IP="${primary_ip}"
MY_IP="${nep}"
PRIMARY_VPN_IP="${primary_vpn_ip}"
THRESHOLD=${fail_threshold}
FAIL_FILE="/tmp/.wg-fo-fail-count"

log() { echo "[\$(date '+%Y-%m-%d %H:%M:%S')] \$1" >> "\$LOG"; }

# 获取当前 DNS 指向
current_dns() {
    local resp=\$(curl -s "https://api.cloudflare.com/client/v4/zones/\${ZONE_ID}/dns_records?type=A&name=\${DOMAIN}" \
        -H "Authorization: Bearer \${CF_TOKEN}" -H "Content-Type: application/json")
    echo "\$resp" | grep -o '"content":"[^"]*"' | head -1 | cut -d'"' -f4
}

# 更新 DNS
update_dns() {
    local new_ip=\$1
    local resp=\$(curl -s "https://api.cloudflare.com/client/v4/zones/\${ZONE_ID}/dns_records?type=A&name=\${DOMAIN}" \
        -H "Authorization: Bearer \${CF_TOKEN}" -H "Content-Type: application/json")
    local rid=\$(echo "\$resp" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "\$rid" ]; then
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/\${ZONE_ID}/dns_records/\${rid}" \
            -H "Authorization: Bearer \${CF_TOKEN}" -H "Content-Type: application/json" \
            --data "{\"type\":\"A\",\"name\":\"\${DOMAIN}\",\"content\":\"\${new_ip}\",\"ttl\":60,\"proxied\":false}" >/dev/null 2>&1
    fi
}

# 检测主机是否存活 (通过 VPN 内网 ping)
primary_alive=false
if ping -c 2 -W 3 "\$PRIMARY_VPN_IP" &>/dev/null; then
    primary_alive=true
fi

# 也尝试公网 ping
if [ "\$primary_alive" = "false" ]; then
    ping -c 2 -W 3 "\$PRIMARY_IP" &>/dev/null && primary_alive=true
fi

current=\$(current_dns)

if [ "\$primary_alive" = "true" ]; then
    # 主机存活
    echo 0 > "\$FAIL_FILE" 2>/dev/null
    # 如果当前指向自己，切回主机
    if [ "\$current" = "\$MY_IP" ]; then
        log "PRIMARY recovered, switching DNS back: \$MY_IP -> \$PRIMARY_IP"
        update_dns "\$PRIMARY_IP"
    fi
else
    # 主机不通
    fail_count=0
    [ -f "\$FAIL_FILE" ] && fail_count=\$(cat "\$FAIL_FILE" 2>/dev/null)
    fail_count=\$((fail_count + 1))
    echo "\$fail_count" > "\$FAIL_FILE"

    if [ "\$fail_count" -ge "\$THRESHOLD" ]; then
        if [ "\$current" != "\$MY_IP" ]; then
            log "FAILOVER: primary down (${fail_threshold}x), switching DNS: \$current -> \$MY_IP"
            update_dns "\$MY_IP"
        fi
    else
        log "NOTICE: primary unreachable (\${fail_count}/\${THRESHOLD})"
    fi
fi

# 日志轮转
[ -f "\$LOG" ] && [ \$(wc -l < "\$LOG") -gt 500 ] && { tail -n 300 "\$LOG" > "\${LOG}.tmp" && mv "\${LOG}.tmp" "\$LOG"; }
FOSCRIPT
        if scp -P "${ssh_port}" -o StrictHostKeyChecking=accept-new \
            "$fo_script" "${ssh_target}:/usr/local/bin/wg-failover.sh" 2>/dev/null; then
            local cron_expr="* * * * *"
            if [[ $check_interval -ge 120 ]]; then
                cron_expr="*/$((( check_interval + 59 ) / 60)) * * * *"
            fi
            ssh $ssh_opts "$ssh_target" "
                chmod +x /usr/local/bin/wg-failover.sh
                (crontab -l 2>/dev/null | grep -v wg-failover; echo '${cron_expr} /usr/local/bin/wg-failover.sh >/dev/null 2>&1') | crontab -
            " 2>/dev/null && print_success "${nname}: 已部署" || print_error "${nname}: cron 安装失败"
        else
            print_error "${nname}: SCP 失败"
        fi
        rm -f "$fo_script"
        ni2=$((ni2+1))
    done
    draw_line
    print_success "DNS 故障转移部署完成！"
    draw_line
    echo -e "${C_CYAN}工作流程:${C_RESET}"
    echo "  正常: 客户端 → ${ep_domain} → ${primary_ip} (本机)"
    echo "  故障: 本机连续 ${fail_threshold} 次不通"
    echo "        → 其他节点修改 DNS: ${ep_domain} → 节点 IP"
    echo "  恢复: 本机恢复后自动切回 DNS
"
    echo -e "${C_YELLOW}注意:${C_RESET}"
    echo "  • DNS TTL 设为 60s，切换后约 1-2 分钟生效
  • 多个节点时，先检测到故障的节点接管
  • 客户端需使用域名作为 endpoint (非 IP)"
    log_action "Cluster DNS failover deployed: domain=$ep_domain threshold=$fail_threshold"
    pause
}

_wg_failover_client_helper() {
    print_title "客户端 Failover 辅助配置"
    echo "此功能帮你批量重新生成客户端配置，使其包含所有节点 endpoint。
客户端看门狗会自动在多个 endpoint 间切换。
"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    local server_ep=$(wg_db_get '.server.endpoint')
    local server_port=$(wg_db_get '.server.port')
    echo -e "  主机: ${C_GREEN}${server_ep}:${server_port}${C_RESET}"
    local ni=0
    while [[ $ni -lt $node_count ]]; do
        local nname=$(wg_db_get ".cluster.nodes[$ni].name")
        local nep=$(wg_db_get ".cluster.nodes[$ni].endpoint")
        local nport=$(wg_db_get ".cluster.nodes[$ni].port")
        echo -e "  ${nname}: ${C_GREEN}${nep}:${nport}${C_RESET}"
        ni=$((ni+1))
    done
    echo "客户端看门狗配置时，将自动包含以上所有 endpoint 作为 failover 候选。
操作建议:
  1. 在客户端设备上安装本脚本的 WG 客户端模式
  2. 启用看门狗时选择 '配置多服务器 failover'
  3. 输入以上所有节点 endpoint
或者使用 Clash/OpenClash 的 url-test 模式 (菜单 6) 自动选最优节点。"
    pause
}

wg_mesh_watchdog_setup() {
    local auto_mode="${1:-false}"  # 自动模式：跳过交互确认
    wg_check_server || return 1
    wg_cluster_mesh_init_db
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled')
    local watchdog_script="/usr/local/bin/wg-mesh-watchdog.sh"
    local watchdog_log="/var/log/wg-mesh-watchdog.log"

    if [[ "$auto_mode" != "true" ]]; then
        print_title "Mesh 看门狗"
    fi

    if [[ "$mesh_enabled" != "true" ]]; then
        [[ "$auto_mode" != "true" ]] && print_warn "Mesh 未启用，请先部署 Mesh 互联" && pause
        return
    fi

    # 已启用时的管理界面（仅交互模式）
    if [[ "$auto_mode" != "true" ]] && crontab -l 2>/dev/null | grep -q "wg-mesh-watchdog.sh"; then
        echo -e "  状态: ${C_GREEN}已启用${C_RESET}"
        echo "  1. 禁用 Mesh 看门狗
  2. 查看日志
  3. 手动触发检测
  0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1)
                cron_remove_job "wg-mesh-watchdog.sh"
                rm -f "$watchdog_script"
                print_success "Mesh 看门狗已禁用"
                log_action "Mesh watchdog disabled"
                ;;
            2) echo ""; tail -n 30 "$watchdog_log" 2>/dev/null || print_warn "无日志" ;;
            3)
                [[ -x "$watchdog_script" ]] && { bash "$watchdog_script"; print_success "检测完成"; tail -n 5 "$watchdog_log" 2>/dev/null; } || print_warn "脚本不存在"
                ;;
        esac
        pause; return
    fi

    # 自动模式：跳过已安装检查，直接重新部署
    if [[ "$auto_mode" == "true" ]]; then
        local deploy_remote=true
        print_info "自动部署 Mesh 看门狗到所有节点..."
    else
        echo "Mesh 看门狗功能:
  • 每分钟检测 wg-mesh 接口存活
  • 接口消失 → 自动拉起
  • Peer 握手超时 → 重启接口
  • 路由丢失 → 自动修复
  • 可选: 部署到所有节点
"
        if ! confirm "启用 Mesh 看门狗?"; then pause; return; fi
        local deploy_remote=false
        if confirm "是否同时部署到所有节点?"; then
            deploy_remote=true
        fi
    fi

    # 收集 mesh 节点信息用于生成脚本
    local mesh_node_count=$(wg_db_get '.cluster.mesh.nodes | length')
    local peer_lans=""
    local mi=0
    while [[ $mi -lt $mesh_node_count ]]; do
        local nlan=$(wg_db_get ".cluster.mesh.nodes[$mi].lan // empty")
        [[ -n "$nlan" ]] && peer_lans+="${nlan} "
        mi=$((mi+1))
    done

    # 生成看门狗脚本
    cat > "$watchdog_script" << 'MESHWD_HEAD'
#!/bin/bash
LOG="/var/log/wg-mesh-watchdog.log"
IFACE="wg-mesh"
STALE=300
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

# 接口存活检测
if ! ip link show "$IFACE" &>/dev/null; then
    log "WARN: $IFACE missing, restarting"
    wg-quick up "$IFACE" 2>>"$LOG"
    sleep 2
    ip link show "$IFACE" &>/dev/null && log "OK: $IFACE recovered" || log "ERROR: restart failed"
    exit 0
fi

# wg show 检测
if ! wg show "$IFACE" &>/dev/null; then
    log "WARN: wg show $IFACE failed, restarting"
    wg-quick down "$IFACE" 2>>"$LOG"; sleep 1
    wg-quick up "$IFACE" 2>>"$LOG"
    exit 0
fi

# Peer 握手检测
now=$(date +%s)
all_stale=true
while IFS=$'\t' read -r _ _ _ _ last_hs _ _ _; do
    [[ -z "$last_hs" || "$last_hs" == "0" ]] && continue
    age=$((now - last_hs))
    [[ $age -lt $STALE ]] && { all_stale=false; break; }
done < <(wg show "$IFACE" dump 2>/dev/null | tail -n +2)

if [[ "$all_stale" == "true" ]]; then
    peer_count=$(wg show "$IFACE" dump 2>/dev/null | tail -n +2 | wc -l)
    if [[ "$peer_count" -gt 0 ]]; then
        if [[ -f /tmp/.mesh-wd-stale ]]; then
            log "WARN: all mesh peers stale 2x, restarting"
            wg-quick down "$IFACE" 2>>"$LOG"; sleep 1
            wg-quick up "$IFACE" 2>>"$LOG"
            rm -f /tmp/.mesh-wd-stale
        else
            log "NOTICE: all mesh peers stale, flagging"
            touch /tmp/.mesh-wd-stale
        fi
    fi
else
    rm -f /tmp/.mesh-wd-stale 2>/dev/null
fi
MESHWD_HEAD

    # 追加路由修复段
    cat >> "$watchdog_script" << MESHWD_ROUTES

# 路由修复
EXPECTED_LANS="${peer_lans}"
for lan in \$EXPECTED_LANS; do
    if ! ip route show dev "\$IFACE" 2>/dev/null | grep -q "\$lan"; then
        ip route add "\$lan" dev "\$IFACE" 2>/dev/null && log "OK: route restored \$lan" || true
    fi
done
MESHWD_ROUTES

    # 日志轮转
    cat >> "$watchdog_script" << 'MESHWD_TAIL'

# 日志轮转
[[ -f "$LOG" ]] && [[ $(wc -l < "$LOG") -gt 500 ]] && { tail -n 300 "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"; }
MESHWD_TAIL
    chmod +x "$watchdog_script"
    cron_add_job "wg-mesh-watchdog.sh" "* * * * * $watchdog_script >/dev/null 2>&1"
    print_success "主机: Mesh 看门狗已启用"

    # 部署到其他节点
    if [[ "$deploy_remote" == "true" ]]; then
        local node_count=$(wg_db_get '.cluster.nodes | length')
        local ni=0
        while [[ $ni -lt $node_count ]]; do
            local nname=$(wg_db_get ".cluster.nodes[$ni].name")
            local ssh_host=$(wg_db_get ".cluster.nodes[$ni].ssh_host")
            local ssh_port=$(wg_db_get ".cluster.nodes[$ni].ssh_port")
            local ssh_user=$(wg_db_get ".cluster.nodes[$ni].ssh_user")
            local ssh_target="${ssh_user}@${ssh_host}"
            print_info "部署到 ${nname}..."
            local _cm=""
            _cm=$(wg_ssh_cm_start "$ssh_host" "$ssh_port" "$ssh_user" 2>/dev/null) || true
            if [[ -n "$_cm" ]]; then
                local ssh_opts="-o ControlPath=${_cm} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${ssh_port}"
            else
                local ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${ssh_port}"
            fi

            # 为节点生成专属脚本 (路由方向不同)
            local remote_lans=""
            local rmi=0
            while [[ $rmi -lt $mesh_node_count ]]; do
                local rn=$(wg_db_get ".cluster.mesh.nodes[$rmi].name")
                local rl=$(wg_db_get ".cluster.mesh.nodes[$rmi].lan // empty")
                [[ "$rn" != "$nname" && -n "$rl" ]] && remote_lans+="${rl} "
                rmi=$((rmi+1))
            done
            local remote_script=$(mktemp)
            # 复用主体，替换路由段
            sed "s|^EXPECTED_LANS=.*|EXPECTED_LANS=\"${remote_lans}\"|" "$watchdog_script" > "$remote_script"
            # 确保目标目录存在
            ssh $ssh_opts "$ssh_target" "mkdir -p /usr/local/bin" 2>/dev/null
            if scp ${_cm:+-o ControlPath=${_cm}} -P "${ssh_port}" -o StrictHostKeyChecking=accept-new \
                "$remote_script" "${ssh_target}:/usr/local/bin/wg-mesh-watchdog.sh" 2>/dev/null || \
                ssh $ssh_opts "$ssh_target" "cat > /usr/local/bin/wg-mesh-watchdog.sh" < "$remote_script" 2>/dev/null; then
                ssh $ssh_opts "$ssh_target" "
                    chmod +x /usr/local/bin/wg-mesh-watchdog.sh
                    (crontab -l 2>/dev/null | grep -v wg-mesh-watchdog; echo '* * * * * /usr/local/bin/wg-mesh-watchdog.sh >/dev/null 2>&1') | crontab -
                " 2>/dev/null && print_success "${nname}: 已部署" || print_error "${nname}: 部署失败"
            else
                print_error "${nname}: SCP 失败"
            fi
            rm -f "$remote_script"
            ni=$((ni+1))
        done
    fi
    print_success "Mesh 看门狗部署完成"
    echo -e "  脚本: ${C_CYAN}${watchdog_script}${C_RESET}"
    echo -e "  日志: ${C_CYAN}${watchdog_log}${C_RESET}"
    echo "  检测: 接口存活 → 握手超时 → 路由修复 (每分钟)"
    log_action "Mesh watchdog enabled (remote=$deploy_remote)"
    pause
}

wg_cluster_mesh_init_db() {
    wg_cluster_init_db
    local has_mesh=$(wg_db_get '.cluster.mesh // empty')
    if [[ -z "$has_mesh" || "$has_mesh" == "null" ]]; then
        wg_db_set '.cluster.mesh = {"enabled": false, "peers": []}' 2>/dev/null || true
    fi
}

# 为两个节点生成 mesh peer 密钥对
# mesh peer 存储在 .cluster.mesh.peers[] 中
# 每条记录: {node_a, node_b, psk, a_pubkey, a_privkey, b_pubkey, b_privkey}
wg_cluster_mesh_gen_keypair() {
    local privkey=$(wg genkey)
    local pubkey=$(echo "$privkey" | wg pubkey)
    echo "${privkey}|${pubkey}"
}

wg_cluster_deploy_node() {
    wg_check_server || return 1
    wg_cluster_init_db
    print_title "一键部署新节点"
    echo -e "${C_CYAN}此功能将通过 SSH 自动完成:${C_RESET}"
    echo "  1. 在新节点上安装 WireGuard
  2. 开启 IP 转发
  3. 同步所有 Peers 配置
  4. 启动 WireGuard 并设置开机自启
  5. 放行防火墙端口
  6. (可选) 部署 Mesh 互联
"

    # ── 收集节点信息 ──
    local node_name="" node_endpoint="" node_port="" node_ip=""
    local node_ssh_host="" node_ssh_port="" node_ssh_user=""
    while [[ -z "$node_name" ]]; do
        read -e -r -p "节点名称 (如 jp-node): " node_name
        [[ ! "$node_name" =~ ^[a-zA-Z0-9_-]+$ ]] && { print_warn "名称只能包含字母数字下划线连字符"; node_name=""; }
        local exists=$(wg_db_get --arg n "$node_name" '.cluster.nodes[] | select(.name == $n) | .name')
        [[ -n "$exists" ]] && { print_error "节点名 '$node_name' 已存在"; node_name=""; }
    done
    while [[ -z "$node_endpoint" ]]; do
        read -e -r -p "节点公网 IP/域名: " node_endpoint
    done
    local server_port=$(wg_db_get '.server.port')
    read -e -r -p "节点 WG 端口 [${server_port}]: " node_port
    node_port=${node_port:-$server_port}
    validate_port "$node_port" || { node_port=$server_port; print_warn "使用默认端口 $server_port"; }
    local subnet_prefix=$(wg_db_get '.server.subnet' | cut -d'.' -f1-3)
    while [[ -z "$node_ip" ]]; do
        read -e -r -p "节点 VPN IP [如 ${subnet_prefix}.101]: " node_ip
        [[ ! "$node_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && { print_warn "IP 格式无效"; node_ip=""; }
    done
    read -e -r -p "SSH 主机 [${node_endpoint}]: " node_ssh_host
    node_ssh_host=${node_ssh_host:-$node_endpoint}
    read -e -r -p "SSH 端口 [22]: " node_ssh_port
    node_ssh_port=${node_ssh_port:-22}
    read -e -r -p "SSH 用户 [root]: " node_ssh_user
    node_ssh_user=${node_ssh_user:-root}
    local do_mesh=false
    if confirm "部署完成后是否同时建立 Mesh 互联?"; then
        do_mesh=true
        local node_lan=""
        read -e -r -p "节点 LAN 网段 (无则留空): " node_lan
    fi

    # ── 确认 ──
    draw_line
    echo -e "${C_CYAN}部署确认:${C_RESET}"
    echo "  名称:       $node_name"
    echo "  Endpoint:   $node_endpoint:$node_port"
    echo "  VPN IP:     $node_ip"
    echo "  SSH:        ${node_ssh_user}@${node_ssh_host}:${node_ssh_port}"
    echo "  Mesh:       $do_mesh"
    [[ "$do_mesh" == "true" && -n "$node_lan" ]] && echo "  LAN:        $node_lan"
    draw_line
    if ! confirm "开始部署?"; then pause; return; fi
    local ssh_target="${node_ssh_user}@${node_ssh_host}"

    # ── Step 1: 建立 SSH 连接 (连接复用，仅需认证一次) ──
    echo ""
    print_info "[1/6] 建立 SSH 连接 (连接复用，仅需认证一次)..."
    local cm_socket
    cm_socket=$(wg_ssh_cm_start "$node_ssh_host" "$node_ssh_port" "$node_ssh_user")
    if [[ $? -ne 0 || -z "$cm_socket" ]]; then
        print_error "SSH 连接失败: ${ssh_target}:${node_ssh_port}"
        echo "请检查:
  • SSH 服务是否运行
  • 端口是否正确
  • 密钥/密码是否配置
  • 防火墙是否放行"
        pause; return 1
    fi
    local ssh_opts="-o ControlPath=${cm_socket} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 -p ${node_ssh_port}"
    print_success "SSH 连接成功 (已启用连接复用，后续步骤免密码)"
    # 自动部署 SSH 密钥（使后续操作及仪表盘免密码）
    if wg_setup_ssh_key_auth "$ssh_opts" "$ssh_target"; then
        print_success "SSH 密钥已部署 (后续操作永久免密码)"
    else
        print_warn "SSH 密钥部署失败 (不影响本次部署，后续可手动配置)"
    fi

    # ── Step 2: 检测远程系统并安装 WG ──
    print_info "[2/6] 安装 WireGuard..."
    local install_result
    install_result=$(ssh $ssh_opts "$ssh_target" '
        # 检测系统 (优先检测 openwrt_release，与本地 detect_platform 一致)
        if [ -f /etc/openwrt_release ]; then
            OS_ID="openwrt"
        elif [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_ID="$ID"
            # fallback: ID 为空但有 opkg 则视为 openwrt
            [ -z "$OS_ID" ] && command -v opkg >/dev/null 2>&1 && OS_ID="openwrt"
        else
            command -v opkg >/dev/null 2>&1 && OS_ID="openwrt" || OS_ID="unknown"
        fi

        # 检查是否已安装
        if command -v wg >/dev/null 2>&1; then
            echo "ALREADY_INSTALLED:$OS_ID"
            exit 0
        fi
        case "$OS_ID" in
            ubuntu|debian)
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq wireguard wireguard-tools >/dev/null 2>&1
                ;;
            centos|rhel|rocky|alma)
                if command -v dnf >/dev/null 2>&1; then
                    dnf install -y epel-release >/dev/null 2>&1 || true
                    dnf install -y wireguard-tools >/dev/null 2>&1
                else
                    yum install -y epel-release >/dev/null 2>&1 || true
                    yum install -y wireguard-tools >/dev/null 2>&1
                fi
                ;;
            fedora)
                dnf install -y wireguard-tools >/dev/null 2>&1
                ;;
            alpine)
                apk add wireguard-tools >/dev/null 2>&1
                ;;
            openwrt)
                opkg update >/dev/null 2>&1
                if ! lsmod | grep -q wireguard; then
                    opkg install kmod-wireguard >/dev/null 2>&1 || true
                fi
                opkg install wireguard-tools luci-proto-wireguard >/dev/null 2>&1
                ;;
            *)
                echo "UNSUPPORTED_OS:$OS_ID"
                exit 1
                ;;
        esac
        command -v wg >/dev/null 2>&1 && echo "INSTALL_OK:$OS_ID" || echo "INSTALL_FAIL"
    ' 2>/dev/null)
    # 提取远程系统类型 (用于后续步骤分支判断)
    local remote_os=""
    case "$install_result" in
        *:openwrt*)  remote_os="openwrt" ;;
        *:ubuntu*|*:debian*) remote_os="debian" ;;
        *:centos*|*:rhel*|*:rocky*|*:alma*) remote_os="rhel" ;;
        *:fedora*)   remote_os="fedora" ;;
        *:alpine*)   remote_os="alpine" ;;
    esac
    # 如果自动检测失败，让用户手动选择
    if [[ -z "$remote_os" ]]; then
        print_warn "无法自动检测远程系统类型"
        echo "  请手动选择远程节点的系统类型:"
        echo "  1. Debian/Ubuntu"
        echo "  2. OpenWrt"
        echo "  3. CentOS/RHEL/Rocky/Alma"
        echo "  4. Fedora"
        echo "  5. Alpine"
        echo "  0. 取消部署"
        read -e -r -p "选择 [0-5]: " os_choice
        case "$os_choice" in
            1) remote_os="debian" ;;
            2) remote_os="openwrt" ;;
            3) remote_os="rhel" ;;
            4) remote_os="fedora" ;;
            5) remote_os="alpine" ;;
            *) print_warn "已取消"; pause; return 1 ;;
        esac
        print_info "已手动选择: $remote_os"
    fi
    case "$install_result" in
        *ALREADY_INSTALLED*) print_success "WireGuard 已安装 (跳过)" ;;
        *INSTALL_OK*) print_success "WireGuard 安装成功" ;;
        *UNSUPPORTED_OS*)
            local unsup_os="${install_result##*UNSUPPORTED_OS:}"
            print_error "不支持的远程系统: $unsup_os"
            pause; return 1 ;;
        *)
            print_error "WireGuard 安装失败"
            echo "  远程输出: $install_result"
            pause; return 1 ;;
    esac
    [[ "$remote_os" == "openwrt" ]] && print_info "检测到远程节点为 OpenWrt，将使用 uci 部署方式"

    # ── Step 3: 开启 IP 转发 ──
    print_info "[3/6] 配置 IP 转发..."
    if [[ "$remote_os" == "openwrt" ]]; then
        # OpenWrt 作为路由器默认已开启 IP 转发，确认即可
        ssh $ssh_opts "$ssh_target" 'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true' 2>/dev/null
    else
        ssh $ssh_opts "$ssh_target" '
            sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
            grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null || {
                sed -i "/net.ipv4.ip_forward/d" /etc/sysctl.conf 2>/dev/null
                echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
            }
        ' 2>/dev/null
    fi
    print_success "IP 转发已开启"

    # ── Step 4: 生成新节点独立密钥并上传 wg0.conf ──
    print_info "[4/6] 生成节点独立密钥并上传配置..."
    # 每个节点有自己独立的 WireGuard 密钥对
    # 这是必须的：若所有节点共享同一 public-key，FlClash/mihomo 会将多个 proxy 视为同一个 peer，
    # 导致只有一个节点能建立会话，其他节点永远超时
    local node_privkey node_pubkey
    local key_result
    key_result=$(ssh $ssh_opts "$ssh_target" 'pk=$(wg genkey); echo "$pk"; echo "$pk" | wg pubkey' 2>/dev/null)
    node_privkey=$(printf '%s' "$key_result" | sed -n '1p')
    node_pubkey=$(printf '%s' "$key_result" | sed -n '2p')
    if [[ -z "$node_privkey" || -z "$node_pubkey" ]]; then
        print_error "新节点密钥生成失败，请检查远程节点 wg 工具是否正常"
        pause; return 1
    fi
    print_success "节点独立密钥已生成 (公钥: ${node_pubkey:0:20}...)"
    local server_subnet=$(wg_db_get '.server.subnet')
    local mask=$(echo "$server_subnet" | cut -d'/' -f2)

    # 生成 peers 段
    local peers_block=""
    local pc=$(wg_db_get '.peers | length') pi=0
    while [[ $pi -lt $pc ]]; do
        if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" ]]; then
            peers_block+="\n[Peer]\n"
            peers_block+="PublicKey = $(wg_db_get ".peers[$pi].public_key")\n"
            peers_block+="PresharedKey = $(wg_db_get ".peers[$pi].preshared_key")\n"
            local peer_ip=$(wg_db_get ".peers[$pi].ip")
            local is_gw=$(wg_db_get ".peers[$pi].is_gateway // false")
            local lan_sub=$(wg_db_get ".peers[$pi].lan_subnets // empty")
            if [[ "$is_gw" == "true" && -n "$lan_sub" ]]; then
                peers_block+="AllowedIPs = ${peer_ip}/32, ${lan_sub}\n"
            else
                peers_block+="AllowedIPs = ${peer_ip}/32\n"
            fi
        fi
        pi=$((pi+1))
    done

    if [[ "$remote_os" == "openwrt" ]]; then
        # ── OpenWrt: 通过 uci 命令配置 WireGuard 接口 ──
        # 构建 uci peers 命令
        local uci_peers_cmds=""
        pi=0
        local peer_idx=0
        while [[ $pi -lt $pc ]]; do
            if [[ "$(wg_db_get ".peers[$pi].enabled")" == "true" ]]; then
                local p_name=$(wg_db_get ".peers[$pi].name")
                local p_pubkey=$(wg_db_get ".peers[$pi].public_key")
                local p_psk=$(wg_db_get ".peers[$pi].preshared_key")
                local p_ip=$(wg_db_get ".peers[$pi].ip")
                local p_is_gw=$(wg_db_get ".peers[$pi].is_gateway // false")
                local p_lan=$(wg_db_get ".peers[$pi].lan_subnets // empty")
                local peer_section="wg_peer${peer_idx}"
                uci_peers_cmds+="uci set network.${peer_section}=wireguard_wg0
uci set network.${peer_section}.description='${p_name}'
uci set network.${peer_section}.public_key='${p_pubkey}'
uci set network.${peer_section}.preshared_key='${p_psk}'
uci delete network.${peer_section}.allowed_ips 2>/dev/null; true
uci add_list network.${peer_section}.allowed_ips='${p_ip}/32'
"
                if [[ "$p_is_gw" == "true" && -n "$p_lan" ]]; then
                    local IFS_BAK="$IFS"
                    IFS=','
                    for cidr in $p_lan; do
                        cidr=$(echo "$cidr" | xargs)
                        [[ -n "$cidr" ]] && uci_peers_cmds+="uci add_list network.${peer_section}.allowed_ips='${cidr}'
"
                    done
                    IFS="$IFS_BAK"
                fi
                uci_peers_cmds+="uci set network.${peer_section}.route_allowed_ips='1'
uci set network.${peer_section}.persistent_keepalive='25'
"
                peer_idx=$((peer_idx+1))
            fi
            pi=$((pi+1))
        done

        local uci_result
        uci_result=$(ssh $ssh_opts "$ssh_target" "
            # 清理旧配置
            uci delete network.wg0 2>/dev/null; true
            uci commit network 2>/dev/null; true
            ifdown wg0 2>/dev/null; true
            # 创建 WireGuard 接口
            uci set network.wg0=interface
            uci set network.wg0.proto='wireguard'
            uci set network.wg0.private_key='${node_privkey}'
            uci set network.wg0.listen_port='${node_port}'
            uci delete network.wg0.addresses 2>/dev/null; true
            uci add_list network.wg0.addresses='${node_ip}/${mask}'
            # 添加 peers
            ${uci_peers_cmds}
            uci commit network
            echo 'UCI_OK'
        " 2>/dev/null)
        if [[ "$uci_result" == *"UCI_OK"* ]]; then
            print_success "uci 配置已写入"
        else
            print_error "uci 配置写入失败"
            echo "  远程输出: $uci_result"
            pause; return 1
        fi
    else
        # ── 标准 Linux: 生成 wg-quick 配置文件 ──
        local tmp_conf=$(mktemp)
        cat > "$tmp_conf" << WGCONF_EOF
[Interface]
PrivateKey = ${node_privkey}
Address = ${node_ip}/${mask}
ListenPort = ${node_port}
PostUp = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -I FORWARD 1 -i %i -j ACCEPT; iptables -I FORWARD 2 -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
PostDown = IFACE=\$(ip route show default | awk '{print \$5; exit}'); iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s ${server_subnet} -o \$IFACE -j MASQUERADE
$(printf '%b' "$peers_block")
WGCONF_EOF
        if scp -o ControlPath="${cm_socket}" -P "${node_ssh_port}" -o StrictHostKeyChecking=accept-new \
            "$tmp_conf" "${ssh_target}:/etc/wireguard/wg0.conf" 2>/dev/null; then
            print_success "配置已上传"
        else
            print_error "配置上传失败"
            rm -f "$tmp_conf"; pause; return 1
        fi
        rm -f "$tmp_conf"
    fi
    # ── Step 5: 启动 WG + 防火墙 + 创建数据库 ──
    print_info "[5/6] 启动 WireGuard 并初始化数据库..."

    # 准备新节点数据库内容（完整配置，包含 public_key、peers、cluster 信息）
    local server_pubkey=$(wg_db_get '.server.public_key')
    local server_dns=$(wg_db_get '.server.dns // "1.1.1.1,8.8.8.8"')
    local my_endpoint=$(wg_db_get '.server.endpoint')
    local my_port=$(wg_db_get '.server.port')
    local my_ip=$(wg_db_get '.server.ip')

    # 构建新节点的 cluster.nodes：包含本机 + 所有已有节点（不包含新节点自己）
    local existing_nodes=$(wg_db_get '.cluster.nodes // []')
    local my_ssh_host my_ssh_port_val my_ssh_user_val
    my_ssh_host=$(wg_db_get '.server.endpoint')
    my_ssh_port_val=22
    my_ssh_user_val="root"
    # 构建本机的节点信息（含本机公钥，供新节点生成 Clash 配置时使用）
    local my_node_json
    my_node_json=$(jq -n \
        --arg name "$(hostname -s)" \
        --arg ep "$my_endpoint" \
        --argjson port "$my_port" \
        --arg ip "$my_ip" \
        --arg pubkey "$server_pubkey" \
        --arg ssh_host "$my_ssh_host" \
        --argjson ssh_port "$my_ssh_port_val" \
        --arg ssh_user "$my_ssh_user_val" \
        '{name:$name, endpoint:$ep, port:$port, ip:$ip, public_key:$pubkey, ssh_host:$ssh_host, ssh_port:$ssh_port, ssh_user:$ssh_user}')
    # 合并：本机信息 + 已有节点 = 新节点看到的 cluster.nodes
    local new_node_cluster_nodes
    new_node_cluster_nodes=$(echo "$existing_nodes" | jq --argjson me "$my_node_json" '. + [$me]')

    local backup_db_content
    backup_db_content=$(jq -n \
        --arg role "server" \
        --arg privkey "$node_privkey" \
        --arg pubkey "$node_pubkey" \
        --arg subnet "$server_subnet" \
        --argjson port "$node_port" \
        --arg ip "$node_ip" \
        --arg ep "$node_endpoint" \
        --arg dns "$server_dns" \
        --argjson peers "$(wg_db_get '.peers // []')" \
        --argjson pf "$(wg_db_get '.port_forwards // []')" \
        --argjson cluster_nodes "$new_node_cluster_nodes" \
        '{
            role: $role,
            server: {
                private_key: $privkey,
                public_key: $pubkey,
                subnet: $subnet,
                port: $port,
                ip: $ip,
                endpoint: $ep,
                dns: $dns
            },
            peers: $peers,
            port_forwards: $pf,
            cluster: {
                enabled: true,
                nodes: $cluster_nodes
            }
        }')

    local tmp_db=$(mktemp)
    echo "$backup_db_content" > "$tmp_db"

    local start_result
    if [[ "$remote_os" == "openwrt" ]]; then
        # ── OpenWrt: 配置防火墙 zone + 启动接口 ──
        start_result=$(ssh $ssh_opts "$ssh_target" "
            # 清理旧防火墙配置
            uci delete firewall.wg_zone 2>/dev/null; true
            uci delete firewall.wg_fwd_lan 2>/dev/null; true
            uci delete firewall.wg_fwd_wg 2>/dev/null; true
            uci delete firewall.wg_allow 2>/dev/null; true
            # 防火墙 zone
            uci set firewall.wg_zone=zone
            uci set firewall.wg_zone.name='wg'
            uci set firewall.wg_zone.input='ACCEPT'
            uci set firewall.wg_zone.output='ACCEPT'
            uci set firewall.wg_zone.forward='ACCEPT'
            uci set firewall.wg_zone.masq='1'
            uci add_list firewall.wg_zone.network='wg0'
            # LAN <-> WG 转发
            uci set firewall.wg_fwd_lan=forwarding
            uci set firewall.wg_fwd_lan.src='lan'
            uci set firewall.wg_fwd_lan.dest='wg'
            uci set firewall.wg_fwd_wg=forwarding
            uci set firewall.wg_fwd_wg.src='wg'
            uci set firewall.wg_fwd_wg.dest='lan'
            # 允许 WAN 入站 WireGuard 端口
            uci set firewall.wg_allow=rule
            uci set firewall.wg_allow.name='Allow-WireGuard'
            uci set firewall.wg_allow.src='wan'
            uci set firewall.wg_allow.dest_port='${node_port}'
            uci set firewall.wg_allow.proto='udp'
            uci set firewall.wg_allow.target='ACCEPT'
            uci commit firewall
            /etc/init.d/firewall reload 2>/dev/null || true
            # 启动 WireGuard 接口
            ifdown wg0 2>/dev/null; true
            /etc/init.d/network reload 2>/dev/null
            sleep 2
            ifup wg0 2>/dev/null
            sleep 2
            # 验证
            ip link show wg0 &>/dev/null && echo 'WG_UP' || echo 'WG_DOWN'
        " 2>/dev/null)
    else
        # ── 标准 Linux: wg-quick + systemctl + ufw ──
        start_result=$(ssh $ssh_opts "$ssh_target" "
            chmod 600 /etc/wireguard/wg0.conf
            # 停止旧实例
            ip link show wg0 &>/dev/null && wg-quick down wg0 2>/dev/null || true
            # 启动
            wg-quick up wg0 2>/dev/null
            systemctl enable wg-quick@wg0 2>/dev/null || true
            # 防火墙
            if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active'; then
                ufw allow ${node_port}/udp comment 'WireGuard' >/dev/null 2>&1
            fi
            # 验证
            ip link show wg0 &>/dev/null && echo 'WG_UP' || echo 'WG_DOWN'
        " 2>/dev/null)
    fi

    if [[ "$start_result" == *"WG_UP"* ]]; then
        print_success "WireGuard 已启动"
        # 上传数据库和角色标识
        # 先创建数据库目录
        ssh $ssh_opts "$ssh_target" "mkdir -p /etc/wireguard/db" 2>/dev/null
        if scp -o ControlPath="${cm_socket}" -P "${node_ssh_port}" -o StrictHostKeyChecking=accept-new \
            "$tmp_db" "${ssh_target}:/etc/wireguard/db/wg-data.json" 2>/dev/null; then
            ssh $ssh_opts "$ssh_target" "
                chmod 600 /etc/wireguard/db/wg-data.json
                mkdir -p /etc/wireguard
                echo 'server' > /etc/wireguard/.role
                chmod 600 /etc/wireguard/.role
            " 2>/dev/null
            print_success "数据库已初始化 (节点可独立管理)"
        else
            print_warn "数据库上传失败 (不影响运行，但节点脚本管理功能受限)"
        fi
    else
        print_error "WireGuard 启动失败"
        if [[ "$remote_os" == "openwrt" ]]; then
            echo "  请 SSH 到节点检查: wg show; logread | grep -i wireguard"
        else
            echo "  请 SSH 到节点检查: journalctl -u wg-quick@wg0"
        fi
    fi
    rm -f "$tmp_db"

    # ── Step 6: 保存节点到 DB ──
    print_info "[6/6] 保存节点信息..."
    wg_db_set --arg name "$node_name" \
              --arg ep "$node_endpoint" \
              --argjson port "$node_port" \
              --arg ip "$node_ip" \
              --arg pubkey "$node_pubkey" \
              --arg ssh_host "$node_ssh_host" \
              --argjson ssh_port "$node_ssh_port" \
              --arg ssh_user "$node_ssh_user" \
              --arg os "${remote_os:-}" \
    '.cluster.enabled = true | .cluster.nodes += [{
        name: $name, endpoint: $ep, port: $port, ip: $ip, public_key: $pubkey,
        ssh_host: $ssh_host, ssh_port: $ssh_port, ssh_user: $ssh_user, os: $os
    }]'
    if [[ "$do_mesh" == "true" && -n "${node_lan:-}" ]]; then
        local ni=$(wg_db_get '.cluster.nodes | length')
        wg_db_set --argjson idx "$((ni-1))" --arg lan "$node_lan" '.cluster.nodes[$idx].lan_subnet = $lan'
    fi
    print_success "节点 '${node_name}' 已保存到集群"

    # ── 反向注册：将新节点信息推送给所有其他已有节点 ──
    local other_count=$(echo "$existing_nodes" | jq 'length')
    if [[ "$other_count" -gt 0 ]]; then
        print_info "同步新节点信息到其他 ${other_count} 个节点..."
        local oi=0
        while [[ $oi -lt $other_count ]]; do
            local o_name=$(echo "$existing_nodes" | jq -r ".[$oi].name")
            local o_ssh_host=$(echo "$existing_nodes" | jq -r ".[$oi].ssh_host")
            local o_ssh_port=$(echo "$existing_nodes" | jq -r ".[$oi].ssh_port")
            local o_ssh_user=$(echo "$existing_nodes" | jq -r ".[$oi].ssh_user")
            local _ocm=""
            _ocm=$(wg_ssh_cm_start "$o_ssh_host" "$o_ssh_port" "$o_ssh_user" 2>/dev/null) || true
            if [[ -n "$_ocm" ]]; then
                local o_ssh_opts="-o ControlPath=${_ocm} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${o_ssh_port}"
            else
                local o_ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${o_ssh_port}"
            fi
            # 在远程节点的数据库中添加新节点（含 public_key 以支持 Clash 多节点独立密钥）
            local add_node_cmd="
                if [ -f /etc/wireguard/db/wg-data.json ]; then
                    jq --arg name '${node_name}' \
                       --arg ep '${node_endpoint}' \
                       --argjson port ${node_port} \
                       --arg ip '${node_ip}' \
                       --arg pubkey '${node_pubkey}' \
                       --arg ssh_host '${node_ssh_host}' \
                       --argjson ssh_port ${node_ssh_port} \
                       --arg ssh_user '${node_ssh_user}' \
                       '.cluster.enabled = true | .cluster.nodes += [{name:\$name,endpoint:\$ep,port:\$port,ip:\$ip,public_key:\$pubkey,ssh_host:\$ssh_host,ssh_port:\$ssh_port,ssh_user:\$ssh_user}]' \
                       /etc/wireguard/db/wg-data.json > /tmp/.wg-db-tmp.json && \
                    mv /tmp/.wg-db-tmp.json /etc/wireguard/db/wg-data.json && \
                    chmod 600 /etc/wireguard/db/wg-data.json && \
                    echo 'NODE_ADDED'
                else
                    echo 'NO_DB'
                fi
            "
            local add_result
            add_result=$(ssh $o_ssh_opts "${o_ssh_user}@${o_ssh_host}" "$add_node_cmd" 2>/dev/null) || true
            if [[ "$add_result" == *"NODE_ADDED"* ]]; then
                print_success "  ${o_name}: 已注册新节点"
            else
                print_warn "  ${o_name}: 注册失败 (${add_result:-SSH连接失败})"
            fi
            [[ -n "$_ocm" ]] && ssh -O exit -o ControlPath="${_ocm}" "${o_ssh_user}@${o_ssh_host}" 2>/dev/null || true
            oi=$((oi+1))
        done
    fi

    # ── 验证连通性 ──
    echo ""
    print_info "验证连通性..."
    sleep 2
    if ping -c 2 -W 3 "$node_ip" &>/dev/null; then
        echo -e "  Ping ${node_ip}: ${C_GREEN}✓ 可达${C_RESET}"
    else
        echo -e "  Ping ${node_ip}: ${C_YELLOW}暂不可达 (可能需要等待几秒)${C_RESET}"
    fi

    # ── 可选 Mesh ──
    if [[ "$do_mesh" == "true" ]]; then
        print_info "开始部署 Mesh 互联..."
        wg_cluster_mesh_setup
        return
    fi
    draw_line
    print_success "节点 '${node_name}' 一键部署完成！"
    draw_line
    echo -e "  ${C_CYAN}后续操作:${C_RESET}"
    echo "  • 添加新 Peer 后使用 '同步 Peers' 保持一致
  • 使用 '部署 Mesh' 建立节点间互通
  • 使用 '集群健康仪表盘' 监控所有节点"
    log_action "WG node deployed: $node_name ($node_endpoint:$node_port) mesh=$do_mesh"

    # 自动安装服务端看门狗（主机侧）
    echo ""
    wg_setup_watchdog "true"

    pause
}

wg_cluster_dashboard() {
    wg_check_server || return 1
    wg_cluster_init_db

    while true; do
    print_title "集群健康仪表盘"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$node_count" -eq 0 ]]; then
        print_warn "暂无集群节点"
        pause; return
    fi
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled // false')
    local total_nodes=$((node_count + 1))
    local now=$(date +%s)
    echo -e "  集群规模: ${C_CYAN}${total_nodes}${C_RESET} 节点 | Mesh: $(
        [[ "$mesh_enabled" == "true" ]] && echo -e "${C_GREEN}已启用${C_RESET}" || echo -e "${C_YELLOW}未启用${C_RESET}"
    )"
    echo ""

    # ── 节点状态表 ──
    printf "${C_CYAN}%-3s %-14s %-24s %-10s %-8s %-12s %-8s %s${C_RESET}\n" \
        "#" "名称" "Endpoint" "WG状态" "SSH" "延迟" "Peers" "负载"
    draw_line
    local s_ep=$(wg_db_get '.server.endpoint')
    local s_port=$(wg_db_get '.server.port')
    local s_ip=$(wg_db_get '.server.ip')
    local s_wg_status="${C_RED}停止${C_RESET}"
    wg_is_running && s_wg_status="${C_GREEN}运行${C_RESET}"
    local s_peers=0
    wg_is_running && s_peers=$(wg show "$WG_INTERFACE" dump 2>/dev/null | tail -n +2 | wc -l)
    local s_load=$(awk '{printf "%.1f", $1}' /proc/loadavg 2>/dev/null || echo "N/A")
    printf "%-3s %-14s %-24s %-10b %-10s %-8s %-12s %s\n" \
        "0" "本机" "${s_ep}:${s_port}" "$s_wg_status" \
        "${C_GREEN}本机${C_RESET}" "-" "${s_peers}个" "$s_load"

    # 其他节点
    local i=0 healthy=0 degraded=0 down=0
    while [[ $i -lt $node_count ]]; do
        local name=$(wg_db_get ".cluster.nodes[$i].name")
        local ep=$(wg_db_get ".cluster.nodes[$i].endpoint")
        local port=$(wg_db_get ".cluster.nodes[$i].port")
        local ip=$(wg_db_get ".cluster.nodes[$i].ip")
        local ssh_host=$(wg_db_get ".cluster.nodes[$i].ssh_host")
        local ssh_port=$(wg_db_get ".cluster.nodes[$i].ssh_port")
        local ssh_user=$(wg_db_get ".cluster.nodes[$i].ssh_user")
        local ssh_target="${ssh_user}@${ssh_host}"

        # 尝试使用 ControlMaster 复用连接（若有），否则用 BatchMode
        local _cm_dir="/tmp/.wg-ssh-cm"
        local _cm_sock="${_cm_dir}/${ssh_user}_${ssh_host}_${ssh_port}"
        local ssh_opts
        if [[ -S "$_cm_sock" ]] && ssh -o ControlPath="$_cm_sock" -O check "${ssh_target}" 2>/dev/null; then
            ssh_opts="-o ControlPath=${_cm_sock} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 -p ${ssh_port}"
        else
            ssh_opts="$(wg_ssh_opts "$ssh_port" 5) -o BatchMode=yes"
        fi

        # SSH 可达性
        local ssh_ok=false
        local ssh_status="${C_YELLOW}无密钥${C_RESET}"
        local wg_status="${C_YELLOW}未知${C_RESET}"
        local latency="-" remote_peers="-" remote_load="-"
        local remote_info="" r_wg=""
        if ssh $ssh_opts "$ssh_target" "true" &>/dev/null; then
            ssh_ok=true
            ssh_status="${C_GREEN}正常${C_RESET}"

            # 远程 WG 状态 + peers + 负载 (单次 SSH 获取所有信息)
            remote_info=$(ssh $ssh_opts "$ssh_target" '
                wg_up=0; peers=0; load="N/A"
                ip link show wg0 &>/dev/null && wg_up=1
                [ "$wg_up" -eq 1 ] && peers=$(wg show wg0 dump 2>/dev/null | tail -n +2 | wc -l)
                [ -f /proc/loadavg ] && load=$(awk "{printf \"%.1f\", \$1}" /proc/loadavg)
                echo "${wg_up}|${peers}|${load}"
            ' 2>/dev/null)
            r_wg=$(echo "$remote_info" | cut -d'|' -f1)
            remote_peers=$(echo "$remote_info" | cut -d'|' -f2)
            remote_load=$(echo "$remote_info" | cut -d'|' -f3)
            [[ "$r_wg" == "1" ]] && wg_status="${C_GREEN}运行${C_RESET}" || wg_status="${C_RED}停止${C_RESET}"
        fi

        # Ping 延迟 (到 VPN IP 或 Endpoint)
        local ping_ok=false
        local ping_target ping_out
        [[ "$mesh_enabled" == "true" ]] && ping_target="$ip" || ping_target="$ep"
        ping_out=$(ping -c 1 -W 2 "$ping_target" 2>/dev/null)
        if [[ $? -eq 0 ]]; then
            ping_ok=true
            latency=$(echo "$ping_out" | awk -F'=' '/time=/{print $NF}')
        else
            latency="${C_RED}超时${C_RESET}"
        fi

        # 健康判定（改进: SSH 不通时使用 Mesh 握手/Ping 综合判断）
        if [[ "$ssh_ok" == "true" && -n "$remote_info" && "$r_wg" == "1" ]]; then
            healthy=$((healthy+1))
        elif [[ "$ssh_ok" == "true" && -n "$remote_info" ]]; then
            degraded=$((degraded+1))
        elif [[ "$ssh_ok" != "true" ]]; then
            # SSH 不可用时，检查 Mesh 握手状态
            local mesh_alive=false
            if [[ "$mesh_enabled" == "true" ]] && wg show wg-mesh &>/dev/null; then
                local _mesh_hs
                _mesh_hs=$(wg show wg-mesh dump 2>/dev/null | tail -n +2 | while IFS=$'\t' read -r _ _ _ aips last_hs _ _ _; do
                    if [[ "$aips" == *"${ip}/32"* && "$last_hs" != "0" && -n "$last_hs" ]]; then
                        local _age=$((now - last_hs))
                        [[ $_age -lt 180 ]] && echo "alive"
                    fi
                done)
                [[ "$_mesh_hs" == *"alive"* ]] && mesh_alive=true
            fi
            if [[ "$mesh_alive" == "true" ]]; then
                healthy=$((healthy+1))
                wg_status="${C_GREEN}运行${C_RESET}"
                ssh_status="${C_YELLOW}无密钥${C_RESET}"
            elif [[ "$ping_ok" == "true" ]]; then
                degraded=$((degraded+1))
                ssh_status="${C_YELLOW}无密钥${C_RESET}"
            else
                down=$((down+1))
                ssh_status="${C_RED}不通${C_RESET}"
            fi
        fi
        printf "%-3s %-14s %-24s %-10b %-10b %-8b %-12s %s\n" \
            "$((i+1))" "$name" "${ep}:${port}" "$wg_status" \
            "$ssh_status" "$latency" "${remote_peers}个" "$remote_load"
        i=$((i+1))
    done
    draw_line

    # ── 健康摘要 ──
    local total_healthy=$((healthy + 1))  # +1 for primary
    echo -n "  集群健康: "
    if [[ $down -eq 0 && $degraded -eq 0 ]]; then
        echo -e "${C_GREEN}● 全部正常${C_RESET} ($total_healthy/$total_nodes 在线)"
    elif [[ $down -eq 0 ]]; then
        echo -e "${C_YELLOW}▲ 部分降级${C_RESET} ($total_healthy/$total_nodes 正常, $degraded 降级)"
    else
        echo -e "${C_RED}✗ 存在故障${C_RESET} ($total_healthy/$total_nodes 正常, $degraded 降级, $down 离线)"
    fi

    # ── Mesh 状态 ──
    if [[ "$mesh_enabled" == "true" ]]; then
        echo -e "${C_CYAN}Mesh 互联:${C_RESET}"
        if wg show wg-mesh &>/dev/null; then
            wg show wg-mesh dump 2>/dev/null | tail -n +2 | while IFS=$'\t' read -r pubkey _ endpoint _ last_hs rx tx _; do
                local peer_name="unknown"
                local mnc=$(wg_db_get '.cluster.mesh.nodes | length')
                local mi=0
                while [[ $mi -lt $mnc ]]; do
                    [[ "$(wg_db_get ".cluster.mesh.nodes[$mi].pubkey")" == "$pubkey" ]] && {
                        peer_name=$(wg_db_get ".cluster.mesh.nodes[$mi].name"); break
                    }
                    mi=$((mi+1))
                done
                local hs_str="从未"
                if [[ "$last_hs" != "0" && -n "$last_hs" ]]; then
                    local age=$((now - last_hs))
                    [[ $age -lt 180 ]] && hs_str="${C_GREEN}${age}s前${C_RESET}" || hs_str="${C_YELLOW}${age}s前${C_RESET}"
                fi
                local rx_h=$(numfmt --to=iec-i --suffix=B "$rx" 2>/dev/null || echo "${rx}B")
                local tx_h=$(numfmt --to=iec-i --suffix=B "$tx" 2>/dev/null || echo "${tx}B")
                printf "  %-14s %-20s 握手:%-12b ↓%s ↑%s\n" "$peer_name" "$endpoint" "$hs_str" "$rx_h" "$tx_h"
            done
        else
            echo -e "  ${C_RED}wg-mesh 接口未运行${C_RESET}"
        fi
    fi

    # ── 客户端 Peer 在线统计 ──
    echo -e "${C_CYAN}客户端在线统计:${C_RESET}"
    if wg_is_running; then
        local online=0 offline=0 total_peers=0
        local pc=$(wg_db_get '.peers | length') pi=0
        while [[ $pi -lt $pc ]]; do
            [[ "$(wg_db_get ".peers[$pi].enabled")" != "true" ]] && { pi=$((pi+1)); continue; }
            total_peers=$((total_peers+1))
            local ppub=$(wg_db_get ".peers[$pi].public_key")
            local last_hs=$(wg show "$WG_INTERFACE" dump 2>/dev/null | grep "^${ppub}" | awk '{print $5}')
            if [[ -n "$last_hs" && "$last_hs" != "0" ]]; then
                local age=$((now - last_hs))
                [[ $age -lt 180 ]] && online=$((online+1)) || offline=$((offline+1))
            else
                offline=$((offline+1))
            fi
            pi=$((pi+1))
        done
        echo -e "  在线: ${C_GREEN}${online}${C_RESET} | 离线: ${C_GRAY}${offline}${C_RESET} | 总计: ${total_peers}"
    fi

    # ── 告警 ──
    local alerts=0
    if [[ $down -gt 0 ]]; then
        echo -e "  ${C_RED}[告警]${C_RESET} $down 个节点离线"
        alerts=$((alerts+1))
    fi
    if [[ $degraded -gt 0 ]]; then
        echo -e "  ${C_YELLOW}[警告]${C_RESET} $degraded 个节点 WG 未运行"
        alerts=$((alerts+1))
    fi
    if [[ "$mesh_enabled" == "true" ]] && ! ip link show wg-mesh &>/dev/null; then
        echo -e "  ${C_RED}[告警]${C_RESET} 本机 Mesh 接口未运行"
        alerts=$((alerts+1))
    fi
    [[ $alerts -eq 0 ]] && echo -e "  ${C_GREEN}无告警${C_RESET}"
    echo -e "${C_GRAY}提示: 按 Enter 刷新, 输入 q 退出${C_RESET}"
    read -e -r -p "" dash_input
    [[ "$dash_input" == "q" || "$dash_input" == "Q" ]] && return
    done
}

wg_cluster_mesh_setup() {
    wg_check_server || return 1
    wg_cluster_mesh_init_db
    print_title "Mesh 全互联配置"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    if [[ "$node_count" -eq 0 ]]; then
        print_warn "至少需要 1 个集群节点才能建立 Mesh"
        pause; return
    fi
    local -a node_names=() node_eps=() node_ports=() node_ips=()
    local -a node_ssh_hosts=() node_ssh_ports=() node_ssh_users=()
    local -a node_lans=()
    node_names+=("primary")
    node_eps+=("$(wg_db_get '.server.endpoint')")
    node_ports+=("$(wg_db_get '.server.port')")
    node_ips+=("$(wg_db_get '.server.ip')")
    node_ssh_hosts+=("localhost")
    node_ssh_ports+=("0")
    node_ssh_users+=("root")
    node_lans+=("")
    local i=0
    while [[ $i -lt $node_count ]]; do
        node_names+=("$(wg_db_get ".cluster.nodes[$i].name")")
        node_eps+=("$(wg_db_get ".cluster.nodes[$i].endpoint")")
        node_ports+=("$(wg_db_get ".cluster.nodes[$i].port")")
        node_ips+=("$(wg_db_get ".cluster.nodes[$i].ip")")
        node_ssh_hosts+=("$(wg_db_get ".cluster.nodes[$i].ssh_host")")
        node_ssh_ports+=("$(wg_db_get ".cluster.nodes[$i].ssh_port")")
        node_ssh_users+=("$(wg_db_get ".cluster.nodes[$i].ssh_user")")
        node_lans+=("")
        i=$((i+1))
    done
    local total=${#node_names[@]}
    echo "集群节点 ($total 台):"
    local idx=0
    while [[ $idx -lt $total ]]; do
        local role_tag="节点"
        [[ $idx -eq 0 ]] && role_tag="主机"
        echo "  ${idx}. [${role_tag}] ${node_names[$idx]} (${node_eps[$idx]}:${node_ports[$idx]}) VPN=${node_ips[$idx]}"
        idx=$((idx+1))
    done
    echo "Mesh 将在 $total 台节点间建立 $((total * (total - 1) / 2)) 条互联隧道"
    echo ""
    echo "配置各节点的 LAN 网段 (用于跨节点路由，无则留空):
"
    idx=0
    while [[ $idx -lt $total ]]; do
        local saved_lan=""
        if [[ $idx -eq 0 ]]; then
            saved_lan=$(wg_db_get '.cluster.mesh.primary_lan // empty' 2>/dev/null)
        else
            saved_lan=$(wg_db_get --argjson idx "$((idx-1))" '.cluster.nodes[$idx].lan_subnet // empty' 2>/dev/null)
        fi
        local prompt="  ${node_names[$idx]} LAN 网段"
        [[ -n "$saved_lan" ]] && prompt+=" [${saved_lan}]"
        prompt+=": "
        read -e -r -p "$prompt" input_lan
        input_lan=${input_lan:-$saved_lan}
        node_lans[$idx]="$input_lan"
        idx=$((idx+1))
    done
    draw_line
    echo -e "${C_CYAN}Mesh 拓扑预览:${C_RESET}"
    local a=0
    while [[ $a -lt $total ]]; do
        local b=$((a+1))
        while [[ $b -lt $total ]]; do
            local route_info=""
            [[ -n "${node_lans[$a]}" ]] && route_info+=" → ${node_names[$a]} LAN: ${node_lans[$a]}"
            [[ -n "${node_lans[$b]}" ]] && route_info+=" → ${node_names[$b]} LAN: ${node_lans[$b]}"
            echo "  ${node_names[$a]} ◄──► ${node_names[$b]}${route_info}"
            b=$((b+1))
        done
        a=$((a+1))
    done
    draw_line
    if ! confirm "开始部署 Mesh?"; then pause; return; fi

    # 为所有远程节点建立 SSH 连接复用（仅需认证一次）
    local -a cm_sockets=()
    cm_sockets+=("")  # idx 0 = 主机（本地），不需要 SSH
    idx=1
    while [[ $idx -lt $total ]]; do
        print_info "建立到 ${node_names[$idx]} 的 SSH 连接..."
        local _cm=""
        _cm=$(wg_ssh_cm_start "${node_ssh_hosts[$idx]}" "${node_ssh_ports[$idx]}" "${node_ssh_users[$idx]}" 2>/dev/null) || true
        if [[ -n "$_cm" ]]; then
            print_success "${node_names[$idx]}: SSH 连接复用已建立"
        else
            print_warn "${node_names[$idx]}: SSH 连接复用失败，将使用普通连接"
        fi
        cm_sockets+=("$_cm")
        idx=$((idx+1))
    done

    echo ""
    print_info "生成 Mesh 密钥..."
    local -a mesh_privkeys=() mesh_pubkeys=()
    idx=0
    while [[ $idx -lt $total ]]; do
        local kp_priv=$(wg genkey)
        local kp_pub=$(echo "$kp_priv" | wg pubkey)
        mesh_privkeys+=("$kp_priv")
        mesh_pubkeys+=("$kp_pub")
        idx=$((idx+1))
    done

    # 用扁平数组代替关联数组 (兼容 bash 3.x / ash)
    # pair_psks_keys[n] = "a_b", pair_psks_vals[n] = psk
    local -a pair_psks_keys=() pair_psks_vals=()
    a=0
    while [[ $a -lt $total ]]; do
        local b=$((a+1))
        while [[ $b -lt $total ]]; do
            pair_psks_keys+=("${a}_${b}")
            pair_psks_vals+=("$(wg genpsk)")
            b=$((b+1))
        done
        a=$((a+1))
    done

    # 查找 PSK 的辅助函数
    _mesh_get_psk() {
        local key="$1"
        local n=0
        while [[ $n -lt ${#pair_psks_keys[@]} ]]; do
            [[ "${pair_psks_keys[$n]}" == "$key" ]] && { echo "${pair_psks_vals[$n]}"; return 0; }
            n=$((n+1))
        done
        return 1
    }

    # 保存 mesh 信息到 DB
    local mesh_json='{"enabled": true, "primary_lan": "'"${node_lans[0]}"'", "nodes": ['
    idx=0
    while [[ $idx -lt $total ]]; do
        [[ $idx -gt 0 ]] && mesh_json+=","
        mesh_json+='{"name":"'"${node_names[$idx]}"'","ip":"'"${node_ips[$idx]}"'","privkey":"'"${mesh_privkeys[$idx]}"'","pubkey":"'"${mesh_pubkeys[$idx]}"'","lan":"'"${node_lans[$idx]}"'"}'
        idx=$((idx+1))
    done
    mesh_json+=']}'
    wg_db_set --argjson mesh "$mesh_json" '.cluster.mesh = $mesh'
    idx=1
    while [[ $idx -lt $total ]]; do
        wg_db_set --argjson idx "$((idx-1))" --arg lan "${node_lans[$idx]}" '.cluster.nodes[$idx].lan_subnet = $lan'
        idx=$((idx+1))
    done
    local server_subnet=$(wg_db_get '.server.subnet')
    local mesh_iface="wg-mesh"
    idx=0
    while [[ $idx -lt $total ]]; do
        print_info "部署 Mesh 到 ${node_names[$idx]}..."
        local cur_port=${node_ports[$idx]}
        local mesh_port=$((cur_port + 1))
        if [[ $mesh_port -gt 65535 ]]; then
            print_error "Mesh 端口 $mesh_port 超出范围 (WG端口=$cur_port)，请使用更小的 WG 端口"
            pause; return 1
        fi

        # 构建 PostUp/PostDown 路由命令
        local postup_cmds="" postdown_cmds=""
        local j=0
        while [[ $j -lt $total ]]; do
            if [[ $idx -ne $j && -n "${node_lans[$j]}" ]]; then
                postup_cmds+="PostUp = ip route add ${node_lans[$j]} dev %i 2>/dev/null || true\n"
                postdown_cmds+="PostDown = ip route del ${node_lans[$j]} dev %i 2>/dev/null || true\n"
            fi
            j=$((j+1))
        done

        # 构建 wg-quick 格式配置 (用 printf 代替 echo -e)
        local mesh_conf=""
        mesh_conf+="[Interface]\n"
        mesh_conf+="PrivateKey = ${mesh_privkeys[$idx]}\n"
        mesh_conf+="ListenPort = ${mesh_port}\n"
        mesh_conf+="Address = ${node_ips[$idx]}/32\n"
        [[ -n "$postup_cmds" ]] && mesh_conf+="${postup_cmds}"
        [[ -n "$postdown_cmds" ]] && mesh_conf+="${postdown_cmds}"
        j=0
        while [[ $j -lt $total ]]; do
            if [[ $idx -ne $j ]]; then
                local pa=$idx pb=$j
                [[ $pa -gt $pb ]] && { pa=$j; pb=$idx; }
                local psk=$(_mesh_get_psk "${pa}_${pb}")
                mesh_conf+="\n[Peer]\n"
                mesh_conf+="# ${node_names[$j]}\n"
                mesh_conf+="PublicKey = ${mesh_pubkeys[$j]}\n"
                mesh_conf+="PresharedKey = ${psk}\n"
                local allowed="${node_ips[$j]}/32"
                [[ -n "${node_lans[$j]}" ]] && allowed+=", ${node_lans[$j]}"
                mesh_conf+="AllowedIPs = ${allowed}\n"
                local remote_mesh_port=$((${node_ports[$j]} + 1))
                mesh_conf+="Endpoint = ${node_eps[$j]}:${remote_mesh_port}\n"
                mesh_conf+="PersistentKeepalive = 25\n"
            fi
            j=$((j+1))
        done
        local tmp_conf=$(mktemp)
        printf '%b' "$mesh_conf" > "$tmp_conf"
        if [[ $idx -eq 0 ]]; then
            if [[ "$PLATFORM" == "openwrt" ]]; then
                # ── 本地节点是 OpenWrt: 使用 uci 配置 Mesh ──
                uci delete network.${mesh_iface} 2>/dev/null; true
                uci set network.${mesh_iface}=interface
                uci set network.${mesh_iface}.proto='wireguard'
                uci set network.${mesh_iface}.private_key="${mesh_privkeys[$idx]}"
                uci set network.${mesh_iface}.listen_port="${mesh_port}"
                uci delete network.${mesh_iface}.addresses 2>/dev/null; true
                uci add_list network.${mesh_iface}.addresses="${node_ips[$idx]}/32"
                # 添加 mesh peers
                local mj=0
                local mesh_peer_idx=0
                while [[ $mj -lt $total ]]; do
                    if [[ $idx -ne $mj ]]; then
                        local mpa=$idx mpb=$mj
                        [[ $mpa -gt $mpb ]] && { mpa=$mj; mpb=$idx; }
                        local mpsk=$(_mesh_get_psk "${mpa}_${mpb}")
                        local msection="mesh_peer${mesh_peer_idx}"
                        local remote_mp=$((${node_ports[$mj]} + 1))
                        uci set network.${msection}=wireguard_${mesh_iface}
                        uci set network.${msection}.description="${node_names[$mj]}"
                        uci set network.${msection}.public_key="${mesh_pubkeys[$mj]}"
                        uci set network.${msection}.preshared_key="${mpsk}"
                        uci delete network.${msection}.allowed_ips 2>/dev/null; true
                        uci add_list network.${msection}.allowed_ips="${node_ips[$mj]}/32"
                        [[ -n "${node_lans[$mj]}" ]] && uci add_list network.${msection}.allowed_ips="${node_lans[$mj]}"
                        uci set network.${msection}.endpoint_host="${node_eps[$mj]}"
                        uci set network.${msection}.endpoint_port="${remote_mp}"
                        uci set network.${msection}.persistent_keepalive='25'
                        uci set network.${msection}.route_allowed_ips='1'
                        mesh_peer_idx=$((mesh_peer_idx+1))
                    fi
                    mj=$((mj+1))
                done
                # Mesh 防火墙 zone
                uci delete firewall.mesh_zone 2>/dev/null; true
                uci delete firewall.mesh_fwd_lan 2>/dev/null; true
                uci delete firewall.mesh_fwd_mesh 2>/dev/null; true
                uci delete firewall.mesh_allow 2>/dev/null; true
                uci set firewall.mesh_zone=zone
                uci set firewall.mesh_zone.name='mesh'
                uci set firewall.mesh_zone.input='ACCEPT'
                uci set firewall.mesh_zone.output='ACCEPT'
                uci set firewall.mesh_zone.forward='ACCEPT'
                uci set firewall.mesh_zone.masq='1'
                uci add_list firewall.mesh_zone.network="${mesh_iface}"
                uci set firewall.mesh_fwd_lan=forwarding
                uci set firewall.mesh_fwd_lan.src='lan'
                uci set firewall.mesh_fwd_lan.dest='mesh'
                uci set firewall.mesh_fwd_mesh=forwarding
                uci set firewall.mesh_fwd_mesh.src='mesh'
                uci set firewall.mesh_fwd_mesh.dest='lan'
                uci set firewall.mesh_allow=rule
                uci set firewall.mesh_allow.name='Allow-WG-Mesh'
                uci set firewall.mesh_allow.src='wan'
                uci set firewall.mesh_allow.dest_port="${mesh_port}"
                uci set firewall.mesh_allow.proto='udp'
                uci set firewall.mesh_allow.target='ACCEPT'
                uci commit network
                uci commit firewall
                /etc/init.d/firewall reload 2>/dev/null || true
                ifdown "${mesh_iface}" 2>/dev/null; true
                /etc/init.d/network reload 2>/dev/null
                sleep 2
                ifup "${mesh_iface}" 2>/dev/null
            else
                # ── 本地节点是标准 Linux ──
                cp "$tmp_conf" "/etc/wireguard/${mesh_iface}.conf"
                chmod 600 "/etc/wireguard/${mesh_iface}.conf"
                ip link show "$mesh_iface" &>/dev/null && wg-quick down "$mesh_iface" 2>/dev/null
                wg-quick up "$mesh_iface" 2>/dev/null
                systemctl enable "wg-quick@${mesh_iface}" 2>/dev/null || true
                if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
                    ufw allow "${mesh_port}/udp" comment "WG-Mesh" >/dev/null 2>&1
                fi
            fi
            print_success "${node_names[$idx]}: Mesh 已部署 (本地, 端口 ${mesh_port}/udp)"
        else
            local _cm_sock="${cm_sockets[$idx]}"
            if [[ -n "$_cm_sock" ]]; then
                local ssh_opts="-o ControlPath=${_cm_sock} -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${node_ssh_ports[$idx]}"
            else
                local ssh_opts=$(wg_ssh_opts "${node_ssh_ports[$idx]}")
            fi
            local ssh_target="${node_ssh_users[$idx]}@${node_ssh_hosts[$idx]}"

            # 检测远程节点系统类型
            local remote_mesh_os=""
            remote_mesh_os=$(ssh $ssh_opts "$ssh_target" '
                if [ -f /etc/os-release ]; then . /etc/os-release; echo "$ID"; elif [ -f /etc/openwrt_release ]; then echo "openwrt"; else echo "unknown"; fi
            ' 2>/dev/null)

            if [[ "$remote_mesh_os" == "openwrt" ]]; then
                # ── 远程 OpenWrt 节点: 使用 uci 配置 Mesh ──
                # 构建 uci peers 命令
                local uci_mesh_peers=""
                local mj=0
                local mesh_peer_idx=0
                while [[ $mj -lt $total ]]; do
                    if [[ $idx -ne $mj ]]; then
                        local mpa=$idx mpb=$mj
                        [[ $mpa -gt $mpb ]] && { mpa=$mj; mpb=$idx; }
                        local mpsk=$(_mesh_get_psk "${mpa}_${mpb}")
                        local msection="mesh_peer${mesh_peer_idx}"
                        local remote_mp=$((${node_ports[$mj]} + 1))
                        local m_allowed="${node_ips[$mj]}/32"
                        uci_mesh_peers+="uci set network.${msection}=wireguard_${mesh_iface}
uci set network.${msection}.description='${node_names[$mj]}'
uci set network.${msection}.public_key='${mesh_pubkeys[$mj]}'
uci set network.${msection}.preshared_key='${mpsk}'
uci delete network.${msection}.allowed_ips 2>/dev/null; true
uci add_list network.${msection}.allowed_ips='${m_allowed}'
"
                        [[ -n "${node_lans[$mj]}" ]] && uci_mesh_peers+="uci add_list network.${msection}.allowed_ips='${node_lans[$mj]}'
"
                        uci_mesh_peers+="uci set network.${msection}.endpoint_host='${node_eps[$mj]}'
uci set network.${msection}.endpoint_port='${remote_mp}'
uci set network.${msection}.persistent_keepalive='25'
uci set network.${msection}.route_allowed_ips='1'
"
                        mesh_peer_idx=$((mesh_peer_idx+1))
                    fi
                    mj=$((mj+1))
                done
                ssh $ssh_opts "$ssh_target" "
                    # 清理旧 Mesh 配置
                    uci delete network.${mesh_iface} 2>/dev/null; true
                    uci commit network 2>/dev/null; true
                    ifdown ${mesh_iface} 2>/dev/null; true
                    # 创建 Mesh 接口
                    uci set network.${mesh_iface}=interface
                    uci set network.${mesh_iface}.proto='wireguard'
                    uci set network.${mesh_iface}.private_key='${mesh_privkeys[$idx]}'
                    uci set network.${mesh_iface}.listen_port='${mesh_port}'
                    uci delete network.${mesh_iface}.addresses 2>/dev/null; true
                    uci add_list network.${mesh_iface}.addresses='${node_ips[$idx]}/32'
                    # 添加 Mesh peers
                    ${uci_mesh_peers}
                    # Mesh 防火墙
                    uci delete firewall.mesh_zone 2>/dev/null; true
                    uci delete firewall.mesh_fwd_lan 2>/dev/null; true
                    uci delete firewall.mesh_fwd_mesh 2>/dev/null; true
                    uci delete firewall.mesh_allow 2>/dev/null; true
                    uci set firewall.mesh_zone=zone
                    uci set firewall.mesh_zone.name='mesh'
                    uci set firewall.mesh_zone.input='ACCEPT'
                    uci set firewall.mesh_zone.output='ACCEPT'
                    uci set firewall.mesh_zone.forward='ACCEPT'
                    uci set firewall.mesh_zone.masq='1'
                    uci add_list firewall.mesh_zone.network='${mesh_iface}'
                    uci set firewall.mesh_fwd_lan=forwarding
                    uci set firewall.mesh_fwd_lan.src='lan'
                    uci set firewall.mesh_fwd_lan.dest='mesh'
                    uci set firewall.mesh_fwd_mesh=forwarding
                    uci set firewall.mesh_fwd_mesh.src='mesh'
                    uci set firewall.mesh_fwd_mesh.dest='lan'
                    uci set firewall.mesh_allow=rule
                    uci set firewall.mesh_allow.name='Allow-WG-Mesh'
                    uci set firewall.mesh_allow.src='wan'
                    uci set firewall.mesh_allow.dest_port='${mesh_port}'
                    uci set firewall.mesh_allow.proto='udp'
                    uci set firewall.mesh_allow.target='ACCEPT'
                    uci commit network
                    uci commit firewall
                    /etc/init.d/firewall reload 2>/dev/null || true
                    /etc/init.d/network reload 2>/dev/null
                    sleep 2
                    ifup ${mesh_iface} 2>/dev/null
                " 2>/dev/null
                print_success "${node_names[$idx]}: Mesh 已部署 (SSH/uci, 端口 ${mesh_port}/udp)"
            else
                # ── 远程标准 Linux 节点: 使用 wg-quick ──
                if scp ${_cm_sock:+-o ControlPath=${_cm_sock}} -P "${node_ssh_ports[$idx]}" -o StrictHostKeyChecking=accept-new \
                    "$tmp_conf" "${ssh_target}:/etc/wireguard/${mesh_iface}.conf" 2>/dev/null; then
                    ssh $ssh_opts "$ssh_target" "
                        chmod 600 /etc/wireguard/${mesh_iface}.conf
                        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
                        ip link show ${mesh_iface} &>/dev/null && wg-quick down ${mesh_iface} 2>/dev/null
                        wg-quick up ${mesh_iface} 2>/dev/null
                        systemctl enable wg-quick@${mesh_iface} 2>/dev/null || true
                        command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q 'Status: active' && \
                            ufw allow ${mesh_port}/udp comment 'WG-Mesh' >/dev/null 2>&1 || true
                    " 2>/dev/null
                    print_success "${node_names[$idx]}: Mesh 已部署 (SSH, 端口 ${mesh_port}/udp)"
                else
                    print_error "${node_names[$idx]}: SSH 部署失败"
                fi
            fi
        fi
        rm -f "$tmp_conf"
        idx=$((idx+1))
    done

    # 清理辅助函数
    unset -f _mesh_get_psk
    draw_line
    print_success "Mesh 全互联部署完成!"
    draw_line
    echo ""
    echo "  Mesh 接口: ${mesh_iface}"
    echo "  连接数:    $((total * (total - 1) / 2)) 条"
    echo -e "${C_CYAN}各节点 Mesh 端口:${C_RESET}"
    idx=0
    while [[ $idx -lt $total ]]; do
        echo "  ${node_names[$idx]}: $((${node_ports[$idx]} + 1))/udp"
        idx=$((idx+1))
    done
    echo -e "${C_CYAN}路由表 (通过 PostUp 持久化):${C_RESET}"
    idx=0
    while [[ $idx -lt $total ]]; do
        [[ -n "${node_lans[$idx]}" ]] && echo "  ${node_lans[$idx]} → 通过 ${node_names[$idx]}"
        idx=$((idx+1))
    done
    echo "  ${server_subnet} → 通过 wg0 (客户端)"
    echo -e "${C_YELLOW}[防火墙]${C_RESET} 各节点 Mesh 端口已自动放行 (UFW)"
    echo -e "${C_CYAN}验证命令:${C_RESET}"
    echo "  wg show ${mesh_iface}"
    idx=1
    while [[ $idx -lt $total ]]; do
        echo "  ping ${node_ips[$idx]}"
        idx=$((idx+1))
    done
    idx=0
    while [[ $idx -lt $total ]]; do
        [[ -n "${node_lans[$idx]}" ]] && echo "  ping $(echo "${node_lans[$idx]}" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".1"}')   # ${node_names[$idx]} LAN"
        idx=$((idx+1))
    done
    log_action "WG mesh deployed: ${total} nodes, $((total * (total - 1) / 2)) links"

    # 自动部署 Mesh 看门狗（默认安装，保障 Mesh 稳定性）
    echo ""
    wg_mesh_watchdog_setup "true"

    pause
}

wg_cluster_mesh_teardown() {
    wg_check_server || return 1
    wg_cluster_mesh_init_db
    print_title "拆除 Mesh 互联"
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled')
    if [[ "$mesh_enabled" != "true" ]]; then
        print_warn "Mesh 未启用"
        pause; return
    fi
    local mesh_iface="wg-mesh"
    local node_count=$(wg_db_get '.cluster.nodes | length')
    echo "将拆除所有节点的 Mesh 互联:"
    echo "  • 停止并删除 ${mesh_iface} 接口"
    echo "  • 清除 Mesh 路由和防火墙规则
  • 不影响 wg0 主隧道
"
    if ! confirm "确认拆除?"; then pause; return; fi
    print_info "拆除主机 Mesh..."
    if ip link show "$mesh_iface" &>/dev/null; then
        wg-quick down "$mesh_iface" 2>/dev/null
    fi
    systemctl disable "wg-quick@${mesh_iface}" 2>/dev/null || true
    rm -f "/etc/wireguard/${mesh_iface}.conf"
    local primary_port=$(wg_db_get '.server.port')
    if [[ "$primary_port" =~ ^[0-9]+$ ]]; then
        local primary_mesh_port=$((primary_port + 1))
        if command_exists ufw; then
            ufw delete allow "${primary_mesh_port}/udp" 2>/dev/null || true
        fi
    fi
    print_success "本机: 已拆除"

    # 其他节点
    local i=0
    while [[ $i -lt $node_count ]]; do
        local name=$(wg_db_get ".cluster.nodes[$i].name")
        local ssh_host=$(wg_db_get ".cluster.nodes[$i].ssh_host")
        local ssh_port=$(wg_db_get ".cluster.nodes[$i].ssh_port")
        local ssh_user=$(wg_db_get ".cluster.nodes[$i].ssh_user")
        local node_wg_port=$(wg_db_get ".cluster.nodes[$i].port")
        print_info "拆除 ${name}..."
        local ssh_opts="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -p ${ssh_port}"
        local node_mesh_port=$((node_wg_port + 1))
        if ssh $ssh_opts "${ssh_user}@${ssh_host}" "
            ip link show ${mesh_iface} &>/dev/null && wg-quick down ${mesh_iface} 2>/dev/null
            systemctl disable wg-quick@${mesh_iface} 2>/dev/null || true
            rm -f /etc/wireguard/${mesh_iface}.conf
            command -v ufw >/dev/null 2>&1 && ufw delete allow ${node_mesh_port}/udp 2>/dev/null || true
        " 2>/dev/null; then
            print_success "${name}: 已拆除"
        else
            print_error "${name}: SSH 连接失败，请手动清理"
        fi
        i=$((i+1))
    done
    wg_db_set '.cluster.mesh = {"enabled": false, "peers": []}' 2>/dev/null
    echo ""
    print_success "Mesh 已完全拆除"
    log_action "WG mesh teardown complete"
    pause
}

wg_cluster_mesh_status() {
    wg_check_server || return 1
    wg_cluster_mesh_init_db
    print_title "Mesh 互联状态"
    local mesh_enabled=$(wg_db_get '.cluster.mesh.enabled')
    local mesh_iface="wg-mesh"
    if [[ "$mesh_enabled" != "true" ]]; then
        print_warn "Mesh 未启用"
        echo "  使用 '部署 Mesh 全互联' 来建立节点间互通"
        pause; return
    fi
    if ip link show "$mesh_iface" &>/dev/null; then
        echo -e "  本地 Mesh 接口: ${C_GREEN}运行中${C_RESET}"
    else
        echo -e "  本地 Mesh 接口: ${C_RED}未运行${C_RESET}"
    fi
    if wg show "$mesh_iface" &>/dev/null; then
        echo -e "${C_CYAN}Mesh Peers:${C_RESET}"
        local mesh_node_count=$(wg_db_get '.cluster.mesh.nodes | length')
        local now=$(date +%s)

        # 用 process substitution 避免子 shell 变量丢失
        while IFS=$'\t' read -r pubkey psk endpoint allowed_ips last_hs rx tx keepalive; do
            [[ -z "$pubkey" ]] && continue
            local peer_name="unknown"
            local ni=0
            while [[ $ni -lt $mesh_node_count ]]; do
                local npub=$(wg_db_get ".cluster.mesh.nodes[$ni].pubkey")
                if [[ "$npub" == "$pubkey" ]]; then
                    peer_name=$(wg_db_get ".cluster.mesh.nodes[$ni].name")
                    break
                fi
                ni=$((ni+1))
            done
            local status="${C_RED}无握手${C_RESET}"
            if [[ "$last_hs" != "0" && -n "$last_hs" ]]; then
                local age=$((now - last_hs))
                if [[ $age -lt 180 ]]; then
                    status="${C_GREEN}活跃 (${age}s前)${C_RESET}"
                else
                    status="${C_YELLOW}陈旧 (${age}s前)${C_RESET}"
                fi
            fi
            local rx_h=$(numfmt --to=iec-i --suffix=B "$rx" 2>/dev/null || echo "${rx}B")
            local tx_h=$(numfmt --to=iec-i --suffix=B "$tx" 2>/dev/null || echo "${tx}B")
            printf "  %-16s %-24s %-20b  ↓%s ↑%s\n" "$peer_name" "$endpoint" "$status" "$rx_h" "$tx_h"
        done < <(wg show "$mesh_iface" dump 2>/dev/null | tail -n +2)
    else
        print_warn "无法读取 ${mesh_iface} 状态"
    fi
    echo -e "${C_CYAN}连通性测试:${C_RESET}"
    local mesh_node_count=$(wg_db_get '.cluster.mesh.nodes | length')
    local ti=0
    while [[ $ti -lt $mesh_node_count ]]; do
        local nname=$(wg_db_get ".cluster.mesh.nodes[$ti].name")
        local nip=$(wg_db_get ".cluster.mesh.nodes[$ti].ip")
        local nlan=$(wg_db_get ".cluster.mesh.nodes[$ti].lan // empty")
        [[ "$nname" == "primary" ]] && { ti=$((ti+1)); continue; }
        local ping_result="${C_RED}不通${C_RESET}"
        if ping -c 1 -W 2 "$nip" &>/dev/null; then
            local latency=$(ping -c 1 -W 2 "$nip" 2>/dev/null | awk -F'=' '/time=/{print $NF}')
            ping_result="${C_GREEN}${latency}${C_RESET}"
        fi
        printf "  %-16s VPN %-16s %b" "$nname" "$nip" "$ping_result"
        if [[ -n "$nlan" ]]; then
            local lan_gw=$(echo "$nlan" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3".1"}')
            local lan_ping="${C_RED}不通${C_RESET}"
            if ping -c 1 -W 2 "$lan_gw" &>/dev/null; then
                lan_ping="${C_GREEN}通${C_RESET}"
            fi
            printf "    LAN %-16s %b" "$lan_gw" "$lan_ping"
        fi
        ti=$((ti+1))
    done
    echo -e "${C_CYAN}路由表 (mesh 相关):${C_RESET}"
    ip route show dev "$mesh_iface" 2>/dev/null | while read -r line; do
        echo "  $line"
    done
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
        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 运行中${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 已停止${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        fi
        local peer_count=$(wg_db_get '.peers | length')
        echo -e "  设备数: ${C_CYAN}${peer_count}${C_RESET}"

        # 集群状态摘要
        wg_cluster_init_db
        local cluster_enabled=$(wg_db_get '.cluster.enabled')
        local node_count=$(wg_db_get '.cluster.nodes | length')
        if [[ "$cluster_enabled" == "true" && "$node_count" -gt 0 ]]; then
            echo -e "  集群: ${C_GREEN}已启用${C_RESET} (${node_count} 个节点)"
        fi
        echo "  ── 设备管理 ──────────────────
  1. 查看状态
  2. 添加设备
  3. 删除设备
  4. 启用/禁用设备
  5. 查看设备配置/二维码
  6. 生成 Clash/OpenClash 配置
  ── 端口转发 ──────────────────
  7. 端口转发管理
  ── 服务控制 ──────────────────
  8. 启动 WireGuard
  9. 停止 WireGuard
  10. 重启 WireGuard
  11. 修改服务端配置
  12. 卸载 WireGuard
  13. 生成 OpenWrt 清空 WG 配置命令
  14. 服务端看门狗 (自动重启保活)
  ── 集群管理 (高可用) ─────────
  15. 集群健康仪表盘
  16. 一键部署新节点 (SSH 自动安装+同步)
  17. 加入已有集群 (Join)
  18. 移除集群节点
  19. 同步 Peers 到所有节点
  20. 部署 Mesh 全互联
  21. 拆除 Mesh 互联
  22. Mesh 看门狗
  23. 自动故障转移
  ── 数据管理 ──────────────────
  24. 导出设备配置 (JSON)
  25. 导入设备配置 (JSON)
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
            7) wg_port_forward_menu ;;
            8) wg_start; pause ;;
            9) wg_stop; pause ;;
            10) wg_restart; pause ;;
            11) wg_modify_server ;;
            12) wg_uninstall; return ;;
            13) wg_openwrt_clean_cmd ;;
            14) wg_setup_watchdog ;;
            15) wg_cluster_dashboard ;;
            16) wg_cluster_deploy_node ;;
            17) wg_cluster_join ;;
            18) wg_cluster_remove_node ;;
            19) wg_cluster_sync ;;
            20) wg_cluster_mesh_setup ;;
            21) wg_cluster_mesh_teardown ;;
            22) wg_mesh_watchdog_setup ;;
            23) wg_cluster_failover_setup ;;
            24) wg_export_peers ;;
            25) wg_import_peers ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_client_menu() {
    while true; do
        print_title "WireGuard 客户端管理"
        if wg_is_running; then
            echo -e "  状态: ${C_GREEN}● 已连接${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        else
            echo -e "  状态: ${C_RED}● 未连接${C_RESET}    接口: ${C_CYAN}${WG_INTERFACE}${C_RESET}"
        fi
        local client_addr client_ep
        client_addr=$(wg_db_get '.client.address' 2>/dev/null)
        client_ep=$(wg_db_get '.client.server_endpoint' 2>/dev/null)
        [[ -n "$client_addr" && "$client_addr" != "null" ]] && echo -e "  地址: ${C_CYAN}${client_addr}${C_RESET}"
        [[ -n "$client_ep" && "$client_ep" != "null" ]] && echo -e "  服务端: ${C_CYAN}${client_ep}${C_RESET}"
        echo ""
        echo "  1. 查看连接状态
  2. 连接
  3. 断开
  4. 重新连接
  5. 更换配置
  6. 看门狗 (自动重连/DNS重解析)
  7. 卸载 WireGuard
  0. 返回上级菜单
"
        read -e -r -p "$(echo -e "${C_CYAN}选择操作: ${C_RESET}")" choice
        case $choice in
            1) wg_client_status ;;
            2) wg_client_connect; pause ;;
            3) wg_client_disconnect; pause ;;
            4) wg_client_reconnect; pause ;;
            5) wg_client_reconfig ;;
            6) wg_setup_watchdog ;;
            7) wg_uninstall; return ;;
            0|"") return ;;
            *) print_warn "无效选项" ;;
        esac
    done
}

wg_install_menu() {
    print_title "安装 WireGuard"
    echo "  请选择安装模式:
  1. 服务端 (Server) - 作为 VPN 服务器，管理多个客户端
  2. 客户端 (Client) - 连接到已有的 WireGuard 服务器
  0. 返回
"
    read -e -r -p "$(echo -e "${C_CYAN}选择: ${C_RESET}")" mode
    case $mode in
        1) wg_server_install ;;
        2) wg_client_install ;;
        0|"") return ;;
        *) print_warn "无效选项" ;;
    esac
}

wg_main_menu() {
    while true; do
        if wg_is_installed; then
            local role
            role=$(wg_get_role)
            case $role in
                server) wg_server_menu; return ;;
                client) wg_client_menu; return ;;
                *)
                    if [[ -f "$WG_CONF" ]] && grep -q "ListenPort" "$WG_CONF" && grep -q "\[Peer\]" "$WG_CONF"; then
                        if grep -c "\[Peer\]" "$WG_CONF" | grep -q "^1$" && ! grep -q "PostUp" "$WG_CONF"; then
                            print_warn "检测到 WireGuard 已安装但角色未知"
                            echo "  1. 作为服务端管理
  2. 作为客户端管理
  3. 卸载重装
  0. 返回"
                            read -e -r -p "选择: " rc
                            case $rc in
                                1) wg_set_role "server"; continue ;;
                                2) wg_set_role "client"; continue ;;
                                3) wg_uninstall; continue ;;
                                *) return ;;
                            esac
                        else
                            wg_set_role "server"; continue
                        fi
                    elif [[ -f "$WG_CONF" ]]; then
                        wg_set_role "client"; continue
                    else
                        print_warn "WireGuard 已安装但无配置文件"
                        echo "  1. 安装为服务端
  2. 安装为客户端
  3. 卸载
  0. 返回"
                        read -e -r -p "选择: " rc2
                        case $rc2 in
                            1) wg_server_install; continue ;;
                            2) wg_client_install; continue ;;
                            3) wg_uninstall; continue ;;
                            *) return ;;
                        esac
                    fi
                    ;;
            esac
        else
            wg_install_menu
            wg_is_installed || return
        fi
    done
}
