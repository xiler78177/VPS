# modules/11d-wireguard-peers.sh - WireGuard peer management
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

# === 清理旧配置 ===
# 停止所有 WireGuard 接口
ifdown wg0 2>/dev/null; true
ifdown wg_mesh 2>/dev/null; true
# 强制删除内核接口 (确保不残留)
for iface in \$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print \$2}'); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
    echo "[+] 已删除接口: \$iface"
done
for iface in wg0 wg_mesh wg-mesh; do
    if ip link show "\$iface" >/dev/null 2>&1; then
        ip link set "\$iface" down 2>/dev/null; true
        ip link delete "\$iface" 2>/dev/null; true
        echo "[+] 已删除接口: \$iface"
    fi
done

# 清理看门狗
rm -f /usr/bin/wg-watchdog.sh 2>/dev/null; true
(crontab -l 2>/dev/null | grep -v wg-watchdog) | crontab - 2>/dev/null; true
/etc/init.d/cron restart 2>/dev/null; true

# 删除所有 wireguard peer 配置段 (含匿名段)
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done
while uci -q get network.@wireguard_wg_mesh[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg_mesh[0]
done
uci delete network.wg_server 2>/dev/null; true

# 删除网络接口
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_mesh 2>/dev/null; true

# 删除防火墙配置 (命名段 + 匿名段)
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci delete firewall.wg_mesh_zone 2>/dev/null; true
uci delete firewall.wg_mesh_fwd 2>/dev/null; true
uci delete firewall.wg_mesh_fwd_lan 2>/dev/null; true
# 清理匿名 zone
i=0
while uci get firewall.@zone[\$i] >/dev/null 2>&1; do
    zname=\$(uci get firewall.@zone[\$i].name 2>/dev/null)
    case "\$zname" in
        wg|wireguard|wg_mesh) uci delete "firewall.@zone[\$i]" 2>/dev/null; true; continue ;;
    esac
    i=\$((i + 1))
done
# 清理匿名 forwarding
i=0
while uci get firewall.@forwarding[\$i] >/dev/null 2>&1; do
    fsrc=\$(uci get firewall.@forwarding[\$i].src 2>/dev/null)
    fdest=\$(uci get firewall.@forwarding[\$i].dest 2>/dev/null)
    case "\$fsrc" in wg|wg_mesh) ;; *) case "\$fdest" in wg|wg_mesh) ;; *) i=\$((i+1)); continue ;; esac ;; esac
    uci delete "firewall.@forwarding[\$i]" 2>/dev/null; true
done

# 清理 OpenClash 绕过规则
ip rule del lookup main prio 100 2>/dev/null; true
for h in \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "\$h" 2>/dev/null; true
done
sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true

uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
/etc/init.d/firewall restart 2>/dev/null; true

# === 安装 WireGuard 组件 ===
# 检测内核是否已支持 WireGuard
WG_KERNEL=0
if [ -d /sys/module/wireguard ] || lsmod 2>/dev/null | grep -q wireguard; then
    echo '[+] 内核已支持 WireGuard'
    WG_KERNEL=1
fi

opkg update || echo '[!] opkg update 失败，尝试继续...'

# 如果内核不支持，安装 kmod
if [ "\$WG_KERNEL" = "0" ]; then
    if opkg install kmod-wireguard 2>/dev/null; then
        echo '[+] kmod-wireguard 安装成功'
    else
        # 再次检查内核是否其实已经支持
        if [ -d /sys/module/wireguard ] || ip link add wg_test type wireguard 2>/dev/null; then
            ip link del wg_test 2>/dev/null; true
            echo '[+] 内核已内置 WireGuard，无需 kmod'
        else
            echo '[!] WireGuard 内核模块不可用，请检查固件是否支持'
        fi
    fi
fi

# 安装用户态工具和 LuCI 协议支持
opkg install wireguard-tools 2>/dev/null || echo '[!] wireguard-tools 安装失败'
opkg install luci-proto-wireguard 2>/dev/null || echo '[!] luci-proto-wireguard 安装失败'

# 重载 rpcd/ubus 以注册 wireguard 协议类型
/etc/init.d/rpcd restart 2>/dev/null; true
sleep 1

# 验证 wireguard 协议类型是否可用
if ! ubus list network.interface 2>/dev/null | grep -q interface; then
    /etc/init.d/network reload 2>/dev/null; sleep 1
fi

# === 配置 WireGuard 接口 ===
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

# === OpenClash 绕过: 让 WireGuard 流量直连不走代理 ===
EP_IP='${ep_host}'
echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$' || \
    EP_IP=\$(nslookup '${ep_host}' 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}')
if [ -n "\${EP_IP}" ]; then
    # 添加策略路由: VPS IP 走主路由表，绕过 OpenClash 的路由表 354
    ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
    ip rule add to "\${EP_IP}" lookup main prio 100
    # nftables: 标记发往 VPS 的包跳过 OpenClash
    nft list chain inet fw4 mangle_prerouting &>/dev/null && {
        nft delete rule inet fw4 mangle_prerouting handle \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}') 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting ip daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
    }
    # 持久化: 写入 /etc/rc.local
    sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true
    sed -i "/^exit 0/i # WireGuard bypass OpenClash\nip rule add to \${EP_IP} lookup main prio 100 2>/dev/null; true" /etc/rc.local 2>/dev/null; true
    echo "[+] OpenClash 绕过规则已添加: \${EP_IP}"
fi

/etc/init.d/network reload

# === 验证 ===
sleep 3
if ifstatus wg0 2>/dev/null | grep -q '"up": true'; then
    echo '[+] wg0 接口启动成功!'
else
    echo '[!] wg0 接口未启动，请检查日志: logread | grep -i wireguard'
    echo '[!] 常见原因: 固件不支持 WireGuard 或 luci-proto-wireguard 版本不匹配'
fi

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
            echo -e "${C_YELLOW}在 OpenWrt SSH 终端依次执行以下命令:${C_RESET}"
            draw_line
            cat << OPENWRT_EOF

# === 清理旧配置 ===
# 停止所有 WireGuard 接口
ifdown wg0 2>/dev/null; true
ifdown wg_mesh 2>/dev/null; true
# 强制删除内核接口 (确保不残留)
for iface in \$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print \$2}'); do
    ip link set "\$iface" down 2>/dev/null; true
    ip link delete "\$iface" 2>/dev/null; true
    echo "[+] 已删除接口: \$iface"
done
for iface in wg0 wg_mesh wg-mesh; do
    if ip link show "\$iface" >/dev/null 2>&1; then
        ip link set "\$iface" down 2>/dev/null; true
        ip link delete "\$iface" 2>/dev/null; true
        echo "[+] 已删除接口: \$iface"
    fi
done

# 清理看门狗
rm -f /usr/bin/wg-watchdog.sh 2>/dev/null; true
(crontab -l 2>/dev/null | grep -v wg-watchdog) | crontab - 2>/dev/null; true
/etc/init.d/cron restart 2>/dev/null; true

# 删除所有 wireguard peer 配置段 (含匿名段)
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done
while uci -q get network.@wireguard_wg_mesh[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg_mesh[0]
done
uci delete network.wg_server 2>/dev/null; true

# 删除网络接口
uci delete network.wg0 2>/dev/null; true
uci delete network.wg_mesh 2>/dev/null; true

# 删除防火墙配置 (命名段 + 匿名段)
uci delete firewall.wg_zone 2>/dev/null; true
uci delete firewall.wg_fwd_lan 2>/dev/null; true
uci delete firewall.wg_fwd_wg 2>/dev/null; true
uci delete firewall.wg_mesh_zone 2>/dev/null; true
uci delete firewall.wg_mesh_fwd 2>/dev/null; true
uci delete firewall.wg_mesh_fwd_lan 2>/dev/null; true
# 清理匿名 zone
i=0
while uci get firewall.@zone[\$i] >/dev/null 2>&1; do
    zname=\$(uci get firewall.@zone[\$i].name 2>/dev/null)
    case "\$zname" in
        wg|wireguard|wg_mesh) uci delete "firewall.@zone[\$i]" 2>/dev/null; true; continue ;;
    esac
    i=\$((i + 1))
done
# 清理匿名 forwarding
i=0
while uci get firewall.@forwarding[\$i] >/dev/null 2>&1; do
    fsrc=\$(uci get firewall.@forwarding[\$i].src 2>/dev/null)
    fdest=\$(uci get firewall.@forwarding[\$i].dest 2>/dev/null)
    case "\$fsrc" in wg|wg_mesh) ;; *) case "\$fdest" in wg|wg_mesh) ;; *) i=\$((i+1)); continue ;; esac ;; esac
    uci delete "firewall.@forwarding[\$i]" 2>/dev/null; true
done

# 清理 OpenClash 绕过规则
ip rule del lookup main prio 100 2>/dev/null; true
for h in \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}'); do
    nft delete rule inet fw4 mangle_prerouting handle "\$h" 2>/dev/null; true
done
sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true

uci commit network 2>/dev/null; true
uci commit firewall 2>/dev/null; true
/etc/init.d/firewall restart 2>/dev/null; true

# === 安装 WireGuard 组件 ===
WG_KERNEL=0
if [ -d /sys/module/wireguard ] || lsmod 2>/dev/null | grep -q wireguard; then
    echo '[+] 内核已支持 WireGuard'
    WG_KERNEL=1
fi

opkg update || echo '[!] opkg update 失败，尝试继续...'

if [ "\$WG_KERNEL" = "0" ]; then
    if opkg install kmod-wireguard 2>/dev/null; then
        echo '[+] kmod-wireguard 安装成功'
    else
        if [ -d /sys/module/wireguard ] || ip link add wg_test type wireguard 2>/dev/null; then
            ip link del wg_test 2>/dev/null; true
            echo '[+] 内核已内置 WireGuard，无需 kmod'
        else
            echo '[!] WireGuard 内核模块不可用，请检查固件是否支持'
        fi
    fi
fi

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

# === OpenClash 绕过: 让 WireGuard 流量直连不走代理 ===
EP_IP='${ep_host}'
echo "\${EP_IP}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\$' || \
    EP_IP=\$(nslookup '${ep_host}' 2>/dev/null | awk '/^Address:/{a=\$2} END{if(a) print a}')
if [ -n "\${EP_IP}" ]; then
    # 添加策略路由: VPS IP 走主路由表，绕过 OpenClash 的路由表 354
    ip rule del to "\${EP_IP}" lookup main prio 100 2>/dev/null; true
    ip rule add to "\${EP_IP}" lookup main prio 100
    # nftables: 标记发往 VPS 的包跳过 OpenClash
    nft list chain inet fw4 mangle_prerouting &>/dev/null && {
        nft delete rule inet fw4 mangle_prerouting handle \$(nft -a list chain inet fw4 mangle_prerouting 2>/dev/null | grep 'wg_bypass' | awk '{print \$NF}') 2>/dev/null; true
        nft insert rule inet fw4 mangle_prerouting ip daddr "\${EP_IP}" udp dport ${sport} counter return comment \"wg_bypass\" 2>/dev/null; true
    }
    # 持久化: 写入 /etc/rc.local
    sed -i '/wg_bypass/d; /WireGuard bypass/d' /etc/rc.local 2>/dev/null; true
    sed -i "/^exit 0/i # WireGuard bypass OpenClash\nip rule add to \${EP_IP} lookup main prio 100 2>/dev/null; true" /etc/rc.local 2>/dev/null; true
    echo "[+] OpenClash 绕过规则已添加: \${EP_IP}"
fi

/etc/init.d/network reload

# === 验证 ===
sleep 3
if ifstatus wg0 2>/dev/null | grep -q '"up": true'; then
    echo '[+] wg0 接口启动成功!'
else
    echo '[!] wg0 接口未启动，请检查: logread | grep -i wireguard'
fi

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

