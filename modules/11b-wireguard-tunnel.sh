# modules/11b-wireguard-tunnel.sh - WireGuard 境外模式: VLESS-Reality 隧道
# 通过 3X-UI 面板的 VLESS-Reality 入站实现 WG 流量伪装
# 替代原有的 udp2raw (Plan B) 方案

# ════════════════════════════════════════════════
# VLESS-Reality 隧道配置 (手动录入模式)
# ════════════════════════════════════════════════

# 交互式配置 VLESS-Reality 隧道 (需用户先在 3X-UI 面板手动创建入站)
wg_tunnel_setup() {
    local wg_port=$1
    print_title "配置 VLESS-Reality 隧道"

    echo -e "${C_CYAN}架构说明:${C_RESET}"
    echo "  客户端 → VLESS-Reality (伪装TLS) → 本机 xray → WG Server (0.0.0.0:${wg_port})"
    echo "  GFW 看到的是正常的 TLS 1.3 流量"
    echo ""

    echo -e "${C_YELLOW}请先在您的 3X-UI 面板创建一个包含 Reality 的 VLESS 入站，然后获取以下信息:${C_RESET}"

    local vless_port vless_uuid reality_pub reality_sid reality_sni vless_net vless_flow

    while true; do
        read -e -r -p "VLESS 监听端口 (Port): " vless_port
        if validate_port "$vless_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    read -e -r -p "客户端 UUID (Client ID): " vless_uuid
    echo -e "${C_RED}注意: 是 Reality 对应的 Public Key(公钥), 千万不要填 Private Key(私钥)!${C_RESET}"
    read -e -r -p "Reality 公钥 (Public Key): " reality_pub
    read -e -r -p "Reality Short ID: " reality_sid
    read -e -r -p "Reality 伪装 SNI 域名 (如 www.microsoft.com): " reality_sni
    read -e -r -p "网络传输方式 (如 tcp / grpc) [tcp]: " vless_net
    vless_net=${vless_net:-tcp}
    read -e -r -p "Flow 控制项 [xtls-rprx-vision]: " vless_flow
    [[ -z "$vless_flow" ]] && vless_flow="xtls-rprx-vision"
    [[ "$vless_flow" == "none" || "$vless_flow" == "null" ]] && vless_flow=""

    # 写入数据库
    wg_db_set --arg dt "vless-reality" '.server.tunnel_type = $dt'
    wg_db_set --arg vp "$vless_port" '.server.vless_port = ($vp | tonumber)'
    wg_db_set --arg uuid "$vless_uuid" '.server.vless_uuid = $uuid'
    wg_db_set --arg net "$vless_net" '.server.vless_network = $net'
    if [[ -n "$vless_flow" ]]; then
        wg_db_set --arg flow "$vless_flow" '.server.vless_flow = $flow'
    else
        wg_db_set '.server.vless_flow = ""'
    fi
    wg_db_set --arg rpub "$reality_pub" '.server.reality_public_key = $rpub'
    wg_db_set '.server.reality_private_key = ""'
    wg_db_set --arg sid "$reality_sid" '.server.reality_short_id = $sid'
    wg_db_set --arg sni "$reality_sni" '.server.reality_sni = $sni'
    wg_db_set --arg dest "${reality_sni}:443" '.server.reality_dest = $dest'

    print_success "VLESS-Reality 参数录入完成！您现在的节点已经与远端配置对齐了。"

    echo ""
    read -e -r -p "是否立即生成 Clash/mihomo 客户端配置? [Y/n]: " _gen_clash
    _gen_clash=${_gen_clash:-Y}
    if [[ "$_gen_clash" =~ ^[Yy]$ ]]; then
        wg_generate_clash_config
    fi
}

# 生成客户端 xray 配置 (用于连接 VLESS-Reality 隧道)
wg_tunnel_generate_client_xray() {
    local peer_idx=$1
    local server_ip=$(wg_db_get '.server.endpoint')
    local vless_port=$(wg_db_get '.server.vless_port // empty')
    local uuid=$(wg_db_get '.server.vless_uuid // empty')
    local network=$(wg_db_get '.server.vless_network // "tcp"')
    local flow=$(wg_db_get '.server.vless_flow // "xtls-rprx-vision"')
    local reality_pub=$(wg_db_get '.server.reality_public_key // empty')
    local short_id=$(wg_db_get '.server.reality_short_id // empty')
    local sni=$(wg_db_get '.server.reality_sni // empty')
    local wg_port=$(wg_db_get '.server.port')

    if [[ -z "$uuid" || "$uuid" == "null" || -z "$reality_pub" || "$reality_pub" == "null" ]]; then
        print_error "VLESS-Reality 隧道未配置，请先运行隧道配置"
        return 1
    fi

    local peer_name=$(wg_db_get ".peers[$peer_idx].name")
    local output_dir="/etc/wireguard/clients"
    mkdir -p "$output_dir"

    # 生成 xray 客户端 JSON
    local xray_conf="${output_dir}/${peer_name}-xray.json"
    cat > "$xray_conf" << XRAYEOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "tag": "wg-in",
      "port": ${wg_port},
      "listen": "127.0.0.1",
      "protocol": "dokodemo-door",
      "settings": {
        "address": "${server_ip}",
        "port": ${wg_port},
        "network": "udp"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "vless-reality",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${server_ip}",
            "port": ${vless_port},
            "users": [
              {
                "id": "${uuid}",
                "encryption": "none",
                "flow": "${flow}"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "${network}",
        "security": "reality",
        "realitySettings": {
          "fingerprint": "chrome",
          "serverName": "${sni}",
          "publicKey": "${reality_pub}",
          "shortId": "${short_id}",
          "spiderX": ""
        }
      }
    }
  ]
}
XRAYEOF
    chmod 600 "$xray_conf"
    echo "$xray_conf"
}

# 显示客户端隧道连接指引
wg_tunnel_show_client_guide() {
    local peer_idx=$1
    local peer_name=$(wg_db_get ".peers[$peer_idx].name")
    local xray_conf="/etc/wireguard/clients/${peer_name}-xray.json"
    local server_ip=$(wg_db_get '.server.endpoint')
    local wg_port=$(wg_db_get '.server.port')

    echo ""
    echo -e "${C_CYAN}=== 境外模式客户端连接指引 (${peer_name}) ===${C_RESET}"
    draw_line
    echo "客户端需要两个组件配合工作:"
    echo ""
    echo -e "  ${C_GREEN}1. xray 客户端${C_RESET} (负责 VLESS-Reality 隧道)"
    echo "     配置文件: ${xray_conf}"
    echo "     作用: 将本地 UDP:${wg_port} 通过 VLESS-Reality 转发到服务端"
    echo ""
    echo -e "  ${C_GREEN}2. WireGuard 客户端${C_RESET} (标准 WG 配置)"
    echo "     配置文件: /etc/wireguard/clients/${peer_name}.conf"
    echo "     Endpoint 指向: 127.0.0.1:${wg_port} (本地 xray 入口)"
    echo ""
    echo -e "${C_YELLOW}启动顺序:${C_RESET}"
    echo "  1. 先启动 xray: xray run -c ${xray_conf}"
    echo "  2. 再启动 WireGuard: wg-quick up wg0"
    draw_line
}

# ── 包装 wg_regenerate_client_confs: 境外模式时 Endpoint 指向本地 xray ──
eval "$(declare -f wg_regenerate_client_confs | sed '1s/wg_regenerate_client_confs/_wg_regenerate_client_confs_orig/')"

wg_regenerate_client_confs() {
    local _mode _saved_ep=""
    _mode=$(wg_db_get '.server.deploy_mode // empty')

    if [[ "$_mode" == "overseas" ]]; then
        _saved_ep=$(wg_db_get '.server.endpoint')
        wg_db_set --arg ep "127.0.0.1" '.server.endpoint = $ep'
    fi

    _wg_regenerate_client_confs_orig "$@"

    if [[ -n "$_saved_ep" ]]; then
        wg_db_set --arg ep "$_saved_ep" '.server.endpoint = $ep'
    fi

    # 境外模式: 额外生成 xray 客户端配置
    if [[ "$_mode" == "overseas" ]]; then
        local pc=$(wg_db_get '.peers | length')
        local i=0
        while [[ $i -lt $pc ]]; do
            wg_tunnel_generate_client_xray "$i" >/dev/null 2>&1
            i=$((i + 1))
        done
    fi
}

# ── 包装 wg_uninstall: 清理隧道残留 ──
eval "$(declare -f wg_uninstall | sed '1s/wg_uninstall/_wg_uninstall_orig/')"

wg_uninstall() {
    # 清理旧版 udp2raw 服务 (兼容升级)
    if systemctl is-active --quiet udp2raw-wg 2>/dev/null || \
       systemctl is-enabled --quiet udp2raw-wg 2>/dev/null; then
        print_info "清理 udp2raw 服务 (旧版残留)..."
        systemctl stop udp2raw-wg 2>/dev/null
        systemctl disable udp2raw-wg 2>/dev/null
        rm -f /etc/systemd/system/udp2raw-wg.service
        systemctl daemon-reload 2>/dev/null
        print_success "udp2raw 已清理"
    fi
    [[ -f /usr/local/bin/udp2raw ]] && rm -f /usr/local/bin/udp2raw

    # 清理 xray 客户端配置文件
    local clients_dir="/etc/wireguard/clients"
    if [[ -d "$clients_dir" ]]; then
        rm -f "$clients_dir"/*-xray.json 2>/dev/null
    fi

    _wg_uninstall_orig "$@"
}

# ════════════════════════════════════════════════
# 隧道管理菜单
# ════════════════════════════════════════════════
wg_tunnel_manage() {
    wg_check_server || return 1
    local deploy_mode=$(wg_db_get '.server.deploy_mode // "domestic"')
    if [[ "$deploy_mode" != "overseas" ]]; then
        print_warn "当前为境内模式，无需隧道管理"
        pause; return
    fi

    print_title "VLESS-Reality 隧道管理"
    local vless_port=$(wg_db_get '.server.vless_port // empty')
    local vless_uuid=$(wg_db_get '.server.vless_uuid // empty')
    local reality_jni=$(wg_db_get '.server.reality_sni // empty')
    local reality_pub=$(wg_db_get '.server.reality_public_key // empty')
    local reality_sid=$(wg_db_get '.server.reality_short_id // empty')
    local vless_net=$(wg_db_get '.server.vless_network // "tcp"')
    local vless_flow=$(wg_db_get '.server.vless_flow // "xtls-rprx-vision"')
    local wg_port=$(wg_db_get '.server.port')

    if [[ -n "$vless_uuid" && "$vless_uuid" != "null" ]]; then
        echo -e "  VLESS 端口:  ${C_GREEN}${vless_port}${C_RESET}"
        echo -e "  传输设定:    ${C_CYAN}${vless_net}${C_RESET} ${vless_flow:+(flow: $vless_flow)}"
        echo -e "  UUID:        ${C_CYAN}${vless_uuid}${C_RESET}"
        echo -e "  Reality SNI: ${C_CYAN}${reality_jni}${C_RESET}"
        echo -e "  Short ID:    ${C_CYAN}${reality_sid}${C_RESET}"
        echo -e "  Public Key:  ${C_CYAN}${reality_pub}${C_RESET}"
        echo -e "  WG 本地监听: ${C_CYAN}0.0.0.0:${wg_port}/udp${C_RESET}"
    else
        echo -e "  ${C_YELLOW}隧道参数未配置${C_RESET}"
    fi
    draw_line
    echo "  1. 重新配置隧道参数
  2. 查看客户端 xray 配置
  3. 查看 3X-UI 配置指引
  0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            wg_tunnel_setup "$wg_port"
            pause
            ;;
        2)
            local pc=$(wg_db_get '.peers | length')
            if [[ "$pc" -eq 0 ]]; then
                print_warn "暂无设备"; pause; return
            fi
            echo "选择设备:"
            local i=0
            while [[ $i -lt $pc ]]; do
                echo "  $((i+1)). $(wg_db_get ".peers[$i].name")"
                i=$((i+1))
            done
            read -e -r -p "选择: " idx
            if [[ "$idx" =~ ^[0-9]+$ && "$idx" -ge 1 && "$idx" -le "$pc" ]]; then
                wg_tunnel_generate_client_xray "$((idx-1))"
                pause
            fi
            ;;
        3)
            echo ""
            echo -e "${C_YELLOW}[3X-UI 配置指引]${C_RESET}"
            echo "  1. 登录 3X-UI 面板"
            echo "  2. 入站列表 → 添加入站"
            echo "  3. 协议: vless, 端口: ${vless_port:-自定义}"
            echo "  4. 传输: ${vless_net}, 安全: reality"
            [[ -n "$vless_flow" ]] && echo "  5. xtls 设置 (Flow): ${vless_flow}"
            echo "  6. SNI/Dest: ${reality_jni:-www.microsoft.com}:443"
            echo "  7. 面板无需特殊设置（客户端直连公网 IP 环回）"
            pause
            ;;
    esac
}
