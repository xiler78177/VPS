# modules/11b-wireguard-tunnel.sh - WireGuard 境外模式: VLESS-Reality 隧道
# 通过 3X-UI 面板的 VLESS-Reality 入站实现 WG 流量伪装
# 替代原有的 udp2raw (Plan B) 方案

# ════════════════════════════════════════════════
# 3X-UI / xray 检测与配置
# ════════════════════════════════════════════════

# 获取 3X-UI 面板信息
_wg_xui_get_info() {
    local db="/etc/x-ui/x-ui.db"
    if [[ ! -f "$db" ]]; then
        echo ""
        return 1
    fi
    # 读取面板端口
    local panel_port
    panel_port=$(sqlite3 "$db" "SELECT value FROM settings WHERE key='webPort'" 2>/dev/null)
    [[ -z "$panel_port" ]] && panel_port="54321"
    echo "$panel_port"
}

# 从 3X-UI 数据库读取已有的 VLESS-Reality 入站
_wg_xui_find_reality_inbound() {
    local db="/etc/x-ui/x-ui.db"
    [[ ! -f "$db" ]] && return 1
    # 查找 protocol=vless 且 streamSettings 包含 reality 的入站
    local result
    result=$(sqlite3 "$db" "SELECT id, port, remark, settings, stream_settings FROM inbounds WHERE protocol='vless' AND stream_settings LIKE '%reality%' LIMIT 5" 2>/dev/null)
    [[ -z "$result" ]] && return 1
    echo "$result"
    return 0
}

# 生成 xray VLESS-Reality 入站配置 (用于 3X-UI 手动添加参考)
wg_tunnel_generate_xray_inbound() {
    local wg_port=$1 vless_port=$2 vless_network=$3 vless_flow=$4 dest_server=$5 dest_port=$6
    local server_name=${dest_server%%:*}

    # 生成 Reality 密钥对
    local reality_keys
    reality_keys=$(xray x25519 2>/dev/null)
    if [[ -z "$reality_keys" ]]; then
        # xray 不在 PATH 中，尝试 3X-UI 自带的
        local xray_bin=""
        for p in /usr/local/x-ui/bin/xray-linux-* /usr/local/x-ui/xray-linux-*; do
            [[ -x "$p" ]] && { xray_bin="$p"; break; }
        done
        if [[ -n "$xray_bin" ]]; then
            reality_keys=$("$xray_bin" x25519 2>/dev/null)
        fi
    fi

    local reality_private_key="" reality_public_key=""
    if [[ -n "$reality_keys" ]]; then
        reality_private_key=$(echo "$reality_keys" | grep -iE 'Private( )?Key' | awk '{print $NF}')
        reality_public_key=$(echo "$reality_keys" | grep -iE 'Public( )?Key|Password' | awk '{print $NF}')
    fi

    # 生成 shortId
    local short_id
    short_id=$(openssl rand -hex 4 2>/dev/null || head -c 8 /dev/urandom | xxd -p)

    # 生成 UUID
    local uuid
    uuid=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen 2>/dev/null)

    # 分支写入避免 jq 解析过长导致异常或截断
    wg_db_set --arg dt "vless-reality" '.server.tunnel_type = $dt'
    wg_db_set --arg vp "$vless_port" '.server.vless_port = ($vp | tonumber)'
    wg_db_set --arg uuid "$uuid" '.server.vless_uuid = $uuid'
    wg_db_set --arg net "$vless_network" '.server.vless_network = $net'
    
    # flow 可能为空
    if [[ -n "$vless_flow" ]]; then
        wg_db_set --arg flow "$vless_flow" '.server.vless_flow = $flow'
    else
        wg_db_set '.server.vless_flow = ""'
    fi
    
    wg_db_set --arg rpub "$reality_public_key" '.server.reality_public_key = $rpub'
    wg_db_set --arg rpriv "$reality_private_key" '.server.reality_private_key = $rpriv'
    wg_db_set --arg sid "$short_id" '.server.reality_short_id = $sid'
    wg_db_set --arg dest "${dest_server}:${dest_port}" '.server.reality_dest = $dest'
    wg_db_set --arg sni "$server_name" '.server.reality_sni = $sni'

    # 输出配置摘要
    echo ""
    print_success "VLESS-Reality 隧道参数已生成"
    draw_line
    echo -e "  VLESS 端口:    ${C_CYAN}${vless_port}${C_RESET}"
    echo -e "  UUID:          ${C_CYAN}${uuid}${C_RESET}"
    echo -e "  Reality SNI:   ${C_CYAN}${server_name}${C_RESET}"
    echo -e "  Reality Dest:  ${C_CYAN}${dest_server}:${dest_port}${C_RESET}"
    echo -e "  Short ID:      ${C_CYAN}${short_id}${C_RESET}"
    echo -e "  Public Key:    ${C_CYAN}${reality_public_key}${C_RESET}"
    echo -e "  WG 监听端口:   ${C_CYAN}0.0.0.0:${wg_port} (UDP)${C_RESET}"
    draw_line
}

# 交互式配置 VLESS-Reality 隧道
wg_tunnel_setup() {
    local wg_port=$1
    print_title "配置 VLESS-Reality 隧道"

    echo -e "${C_CYAN}架构说明:${C_RESET}"
    echo "  客户端 → VLESS-Reality (伪装TLS) → 本机 xray → WG Server (0.0.0.0:${wg_port})"
    echo "  GFW 看到的是正常的 TLS 1.3 流量"
    echo ""

    # 检测已有的 Reality 入站
    local existing_inbounds
    existing_inbounds=$(_wg_xui_find_reality_inbound 2>/dev/null)
    if [[ -n "$existing_inbounds" ]]; then
        echo -e "${C_GREEN}检测到已有 VLESS-Reality 入站:${C_RESET}"
        echo "$existing_inbounds" | while IFS='|' read -r id port remark _settings _stream; do
            echo -e "  ID=${id} 端口=${C_CYAN}${port}${C_RESET} 备注=${remark}"
        done
        echo ""
    fi

    # VLESS 监听端口
    local vless_port
    local default_vless_port=""
    if [[ -n "$existing_inbounds" ]]; then
        default_vless_port=$(echo "$existing_inbounds" | head -1 | cut -d'|' -f2)
    fi
    while true; do
        if [[ -n "$default_vless_port" ]]; then
            read -e -r -p "VLESS-Reality 监听端口 [${default_vless_port}]: " vless_port
            vless_port=${vless_port:-$default_vless_port}
        else
            read -e -r -p "VLESS-Reality 监听端口: " vless_port
        fi
        if validate_port "$vless_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    # 传输层配置 (network & flow)
    echo ""
    echo "获取 3X-UI 端的传输层配置:"
    local vless_network vless_flow
    read -e -r -p "Transmission (Network) (tcp/xhttp/grpc 等) [tcp]: " vless_network
    vless_network=${vless_network:-tcp}
    
    if [[ "$vless_network" == "tcp" ]]; then
        read -e -r -p "Flow 控制选项 (无则留空) [xtls-rprx-vision]: " vless_flow
        # 用户直接回车默认用 vision，如果明确输入 空格/none/表示为空，就不设置
        [[ -z "$vless_flow" ]] && vless_flow="xtls-rprx-vision"
        [[ "$vless_flow" == "none" || "$vless_flow" == "null" ]] && vless_flow=""
    else
        read -e -r -p "Flow 控制选项 (非 tcp 一般留空): " vless_flow
    fi

    # Reality 伪装目标
    local dest_server dest_port
    echo ""
    echo "Reality 伪装目标 (SNI 目标网站):"
    echo -e "  推荐: ${C_CYAN}www.microsoft.com${C_RESET}, ${C_CYAN}www.apple.com${C_RESET}, ${C_CYAN}www.samsung.com${C_RESET}"
    read -e -r -p "伪装目标域名 [www.microsoft.com]: " dest_server
    dest_server=${dest_server:-www.microsoft.com}
    read -e -r -p "伪装目标端口 [443]: " dest_port
    dest_port=${dest_port:-443}

    # 生成配置
    wg_tunnel_generate_xray_inbound "$wg_port" "$vless_port" "$vless_network" "$vless_flow" "$dest_server" "$dest_port"

    # 生成 3X-UI 可导入的 JSON 模板: 需先从数据库中重新提取生成的关键参数
    local uuid=$(wg_db_get '.server.vless_uuid')
    local reality_private_key=$(wg_db_get '.server.reality_private_key')
    local short_id=$(wg_db_get '.server.reality_short_id')
    local server_name=$(wg_db_get '.server.reality_sni')
    local c_time=$(date +%s000)

    local subid
    subid=$(openssl rand -hex 8 2>/dev/null || head -c 8 /dev/urandom | xxd -p)

    # 纯 jq 构建: 内层对象用 tojson 自动转为 JSON 字符串，匹配 3X-UI 数据库存储格式
    local xui_template
    xui_template=$(jq -n \
        --arg uuid "$uuid" \
        --arg flow "$vless_flow" \
        --arg subid "$subid" \
        --arg vp "$vless_port" \
        --arg net "$vless_network" \
        --arg dest "${dest_server}:${dest_port}" \
        --arg sni "$server_name" \
        --arg pk "$reality_private_key" \
        --arg sid "$short_id" \
    '{
      "id": 1,
      "userId": 0,
      "up": 0,
      "down": 0,
      "total": 0,
      "allTime": 0,
      "remark": "WG-Tunnel",
      "enable": true,
      "expiryTime": 0,
      "trafficReset": "never",
      "lastTrafficResetTime": 0,
      "listen": "",
      "port": ($vp|tonumber),
      "protocol": "vless",
      "settings": ({"clients":[{"id":$uuid,"security":"","password":"","flow":$flow,"email":"WG-Tunnel","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":0,"subId":$subid,"comment":"","reset":0}],"decryption":"none","encryption":"none"}|tojson),
      "streamSettings": ({"network":$net,"security":"reality","externalProxy":[],"realitySettings":{"show":false,"xver":0,"target":$dest,"serverNames":[$sni],"privateKey":$pk,"minClientVer":"","maxClientVer":"","maxTimediff":0,"shortIds":[$sid],"mldsa65Seed":"","settings":{"publicKey":"","fingerprint":"chrome","serverName":"","spiderX":"/","mldsa65Verify":""}},"tcpSettings":{"acceptProxyProtocol":false,"header":{"type":"none"}}}|tojson),
      "tag": ("inbound-"+$vp),
      "sniffing": ({"enabled":true,"destOverride":["http","tls","quic","fakedns"],"metadataOnly":false,"routeOnly":false}|tojson)
    }')

    if [[ -z "$xui_template" ]]; then
        print_error "JSON 模板生成失败 (请检查 jq 是否安装)"
        return 1
    fi

    # 提供 3X-UI 配置指引
    echo ""
    echo -e "${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    echo -e "${C_CYAN}请复制以下 JSON 文本 (包含括号):${C_RESET}"
    echo -e "${C_YELLOW}${xui_template}${C_RESET}"
    echo -e "${C_GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${C_RESET}"
    
    echo -e "${C_CYAN}[下一步] 使用 3X-UI 模板导入:${C_RESET}"
    echo "  1. 登录 3X-UI 面板，进入 [入站列表]"
    echo "  2. 点击右上角的 [+] 旁边箭头 或 找到 [导入 (Import)] 按钮"
    echo "  3. 将上面的 JSON 文本完整粘贴进去，点击确定保存"
    echo "  4. (无需额外路由处理) 客户端代理请求服务端公网 IP，流量即可自动回环"
    echo ""

    log_action "WireGuard tunnel: VLESS-Reality configured (port=${vless_port} net=${vless_network} flow=${vless_flow} sni=${dest_server})"

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
