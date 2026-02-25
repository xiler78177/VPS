# modules/11b-wireguard-udp2raw.sh - WireGuard B 方案: udp2raw (UDP over TCP)
# 通过函数包装将 B 方案逻辑集成到 WG 主流程，无需修改 11-wireguard.sh

# ════════════════════════════════════════════════
# udp2raw 工具函数
# ════════════════════════════════════════════════

# 安装 udp2raw 二进制
wg_install_udp2raw() {
    if command -v udp2raw &>/dev/null; then
        print_info "udp2raw 已安装"
        return 0
    fi

    local arch bin_name
    arch=$(uname -m)
    case "$arch" in
        x86_64|amd64) bin_name="udp2raw_amd64" ;;
        aarch64)      bin_name="udp2raw_arm_asm_aes" ;;
        armv7*|armhf) bin_name="udp2raw_arm" ;;
        i*86)         bin_name="udp2raw_x86" ;;
        *) print_error "不支持的架构: $arch"; return 1 ;;
    esac

    local tmp_dir url
    tmp_dir=$(mktemp -d)
    url="https://github.com/wangyu-/udp2raw/releases/latest/download/udp2raw_binaries.tar.gz"

    print_info "下载 udp2raw..."
    if ! curl -fsSL -o "$tmp_dir/udp2raw.tar.gz" "$url" 2>/dev/null; then
        curl -fsSL -o "$tmp_dir/udp2raw.tar.gz" "https://ghp.ci/$url" 2>/dev/null || {
            print_error "下载 udp2raw 失败"
            rm -rf "$tmp_dir"; return 1
        }
    fi

    tar xzf "$tmp_dir/udp2raw.tar.gz" -C "$tmp_dir" 2>/dev/null || {
        print_error "解压失败"; rm -rf "$tmp_dir"; return 1
    }

    local src="$tmp_dir/$bin_name"
    if [[ ! -f "$src" ]]; then
        src=$(find "$tmp_dir" -name "udp2raw_*" -type f 2>/dev/null | head -1)
        [[ -f "$src" ]] || { print_error "未找到 udp2raw 二进制"; rm -rf "$tmp_dir"; return 1; }
    fi

    cp "$src" /usr/local/bin/udp2raw
    chmod +x /usr/local/bin/udp2raw
    rm -rf "$tmp_dir"
    print_success "udp2raw 安装完成"
}

# 创建并启动 udp2raw systemd 服务
_wg_setup_udp2raw_service() {
    local tcp_port=$1 wg_port=$2 password=$3

    cat > /etc/systemd/system/udp2raw-wg.service << SVCEOF
[Unit]
Description=udp2raw tunnel for WireGuard (Plan B)
After=network.target
Before=wg-quick@${WG_INTERFACE}.service

[Service]
Type=simple
ExecStart=/usr/local/bin/udp2raw -s -l 0.0.0.0:${tcp_port} -r 127.0.0.1:${wg_port} --raw-mode faketcp -a -k "${password}"
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable udp2raw-wg >/dev/null 2>&1
    systemctl restart udp2raw-wg

    if systemctl is-active --quiet udp2raw-wg; then
        print_success "udp2raw 服务已启动"
        return 0
    fi
    print_error "udp2raw 服务启动失败，请检查: journalctl -u udp2raw-wg"
    return 1
}

# 修正客户端 .conf 文件 Endpoint 为 127.0.0.1 (B 方案)
_wg_fix_configs_for_plan_b() {
    local ep port conf_dir="/etc/wireguard/clients"
    ep=$(wg_db_get '.server.endpoint')
    port=$(wg_db_get '.server.port')
    [[ -d "$conf_dir" ]] || return 0
    for f in "$conf_dir"/*.conf; do
        [[ -f "$f" ]] || continue
        sed -i "s|Endpoint = ${ep}:${port}|Endpoint = 127.0.0.1:${port}|g" "$f" 2>/dev/null
    done
}

# 打印客户端 udp2raw 连接指南
_wg_print_udp2raw_guide() {
    local ep=$1 tcp_port=$2 wg_port=$3 password=$4
    echo -e "  ${C_YELLOW}[客户端连接方式 - B 方案]${C_RESET}"
    echo -e "  1. 下载 udp2raw: ${C_CYAN}https://github.com/wangyu-/udp2raw/releases${C_RESET}"
    echo -e "  2. 客户端先启动 udp2raw:"
    echo -e "     ${C_GREEN}udp2raw -c -l 127.0.0.1:${wg_port} -r ${ep}:${tcp_port} --raw-mode faketcp -a -k \"${password}\"${C_RESET}"
    echo -e "  3. 再启动 WireGuard (Endpoint 已设为 127.0.0.1:${wg_port})"
}

# B 方案部署入口 (WG 安装完成后调用)
_wg_post_install_plan_b() {
    print_title "部署 B 方案: UDP over TCP (udp2raw)"

    local wg_port
    wg_port=$(wg_db_get '.server.port')

    # 选择 udp2raw TCP 端口 (默认与 WG UDP 端口相同，TCP/UDP 不冲突)
    local udp2raw_port
    while true; do
        read -e -r -p "udp2raw TCP 端口 [${wg_port}]: " udp2raw_port
        udp2raw_port=${udp2raw_port:-$wg_port}
        if validate_port "$udp2raw_port"; then break; fi
        print_warn "端口无效 (1-65535)"
    done

    # [B-1/3] 安装 udp2raw
    print_info "[B-1/3] 安装 udp2raw..."
    wg_install_udp2raw || return 1

    # 生成随机密码
    local password
    password=$(head -c 16 /dev/urandom | base64 | tr -d '/+=' | head -c 16)

    # [B-2/3] 配置并启动服务
    print_info "[B-2/3] 配置 udp2raw 服务..."
    _wg_setup_udp2raw_service "$udp2raw_port" "$wg_port" "$password" || return 1

    # [B-3/3] 保存到数据库
    print_info "[B-3/3] 保存 B 方案配置..."
    wg_db_set --arg plan "B" --arg p "$udp2raw_port" --arg pw "$password" \
        '.server.deploy_plan = $plan | .server.udp2raw_port = ($p | tonumber) | .server.udp2raw_password = $pw'

    # 防火墙放行 TCP 端口
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${udp2raw_port}/tcp" comment "udp2raw for WireGuard" >/dev/null 2>&1
        print_success "UFW 已放行 ${udp2raw_port}/tcp"
    fi

    # 修正已有客户端配置的 Endpoint
    _wg_fix_configs_for_plan_b

    # 显示摘要
    local ep
    ep=$(wg_db_get '.server.endpoint')
    draw_line
    print_success "B 方案部署完成！"
    echo -e "  udp2raw 端口: ${C_GREEN}${udp2raw_port}/tcp (faketcp)${C_RESET}"
    echo -e "  连接密码:     ${C_CYAN}${password}${C_RESET}"
    echo ""
    _wg_print_udp2raw_guide "$ep" "$udp2raw_port" "$wg_port" "$password"
    draw_line
    pause
}

# 显示 udp2raw 连接信息 (供 peer 操作后调用)
_wg_show_udp2raw_info() {
    local plan
    plan=$(wg_db_get '.server.deploy_plan // empty')
    [[ "$plan" == "B" ]] || return 0

    local ep tcp_port wg_port password
    ep=$(wg_db_get '.server.endpoint')
    tcp_port=$(wg_db_get '.server.udp2raw_port')
    wg_port=$(wg_db_get '.server.port')
    password=$(wg_db_get '.server.udp2raw_password')

    echo ""
    _wg_print_udp2raw_guide "$ep" "$tcp_port" "$wg_port" "$password"
}

# ════════════════════════════════════════════════
# 函数包装: 将 B 方案透明集成到 WG 主流程
# ════════════════════════════════════════════════

# ── 包装 wg_server_install: 前置检测 + 后置 B 方案部署 ──
eval "$(declare -f wg_server_install | sed '1s/wg_server_install/_wg_server_install_orig/')"

wg_server_install() {
    # 已安装为服务端则跳过检测，直接走原逻辑
    if wg_is_installed && [[ "$(wg_get_role)" == "server" ]]; then
        _wg_server_install_orig "$@"
        return $?
    fi

    # 已安装为客户端也跳过检测
    if wg_is_installed && [[ "$(wg_get_role)" == "client" ]]; then
        _wg_server_install_orig "$@"
        return $?
    fi

    # 网络资质检测 → 设置 WG_DEPLOY_PLAN
    wg_net_qualify_server || return 1

    # 执行原始安装流程
    _wg_server_install_orig "$@"
    local rc=$?

    # 安装成功后处理部署方案
    if [[ $rc -eq 0 ]] && wg_is_installed; then
        if [[ "$WG_DEPLOY_PLAN" == "B" ]]; then
            _wg_post_install_plan_b
        else
            wg_db_set --arg plan "A" '.server.deploy_plan = $plan' 2>/dev/null
        fi
    fi

    return $rc
}

# ── 包装 wg_add_peer: B 方案时临时替换 Endpoint ──
eval "$(declare -f wg_add_peer | sed '1s/wg_add_peer/_wg_add_peer_orig/')"

wg_add_peer() {
    local _plan _saved_ep=""
    _plan=$(wg_db_get '.server.deploy_plan // empty')

    # B 方案: 临时将 endpoint 设为 127.0.0.1，使生成的配置和 QR 码正确
    if [[ "$_plan" == "B" ]]; then
        _saved_ep=$(wg_db_get '.server.endpoint')
        wg_db_set --arg ep "127.0.0.1" '.server.endpoint = $ep'
    fi

    _wg_add_peer_orig "$@"
    local rc=$?

    # 恢复真实 endpoint
    if [[ -n "$_saved_ep" ]]; then
        wg_db_set --arg ep "$_saved_ep" '.server.endpoint = $ep'
    fi

    # 添加成功后显示 udp2raw 连接说明
    [[ $rc -eq 0 && "$_plan" == "B" ]] && _wg_show_udp2raw_info

    return $rc
}

# ── 包装 wg_regenerate_client_confs: B 方案时修正 Endpoint ──
eval "$(declare -f wg_regenerate_client_confs | sed '1s/wg_regenerate_client_confs/_wg_regenerate_client_confs_orig/')"

wg_regenerate_client_confs() {
    local _plan _saved_ep=""
    _plan=$(wg_db_get '.server.deploy_plan // empty')

    if [[ "$_plan" == "B" ]]; then
        _saved_ep=$(wg_db_get '.server.endpoint')
        wg_db_set --arg ep "127.0.0.1" '.server.endpoint = $ep'
    fi

    _wg_regenerate_client_confs_orig "$@"

    if [[ -n "$_saved_ep" ]]; then
        wg_db_set --arg ep "$_saved_ep" '.server.endpoint = $ep'
    fi
}

# ── 包装 wg_uninstall: 清理 udp2raw 残留 ──
eval "$(declare -f wg_uninstall | sed '1s/wg_uninstall/_wg_uninstall_orig/')"

wg_uninstall() {
    # 清理 udp2raw 服务和二进制
    if systemctl is-active --quiet udp2raw-wg 2>/dev/null || \
       systemctl is-enabled --quiet udp2raw-wg 2>/dev/null; then
        print_info "清理 udp2raw 服务..."
        systemctl stop udp2raw-wg 2>/dev/null
        systemctl disable udp2raw-wg 2>/dev/null
        rm -f /etc/systemd/system/udp2raw-wg.service
        systemctl daemon-reload 2>/dev/null
        print_success "udp2raw 已清理"
    fi
    [[ -f /usr/local/bin/udp2raw ]] && rm -f /usr/local/bin/udp2raw

    _wg_uninstall_orig "$@"
}
