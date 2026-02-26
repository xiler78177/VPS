# modules/11a-wireguard-netcheck.sh - WireGuard 部署模式选择
# 替代原有的自动网络检测，改为用户交互式选择部署场景

# 部署模式全局变量: domestic=境内直连, overseas=境外隧道
WG_DEPLOY_MODE=""

# 判断一个 IPv4 是否属于私有/CGNAT 地址段
_wg_is_private_ip() {
    local ip="$1"
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"
    [[ "$o1" -eq 10 ]] && return 0
    [[ "$o1" -eq 172 && "$o2" -ge 16 && "$o2" -le 31 ]] && return 0
    [[ "$o1" -eq 192 && "$o2" -eq 168 ]] && return 0
    [[ "$o1" -eq 100 && "$o2" -ge 64 && "$o2" -le 127 ]] && return 0
    return 1
}

# 检测本机是否拥有公网 IP
wg_check_public_ip() {
    local found_public=false found_any=false
    local line ip iface
    while IFS= read -r line; do
        [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/[0-9]+.*[[:space:]]([a-zA-Z0-9_.-]+)[[:space:]]*$ ]] || continue
        ip="${BASH_REMATCH[1]}"
        iface="${BASH_REMATCH[2]}"
        case "$iface" in
            docker*|br-*|veth*|virbr*|lo|cni*|flannel*|cali*) continue ;;
        esac
        found_any=true
        if _wg_is_private_ip "$ip"; then
            echo -e "  ${C_YELLOW}├ ${iface}: ${ip} (内网)${C_RESET}"
        else
            echo -e "  ${C_GREEN}├ ${iface}: ${ip} (公网)${C_RESET}"
            found_public=true
        fi
    done < <(ip -4 addr show scope global 2>/dev/null | grep 'inet ')
    if ! $found_any; then
        echo -e "  ${C_RED}└ 未检测到任何 scope global 的 IPv4 地址${C_RESET}"
        return 1
    fi
    $found_public && return 0 || return 1
}

# 检测 3X-UI 是否已安装并运行
wg_check_xui_installed() {
    if [[ -f /usr/local/x-ui/x-ui ]] || systemctl is-active --quiet x-ui 2>/dev/null; then
        return 0
    fi
    if [[ -f /etc/x-ui/x-ui.db ]]; then
        return 0
    fi
    return 1
}

# 交互式部署模式选择
# 设置 WG_DEPLOY_MODE: domestic (境内) 或 overseas (境外)
# 返回 0 = 允许继续安装，返回 1 = 用户取消
wg_select_deploy_mode() {
    echo -e "\n${C_CYAN}[部署模式选择]${C_RESET}"
    draw_line
    echo -e "  ${C_CYAN}检测本机网络环境...${C_RESET}"
    wg_check_public_ip
    draw_line
    echo ""
    echo "请选择 WireGuard 部署场景:"
    echo ""
    echo -e "  ${C_GREEN}1. 境内部署${C_RESET} (家庭NAS/内网设备/境内VPS)"
    echo "     WireGuard 标准 UDP 直连，可配合 DDNS"
    echo "     MTU=${WG_MTU_DIRECT}，无额外封装开销"
    echo ""
    echo -e "  ${C_YELLOW}2. 境外部署${C_RESET} (翻墙/境外VPS)"
    echo "     WireGuard 仅监听本地，通过 VLESS-Reality 隧道对外"
    echo "     MTU=${WG_MTU_TUNNEL}，需要已安装 3X-UI 面板"
    echo ""
    echo "  0. 取消安装"
    echo ""

    local choice
    while true; do
        read -e -r -p "选择部署模式 [1]: " choice
        choice=${choice:-1}
        case "$choice" in
            1)
                WG_DEPLOY_MODE="domestic"
                print_success "已选择: 境内部署 (标准 UDP 直连)"
                log_action "WireGuard: deploy_mode=domestic selected"
                return 0
                ;;
            2)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    print_error "OpenWrt 暂不支持境外隧道模式"
                    continue
                fi
                if ! wg_check_xui_installed; then
                    print_warn "未检测到 3X-UI 面板"
                    echo -e "  境外模式需要 3X-UI 提供 VLESS-Reality 隧道"
                    if ! confirm "是否仍要继续？(需要后续手动安装 3X-UI)"; then
                        continue
                    fi
                fi
                WG_DEPLOY_MODE="overseas"
                print_success "已选择: 境外部署 (VLESS-Reality 隧道)"
                log_action "WireGuard: deploy_mode=overseas selected"
                return 0
                ;;
            0)
                print_info "安装已取消"
                return 1
                ;;
            *)
                print_warn "无效选项"
                ;;
        esac
    done
}
