# modules/11a-wireguard-netcheck.sh - WireGuard 服务端网络资质检测
# 在部署 WG 服务端前检测本机是否直接接入公网（排除 NAT 环境）

# 部署方案全局变量: A=标准 UDP (公网直连), B=UDP over TCP (NAT 环境)
WG_DEPLOY_PLAN="A"

# 判断一个 IPv4 是否属于私有/CGNAT 地址段
_wg_is_private_ip() {
    local ip="$1"
    local IFS='.'
    read -r o1 o2 o3 o4 <<< "$ip"
    [[ "$o1" -eq 10 ]] && return 0                                    # 10.0.0.0/8
    [[ "$o1" -eq 172 && "$o2" -ge 16 && "$o2" -le 31 ]] && return 0  # 172.16.0.0/12
    [[ "$o1" -eq 192 && "$o2" -eq 168 ]] && return 0                  # 192.168.0.0/16
    [[ "$o1" -eq 100 && "$o2" -ge 64 && "$o2" -le 127 ]] && return 0 # 100.64.0.0/10 (CGNAT)
    return 1
}

# 检测本机是否拥有公网 IP（排除虚拟接口）
# 返回 0 = 有公网 IP，返回 1 = 全部为私有 IP（NAT 环境）
wg_check_public_ip() {
    local found_public=false found_any=false
    local line ip iface

    while IFS= read -r line; do
        # 匹配: inet x.x.x.x/xx ... <接口名>
        [[ "$line" =~ inet[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/[0-9]+.*[[:space:]]([a-zA-Z0-9_.-]+)[[:space:]]*$ ]] || continue
        ip="${BASH_REMATCH[1]}"
        iface="${BASH_REMATCH[2]}"

        # 排除虚拟/容器接口
        case "$iface" in
            docker*|br-*|veth*|virbr*|lo|cni*|flannel*|cali*) continue ;;
        esac

        found_any=true

        if _wg_is_private_ip "$ip"; then
            echo -e "  ${C_YELLOW}├ ${iface}: ${ip} (内网/NAT)${C_RESET}"
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

# 交互式网络资质检测
# 设置 WG_DEPLOY_PLAN: A (公网直连) 或 B (NAT + udp2raw)
# 返回 0 = 允许继续安装，返回 1 = 用户取消
wg_net_qualify_server() {
    echo -e "\n${C_CYAN}[网络资质检测] 检查本机网络环境...${C_RESET}"
    draw_line

    if wg_check_public_ip; then
        draw_line
        print_success "检测通过: 公网直连，使用方案 A (标准 UDP)"
        WG_DEPLOY_PLAN="A"
        return 0
    fi

    draw_line
    echo ""
    print_warn "所有网络接口均为内网 IP，判定为 NAT 环境"
    echo -e "  ${C_YELLOW}NAT 环境下 WG 的 UDP 流量可能被识别并封禁端口${C_RESET}"
    echo -e "  ${C_CYAN}将自动启用 B 方案: 使用 udp2raw 将 UDP 封装为伪 TCP${C_RESET}"
    echo ""

    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_error "OpenWrt 暂不支持 B 方案 (udp2raw)"
        pause; return 1
    fi

    if confirm "使用 B 方案继续部署？"; then
        WG_DEPLOY_PLAN="B"
        print_info "已选择 B 方案: UDP over TCP (udp2raw)"
        log_action "WireGuard: NAT detected, Plan B (udp2raw) selected"
        return 0
    fi

    print_info "安装已取消"
    pause; return 1
}
