# modules/11a-wireguard-netcheck.sh - OpenWrt 环境兼容性检测

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

# OpenWrt 环境兼容性全面检测
# 返回 0 = 全部通过，返回 1 = 有致命项失败
wg_check_openwrt_compat() {
    echo -e "\n${C_CYAN}[OpenWrt 环境兼容性检测]${C_RESET}"
    draw_line

    local fatal=0 warn=0

    # ── [必须] 平台确认 ──
    if [[ "$PLATFORM" == "openwrt" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   平台: OpenWrt"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} 平台: ${PLATFORM} (当前仅支持 OpenWrt)"
        fatal=$((fatal + 1))
    fi

    # ── [信息] 发行版详情 ──
    if [[ -f /etc/openwrt_release ]]; then
        local distro version
        distro=$(grep 'DISTRIB_DESCRIPTION' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
        version=$(grep 'DISTRIB_RELEASE' /etc/openwrt_release 2>/dev/null | cut -d"'" -f2)
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 发行版: ${distro:-未知}"
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 版本号: ${version:-未知}"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} 未找到 /etc/openwrt_release"
        warn=$((warn + 1))
    fi

    # ── [必须] opkg 包管理器 ──
    if command -v opkg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   opkg 包管理器可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} opkg 不可用 (无法安装软件包)"
        fatal=$((fatal + 1))
    fi

    # ── [必须] uci 命令 ──
    if command -v uci &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   uci 配置系统可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} uci 不可用 (无法管理网络/防火墙配置)"
        fatal=$((fatal + 1))
    fi

    # ── [必须] nft 命令 + 权限 ──
    if command -v nft &>/dev/null; then
        if nft list tables &>/dev/null; then
            echo -e "  ${C_GREEN}[OK]${C_RESET}   nftables 可用且有权限"
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} nft 命令存在但无执行权限 (需要 root)"
            fatal=$((fatal + 1))
        fi
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} nft 不可用 (防火墙规则依赖 nftables)"
        fatal=$((fatal + 1))
    fi

    # ── [检测] fw4 mangle_prerouting 链 ──
    if nft list chain inet fw4 mangle_prerouting &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   fw4 mangle_prerouting 链存在"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} fw4 mangle_prerouting 链不存在 (Mihomo bypass 将在其运行后自动配置)"
        warn=$((warn + 1))
    fi

    # ── [检测] 内核 WireGuard 支持 ──
    local wg_kernel=false
    if [[ -d /sys/module/wireguard ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    elif lsmod 2>/dev/null | grep -q wireguard; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   内核 WireGuard 模块已加载"
        wg_kernel=true
    fi
    if [[ "$wg_kernel" != "true" ]]; then
        # 尝试检测是否可安装
        if opkg list 2>/dev/null | grep -q 'kmod-wireguard'; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} 内核 WireGuard 模块未加载 (kmod-wireguard 可从 feeds 安装)"
            warn=$((warn + 1))
        elif opkg list-installed 2>/dev/null | grep -q 'kmod-wireguard'; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} kmod-wireguard 已安装但模块未加载 (可能需要重启)"
            warn=$((warn + 1))
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} 内核不支持 WireGuard 且 kmod-wireguard 不在可用包列表中"
            echo -e "         可能的原因: 自定义固件未编译 WireGuard 支持或 feeds 不匹配"
            fatal=$((fatal + 1))
        fi
    fi

    # ── [推荐] jq ──
    if command -v jq &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   jq 已安装"
    else
        if opkg list 2>/dev/null | grep -q '^jq '; then
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} jq 未安装 (将在安装阶段自动安装)"
            warn=$((warn + 1))
        else
            echo -e "  ${C_RED}[FAIL]${C_RESET} jq 未安装且不在可用包列表中 (JSON 数据库操作依赖)"
            fatal=$((fatal + 1))
        fi
    fi

    # ── [推荐] qrencode ──
    if command -v qrencode &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   qrencode 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} qrencode 未安装 (二维码功能不可用，不影响核心功能)"
        warn=$((warn + 1))
    fi

    # ── [推荐] wg 工具 ──
    if command -v wg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   wireguard-tools 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} wireguard-tools 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [信息] IP 转发状态 ──
    local ipfwd
    ipfwd=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    if [[ "$ipfwd" == "1" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   IP 转发已启用"
    else
        echo -e "  ${C_CYAN}[INFO]${C_RESET} IP 转发未启用 (安装时将自动开启)"
    fi

    # ── [信息] br-lan 网段 ──
    local br_lan_addr
    br_lan_addr=$(ip -4 addr show br-lan 2>/dev/null | grep -oP 'inet \K[0-9.]+/[0-9]+' | head -1)
    if [[ -n "$br_lan_addr" ]]; then
        echo -e "  ${C_CYAN}[INFO]${C_RESET} br-lan 网段: ${br_lan_addr}"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} 未检测到 br-lan 接口 (服务端 LAN 映射需要手动指定)"
        warn=$((warn + 1))
    fi

    # ── [信息] 本机网络 ──
    echo -e "\n${C_CYAN}  本机网络地址:${C_RESET}"
    wg_check_public_ip

    # ── 汇总 ──
    draw_line
    if [[ $fatal -gt 0 ]]; then
        echo -e "  ${C_RED}检测结果: ${fatal} 项致命错误, ${warn} 项警告${C_RESET}"
        print_error "环境不满足安装条件，请先解决上述 [FAIL] 项"
        return 1
    elif [[ $warn -gt 0 ]]; then
        echo -e "  ${C_YELLOW}检测结果: 全部通过, ${warn} 项警告${C_RESET}"
        print_success "环境检测通过 (存在警告但不影响安装)"
    else
        echo -e "  ${C_GREEN}检测结果: 全部通过${C_RESET}"
        print_success "OpenWrt 环境完全兼容"
    fi
    return 0
}
