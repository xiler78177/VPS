# modules/12a-wireguard-deb-netcheck.sh - Debian/Ubuntu 环境兼容性检测

# Debian/Ubuntu 环境兼容性全面检测
# 返回 0 = 全部通过，返回 1 = 有致命项失败
wg_deb_check_compat() {
    echo -e "\n${C_CYAN}[Debian/Ubuntu 环境兼容性检测]${C_RESET}"
    draw_line

    local fatal=0 warn=0

    # ── [必须] 平台确认 ──
    if [[ "$PLATFORM" == "debian" ]]; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   平台: Debian/Ubuntu"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} 平台: ${PLATFORM} (此模块仅支持 Debian/Ubuntu)"
        fatal=$((fatal + 1))
    fi

    # ── [信息] 发行版详情 ──
    if [[ -f /etc/os-release ]]; then
        local distro version
        distro=$(grep 'PRETTY_NAME' /etc/os-release 2>/dev/null | cut -d'"' -f2)
        version=$(grep 'VERSION_ID' /etc/os-release 2>/dev/null | cut -d'"' -f2)
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 发行版: ${distro:-未知}"
        echo -e "  ${C_CYAN}[INFO]${C_RESET} 版本号: ${version:-未知}"
    fi

    # ── [必须] apt 包管理器 ──
    if command -v apt-get &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   apt 包管理器可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} apt 不可用 (无法安装软件包)"
        fatal=$((fatal + 1))
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
        local kver
        kver=$(uname -r | cut -d'.' -f1-2)
        local kmajor kminor
        kmajor=$(echo "$kver" | cut -d'.' -f1)
        kminor=$(echo "$kver" | cut -d'.' -f2)
        if [[ "$kmajor" -gt 5 ]] || [[ "$kmajor" -eq 5 && "$kminor" -ge 6 ]]; then
            echo -e "  ${C_CYAN}[INFO]${C_RESET} 内核 $(uname -r) (≥5.6, 内置 WireGuard 支持)"
        else
            echo -e "  ${C_YELLOW}[WARN]${C_RESET} 内核 $(uname -r) (<5.6, 可能需要 wireguard-dkms)"
            warn=$((warn + 1))
        fi
    fi

    # ── [推荐] jq ──
    if command -v jq &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   jq 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} jq 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [推荐] wg 工具 ──
    if command -v wg &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   wireguard-tools 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} wireguard-tools 未安装 (将在安装阶段自动安装)"
        warn=$((warn + 1))
    fi

    # ── [推荐] qrencode ──
    if command -v qrencode &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   qrencode 已安装"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} qrencode 未安装 (二维码功能不可用，不影响核心功能)"
        warn=$((warn + 1))
    fi

    # ── [检测] iptables ──
    if command -v iptables &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   iptables 可用"
    else
        echo -e "  ${C_YELLOW}[WARN]${C_RESET} iptables 不可用 (将在安装阶段自动安装)"
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

    # ── [信息] systemd ──
    if command -v systemctl &>/dev/null; then
        echo -e "  ${C_GREEN}[OK]${C_RESET}   systemd 可用"
    else
        echo -e "  ${C_RED}[FAIL]${C_RESET} systemd 不可用 (wg-quick 服务依赖 systemd)"
        fatal=$((fatal + 1))
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
        print_success "Debian/Ubuntu 环境完全兼容"
    fi
    return 0
}
