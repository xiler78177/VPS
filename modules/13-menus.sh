# modules/13-menus.sh - 主菜单、OpenWrt 菜单、main() 入口
show_main_menu() {
    fix_terminal
    clear
    local W=76
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+22+W)/2)) "$SCRIPT_NAME $VERSION [OpenWrt]"
    else
        printf "${C_CYAN}%*s${C_RESET}\n" $(((${#SCRIPT_NAME}+10+W)/2)) "$SCRIPT_NAME $VERSION"
    fi
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    show_dual_column_sysinfo
    printf "${C_CYAN}%${W}s${C_RESET}\n" | tr ' ' '='
    echo -e " ${C_CYAN}[ 安全防护 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "$(echo -e "${C_GRAY}1. 基础依赖安装 [不可用]${C_RESET}")" "$(echo -e "${C_GRAY}2. UFW 防火墙 [不可用]${C_RESET}")"
        printf "  %-36s %-36s\n" "$(echo -e "${C_GRAY}3. Fail2ban [不可用]${C_RESET}")"       "$(echo -e "${C_GRAY}4. SSH 管理 [不可用]${C_RESET}")"
    else
        printf "  %-36s %-36s\n" "1. 基础依赖安装" "2. UFW 防火墙管理"
        printf "  %-36s %-36s\n" "3. Fail2ban 入侵防御" "4. SSH 安全配置"
    fi
    echo -e " ${C_CYAN}[ 系统优化 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "5. 系统优化 (BBR/主机名/时区)" "6. 网络工具 (DNS)"
    else
        printf "  %-36s %-36s\n" "5. 系统优化 (BBR/Swap)" "6. 网络工具 (DNS/测速)"
    fi
    echo -e " ${C_CYAN}[ 网络服务 ]${C_RESET}"
    if [[ "$PLATFORM" == "openwrt" ]]; then
        printf "  %-36s %-36s\n" "7. Web 服务 (SSL+Nginx+DDNS)" "$(echo -e "${C_GRAY}8. Docker [不可用]${C_RESET}")"
    else
        printf "  %-36s %-36s\n" "7. Web 服务 (SSL+Nginx)" "8. Docker 管理"
    fi
    printf "  %-36s\n" "9. WireGuard VPN"
    echo -e " ${C_CYAN}[ 维护工具 ]${C_RESET}"
    printf "  %-36s %-36s\n" "10. 查看操作日志" "11. 备份与恢复 (WebDAV)"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf "  %-36s\n" "0. 退出脚本"
}

menu_opt_openwrt() {
    fix_terminal
    while true; do
        print_title "系统优化 (OpenWrt 精简模式)"
        echo "1. 开启 BBR 加速
2. 修改主机名
3. 修改时区"
        echo -e "${C_GRAY}4. 虚拟内存 Swap [不可用]${C_RESET}"
        echo -e "${C_GRAY}5. 系统垃圾清理 [不可用]${C_RESET}"
        echo "0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) opt_bbr ;;
            2) opt_hostname ;;
            3) select_timezone || true; pause ;;
            4) feature_blocked "虚拟内存 Swap" ;;
            5) feature_blocked "系统垃圾清理 (apt)" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}
menu_net_openwrt() {
    fix_terminal
    while true; do
        print_title "网络管理工具 (OpenWrt 精简模式)"
        echo "1. DNS 配置"
        echo -e "${C_GRAY}2. IPv4/IPv6 优先级 [不可用]${C_RESET}"
        echo -e "${C_GRAY}3. iPerf3 测速 [不可用]${C_RESET}"
        echo "0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) net_dns ;;
            2) feature_blocked "IPv4/IPv6 优先级 (需要 /etc/gai.conf)" ;;
            3) feature_blocked "iPerf3 测速" ;;
            0|q) break ;;
            *) print_error "无效" ;;
        esac
    done
}

main() {
    # 支持 --backup 命令行参数（用于定时任务）
    if [[ "${1:-}" == "--backup" ]]; then
        check_root
        check_os
        init_environment
        # cron 非交互模式：自动备份全部并上传
        BACKUP_NON_INTERACTIVE=1
        export BACKUP_NON_INTERACTIVE
        backup_create
        exit 0
    fi
    check_root
    check_os
    init_environment
    refresh_ssh_port
    
    while true; do
        show_main_menu
        read -e -r -p "请选择功能 [0-11]: " choice
        case $choice in
            1)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "基础依赖安装 (apt-get)"
                else
                    menu_update
                fi
                ;;
            2)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "UFW 防火墙 (OpenWrt 请用 LuCI 或 fw4)"
                else
                    menu_ufw
                fi
                ;;
            3)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Fail2ban"
                else
                    menu_f2b
                fi
                ;;
            4)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "SSH 完整管理 (OpenWrt 请用 LuCI 或编辑 /etc/config/dropbear)"
                else
                    menu_ssh
                fi
                ;;
            5)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_opt_openwrt
                else
                    menu_opt
                fi
                ;;
            6)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    menu_net_openwrt
                else
                    menu_net
                fi
                ;;
            7) menu_web ;;
            8)
                if [[ "$PLATFORM" == "openwrt" ]]; then
                    feature_blocked "Docker 管理"
                else
                    menu_docker
                fi
                ;;
            9)
                wg_main_menu
                ;;
            10)
                print_title "操作日志 (最近 50 条)"
                if [[ -f "$LOG_FILE" ]]; then
                    tail -n 50 "$LOG_FILE"
                else
                    print_warn "日志文件不存在。"
                fi
                pause
                ;;
            11)
                menu_backup
                ;;
            0|q|Q)
                echo ""
                print_success "感谢使用 $SCRIPT_NAME！"
                exit 0
                ;;
            *)
                print_error "无效选项，请重新选择。"
                sleep 1
                ;;
        esac
    done
}
