# modules/14-email.sh - Cloudflare 临时邮箱菜单入口
# 项目: https://github.com/dreamhunter2333/cloudflare_temp_email
# 模块拆分: 14a state / 14b cf-api / 14c deploy / 14d manage / 14e uninstall

email_status() {
    print_title "临时邮箱部署状态"
    if ! email_state_load 2>/dev/null; then
        print_warn "未部署"
        echo "  $(ls -ld "$EMAIL_INSTALL_DIR" 2>/dev/null || echo "本地目录不存在")"
        pause; return
    fi
    echo -e "  ${C_CYAN}域名:${C_RESET}        ${EMAIL_DOMAIN}"
    echo -e "  ${C_CYAN}前端:${C_RESET}        https://${EMAIL_FRONTEND_DOMAIN}"
    echo -e "  ${C_CYAN}API:${C_RESET}         https://${EMAIL_API_DOMAIN}"
    echo -e "  ${C_CYAN}管理面板:${C_RESET}    https://${EMAIL_FRONTEND_DOMAIN}/admin"
    echo -e "  ${C_CYAN}邮箱格式:${C_RESET}    ${EMAIL_ADDRESS_PREFIX:+${EMAIL_ADDRESS_PREFIX}.}xxx@${EMAIL_DOMAIN}"
    echo -e "  ${C_CYAN}版本:${C_RESET}        ${EMAIL_INSTALL_VERSION}"
    echo -e "  ${C_CYAN}部署时间:${C_RESET}    ${EMAIL_INSTALL_DATE}"
    echo -e "  ${C_CYAN}D1 数据库:${C_RESET}   ${EMAIL_D1_NAME}"
    echo -e "  ${C_CYAN}Resend:${C_RESET}      $([[ ${EMAIL_RESEND_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_GRAY}未启用${C_RESET}")"
    echo -e "  ${C_CYAN}Catch-all:${C_RESET}   $([[ ${EMAIL_CATCH_ALL_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_YELLOW}需手动检查${C_RESET}")"
    echo -e "  ${C_GRAY}State:    ${EMAIL_STATE_FILE}${C_RESET}"
    echo -e "  ${C_GRAY}Log:      ${EMAIL_LOG_FILE}${C_RESET}"
    [[ -f "$EMAIL_ADMIN_FILE" ]] && echo -e "  ${C_GRAY}Admin pw: ${EMAIL_ADMIN_FILE} (mode 600)${C_RESET}"

    echo ""
    print_info "Worker 健康检查..."
    local resp
    resp=$(curl -sS --max-time 8 "https://${EMAIL_API_DOMAIN}/health_check" 2>/dev/null)
    if [[ "$resp" == "OK" ]]; then
        print_success "API 后端正常 (https://${EMAIL_API_DOMAIN}/health_check → OK)"
    else
        print_warn "API 未响应或 DNS 未生效 (response: ${resp:-空})"
    fi
    pause
}

email_view_log() {
    print_title "查看部署日志"
    if [[ ! -f "$EMAIL_LOG_FILE" ]]; then
        print_warn "日志尚未生成: $EMAIL_LOG_FILE"
        pause; return
    fi
    echo -e "${C_GRAY}（最近 80 行；完整日志: $EMAIL_LOG_FILE）${C_RESET}"
    draw_line
    # 走脱敏管道：兜底过滤旧版本日志里可能残留的 secret_text / Bearer / TOKEN= 形式
    tail -n 80 "$EMAIL_LOG_FILE" | _email_redact_secrets
    draw_line
    pause
}

menu_email() {
    fix_terminal
    while true; do
        print_title "Cloudflare 临时邮箱"
        # 三态：installed=完整部署 / partial=state 存在但 INSTALLED=0 / none=无 state
        local state_kind="none"
        if email_state_load 2>/dev/null; then
            state_kind="installed"
        elif [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
            _email_state_reset_vars
            # shellcheck disable=SC1090
            source "$EMAIL_STATE_FILE"
            state_kind="partial"
        fi

        case "$state_kind" in
            none)
                echo -e "  ${C_YELLOW}状态: 未部署${C_RESET}"
                echo ""
                echo "1. 一键部署"
                echo "2. 查看部署日志"
                echo "0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_deploy ;;
                    2) email_view_log ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
            partial)
                echo -e "  ${C_RED}状态: 部署未完成${C_RESET}  域名: ${EMAIL_DOMAIN:-?}"
                echo -e "  ${C_GRAY}（state 中 EMAIL_INSTALLED=0，远端可能残留 D1/Worker/Pages/DNS）${C_RESET}"
                echo ""
                echo -e "  ${C_GREEN}1. 强制卸载${C_RESET}（推荐 — 先回收远端残留再重新部署）"
                echo "  2. 重新部署（自动备份旧 state，但会生成新资源名 — 仅在确认旧资源已手工清理时使用）"
                echo "  3. 查看部署日志"
                echo "  0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_uninstall ;;
                    2) email_deploy ;;
                    3) email_view_log ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
            installed)
                echo -e "  ${C_GREEN}状态: 已部署${C_RESET}  ${EMAIL_FRONTEND_DOMAIN}  (${EMAIL_INSTALL_VERSION})"
                echo ""
                echo "1. 查看部署状态 + 健康检查"
                echo "2. 修改管理员密码"
                echo "3. 管理收信域名 (DOMAINS)"
                echo "4. 配置 / 更新 Resend"
                echo "5. 升级到最新版本"
                echo "6. 重新部署 Worker / Pages (保留 D1)"
                echo "7. 查看部署日志"
                echo "8. 完全卸载"
                echo "0. 返回"
                read -e -r -p "选择: " c
                case $c in
                    1) email_status ;;
                    2) email_manage_change_admin_password ;;
                    3) email_manage_domains ;;
                    4) email_manage_resend ;;
                    5) email_manage_upgrade ;;
                    6) email_manage_redeploy ;;
                    7) email_view_log ;;
                    8) email_uninstall ;;
                    0|q) break ;;
                    *) print_error "无效选项" ;;
                esac
                ;;
        esac
    done
}
