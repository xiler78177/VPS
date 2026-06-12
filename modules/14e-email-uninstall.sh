# modules/14e-email-uninstall.sh - 完全自动回收（Worker/Pages/D1/DNS/Catch-all）

email_uninstall() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "完全卸载 Cloudflare Temp Email"

    # 不再硬卡 EMAIL_INSTALLED=1 — 只要 state 文件能加载，即视为有可回收的远端资源（涵盖部署中途失败的场景）
    local has_state=0
    if [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
        _email_state_reset_vars
        # shellcheck disable=SC1090
        source "$EMAIL_STATE_FILE"
        has_state=1
    fi

    if [[ $has_state -eq 0 ]]; then
        print_warn "未检测到 state 文件，将仅执行本地清理"
        if [[ -d "$EMAIL_INSTALL_DIR" ]]; then
            confirm "删除本地目录 $EMAIL_INSTALL_DIR ?" && rm -rf "$EMAIL_INSTALL_DIR"
        fi
        rm -f "$EMAIL_ADMIN_FILE"
        email_state_clear
        pause; return
    fi

    if [[ "${EMAIL_INSTALLED:-0}" != "1" ]]; then
        print_warn "检测到上次部署未完成（state 中 EMAIL_INSTALLED=0）"
        print_info "将尝试回收 state 中记录的部分资源"
    fi

    # 显示待清理资源清单
    echo -e "${C_YELLOW}以下 Cloudflare 资源将被删除：${C_RESET}"
    echo "  • Worker:        ${EMAIL_WORKER_NAME}"
    echo "  • Pages:         ${EMAIL_PAGES_PROJECT}"
    echo "  • D1 数据库:     ${EMAIL_D1_NAME} (${EMAIL_D1_ID})"
    echo "  • Catch-all:     ${EMAIL_DOMAIN}"
    local _dns_count=0
    local _id
    for _id in "$EMAIL_DNS_FRONTEND_ID" "$EMAIL_DNS_MX1_ID" "$EMAIL_DNS_MX2_ID" "$EMAIL_DNS_MX3_ID" \
               "$EMAIL_DNS_DKIM_ID" "$EMAIL_DNS_SPF_ID" "$EMAIL_DNS_SEND_MX_ID" "$EMAIL_DNS_DMARC_ID"; do
        [[ -n "$_id" ]] && _dns_count=$((_dns_count+1))
    done
    echo "  • DNS 记录:      $_dns_count 条 (front CNAME / MX / Resend TXT 等)"
    echo "  • 本地目录:      $EMAIL_INSTALL_DIR"
    echo "  • 状态/日志:     $EMAIL_STATE_FILE, $EMAIL_ADMIN_FILE"
    echo ""
    echo -e "${C_RED}⚠ D1 数据库中存储的所有邮件、用户、地址都将永久丢失！${C_RESET}"
    echo ""

    confirm "确认执行完全卸载?" || { pause; return; }
    local final
    read -e -r -p "再次确认请输入卸载目标域名 [$EMAIL_DOMAIN]: " final
    if [[ "$final" != "$EMAIL_DOMAIN" ]]; then
        print_warn "域名不匹配，已取消"; pause; return
    fi

    # 拿 Token
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        email_read_secret "Cloudflare API Token (具备删除权限)" CF_API_TOKEN || { pause; return; }
        export CF_API_TOKEN
        if ! _email_cf_token_verify 2>/dev/null; then
            print_error "Token 校验失败"; pause; return
        fi
    fi
    if [[ -z "${CF_ACCOUNT_ID:-}" ]]; then
        if [[ -n "${EMAIL_CF_ACCOUNT_ID:-}" ]]; then
            CF_ACCOUNT_ID="$EMAIL_CF_ACCOUNT_ID"
            export CF_ACCOUNT_ID
        else
            # 兼容旧 state — 强制让用户选，绝不取第一个（否则可能误删错账户资源）
            print_warn "state 中未记录 Account ID，需要选择正确账户以避免误删"
            _email_deploy_pick_account || { pause; return; }
        fi
    fi
    # 同步导出 Wrangler 新版环境变量
    _email_export_wrangler_env

    echo ""
    print_info "开始回收远程资源..."
    local uninstall_failed=0

    # 1. 关闭 catch-all
    if [[ "${EMAIL_CATCH_ALL_ENABLED:-0}" == "1" && -n "$EMAIL_ZONE_ID" ]]; then
        if email_run "禁用 Email Routing catch-all" _email_cf_catch_all_disable "$EMAIL_ZONE_ID"; then
            EMAIL_CATCH_ALL_ENABLED=0
        else
            uninstall_failed=1
        fi
    fi

    # 2. DNS 记录（按 state 中记录的 ID 删除）
    if [[ -n "$EMAIL_ZONE_ID" ]]; then
        _email_uninstall_delete_dns || uninstall_failed=1
    fi

    # 3. Worker
    if [[ -n "$EMAIL_WORKER_NAME" ]]; then
        if email_run "删除 Worker ${EMAIL_WORKER_NAME}" _email_cf_worker_delete "$EMAIL_WORKER_NAME"; then :; else
            print_warn "Worker 删除失败（可能已不存在）"
            uninstall_failed=1
        fi
    fi

    # 4. Pages
    if [[ -n "$EMAIL_PAGES_PROJECT" ]]; then
        if email_run "删除 Pages ${EMAIL_PAGES_PROJECT}" _email_cf_pages_project_delete "$EMAIL_PAGES_PROJECT"; then :; else
            print_warn "Pages 删除失败（可能已不存在）"
            uninstall_failed=1
        fi
    fi

    # 5. D1
    if [[ -n "$EMAIL_D1_ID" ]]; then
        if email_run "删除 D1 ${EMAIL_D1_NAME}" _email_cf_d1_delete "$EMAIL_D1_ID"; then :; else
            print_warn "D1 删除失败 — 请登录 Dashboard 手动删除 ${EMAIL_D1_NAME}"
            uninstall_failed=1
        fi
    fi

    # 6. 本地目录与状态（先保存日志要用到的字段，再清 state）
    local _log_domain="${EMAIL_DOMAIN:-unknown}"
    if [[ "$uninstall_failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "远端资源未完全删除，已保留本地目录和 state，避免丢失资源 ID。"
        print_warn "请根据上方失败项处理后重新执行卸载。"
        log_action "Cloudflare Temp Email uninstall incomplete: $_log_domain"
        unset CF_API_TOKEN CLOUDFLARE_API_TOKEN
        pause
        return 1
    fi

    rm -rf "$EMAIL_INSTALL_DIR"
    rm -f "$EMAIL_ADMIN_FILE"
    print_success "本地目录已删除: $EMAIL_INSTALL_DIR"
    print_success "管理员密码文件已删除"
    email_state_clear
    print_success "状态文件已清除"

    log_action "Cloudflare Temp Email fully uninstalled: $_log_domain"
    echo ""
    echo -e "${C_GREEN}========== 卸载完成 ==========${C_RESET}"
    echo -e "${C_GRAY}部署日志保留在 $EMAIL_LOG_FILE — 如确认无需可手动删除${C_RESET}"
    unset CF_API_TOKEN
    pause
}

_email_uninstall_delete_dns() {
    local zid="$EMAIL_ZONE_ID"
    local failed=0
    local pairs=(
        "EMAIL_DNS_FRONTEND_ID:CNAME(前端)"
        "EMAIL_DNS_MX1_ID:MX(route1)"
        "EMAIL_DNS_MX2_ID:MX(route2)"
        "EMAIL_DNS_MX3_ID:MX(route3)"
        "EMAIL_DNS_DKIM_ID:TXT(DKIM)"
        "EMAIL_DNS_SPF_ID:TXT(SPF)"
        "EMAIL_DNS_SEND_MX_ID:MX(Resend)"
        "EMAIL_DNS_DMARC_ID:TXT(DMARC)"
    )
    local entry var_name label rid
    for entry in "${pairs[@]}"; do
        var_name="${entry%%:*}"
        label="${entry#*:}"
        rid="${!var_name}"
        [[ -z "$rid" ]] && continue
        if _email_cf_dns_delete "$zid" "$rid" 2>/dev/null; then
            print_success "已删 DNS: $label"
        else
            print_warn "DNS 删除失败: $label (id=$rid)"
            failed=1
        fi
    done

    # 兜底：按 type+name 清理仍可能残留的同名记录（防 state 不完整）
    _email_cf_dns_purge "$zid" "CNAME" "$EMAIL_FRONTEND_DOMAIN" 2>/dev/null || true
    _email_cf_dns_purge "$zid" "MX"    "$EMAIL_DOMAIN" 2>/dev/null || true
    if [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]]; then
        _email_cf_dns_purge "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "TXT" "send.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "MX"  "send.${EMAIL_DOMAIN}" 2>/dev/null || true
        _email_cf_dns_purge "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" 2>/dev/null || true
    fi
    return "$failed"
}
