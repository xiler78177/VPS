# modules/14d-email-manage.sh - 临时邮箱管理操作（改密码 / 改域名 / Resend / 升级）

# 前置：所有 manage 操作均要求 state 已加载 + Token 已输入
_email_manage_prepare() {
    if ! email_state_load 2>/dev/null; then
        print_error "未检测到已部署的临时邮箱（缺少 ${EMAIL_STATE_FILE}）"
        return 1
    fi
    if [[ -z "${CF_API_TOKEN:-}" ]]; then
        echo -e "${C_GRAY}管理操作需要 Cloudflare API Token (与部署时同 Token 即可)${C_RESET}"
        email_read_secret "Cloudflare API Token" CF_API_TOKEN || return 1
        export CF_API_TOKEN
        if ! _email_cf_token_verify 2>/dev/null; then
            print_error "Token 校验失败"
            unset CF_API_TOKEN
            return 1
        fi
    fi
    if [[ -z "${CF_ACCOUNT_ID:-}" ]]; then
        if [[ -n "${EMAIL_CF_ACCOUNT_ID:-}" ]]; then
            CF_ACCOUNT_ID="$EMAIL_CF_ACCOUNT_ID"
            export CF_ACCOUNT_ID
        else
            # 兼容旧 state（无持久化 ACCOUNT_ID）— 强制让用户选，避免误取第一个
            print_warn "state 中未记录 Account ID（旧版本部署），需要重新选择"
            _email_deploy_pick_account || return 1
            EMAIL_CF_ACCOUNT_ID="$CF_ACCOUNT_ID"
            email_state_write
        fi
    fi
    # 同步导出 Wrangler 新版环境变量
    _email_export_wrangler_env
    cd "$EMAIL_INSTALL_DIR/worker" 2>/dev/null || {
        print_error "本地项目目录缺失: $EMAIL_INSTALL_DIR/worker"
        return 1
    }
}

# 解析 wrangler.toml [vars] 中的 string 字段值（用于保留 JWT_SECRET 等）
_email_toml_get_var() {
    local key="$1" toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    [[ -f "$toml" ]] || return 1
    grep -E "^${key}[[:space:]]*=" "$toml" | head -1 | sed -E 's/^[^=]+=[[:space:]]*"?([^"]*)"?.*/\1/'
}

_email_manage_update_admin_passwords_var() {
    local admin_json="$1"
    local toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    [[ -f "$toml" ]] || return 1

    cp -a "$toml" "${toml}.adminpw.bak.$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true
    local line="ADMIN_PASSWORDS = ${admin_json}"
    local content
    if grep -qE '^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=' "$toml"; then
        content=$(ADMIN_PASSWORDS_LINE="$line" awk '
            BEGIN { line = ENVIRON["ADMIN_PASSWORDS_LINE"] }
            /^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=/ { print line; next }
            { print }
        ' "$toml") || return 1
    else
        content=$(ADMIN_PASSWORDS_LINE="$line" awk '
            BEGIN { line = ENVIRON["ADMIN_PASSWORDS_LINE"]; inserted=0 }
            /^\[vars\]/ { print; print line; inserted=1; next }
            { print }
            END {
                if (!inserted) {
                    print ""
                    print "[vars]"
                    print line
                }
            }
        ' "$toml") || return 1
    fi
    _email_write_private_file "$toml" "$content" || return 1
    _email_export_wrangler_env
    cd "$EMAIL_INSTALL_DIR/worker" || return 1
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || return 1
    email_run "更新 ADMIN_PASSWORDS 普通变量并重新部署 Worker" _email_wrangler deploy
}

# ── 1. 修改管理员密码 ──
email_manage_change_admin_password() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "修改管理员密码"
    _email_manage_prepare || { pause; return; }

    echo -e "${C_GRAY}留空将自动生成 32 位十六进制密码${C_RESET}"
    local new_pw=""
    # 隐藏输入避免肩窥；空值走自动生成分支
    read -r -s -p "$(echo -e "${C_YELLOW}新管理员密码 [留空自动生成]: ${C_RESET}")" new_pw
    echo ""
    if [[ -z "$new_pw" ]]; then
        new_pw=$(openssl rand -hex 16)
        print_info "已自动生成"
    else
        print_info "已收到密码（不回显）"
    fi
    if (( ${#new_pw} < 8 )); then
        print_error "密码长度不足 8 位"; pause; return
    fi

    local admin_json
    # 与 14c 一致：JSON 数组字面量 ["pw"]，不要 | tostring
    admin_json=$(jq -nc --arg p "$new_pw" '[$p]')
    if ! email_run "写入 ADMIN_PASSWORDS secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "ADMIN_PASSWORDS" "$admin_json"; then
        print_warn "secret 写入失败，尝试兼容旧部署的 ADMIN_PASSWORDS 普通变量"
        if ! _email_manage_update_admin_passwords_var "$admin_json"; then
            print_error "管理员密码更新失败"
            pause; return
        fi
    fi
    email_save_admin_password "$new_pw"
    echo ""
    echo -e "${C_GREEN}========== 管理员密码已更新 ==========${C_RESET}"
    echo -e "  新密码:       ${C_YELLOW}${new_pw}${C_RESET}"
    echo -e "  已保存:       ${C_GRAY}${EMAIL_ADMIN_FILE}${C_RESET}"
    log_action "Email admin password rotated"
    unset new_pw
    pause
}

# ── 2. 管理收信域名 DOMAINS ──
email_manage_domains() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "管理收信域名 (DOMAINS)"
    _email_manage_prepare || { pause; return; }

    local toml="$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    local current
    current=$(grep -E '^DOMAINS[[:space:]]*=' "$toml" | head -1 | sed -E 's/^DOMAINS[[:space:]]*=[[:space:]]*//')
    [[ -z "$current" ]] && current='["'"$EMAIL_DOMAIN"'"]'
    echo -e "${C_CYAN}当前 DOMAINS:${C_RESET} $current"
    echo ""
    echo "1. 追加一个域名"
    echo "2. 移除一个域名"
    echo "0. 返回"
    read -e -r -p "选择: " act
    [[ "$act" != "1" && "$act" != "2" ]] && return

    local target
    read -e -r -p "目标域名: " target
    validate_domain "$target" || { print_error "域名格式无效"; pause; return; }

    # 当前域名数组
    local arr
    if ! arr=$(printf '%s' "$current" | jq -c '.' 2>/dev/null) \
       || ! printf '%s' "$arr" | jq -e 'type == "array" and all(.[]; type == "string")' >/dev/null 2>&1; then
        print_error "DOMAINS 当前配置不是合法 JSON 字符串数组，请先手工修复 wrangler.toml"
        pause; return 1
    fi
    local new_arr
    case $act in
        1)
            if echo "$arr" | jq -e --arg d "$target" 'index($d) != null' >/dev/null 2>&1; then
                print_warn "$target 已存在"; pause; return
            fi
            new_arr=$(echo "$arr" | jq -c --arg d "$target" '. + [$d]')
            ;;
        2)
            if [[ "$target" == "$EMAIL_DOMAIN" ]]; then
                print_error "主域名 $EMAIL_DOMAIN 不能移除（如需更换请重新部署）"
                pause; return
            fi
            new_arr=$(echo "$arr" | jq -c --arg d "$target" 'map(select(. != $d))')
            ;;
    esac

    # 替换 DOMAINS 和 DEFAULT_DOMAINS。先备份，只有 Worker 重新部署成功才保留本地修改。
    local backup tmp
    backup=$(mktemp "${toml}.domains.bak.XXXXXX") || { print_error "创建备份失败"; pause; return; }
    tmp=$(mktemp "${toml}.domains.XXXXXX") || { rm -f "$backup"; print_error "创建临时文件失败"; pause; return; }
    cp -a "$toml" "$backup" || { rm -f "$backup" "$tmp"; print_error "备份 wrangler.toml 失败"; pause; return; }
    if ! DOMAINS_JSON="$new_arr" awk '
        BEGIN { value = ENVIRON["DOMAINS_JSON"]; seen_domains = 0; seen_defaults = 0 }
        /^[[:space:]]*DEFAULT_DOMAINS[[:space:]]*=/ { print "DEFAULT_DOMAINS = " value; seen_defaults = 1; next }
        /^[[:space:]]*DOMAINS[[:space:]]*=/ { print "DOMAINS = " value; seen_domains = 1; next }
        { print }
        END { if (!seen_domains || !seen_defaults) exit 2 }
    ' "$toml" > "$tmp"; then
        rm -f "$tmp"
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "wrangler.toml 缺少 DOMAINS/DEFAULT_DOMAINS，已恢复原文件"
        pause; return 1
    fi
    mv -f "$tmp" "$toml" || { cp -a "$backup" "$toml" 2>/dev/null || true; rm -f "$backup" "$tmp"; print_error "更新 wrangler.toml 失败，已恢复原文件"; pause; return; }
    chmod 600 "$toml"
    print_success "wrangler.toml 已更新"
    echo "  DOMAINS = $new_arr"

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || {
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "依赖安装失败，wrangler.toml 已恢复"
        pause; return 1
    }
    if email_run "重新部署 Worker" _email_wrangler deploy; then
        rm -f "$backup"
        print_success "Worker 已更新，新域名已生效"
        log_action "Email DOMAINS updated: $new_arr"
    else
        cp -a "$backup" "$toml" 2>/dev/null || true
        rm -f "$backup"
        print_error "部署失败，wrangler.toml 已恢复"
        pause; return 1
    fi
    pause
}

# ── 3. Resend ──
email_manage_resend() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "配置 / 更新 Resend"
    _email_manage_prepare || { pause; return; }

    echo -e "当前状态: $([[ ${EMAIL_RESEND_ENABLED:-0} -eq 1 ]] && echo "${C_GREEN}已启用${C_RESET}" || echo "${C_GRAY}未启用${C_RESET}")"
    [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]] && echo "  发件子域:  $EMAIL_RESEND_SEND_DOMAIN"
    echo ""
    echo "1. 启用 / 重新配置 Resend"
    echo "2. 仅更新 RESEND_TOKEN（不动 DNS）"
    echo "3. 禁用 Resend（删除相关 DNS 记录）"
    echo "0. 返回"
    read -e -r -p "选择: " act
    case $act in
        1) _email_manage_resend_setup ;;
        2) _email_manage_resend_token_only ;;
        3) _email_manage_resend_disable ;;
        *) return ;;
    esac
    pause
}

_email_manage_resend_setup() {
    local tok dkim
    email_read_secret "Resend API Token" tok || { print_error "Token 不能为空"; return 1; }
    print_info "已收到 Token: $(email_mask_token "$tok")"
    read -e -r -p "Resend DKIM (p=MIGfMA0...): " dkim
    [[ -z "$dkim" ]] && { print_error "DKIM 不能为空"; unset tok dkim; return 1; }

    if ! email_run "写入 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_error "secret 写入失败"
        unset tok dkim
        return 1
    fi

    local send_sub="send.${EMAIL_DOMAIN}"
    local zid="$EMAIL_ZONE_ID"

    # 清旧记录（按 type+name 全量清，避免脏数据残留）
    local purge_failed=0
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}" || purge_failed=1
    _email_cf_dns_purge "$zid" TXT "$send_sub" || purge_failed=1
    _email_cf_dns_purge "$zid" MX  "$send_sub" || purge_failed=1
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}" || purge_failed=1
    if [[ "$purge_failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "清理旧 Resend DNS 记录失败，已停止启用并保留当前 state。"
        print_warn "RESEND_TOKEN secret 可能已写入；请修复 Cloudflare DNS/API 问题后重试。"
        unset tok dkim
        return 1
    fi

    local create_failed=0
    _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$dkim" \
        && print_success "DKIM" || { print_warn "DKIM 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
        && print_success "SPF" || { print_warn "SPF 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
        && print_success "Send MX" || { print_warn "Send MX 失败"; create_failed=1; }
    _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
        && print_success "DMARC" || { print_warn "DMARC 失败"; create_failed=1; }
    if [[ "$create_failed" -ne 0 ]]; then
        EMAIL_RESEND_ENABLED=0
        EMAIL_RESEND_SEND_DOMAIN=""
        email_state_write 2>/dev/null || true
        print_error "创建 Resend DNS 记录失败，已停止启用并保留当前 state。"
        print_warn "可能已有部分 DNS 记录创建成功；修复 Cloudflare DNS/API 问题后可重新配置。"
        unset tok dkim
        return 1
    fi

    EMAIL_RESEND_ENABLED=1
    EMAIL_RESEND_SEND_DOMAIN="$send_sub"
    email_state_write
    print_success "Resend 已启用"
    echo -e "${C_YELLOW}下一步:${C_RESET} 访问 https://resend.com/domains 触发 DKIM/SPF 验证"
    log_action "Email Resend enabled for $EMAIL_DOMAIN"
    unset tok dkim
}

_email_manage_resend_token_only() {
    local tok
    email_read_secret "新 Resend API Token" tok || return 1
    print_info "已收到 Token: $(email_mask_token "$tok")"
    if email_run "更新 RESEND_TOKEN secret" _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$tok"; then
        print_success "RESEND_TOKEN 已更新"
        log_action "Email Resend token rotated"
    else
        print_error "RESEND_TOKEN 更新失败"
        unset tok
        return 1
    fi
    unset tok
}

_email_manage_resend_disable() {
    confirm "确认禁用 Resend 并删除相关 DNS 记录?" || return
    local zid="$EMAIL_ZONE_ID"
    local failed=0
    if [[ -n "${EMAIL_DNS_DKIM_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_DKIM_ID" && print_success "已删 DKIM" || { print_warn "DKIM 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_SPF_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_SPF_ID" && print_success "已删 SPF" || { print_warn "SPF 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_SEND_MX_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_SEND_MX_ID" && print_success "已删 Send MX" || { print_warn "Send MX 删除失败"; failed=1; }
    fi
    if [[ -n "${EMAIL_DNS_DMARC_ID:-}" ]]; then
        _email_cf_dns_delete "$zid" "$EMAIL_DNS_DMARC_ID" && print_success "已删 DMARC" || { print_warn "DMARC 删除失败"; failed=1; }
    fi
    # 同步清掉可能的同名脏记录
    _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" TXT "send.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" MX  "send.${EMAIL_DOMAIN}" || failed=1
    _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}" || failed=1

    if [[ "$failed" -ne 0 ]]; then
        email_state_write 2>/dev/null || true
        print_error "部分 Resend DNS 记录删除失败，已保留 Resend state，便于修复后重试。"
        return 1
    fi

    print_warn "RESEND_TOKEN secret 不会自动清除，如需彻底清理请在 Dashboard → Workers → Settings → Variables 删除"
    EMAIL_RESEND_ENABLED=0
    EMAIL_RESEND_SEND_DOMAIN=""
    EMAIL_DNS_DKIM_ID=""; EMAIL_DNS_SPF_ID=""; EMAIL_DNS_SEND_MX_ID=""; EMAIL_DNS_DMARC_ID=""
    email_state_write
    log_action "Email Resend disabled for $EMAIL_DOMAIN"
}

# ── 4. 升级到最新版本 ──
email_manage_upgrade() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "升级到最新版本"
    _email_manage_prepare || { pause; return; }
    local old_version="${EMAIL_INSTALL_VERSION:-未知}"

    echo -e "${C_CYAN}当前版本:${C_RESET} ${EMAIL_INSTALL_VERSION:-未知}"
    email_run "拉取上游 tags" git -C "$EMAIL_INSTALL_DIR" fetch --tags --prune || { pause; return; }

    local latest
    latest=$(git -C "$EMAIL_INSTALL_DIR" describe --tags "$(git -C "$EMAIL_INSTALL_DIR" rev-list --tags --max-count=1)" 2>/dev/null)
    [[ -z "$latest" ]] && { print_error "无法识别最新 tag"; pause; return; }
    echo -e "${C_CYAN}最新版本:${C_RESET} $latest"

    if [[ "$latest" == "${EMAIL_INSTALL_VERSION:-}" ]]; then
        print_success "已是最新版本，无需升级"
        pause; return
    fi
    confirm "确认升级到 $latest?" || return

    email_run "checkout $latest" git -C "$EMAIL_INSTALL_DIR" checkout --quiet "$latest" || { pause; return; }
    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || { pause; return; }

    # 增量 D1 migration：跑 patches_applied 中没出现过的
    local applied_str="${EMAIL_PATCHES_APPLIED:-} "
    local new_patches=()
    local p base
    while IFS= read -r p; do
        base=$(basename "$p")
        if [[ "$applied_str" != *" $base "* && "$applied_str" != "$base "* ]]; then
            new_patches+=("$p")
        fi
    done < <(ls "$EMAIL_INSTALL_DIR/db"/*-patch.sql 2>/dev/null | sort)

    if (( ${#new_patches[@]} > 0 )); then
        print_info "发现 ${#new_patches[@]} 个新 D1 migration"
        for p in "${new_patches[@]}"; do
            base=$(basename "$p")
            if email_run "应用 $base" _email_wrangler d1 execute "$EMAIL_D1_NAME" --file="$p" --remote; then
                EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED} ${base}"
                EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED# }"
                if ! email_state_write; then
                    print_error "patch $base 已应用，但写入升级进度失败；已中止升级（worker 未重新部署）"
                    pause; return
                fi
            else
                print_error "patch $base 失败，已中止升级（worker 未重新部署）"
                pause; return
            fi
        done
    else
        print_info "无新增 D1 migration"
    fi

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "部署 Worker $latest" _email_wrangler deploy || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/frontend" || return
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "前端依赖" pnpm install --no-frozen-lockfile || { pause; return; }
    email_run "构建前端" pnpm build:pages || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/pages" || return
    # 升级链路同样需要同步 pages service binding —
    # 上游 tag 切换后 pages/wrangler.toml 可能重置为默认 service=cloudflare_temp_email
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（请手工检查）"
    email_run "Pages 依赖" pnpm install --no-frozen-lockfile || {
        _email_restore_pages_service_binding
        pause; return
    }
    local pages_rc=0
    email_run "部署 Pages" _email_wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
        --branch production --commit-dirty=true || pages_rc=$?
    _email_restore_pages_service_binding
    if [[ "$pages_rc" -ne 0 ]]; then
        pause; return
    fi

    EMAIL_INSTALL_VERSION="$latest"
    email_state_write
    print_success "已升级到 $latest"
    log_action "Email upgraded ${old_version} → $latest"
    pause
}

# ── 5. 重新部署（保留 D1 数据）──
email_manage_redeploy() {
    trap '_email_clear_sensitive_env' RETURN
    print_title "重新部署 Worker / Pages（保留 D1 数据）"
    _email_manage_prepare || { pause; return; }
    confirm "确认重新部署当前版本 ${EMAIL_INSTALL_VERSION}?" || return

    cd "$EMAIL_INSTALL_DIR/worker" || return
    email_run "Worker 依赖" pnpm install --no-frozen-lockfile || { pause; return; }
    email_run "部署 Worker" _email_wrangler deploy || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/frontend" || return
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "构建前端" pnpm build:pages || { pause; return; }

    cd "$EMAIL_INSTALL_DIR/pages" || return
    # 重部署链路也需要同步 service binding（防止本地 dirty 文件被覆盖后丢失自定义 worker 名）
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（请手工检查）"
    local pages_rc=0
    email_run "部署 Pages" _email_wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
        --branch production --commit-dirty=true || pages_rc=$?
    _email_restore_pages_service_binding
    if [[ "$pages_rc" -ne 0 ]]; then
        pause; return
    fi

    print_success "重新部署完成"
    log_action "Email redeployed: $EMAIL_INSTALL_VERSION"
    pause
}
