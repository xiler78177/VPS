# modules/14c-email-deploy.sh - Cloudflare Temp Email 部署主流程

# ── 入口 ──
email_deploy() {
    print_title "Cloudflare Temp Email 一键部署"
    echo -e "${C_CYAN}项目: https://github.com/dreamhunter2333/cloudflare_temp_email${C_RESET}"
    echo ""

    # 已部署：让用户决定是否覆盖
    if email_state_load 2>/dev/null; then
        print_warn "检测到已有部署：${EMAIL_FRONTEND_DOMAIN:-?} / ${EMAIL_API_DOMAIN:-?}"
        echo -e "${C_GRAY}如需修改密码/域名/Resend，请使用管理菜单；本流程会覆盖现有配置。${C_RESET}"
        confirm "继续覆盖部署?" || { pause; return; }
        local bak
        bak=$(email_state_backup) && [[ -n "$bak" ]] && print_info "已备份旧 state → $bak"
    # 半成品（state 存在但 INSTALLED=0）：强警告，建议先卸载残留
    elif [[ -f "$EMAIL_STATE_FILE" ]] && validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null; then
        _email_state_reset_vars
        # shellcheck disable=SC1090
        source "$EMAIL_STATE_FILE"
        echo -e "${C_RED}⚠ 检测到上次部署未完成（state 存在但 EMAIL_INSTALLED=0）${C_RESET}"
        echo "  旧 state 中记录的资源："
        [[ -n "$EMAIL_D1_ID" ]]         && echo "    • D1:     $EMAIL_D1_NAME ($EMAIL_D1_ID)"
        [[ -n "$EMAIL_WORKER_NAME" ]]   && echo "    • Worker: $EMAIL_WORKER_NAME"
        [[ -n "$EMAIL_PAGES_PROJECT" ]] && echo "    • Pages:  $EMAIL_PAGES_PROJECT"
        echo ""
        print_warn "强烈建议先返回菜单选【强制卸载】清理远端残留，再重新部署。"
        print_warn "直接覆盖部署会生成新的 D1/Pages 名，旧资源 ID 将永远丢失，导致后续无法精准回收。"
        echo ""
        if ! confirm "确定要继续覆盖部署？（旧 state 会备份到 .bak.<时间戳>）"; then
            pause; return
        fi
        local bak
        bak=$(email_state_backup) && [[ -n "$bak" ]] && print_info "已备份旧 state → $bak"
    fi

    _email_state_reset_vars
    email_state_init_dirs
    email_log "===== email_deploy start ====="

    _email_deploy_check_env || { pause; return 1; }
    _email_deploy_collect_inputs || { pause; return 1; }

    # 校验 token / 拉 zone
    if ! email_run "校验 Cloudflare API Token" _email_cf_token_verify; then
        print_error "Token 验证失败，请检查 Token 权限与有效性"
        return 1
    fi

    if ! EMAIL_ZONE_ID=$(_email_cf_zone_id_by_name "$EMAIL_DOMAIN"); then
        print_error "无法获取域名 Zone ID，确认 $EMAIL_DOMAIN 已托管到 Cloudflare"
        return 1
    fi
    email_log "Zone ID: $EMAIL_ZONE_ID"
    print_success "Zone ID: $EMAIL_ZONE_ID"

    _email_deploy_pick_worker_name || { pause; return 1; }

    _email_deploy_clone_project || { pause; return 1; }
    _email_deploy_setup_d1 || { pause; return 1; }
    _email_deploy_render_toml || { pause; return 1; }
    _email_deploy_worker || { pause; return 1; }
    _email_deploy_secrets || { pause; return 1; }
    _email_deploy_frontend || { pause; return 1; }
    _email_deploy_pages || { pause; return 1; }
    _email_deploy_dns || { pause; return 1; }
    _email_deploy_email_routing || { pause; return 1; }

    EMAIL_INSTALLED=1
    EMAIL_INSTALL_DATE="$(date '+%Y-%m-%d %H:%M:%S')"
    email_state_write

    _email_deploy_postcheck
    _email_deploy_summary
    log_action "Cloudflare Temp Email deployed: ${EMAIL_FRONTEND_DOMAIN} / ${EMAIL_API_DOMAIN}"
    pause
}

# ── 1. 环境依赖 ──
_email_validate_dns_label() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]]
}

# 当 Token 可见多个 Account 时，强制让用户选；只有 1 个时静默选用
_email_deploy_pick_account() {
    local accounts_raw count
    accounts_raw=$(_email_cf_accounts_list 2>/dev/null) || {
        print_error "获取 Account 列表失败（Token 权限不足?）"
        return 1
    }
    count=$(printf '%s\n' "$accounts_raw" | grep -c .)
    if [[ "$count" -eq 0 ]]; then
        print_error "Token 未关联任何 Account"
        return 1
    fi
    if [[ "$count" -eq 1 ]]; then
        CF_ACCOUNT_ID=$(printf '%s' "$accounts_raw" | awk -F'\t' '{print $1}')
        export CF_ACCOUNT_ID
        local aname
        aname=$(printf '%s' "$accounts_raw" | awk -F'\t' '{print $2}')
        print_success "Account: $aname ($CF_ACCOUNT_ID)"
        return 0
    fi
    echo -e "${C_CYAN}Token 可见多个 Cloudflare Account，请选择:${C_RESET}"
    local i=1 ids=() names=() aid aname
    while IFS=$'\t' read -r aid aname; do
        [[ -z "$aid" ]] && continue
        printf "  %d. %s (%s)\n" "$i" "$aname" "$aid"
        ids+=("$aid"); names+=("$aname"); ((i++)) || true
    done <<< "$accounts_raw"
    local sel
    while true; do
        read -e -r -p "选择 [1-$((i-1))]: " sel
        if [[ "$sel" =~ ^[0-9]+$ && "$sel" -ge 1 && "$sel" -le $((i-1)) ]]; then
            CF_ACCOUNT_ID="${ids[$((sel-1))]}"
            export CF_ACCOUNT_ID
            print_success "Account: ${names[$((sel-1))]} ($CF_ACCOUNT_ID)"
            return 0
        fi
        print_error "无效选择"
    done
}

_email_deploy_check_env() {
    print_info "检查运行环境..."
    local pkg
    for pkg in git curl jq; do
        command_exists "$pkg" || install_package "$pkg" || { print_error "$pkg 安装失败"; return 1; }
    done

    if ! command_exists node; then
        email_run "安装 Node.js 22" bash -c '
            curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null 2>&1
            apt-get install -y -qq nodejs
        ' || { print_error "Node.js 安装失败，请手动安装"; return 1; }
    fi
    command_exists pnpm || email_run "安装 pnpm" npm install -g pnpm || return 1
    command_exists wrangler || email_run "安装 wrangler" npm install -g wrangler || return 1
    print_success "环境检查通过 (node=$(node -v 2>/dev/null) pnpm=$(pnpm -v 2>/dev/null) wrangler=$(wrangler --version 2>/dev/null | head -1))"
}

# ── 2. 交互式收集（Token 隐藏 / 管理员密码不回显）──
_email_deploy_collect_inputs() {
    echo ""
    email_read_secret "Cloudflare API Token" CF_API_TOKEN || { print_error "Token 不能为空"; return 1; }
    export CF_API_TOKEN
    print_info "已收到 Token: $(email_mask_token "$CF_API_TOKEN")"

    local cf_aid=""
    read -e -r -p "Cloudflare Account ID (留空让脚本列出可见账户): " cf_aid
    if [[ -z "$cf_aid" ]]; then
        _email_deploy_pick_account || return 1
    else
        CF_ACCOUNT_ID="$cf_aid"
        export CF_ACCOUNT_ID
    fi
    # 持久化到 state，供后续管理/卸载使用，避免多 Account 场景下误用第一个
    EMAIL_CF_ACCOUNT_ID="$CF_ACCOUNT_ID"
    # 同步导出 Wrangler 新版环境变量（避免走 deprecated CF_*）
    _email_export_wrangler_env

    read -e -r -p "域名 (如 example.com): " EMAIL_DOMAIN
    validate_domain "$EMAIL_DOMAIN" || { print_error "域名格式无效"; return 1; }

    while :; do
        read -e -r -p "API 子域名前缀 [mail-api]: " EMAIL_API_PREFIX
        EMAIL_API_PREFIX="${EMAIL_API_PREFIX:-mail-api}"
        _email_validate_dns_label "$EMAIL_API_PREFIX" && break
        print_error "前缀格式无效（DNS label: 仅 a-z 0-9 -，首尾非短横，1-63 字符）"
    done
    while :; do
        read -e -r -p "前端子域名前缀 [mail]: " EMAIL_FRONTEND_PREFIX
        EMAIL_FRONTEND_PREFIX="${EMAIL_FRONTEND_PREFIX:-mail}"
        _email_validate_dns_label "$EMAIL_FRONTEND_PREFIX" && break
        print_error "前缀格式无效（DNS label）"
    done
    while :; do
        read -e -r -p "邮箱地址前缀 (留空无前缀): " EMAIL_ADDRESS_PREFIX
        # 邮箱地址前缀可为空；非空时按 DNS label 字符集校验（更严格的 mailbox local-part 略过）
        [[ -z "$EMAIL_ADDRESS_PREFIX" ]] && break
        _email_validate_dns_label "$EMAIL_ADDRESS_PREFIX" && break
        print_error "前缀格式无效（仅 a-z 0-9 -）"
    done

    EMAIL_API_DOMAIN="${EMAIL_API_PREFIX}.${EMAIL_DOMAIN}"
    EMAIL_FRONTEND_DOMAIN="${EMAIL_FRONTEND_PREFIX}.${EMAIL_DOMAIN}"
    # Pages 项目用随机后缀彻底避免撞名（pages 名不影响 worker 路由）
    EMAIL_PAGES_PROJECT="temp-email-pages-$(openssl rand -hex 3)"
    EMAIL_D1_NAME="temp-email-$(openssl rand -hex 3)"
    # Worker 名在 _email_deploy_pick_worker_name 中决定（需要先验证 Token）
    EMAIL_WORKER_NAME=""

    echo -e "${C_GRAY}留空将自动生成 32 位十六进制密码（部署完成后展示并保存到 ${EMAIL_ADMIN_FILE}）${C_RESET}"
    local admin_pw=""
    # 隐藏输入避免肩窥；email_read_secret 在空值时返回 1，但这里允许留空走自动生成
    read -r -s -p "$(echo -e "${C_YELLOW}管理员密码 [留空自动生成]: ${C_RESET}")" admin_pw
    echo ""
    EMAIL_ADMIN_PASSWORD="$admin_pw"
    if [[ -z "$EMAIL_ADMIN_PASSWORD" ]]; then
        EMAIL_ADMIN_PASSWORD=$(openssl rand -hex 16)
        print_success "已自动生成管理员密码（部署完成后展示并保存到 $EMAIL_ADMIN_FILE）"
    else
        print_info "已收到管理员密码（不回显）"
    fi

    EMAIL_JWT_SECRET=$(openssl rand -hex 32)

    EMAIL_RESEND_TOKEN=""
    EMAIL_RESEND_DKIM=""
    if confirm "是否启用 Resend 发件能力?"; then
        email_read_secret "Resend API Token" EMAIL_RESEND_TOKEN || { print_error "Resend Token 不能为空"; return 1; }
        print_info "已收到 Resend Token: $(email_mask_token "$EMAIL_RESEND_TOKEN")"
        read -e -r -p "Resend DKIM 值 (p=MIGfMA0...): " EMAIL_RESEND_DKIM
        [[ -z "$EMAIL_RESEND_DKIM" ]] && { print_error "DKIM 不能为空"; return 1; }
        EMAIL_RESEND_ENABLED=1
        EMAIL_RESEND_SEND_DOMAIN="send.${EMAIL_DOMAIN}"
    fi

    echo ""
    print_info "配置确认:"
    echo "  域名:           $EMAIL_DOMAIN"
    echo "  API 地址:       https://$EMAIL_API_DOMAIN"
    echo "  前端地址:       https://$EMAIL_FRONTEND_DOMAIN"
    echo "  邮箱格式:       ${EMAIL_ADDRESS_PREFIX:+${EMAIL_ADDRESS_PREFIX}.}xxx@${EMAIL_DOMAIN}"
    echo "  D1 数据库名:    $EMAIL_D1_NAME"
    echo "  管理员密码:     $([[ -n "$admin_pw" ]] && echo "(用户提供)" || echo "(自动生成 — 完成后查看)")"
    echo "  Resend:         $([[ $EMAIL_RESEND_ENABLED -eq 1 ]] && echo "已启用" || echo "未启用")"
    echo ""
    echo -e "${C_RED}========== ⚠ MX 记录将被替换 — 请仔细阅读 ==========${C_RESET}"
    echo -e "${C_YELLOW}本部署会清空 ${C_RESET}${C_RED}${EMAIL_DOMAIN}${C_RESET}${C_YELLOW} 根域现有的所有 MX 记录，并写入 3 条 Cloudflare Email Routing：${C_RESET}"
    echo -e "${C_GRAY}    • route1.mx.cloudflare.net  (priority 12)${C_RESET}"
    echo -e "${C_GRAY}    • route2.mx.cloudflare.net  (priority 41)${C_RESET}"
    echo -e "${C_GRAY}    • route3.mx.cloudflare.net  (priority 69)${C_RESET}"
    echo -e "${C_RED}如该域名已有：Google Workspace / Microsoft 365 / Zoho / 自建邮件服务器 / 任何企业邮箱，${C_RESET}"
    echo -e "${C_RED}部署后这些服务将立即停止收信！${C_RESET}"
    echo -e "${C_GREEN}推荐做法：使用一个未托管邮件的专用域名作为 EMAIL_DOMAIN${C_RESET}"
    echo -e "${C_GREEN}（例如新购的 .top/.xyz 等便宜域名，从未配置过 MX）。${C_RESET}"
    echo -e "${C_GRAY}如需用子域名（如 ${C_RESET}${C_CYAN}tmp.${EMAIL_DOMAIN}${C_RESET}${C_GRAY}），${C_RESET}"
    echo -e "${C_GRAY}必须先在 Cloudflare 控制台把该子域名独立托管/委派为新 Zone（与主域 Zone 分离），${C_RESET}"
    echo -e "${C_GRAY}否则部署会在 \"获取 Zone ID\" 阶段失败 — CF Email Routing 要求收信域名必须是独立 Zone。${C_RESET}"
    echo -e "${C_RED}======================================================${C_RESET}"
    echo ""
    confirm "确认以上配置开始部署?" || return 1
    # 二次确认 MX 替换 — 防止用户在第一道 confirm 时未仔细看警告
    if ! confirm "$(echo -e "${C_RED}再次确认：${EMAIL_DOMAIN} 没有正在使用的企业邮箱或其他 MX 服务，可以清空现有 MX?${C_RESET}")"; then
        print_warn "已取消部署 — 强烈建议改用专用域名（或已独立托管为 Zone 的子域名）后重试"
        return 1
    fi
}

# ── 2b. Worker 名字决策（需要 Token 已验证）──
_email_deploy_pick_worker_name() {
    local default_name="cloudflare_temp_email"
    if ! _email_cf_worker_exists "$default_name"; then
        EMAIL_WORKER_NAME="$default_name"
        print_success "Worker 名: $EMAIL_WORKER_NAME"
        return 0
    fi
    print_warn "账户已存在名为 ${default_name} 的 Worker"
    echo "  1. 取消部署"
    echo "  2. 使用自定义 Worker 名"
    echo "  3. 覆盖现有 Worker (危险：会破坏当前同名 Worker 的部署!)"
    local ans new_name
    while true; do
        read -e -r -p "选择 [1]: " ans
        case "${ans:-1}" in
            1)
                print_warn "已取消部署"
                return 1
                ;;
            2)
                read -e -r -p "新 Worker 名 (3-63 字符, 仅 a-z 0-9 - _): " new_name
                if [[ ! "$new_name" =~ ^[a-z][a-z0-9_-]{2,62}$ ]]; then
                    print_error "名字格式无效（需以小写字母开头）"
                    continue
                fi
                if _email_cf_worker_exists "$new_name"; then
                    print_error "$new_name 也已存在，请换一个"
                    continue
                fi
                EMAIL_WORKER_NAME="$new_name"
                print_success "Worker 名: $EMAIL_WORKER_NAME"
                return 0
                ;;
            3)
                confirm "确认覆盖现有 ${default_name}? 此操作不可逆" || continue
                EMAIL_WORKER_NAME="$default_name"
                print_warn "将覆盖现有 Worker: $EMAIL_WORKER_NAME"
                return 0
                ;;
            *) print_error "无效选项" ;;
        esac
    done
}

# ── 3. clone 项目 ──
_email_deploy_clone_project() {
    if [[ -d "$EMAIL_INSTALL_DIR/.git" ]]; then
        email_run "更新仓库" git -C "$EMAIL_INSTALL_DIR" fetch --tags --prune || return 1
    else
        rm -rf "$EMAIL_INSTALL_DIR"
        email_run "克隆 cloudflare_temp_email" git clone --quiet \
            https://github.com/dreamhunter2333/cloudflare_temp_email.git "$EMAIL_INSTALL_DIR" || return 1
    fi
    local latest_tag
    latest_tag=$(git -C "$EMAIL_INSTALL_DIR" describe --tags "$(git -C "$EMAIL_INSTALL_DIR" rev-list --tags --max-count=1)" 2>/dev/null || echo "")
    if [[ -z "$latest_tag" ]]; then
        print_error "未能解析 git tag，仓库可能异常"
        return 1
    fi
    email_run "切换到最新 tag $latest_tag" git -C "$EMAIL_INSTALL_DIR" checkout --quiet "$latest_tag" || return 1
    EMAIL_INSTALL_VERSION="$latest_tag"
    print_success "项目版本: $latest_tag"
}

# ── 4. D1 数据库 ──
_email_deploy_setup_d1() {
    cd "$EMAIL_INSTALL_DIR/worker" || return 1

    local out
    print_info "创建 D1 数据库 $EMAIL_D1_NAME..."
    if ! out=$(wrangler d1 create "$EMAIL_D1_NAME" 2>&1); then
        email_log "wrangler d1 create failed: $out"
        print_error "D1 创建失败"; tail -n 10 "$EMAIL_LOG_FILE" | sed 's/^/  /'
        return 1
    fi
    echo "$out" >> "$EMAIL_LOG_FILE"
    EMAIL_D1_ID=$(echo "$out" | grep -oE 'database_id\s*=\s*"[^"]+"' | head -1 | grep -oE '"[^"]+"' | tr -d '"')
    [[ -n "$EMAIL_D1_ID" ]] || { print_error "解析 D1 ID 失败"; return 1; }
    print_success "D1 ID: $EMAIL_D1_ID"

    # 立刻写一份临时 state 以便失败时能回收
    email_state_write

    # 渲染最小 wrangler.toml 以便 d1 execute 找到 binding
    _email_render_min_toml || return 1

    # 按字母序应用所有 migration: schema.sql 优先，然后 *-patch.sql
    local patches=("../db/schema.sql")
    local p
    while IFS= read -r p; do
        patches+=("$p")
    done < <(ls "$EMAIL_INSTALL_DIR/db"/*-patch.sql 2>/dev/null | sort)

    for p in "${patches[@]}"; do
        [[ -f "$p" ]] || continue
        local base
        base=$(basename "$p")
        email_run "应用 D1 schema: $base" \
            wrangler d1 execute "$EMAIL_D1_NAME" --file="$p" --remote || return 1
        EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED} ${base}"
    done
    EMAIL_PATCHES_APPLIED="${EMAIL_PATCHES_APPLIED# }"
}

# 仅含 D1 binding 的最小 toml（供 d1 execute 使用）
_email_render_min_toml() {
    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<EOF
name = "${EMAIL_WORKER_NAME}"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]

[[d1_databases]]
binding = "DB"
database_name = "${EMAIL_D1_NAME}"
database_id = "${EMAIL_D1_ID}"
EOF
}

# ── 5. 完整 wrangler.toml ──
_email_deploy_render_toml() {
    local domains_json prefix_val
    domains_json="[\"${EMAIL_DOMAIN}\"]"
    # 上游 Worker 直接把 PREFIX 拼到 local-part 前面（无分隔符）。
    # 为得到用户在确认页看到的 "prefix.xxx@domain" 形态，写入 wrangler.toml 时自动补 "."
    # 末尾。用户已带 "." 时不重复。
    if [[ -n "$EMAIL_ADDRESS_PREFIX" ]]; then
        if [[ "${EMAIL_ADDRESS_PREFIX: -1}" == "." ]]; then
            prefix_val="$EMAIL_ADDRESS_PREFIX"
        else
            prefix_val="${EMAIL_ADDRESS_PREFIX}."
        fi
    else
        prefix_val=""
    fi

    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<EOF
name = "${EMAIL_WORKER_NAME}"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]
keep_vars = true

routes = [
    { pattern = "${EMAIL_API_DOMAIN}", custom_domain = true },
]

# 注意：Cloudflare Send Email binding（[[send_email]]）要求 Email Routing 已启用 + 发件地址
# 已在 Dashboard 完成验证，否则首次 wrangler deploy 会失败。本脚本默认不启用此 binding，
# 与上游 wrangler.toml.template 保持一致；Resend 用户走 RESEND_TOKEN secret，无需 send_email。
# 如确需使用 Cloudflare 原生 SEND_MAIL，请手动在 Dashboard 完成地址验证后取消下列注释并重新部署。
#send_email = [
#    { name = "SEND_MAIL" },
#]

[triggers]
crons = [ "0 0 * * *" ]

[vars]
PREFIX = "${prefix_val}"
DEFAULT_DOMAINS = ${domains_json}
DOMAINS = ${domains_json}
JWT_SECRET = "${EMAIL_JWT_SECRET}"
BLACK_LIST = ""
ENABLE_USER_CREATE_EMAIL = true
ENABLE_USER_DELETE_EMAIL = true
ENABLE_AUTO_REPLY = false

[[d1_databases]]
binding = "DB"
database_name = "${EMAIL_D1_NAME}"
database_id = "${EMAIL_D1_ID}"
EOF
    chmod 600 "$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    print_success "wrangler.toml 已生成"
}

# ── 6. 部署 Worker ──
_email_deploy_worker() {
    cd "$EMAIL_INSTALL_DIR/worker" || return 1
    email_run "安装 Worker 依赖" npm install --no-audit --no-fund || return 1
    email_run "部署 Worker (${EMAIL_API_DOMAIN})" npx wrangler deploy || return 1
}

# ── 7. 写 secrets：ADMIN_PASSWORDS + Resend Token（走 API 不走 wrangler）──
_email_deploy_secrets() {
    # ADMIN_PASSWORDS 走 secret — 值为 JSON 数组字面量 ["pw"]，上游 Worker 端 JSON.parse 后得数组
    # 不要再 | tostring，否则 secret 变成字符串字面量 "[\"pw\"]"，JSON.parse 得字符串而不是数组
    local admin_json
    admin_json=$(jq -nc --arg p "$EMAIL_ADMIN_PASSWORD" '[$p]')
    if ! _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "ADMIN_PASSWORDS" "$admin_json"; then
        print_error "ADMIN_PASSWORDS secret 写入失败"
        return 1
    fi
    print_success "ADMIN_PASSWORDS 已通过 secret 配置"
    email_save_admin_password "$EMAIL_ADMIN_PASSWORD"

    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        if _email_cf_worker_secret_put "$EMAIL_WORKER_NAME" "RESEND_TOKEN" "$EMAIL_RESEND_TOKEN"; then
            print_success "RESEND_TOKEN 已通过 secret 配置"
        else
            print_warn "RESEND_TOKEN 配置失败 — 可稍后通过管理菜单重试"
        fi
    fi
}

# ── 8. 构建前端 ──
_email_deploy_frontend() {
    cd "$EMAIL_INSTALL_DIR/frontend" || return 1
    email_run "安装前端依赖" pnpm install --no-frozen-lockfile || return 1
    export VITE_API_BASE="https://${EMAIL_API_DOMAIN}"
    email_run "构建前端 (VITE_API_BASE=${VITE_API_BASE})" pnpm build:pages || return 1
}

# ── 9. 部署 Pages 前端 ──
_email_deploy_pages() {
    cd "$EMAIL_INSTALL_DIR/pages" || return 1

    # 同步 pages/wrangler.toml service binding（升级/重部署链路同样调用此 helper，避免遗漏）
    _email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" \
        && print_success "Pages service binding 已确认: ${EMAIL_WORKER_NAME}" \
        || print_warn "pages/wrangler.toml service 未同步（文件可能缺失，请手工检查）"

    email_run "安装 Pages 依赖" pnpm install --no-frozen-lockfile || return 1

    # 创建项目（已存在则忽略）
    if ! _email_cf_pages_project_create "$EMAIL_PAGES_PROJECT" 2>/dev/null; then
        email_log "Pages project create returned non-zero — 可能已存在，继续"
    fi

    email_run "部署 Pages (${EMAIL_PAGES_PROJECT})" \
        npx wrangler pages deploy --project-name "$EMAIL_PAGES_PROJECT" \
            --branch production --commit-dirty=true || return 1

    EMAIL_PAGES_DOMAIN=$(_email_cf_pages_get_subdomain "$EMAIL_PAGES_PROJECT" 2>/dev/null)
    [[ -n "$EMAIL_PAGES_DOMAIN" ]] || EMAIL_PAGES_DOMAIN="${EMAIL_PAGES_PROJECT}.pages.dev"
    print_success "Pages 部署完成: $EMAIL_PAGES_DOMAIN"

    # 绑定自定义域名
    if _email_cf_pages_attach_domain "$EMAIL_PAGES_PROJECT" "$EMAIL_FRONTEND_DOMAIN" 2>/dev/null; then
        print_success "Pages 自定义域名: $EMAIL_FRONTEND_DOMAIN"
    else
        print_warn "自定义域名绑定失败（可能已绑定或域名未配置）"
    fi
}

# ── 10. DNS 记录 ──
# 收信关键记录（Frontend CNAME / MX）失败时 return 1，由 email_deploy 阻断完成标记；
# Resend 相关（DKIM/SPF/DMARC）仅 warn，因为发件是可选能力
_email_deploy_dns() {
    print_info "添加 DNS 记录..."
    local zid="$EMAIL_ZONE_ID"
    local _dns_fail=0

    # 前端 CNAME（橙云代理）— 若同名记录已存在，先清理
    _email_cf_dns_purge "$zid" CNAME "$EMAIL_FRONTEND_DOMAIN"
    if _email_cf_dns_create_record_into EMAIL_DNS_FRONTEND_ID "$zid" "CNAME" \
            "$EMAIL_FRONTEND_DOMAIN" "$EMAIL_PAGES_DOMAIN" "" "true"; then
        print_success "CNAME $EMAIL_FRONTEND_PREFIX → $EMAIL_PAGES_DOMAIN"
    else
        print_error "前端 CNAME 添加失败 — 用户将无法通过 ${EMAIL_FRONTEND_DOMAIN} 访问 UI"
        _dns_fail=1
    fi

    # MX 记录到 Cloudflare Email Routing（3 条任一缺失会降级路由，全失败则无法收信）
    _email_cf_dns_purge "$zid" MX "$EMAIL_DOMAIN"
    local _mx_ok=0
    if _email_cf_dns_create_record_into EMAIL_DNS_MX1_ID "$zid" "MX" "$EMAIL_DOMAIN" "route1.mx.cloudflare.net" "12"; then
        print_success "MX 1 (route1)"; _mx_ok=$((_mx_ok+1))
    else
        print_warn "MX 1 失败"
    fi
    if _email_cf_dns_create_record_into EMAIL_DNS_MX2_ID "$zid" "MX" "$EMAIL_DOMAIN" "route2.mx.cloudflare.net" "41"; then
        print_success "MX 2 (route2)"; _mx_ok=$((_mx_ok+1))
    else
        print_warn "MX 2 失败"
    fi
    if _email_cf_dns_create_record_into EMAIL_DNS_MX3_ID "$zid" "MX" "$EMAIL_DOMAIN" "route3.mx.cloudflare.net" "69"; then
        print_success "MX 3 (route3)"; _mx_ok=$((_mx_ok+1))
    else
        print_warn "MX 3 失败"
    fi
    if [[ "$_mx_ok" -eq 0 ]]; then
        print_error "MX 记录全部添加失败 — 邮箱将无法收信"
        _dns_fail=1
    elif [[ "$_mx_ok" -lt 3 ]]; then
        print_warn "MX 记录仅创建 ${_mx_ok}/3 — Cloudflare 推荐 3 条，建议 Dashboard 补齐"
    fi

    # Resend 相关（DKIM/SPF/SEND_MX/DMARC）仅 warn — 不影响收信主链路
    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        local send_sub="send.${EMAIL_DOMAIN}"
        _email_cf_dns_purge "$zid" TXT "resend._domainkey.${EMAIL_DOMAIN}"
        _email_cf_dns_purge "$zid" TXT "$send_sub"
        _email_cf_dns_purge "$zid" MX  "$send_sub"
        _email_cf_dns_purge "$zid" TXT "_dmarc.${EMAIL_DOMAIN}"

        _email_cf_dns_create_record_into EMAIL_DNS_DKIM_ID "$zid" "TXT" "resend._domainkey.${EMAIL_DOMAIN}" "$EMAIL_RESEND_DKIM" \
            && print_success "DKIM (resend._domainkey)" || print_warn "DKIM 失败（发件能力受影响，可后续 Dashboard 补）"
        _email_cf_dns_create_record_into EMAIL_DNS_SPF_ID "$zid" "TXT" "$send_sub" "v=spf1 include:amazonses.com ~all" \
            && print_success "SPF (send.${EMAIL_DOMAIN})" || print_warn "SPF 失败（发件能力受影响）"
        _email_cf_dns_create_record_into EMAIL_DNS_SEND_MX_ID "$zid" "MX" "$send_sub" "feedback-smtp.us-east-1.amazonses.com" "10" \
            && print_success "Send MX" || print_warn "Send MX 失败（发件能力受影响）"
        _email_cf_dns_create_record_into EMAIL_DNS_DMARC_ID "$zid" "TXT" "_dmarc.${EMAIL_DOMAIN}" "v=DMARC1; p=none;" \
            && print_success "DMARC" || print_warn "DMARC 失败（发件能力受影响）"
    fi

    # 失败也落盘 record_id（已创建的部分仍可被卸载回收），主流程根据 return 决定是否标 installed
    email_state_write
    return $_dns_fail
}

# ── 11. Email Routing catch-all → Worker ──
# routing enable 或 catch-all 任一失败 → return 1，主流程不会标 installed
_email_deploy_email_routing() {
    if ! email_run "启用 Cloudflare Email Routing" _email_cf_email_routing_enable "$EMAIL_ZONE_ID"; then
        print_error "Email Routing 启用失败 — 临时邮箱无法收信"
        print_info "请登录 Dashboard → Email → Email Routing 手动启用后，进 partial 菜单【强制卸载】+【重新部署】"
        email_state_write
        return 1
    fi
    if ! email_run "配置 Catch-all → Worker(${EMAIL_WORKER_NAME})" _email_cf_catch_all_to_worker "$EMAIL_ZONE_ID" "$EMAIL_WORKER_NAME"; then
        print_error "Catch-all 自动配置失败 — 邮件不会路由到 Worker（收信不入库）"
        print_info "Dashboard → Email Routing → Catch-all → 手动指向 Worker(${EMAIL_WORKER_NAME})"
        email_state_write
        return 1
    fi
    EMAIL_CATCH_ALL_ENABLED=1
    email_state_write
    return 0
}

# ── 12. 健康检查 ──
_email_deploy_postcheck() {
    print_info "等待部署生效 (10s)..."
    sleep 10
    local resp
    resp=$(curl -sS --max-time 10 "https://${EMAIL_API_DOMAIN}/health_check" 2>/dev/null)
    if [[ "$resp" == "OK" ]]; then
        print_success "Worker 后端健康检查通过"
    else
        print_warn "Worker 暂未响应 — DNS/边缘可能需要数分钟生效"
    fi
}

# ── 13. 汇总 ──
_email_deploy_summary() {
    echo ""
    echo -e "${C_GREEN}========== 部署完成 ==========${C_RESET}"
    echo -e "  前端地址:    ${C_CYAN}https://${EMAIL_FRONTEND_DOMAIN}${C_RESET}"
    echo -e "  API 地址:    ${C_CYAN}https://${EMAIL_API_DOMAIN}${C_RESET}"
    echo -e "  管理面板:    ${C_CYAN}https://${EMAIL_FRONTEND_DOMAIN}/admin${C_RESET}"
    echo -e "  管理员密码:  ${C_YELLOW}${EMAIL_ADMIN_PASSWORD}${C_RESET}"
    echo -e "  密码已保存:  ${C_GRAY}${EMAIL_ADMIN_FILE} (mode 600)${C_RESET}"
    echo -e "  状态文件:    ${C_GRAY}${EMAIL_STATE_FILE}${C_RESET}"
    echo -e "  部署日志:    ${C_GRAY}${EMAIL_LOG_FILE}${C_RESET}"
    echo ""
    if [[ "$EMAIL_RESEND_ENABLED" == "1" ]]; then
        echo -e "${C_YELLOW}Resend 后续:${C_RESET} 访问 https://resend.com/domains 触发验证"
        echo ""
    fi

    # 防止敏感变量残留
    unset CF_API_TOKEN EMAIL_RESEND_TOKEN EMAIL_RESEND_DKIM EMAIL_JWT_SECRET EMAIL_ADMIN_PASSWORD
}
