# modules/14-email.sh - Cloudflare 临时邮箱部署
# 项目: https://github.com/dreamhunter2333/cloudflare_temp_email

EMAIL_INSTALL_DIR="/root/cloudflare_temp_email"

email_status() {
    print_title "临时邮箱部署状态"
    if [[ ! -d "$EMAIL_INSTALL_DIR" ]]; then
        print_warn "未检测到安装目录 ($EMAIL_INSTALL_DIR)"
        pause; return
    fi
    print_success "安装目录: $EMAIL_INSTALL_DIR"
    local ver
    ver=$(cd "$EMAIL_INSTALL_DIR" && git describe --tags 2>/dev/null || echo "未知")
    echo -e "  版本: ${C_CYAN}$ver${C_RESET}"

    if [[ -f "$EMAIL_INSTALL_DIR/worker/wrangler.toml" ]]; then
        local api_domain
        api_domain=$(grep -oP 'pattern\s*=\s*"\K[^"]+' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null | head -1)
        if [[ -n "$api_domain" ]]; then
            echo -e "  API 域名: ${C_CYAN}$api_domain${C_RESET}"
            echo ""
            print_info "检测 Worker 健康状态..."
            local health
            health=$(curl -s --connect-timeout 10 "https://$api_domain/health_check" 2>&1)
            if [[ "$health" == "OK" ]]; then
                print_success "Worker 后端运行正常"
            else
                print_warn "Worker 未响应 (可能 DNS 未生效或未部署)"
            fi
        fi
    else
        print_warn "未找到 wrangler.toml 配置"
    fi
    pause
}

email_deploy() {
    print_title "Cloudflare Temp Email 一键部署"
    echo -e "${C_CYAN}项目: https://github.com/dreamhunter2333/cloudflare_temp_email${C_RESET}"
    echo ""

    # --- 交互式输入 ---
    read -e -r -p "Cloudflare API Token: " cf_api_token
    [[ -z "$cf_api_token" ]] && { print_error "API Token 不能为空"; pause; return; }
    read -e -r -p "Cloudflare Account ID (留空自动获取): " cf_account_id
    if [[ -z "$cf_account_id" ]]; then
        print_info "正在自动获取 Account ID..."
        cf_account_id=$(curl -s "https://api.cloudflare.com/client/v4/accounts?page=1&per_page=1" \
            -H "Authorization: Bearer $cf_api_token" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'][0]['id'])" 2>/dev/null)
        if [[ -z "$cf_account_id" ]]; then
            print_error "自动获取 Account ID 失败，请手动输入"; pause; return
        fi
        print_success "Account ID: $cf_account_id"
    fi

    read -e -r -p "域名 (如 example.com): " domain
    [[ -z "$domain" ]] && { print_error "域名不能为空"; pause; return; }

    read -e -r -p "API 子域名前缀 [mail-api]: " api_prefix
    api_prefix=${api_prefix:-mail-api}

    read -e -r -p "前端子域名前缀 [mail]: " frontend_prefix
    frontend_prefix=${frontend_prefix:-mail}

    read -e -r -p "邮箱地址前缀 [留空无前缀]: " email_prefix

    read -e -r -p "管理员密码 [留空自动生成]: " admin_password
    if [[ -z "$admin_password" ]]; then
        admin_password=$(openssl rand -hex 16)
        print_success "已生成管理员密码: $admin_password"
    fi

    read -e -r -p "Resend API Token [留空跳过发送功能]: " resend_token
    local resend_dkim=""
    if [[ -n "$resend_token" ]]; then
        read -e -r -p "Resend DKIM 值 (p=MIGfMA0...): " resend_dkim
        [[ -z "$resend_dkim" ]] && { print_error "配置 Resend 时 DKIM 值不能为空"; pause; return; }
    fi

    local api_domain="${api_prefix}.${domain}"
    local frontend_domain="${frontend_prefix}.${domain}"
    local jwt_secret
    jwt_secret=$(openssl rand -hex 32)

    echo ""
    print_info "配置确认:"
    echo "  域名:         $domain"
    echo "  API 地址:     https://$api_domain"
    echo "  前端地址:     https://$frontend_domain"
    echo "  邮箱格式:     ${email_prefix:+${email_prefix}.}xxx@$domain"
    echo "  管理员密码:   $admin_password"
    echo "  Resend:       ${resend_token:+已配置}${resend_token:-未配置}"
    echo ""
    if ! confirm "确认以上配置开始部署?"; then pause; return; fi

    # --- 环境检查 ---
    export CLOUDFLARE_API_TOKEN="$cf_api_token"
    export CLOUDFLARE_ACCOUNT_ID="$cf_account_id"

    print_info "检查运行环境..."
    if ! command -v git &>/dev/null; then
        print_info "安装 git..."
        apt-get update -qq && apt-get install -y -qq git || { print_error "git 安装失败"; pause; return; }
    fi
    if ! command -v node &>/dev/null; then
        print_info "安装 Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y -qq nodejs || { print_error "Node.js 安装失败"; pause; return; }
    fi
    if ! command -v pnpm &>/dev/null; then
        print_info "安装 pnpm..."
        npm install -g pnpm || { print_error "pnpm 安装失败"; pause; return; }
    fi
    if ! command -v wrangler &>/dev/null; then
        print_info "安装 wrangler..."
        npm install -g wrangler || { print_error "wrangler 安装失败"; pause; return; }
    fi
    print_success "环境检查通过"

    # --- 获取 Zone ID ---
    print_info "获取域名 Zone ID..."
    local zone_id
    zone_id=$(curl -s "https://api.cloudflare.com/client/v4/zones?name=$domain" \
        -H "Authorization: Bearer $cf_api_token" | python3 -c "import sys,json; r=json.load(sys.stdin)['result']; print(r[0]['id'] if r else '')" 2>/dev/null)
    [[ -z "$zone_id" ]] && { print_error "获取 Zone ID 失败，请确认域名已托管到 Cloudflare"; pause; return; }
    print_success "Zone ID: $zone_id"

    # --- 克隆项目 ---
    if [[ -d "$EMAIL_INSTALL_DIR" ]]; then
        print_warn "目录 $EMAIL_INSTALL_DIR 已存在，跳过克隆"
        cd "$EMAIL_INSTALL_DIR"
        git fetch --tags
    else
        print_info "克隆项目..."
        git clone https://github.com/dreamhunter2333/cloudflare_temp_email.git "$EMAIL_INSTALL_DIR" || { print_error "克隆失败"; pause; return; }
        cd "$EMAIL_INSTALL_DIR"
    fi
    local latest_tag
    latest_tag=$(git describe --tags "$(git rev-list --tags --max-count=1)")
    print_info "切换到最新版本 $latest_tag..."
    git checkout "$latest_tag" 2>/dev/null
    print_success "项目版本: $latest_tag"

    # --- 创建 D1 数据库 ---
    print_info "创建 D1 数据库..."
    local d1_output d1_id
    d1_output=$(wrangler d1 create dev 2>&1) || { print_error "创建 D1 数据库失败: $d1_output"; pause; return; }
    d1_id=$(echo "$d1_output" | grep -oP 'database_id\s*=\s*"\K[^"]+')
    [[ -z "$d1_id" ]] && { print_error "无法解析 D1 数据库 ID"; pause; return; }
    print_success "D1 数据库 ID: $d1_id"

    # --- 生成 wrangler.toml ---
    print_info "生成 Worker 配置文件..."
    cd "$EMAIL_INSTALL_DIR/worker"
    cat > wrangler.toml << TOML_EOF
name = "cloudflare_temp_email"
main = "src/worker.ts"
compatibility_date = "2025-04-01"
compatibility_flags = [ "nodejs_compat" ]
keep_vars = true

routes = [
	{ pattern = "$api_domain", custom_domain = true },
]

send_email = [
   { name = "SEND_MAIL" },
]

[triggers]
crons = [ "0 0 * * *" ]

[vars]
PREFIX = "$email_prefix"
DEFAULT_DOMAINS = ["$domain"]
DOMAINS = ["$domain"]
JWT_SECRET = "$jwt_secret"
ADMIN_PASSWORDS = ["$admin_password"]
BLACK_LIST = ""
ENABLE_USER_CREATE_EMAIL = true
ENABLE_USER_DELETE_EMAIL = true
ENABLE_AUTO_REPLY = false

[[d1_databases]]
binding = "DB"
database_name = "dev"
database_id = "$d1_id"
TOML_EOF
    print_success "wrangler.toml 已生成"

    print_info "初始化数据库..."
    wrangler d1 execute dev --file=../db/schema.sql --remote || { print_error "数据库初始化失败"; pause; return; }
    print_success "数据库初始化完成"

    # --- 部署 Worker 后端 ---
    print_info "安装 Worker 依赖..."
    npm install --silent 2>&1 | tail -1
    print_info "部署 Worker 后端..."
    npx wrangler deploy 2>&1 || { print_error "Worker 部署失败"; pause; return; }
    print_success "Worker 后端已部署到 $api_domain"

    if [[ -n "$resend_token" ]]; then
        print_info "配置 Resend Token..."
        echo "$resend_token" | wrangler secret put RESEND_TOKEN 2>&1 || print_warn "Resend Token 配置失败"
    fi

    # --- 部署 Pages 前端 ---
    print_info "安装前端依赖..."
    cd "$EMAIL_INSTALL_DIR/frontend"
    pnpm install --no-frozen-lockfile --silent 2>&1 | tail -1
    print_info "构建前端..."
    pnpm build:pages 2>&1 | tail -3

    print_info "创建 Pages 项目..."
    wrangler pages project create temp-email-pages --production-branch production 2>&1 || print_warn "Pages 项目可能已存在"

    print_info "部署 Pages 前端..."
    cd "$EMAIL_INSTALL_DIR/pages"
    pnpm install --no-frozen-lockfile --silent 2>&1 | tail -1
    wrangler pages deploy --branch production --commit-dirty=true 2>&1 || { print_error "Pages 部署失败"; pause; return; }
    print_success "Pages 前端已部署"

    # --- DNS 记录 ---
    print_info "添加 DNS 记录..."
    _email_add_dns() {
        local type=$1 name=$2 content=$3 priority=$4 proxied=$5
        local data="{\"type\":\"$type\",\"name\":\"$name\",\"content\":\"$content\""
        [[ -n "$priority" ]] && data="$data,\"priority\":$priority"
        [[ "$proxied" == "true" ]] && data="$data,\"proxied\":true"
        data="$data}"
        local result
        result=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
            -H "Authorization: Bearer $cf_api_token" \
            -H "Content-Type: application/json" \
            -d "$data")
        if echo "$result" | python3 -c "import sys,json; sys.exit(0 if json.load(sys.stdin)['success'] else 1)" 2>/dev/null; then
            print_success "DNS: $type $name"
        else
            print_warn "DNS 记录添加失败或已存在: $type $name"
        fi
    }

    local pages_domain
    pages_domain=$(wrangler pages project list 2>&1 | grep temp-email-pages | awk '{print $2}')
    [[ -z "$pages_domain" ]] && pages_domain="temp-email-pages.pages.dev"
    _email_add_dns "CNAME" "$frontend_prefix" "$pages_domain" "" "true"
    _email_add_dns "MX" "$domain" "route1.mx.cloudflare.net" 12
    _email_add_dns "MX" "$domain" "route2.mx.cloudflare.net" 41
    _email_add_dns "MX" "$domain" "route3.mx.cloudflare.net" 69

    if [[ -n "$resend_token" ]]; then
        print_info "添加 Resend DNS 记录..."
        _email_add_dns "TXT" "resend._domainkey" "$resend_dkim"
        _email_add_dns "TXT" "send" "v=spf1 include:amazonses.com ~all"
        _email_add_dns "MX" "send" "feedback-smtp.us-east-1.amazonses.com" 10
        _email_add_dns "TXT" "_dmarc" "v=DMARC1; p=none;"
    fi

    # --- 绑定自定义域名 ---
    print_info "绑定前端自定义域名 $frontend_domain..."
    curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$cf_account_id/pages/projects/temp-email-pages/domains" \
        -H "Authorization: Bearer $cf_api_token" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"$frontend_domain\"}" | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d['success'] else d['errors'])" 2>/dev/null

    # --- 验证 ---
    print_info "等待部署生效 (10秒)..."
    sleep 10
    local health
    health=$(curl -s --connect-timeout 10 "https://$api_domain/health_check" 2>&1)
    if [[ "$health" == "OK" ]]; then
        print_success "Worker 后端运行正常"
    else
        print_warn "Worker 暂未响应，可能需要等待 DNS 生效"
    fi

    # --- 部署汇总 ---
    echo ""
    echo -e "${C_GREEN}========== 部署完成 ==========${C_RESET}"
    echo -e "  前端地址:     ${C_CYAN}https://$frontend_domain${C_RESET}"
    echo -e "  API 地址:     ${C_CYAN}https://$api_domain${C_RESET}"
    echo -e "  管理面板:     ${C_CYAN}https://$frontend_domain/admin${C_RESET}"
    echo -e "  管理员密码:   ${C_YELLOW}$admin_password${C_RESET}"
    echo -e "  邮箱格式:     ${C_CYAN}${email_prefix:+${email_prefix}.}xxx@$domain${C_RESET}"
    echo ""
    echo -e "${C_YELLOW}还需手动完成:${C_RESET}"
    echo "  1. 登录 Cloudflare → 域名 $domain → Email > Email Routing"
    echo "     Catch-all → Action = Send to a Worker → cloudflare_temp_email"
    if [[ -n "$resend_token" ]]; then
        echo "  2. 访问 https://resend.com/domains 验证 DNS"
    fi
    echo ""
    log_action "Cloudflare Temp Email deployed: $frontend_domain / $api_domain"
    pause
}

email_uninstall() {
    print_title "卸载临时邮箱"
    if [[ ! -d "$EMAIL_INSTALL_DIR" ]]; then
        print_warn "未检测到安装目录 ($EMAIL_INSTALL_DIR)"
        pause; return
    fi
    print_warn "本操作将删除本地安装目录: $EMAIL_INSTALL_DIR"
    print_warn "Cloudflare 上的 Worker/Pages/D1/DNS 需要手动清理"
    echo ""
    if ! confirm "确认卸载?"; then pause; return; fi
    rm -rf "$EMAIL_INSTALL_DIR"
    print_success "本地目录已删除"
    echo ""
    echo -e "${C_YELLOW}请手动清理 Cloudflare 资源:${C_RESET}"
    echo "  1. Workers & Pages → 删除 cloudflare_temp_email 和 temp-email-pages"
    echo "  2. D1 → 删除 dev 数据库"
    echo "  3. DNS → 删除相关 MX/CNAME/TXT 记录"
    echo "  4. Email Routing → 关闭 Catch-all"
    log_action "Cloudflare Temp Email uninstalled (local dir removed)"
    pause
}

menu_email() {
    while true; do
        print_title "Cloudflare 临时邮箱"
        echo "1. 一键部署"
        echo "2. 查看部署状态"
        echo "3. 卸载"
        echo "0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) email_deploy ;;
            2) email_status ;;
            3) email_uninstall ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
