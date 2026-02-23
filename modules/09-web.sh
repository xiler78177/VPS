# modules/09-web.sh - Web服务管理（Certbot/Nginx/Cloudflare/SaaS/反代）
_web_dep_check_results=()

_web_dep_verify() {
    local name="$1" check_cmd="$2"
    if eval "$check_cmd" >/dev/null 2>&1; then
        _web_dep_check_results+=("${C_GREEN}✓${C_RESET} $name")
        return 0
    else
        _web_dep_check_results+=("${C_RED}✗${C_RESET} $name")
        return 1
    fi
}

_web_dep_fix() {
    local name="$1" check_cmd="$2" install_func="$3"
    if ! eval "$check_cmd" >/dev/null 2>&1; then
        print_info "修复: $name ..."
        if eval "$install_func"; then
            if eval "$check_cmd" >/dev/null 2>&1; then
                print_success "$name 修复成功"
                return 0
            fi
        fi
        print_error "$name 修复失败"
        return 1
    fi
    return 0
}

_purge_snap_certbot() {
    if snap list certbot &>/dev/null 2>&1; then
        print_info "检测到 snap 版 certbot，正在清理..."
        snap remove certbot 2>/dev/null || true
        snap remove certbot-dns-cloudflare 2>/dev/null || true
        rm -f /usr/bin/certbot /snap/bin/certbot 2>/dev/null || true
        if snap list 2>/dev/null | wc -l | grep -q "^1$"; then
            print_info "snap 中无其他软件包，清理 snapd..."
            systemctl stop snapd snapd.socket 2>/dev/null || true
            apt-get purge -y snapd 2>/dev/null || true
            rm -rf /snap /var/snap /var/lib/snapd ~/snap 2>/dev/null || true
            print_success "snapd 已清理"
        fi
        log_action "Purged snap certbot"
    fi
}

_install_certbot_apt() {
    _purge_snap_certbot
    update_apt_cache
    apt-get install -y certbot >/dev/null 2>&1
}

_install_certbot_snap() {
    install_package "snapd" "silent" || return 1
    snap install --classic certbot >/dev/null 2>&1 || return 1
    ln -sf /snap/bin/certbot /usr/bin/certbot
}

_install_certbot_dns_cf_apt() {
    _purge_snap_certbot
    update_apt_cache
    if ! dpkg -s certbot &>/dev/null; then
        apt-get install -y certbot >/dev/null 2>&1 || return 1
    fi
    apt-get install -y python3-certbot-dns-cloudflare >/dev/null 2>&1
}

_install_certbot_dns_cf_snap() {
    if ! command_exists snap; then
        install_package "snapd" "silent" || { print_error "snapd 安装失败"; return 1; }
        if is_systemd; then
            systemctl enable --now snapd.socket >/dev/null 2>&1 || true
            print_info "等待 snapd 初始化 (低配机器可能需要几分钟)..."
            local wait=0
            while [[ $wait -lt 120 ]]; do
                snap version &>/dev/null && break
                echo -ne "\r  已等待 ${wait}s..."
                sleep 3; wait=$((wait + 3))
            done
            if ! snap version &>/dev/null; then
                print_error "snapd 未就绪 (等待 ${wait}s 超时)"
                return 1
            fi
        fi
    fi
    snap install core 2>/dev/null || true
    snap refresh core 2>/dev/null || true
    print_info "snap 安装 certbot (可能需要几分钟，请耐心等待)..."
    if ! snap install --classic certbot 2>&1; then
        print_error "snap install certbot 失败"
        return 1
    fi
    ln -sf /snap/bin/certbot /usr/bin/certbot
    # 授权插件 root 权限（snap 强制要求）
    snap set certbot trust-plugin-with-root=ok 2>/dev/null || true
    print_info "snap 安装 certbot-dns-cloudflare..."
    if ! snap install certbot-dns-cloudflare 2>&1; then
        print_error "snap install certbot-dns-cloudflare 失败"
        return 1
    fi
    snap connect certbot:plugin certbot-dns-cloudflare >/dev/null 2>&1 || true
    print_success "snap 安装完成"
    return 0
}

_install_certbot_dns_cf() {
    # 先尝试 apt 安装
    _install_certbot_dns_cf_apt || true

    # 检查 apt 装的版本是否可用（版本号 >= 1.0）
    if _check_certbot_dns_cf; then
        return 0
    fi

    # apt 版本不可用（如 20.04 的 0.39），切换 snap
    print_warn "apt 版本不兼容，切换 snap 安装..."
    apt-get remove -y certbot python3-certbot-dns-cloudflare 2>/dev/null || true
    _install_certbot_dns_cf_snap
}

_install_nginx() {
    update_apt_cache
    apt-get install -y nginx >/dev/null 2>&1 || return 1
    is_systemd && systemctl enable --now nginx >/dev/null 2>&1 || true
}

_check_certbot_dns_cf() {
    command_exists certbot || return 1
    certbot plugins 2>/dev/null | grep -q dns-cloudflare || return 1
    # Ubuntu 20.04: certbot-dns-cloudflare 0.39 与 cloudflare 2.1 不兼容
    local cb_ver=$(certbot --version 2>&1 | grep -oP '[\d.]+')
    if [[ "${cb_ver%%.*}" == "0" ]]; then
        print_warn "certbot $cb_ver 版本过旧，不支持 API Token"
        return 1
    fi
    return 0
}

_check_nginx_dirs() {
    [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]
}

web_env_check() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        for pkg in jq curl openssl-util ca-bundle; do
            if ! opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
                opkg update >/dev/null 2>&1
                opkg install "$pkg" >/dev/null 2>&1 || true
            fi
        done
        if ! command_exists certbot; then
            print_warn "OpenWrt 上 certbot 可能不可用。"
            print_info "建议使用 opkg install acme acme-dnsapi 或手动安装 certbot。"
            if ! confirm "是否继续尝试？"; then
                return 1
            fi
        fi
        if ! command_exists nginx; then
            print_info "安装 nginx..."
            opkg update >/dev/null 2>&1
            opkg install nginx-ssl >/dev/null 2>&1 || opkg install nginx >/dev/null 2>&1 || {
                print_warn "nginx 安装失败，反代功能可能不可用"
            }
        fi
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets 2>/dev/null || true
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        return 0
    fi
    print_info "Web 环境依赖自检..."
    local deps=(
        "jq|command_exists jq|install_package jq silent"
        "nginx|command_exists nginx|_install_nginx"
        "nginx 目录结构|_check_nginx_dirs|mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets"
        "certbot|command_exists certbot|_install_certbot_apt || _install_certbot_snap"
        "certbot dns-cloudflare 插件|_check_certbot_dns_cf|_install_certbot_dns_cf"
    )

    # 第一轮: 检查
    _web_dep_check_results=()
    local need_fix=0
    for dep in "${deps[@]}"; do
        IFS='|' read -r name check_cmd install_func <<< "$dep"
        if ! _web_dep_verify "$name" "$check_cmd"; then
            need_fix=1
        fi
    done
    echo -e "${C_CYAN}依赖检查结果:${C_RESET}"
    for r in "${_web_dep_check_results[@]}"; do
        echo -e "  $r"
    done

    # 第二轮: 修复
    if [[ $need_fix -eq 1 ]]; then
        print_warn "检测到缺失依赖，正在自动修复..."
        local fix_failed=0
        for dep in "${deps[@]}"; do
            IFS='|' read -r name check_cmd install_func <<< "$dep"
            if ! _web_dep_fix "$name" "$check_cmd" "$install_func"; then
                fix_failed=1
            fi
        done

        # 第三轮: 最终验证
        if [[ $fix_failed -eq 1 ]]; then
            print_error "部分依赖修复失败，最终验证:"
            local final_ok=1
            for dep in "${deps[@]}"; do
                IFS='|' read -r name check_cmd install_func <<< "$dep"
                if eval "$check_cmd" >/dev/null 2>&1; then
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"
                else
                    echo -e "  ${C_RED}✗${C_RESET} $name"
                    final_ok=0
                fi
            done
            if [[ $final_ok -eq 0 ]]; then
                print_error "关键依赖缺失，无法继续。请手动修复后重试。"
                echo "手动修复参考:
  apt-get update
  apt-get install -y certbot python3-certbot-dns-cloudflare nginx jq
或使用 snap:
  snap install --classic certbot
  snap install certbot-dns-cloudflare
  snap connect certbot:plugin certbot-dns-cloudflare"
                return 1
            fi
        fi
        print_success "所有依赖已就绪"
    else
        print_success "所有依赖检查通过"
    fi
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    return 0
}

_cf_api() {
    # 基础速率保护：防止触发 CF API 1200 req/5min 限制
    sleep 0.3
    local method=$1 endpoint=$2 token=$3; shift 3
    curl -s -X "$method" "https://api.cloudflare.com/client/v4${endpoint}" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" "$@"
}

_cf_api_ok() { [[ "$(echo "$1" | jq -r '.success')" == "true" ]]; }
_cf_api_err() { echo "$1" | jq -r '.errors[0].message // "未知错误"'; }

_cf_get_zone_id() {
    local domain=$1 token=$2
    # 逐级尝试: gpt.xx.kg -> xx.kg -> kg
    local current="$domain"
    while [[ "$current" == *"."* ]]; do
        local resp=$(_cf_api GET "/zones?name=$current" "$token")
        if _cf_api_ok "$resp"; then
            local zid=$(echo "$resp" | jq -r '.result[0].id // empty')
            [[ -n "$zid" ]] && { echo "$zid"; return 0; }
        fi
        current="${current#*.}"
    done
    # Fallback: 列出所有 zone，本地匹配 (解决二级域名 zone 查找问题)
    local resp=$(_cf_api GET "/zones?per_page=50" "$token")
    if _cf_api_ok "$resp"; then
        local try="$domain"
        while [[ "$try" == *"."* ]]; do
            local zid=$(echo "$resp" | jq -r --arg d "$try" '.result[] | select(.name == $d) | .id' | head -1)
            [[ -n "$zid" ]] && { echo "$zid"; return 0; }
            try="${try#*.}"
        done
    fi
    return 1
}

_cf_dns_upsert() {
    local zone_id=$1 token=$2 type=$3 name=$4 content=$5 proxied=${6:-false}
    local resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    local data=$(jq -n --arg type "$type" --arg name "$name" --arg content "$content" --argjson proxied "$proxied" \
        '{type:$type, name:$name, content:$content, ttl:1, proxied:$proxied}')
    if [[ -n "$rid" ]]; then
        _cf_api PUT "/zones/$zone_id/dns_records/$rid" "$token" --data "$data"
    else
        _cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$data"
    fi
}

_cf_dns_delete() {
    local zone_id=$1 token=$2 type=$3 name=$4
    local resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$name" "$token")
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    [[ -n "$rid" ]] && _cf_api DELETE "/zones/$zone_id/dns_records/$rid" "$token"
}

web_cf_saas_setup() {
    print_title "Cloudflare SaaS 优选加速配置"
    echo -e "${C_RED}╔════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_RED}║                         ⚠ 重要提示                           ║${C_RESET}"
    echo -e "${C_RED}╠════════════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "${C_RED}║${C_RESET} 1. 此功能利用 CF SaaS (自定义主机名) 实现 CDN 优选加速      ${C_RED}║${C_RESET}"
    echo -e "${C_RED}║${C_RESET} 2. 可能违反 Cloudflare TOS，存在封号风险（目前罕见）        ${C_RED}║${C_RESET}"
    echo -e "${C_RED}║${C_RESET} 3. 需先在 CF 后台绑定信用卡/PayPal 开通 SaaS 功能           ${C_RED}║${C_RESET}"
    echo -e "${C_RED}║${C_RESET} 4. 仅支持子域名 (如 www.example.com)，不支持根域名          ${C_RED}║${C_RESET}"
    echo -e "${C_RED}╚════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo -e "${C_CYAN}┌─ 配置流程 ──────────────────────────────────────────────────┐${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤1: 输入 CF API Token + 域名信息                        ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤2: SSL/TLS 设为 Full 模式                               ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤3: 创建回源记录 origin.xxx → 服务器IP (开代理)          ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤4: 设置 SaaS 回退源 (Fallback Origin)                   ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤5: 添加自定义主机名 + TXT 验证                          ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 步骤6: 业务域名 CNAME → 优选域名 (关代理)                   ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET}                                                             ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}│${C_RESET} 完成后: 用户 → 优选IP → CF高速节点 → 源服务器               ${C_CYAN}│${C_RESET}"
    echo -e "${C_CYAN}└─────────────────────────────────────────────────────────────┘${C_RESET}"
    if ! confirm "已了解风险并准备开始？"; then return; fi

    # ── 步骤 1: 收集信息 ──
    echo -e "${C_CYAN}━━━ 步骤 1/6: 基础信息 ━━━${C_RESET}"
    local token="" root_domain="" biz_sub="" origin_sub="origin" zone_id="" server_ip=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL + Zone.Custom Hostnames${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 → My Profile → API Tokens → Create Token${C_RESET}"
    echo -e "  ${C_GRAY}建议用 'Edit zone DNS' 模板，额外添加 SSL 和 Custom Hostnames 权限${C_RESET}"
    while [[ -z "$token" ]]; do
        read -s -r -p "API Token: " token; echo ""
    done
    print_info "验证 Token..."
    local vr=$(_cf_api GET "/user/tokens/verify" "$token")
    if ! _cf_api_ok "$vr"; then
        print_error "Token 验证失败: $(_cf_api_err "$vr")"
        pause; return
    fi
    print_success "Token 有效"
    print_guide "输入根域名 (必须已托管在 Cloudflare)"
    echo -e "  ${C_GRAY}例如: example.com${C_RESET}"
    while [[ -z "$root_domain" ]]; do
        read -e -r -p "根域名: " root_domain
        validate_domain "$root_domain" || { print_error "格式无效"; root_domain=""; }
    done
    print_info "获取 Zone ID..."
    zone_id=$(_cf_get_zone_id "$root_domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 $root_domain 的 Zone，请确认已托管在 CF"
        pause; return
    fi
    print_success "Zone ID: $zone_id"
    print_guide "输入要加速的子域名前缀"
    echo -e "  ${C_GRAY}例如输入 www → 加速 www.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}例如输入 blog → 加速 blog.${root_domain}${C_RESET}"
    echo -e "  ${C_YELLOW}注意: 不支持根域名，仅支持子域名${C_RESET}"
    while [[ -z "$biz_sub" ]]; do
        read -e -r -p "子域名前缀: " biz_sub
        [[ -z "$biz_sub" ]] && print_warn "不能为空"
    done
    local biz_domain="${biz_sub}.${root_domain}"
    if [[ -f "${SAAS_CONFIG_DIR}/${biz_domain}.conf" ]]; then
        print_warn "${biz_domain} 已有 SaaS 配置"
        if ! confirm "覆盖现有配置？"; then pause; return; fi
    fi
    print_guide "回源子域名前缀 (CF 通过此域名回源到你的服务器)"
    echo -e "  ${C_GRAY}默认 origin → origin.${root_domain} 指向服务器IP并开启CF代理(小黄云)${C_RESET}"
    echo -e "  ${C_GRAY}此域名仅用于 CF 内部回源，用户不会直接访问${C_RESET}"
    read -e -r -p "回源前缀 [origin]: " origin_sub
    origin_sub=${origin_sub:-origin}
    local origin_domain="${origin_sub}.${root_domain}"
    echo ""
    print_guide "源服务器 IP (回源域名将指向此 IP)"
    local default_ip=$(get_public_ipv4)
    [[ -n "$default_ip" ]] && echo -e "  ${C_GRAY}检测到本机 IP: ${default_ip}${C_RESET}"
    read -e -r -p "服务器 IP [${default_ip:-}]: " server_ip
    server_ip=${server_ip:-$default_ip}
    if ! validate_ip "$server_ip"; then
        print_error "IP 格式无效"; pause; return
    fi

    # 选择优选域名
    echo -e "${C_CYAN}选择优选域名 (CNAME 目标，提供高速 CF 节点):${C_RESET}"
    echo -e "  ${C_GRAY}优选域名背后是经过筛选的对中国大陆友好的 CF 节点 IP${C_RESET}"
    echo -e "  ${C_GRAY}用户访问你的业务域名时，DNS 会 CNAME 到优选域名获取最快的节点${C_RESET}"
    local i=1 pd_arr=()
    for d in $SAAS_PREFERRED_DOMAINS; do
        pd_arr+=("$d")
        echo "  $i. $d"
        ((i++))
    done
    echo "  $i. 自定义输入"
    local pd_choice preferred_domain
    read -e -r -p "选择 [1]: " pd_choice
    pd_choice=${pd_choice:-1}
    if [[ "$pd_choice" =~ ^[0-9]+$ ]] && (( pd_choice >= 1 && pd_choice <= ${#pd_arr[@]} )); then
        preferred_domain="${pd_arr[$((pd_choice-1))]}"
    else
        read -e -r -p "输入优选域名: " preferred_domain
        validate_domain "$preferred_domain" || { print_error "域名格式无效"; pause; return; }
    fi
    print_success "优选域名: $preferred_domain"

    # ── 配置确认 ──
    draw_line
    echo -e "${C_CYAN}配置确认:${C_RESET}"
    echo -e "  根域名:     ${C_GREEN}${root_domain}${C_RESET}"
    echo -e "  业务域名:   ${C_GREEN}${biz_domain}${C_RESET}  ← 用户访问地址"
    echo -e "  回源域名:   ${C_GREEN}${origin_domain}${C_RESET}  ← 指向服务器(开代理)"
    echo -e "  服务器 IP:  ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  优选域名:   ${C_GREEN}${preferred_domain}${C_RESET}  ← CNAME 目标"
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    echo -e "    1. SSL/TLS → Full"
    echo -e "    2. ${origin_domain} → ${server_ip} (A记录, 开代理)"
    echo -e "    3. 设置 SaaS 回退源 → ${origin_domain}"
    echo -e "    4. 添加自定义主机名 ${biz_domain}"
    echo -e "    5. 添加 TXT 验证记录并等待验证"
    echo -e "    6. ${biz_domain} → CNAME → ${preferred_domain} (关代理)"
    draw_line
    if ! confirm "确认执行以上操作？"; then
        print_warn "已取消"; pause; return
    fi

    # ── 步骤 2: SSL/TLS → Full ──
    echo -e "${C_CYAN}━━━ 步骤 2/6: 设置 SSL/TLS 为 Full 模式 ━━━${C_RESET}"
    echo -e "  ${C_GRAY}原因: SaaS 回源需要 Full 模式才能正确建立 HTTPS 连接${C_RESET}"
    local ssl_resp=$(_cf_api PATCH "/zones/$zone_id/settings/ssl" "$token" \
        --data '{"value":"full"}')
    if _cf_api_ok "$ssl_resp"; then
        print_success "SSL/TLS 已设为 Full"
    else
        print_warn "SSL 设置: $(_cf_api_err "$ssl_resp") (可能已是 Full，继续)"
    fi

    # ── 步骤 3: 创建回源 DNS 记录 ──
    echo -e "${C_CYAN}━━━ 步骤 3/6: 创建回源记录 ━━━${C_RESET}"
    echo -e "  ${C_GRAY}${origin_domain} → ${server_ip} (A 记录, proxied=true/开代理)${C_RESET}"
    echo -e "  ${C_GRAY}此记录让 CF 知道你的源服务器在哪里${C_RESET}"
    local origin_resp=$(_cf_dns_upsert "$zone_id" "$token" "A" "$origin_domain" "$server_ip" "true")
    if _cf_api_ok "$origin_resp"; then
        print_success "回源记录: ${origin_domain} → ${server_ip} (代理已开启)"
    else
        print_error "回源记录创建失败: $(_cf_api_err "$origin_resp")"
        pause; return
    fi

    # ── 步骤 4: 设置 SaaS 回退源 ──
    echo -e "${C_CYAN}━━━ 步骤 4/6: 设置 SaaS 回退源 ━━━${C_RESET}"
    echo -e "  ${C_GRAY}告诉 CF SaaS: 当自定义主机名收到请求时，回源到 ${origin_domain}${C_RESET}"
    local fb_resp=$(_cf_api PUT "/zones/$zone_id/custom_hostnames/fallback_origin" "$token" \
        --data "{\"origin\":\"$origin_domain\"}")
    if _cf_api_ok "$fb_resp"; then
        print_success "回退源已设置: ${origin_domain}"
    else
        local fb_err=$(_cf_api_err "$fb_resp")
        if echo "$fb_err" | grep -qi "already"; then
            print_warn "回退源已存在，继续"
        else
            print_error "回退源设置失败: $fb_err"
            echo -e "  ${C_YELLOW}请确认已在 CF 后台绑定信用卡/PayPal 开通 SaaS 功能${C_RESET}"
            echo -e "  ${C_YELLOW}且 API Token 有 Custom Hostnames 权限${C_RESET}"
            pause; return
        fi
    fi

    # 等待回退源激活
    print_info "等待回退源激活 (最长 60 秒)..."
    local fb_active=false
    for attempt in $(seq 1 12); do
        sleep 5
        local fb_st=$(_cf_api GET "/zones/$zone_id/custom_hostnames/fallback_origin" "$token")
        local fb_status=$(echo "$fb_st" | jq -r '.result.status // empty')
        echo -ne "\r  检测中... (${attempt}/12) 状态: ${fb_status:-pending}    "
        [[ "$fb_status" == "active" ]] && { fb_active=true; echo ""; break; }
    done
    if [[ "$fb_active" == "true" ]]; then
        print_success "回退源已激活"
    else
        print_warn "回退源尚未激活 (状态: ${fb_status:-unknown})，可能需要更多时间"
        echo -e "  ${C_GRAY}脚本将继续执行，通常会在几分钟内自动激活${C_RESET}"
    fi

    # ── 步骤 5: 添加自定义主机名 + TXT 验证 ──
    echo -e "${C_CYAN}━━━ 步骤 5/6: 添加自定义主机名并验证 ━━━${C_RESET}"
    echo -e "  ${C_GRAY}在 CF SaaS 中注册 ${biz_domain}，并通过 TXT 记录验证所有权${C_RESET}"
    local ch_resp=$(_cf_api POST "/zones/$zone_id/custom_hostnames" "$token" \
        --data "{\"hostname\":\"$biz_domain\",\"ssl\":{\"method\":\"txt\",\"type\":\"dv\",\"settings\":{\"min_tls_version\":\"1.2\"}}}")
    local ch_id=""
    if _cf_api_ok "$ch_resp"; then
        ch_id=$(echo "$ch_resp" | jq -r '.result.id')
        print_success "自定义主机名已添加: ${biz_domain}"
    else
        local ch_err=$(_cf_api_err "$ch_resp")
        if echo "$ch_err" | grep -qi "already exists"; then
            print_warn "自定义主机名已存在，获取现有配置..."
            local existing=$(_cf_api GET "/zones/$zone_id/custom_hostnames?hostname=$biz_domain" "$token")
            ch_id=$(echo "$existing" | jq -r '.result[0].id // empty')
            [[ -n "$ch_id" ]] && print_success "找到现有配置" || { print_error "无法获取"; pause; return; }
        else
            print_error "添加失败: $ch_err"; pause; return
        fi
    fi

    # 获取验证信息并添加 TXT 记录
    print_info "获取验证信息..."
    sleep 3
    local ch_detail=$(_cf_api GET "/zones/$zone_id/custom_hostnames/$ch_id" "$token")
    local own_name=$(echo "$ch_detail" | jq -r '.result.ownership_verification.name // empty')
    local own_value=$(echo "$ch_detail" | jq -r '.result.ownership_verification.value // empty')
    local ssl_txt_name=$(echo "$ch_detail" | jq -r '.result.ssl.txt_name // empty')
    local ssl_txt_value=$(echo "$ch_detail" | jq -r '.result.ssl.txt_value // empty')
    local ch_status=$(echo "$ch_detail" | jq -r '.result.status // empty')
    local ssl_status=$(echo "$ch_detail" | jq -r '.result.ssl.status // empty')
    echo -e "  主机名状态: ${ch_status:-pending}"
    echo -e "  SSL 状态:   ${ssl_status:-pending}"

    # 添加所有权验证 TXT
    if [[ -n "$own_name" && -n "$own_value" && "$ch_status" != "active" ]]; then
        echo -e "${C_YELLOW}添加所有权验证 TXT 记录:${C_RESET}"
        echo -e "  名称: ${C_GREEN}${own_name}${C_RESET}"
        echo -e "  内容: ${C_GREEN}${own_value}${C_RESET}"
        local txt_r=$(_cf_dns_upsert "$zone_id" "$token" "TXT" "$own_name" "$own_value" "false")
        _cf_api_ok "$txt_r" && print_success "所有权 TXT 已添加" || print_warn "TXT 添加失败: $(_cf_api_err "$txt_r")，请手动添加"
    fi

    # 添加 SSL 验证 TXT
    if [[ -n "$ssl_txt_name" && -n "$ssl_txt_value" && "$ssl_status" != "active" ]]; then
        echo -e "${C_YELLOW}添加 SSL 验证 TXT 记录:${C_RESET}"
        echo -e "  名称: ${C_GREEN}${ssl_txt_name}${C_RESET}"
        echo -e "  内容: ${C_GREEN}${ssl_txt_value}${C_RESET}"
        local ssl_r=$(_cf_dns_upsert "$zone_id" "$token" "TXT" "$ssl_txt_name" "$ssl_txt_value" "false")
        _cf_api_ok "$ssl_r" && print_success "SSL TXT 已添加" || print_warn "SSL TXT 添加失败: $(_cf_api_err "$ssl_r")，请手动添加"
    fi

    # 等待验证
    if [[ "$ch_status" != "active" ]]; then
        print_info "等待验证通过 (最长 5 分钟)..."
        echo -e "  ${C_GRAY}CF 需要时间传播 TXT 记录并完成验证${C_RESET}"
        local verified=false
        for attempt in $(seq 1 30); do
            sleep 10
            ch_detail=$(_cf_api GET "/zones/$zone_id/custom_hostnames/$ch_id" "$token")
            ch_status=$(echo "$ch_detail" | jq -r '.result.status // empty')
            ssl_status=$(echo "$ch_detail" | jq -r '.result.ssl.status // empty')
            echo -ne "\r  检测中... (${attempt}/30) 主机名: ${ch_status} | SSL: ${ssl_status}          "
            [[ "$ch_status" == "active" ]] && { verified=true; echo ""; break; }
        done
        if [[ "$verified" == "true" ]]; then
            print_success "自定义主机名验证通过！"
        else
            print_warn "验证尚未完成 (主机名: ${ch_status}, SSL: ${ssl_status})"
            echo -e "  ${C_YELLOW}CF 验证有时需要更长时间，脚本将继续配置 CNAME${C_RESET}"
            echo -e "  ${C_YELLOW}验证通常会在几分钟内自动完成${C_RESET}"
            if ! confirm "继续配置 CNAME？(选 N 则保存进度，稍后可查看状态)"; then
                mkdir -p "$SAAS_CONFIG_DIR"
                cat > "${SAAS_CONFIG_DIR}/${biz_domain}.conf" << SAASEOF
SAAS_STATUS="pending"
ROOT_DOMAIN="$root_domain"
BIZ_DOMAIN="$biz_domain"
ORIGIN_DOMAIN="$origin_domain"
SERVER_IP="$server_ip"
PREFERRED_DOMAIN="$preferred_domain"
ZONE_ID="$zone_id"
CH_ID="$ch_id"
CREATED="$(date '+%Y-%m-%d %H:%M:%S')"
SAASEOF
                chmod 600 "${SAAS_CONFIG_DIR}/${biz_domain}.conf"
                print_info "进度已保存，验证通过后可通过 '查看 SaaS 配置' 检查状态"
                pause; return
            fi
        fi
    else
        print_success "主机名已激活，无需等待"
    fi

    # ── 步骤 6: 业务域名 CNAME 到优选域名 ──
    echo -e "${C_CYAN}━━━ 步骤 6/6: 配置业务域名 CNAME ━━━${C_RESET}"
    echo -e "  ${C_GRAY}${biz_domain} → CNAME → ${preferred_domain} (关闭代理/小黄云)${C_RESET}"
    echo -e "  ${C_GRAY}关闭代理是关键: 让 DNS 直接解析到优选域名的高速 IP${C_RESET}"
    local cname_resp=$(_cf_dns_upsert "$zone_id" "$token" "CNAME" "$biz_domain" "$preferred_domain" "false")
    if _cf_api_ok "$cname_resp"; then
        print_success "CNAME 已配置: ${biz_domain} → ${preferred_domain} (代理已关闭)"
    else
        print_error "CNAME 配置失败: $(_cf_api_err "$cname_resp")"
        pause; return
    fi

    # 保存配置
    mkdir -p "$SAAS_CONFIG_DIR"
    cat > "${SAAS_CONFIG_DIR}/${biz_domain}.conf" << SAASEOF
SAAS_STATUS="active"
ROOT_DOMAIN="$root_domain"
BIZ_DOMAIN="$biz_domain"
ORIGIN_DOMAIN="$origin_domain"
SERVER_IP="$server_ip"
PREFERRED_DOMAIN="$preferred_domain"
ZONE_ID="$zone_id"
CH_ID="$ch_id"
CREATED="$(date '+%Y-%m-%d %H:%M:%S')"
SAASEOF
    chmod 600 "${SAAS_CONFIG_DIR}/${biz_domain}.conf"
    # 完成
    draw_line
    print_success "Cloudflare SaaS 优选加速配置完成！"
    draw_line
    echo -e "  ${C_CYAN}访问链路:${C_RESET}"
    echo -e "    用户访问 ${C_GREEN}${biz_domain}${C_RESET}"
    echo -e "      → DNS CNAME → ${C_GREEN}${preferred_domain}${C_RESET} (优选高速节点)"
    echo -e "      → CF SaaS 匹配主机名 → 回退源 ${C_GREEN}${origin_domain}${C_RESET}"
    echo -e "      → CF 代理回源 → 服务器 ${C_GREEN}${server_ip}${C_RESET}"
    echo -e "  ${C_YELLOW}注意事项:${C_RESET}"
    echo -e "    • 确保服务器上 ${biz_domain} 的网站/服务已配置并开启 SSL"
    echo -e "    • 如果使用 Nginx，server_name 需包含 ${biz_domain}"
    echo -e "    • 首次生效可能需要几分钟等待 DNS 传播"
    echo -e "    • 可通过 ping ${biz_domain} 验证是否解析到优选 IP"
    draw_line
    log_action "SaaS CDN configured: ${biz_domain} -> ${preferred_domain} (origin: ${origin_domain})"
    pause
}

_cf_get_origin_ruleset() {
    local token="$1" zone_id="$2"
    local url="https://api.cloudflare.com/client/v4/zones/${zone_id}/rulesets/phases/http_request_origin/entrypoint"
    local resp=$(curl -s -w "\n%{http_code}" -X GET "$url" \
        -H "Authorization: Bearer $token" -H "Content-Type: application/json")
    local code=$(echo "$resp" | tail -1)
    local body=$(echo "$resp" | sed '$d')
    if [[ "$code" == "200" ]]; then
        echo "$body"
        return 0
    elif [[ "$code" == "404" ]]; then
        return 0
    else
        echo "$body"
        return 1
    fi
}

_cf_put_origin_ruleset() {
    local token="$1" zone_id="$2" rules_json="$3"
    local url="https://api.cloudflare.com/client/v4/zones/${zone_id}/rulesets/phases/http_request_origin/entrypoint"
    local payload=$(jq -n \
        --argjson rules "$rules_json" \
        '{
            "name": "Origin Rules",
            "kind": "zone",
            "phase": "http_request_origin",
            "rules": $rules
        }')
    local resp=$(curl -s -X PUT "$url" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json" \
        --data "$payload")
    if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
        return 0
    else
        echo "$resp" | jq -r '.errors[0].message // "未知错误"'
        return 1
    fi
}

web_cf_origin_rule_create() {
    print_title "创建 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    echo -e "${C_YELLOW}功能说明:${C_RESET}"
    echo "  解决运营商封锁 443 端口的问题。
  用户仍用标准 https:// 访问，CF 自动将回源端口改为你指定的端口。
"

    # 收集信息
    local token="" domain="" port=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    while [[ -z "$domain" ]]; do
        read -e -r -p "完整域名 (如 www.example.com): " domain
        if ! validate_domain "$domain"; then
            print_error "域名格式无效"; domain=""
        fi
    done
    while true; do
        read -e -r -p "回源端口 (如 8443, 2053, 2083, 2087, 2096): " port
        if validate_port "$port" 2>/dev/null || [[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]]; then
            break
        fi
        print_warn "端口无效，请输入 1-65535 之间的数字"
    done

    # 获取 Zone ID
    print_info "获取 Zone ID..."
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID，请检查 Token 权限和域名"; pause; return
    fi
    print_success "Zone ID: $zone_id"

    # 获取现有规则
    print_info "读取现有回源规则..."
    local existing
    existing=$(_cf_get_origin_ruleset "$token" "$zone_id")
    if [[ $? -ne 0 ]]; then
        print_error "API 请求失败: $(echo "$existing" | jq -r '.errors[0].message // "未知错误"')"
        pause; return
    fi

    # 提取现有 rules 数组（如果有的话）
    local existing_rules="[]"
    if [[ -n "$existing" ]]; then
        existing_rules=$(echo "$existing" | jq '.result.rules // []')
    fi

    # 检查是否已存在同域名的规则，如果有则替换
    local desc="Script-Origin-${domain}-${port}"
    local filtered_rules=$(echo "$existing_rules" | jq --arg d "$domain" \
        '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]')

    # 构建新规则
    local new_rule=$(jq -n \
        --arg expr "http.host eq \"${domain}\"" \
        --arg desc "$desc" \
        --argjson port "$port" \
        '{
            "action": "route",
            "action_parameters": { "origin": { "port": $port } },
            "expression": $expr,
            "description": $desc,
            "enabled": true
        }')

    # 合并：旧规则 + 新规则
    local final_rules=$(echo "$filtered_rules" | jq --argjson new "$new_rule" '. + [$new]')

    # 写入
    print_info "写入回源规则..."
    local err
    err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules")
    if [[ $? -ne 0 ]]; then
        print_error "规则创建失败: $err"; pause; return
    fi
    print_success "回源规则创建成功！"
    echo -e "  域名: ${C_GREEN}${domain}${C_RESET}"
    echo -e "  链路: 用户 :443 → CF 边缘 → 回源 :${C_GREEN}${port}${C_RESET} → 你的服务器"
    echo -e "  生效: 约 30 秒"

    # 提示服务器端操作
    draw_line
    echo -e "${C_CYAN}服务器端操作提示:${C_RESET}"
    echo "  1. Nginx 监听端口改为 ${port}:"
    echo "     listen ${port} ssl http2;"
    echo "  2. 防火墙放行:"
    echo "     ufw allow ${port}/tcp"
    echo "  3. 如果服务器在 NAT 后面（如家宽），路由器需要转发外网 ${port} → 内网 ${port}"
    pause
}

web_cf_origin_rule_list() {
    print_title "查看 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    local token=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    local domain=""
    read -e -r -p "根域名 (如 example.com): " domain
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID"; pause; return
    fi
    local resp=$(_cf_get_origin_ruleset "$token" "$zone_id")
    if [[ -z "$resp" ]]; then
        print_warn "该域名下没有任何回源规则"
        pause; return
    fi
    local count=$(echo "$resp" | jq '.result.rules | length')
    if [[ "$count" == "0" ]]; then
        print_warn "该域名下没有任何回源规则"
        pause; return
    fi
    echo -e "${C_CYAN}当前回源规则 (共 ${count} 条):${C_RESET}"
    draw_line
    echo "$resp" | jq -r '.result.rules[] | [
        "  描述: \(.description // "无")",
        "  表达式: \(.expression)",
        "  回源端口: \(.action_parameters.origin.port // "默认")",
        "  状态: \(if .enabled then "启用" else "禁用" end)",
        "  ---"
    ] | .[]'
    pause
}

web_cf_origin_rule_delete() {
    print_title "删除 CF 回源规则 (Origin Rules)"
    command_exists jq || install_package "jq" "silent"
    local token=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    local domain=""
    read -e -r -p "根域名 (如 example.com): " domain
    local zone_id=$(_cf_get_zone_id "$domain" "$token")
    if [[ -z "$zone_id" ]]; then
        print_error "未找到 Zone ID"; pause; return
    fi
    local resp=$(_cf_get_origin_ruleset "$token" "$zone_id")
    if [[ -z "$resp" ]]; then
        print_warn "没有任何回源规则"; pause; return
    fi
    local rules=$(echo "$resp" | jq '.result.rules')
    local count=$(echo "$rules" | jq 'length')
    if [[ "$count" == "0" ]]; then
        print_warn "没有任何回源规则"; pause; return
    fi

    # 列出规则供选择
    echo -e "${C_CYAN}当前规则:${C_RESET}"
    for i in $(seq 0 $((count - 1))); do
        local desc=$(echo "$rules" | jq -r ".[$i].description // \"规则$((i+1))\"")
        local expr=$(echo "$rules" | jq -r ".[$i].expression")
        local port=$(echo "$rules" | jq -r ".[$i].action_parameters.origin.port // \"默认\"")
        echo -e "  ${C_GREEN}$((i+1))${C_RESET}. ${desc}"
        echo "     匹配: ${expr} → 端口: ${port}"
    done
    read -e -r -p "输入要删除的规则编号 (0=取消): " choice
    if [[ "$choice" == "0" || -z "$choice" ]]; then return; fi
    local idx=$((choice - 1))
    if [[ $idx -lt 0 || $idx -ge $count ]]; then
        print_error "编号无效"; pause; return
    fi
    local del_desc=$(echo "$rules" | jq -r ".[$idx].description // \"规则\"")

    # 移除选中的规则
    local new_rules=$(echo "$rules" | jq --argjson i "$idx" 'del(.[$i])')
    read -e -r -p "确认删除 [${del_desc}]? (y/N): " del_confirm
    [[ "$del_confirm" != "y" && "$del_confirm" != "Y" ]] && return
    print_info "删除中..."
    local err
    err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$new_rules")
    if [[ $? -ne 0 ]]; then
        print_error "删除失败: $err"; pause; return
    fi
    print_success "规则已删除"
    pause
}

web_cf_saas_status() {
    print_title "查看 SaaS 优选配置"
    if [[ ! -d "$SAAS_CONFIG_DIR" ]] || [[ -z "$(ls -A "$SAAS_CONFIG_DIR" 2>/dev/null)" ]]; then
        print_warn "暂无 SaaS 优选配置"
        pause; return
    fi
        printf "${C_CYAN}%-30s %-10s %-30s %-20s %s${C_RESET}\n" "业务域名" "状态" "优选域名" "回源域名" "创建时间"
    draw_line
    for conf in "$SAAS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local SAAS_STATUS="" BIZ_DOMAIN="" PREFERRED_DOMAIN="" ORIGIN_DOMAIN="" CREATED=""
        validate_conf_file "$conf" || continue
        source "$conf"
        local status_display="${C_GREEN}${SAAS_STATUS}${C_RESET}"
        [[ "$SAAS_STATUS" == "pending" ]] && status_display="${C_YELLOW}${SAAS_STATUS}${C_RESET}"
        printf "%-30s %-10b %-30s %-20s %s\n" "$BIZ_DOMAIN" "$status_display" "$PREFERRED_DOMAIN" "$ORIGIN_DOMAIN" "$CREATED"
    done
    pause
}

web_cf_saas_delete() {
    print_title "删除 SaaS 优选配置"
    if [[ ! -d "$SAAS_CONFIG_DIR" ]] || [[ -z "$(ls -A "$SAAS_CONFIG_DIR" 2>/dev/null)" ]]; then
        print_warn "暂无 SaaS 优选配置"
        pause; return
    fi
    local i=1 domains=() files=()
    for conf in "$SAAS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local BIZ_DOMAIN=""
        validate_conf_file "$conf" || continue
        source "$conf"
        domains+=("$BIZ_DOMAIN")
        files+=("$conf")
        echo "$i. $BIZ_DOMAIN"
        ((i++))
    done
    echo "0. 返回"
    read -e -r -p "选择要删除的配置: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号"; pause; return
    fi
    local target_conf="${files[$((idx-1))]}"
    local SAAS_STATUS="" ROOT_DOMAIN="" BIZ_DOMAIN="" ORIGIN_DOMAIN="" SERVER_IP=""
    local PREFERRED_DOMAIN="" ZONE_ID="" CH_ID=""
    if ! validate_conf_file "$target_conf"; then
        print_error "配置文件格式异常"; pause; return
    fi
    source "$target_conf"
    echo -e "${C_RED}即将删除 SaaS 配置: ${BIZ_DOMAIN}${C_RESET}"
    echo "可选的清理操作:
  1. 仅删除本地配置文件 (CF 上的记录保留)
  2. 删除本地配置 + CF 上的自定义主机名和相关 DNS 记录
  0. 取消
"
    read -e -r -p "选择: " del_mode
    [[ "$del_mode" == "0" || -z "$del_mode" ]] && return
    if [[ "$del_mode" == "2" ]]; then
        read -s -r -p "Cloudflare API Token: " del_token; echo ""
        if [[ -n "$CH_ID" && -n "$ZONE_ID" ]]; then
            print_info "删除自定义主机名..."
            local del_ch=$(_cf_api DELETE "/zones/$ZONE_ID/custom_hostnames/$CH_ID" "$del_token")
            _cf_api_ok "$del_ch" && print_success "自定义主机名已删除" || print_warn "删除失败: $(_cf_api_err "$del_ch")"
        fi
        if [[ -n "$BIZ_DOMAIN" && -n "$ZONE_ID" ]]; then
            print_info "删除 CNAME 记录 ${BIZ_DOMAIN}..."
            _cf_dns_delete "$ZONE_ID" "$del_token" "CNAME" "$BIZ_DOMAIN"
            print_success "CNAME 记录已清理"
        fi
        echo -e "${C_YELLOW}以下记录可能被其他配置共用，请确认是否删除:${C_RESET}"
        if [[ -n "$ORIGIN_DOMAIN" ]] && confirm "删除回源记录 ${ORIGIN_DOMAIN}？"; then
            _cf_dns_delete "$ZONE_ID" "$del_token" "A" "$ORIGIN_DOMAIN"
            print_success "回源记录已删除"
        fi
        if confirm "删除 SaaS 回退源设置？(如有其他 SaaS 域名请选 N)"; then
            _cf_api DELETE "/zones/$ZONE_ID/custom_hostnames/fallback_origin" "$del_token" >/dev/null 2>&1
            print_success "回退源已删除"
        fi
    fi
    rm -f "$target_conf"
    print_success "本地配置已删除: ${BIZ_DOMAIN}"
    log_action "SaaS config deleted: ${BIZ_DOMAIN} (mode=${del_mode})"
    pause
}

_CF_RESULT_DOMAIN=""
_CF_RESULT_TOKEN=""

web_cf_dns_update() {
    local DOMAIN="" CF_API_TOKEN=""
    _CF_RESULT_DOMAIN=""
    _CF_RESULT_TOKEN=""
    print_title "Cloudflare DNS 智能解析"
    command_exists jq || install_package "jq" "silent"
    print_info "正在探测本机公网 IP..."
    local ipv4 ipv6
    ipv4=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv4=""
    ipv6=$(curl -6 -s --max-time 5 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv6=""
    echo "----------------------------------------"
    echo "IPv4: ${ipv4:-[✗] 未检测到}"
    echo "IPv6: ${ipv6:-[✗] 未检测到}"
    echo "----------------------------------------"
    echo "1. 仅解析 IPv4 (A)
2. 仅解析 IPv6 (AAAA)
3. 双栈解析 (A + AAAA)
0. 跳过"
    read -e -r -p "请选择: " mode
    if [[ "$mode" == "0" ]]; then return; fi
    while [[ -z "$CF_API_TOKEN" ]]; do
        read -s -r -p "Cloudflare API Token: " CF_API_TOKEN
        echo ""
    done
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名: " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    print_info "正在获取 Zone ID..."
    local zone_id=""
    zone_id=$(_cf_get_zone_id "$DOMAIN" "$CF_API_TOKEN")
    if [[ -z "$zone_id" ]]; then
        print_error "无法获取 Zone ID，请检查 Token 权限和域名是否已托管在 CF"
        pause; return
    fi
    print_success "找到 Zone ID: $zone_id"
    echo -e "${C_YELLOW}注意: 开启代理后，只有 HTTP/HTTPS 流量能通过 Cloudflare。${C_RESET}"
    echo -e "${C_YELLOW}SSH、RDP、端口转发等非 HTTP 服务将无法使用此域名访问。${C_RESET}"
    read -e -r -p "是否开启 Cloudflare 代理 (小云朵)? [y/N]: " proxy_choice
    local proxied="false"
    [[ "${proxy_choice,,}" == "y" ]] && proxied="true"
    
    update_record() {
        local type=$1
        local ip=$2
        [[ -z "$ip" ]] && return
        print_info "处理 $type 记录 -> $ip (代理: $proxied)"
        local records=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records?type=$type&name=$DOMAIN" \
            -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json")
        local record_id=$(echo "$records" | jq -r '.result[0].id')
        local count=$(echo "$records" | jq -r '.result | length')
        [[ "$count" -gt 1 ]] && print_warn "警告: 存在多条 $type 记录，仅更新第一条。"
        if [[ "$record_id" != "null" && -n "$record_id" ]]; then
            local resp=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
            if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
                print_success "更新成功"
            else
                print_error "更新失败: $(echo "$resp" | jq -r '.errors[0].message')"
            fi
        else
            local resp=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
                -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
                --data "{\"type\":\"$type\",\"name\":\"$DOMAIN\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
            if [[ "$(echo "$resp" | jq -r '.success')" == "true" ]]; then
                print_success "创建成功"
            else
                print_error "创建失败: $(echo "$resp" | jq -r '.errors[0].message')"
            fi
        fi
    }
    case $mode in
        1) update_record "A" "$ipv4" ;;
        2) update_record "AAAA" "$ipv6" ;;
        3) update_record "A" "$ipv4"; update_record "AAAA" "$ipv6" ;;
    esac
    print_success "DNS 配置完成。"
    log_action "Cloudflare DNS updated for $DOMAIN"
    local ddns_v4=$([[ "$mode" == "1" || "$mode" == "3" ]] && echo "true" || echo "false")
    local ddns_v6=$([[ "$mode" == "2" || "$mode" == "3" ]] && echo "true" || echo "false")
    ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_v4" "$ddns_v6" "$proxied"
    _CF_RESULT_DOMAIN="$DOMAIN"
    _CF_RESULT_TOKEN="$CF_API_TOKEN"
    sleep 2
}

web_view_config() {
    print_title "查看详细配置"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    local i=1
    local domains=()
    local files=()
    echo "请选择要查看的域名:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    read -e -r -p "请输入序号: " idx
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    local DOMAIN="" CERT_PATH="" DEPLOY_HOOK_SCRIPT=""
    if ! validate_conf_file "$target_conf"; then
        print_error "配置文件格式异常"; pause; return
    fi
    source "$target_conf"
    CERT_PATH=${CERT_PATH:-"${CERT_PATH_PREFIX}/${target_domain}"}
    DEPLOY_HOOK_SCRIPT=${DEPLOY_HOOK_SCRIPT:-"/root/cert-renew-hook-${target_domain}.sh"}
    print_title "配置详情: $target_domain"
    echo -e "${C_CYAN}[基础信息]${C_RESET}"
    echo "域名: $target_domain"
    echo "证书目录: $CERT_PATH"
    echo "Hook 脚本: $DEPLOY_HOOK_SCRIPT"
    echo -e "\n${C_CYAN}[自动续签计划 (Crontab)]${C_RESET}"
    local cron_out=$(crontab -l 2>/dev/null | grep -v -E "^[[:space:]]*no crontab for " || true)
    if [[ -n "$DEPLOY_HOOK_SCRIPT" ]] && echo "$cron_out" | grep -F -q "$DEPLOY_HOOK_SCRIPT"; then
        echo "$cron_out" | grep -F "$DEPLOY_HOOK_SCRIPT"
    else
        echo -e "${C_YELLOW}未配置自动续签任务${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[证书状态]${C_RESET}"
    local fullchain="$CERT_PATH/fullchain.pem"
    local privkey="$CERT_PATH/privkey.pem"
    if [[ -f "$fullchain" ]]; then
        local end_date=$(openssl x509 -enddate -noout -in "$fullchain" | cut -d= -f2)
        local end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local days_left=$(( (end_epoch - now_epoch) / 86400 ))
        if [ "$days_left" -lt 0 ]; then
            echo -e "过期时间: ${C_RED}${end_date} (已过期)${C_RESET}"
        elif [ "$days_left" -lt 30 ]; then
            echo -e "过期时间: ${C_YELLOW}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        else
            echo -e "过期时间: ${C_GREEN}${end_date} (剩余 ${days_left} 天)${C_RESET}"
        fi
    else
        echo -e "公钥文件: ${C_RED}未找到${C_RESET}"
    fi
    if [[ -f "$privkey" ]]; then
        echo "私钥文件: $privkey (存在)"
    else
        echo -e "私钥文件: ${C_RED}未找到${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[Nginx 配置摘要]${C_RESET}"
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_status="已启用"
    if [[ ! -f "$nginx_conf" ]]; then
        local avail_conf="/etc/nginx/sites-available/${target_domain}.conf"
        if [[ -f "$avail_conf" ]]; then
            nginx_conf="$avail_conf"
            nginx_status="${C_YELLOW}未启用${C_RESET}"
        fi
    fi
    if [[ -f "$nginx_conf" ]]; then
        echo -e "配置文件: $nginx_conf ($nginx_status)"
        echo "关键指令:"
        grep -E "^\s*(listen|server_name|proxy_pass|ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)\b" "$nginx_conf" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_YELLOW}该域名未配置 Nginx 反代。${C_RESET}"
    fi
    echo -e "\n${C_CYAN}[Hook 脚本摘要]${C_RESET}"
    if [[ -f "$DEPLOY_HOOK_SCRIPT" ]]; then
        echo "脚本路径: $DEPLOY_HOOK_SCRIPT"
        echo "关键动作:"
        grep -E 'export PATH=|cp -L|reload nginx|x-ui|3x-ui' "$DEPLOY_HOOK_SCRIPT" | sed 's/^[[:space:]]*/  /'
    else
        echo -e "${C_RED}Hook 脚本丢失！建议重新添加域名。${C_RESET}"
    fi
    pause
}

web_delete_domain() {
    print_title "删除域名配置"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已保存的域名配置。"
        pause; return
    fi
    local i=1
    local domains=()
    local files=()
    echo "发现以下配置:"
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        if [[ -n "$d" ]]; then
            domains+=("$d")
            files+=("$conf")
            echo "$i. $d"
            ((i++))
        fi
    done
    echo "0. 返回"
    read -e -r -p "请输入序号删除: " idx
    if [[ "$idx" == "0" || -z "$idx" ]]; then return; fi
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -gt ${#domains[@]} ]]; then
        print_error "无效序号。"
        pause; return
    fi
    local target_domain="${domains[$((idx-1))]}"
    local target_conf="${files[$((idx-1))]}"
    echo -e "${C_RED}"
    echo "!!! 危险操作 !!!"
    echo "即将删除域名: $target_domain"
    echo "这将执行:
1. 删除 SSL 证书 (certbot delete)
2. 删除 Nginx 配置文件并重载
3. 删除 自动续签 Hook 脚本
4. 清理 Crontab 定时任务
5. 删除 脚本保存的配置"
    echo -e "${C_RESET}"
    if ! confirm "确认彻底删除吗?"; then return; fi
    print_info "正在执行清理..."
    if certbot delete --cert-name "$target_domain" --non-interactive 2>/dev/null; then
        print_success "证书已吊销/删除。"
    else
        print_warn "Certbot 删除失败或证书不存在。"
    fi
    local nginx_conf="/etc/nginx/sites-enabled/${target_domain}.conf"
    local nginx_conf_src="/etc/nginx/sites-available/${target_domain}.conf"
    if [[ -f "$nginx_conf" || -f "$nginx_conf_src" ]]; then
        rm -f "$nginx_conf" "$nginx_conf_src"
        if is_systemd && command_exists nginx; then
            systemctl reload nginx 2>/dev/null || true
        elif command_exists nginx; then
            nginx -s reload 2>/dev/null || true
        fi
        print_success "Nginx 配置已删除。"
    fi
    local hook_script="${CERT_HOOKS_DIR}/renew-${target_domain}.sh"
    [[ ! -f "$hook_script" ]] && hook_script="/root/cert-renew-hook-${target_domain}.sh"
    if [[ -f "$hook_script" ]]; then
        rm -f "$hook_script"
        print_success "Hook 脚本已删除。"
    fi
    # 清理 Cloudflare 凭据文件
    local cf_cred="/root/.cloudflare-${target_domain}.ini"
    if [[ -f "$cf_cred" ]]; then
        rm -f "$cf_cred"
        print_success "Cloudflare 凭据文件已清理。"
    fi
    shopt -s nullglob
    local remaining_hooks=("${CERT_HOOKS_DIR}"/*.sh /root/cert-renew-hook-*.sh)
    shopt -u nullglob
    if [[ ${#remaining_hooks[@]} -eq 0 ]]; then
        cron_remove_job "certbot renew"
        print_success "全局续签任务已清理（无剩余域名）。"
    fi
    rm -f "$target_conf"
    print_success "管理配置已移除。"
    log_action "Deleted domain config: $target_domain"
    pause
}

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    local DOMAIN="" CF_API_TOKEN="" LOCAL_PROXY_PASS="" NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL=""
    web_env_check || { pause; return; }
    print_guide "此步骤将申请 SSL 证书并（可选）配置 Nginx 反向代理。"
    if confirm "是否需要先自动配置 Cloudflare DNS 解析 (A/AAAA)?"; then
        web_cf_dns_update
        [[ -n "$_CF_RESULT_DOMAIN" ]] && DOMAIN="$_CF_RESULT_DOMAIN"
        [[ -n "$_CF_RESULT_TOKEN" ]] && CF_API_TOKEN="$_CF_RESULT_TOKEN"
        _CF_RESULT_DOMAIN=""
        _CF_RESULT_TOKEN=""
        echo ""
    fi
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名 (如 example.com): " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        print_warn "配置已存在，请先删除。"
        pause; return
    fi
    print_guide "脚本使用 DNS API 申请证书，需要您的 Cloudflare API Token。"
    while [[ -z "$CF_API_TOKEN" ]]; do
        read -s -r -p "Cloudflare API Token: " CF_API_TOKEN
        echo ""
    done
    local do_nginx=0
    if confirm "是否配置 Nginx 反向代理 (用于隐藏后端端口)?"; then
        do_nginx=1
        print_guide "请输入 Nginx 监听的端口 (通常 HTTP=80, HTTPS=443)"
        
        while true; do
            read -e -r -p "HTTP 端口 [80]: " hp
            NGINX_HTTP_PORT=${hp:-80}
            if validate_port "$NGINX_HTTP_PORT"; then break; fi
            print_warn "端口无效"
        done
        while true; do
            read -e -r -p "HTTPS 端口 [443]: " sp
            NGINX_HTTPS_PORT=${sp:-443}
            if validate_port "$NGINX_HTTPS_PORT"; then break; fi
            print_warn "端口无效"
        done
        read -e -r -p "后端协议 [1]http [2]https: " proto
        BACKEND_PROTOCOL=$([[ "$proto" == "2" ]] && echo "https" || echo "http")
        print_guide "请输入后端服务的实际地址 (例如 127.0.0.1:54321)"
        while [[ -z "$LOCAL_PROXY_PASS" ]]; do
            read -e -r -p "反代目标: " inp
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"
            else
                print_warn "格式错误，请重试"
            fi
        done
    else
        echo ""
        print_guide "您选择了【不配置 Nginx】。"
        print_guide "证书生成后，请手动在 3x-ui 面板设置中填写公钥/私钥路径。"
        echo ""
    fi
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    local CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    print_info "正在申请证书 (这可能需要 1-2 分钟)..."
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$DOMAIN" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive; then
        print_success "证书获取成功！"
        local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_dir/fullchain.pem"
        cp -L "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir/privkey.pem"
        chmod 644 "$cert_dir/fullchain.pem"
        chmod 600 "$cert_dir/privkey.pem"
        if [[ $do_nginx -eq 1 ]]; then
            local NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
            if [[ ! -f /etc/nginx/snippets/ssl-params.conf ]]; then
                local ssl_params="ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security \"max-age=15768000\" always;"
                write_file_atomic "/etc/nginx/snippets/ssl-params.conf" "$ssl_params"
            fi
            local redir_port=""
            [[ "$NGINX_HTTPS_PORT" != "443" ]] && redir_port=":${NGINX_HTTPS_PORT}"
            local nginx_conf="# Config for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION
server {
    listen $NGINX_HTTP_PORT;
    listen [::]:$NGINX_HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
    listen $NGINX_HTTPS_PORT ssl http2;
    listen [::]:$NGINX_HTTPS_PORT ssl http2;
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    location / {
        proxy_pass $LOCAL_PROXY_PASS;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
}"
            write_file_atomic "$NGINX_CONF_PATH" "$nginx_conf"
            ln -sf "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
            if nginx -t >/dev/null 2>&1; then
                if is_systemd; then
                    systemctl reload nginx || systemctl restart nginx
                else
                    nginx -s reload 2>/dev/null || service nginx reload
                fi
                print_success "Nginx 配置已生效。"
            else
                print_error "Nginx 配置测试失败！"
                nginx -t 2>&1 | tail -5
                rm -f "/etc/nginx/sites-enabled/${DOMAIN}.conf"
                rm -f "$NGINX_CONF_PATH"
                pause; return
            fi
            if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw allow "$NGINX_HTTP_PORT/tcp" comment "Nginx-HTTP" >/dev/null 2>&1 || true
                ufw allow "$NGINX_HTTPS_PORT/tcp" comment "Nginx-HTTPS" >/dev/null 2>&1 || true
                print_success "防火墙规则已更新。"
            fi
        fi
                mkdir -p "$CERT_HOOKS_DIR"
        local DEPLOY_HOOK_SCRIPT="${CERT_HOOKS_DIR}/renew-${DOMAIN}.sh"
        local hook_content="#!/bin/bash
# Auto-generated renewal hook for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=\"$DOMAIN\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"
echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

# Copy certificates
if [[ -f \"\${LETSENCRYPT_LIVE}/fullchain.pem\" ]]; then
    cp -L \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${CERT_DIR}/fullchain.pem\"
    cp -L \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}/privkey.pem\"
    chmod 644 \"\${CERT_DIR}/fullchain.pem\"
    chmod 600 \"\${CERT_DIR}/privkey.pem\"
    echo \"[\$(date)] Certificates copied successfully\" >> /var/log/cert-renew.log
else
    echo \"[\$(date)] ERROR: Certificate files not found\" >> /var/log/cert-renew.log
    exit 1
fi
"
        if [[ $do_nginx -eq 1 ]]; then
            hook_content+="
# Reload Nginx
if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx 2>&1 | tee -a /var/log/cert-renew.log
elif command -v service >/dev/null 2>&1; then
    service nginx reload 2>&1 | tee -a /var/log/cert-renew.log
else
    nginx -s reload 2>&1 | tee -a /var/log/cert-renew.log
fi
echo \"[\$(date)] Nginx reloaded\" >> /var/log/cert-renew.log
"
        fi
        hook_content+="
echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
        write_file_atomic "$DEPLOY_HOOK_SCRIPT" "$hook_content"
        chmod +x "$DEPLOY_HOOK_SCRIPT"
        if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
            cron_add_job "certbot renew" "0 3 * * * certbot renew --quiet; for h in ${CERT_HOOKS_DIR}/*.sh; do [ -x \"\$h\" ] && bash \"\$h\"; done"
            print_success "全局自动续签任务已添加 (每日 3:00 AM)。"
        else
            print_info "全局续签任务已存在，无需重复添加。"
        fi
        local config_content="# Domain configuration for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION at $(date)
DOMAIN=\"$DOMAIN\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"$DEPLOY_HOOK_SCRIPT\"
CLOUDFLARE_CREDENTIALS=\"$CLOUDFLARE_CREDENTIALS\"
"
        if [[ $do_nginx -eq 1 ]]; then
            config_content+="NGINX_CONF_PATH=\"$NGINX_CONF_PATH\"
NGINX_HTTP_PORT=\"$NGINX_HTTP_PORT\"
NGINX_HTTPS_PORT=\"$NGINX_HTTPS_PORT\"
LOCAL_PROXY_PASS=\"$LOCAL_PROXY_PASS\"
"
        fi
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "$config_content"
        if [[ -n "$CF_API_TOKEN" ]] && [[ ! -f "$DDNS_CONFIG_DIR/${DOMAIN}.conf" ]]; then
                        local zone_id=""
            zone_id=$(_cf_get_zone_id "$DOMAIN" "$CF_API_TOKEN")
            if [[ -n "$zone_id" ]]; then
                local ddns_ipv4="false" ddns_ipv6="false"
                [[ -n "$(get_public_ipv4)" ]] && ddns_ipv4="true"
                [[ -n "$(get_public_ipv6)" ]] && ddns_ipv6="true"
                ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "false"
            fi
        fi
        draw_line
        print_success "域名配置完成！"
        draw_line
        echo -e "${C_CYAN}[证书路径]${C_RESET}"
        echo "  公钥: ${cert_dir}/fullchain.pem"
        echo "  私钥: ${cert_dir}/privkey.pem"
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}[访问地址]${C_RESET}"
            echo "  https://${DOMAIN}:${NGINX_HTTPS_PORT}"
            echo -e "\n${C_CYAN}[反代配置]${C_RESET}"
            echo "  后端: $LOCAL_PROXY_PASS"
        else
            echo -e "\n${C_YELLOW}[手动配置提示]${C_RESET}"
            echo "  请在 3x-ui 面板设置中填写上述证书路径"
        fi
        echo -e "\n${C_CYAN}[自动续签]${C_RESET}"
        echo "  Hook 脚本: $DEPLOY_HOOK_SCRIPT"
        echo "  Crontab: 每日 3:00 AM 自动检查"
        draw_line
        log_action "Domain configured: $DOMAIN (Nginx: $do_nginx)"
    else
        print_error "证书申请失败！请检查:"
        echo "1. 域名 DNS 是否正确解析到本机
2. API Token 权限是否正确
3. 网络连接是否正常"
        rm -f "$CLOUDFLARE_CREDENTIALS"
    fi
    pause
}

web_reverse_proxy_site() {
    print_title "添加反向代理网站"
    
    # 检查 Nginx 是否可用
    if ! command_exists nginx; then
        print_error "Nginx 未安装。请先使用菜单 1 添加域名以自动安装依赖。"
        pause; return
    fi
    echo -e "${C_CYAN}选择反代模板:${C_RESET}"
    echo "  1. Emby / Jellyfin (流媒体优化: 大缓冲区/WebSocket/超长超时)
  2. 通用反代 (适用于大多数 Web 服务)
  0. 返回
"
    read -e -r -p "选择模板: " tpl_choice
    [[ "$tpl_choice" == "0" || -z "$tpl_choice" ]] && return
    local template_name=""
    case $tpl_choice in
        1) template_name="emby" ;;
        2) template_name="generic" ;;
        *) print_error "无效选项"; pause; return ;;
    esac
    
    # 域名输入
    local DOMAIN=""
    while [[ -z "$DOMAIN" ]]; do
        read -e -r -p "请输入域名 (如 emby.example.com): " DOMAIN
        if ! validate_domain "$DOMAIN"; then
            print_error "域名格式无效。"
            DOMAIN=""
        fi
    done
    
    # 检查 Nginx 配置是否已存在
    if [[ -f "/etc/nginx/sites-available/${DOMAIN}.conf" ]]; then
        print_warn "该域名的 Nginx 配置已存在: /etc/nginx/sites-available/${DOMAIN}.conf"
        if ! confirm "是否覆盖?"; then
            pause; return
        fi
    fi
    
    # 证书路径
    local cert_dir="${CERT_PATH_PREFIX}/${DOMAIN}"
    local has_cert=0
    if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/privkey.pem" ]]; then
        print_success "检测到已有证书: ${cert_dir}"
        has_cert=1
    else
        # 尝试查找通配符证书或主域证书
        local parent_domain=$(echo "$DOMAIN" | sed 's/^[^.]*\.//')
        if [[ -f "${CERT_PATH_PREFIX}/${parent_domain}/fullchain.pem" ]]; then
            cert_dir="${CERT_PATH_PREFIX}/${parent_domain}"
            print_success "使用主域证书: ${cert_dir}"
            has_cert=1
        fi
    fi
    if [[ $has_cert -eq 0 ]]; then
        print_warn "未找到证书。"
        echo "  1. 使用菜单 [1.添加域名] 先申请证书再回来配置反代
  2. 手动指定证书路径
"
        read -e -r -p "选择: " cert_opt
        case $cert_opt in
            1) pause; return ;;
            2)
                read -e -r -p "证书公钥路径 (fullchain.pem): " custom_cert
                read -e -r -p "证书私钥路径 (privkey.pem): " custom_key
                if [[ ! -f "$custom_cert" || ! -f "$custom_key" ]]; then
                    print_error "证书文件不存在"; pause; return
                fi
                mkdir -p "$cert_dir"
                cp -L "$custom_cert" "$cert_dir/fullchain.pem"
                cp -L "$custom_key" "$cert_dir/privkey.pem"
                chmod 644 "$cert_dir/fullchain.pem"
                chmod 600 "$cert_dir/privkey.pem"
                has_cert=1
                ;;
            *) pause; return ;;
        esac
    fi
    
    # 后端地址
    local BACKEND_URL=""
    print_guide "输入后端服务地址 (例如 127.0.0.1:8096, 或完整URL http://127.0.0.1:8096)"
    while [[ -z "$BACKEND_URL" ]]; do
        read -e -r -p "后端地址: " inp
        # 纯端口号自动补全
        [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
        # 没有协议头的自动补 http
        if [[ "$inp" =~ ^(http|https):// ]]; then
            BACKEND_URL="$inp"
        elif [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
            BACKEND_URL="http://${inp}"
        else
            print_warn "格式错误，请输入 IP:端口 或完整URL"
        fi
    done
    
    # 端口配置
    local HTTP_PORT HTTPS_PORT
    read -e -r -p "HTTP 端口 [80]: " hp
    HTTP_PORT=${hp:-80}
    validate_port "$HTTP_PORT" || { print_error "端口无效"; pause; return; }
    read -e -r -p "HTTPS 端口 [443]: " sp
    HTTPS_PORT=${sp:-443}
    validate_port "$HTTPS_PORT" || { print_error "端口无效"; pause; return; }
    
    # 生成 SSL 参数文件（如果不存在）
    if [[ ! -f /etc/nginx/snippets/ssl-params.conf ]]; then
        local ssl_params="ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security \"max-age=15768000\" always;"
        write_file_atomic "/etc/nginx/snippets/ssl-params.conf" "$ssl_params"
    fi
    local redir_port=""
    [[ "$HTTPS_PORT" != "443" ]] && redir_port=":${HTTPS_PORT}"
    
    # 根据模板生成 Nginx 配置
    local nginx_conf=""
    if [[ "$template_name" == "emby" ]]; then
        nginx_conf="# Emby/Jellyfin 流媒体反代配置
# Generated by $SCRIPT_NAME $VERSION
# 模板: Emby/Jellyfin 流媒体优化
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
    listen $HTTPS_PORT ssl http2;
    listen [::]:$HTTPS_PORT ssl http2;
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;

    # 流媒体优化参数
    client_max_body_size 128M;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
    send_timeout 86400s;

    # 主页面和 API
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Protocol \$scheme;
        proxy_set_header X-Forwarded-Host \$http_host;
        
        # WebSocket 支持 (Emby/Jellyfin 远程控制)
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        
        # 流媒体缓冲优化
        proxy_buffering off;
        proxy_request_buffering off;
    }

    # WebSocket 端点
    location /embywebsocket {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }

    # Jellyfin WebSocket 端点
    location /socket {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}"
    else
        # 通用反代模板
        nginx_conf="# 通用反向代理配置
# Generated by $SCRIPT_NAME $VERSION
# 模板: 通用
server {
    listen $HTTP_PORT;
    listen [::]:$HTTP_PORT;
    server_name $DOMAIN;
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
    listen $HTTPS_PORT ssl http2;
    listen [::]:$HTTPS_PORT ssl http2;
    server_name $DOMAIN;
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass $BACKEND_URL;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }
}"
    fi
    local NGINX_CONF_PATH="/etc/nginx/sites-available/${DOMAIN}.conf"
    write_file_atomic "$NGINX_CONF_PATH" "$nginx_conf"
    ln -sf "$NGINX_CONF_PATH" "/etc/nginx/sites-enabled/${DOMAIN}.conf"
    # 测试并加载配置
    if nginx -t >/dev/null 2>&1; then
        if is_systemd; then
            systemctl reload nginx || systemctl restart nginx
        else
            nginx -s reload 2>/dev/null || service nginx reload
        fi
        print_success "Nginx 反代配置已生效。"
    else
        print_error "Nginx 配置测试失败！"
        nginx -t 2>&1 | tail -5
        rm -f "/etc/nginx/sites-enabled/${DOMAIN}.conf"
        rm -f "$NGINX_CONF_PATH"
        pause; return
    fi
    
    # 防火墙规则
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$HTTP_PORT/tcp" comment "ReverseProxy-HTTP" >/dev/null 2>&1 || true
        ufw allow "$HTTPS_PORT/tcp" comment "ReverseProxy-HTTPS" >/dev/null 2>&1 || true
        print_success "防火墙规则已更新。"
    fi
    draw_line
    print_success "反向代理配置完成！"
    draw_line
    echo -e "${C_CYAN}[访问地址]${C_RESET}"
    echo "  https://${DOMAIN}${redir_port}"
    echo -e "\n${C_CYAN}[反代后端]${C_RESET}"
    echo "  $BACKEND_URL"
    echo -e "\n${C_CYAN}[模板]${C_RESET}"
    echo "  $( [[ "$template_name" == "emby" ]] && echo "Emby/Jellyfin 流媒体优化" || echo "通用")"
    echo -e "\n${C_CYAN}[配置文件]${C_RESET}"
    echo "  $NGINX_CONF_PATH"
    draw_line
    log_action "Reverse proxy configured: $DOMAIN -> $BACKEND_URL (template=$template_name)"
    pause
}

web_edit_reverse_proxy() {
    print_title "修改反向代理后端地址"
    if ! command_exists nginx; then
        print_error "Nginx 未安装。"
        pause; return
    fi
    shopt -s nullglob
    local confs=(/etc/nginx/sites-available/*.conf)
    shopt -u nullglob
    if [[ ${#confs[@]} -eq 0 ]]; then
        print_warn "未找到 Nginx 反代配置。"
        pause; return
    fi
    local i=1 domains=() files=()
    echo "请选择要修改的站点:"
    for conf in "${confs[@]}"; do
        local domain=$(basename "$conf" .conf)
        local backend=$(grep -oP 'proxy_pass\s+\K[^;]+' "$conf" | head -1)
        echo -e "  $i. ${C_CYAN}${domain}${C_RESET} → ${backend:-未知}"
        domains+=("$domain")
        files+=("$conf")
        ((i++))
    done
    echo "  0. 返回"
    read -e -r -p "选择: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if ! [[ "$idx" =~ ^[0-9]+$ ]] || [[ "$idx" -lt 1 || "$idx" -gt ${#files[@]} ]]; then
        print_error "无效序号"; pause; return
    fi
    local target_conf="${files[$((idx-1))]}"
    local target_domain="${domains[$((idx-1))]}"
    local current_backend=$(grep -oP 'proxy_pass\s+\K[^;]+' "$target_conf" | head -1)
    echo ""
    echo -e "当前后端: ${C_YELLOW}${current_backend}${C_RESET}"
    echo ""
    print_guide "输入新的后端地址 (例如 127.0.0.1:8096, 或完整URL http://127.0.0.1:8096)"
    local new_backend=""
    while [[ -z "$new_backend" ]]; do
        read -e -r -p "新后端地址 (留空取消): " inp
        [[ -z "$inp" ]] && return
        [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
        if [[ "$inp" =~ ^(http|https):// ]]; then
            new_backend="$inp"
        elif [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
            new_backend="http://${inp}"
        else
            print_warn "格式错误，请输入 IP:端口 或完整URL"
        fi
    done
    if [[ "$new_backend" == "$current_backend" ]]; then
        print_warn "新地址与当前相同，无需修改。"
        pause; return
    fi
    cp "$target_conf" "${target_conf}.bak"
    sed -i "s|proxy_pass ${current_backend};|proxy_pass ${new_backend};|g" "$target_conf"
    if nginx -t >/dev/null 2>&1; then
        if is_systemd; then
            systemctl reload nginx || systemctl restart nginx
        else
            nginx -s reload 2>/dev/null || service nginx reload
        fi
        rm -f "${target_conf}.bak"
        print_success "反向代理后端已更新: ${target_domain}"
        echo -e "  ${current_backend} → ${C_GREEN}${new_backend}${C_RESET}"
    else
        mv "${target_conf}.bak" "$target_conf"
        print_error "Nginx 配置测试失败，已回滚。"
        nginx -t 2>&1 | tail -5
    fi
    log_action "Reverse proxy backend updated: $target_domain ${current_backend} -> ${new_backend}"
    pause
}

web_cert_overview() {
    print_title "证书状态总览"
    shopt -s nullglob
    local conf_files=("${CONFIG_DIR}"/*.conf)
    shopt -u nullglob
    if [[ ${#conf_files[@]} -eq 0 ]]; then
        print_warn "当前没有已管理的域名。"
        pause; return
    fi
    printf "${C_CYAN}%-4s %-32s %-14s %-22s %s${C_RESET}\n" "#" "域名" "剩余天数" "过期时间" "状态"
    draw_line
    local i=1 warn_count=0 expired_count=0 ok_count=0 missing_count=0
    for conf in "${conf_files[@]}"; do
        local d=$(grep '^DOMAIN=' "$conf" | cut -d'"' -f2)
        [[ -z "$d" ]] && continue
        local cert_path="${CERT_PATH_PREFIX}/${d}"
        local fullchain="${cert_path}/fullchain.pem"
        local days_str expiry_str status_str
        if [[ -f "$fullchain" ]]; then
            local end_date
            end_date=$(openssl x509 -enddate -noout -in "$fullchain" 2>/dev/null | cut -d= -f2)
            if [[ -n "$end_date" ]]; then
                local end_epoch now_epoch days_left
                end_epoch=$(date -d "$end_date" +%s 2>/dev/null || echo 0)
                now_epoch=$(date +%s)
                days_left=$(( (end_epoch - now_epoch) / 86400 ))
                expiry_str=$(date -d "$end_date" '+%Y-%m-%d' 2>/dev/null || echo "$end_date")
                if [[ $days_left -lt 0 ]]; then
                    days_str="${C_RED}已过期${C_RESET}"
                    status_str="${C_RED}✗ 过期${C_RESET}"
                    expired_count=$((expired_count + 1))
                elif [[ $days_left -lt 7 ]]; then
                    days_str="${C_RED}${days_left} 天${C_RESET}"
                    status_str="${C_RED}! 紧急${C_RESET}"
                    warn_count=$((warn_count + 1))
                elif [[ $days_left -lt 30 ]]; then
                    days_str="${C_YELLOW}${days_left} 天${C_RESET}"
                    status_str="${C_YELLOW}△ 即将过期${C_RESET}"
                    warn_count=$((warn_count + 1))
                else
                    days_str="${C_GREEN}${days_left} 天${C_RESET}"
                    status_str="${C_GREEN}✓ 正常${C_RESET}"
                    ok_count=$((ok_count + 1))
                fi
            else
                expiry_str="解析失败"
                days_str="-"
                status_str="${C_RED}? 异常${C_RESET}"
                missing_count=$((missing_count + 1))
            fi
        else
            expiry_str="无证书文件"
            days_str="-"
            status_str="${C_RED}✗ 缺失${C_RESET}"
            missing_count=$((missing_count + 1))
        fi
        printf "%-4s %-32s %-24b %-22s %b\n" "$i" "$d" "$days_str" "$expiry_str" "$status_str"
        ((i++))
    done
    draw_line
    local total=$((ok_count + warn_count + expired_count + missing_count))
    echo -e "共 ${C_CYAN}${total}${C_RESET} 个域名: ${C_GREEN}正常 ${ok_count}${C_RESET} | ${C_YELLOW}警告 ${warn_count}${C_RESET} | ${C_RED}过期 ${expired_count}${C_RESET} | ${C_RED}缺失 ${missing_count}${C_RESET}"
    if [[ $warn_count -gt 0 || $expired_count -gt 0 ]]; then
        echo ""
        print_warn "有证书需要关注，建议使用 [8.手动续签] 进行续签。"
    fi
    pause
}

menu_web() {
    fix_terminal
    while true; do
        print_title "Web 服务管理 (SSL + Nginx + DDNS)"
        local cert_count=$(ls -1 "$CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
        local ddns_count=$(ls -1 "$DDNS_CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
        local saas_count=$(ls -1 "$SAAS_CONFIG_DIR"/*.conf 2>/dev/null | wc -l)
        echo -e "证书域名: ${C_GREEN}${cert_count}${C_RESET} | DDNS域名: ${C_GREEN}${ddns_count}${C_RESET} | SaaS加速: ${C_GREEN}${saas_count}${C_RESET}"
        [[ $ddns_count -gt 0 ]] && crontab -l 2>/dev/null | grep -q "ddns-update.sh" && echo -e "DDNS状态: ${C_GREEN}运行中${C_RESET}"
        echo -e "${C_CYAN}--- 域名管理 ---${C_RESET}"
        echo "1. 添加域名 (申请证书 + 配置反代 + DDNS)
2. 查看已配置域名详情
3. 删除域名配置
"
        echo -e "${C_CYAN}--- DNS & DDNS ---${C_RESET}"
        echo "4. Cloudflare DNS 解析 (支持 DDNS)
5. 查看 DDNS 配置
6. 删除 DDNS 配置
7. 立即更新 DDNS
"
        echo -e "${C_CYAN}--- 证书维护 ---${C_RESET}"
        echo "8. 手动续签所有证书
9. 查看日志 (证书/DDNS)
"
        echo -e "${C_CYAN}--- SaaS 优选加速 ---${C_RESET}"
        echo "10. 配置 SaaS 优选加速 (CF CDN 优选)
11. 查看 SaaS 优选配置
12. 删除 SaaS 优选配置
"
        echo -e "${C_CYAN}--- 回源规则 (解决端口封锁) ---${C_RESET}"
        echo "13. 创建回源规则 (Origin Rules)
14. 查看回源规则
15. 删除回源规则
"
        echo -e "${C_CYAN}--- 反向代理 ---${C_RESET}"
        echo "16. 添加反代网站 (Emby/Jellyfin/通用)
17. 修改反代后端地址
"
        echo -e "${C_CYAN}--- 证书总览 ---${C_RESET}"
        echo "18. 证书状态总览
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) web_add_domain ;;
            2) web_view_config ;;
            3) web_delete_domain ;;
            4) web_env_check && web_cf_dns_update || pause ;;
            5) ddns_list ;;
            6) ddns_delete ;;
            7) ddns_force_update ;;
            8)
                print_title "手动续签证书"
                command_exists certbot || { print_error "Certbot 未安装"; pause; continue; }
                echo "1. 常规续签 (仅续签即将过期的证书)
2. 强制续签 (忽略过期时间，可能触发 Let's Encrypt 频率限制)"
                read -e -r -p "选择 [1]: " renew_mode
                renew_mode=${renew_mode:-1}
                print_info "正在续签..."
                if [[ "$renew_mode" == "2" ]]; then
                    print_warn "强制续签: Let's Encrypt 限制每周 5 次相同证书"
                    if confirm "确认强制续签?"; then
                        certbot renew --force-renewal 2>&1 | tee /tmp/certbot-renew.log
                        local renew_rc=${PIPESTATUS[0]}
                    else
                        pause; continue
                    fi
                else
                    certbot renew 2>&1 | tee /tmp/certbot-renew.log
                    local renew_rc=${PIPESTATUS[0]}
                fi
                if [[ ${renew_rc:-1} -ne 0 ]]; then
                    print_warn "证书续签可能失败 (退出码: ${renew_rc})"
                fi
                shopt -s nullglob
                for hook in "${CERT_HOOKS_DIR}"/*.sh /root/cert-renew-hook-*.sh; do
                    [[ -x "$hook" ]] && bash "$hook"
                done
                shopt -u nullglob
                log_action "Manual cert renewal (mode=$renew_mode)"
                pause
                ;;
            9)
                echo "1. 证书续签日志  2. DDNS 更新日志"
                read -e -r -p "选择: " lc
                case $lc in
                    1) [[ -f /var/log/cert-renew.log ]] && tail -n 50 /var/log/cert-renew.log || print_warn "无日志" ;;
                    2) [[ -f "$DDNS_LOG" ]] && tail -n 50 "$DDNS_LOG" || print_warn "无日志" ;;
                esac
                pause
                ;;
            10) web_cf_saas_setup ;;
            11) web_cf_saas_status ;;
            12) web_cf_saas_delete ;;
            13) web_cf_origin_rule_create ;;
            14) web_cf_origin_rule_list ;;
            15) web_cf_origin_rule_delete ;;
            16) web_reverse_proxy_site ;;
            17) web_edit_reverse_proxy ;;
            18) web_cert_overview ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
