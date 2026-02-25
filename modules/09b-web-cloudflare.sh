# modules/09b-web-cloudflare.sh - Cloudflare API / SaaS / Origin Rules / DNS

# ── CF API 核心 ──

_cf_api() {
    # 基础速率保护：防止触发 CF API 1200 req/5min 限制
    sleep 0.3
    local method=$1 endpoint=$2 token=$3; shift 3
    local attempt resp
    for attempt in 1 2 3; do
        resp=$(curl -s --max-time 30 -X "$method" "https://api.cloudflare.com/client/v4${endpoint}" \
            -H "Authorization: Bearer $token" \
            -H "Content-Type: application/json" "$@" 2>/dev/null)
        # 成功获取响应则返回
        [[ -n "$resp" ]] && { echo "$resp"; return 0; }
        # 重试前等待（指数退避）
        [[ $attempt -lt 3 ]] && sleep $((attempt * 2))
    done
    # 3 次全失败，返回错误 JSON
    echo '{"success":false,"errors":[{"message":"API 请求超时（已重试 3 次）"}]}'
    return 1
}

_cf_api_ok() { [[ "$(jq -r '.success' <<< "$1")" == "true" ]]; }
_cf_api_err() { jq -r '.errors[0].message // "未知错误"' <<< "$1"; }

# CF API Token 验证
_cf_verify_token() {
    local token="$1"
    local vr=$(_cf_api GET "/user/tokens/verify" "$token")
    if ! _cf_api_ok "$vr"; then
        print_error "Token 验证失败: $(_cf_api_err "$vr")"
        return 1
    fi
    return 0
}

# 读取并验证 CF API Token
_cf_read_token() {
    local _var_name="${1:-CF_API_TOKEN}"
    local token=""
    while [[ -z "$token" ]]; do
        read -s -r -p "Cloudflare API Token: " token; echo ""
    done
    print_info "验证 Token..."
    if ! _cf_verify_token "$token"; then
        return 1
    fi
    print_success "Token 有效"
    printf -v "$_var_name" '%s' "$token"
    return 0
}

# ── DNS 操作 ──

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

# 通用 DNS 记录更新
_cf_update_dns_record() {
    local zone_id="$1" token="$2" domain="$3" type="$4" ip="$5" proxied="$6"
    [[ -z "$ip" ]] && return 0
    print_info "处理 $type 记录 -> $ip (代理: $proxied)"
    local records=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain" "$token")
    local record_id=$(jq -r '.result[0].id // empty' <<< "$records")
    local count=$(jq -r '.result | length' <<< "$records")
    [[ "$count" -gt 1 ]] && print_warn "警告: 存在 ${count} 条 $type 记录，仅更新第一条。建议手动清理多余记录。"
    local data=$(jq -n --arg type "$type" --arg name "$domain" --arg content "$ip" --argjson proxied "$proxied" \
        '{type:$type, name:$name, content:$content, ttl:1, proxied:$proxied}')
    local resp
    if [[ -n "$record_id" ]]; then
        resp=$(_cf_api PUT "/zones/$zone_id/dns_records/$record_id" "$token" --data "$data")
    else
        resp=$(_cf_api POST "/zones/$zone_id/dns_records" "$token" --data "$data")
    fi
    if _cf_api_ok "$resp"; then
        print_success "$([[ -n "$record_id" ]] && echo '更新' || echo '创建')成功"
        return 0
    else
        print_error "$([[ -n "$record_id" ]] && echo '更新' || echo '创建')失败: $(_cf_api_err "$resp")"
        return 1
    fi
}

# ── DNS 智能解析 ──

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
    # IPv6 格式校验：必须包含冒号
    [[ -n "$ipv6" && ! "$ipv6" =~ : ]] && { print_warn "IPv6 探测结果异常 ($ipv6)，已忽略"; ipv6=""; }
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
    # 选择 IPv6 但未检测到时给予提示
    if [[ ("$mode" == "2" || "$mode" == "3") && -z "$ipv6" ]]; then
        print_warn "未检测到 IPv6 地址，AAAA 记录将跳过"
    fi
    if [[ ("$mode" == "1" || "$mode" == "3") && -z "$ipv4" ]]; then
        print_warn "未检测到 IPv4 地址，A 记录将跳过"
    fi
    # 读取并验证 Token
    if ! _cf_read_token "CF_API_TOKEN"; then
        pause; return
    fi
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

    # 使用提取的模块级函数
    case $mode in
        1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied" ;;
        2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" ;;
        3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$proxied"
           _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$proxied" ;;
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

# ── SaaS 优选加速 ──

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
    if [[ ${#pd_arr[@]} -eq 0 ]]; then
        print_warn "未配置预设优选域名列表 (SAAS_PREFERRED_DOMAINS 为空)"
    fi
    echo "  $i. 自定义输入"
    local pd_choice preferred_domain
    read -e -r -p "选择 [${#pd_arr[@]} -gt 0 && echo 1 || echo $i]: " pd_choice
    pd_choice=${pd_choice:-$([[ ${#pd_arr[@]} -gt 0 ]] && echo 1 || echo $i)}
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

# ── Origin Rules ──

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

# ── SaaS 状态和删除 ──

web_cf_saas_status() {
    print_title "查看 SaaS 优选配置"
    if [[ ! -d "$SAAS_CONFIG_DIR" ]] || [[ -z "$(ls -A "$SAAS_CONFIG_DIR" 2>/dev/null)" ]]; then
        print_warn "暂无 SaaS 优选配置"
        pause; return
    fi
    echo -e "${C_CYAN}业务域名                       状态       优选域名                       回源域名             创建时间${C_RESET}"
    draw_line
    for conf in "$SAAS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        local SAAS_STATUS="" BIZ_DOMAIN="" PREFERRED_DOMAIN="" ORIGIN_DOMAIN="" CREATED=""
        validate_conf_file "$conf" || continue
        _safe_source_conf "$conf"
        local status_icon="${C_GREEN}✓${C_RESET}"
        [[ "$SAAS_STATUS" == "pending" ]] && status_icon="${C_YELLOW}…${C_RESET}"
        echo -e "  ${BIZ_DOMAIN}  ${status_icon} ${SAAS_STATUS}  ${PREFERRED_DOMAIN}  ${ORIGIN_DOMAIN}  ${CREATED}"
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
        _safe_source_conf "$conf"
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
    _safe_source_conf "$target_conf"
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
