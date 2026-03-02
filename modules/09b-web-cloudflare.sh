# modules/09b-web-cloudflare.sh - Cloudflare API / Origin Rules / DNS

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
    if [[ -n "${_CACHED_IPV4:-}" || -n "${_CACHED_IPV6:-}" ]]; then
        ipv4="$_CACHED_IPV4"; ipv6="$_CACHED_IPV6"
    else
        ipv4=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv4=""
        ipv6=$(curl -6 -s --max-time 5 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv6=""
        _CACHED_IPV4="$ipv4"; _CACHED_IPV6="$ipv6"
    fi
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
        '{ "rules": $rules }')
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
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules"); then
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
    if ! _cf_read_token "token"; then
        pause; return
    fi
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
    if ! _cf_read_token "token"; then
        pause; return
    fi
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
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$new_rules"); then
        print_error "删除失败: $err"; pause; return
    fi
    print_success "规则已删除"
    pause
}

