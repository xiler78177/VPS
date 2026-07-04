# modules/09e-web-home-expose.sh - 家宽内网服务公网暴露（一键配置）
# 整合 DNS + 证书 + Nginx + DDNS + Origin Rules 为一条龙流程

_web_home_expose_rollback() {
    local domain="$1" zone_id="$2" token="$3" dns_snapshot="$4" restore_dns="${5:-0}"
    local origin_rules_snapshot="${6:-}" restore_origin="${7:-0}" cleanup_local="${8:-0}"

    if [[ "$restore_origin" == "1" && -n "$origin_rules_snapshot" ]]; then
        print_warn "配置失败，正在恢复 Cloudflare Origin Rules 快照..."
        _cf_origin_rules_restore "$token" "$zone_id" "$origin_rules_snapshot" || \
            print_warn "Origin Rules 快照恢复失败，请人工核查 ${domain} 的回源规则"
    fi
    if [[ "$restore_dns" == "1" && -n "$dns_snapshot" ]]; then
        print_warn "配置失败，正在恢复 Cloudflare DNS 快照..."
        _cf_dns_restore_records "$zone_id" "$token" "$domain" "$dns_snapshot" A AAAA CNAME || \
            print_warn "Cloudflare DNS 快照恢复失败，请人工核查 ${domain} 的 A/AAAA/CNAME 记录"
    fi
    if [[ "$cleanup_local" == "1" ]]; then
        print_warn "正在清理本地半成品..."
        _web_cleanup_domain "$domain" "quiet" || true
    fi
}

web_home_expose() {
    print_title "家宽内网服务公网暴露（一键配置）"
    echo -e "${C_CYAN}将家庭宽带内网服务通过 DDNS + CF + HTTPS 暴露到公网${C_RESET}"
    echo -e "  适用: Alist / Jellyfin / NAS / HomeAssistant 等"
    echo -e "  自动完成: DNS -> 证书 -> Nginx -> DDNS -> 回源规则"

    # 依赖检查
    web_env_check || { pause; return; }

    # Phase 1: 一次性收集所有配置信息
    echo -e "\n${C_CYAN}=== 第一阶段: 收集配置信息 ===${C_RESET}\n"

    # 1. CF API Token
    local token=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 -> My Profile -> API Tokens -> Create Token${C_RESET}"
    while [[ -z "$token" ]]; do
        read -s -r -p "API Token: " token; echo ""
    done
    print_info "验证 Token..."
    if ! _cf_verify_token "$token"; then
        pause; return
    fi
    print_success "Token 有效"

    # 2. 选择域名 (自动列出 Token 可管理的域名)
    print_info "获取 Token 可管理的域名列表..."
    local zones_json zone_list=() zone_ids=()
    zones_json=$(_cf_list_zones "$token" "status=active")
    if ! _cf_api_ok "$zones_json"; then
        print_error "获取域名列表失败: $(_cf_api_err "$zones_json")"
        pause; return
    fi
    while IFS='|' read -r zname zid; do
        [[ -z "$zname" ]] && continue
        zone_list+=("$zname")
        zone_ids+=("$zid")
    done < <(echo "$zones_json" | jq -r '.result[] | "\(.name)|\(.id)"')

    if [[ ${#zone_list[@]} -eq 0 ]]; then
        print_error "该 Token 无可管理的域名，请检查 Token 权限"
        pause; return
    fi

    echo -e "${C_CYAN}可用域名:${C_RESET}"
    for i in "${!zone_list[@]}"; do
        echo "  $((i+1)). ${zone_list[$i]}"
    done
    local zone_choice
    while true; do
        read -e -r -p "选择域名 [1]: " zone_choice
        zone_choice=${zone_choice:-1}
        if [[ "$zone_choice" =~ ^[0-9]+$ ]] && (( zone_choice >= 1 && zone_choice <= ${#zone_list[@]} )); then
            break
        fi
        print_warn "请输入 1-${#zone_list[@]}"
    done
    local root_domain="${zone_list[$((zone_choice-1))]}"
    local zone_id="${zone_ids[$((zone_choice-1))]}"
    print_success "已选择: ${root_domain} (Zone: ${zone_id})"

    # 3. (SaaS 优选已移除 - CF NS 接入不支持，需第三方 DNS)

    # 4. 子域名前缀
    local sub_prefix=""
    print_guide "输入子域名前缀"
    echo -e "  ${C_GRAY}例如输入 alist -> 访问地址为 alist.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}例如输入 nas -> 访问地址为 nas.${root_domain}${C_RESET}"
    while true; do
        read -e -r -p "子域名前缀: " sub_prefix
        if [[ -z "$sub_prefix" ]]; then
            print_warn "不能为空"
            continue
        fi
        validate_dns_label "$sub_prefix" && break
        print_error "子域名前缀格式无效（仅小写字母、数字、短横；首尾不能为短横，1-63 字符）"
        sub_prefix=""
    done
    local full_domain="${sub_prefix}.${root_domain}"

    # 检查是否已有配置
    if [[ -f "${CONFIG_DIR}/${full_domain}.conf" ]] || \
       [[ -f "/etc/nginx/sites-available/${full_domain}.conf" ]]; then
        print_warn "${full_domain} 已有配置 (域名/Nginx/DDNS 等)"
        if ! confirm "自动清除旧配置并重新配置？"; then pause; return; fi
        print_info "清理旧配置..."
        _web_cleanup_domain "$full_domain" "quiet"
    fi

    # 5. 后端服务地址
    local backend_addr=""
    print_guide "内网服务地址 (IP:端口)"
    echo -e "  ${C_GRAY}服务在本机: 直接输入端口号即可，如 5244${C_RESET}"
    echo -e "  ${C_GRAY}服务在其他设备: 输入 IP:端口，如 192.168.1.100:5244${C_RESET}"
    echo -e "  ${C_GRAY}常用端口: Alist 5244, Jellyfin/Emby 8096${C_RESET}"
    while true; do
        read -e -r -p "后端地址 [127.0.0.1:5244]: " backend_addr
        backend_addr=${backend_addr:-"127.0.0.1:5244"}
        # 只输入了端口号，自动补 127.0.0.1
        if [[ "$backend_addr" =~ ^[0-9]+$ ]]; then
            if (( backend_addr >= 1 && backend_addr <= 65535 )); then
                backend_addr="127.0.0.1:${backend_addr}"
                break
            fi
            print_warn "端口无效，请输入 1-65535"
            continue
        fi
        # IP:端口 格式校验
        if [[ "$backend_addr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
            local _bport=${backend_addr##*:}
            if (( _bport >= 1 && _bport <= 65535 )); then
                break
            fi
        fi
        print_warn "格式无效，请输入 端口号 或 IP:端口"
    done
    print_success "后端地址: ${backend_addr}"

    # 6. Nginx HTTPS 监听端口
    local https_port="" requested_https_port="" origin_rule_needed=0
    print_guide "Nginx HTTPS 监听端口 (对外暴露的端口)"
    echo -e "  ${C_GRAY}家宽通常 443 被封，建议用 8443${C_RESET}"
    echo -e "  ${C_GRAY}CF 支持的 HTTPS 端口: 443 2053 2083 2087 2096 8443${C_RESET}"
    while true; do
        read -e -r -p "HTTPS 端口 [8443]: " https_port
        https_port=${https_port:-8443}
        if [[ "$https_port" =~ ^[0-9]+$ ]] && (( https_port >= 1 && https_port <= 65535 )); then
            break
        fi
        print_warn "端口无效"
    done
    requested_https_port="$https_port"
    # Reality 443 共存：用户选择 443 时，Nginx 下沉到 web 内部端口；公网 443 由 stream 分流。
    https_port="$(_web_coexist_https_port "$https_port")"
    if [[ "$https_port" != "443" ]]; then
        if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
            origin_rule_needed=0
        else
            origin_rule_needed=1
        fi
    fi


    # 7. DDNS 间隔
    local ddns_interval=""
    read -e -r -p "DDNS 检测间隔(分钟, 1-59) [5]: " ddns_interval
    ddns_interval=${ddns_interval:-5}
    if [[ ! "$ddns_interval" =~ ^[0-9]+$ ]] || (( ddns_interval < 1 || ddns_interval > 59 )); then
        print_warn "间隔无效，使用默认值 5"
        ddns_interval=5
    fi

    # 8. 探测公网 IP
    print_info "探测公网 IP..."
    local public_ip=""
    public_ip=$(get_public_ipv4)
    if [[ -z "$public_ip" ]]; then
        print_warn "未自动检测到 IPv4，请手动输入"
        read -e -r -p "公网 IPv4: " public_ip
        if ! validate_ip "$public_ip"; then
            print_error "IP 格式无效"; pause; return
        fi
    fi
    print_success "公网 IP: $public_ip"

    # 配置确认
    echo ""
    draw_line
    echo -e "${C_CYAN}配置确认:${C_RESET}"
    echo -e "  访问域名:     ${C_GREEN}${full_domain}${C_RESET}"
    echo -e "  根域名:       ${C_GREEN}${root_domain}${C_RESET} (Zone: ${zone_id})"
    echo -e "  公网 IP:      ${C_GREEN}${public_ip}${C_RESET}"
    echo -e "  后端地址:     ${C_GREEN}${backend_addr}${C_RESET} (内网服务)"
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        echo -e "  HTTPS 端口:   ${C_GREEN}${requested_https_port}${C_RESET} (对外) / ${C_GREEN}${https_port}${C_RESET} (Nginx 内部监听)"
    else
        echo -e "  HTTPS 端口:   ${C_GREEN}${https_port}${C_RESET} (Nginx 对外监听)"
    fi
    echo -e "  DDNS 间隔:    ${C_GREEN}${ddns_interval} 分钟${C_RESET}"
    echo -e "  加速模式:     ${C_GREEN}CF CDN 代理${C_RESET} (A 记录 + Proxied)"
    echo ""
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    local auto_step=1
    echo -e "    ${auto_step}. DNS 解析 -> ${full_domain} -> ${public_ip} (CF 代理)"; ((auto_step++))
    echo -e "    ${auto_step}. SSL 证书申请 (Let's Encrypt DNS 验证)"; ((auto_step++))
    echo -e "    ${auto_step}. Nginx 反向代理 (:${https_port} -> ${backend_addr})"; ((auto_step++))
    echo -e "    ${auto_step}. DDNS 自动更新 (每 ${ddns_interval} 分钟)"; ((auto_step++))
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        echo -e "    ${auto_step}. 共存模式刷新 SNI 白名单（公网 443 -> 内部 ${https_port}）"; ((auto_step++))
    else
        echo -e "    ${auto_step}. 防火墙放行端口 ${https_port}"; ((auto_step++))
    fi
    [[ "$origin_rule_needed" -eq 1 ]] && { echo -e "    ${auto_step}. CF Origin Rule (用户 :443 -> 回源 :${https_port})"; ((auto_step++)); }
    echo ""
    echo -e "  ${C_YELLOW}[手动操作提醒]${C_RESET}"
    echo -e "  ${C_YELLOW}  请确保路由器 (OpenWrt/爱快等) 已做端口转发:${C_RESET}"
    echo -e "  ${C_YELLOW}  外网 ${requested_https_port}/TCP -> 内网运行 Nginx 的设备IP:${requested_https_port}/TCP${C_RESET}"
    if [[ "$backend_addr" != 127.0.0.1:* ]]; then
        echo -e "  ${C_YELLOW}  后端服务在其他设备 (${backend_addr})，请确保内网互通${C_RESET}"
    fi
    draw_line
    if ! confirm "确认开始执行?"; then
        print_warn "已取消"; pause; return
    fi

    # Phase 2: 自动执行
    local step=1 total_steps=5
    local dns_snapshot="" dns_restore_needed=0 origin_rules_snapshot="" origin_restore_needed=0
    [[ "$origin_rule_needed" -eq 1 ]] && total_steps=$((total_steps + 1))

    # Step: DNS 解析
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DNS 解析 ===${C_RESET}"
    dns_snapshot=$(_cf_dns_snapshot_records "$zone_id" "$token" "$full_domain" A AAAA CNAME) || {
        print_error "DNS 快照创建失败，已中止以避免后续失败无法恢复 Cloudflare 远端状态"
        pause; return 1
    }
    dns_restore_needed=1
    # 重新配置时可能残留旧 CNAME，CF 不允许同名 A/CNAME 共存，需先清除
    if ! _cf_dns_delete "$zone_id" "$token" "CNAME" "$full_domain"; then
        print_error "清理旧 CNAME 记录失败，已中止以避免 A/CNAME 冲突或覆盖失败。"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 0
        pause; return 1
    fi
    print_info "创建 A 记录: ${full_domain} -> ${public_ip} (开启 CF 代理)"
    if ! _cf_update_dns_record "$zone_id" "$token" "$full_domain" "A" "$public_ip" "true"; then
        print_error "DNS 记录创建失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 0
        pause; return 1
    fi
    ((step++))

    # Step: SSL 证书
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] SSL 证书申请 ===${C_RESET}"
    local cert_dir="${CERT_PATH_PREFIX}/${full_domain}"
    mkdir -p "$cert_dir" || {
        print_error "证书目录创建失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    local cf_cred="/root/.cloudflare-${full_domain}.ini"
    write_private_file_atomic "$cf_cred" "dns_cloudflare_api_token = $token" || {
        print_error "Cloudflare 凭据写入失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    print_info "正在申请证书 (DNS 验证，可能需要 1-2 分钟)..."
    if certbot certonly \
        --dns-cloudflare \
        --dns-cloudflare-credentials "$cf_cred" \
        --dns-cloudflare-propagation-seconds 60 \
        -d "$full_domain" \
        --email "$EMAIL" \
        --agree-tos \
        --no-eff-email \
        --non-interactive; then
        copy_cert_pair_atomic "/etc/letsencrypt/live/${full_domain}/fullchain.pem" "/etc/letsencrypt/live/${full_domain}/privkey.pem" "$cert_dir" || {
            print_error "证书复制失败"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
        print_success "证书获取成功"
    else
        print_error "证书申请失败！请检查 Token 权限和网络"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    ((step++))

    # Step: Nginx 反向代理
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] Nginx 反向代理 ===${C_RESET}"
    _ensure_ssl_params
    local redir_port
    redir_port="$(_web_coexist_redir_suffix "$https_port")"
    local nginx_conf="# 家宽公网暴露 - ${full_domain}
# Generated by $SCRIPT_NAME $VERSION (web_home_expose)
server {
    listen 80;
    listen [::]:80;
    server_name ${full_domain};
    return 301 https://\$host${redir_port}\$request_uri;
}
server {
$(_nginx_tls_http2_block "$https_port")
    server_name ${full_domain};
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    client_max_body_size 50M;
    location / {
        proxy_pass http://${backend_addr};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \"upgrade\";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
        proxy_request_buffering off;
    }
}"
    if ! _nginx_deploy_conf "$full_domain" "$nginx_conf"; then
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    print_success "Nginx 已部署 (:${https_port} -> ${backend_addr})"
    # 443 共存模式：把本站域名加入 stream SNI 白名单（未启用则 no-op）
    declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
    ((step++))

    # Step: DDNS
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] DDNS 动态解析 ===${C_RESET}"
    local ddns_domain="$full_domain"
    local ddns_proxied="true"
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN=\"${ddns_domain}\"
DDNS_TOKEN=\"${token}\"
DDNS_ZONE_ID=\"${zone_id}\"
DDNS_IPV4=\"true\"
DDNS_IPV6=\"false\"
DDNS_PROXIED=\"${ddns_proxied}\"
DDNS_INTERVAL=\"${ddns_interval}\""
    write_private_file_atomic "$DDNS_CONFIG_DIR/${ddns_domain}.conf" "$ddns_conf_content" || {
        print_error "DDNS 配置写入失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    ddns_create_script || {
        print_error "DDNS 更新脚本生成失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    ddns_rebuild_cron || {
        print_error "DDNS cron 更新失败"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    }
    print_success "DDNS 已配置: ${ddns_domain} (每 ${ddns_interval} 分钟)"
    ((step++))

    # Step: 防火墙
    echo -e "\n${C_CYAN}=== [${step}/${total_steps}] 防火墙 ===${C_RESET}"
    if declare -F _web_coexist_is_inner_port >/dev/null && _web_coexist_is_inner_port "$https_port"; then
        print_info "共存模式：${https_port} 为内部端口，仅 loopback 可达，不放行到公网（对外由 443 提供）"
        if ! command_exists ufw || ! ufw_is_active; then
            print_info "UFW 未启用，跳过 (共存模式请确保服务器防火墙已放行公网 ${requested_https_port})"
        fi
    else
        _web_allow_public_tcp_port "$https_port" "HomeExpose-${full_domain}" "${https_port}/tcp" || {
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
    fi
    ((step++))

    # Step: Origin Rule (公网 443 需回源到非内部端口时)
    if [[ "$origin_rule_needed" -eq 1 ]]; then
        echo -e "\n${C_CYAN}=== [${step}/${total_steps}] CF Origin Rule (端口回源) ===${C_RESET}"
        print_info "创建回源规则: 用户访问 :443 -> CF 回源 :${https_port}"
        local existing
        if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
            print_error "Origin Rules 读取失败，端口回源规则未创建。"
            print_warn "请稍后通过菜单 [10.创建回源规则] 手动添加后再使用该公网 443 入口。"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause
            return 1
        else
            local existing_rules="[]"
            if [[ -n "$existing" ]]; then
                existing_rules=$(echo "$existing" | jq -c '.result.rules // []') || {
                    print_error "Origin Rules 响应解析失败"
                    _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                    pause; return 1
                }
            fi
            origin_rules_snapshot="$existing_rules"
            origin_restore_needed=1
            # 移除同域名旧规则
        local filtered_rules=$(echo "$existing_rules" | jq --arg d "$full_domain" \
            '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]') || {
                print_error "Origin Rules 过滤旧规则失败"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause; return 1
            }
        # 构建新规则
        local new_rule=$(jq -n \
            --arg expr "http.host eq \"${full_domain}\"" \
            --arg desc "HomeExpose-${full_domain}-${https_port}" \
            --argjson port "$https_port" \
            '{
                "action": "route",
                "action_parameters": { "origin": { "port": $port } },
                "expression": $expr,
                "description": $desc,
                "enabled": true
            }') || {
                print_error "Origin Rules 新规则构造失败"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause; return 1
            }
        local final_rules=$(echo "$filtered_rules" | jq --argjson new "$new_rule" '. + [$new]') || {
            print_error "Origin Rules 新旧规则合并失败"
            _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
            pause; return 1
        }
        local err
            if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final_rules"); then
                print_error "Origin Rule 创建失败: $err"
                _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
                pause
                return 1
            else
                print_success "Origin Rule 已创建 (用户 :443 -> 回源 :${https_port})"
            fi
            ((step++))
        fi
    fi

    # Step: SSL/TLS Full 模式
    print_info "设置 SSL/TLS 为 Full 模式..."
    local ssl_resp=$(_cf_api PATCH "/zones/$zone_id/settings/ssl" "$token" \
        --data '{"value":"full"}')
    _cf_api_ok "$ssl_resp" && print_success "SSL/TLS -> Full" || \
        print_warn "SSL 设置: $(_cf_api_err "$ssl_resp") (可能已是 Full)"

    # 保存配置文件 + 证书续签 Hook
    mkdir -p "$CONFIG_DIR" "$CERT_HOOKS_DIR"

    # 续签 Hook 脚本
    local hook_script="${CERT_HOOKS_DIR}/renew-${full_domain}.sh"
    local hook_content="#!/bin/bash
# Auto-generated renewal hook for $full_domain (home expose)
# Generated by $SCRIPT_NAME $VERSION
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DOMAIN=\"$full_domain\"
CERT_DIR=\"${cert_dir}\"
LETSENCRYPT_LIVE=\"/etc/letsencrypt/live/\${DOMAIN}\"
echo \"[\$(date)] Starting renewal hook for \$DOMAIN\" >> /var/log/cert-renew.log

$(render_cert_pair_hook_helper)

if copy_cert_pair_atomic \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${LETSENCRYPT_LIVE}/privkey.pem\" \"\${CERT_DIR}\"; then
    echo \"[\$(date)] Certificates copied successfully\" >> /var/log/cert-renew.log
else
    echo \"[\$(date)] ERROR: Certificate files not found\" >> /var/log/cert-renew.log
    exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl reload nginx 2>&1 | tee -a /var/log/cert-renew.log
else
    nginx -s reload 2>&1 | tee -a /var/log/cert-renew.log
fi
echo \"[\$(date)] Renewal hook completed for \$DOMAIN\" >> /var/log/cert-renew.log
exit 0
"
    if ! write_file_atomic "$hook_script" "$hook_content"; then
        print_error "证书续签 Hook 写入失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    if ! chmod +x "$hook_script"; then
        print_error "证书续签 Hook 权限设置失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi

    # Crontab 自动续签
    local cron_tag="CertRenew_${full_domain}"
    local cron_minute=$(( $(echo "$full_domain" | cksum | cut -d' ' -f1) % 60 ))
    if ! cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${full_domain}' --deploy-hook '${hook_script}' # ${cron_tag}"; then
        print_error "证书续签 cron 安装失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi

    # 域名管理配置文件
    local domain_config_content="# Domain configuration for ${full_domain}
# Generated by $SCRIPT_NAME $VERSION (web_home_expose)
DOMAIN=\"${full_domain}\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"${hook_script}\"
CLOUDFLARE_CREDENTIALS=\"${cf_cred}\"
NGINX_HTTP_PORT=\"80\"
NGINX_HTTPS_PORT=\"${https_port}\"
LOCAL_PROXY_PASS=\"http://${backend_addr}\"
HOME_EXPOSE=\"true\""
    if ! write_file_atomic "${CONFIG_DIR}/${full_domain}.conf" "$domain_config_content"; then
        print_error "域名管理配置写入失败，正在清理本地半成品"
        _web_home_expose_rollback "$full_domain" "$zone_id" "$token" "$dns_snapshot" "$dns_restore_needed" "$origin_rules_snapshot" "$origin_restore_needed" 1
        pause; return 1
    fi
    dns_restore_needed=0
    origin_restore_needed=0

    # 完成报告
    echo ""
    draw_line
    print_success "家宽公网暴露配置完成！"
    draw_line
    echo -e "  ${C_CYAN}[访问地址]${C_RESET}"
    echo -e "    https://${full_domain}"
    echo ""
    echo -e "  ${C_CYAN}[访问链路]${C_RESET}"
    echo -e "    用户 -> ${C_GREEN}${full_domain}${C_RESET} (CF CDN 代理)"
    [[ "$origin_rule_needed" -eq 1 ]] && \
    echo -e "      -> Origin Rule :443 -> :${C_GREEN}${https_port}${C_RESET}"
    echo -e "      -> 家宽路由器 -> 内网 Nginx -> ${C_GREEN}${backend_addr}${C_RESET}"
    echo ""
    echo -e "  ${C_CYAN}[证书]${C_RESET}"
    echo -e "    公钥: ${cert_dir}/fullchain.pem"
    echo -e "    私钥: ${cert_dir}/privkey.pem"
    echo -e "    续签: 每日 3:$(printf '%02d' $cron_minute) AM 自动检查"
    echo ""
    echo -e "  ${C_CYAN}[DDNS]${C_RESET}"
    echo -e "    域名: ${ddns_domain}"
    echo -e "    间隔: 每 ${ddns_interval} 分钟"
    echo ""
    echo -e "  ${C_YELLOW}[路由器操作 - 需要手动完成]${C_RESET}"
    echo -e "    请在路由器 (OpenWrt/爱快等) 做端口转发:"
    echo -e "    外网 ${C_GREEN}${requested_https_port}${C_RESET}/TCP -> 运行 Nginx 的设备IP:${C_GREEN}${requested_https_port}${C_RESET}/TCP"
    if [[ "$backend_addr" != 127.0.0.1:* ]]; then
        echo -e "    后端服务在 ${C_GREEN}${backend_addr}${C_RESET}，请确保内网互通"
    fi
    echo -e "    当前 CF 支持的 HTTPS 代理端口: ${C_GREEN}443 2053 2083 2087 2096 8443${C_RESET}"
    draw_line
    log_action "Home expose configured: ${full_domain} -> ${backend_addr} (port=${https_port})"

    # 可选: 内网 DNS 劫持 (解决 NAT 回环)
    echo ""
    echo -e "${C_CYAN}内网 DNS 劫持 (解决 NAT 回环问题):${C_RESET}"
    echo -e "  ${C_GRAY}问题: 内网设备访问 ${full_domain} -> 解析到公网 IP -> 路由器 -> 无法回环${C_RESET}"
    echo -e "  ${C_GRAY}解决: 在路由器 dnsmasq 添加本地解析，内网直连不走公网${C_RESET}"
    if confirm "是否自动配置路由器内网 DNS 劫持 (需 SSH 到 OpenWrt)?"; then
        # 检测网关 IP
        local gw_ip=""
        gw_ip=$(ip route | grep '^default' | awk '{print $3}' | head -1)
        [[ -z "$gw_ip" ]] && gw_ip="10.10.100.1"
        read -e -r -p "路由器 SSH 地址 [root@${gw_ip}]: " router_ssh
        router_ssh=${router_ssh:-"root@${gw_ip}"}

        # 检测本机内网 IP (Nginx 所在设备)
        local local_ip=""
        local_ip=$(ip route get "${gw_ip}" 2>/dev/null | grep -oP 'src \K[0-9.]+' | head -1)
        [[ -z "$local_ip" ]] && local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
        read -e -r -p "本机内网 IP (运行 Nginx 的设备) [${local_ip}]: " nginx_ip
        nginx_ip=${nginx_ip:-"$local_ip"}

        if [[ -z "$nginx_ip" ]]; then
            print_error "未能检测到内网 IP，请手动输入"
            read -e -r -p "内网 IP: " nginx_ip
            [[ -z "$nginx_ip" ]] && { print_warn "跳过 DNS 劫持配置"; pause; return; }
        fi
        if ! validate_ip "$nginx_ip"; then
            print_error "内网 IP 无效: ${nginx_ip}"
            print_warn "跳过 DNS 劫持配置"
            pause
            return 0
        fi

        echo -e "${C_CYAN}配置预览:${C_RESET}"
        echo -e "  路由器: ${C_GREEN}${router_ssh}${C_RESET}"
        echo -e "  规则:   ${C_GREEN}${full_domain} -> ${nginx_ip}${C_RESET}"
        echo ""
        print_info "正在 SSH 到路由器配置 dnsmasq..."

        # 通过 uci 配置 (兼容所有 OpenWrt 版本)
        local uci_cmds="
DHCP_BACKUP=\$(mktemp /tmp/server-manage-dhcp.XXXXXX 2>/dev/null) || exit 1
cleanup_dhcp_domain() { rm -f \"\$DHCP_BACKUP\" 2>/dev/null; }
rollback_dhcp_domain() {
    rc=\${1:-1}
    if [ -f \"\$DHCP_BACKUP\" ]; then
        uci import dhcp < \"\$DHCP_BACKUP\" >/dev/null 2>&1 || true
        uci commit dhcp >/dev/null 2>&1 || true
        /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    fi
    cleanup_dhcp_domain
    exit \"\$rc\"
}
trap cleanup_dhcp_domain EXIT
uci export dhcp > \"\$DHCP_BACKUP\" || rollback_dhcp_domain 1
# 精确清除: 遍历查找并删除匹配的 domain 条目
idx=0
while uci -q get dhcp.@domain[\$idx] >/dev/null 2>&1; do
    name=\$(uci -q get dhcp.@domain[\$idx].name 2>/dev/null) || rollback_dhcp_domain 1
    if [ \"\$name\" = '${full_domain}' ]; then
        uci delete dhcp.@domain[\$idx] || rollback_dhcp_domain 1
    else
        idx=\$((idx + 1))
    fi
done
# 添加新记录
uci add dhcp domain >/dev/null || rollback_dhcp_domain 1
uci set dhcp.@domain[-1].name='${full_domain}' || rollback_dhcp_domain 1
uci set dhcp.@domain[-1].ip='${nginx_ip}' || rollback_dhcp_domain 1
uci commit dhcp || rollback_dhcp_domain 1
/etc/init.d/dnsmasq restart || rollback_dhcp_domain 1
cleanup_dhcp_domain
		"
        if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new \
            "$router_ssh" "${uci_cmds}" 2>&1; then
            print_success "内网 DNS 劫持配置成功！"
            echo -e "  ${C_GREEN}${full_domain} -> ${nginx_ip}${C_RESET} (内网直连)"
        else
            print_warn "SSH 配置失败，请手动在路由器上执行:"
            echo -e "  ${C_YELLOW}ssh ${router_ssh}${C_RESET}"
            echo -e "  ${C_YELLOW}uci add dhcp domain${C_RESET}"
            echo -e "  ${C_YELLOW}uci set dhcp.@domain[-1].name='${full_domain}'${C_RESET}"
            echo -e "  ${C_YELLOW}uci set dhcp.@domain[-1].ip='${nginx_ip}'${C_RESET}"
            echo -e "  ${C_YELLOW}uci commit dhcp${C_RESET}"
            echo -e "  ${C_YELLOW}/etc/init.d/dnsmasq restart${C_RESET}"
        fi
    fi
    pause
}
