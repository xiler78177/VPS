# modules/09c-web-domain.sh - 域名管理（添加/查看/删除 + 证书总览 + 续签/日志）

web_add_domain() {
    print_title "添加域名配置 (SSL + Nginx)"
    web_env_check || { pause; return; }

    # ══════════════════════════════════════════════════════════════
    #  配置收集阶段
    # ══════════════════════════════════════════════════════════════
    echo -e "\n${C_CYAN}━━━ 收集配置信息 ━━━${C_RESET}\n"

    # 1. CF API Token
    local CF_API_TOKEN=""
    print_guide "输入 Cloudflare API Token"
    echo -e "  ${C_GRAY}权限需要: Zone.DNS + Zone.SSL${C_RESET}"
    echo -e "  ${C_GRAY}创建: CF 后台 → My Profile → API Tokens → Create Token${C_RESET}"
    if ! _cf_read_token "CF_API_TOKEN"; then
        pause; return
    fi

    # 2. 选择域名 (自动列出 Token 可管理的域名)
    print_info "获取 Token 可管理的域名列表..."
    local zones_json zone_list=() zone_ids=()
    zones_json=$(_cf_api GET "/zones?per_page=50&status=active" "$CF_API_TOKEN")
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

    # 3. 子域名前缀
    local sub_prefix="" DOMAIN=""
    print_guide "输入子域名前缀"
    echo -e "  ${C_GRAY}例如输入 www → 完整域名为 www.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}例如输入 panel → 完整域名为 panel.${root_domain}${C_RESET}"
    echo -e "  ${C_GRAY}直接回车 → 使用根域名 ${root_domain}${C_RESET}"
    read -e -r -p "子域名前缀 [留空=根域名]: " sub_prefix
    if [[ -z "$sub_prefix" ]]; then
        DOMAIN="$root_domain"
    else
        DOMAIN="${sub_prefix}.${root_domain}"
    fi

    # 检查是否已有配置
    if [[ -f "${CONFIG_DIR}/${DOMAIN}.conf" ]]; then
        print_warn "${DOMAIN} 配置已存在"
        if ! confirm "覆盖现有配置？"; then pause; return; fi
    fi

    # 4. Nginx 反向代理
    local do_nginx=0 NGINX_HTTP_PORT="" NGINX_HTTPS_PORT="" BACKEND_PROTOCOL="" LOCAL_PROXY_PASS=""
    if confirm "是否配置 Nginx 反向代理 (用于隐藏后端端口)?"; then
        do_nginx=1
        print_guide "Nginx 监听端口"
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
        print_guide "后端服务地址"
        echo -e "  ${C_GRAY}服务在本机: 直接输入端口号即可，如 54321${C_RESET}"
        echo -e "  ${C_GRAY}服务在其他设备: 输入 IP:端口，如 192.168.1.100:5244${C_RESET}"
        # 支持调用方通过 _WEB_PRESET_PROXY 预填反代目标 (如端口转发联动)
        if [[ -n "${_WEB_PRESET_PROXY:-}" ]]; then
            local _preset_inp="$_WEB_PRESET_PROXY"
            _WEB_PRESET_PROXY=""
            [[ "$_preset_inp" =~ ^[0-9]+$ ]] && _preset_inp="127.0.0.1:$_preset_inp"
            if [[ "$_preset_inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${_preset_inp}"
                print_info "反代目标 (已预填): ${LOCAL_PROXY_PASS}"
            fi
        fi
        while [[ -z "$LOCAL_PROXY_PASS" ]]; do
            read -e -r -p "后端地址 [127.0.0.1:54321]: " inp
            inp=${inp:-"127.0.0.1:54321"}
            [[ "$inp" =~ ^[0-9]+$ ]] && inp="127.0.0.1:$inp"
            if [[ "$inp" =~ ^(\[.*\]|[a-zA-Z0-9.-]+):[0-9]+$ ]]; then
                LOCAL_PROXY_PASS="${BACKEND_PROTOCOL}://${inp}"
            else
                print_warn "格式错误，请输入 端口号 或 IP:端口"
            fi
        done
    else
        echo ""
        print_guide "您选择了【不配置 Nginx】。"
        print_guide "证书生成后，请手动在面板设置中填写公钥/私钥路径。"
        echo ""
    fi

    # 5. DNS 解析
    print_info "探测本机公网 IP..."
    local ipv4 ipv6
    ipv4=$(curl -4 -s --max-time 5 https://4.ipw.cn 2>/dev/null || curl -4 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv4=""
    ipv6=$(curl -6 -s --max-time 5 https://6.ipw.cn 2>/dev/null || curl -6 -s --max-time 5 https://ifconfig.me 2>/dev/null) || ipv6=""
    _CACHED_IPV4="$ipv4"; _CACHED_IPV6="$ipv6"
    [[ -n "$ipv6" && ! "$ipv6" =~ : ]] && { print_warn "IPv6 探测异常 ($ipv6)，已忽略"; ipv6=""; }
    echo "  IPv4: ${ipv4:-[✗] 未检测到}"
    echo "  IPv6: ${ipv6:-[✗] 未检测到}"
    local dns_mode=""
    echo -e "${C_CYAN}DNS 解析方式:${C_RESET}"
    echo "  1. 仅 A 记录 (IPv4)"
    echo "  2. 仅 AAAA 记录 (IPv6)"
    echo "  3. 双栈 (A + AAAA)"
    echo "  0. 跳过 DNS (手动管理)"
    read -e -r -p "选择 [1]: " dns_mode
    dns_mode=${dns_mode:-1}
    local dns_proxied="false"
    if [[ "$dns_mode" != "0" ]]; then
        echo -e "${C_YELLOW}注意: 开启代理后，仅 HTTP/HTTPS 流量能通过 Cloudflare${C_RESET}"
        read -e -r -p "是否开启 Cloudflare 代理 (小云朵)? [y/N]: " proxy_choice
        [[ "${proxy_choice,,}" == "y" ]] && dns_proxied="true"
    fi

    # ══════════════════════════════════════════════════════════════
    #  配置确认
    # ══════════════════════════════════════════════════════════════
    echo ""
    draw_line
    echo -e "${C_CYAN}配置确认:${C_RESET}"
    echo -e "  域名:         ${C_GREEN}${DOMAIN}${C_RESET}"
    echo -e "  根域名:       ${C_GREEN}${root_domain}${C_RESET} (Zone: ${zone_id})"
    if [[ $do_nginx -eq 1 ]]; then
        echo -e "  Nginx:        ${C_GREEN}开启${C_RESET} (HTTP:${NGINX_HTTP_PORT} HTTPS:${NGINX_HTTPS_PORT})"
        echo -e "  反代目标:     ${C_GREEN}${LOCAL_PROXY_PASS}${C_RESET}"
    else
        echo -e "  Nginx:        ${C_YELLOW}关闭${C_RESET} (仅申请证书)"
    fi
    case $dns_mode in
        1) echo -e "  DNS:          ${C_GREEN}A → ${ipv4:-未检测到}${C_RESET} (代理: ${dns_proxied})" ;;
        2) echo -e "  DNS:          ${C_GREEN}AAAA → ${ipv6:-未检测到}${C_RESET} (代理: ${dns_proxied})" ;;
        3) echo -e "  DNS:          ${C_GREEN}A+AAAA${C_RESET} (代理: ${dns_proxied})" ;;
        0) echo -e "  DNS:          ${C_YELLOW}跳过${C_RESET}" ;;
    esac
    echo ""
    echo -e "  ${C_YELLOW}将自动执行:${C_RESET}"
    local auto_step=1
    [[ "$dns_mode" != "0" ]] && { echo -e "    ${auto_step}. DNS 解析配置"; ((auto_step++)); }
    echo -e "    ${auto_step}. SSL 证书申请 (Let's Encrypt DNS 验证)"; ((auto_step++))
    [[ $do_nginx -eq 1 ]] && { echo -e "    ${auto_step}. Nginx 反向代理部署"; ((auto_step++)); }
    [[ $do_nginx -eq 1 ]] && { echo -e "    ${auto_step}. 防火墙端口放行"; ((auto_step++)); }
    echo -e "    ${auto_step}. 证书自动续签配置"; ((auto_step++))
    [[ "$dns_mode" != "0" ]] && echo -e "    ${auto_step}. DDNS 动态解析"
    draw_line
    if ! confirm "确认开始执行?"; then
        print_warn "已取消"; pause; return
    fi

    # ══════════════════════════════════════════════════════════════
    #  执行阶段
    # ══════════════════════════════════════════════════════════════
    local step=1

    # ── DNS 解析 ──
    if [[ "$dns_mode" != "0" ]]; then
        echo -e "\n${C_CYAN}━━━ [${step}] DNS 解析 ━━━${C_RESET}"
        case $dns_mode in
            1) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied" ;;
            2) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
            3) _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "A" "$ipv4" "$dns_proxied"
               _cf_update_dns_record "$zone_id" "$CF_API_TOKEN" "$DOMAIN" "AAAA" "$ipv6" "$dns_proxied" ;;
        esac
        ((step++))
    fi

    # ── SSL 证书 ──
    echo -e "\n${C_CYAN}━━━ [${step}] SSL 证书申请 ━━━${C_RESET}"
    mkdir -p "${CERT_PATH_PREFIX}/${DOMAIN}"
    local CLOUDFLARE_CREDENTIALS="/root/.cloudflare-${DOMAIN}.ini"
    write_file_atomic "$CLOUDFLARE_CREDENTIALS" "dns_cloudflare_api_token = $CF_API_TOKEN"
    chmod 600 "$CLOUDFLARE_CREDENTIALS"
    print_info "正在申请证书 (DNS 验证，可能需要 1-2 分钟)..."
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
        ((step++))

        # ── Nginx 反向代理 ──
        if [[ $do_nginx -eq 1 ]]; then
            echo -e "\n${C_CYAN}━━━ [${step}] Nginx 反向代理 ━━━${C_RESET}"
            _ensure_ssl_params
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
            if ! _nginx_deploy_conf "$DOMAIN" "$nginx_conf"; then
                pause; return
            fi
            print_success "Nginx 配置已生效"
            ((step++))

            # ── 防火墙 ──
            echo -e "\n${C_CYAN}━━━ [${step}] 防火墙 ━━━${C_RESET}"
            if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
                ufw allow "$NGINX_HTTP_PORT/tcp" comment "Nginx-HTTP" >/dev/null 2>&1 || true
                ufw allow "$NGINX_HTTPS_PORT/tcp" comment "Nginx-HTTPS" >/dev/null 2>&1 || true
                print_success "防火墙规则已更新"
            else
                print_info "UFW 未启用，跳过"
            fi
            ((step++))
        fi

        # ── 证书自动续签 ──
        echo -e "\n${C_CYAN}━━━ [${step}] 证书自动续签 ━━━${C_RESET}"
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
        local cron_tag="CertRenew_${DOMAIN}"
        local cron_minute=$(( $(echo "$DOMAIN" | cksum | cut -d' ' -f1) % 60 ))
        cron_add_job "$cron_tag" "${cron_minute} 3 * * * certbot renew --quiet --cert-name '${DOMAIN}' --deploy-hook '${DEPLOY_HOOK_SCRIPT}' # ${cron_tag}"
        print_success "自动续签已配置 (每日 3:$(printf '%02d' $cron_minute) AM)"

        # 保存域名管理配置
        local config_content="# Domain configuration for $DOMAIN
# Generated by $SCRIPT_NAME $VERSION at $(date)
DOMAIN=\"$DOMAIN\"
CERT_PATH=\"${cert_dir}\"
DEPLOY_HOOK_SCRIPT=\"$DEPLOY_HOOK_SCRIPT\"
CLOUDFLARE_CREDENTIALS=\"$CLOUDFLARE_CREDENTIALS\"
"
        if [[ $do_nginx -eq 1 ]]; then
            config_content+="NGINX_CONF_PATH=\"/etc/nginx/sites-available/${DOMAIN}.conf\"

NGINX_HTTP_PORT=\"$NGINX_HTTP_PORT\"
NGINX_HTTPS_PORT=\"$NGINX_HTTPS_PORT\"
LOCAL_PROXY_PASS=\"$LOCAL_PROXY_PASS\"
"
        fi
        write_file_atomic "${CONFIG_DIR}/${DOMAIN}.conf" "$config_content"
        ((step++))

        # ── DDNS 动态解析 ──
        if [[ "$dns_mode" != "0" ]] && [[ ! -f "$DDNS_CONFIG_DIR/${DOMAIN}.conf" ]]; then
            echo -e "\n${C_CYAN}━━━ [${step}] DDNS 动态解析 ━━━${C_RESET}"
            local ddns_ipv4="false" ddns_ipv6="false"
            [[ "$dns_mode" == "1" || "$dns_mode" == "3" ]] && ddns_ipv4="true"
            [[ "$dns_mode" == "2" || "$dns_mode" == "3" ]] && ddns_ipv6="true"
            ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "$dns_proxied"
        fi

        # ══════════════════════════════════════════════════════════════
        #  完成报告
        # ══════════════════════════════════════════════════════════════
        echo ""
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
            echo "  请在面板设置中填写上述证书路径"
        fi
        echo -e "\n${C_CYAN}[自动续签]${C_RESET}"
        echo "  Hook 脚本: $DEPLOY_HOOK_SCRIPT"
        echo "  Crontab: 每日 3:$(printf '%02d' $cron_minute) AM 自动检查"
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
    _safe_source_conf "$target_conf"
    CERT_PATH=${CERT_PATH:-"${CERT_PATH_PREFIX}/${target_domain}"}
    DEPLOY_HOOK_SCRIPT=${DEPLOY_HOOK_SCRIPT:-"/root/cert-renew-hook-${target_domain}.sh"}
    print_title "配置详情: $target_domain"
    echo -e "${C_CYAN}[基础信息]${C_RESET}"
    echo "域名: $target_domain"
    echo "证书目录: $CERT_PATH"
    echo "Hook 脚本: $DEPLOY_HOOK_SCRIPT"
    echo -e "\n${C_CYAN}[自动续签计划 (Crontab)]${C_RESET}"
    local cron_out=$(crontab -l 2>/dev/null | grep -v -E "^[[:space:]]*no crontab for " || true)
    local domain_cron=$(echo "$cron_out" | grep -F "$target_domain" | grep "certbot" || true)
    if [[ -n "$domain_cron" ]]; then
        echo "$domain_cron"
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
    _web_cleanup_domain "$target_domain"
    log_action "Deleted domain config: $target_domain"
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
    echo -e "${C_CYAN}#    域名                             剩余天数       过期时间               状态${C_RESET}"
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
        echo -e "  $i  $d  $days_str  $expiry_str  $status_str"
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
