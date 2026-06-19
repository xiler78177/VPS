# modules/02-network.sh - 公网IP获取、DDNS管理
_extract_ipv4_from_text() {
    local raw="$1" ip=""
    [[ -z "$raw" ]] && return 1
    ip=$(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    [[ -n "$ip" && "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    echo "$ip"
    return 0
}

# 统一公网 IP 获取函数（使用国内可达的 API）
get_public_ipv4() {
    local raw="" ip="" url=""
    local endpoints=(
        "https://4.ipw.cn"
        "https://myip.ipip.net/ip"
        "https://ip.3322.net"
        "https://ifconfig.me/ip"
        "https://4.ident.me"
    )
    for url in "${endpoints[@]}"; do
        raw=$(curl -4 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
        ip=$(_extract_ipv4_from_text "$raw") || continue
        echo "$ip"
        return 0
    done
    return 1
}

get_public_ipv6() {
    local ip=""
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://6.ipw.cn 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://v6.ident.me 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    ip=$(curl -6 -s --connect-timeout 3 --max-time 5 https://ifconfig.me 2>/dev/null) && [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]] && { echo "$ip"; return 0; }
    return 1
}

ddns_rebuild_cron() {
    cron_remove_job "ddns-update.sh"
    if [[ -d "$DDNS_CONFIG_DIR" ]] && ls "$DDNS_CONFIG_DIR"/*.conf &>/dev/null 2>&1; then
        # cron 的 */59 语义是每小时第 0/59 分钟触发（中间会出现 1 分钟间隔），
        # 因此统一每分钟唤醒，再由 ddns-update.sh 按每份配置的 DDNS_INTERVAL 节流。
        cron_add_job "ddns-update.sh" "* * * * * $DDNS_UPDATE_SCRIPT >/dev/null 2>&1"
    fi
}

ddns_create_script() {
    mkdir -p "$DDNS_CONFIG_DIR"
    mkdir -p "$(dirname "$DDNS_UPDATE_SCRIPT")"
        cat > "$DDNS_UPDATE_SCRIPT" << 'EOF'
#!/bin/bash
if command -v flock >/dev/null 2>&1; then
    exec 200>/var/lock/ddns-update.lock
    flock -n 200 || exit 0
else
    mkdir /tmp/ddns-update.lock 2>/dev/null || exit 0
    trap 'rmdir /tmp/ddns-update.lock 2>/dev/null' EXIT
fi
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
DDNS_STAMP_DIR="/var/lib/ddns"
mkdir -p "$DDNS_STAMP_DIR" 2>/dev/null || {
    DDNS_STAMP_DIR="/tmp/ddns-state"
    mkdir -p "$DDNS_STAMP_DIR" 2>/dev/null || true
}
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$DDNS_LOG"; }

extract_ipv4() {
    local raw="$1" ip=""
    [[ -z "$raw" ]] && return 1
    ip=$(printf '%s' "$raw" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
    [[ -n "$ip" && "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    echo "$ip"
    return 0
}

get_ip() {
    local raw="" ip="" url=""
    if [[ "$1" == "4" ]]; then
        for url in \
            https://4.ipw.cn \
            https://myip.ipip.net/ip \
            https://ip.3322.net \
            https://ifconfig.me/ip \
            https://4.ident.me
        do
            raw=$(curl -4 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
            ip=$(extract_ipv4 "$raw") || continue
            echo "$ip"
            return 0
        done
        return 1
    else
        for url in \
            https://6.ipw.cn \
            https://v6.ident.me \
            https://ifconfig.me/ip
        do
            raw=$(curl -6 -s --connect-timeout 3 --max-time 5 "$url" 2>/dev/null) || continue
            [[ "$raw" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$raw" == *:* ]] && { echo "$raw"; return 0; }
        done
        return 1
    fi
}

update_cf() {
    local domain=$1 rt=$2 ip=$3 token=$4 zone=$5 proxied=${6:-false}
    [[ "$proxied" == "true" || "$proxied" == "false" ]] || proxied="false"
    local resp=$(curl -s --connect-timeout 10 --max-time 30 "https://api.cloudflare.com/client/v4/zones/$zone/dns_records?type=$rt&name=$domain" \
        -H "Authorization: Bearer $token" -H "Content-Type: application/json")
    if [[ "$(echo "$resp" | jq -r ".success // false" 2>/dev/null)" != "true" ]]; then
        log "[$domain] $rt lookup failed"
        return 1
    fi
    local rid=$(echo "$resp" | jq -r '.result[0].id // empty')
    local dns_ip=$(echo "$resp" | jq -r '.result[0].content // empty')
    [[ "$ip" == "$dns_ip" ]] && return 0
    
    local method="POST" url="https://api.cloudflare.com/client/v4/zones/$zone/dns_records"
    [[ -n "$rid" ]] && { method="PUT"; url="$url/$rid"; }
    
    resp=$(curl -s --connect-timeout 10 --max-time 30 -X "$method" "$url" -H "Authorization: Bearer $token" -H "Content-Type: application/json" \
        --data "{\"type\":\"$rt\",\"name\":\"$domain\",\"content\":\"$ip\",\"ttl\":1,\"proxied\":$proxied}")
    [[ "$(echo "$resp" | jq -r '.success')" == "true" ]] && { log "[$domain] $rt: $dns_ip -> $ip"; return 0; }
    log "[$domain] $rt update failed"; return 1
}

# 安全解析 conf：不 source，避免恶意命令替换 / 变量扩展执行
# 仅接受白名单 KEY，value 必须是双引号包裹的简单字面量
parse_ddns_conf() {
    local conf="$1" line key val
    local fown fmode
    fown=$(stat -c '%U' "$conf" 2>/dev/null || echo "")
    fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
    if [[ "$fown" != "root" ]]; then
        log "owner 非 root，跳过: $conf (owner=$fown)"
        return 1
    fi
    if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
        log "权限过宽，跳过: $conf (mode=$fmode)"
        return 1
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL)=\"([^\"\$\`\\]*)\"$ ]]; then
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            case "$key" in
                DDNS_DOMAIN)   DDNS_DOMAIN="$val" ;;
                DDNS_TOKEN)    DDNS_TOKEN="$val" ;;
                DDNS_ZONE_ID)  DDNS_ZONE_ID="$val" ;;
                DDNS_IPV4)     DDNS_IPV4="$val" ;;
                DDNS_IPV6)     DDNS_IPV6="$val" ;;
                DDNS_PROXIED)  DDNS_PROXIED="$val" ;;
                DDNS_INTERVAL) DDNS_INTERVAL="$val" ;;
            esac
        else
            log "格式异常行，跳过: $conf"
            return 1
        fi
    done < "$conf"
    [[ -n "$DDNS_DOMAIN" && -n "$DDNS_TOKEN" && -n "$DDNS_ZONE_ID" ]] || {
        log "必填字段缺失，跳过: $conf"
        return 1
    }
    DDNS_IPV4=${DDNS_IPV4:-false}
    DDNS_IPV6=${DDNS_IPV6:-false}
    DDNS_PROXIED=${DDNS_PROXIED:-false}
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    return 0
}

ddns_should_run() {
    local conf="$1" interval="${DDNS_INTERVAL:-5}" now last="" stamp_name stamp
    [[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 1 && "$interval" -le 59 ]] || interval=5
    stamp_name=$(basename "$conf" | sed 's/[^A-Za-z0-9_.-]/_/g')
    stamp="$DDNS_STAMP_DIR/${stamp_name}.stamp"
    now=$(date +%s)
    [[ -f "$stamp" ]] && read -r last < "$stamp" || true
    if [[ "$last" =~ ^[0-9]+$ ]] && (( now - last < interval * 60 )); then
        return 1
    fi
    printf '%s\n' "$now" > "$stamp" 2>/dev/null || true
    return 0
}

for conf in "$DDNS_CONFIG_DIR"/*.conf; do
    [ -f "$conf" ] || continue
    parse_ddns_conf "$conf" || continue
    ddns_should_run "$conf" || continue
    [[ "$DDNS_IPV4" == "true" ]] && { ip=$(get_ip 4); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" A "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
    [[ "$DDNS_IPV6" == "true" ]] && { ip=$(get_ip 6); [[ -n "$ip" ]] && update_cf "$DDNS_DOMAIN" AAAA "$ip" "$DDNS_TOKEN" "$DDNS_ZONE_ID" "$DDNS_PROXIED"; }
done
EOF
    chmod +x "$DDNS_UPDATE_SCRIPT"
}

ddns_setup() {
    local domain=$1 token=$2 zone_id=$3 ipv4=$4 ipv6=$5 proxied=$6
    echo -e "${C_CYAN}[DDNS 动态解析配置]${C_RESET}"
    if ! confirm "是否启用 DDNS 自动更新 (IP 变化时自动更新 DNS)?"; then
        return 0
    fi
        read -e -r -p "检测间隔(分钟, 1-59) [5]: " interval
    interval=${interval:-5}
    if [[ ! "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 || "$interval" -gt 59 ]]; then
        print_warn "间隔必须为 1-59，使用默认值 5"
        interval=5
    fi
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\""
    write_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    chmod 600 "$DDNS_CONFIG_DIR/${domain}.conf"
    ddns_create_script
    ddns_rebuild_cron
    print_success "DDNS 已启用 (每 ${interval} 分钟检测)"
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

ddns_setup_noninteractive() {
    local domain=$1 token=$2 zone_id=$3 ipv4=${4:-true} ipv6=${5:-false} proxied=${6:-false} interval=${7:-5}
    [[ -z "$domain" || -z "$token" || -z "$zone_id" ]] && return 1
    if [[ ! "$interval" =~ ^[0-9]+$ ]] || [[ "$interval" -lt 1 || "$interval" -gt 59 ]]; then
        interval=5
    fi
    mkdir -p "$DDNS_CONFIG_DIR"
    local ddns_conf_content="DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"$interval\""
    write_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "$ddns_conf_content" || { print_error "DDNS 配置写入失败"; return 1; }
    chmod 600 "$DDNS_CONFIG_DIR/${domain}.conf"
    ddns_create_script
    ddns_rebuild_cron
    log_action "DDNS enabled: $domain interval=${interval}m"
    return 0
}

# 顶层（交互菜单）安全解析 conf：与生成脚本 ddns-update.sh 内嵌的同名解析器逻辑一致，
# 但诊断走顶层的 log_action（heredoc 里的 log 仅存在于生成脚本中）。
# ddns_list / ddns_delete 复用本函数——与本文件 get_public_ipv4(顶层)/get_ip(生成脚本) 的双份模式一致。
parse_ddns_conf() {
    local conf="$1" line key val
    local fown fmode
    fown=$(stat -c '%U' "$conf" 2>/dev/null || echo "")
    fmode=$(stat -c '%a' "$conf" 2>/dev/null || echo "")
    if [[ "$fown" != "root" ]]; then
        log_action "DDNS 解析跳过：owner 非 root: $conf (owner=$fown)"
        return 1
    fi
    if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then
        log_action "DDNS 解析跳过：权限过宽: $conf (mode=$fmode)"
        return 1
    fi
    DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID=""
    DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if [[ "$line" =~ ^(DDNS_DOMAIN|DDNS_TOKEN|DDNS_ZONE_ID|DDNS_IPV4|DDNS_IPV6|DDNS_PROXIED|DDNS_INTERVAL)=\"([^\"\$\`\\]*)\"$ ]]; then
            key="${BASH_REMATCH[1]}"
            val="${BASH_REMATCH[2]}"
            case "$key" in
                DDNS_DOMAIN)   DDNS_DOMAIN="$val" ;;
                DDNS_TOKEN)    DDNS_TOKEN="$val" ;;
                DDNS_ZONE_ID)  DDNS_ZONE_ID="$val" ;;
                DDNS_IPV4)     DDNS_IPV4="$val" ;;
                DDNS_IPV6)     DDNS_IPV6="$val" ;;
                DDNS_PROXIED)  DDNS_PROXIED="$val" ;;
                DDNS_INTERVAL) DDNS_INTERVAL="$val" ;;
            esac
        else
            log_action "DDNS 解析跳过：格式异常行: $conf"
            return 1
        fi
    done < "$conf"
    [[ -n "$DDNS_DOMAIN" && -n "$DDNS_TOKEN" && -n "$DDNS_ZONE_ID" ]] || {
        log_action "DDNS 解析跳过：必填字段缺失: $conf"
        return 1
    }
    DDNS_IPV4=${DDNS_IPV4:-false}
    DDNS_IPV6=${DDNS_IPV6:-false}
    DDNS_PROXIED=${DDNS_PROXIED:-false}
    [[ "$DDNS_IPV4" == "true" || "$DDNS_IPV4" == "false" ]] || DDNS_IPV4="false"
    [[ "$DDNS_IPV6" == "true" || "$DDNS_IPV6" == "false" ]] || DDNS_IPV6="false"
    [[ "$DDNS_PROXIED" == "true" || "$DDNS_PROXIED" == "false" ]] || DDNS_PROXIED="false"
    return 0
}

ddns_list() {
    print_title "DDNS 配置列表"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无 DDNS 配置"; pause; return; }
    printf "${C_CYAN}%-30s %-6s %-6s %-8s %s${C_RESET}\n" "域名" "IPv4" "IPv6" "代理" "间隔"
    draw_line
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID="" DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
        parse_ddns_conf "$conf" || continue
        printf "%-30s %-6s %-6s %-8s %s\n" "$DDNS_DOMAIN" \
            "$([[ "$DDNS_IPV4" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_IPV6" == "true" ]] && echo "✓" || echo "-")" \
            "$([[ "$DDNS_PROXIED" == "true" ]] && echo "开启" || echo "关闭")" \
            "${DDNS_INTERVAL}分钟"
    done
    local ip4=$(get_public_ipv4)
    local ip6=$(get_public_ipv6)
    echo -e "${C_CYAN}当前IP:${C_RESET} IPv4=${ip4:-N/A} IPv6=${ip6:-N/A}"
    pause
}
ddns_delete() {
    print_title "删除 DDNS 配置"
    [[ ! -d "$DDNS_CONFIG_DIR" || -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]] && { print_warn "暂无配置"; pause; return; }
    local i=1 domains=() files=()
    for conf in "$DDNS_CONFIG_DIR"/*.conf; do
        [[ -f "$conf" ]] || continue
        DDNS_DOMAIN="" DDNS_TOKEN="" DDNS_ZONE_ID="" DDNS_IPV4="" DDNS_IPV6="" DDNS_PROXIED="" DDNS_INTERVAL=""
        parse_ddns_conf "$conf" || continue
        domains+=("$DDNS_DOMAIN"); files+=("$conf")
        echo "$i. $DDNS_DOMAIN"; ((i++))
    done
    echo "0. 返回"
    read -e -r -p "选择: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    [[ "$idx" =~ ^[0-9]+$ && "$idx" -le ${#domains[@]} ]] || { print_error "无效"; pause; return; }
    confirm "删除 ${domains[$((idx-1))]} 的 DDNS?" && {
        rm -f "${files[$((idx-1))]}"
        if [[ -z "$(ls -A "$DDNS_CONFIG_DIR" 2>/dev/null)" ]]; then
            cron_remove_job "ddns-update.sh"
            rm -f "$DDNS_UPDATE_SCRIPT"
        else
            ddns_rebuild_cron
        fi
        print_success "已删除"; log_action "DDNS deleted: ${domains[$((idx-1))]}"
    }
    pause
}
ddns_force_update() {
    if [[ -x "$DDNS_UPDATE_SCRIPT" ]]; then
        print_info "正在更新..."
        "$DDNS_UPDATE_SCRIPT"
        print_success "更新完成"
        tail -n 10 "$DDNS_LOG" 2>/dev/null || echo "暂无日志"
    else
        print_warn "DDNS 未配置"
    fi
    pause
}
