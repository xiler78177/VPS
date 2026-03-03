# modules/04-firewall.sh - UFW 防火墙管理
ufw_setup() {
    install_package "ufw"
    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行，请先禁用它。"
        return
    fi
    print_info "配置默认规则..."
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw allow "$CURRENT_SSH_PORT/tcp" comment "SSH-Access" >/dev/null
    if confirm "启用 UFW 可能导致 SSH 断开(若端口配置错误)，确认启用?"; then
        echo "y" | ufw enable
        print_success "UFW 已启用。"
        log_action "UFW enabled with SSH port $CURRENT_SSH_PORT"
    fi
    pause
}

ufw_del() {
    _require_cmd ufw "UFW" || return
    print_title "删除 UFW 规则"
    echo -e "${C_CYAN}当前放行的端口 (已过滤 Fail2ban 规则):${C_RESET}"
    ufw status | grep "ALLOW" | awk '{print $1}' | sort -t'/' -k1,1n -u
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时删除 tcp 和 udp${C_RESET}"
    read -e -r -p "要删除的规则: " rules
    [[ -z "$rules" ]] && return
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            if [[ -n "$proto" ]]; then
                ufw delete allow "${port}${proto}" 2>/dev/null && print_success "已删除: ${port}${proto}" || print_warn "${port}${proto} 不存在"
            else
                ufw delete allow "${port}/tcp" 2>/dev/null && print_success "已删除: ${port}/tcp" || print_warn "${port}/tcp 不存在"
                ufw delete allow "${port}/udp" 2>/dev/null && print_success "已删除: ${port}/udp" || true
            fi
        else
            print_error "无效格式: $rule"
        fi
    done
    log_action "UFW rules deleted: $rules"
    pause
}

ufw_safe_reset() {
    _require_cmd ufw "UFW" || return
    if confirm "这将重置所有规则！脚本会尝试保留当前 SSH 端口，确定吗？"; then
        print_info "正在重置..."
        echo "y" | ufw disable >/dev/null
        echo "y" | ufw reset >/dev/null
        ufw default deny incoming >/dev/null
        ufw default allow outgoing >/dev/null
        ufw allow "$CURRENT_SSH_PORT/tcp" comment "SSH-Access" >/dev/null
        echo "y" | ufw enable >/dev/null
        print_success "重置完成。SSH 端口 $CURRENT_SSH_PORT 已放行。"
        log_action "UFW reset completed"
    fi
    pause
}

ufw_add() {
    _require_cmd ufw "UFW" || return
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时放行 tcp 和 udp${C_RESET}"
    read -e -r -p "要放行的规则: " rules
    [[ -z "$rules" ]] && return
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            if validate_port "$port"; then
                if [[ -n "$proto" ]]; then
                    ufw allow "${port}${proto}" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}${proto}" || \
                        print_error "添加失败: ${port}${proto}"
                else
                    ufw allow "${port}/tcp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/tcp" || \
                        print_error "添加失败: ${port}/tcp"
                    ufw allow "${port}/udp" comment "Manual-Add" >/dev/null && \
                        print_success "已放行: ${port}/udp" || \
                        print_error "添加失败: ${port}/udp"
                fi
                log_action "UFW allowed ${port}${proto:-/tcp+udp}"
            else
                print_error "端口无效: $port"
            fi
        else
            print_error "无效格式: $rule"
        fi
    done
    pause
}

# ── GeoIP 国家级 IP 白/黑名单 ──
readonly GEOIP_CONF_DIR="/etc/server-manage"
readonly GEOIP_CONF="${GEOIP_CONF_DIR}/geoip.conf"
readonly GEOIP_DATA_DIR="${GEOIP_CONF_DIR}/geoip-data"
readonly GEOIP_CHAIN="GEOIP_FILTER"
readonly GEOIP_URL="https://www.ipdeny.com/ipblocks/data/aggregated"

_geoip_country_name() {
    case "${1^^}" in
        CN) echo "中国" ;; JP) echo "日本" ;; US) echo "美国" ;; KR) echo "韩国" ;;
        SG) echo "新加坡" ;; HK) echo "香港" ;; TW) echo "台湾" ;; DE) echo "德国" ;;
        GB) echo "英国" ;; FR) echo "法国" ;; RU) echo "俄罗斯" ;; AU) echo "澳大利亚" ;;
        CA) echo "加拿大" ;; IN) echo "印度" ;; NL) echo "荷兰" ;; BR) echo "巴西" ;;
        *) echo "${1^^}" ;;
    esac
}

_geoip_load_conf() {
    GEOIP_MODE="" GEOIP_COUNTRIES="" GEOIP_LAST_UPDATE=""
    [[ -f "$GEOIP_CONF" ]] && validate_conf_file "$GEOIP_CONF" && source "$GEOIP_CONF"
}

_geoip_download() {
    local countries="$1"
    mkdir -p "$GEOIP_DATA_DIR"
    local ok=0 fail=0
    for cc in $countries; do
        cc="${cc,,}"
        local url="${GEOIP_URL}/${cc}-aggregated.zone"
        local dest="${GEOIP_DATA_DIR}/${cc}.zone"
        if curl -sSL --connect-timeout 10 --max-time 30 -o "$dest" "$url" 2>/dev/null; then
            local count=$(grep -c '^[0-9]' "$dest" 2>/dev/null || echo 0)
            if [[ "$count" -gt 0 ]]; then
                echo -e "  ${C_GREEN}✓${C_RESET} ${cc^^} ($(_geoip_country_name "$cc")): ${count} 条 IP 段"
                ((ok++)) || true
            else
                print_warn "${cc^^}: 文件为空或格式异常"
                rm -f "$dest"; ((fail++)) || true
            fi
        else
            print_error "${cc^^}: 下载失败"
            ((fail++)) || true
        fi
    done
    [[ $ok -gt 0 ]] && return 0 || return 1
}

_geoip_apply() {
    local mode="$1" countries="$2"
    local set_name="geoip_${mode}"
    local tmp_set="${set_name}_tmp"
    # Bulk load into temp set
    ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set"
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] || continue
        sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null
    done
    # Atomic swap
    ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
    ipset swap "$tmp_set" "$set_name"
    ipset destroy "$tmp_set" 2>/dev/null || true
    # Build iptables chain
    iptables -N "$GEOIP_CHAIN" 2>/dev/null || iptables -F "$GEOIP_CHAIN"
    iptables -A "$GEOIP_CHAIN" -i lo -j RETURN
    iptables -A "$GEOIP_CHAIN" -s 127.0.0.0/8 -j RETURN
    iptables -A "$GEOIP_CHAIN" -s 10.0.0.0/8 -j RETURN
    iptables -A "$GEOIP_CHAIN" -s 172.16.0.0/12 -j RETURN
    iptables -A "$GEOIP_CHAIN" -s 192.168.0.0/16 -j RETURN
    iptables -A "$GEOIP_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
    if [[ "$mode" == "whitelist" ]]; then
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j RETURN
        iptables -A "$GEOIP_CHAIN" -j DROP
    else
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j DROP
    fi
    # Insert into INPUT chain at position 1 (before UFW)
    iptables -C INPUT -j "$GEOIP_CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$GEOIP_CHAIN"
}

_geoip_clear() {
    iptables -D INPUT -j "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -F "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -X "$GEOIP_CHAIN" 2>/dev/null || true
    ipset destroy geoip_whitelist 2>/dev/null || true
    ipset destroy geoip_blacklist 2>/dev/null || true
}

_geoip_install_persistence() {
    # Apply script (runs on boot)
    cat > /usr/local/bin/geoip-apply.sh << 'APPLY_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
CHAIN="GEOIP_FILTER"
[ -f "$CONF" ] || exit 0
GEOIP_MODE="" GEOIP_COUNTRIES=""
source "$CONF"
[ -z "$GEOIP_MODE" ] && exit 0
set_name="geoip_${GEOIP_MODE}"
tmp_set="${set_name}_tmp"
ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set"
for cc in $GEOIP_COUNTRIES; do
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null
done
ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
ipset swap "$tmp_set" "$set_name"
ipset destroy "$tmp_set" 2>/dev/null || true
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
iptables -A "$CHAIN" -i lo -j RETURN
iptables -A "$CHAIN" -s 127.0.0.0/8 -j RETURN
iptables -A "$CHAIN" -s 10.0.0.0/8 -j RETURN
iptables -A "$CHAIN" -s 172.16.0.0/12 -j RETURN
iptables -A "$CHAIN" -s 192.168.0.0/16 -j RETURN
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
if [ "$GEOIP_MODE" = "whitelist" ]; then
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j RETURN
    iptables -A "$CHAIN" -j DROP
else
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j DROP
fi
iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
APPLY_EOF
    chmod +x /usr/local/bin/geoip-apply.sh
    # Update script (cron weekly)
    cat > /usr/local/bin/geoip-update.sh << 'UPDATE_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
URL="https://www.ipdeny.com/ipblocks/data/aggregated"
[ -f "$CONF" ] || exit 0
GEOIP_MODE="" GEOIP_COUNTRIES=""
source "$CONF"
[ -z "$GEOIP_COUNTRIES" ] && exit 0
for cc in $GEOIP_COUNTRIES; do
    cc="${cc,,}"
    curl -sSL --connect-timeout 10 --max-time 30 \
        -o "${DATA}/${cc}.zone" "${URL}/${cc}-aggregated.zone" 2>/dev/null
done
/usr/local/bin/geoip-apply.sh
sed -i "s/^GEOIP_LAST_UPDATE=.*/GEOIP_LAST_UPDATE=\"$(date +%Y-%m-%d)\"/" "$CONF"
UPDATE_EOF
    chmod +x /usr/local/bin/geoip-update.sh
    # Systemd boot service
    if is_systemd; then
        cat > /etc/systemd/system/geoip-firewall.service << 'SVC_EOF'
[Unit]
Description=GeoIP Firewall Rules
After=network.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/geoip-apply.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
        systemctl daemon-reload
        systemctl enable geoip-firewall >/dev/null 2>&1
    fi
    # Weekly cron (Sunday 04:00)
    cron_add_job "geoip-update.sh" "0 4 * * 0 /usr/local/bin/geoip-update.sh >/dev/null 2>&1"
}

geoip_setup() {
    print_title "GeoIP 国家级 IP 白/黑名单"
    if ! command_exists ipset; then
        install_package "ipset"
        if ! command_exists ipset; then
            print_error "ipset 安装失败。"; pause; return
        fi
    fi
    if ! command_exists iptables; then
        print_error "iptables 未安装。"; pause; return
    fi
    _geoip_load_conf
    if [[ -n "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 已配置: 模式=${GEOIP_MODE} 国家=${GEOIP_COUNTRIES}"
        if ! confirm "重新配置将覆盖现有规则，继续?"; then
            pause; return
        fi
        _geoip_clear
    fi
    echo -e "${C_CYAN}选择模式:${C_RESET}"
    echo "  1. 白名单 (仅允许指定国家访问，其他全部拦截)"
    echo "  2. 黑名单 (仅封禁指定国家，其他正常放行)"
    read -e -r -p "选择 [1]: " mode_choice
    local mode="whitelist"
    [[ "$mode_choice" == "2" ]] && mode="blacklist"
    if [[ "$mode" == "whitelist" ]]; then
        echo -e "${C_YELLOW}[!] 白名单模式: 非白名单国家的所有入站连接将被直接丢弃${C_RESET}"
        echo -e "${C_YELLOW}    请确保你的访问来源国家都已加入白名单${C_RESET}"
    fi
    echo ""
    echo -e "${C_CYAN}常用国家代码:${C_RESET}"
    echo "  CN 中国    JP 日本    US 美国    KR 韩国    SG 新加坡"
    echo "  HK 香港    TW 台湾    DE 德国    GB 英国    FR 法国"
    echo "  RU 俄罗斯  AU 澳大利亚  CA 加拿大  NL 荷兰    IN 印度"
    echo ""
    read -e -r -p "输入国家代码 (空格分隔): " countries_input
    [[ -z "$countries_input" ]] && { print_warn "已取消"; pause; return; }
    local countries=""
    for cc in $countries_input; do
        cc="${cc^^}"
        if [[ ! "$cc" =~ ^[A-Z]{2}$ ]]; then
            print_error "无效国家代码: $cc (需要2位字母)"; pause; return
        fi
        countries="$countries $cc"
    done
    countries=$(echo "$countries" | xargs)
    # SSH safety check (whitelist mode)
    if [[ "$mode" == "whitelist" ]]; then
        local ssh_ip="${SSH_CLIENT%% *}"
        if [[ -n "$ssh_ip" ]]; then
            print_info "当前 SSH 来源: $ssh_ip"
            echo -e "${C_RED}[安全提示] 请确认你的 IP 所在国家已在白名单中！${C_RESET}"
            if ! confirm "确认继续? (设置错误将导致 SSH 断开)"; then
                pause; return
            fi
        fi
    fi
    draw_line
    echo -e "${C_CYAN}配置摘要:${C_RESET}"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单 (仅允许)" || echo "黑名单 (仅封禁)")"
    echo "  国家: $countries"
    draw_line
    if ! confirm "确认应用?"; then
        print_warn "已取消"; pause; return
    fi
    print_info "正在下载 IP 数据..."
    if ! _geoip_download "$countries"; then
        print_error "所有国家数据下载失败"; pause; return
    fi
    print_info "正在应用防火墙规则..."
    _geoip_apply "$mode" "$countries"
    local total=0
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] && total=$((total + $(grep -c '^[0-9]' "$f" 2>/dev/null || echo 0)))
    done
    mkdir -p "$GEOIP_CONF_DIR"
    cat > "$GEOIP_CONF" << EOF
GEOIP_MODE="$mode"
GEOIP_COUNTRIES="$countries"
GEOIP_LAST_UPDATE="$(date +%Y-%m-%d)"
EOF
    chmod 600 "$GEOIP_CONF"
    _geoip_install_persistence
    print_success "GeoIP 规则已生效！"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单" || echo "黑名单")"
    echo "  国家: $countries"
    echo "  IP段: ${total} 条"
    echo "  自动更新: 每周日 04:00"
    log_action "GeoIP configured: mode=$mode countries=$countries entries=$total"
    pause
}

geoip_status() {
    print_title "GeoIP 状态"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    local set_name="geoip_${GEOIP_MODE}"
    echo -e "${C_CYAN}模式:${C_RESET} $([[ "$GEOIP_MODE" == "whitelist" ]] && echo "白名单 (仅允许)" || echo "黑名单 (仅封禁)")"
    echo -e "${C_CYAN}国家:${C_RESET} $GEOIP_COUNTRIES"
    echo -e "${C_CYAN}更新:${C_RESET} ${GEOIP_LAST_UPDATE:-未知}"
    echo ""
    echo -e "${C_CYAN}[IP 段统计]${C_RESET}"
    local total=0
    for cc in $GEOIP_COUNTRIES; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        if [[ -f "$f" ]]; then
            local count=$(grep -c '^[0-9]' "$f" 2>/dev/null || echo 0)
            printf "  %-4s %-10s %s 条\n" "${cc}" "$(_geoip_country_name "$cc")" "$count"
            total=$((total + count))
        fi
    done
    echo "  总计: ${total} 条"
    echo ""
    echo -e "${C_CYAN}[iptables 命中统计]${C_RESET}"
    iptables -L "$GEOIP_CHAIN" -n -v 2>/dev/null | head -20 || \
        print_warn "iptables 规则不存在"
    echo ""
    echo -e "${C_CYAN}[ipset 集合]${C_RESET}"
    if ipset list "$set_name" 2>/dev/null | head -5; then
        local entries=$(ipset list "$set_name" 2>/dev/null | grep -c '^[0-9]' || echo 0)
        echo "  已加载条目: ${entries}"
    else
        print_warn "ipset 集合不存在"
    fi
    pause
}

geoip_update() {
    print_title "更新 GeoIP 数据"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    print_info "正在更新 IP 数据 (${GEOIP_COUNTRIES})..."
    if _geoip_download "$GEOIP_COUNTRIES"; then
        print_info "正在重新加载规则..."
        _geoip_apply "$GEOIP_MODE" "$GEOIP_COUNTRIES"
        sed -i "s/^GEOIP_LAST_UPDATE=.*/GEOIP_LAST_UPDATE=\"$(date +%Y-%m-%d)\"/" "$GEOIP_CONF"
        print_success "更新完成"
        log_action "GeoIP data updated: $GEOIP_COUNTRIES"
    else
        print_error "更新失败"
    fi
    pause
}

geoip_disable() {
    print_title "禁用 GeoIP"
    _geoip_load_conf
    if [[ -z "$GEOIP_MODE" ]]; then
        print_warn "GeoIP 未配置"; pause; return
    fi
    if ! confirm "确认禁用 GeoIP 规则? (将移除所有国家限制)"; then return; fi
    _geoip_clear
    rm -f "$GEOIP_CONF"
    rm -rf "$GEOIP_DATA_DIR"
    rm -f /usr/local/bin/geoip-apply.sh /usr/local/bin/geoip-update.sh
    cron_remove_job "geoip-update.sh"
    if is_systemd; then
        systemctl disable geoip-firewall 2>/dev/null || true
        rm -f /etc/systemd/system/geoip-firewall.service
        systemctl daemon-reload
    fi
    print_success "GeoIP 已禁用，所有规则已清除。"
    log_action "GeoIP disabled and cleaned up"
    pause
}

menu_geoip() {
    fix_terminal
    while true; do
        print_title "GeoIP 国家级 IP 白/黑名单"
        _geoip_load_conf
        if [[ -n "$GEOIP_MODE" ]]; then
            echo -e "${C_GREEN}状态: 已启用${C_RESET}"
            echo -e "模式: $([[ "$GEOIP_MODE" == "whitelist" ]] && echo "白名单" || echo "黑名单") | 国家: ${GEOIP_COUNTRIES} | 更新: ${GEOIP_LAST_UPDATE:-未知}"
        else
            echo -e "${C_YELLOW}状态: 未配置${C_RESET}"
        fi
        echo ""
        echo "1. 配置 GeoIP 规则
2. 查看当前状态
3. 手动更新 IP 数据库
4. 禁用 GeoIP
0. 返回"
        read -e -r -p "选择: " c
        case $c in
            1) geoip_setup ;;
            2) geoip_status ;;
            3) geoip_update ;;
            4) geoip_disable ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

menu_ufw() {
    fix_terminal
    while true; do
        print_title "UFW 防火墙管理"
        if command_exists ufw; then
            local ufw_status=$(ufw status 2>/dev/null | head -n 1 || echo "未运行")
            echo -e "${C_CYAN}当前状态:${C_RESET} $ufw_status"
        else
            echo -e "${C_YELLOW}UFW 未安装${C_RESET}"
        fi
        echo "1. 安装并启用 UFW
2. 查看本机监听端口
3. 添加放行端口
4. 查看当前规则
5. 删除规则
6. 禁用 UFW
7. 重置默认规则 (安全模式)
8. GeoIP 国家级 IP 白/黑名单
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) ufw_setup ;;
            2) check_port_usage ;;
            3) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_add
                fi
                ;;
            4) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    print_title "当前防火墙规则"
                    ufw status numbered
                    pause
                fi
                ;;
            5) 
                if ! command_exists ufw; then
                    print_error "UFW 未安装，请先选择选项 1 安装。"
                    pause
                else
                    ufw_del
                fi
                ;;
            6)
                if ! command_exists ufw; then
                    print_error "UFW 未安装。"
                    pause
                elif confirm "确认禁用 UFW？"; then
                    echo "y" | ufw disable
                    print_success "UFW 已禁用。"
                    log_action "UFW disabled"
                    pause
                fi
                ;;
            7) ufw_safe_reset ;;
            8) menu_geoip ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

