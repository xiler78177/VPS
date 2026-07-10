# modules/04-firewall.sh - UFW 防火墙管理
_ufw_validate_current_ssh_ports() {
    local _ssh_port found=0
    for _ssh_port in $CURRENT_SSH_PORTS; do
        found=1
        validate_port "$_ssh_port" || {
            print_error "无法确认当前 SSH 端口，拒绝操作 UFW"
            return 1
        }
    done
    if [[ "$found" -eq 0 ]]; then
        print_error "无法确认当前 SSH 端口，拒绝操作 UFW"
        return 1
    fi
    return 0
}

_ufw_apply_default_ssh_rules() {
    local _ssh_port
    _ufw_validate_current_ssh_ports || return 1
    print_info "配置默认规则..."
    if ! ufw default deny incoming >/dev/null; then
        print_error "设置 UFW 默认入站拒绝失败。"
        return 1
    fi
    if ! ufw default allow outgoing >/dev/null; then
        print_error "设置 UFW 默认出站允许失败。"
        return 1
    fi
    for _ssh_port in $CURRENT_SSH_PORTS; do
        if ! ufw allow "$_ssh_port/tcp" comment "SSH-Access" >/dev/null; then
            print_error "放行 SSH 端口 ${_ssh_port}/tcp 失败，拒绝继续启用 UFW。"
            return 1
        fi
    done
    return 0
}

ufw_setup() {
    install_package "ufw" || { print_error "UFW 安装失败。"; pause; return 1; }
    _require_cmd ufw "UFW" || return
    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行，请先禁用它。"
        pause; return 1
    fi
    refresh_ssh_port
    _ufw_apply_default_ssh_rules || { pause; return 1; }
    if confirm "启用 UFW 可能导致 SSH 断开(若端口配置错误)，确认启用?"; then
        if ! echo "y" | ufw enable >/dev/null; then
            print_error "UFW 启用失败。"
            pause; return 1
        fi
        print_success "UFW 已启用。"
        log_action "UFW enabled with SSH ports $CURRENT_SSH_PORTS"
    fi
    pause
}

ufw_del() {
    _require_cmd ufw "UFW" || return
    print_title "删除 UFW 规则"
    echo -e "${C_CYAN}当前放行的端口 (已过滤 Fail2ban 规则):${C_RESET}"
    ufw status | grep "ALLOW" | grep -viE 'fail2ban|f2b' | awk '{print $1}' | sort -t'/' -k1,1n -u
    echo -e "${C_YELLOW}格式: 端口 或 端口/协议 (如 80, 443/tcp, 53/udp)${C_RESET}"
    echo -e "${C_YELLOW}多个用空格分隔，不指定协议则同时删除 tcp 和 udp${C_RESET}"
    read -e -r -p "要删除的规则: " rules
    [[ -z "$rules" ]] && return
    refresh_ssh_port
    for rule in $rules; do
        if [[ "$rule" =~ ^([0-9]+)(/tcp|/udp)?$ ]]; then
            local port="${BASH_REMATCH[1]}"
            local proto="${BASH_REMATCH[2]}"
            if ! validate_port "$port"; then
                print_error "端口无效: $port"
                continue
            fi
            # 防误锁：删除当前 SSH 端口的放行规则前强制二次确认
            if [[ " $CURRENT_SSH_PORTS " == *" $port "* ]]; then
                print_warn "端口 ${port} 是当前 SSH 端口！删除其放行规则可能导致断开后无法重连。"
                confirm "确认仍要删除 ${port} 的放行规则?" || { print_info "已跳过 ${port}"; continue; }
            fi
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
        refresh_ssh_port
        _ufw_validate_current_ssh_ports || { pause; return 1; }
        if ! echo "y" | ufw disable >/dev/null; then
            print_error "UFW 禁用失败，已中止重置。"
            pause; return 1
        fi
        if ! echo "y" | ufw reset >/dev/null; then
            print_error "UFW 重置失败。"
            pause; return 1
        fi
        _ufw_apply_default_ssh_rules || { pause; return 1; }
        if ! echo "y" | ufw enable >/dev/null; then
            print_error "UFW 重新启用失败，请手动检查当前防火墙状态。"
            pause; return 1
        fi
        print_success "重置完成。SSH 端口 ${CURRENT_SSH_PORTS} 已放行。"
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

FIREWALL_SSH_OPEN_BACKENDS=""
FIREWALL_UDP_OPEN_BACKENDS=""

_firewall_iptables_input_restrictive() {
    local bin="$1"
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk '
        $1=="-P" && $2=="INPUT" && ($3=="DROP" || $3=="REJECT") { found=1 }
        $1=="-A" && $2=="INPUT" && $0 ~ / -j (DROP|REJECT)( |$)/ { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_has_tcp_accept() {
    local bin="$1" port="$2"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk -v p="$port" '
        $1=="-A" && $2=="INPUT" &&
        $0 ~ / -j ACCEPT( |$)/ &&
        $0 ~ /(^| )-p tcp( |$)/ &&
        $0 ~ ("(^| )--dport " p "($| )") { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_insert_tcp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage SSH}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    _firewall_iptables_has_tcp_accept "$bin" "$port" && return 0

    "$bin" -I INPUT 1 -p tcp -m state --state NEW -m tcp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -I INPUT 1 -p tcp -m tcp --dport "$port" -j ACCEPT
}

_firewall_iptables_delete_tcp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage SSH}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 0
    "$bin" -D INPUT -p tcp -m state --state NEW -m tcp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -D INPUT -p tcp -m tcp --dport "$port" -j ACCEPT 2>/dev/null || true
}

_firewall_iptables_has_udp_accept() {
    local bin="$1" port="$2"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    "$bin" -S INPUT 2>/dev/null | awk -v p="$port" '
        $1=="-A" && $2=="INPUT" &&
        $0 ~ / -j ACCEPT( |$)/ &&
        $0 ~ /(^| )-p udp( |$)/ &&
        $0 ~ ("(^| )--dport " p "($| )") { found=1 }
        END { exit found ? 0 : 1 }
    '
}

_firewall_iptables_insert_udp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage UDP}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 1
    _firewall_iptables_has_udp_accept "$bin" "$port" && return 0

    "$bin" -I INPUT 1 -p udp -m udp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -I INPUT 1 -p udp -m udp --dport "$port" -j ACCEPT
}

_firewall_iptables_delete_udp_accept() {
    local bin="$1" port="$2" comment="${3:-server-manage UDP}"
    validate_port "$port" || return 1
    command_exists "$bin" || return 0
    "$bin" -D INPUT -p udp -m udp --dport "$port" \
        -m comment --comment "$comment" -j ACCEPT 2>/dev/null && return 0
    "$bin" -D INPUT -p udp -m udp --dport "$port" -j ACCEPT 2>/dev/null || true
}

_firewall_iptables_save_rules() {
    local save_bin="$1" rules_file="$2" tmpfile
    [[ -f "$rules_file" ]] || return 2
    command_exists "$save_bin" || return 2
    tmpfile=$(mktemp "$(dirname "$rules_file")/.tmp.server-manage.iptables.XXXXXX") || return 1
    _tmp_register "$tmpfile"
    if ! "$save_bin" > "$tmpfile"; then
        rm -f "$tmpfile"
        _tmp_unregister "$tmpfile"
        return 1
    fi
    chmod --reference="$rules_file" "$tmpfile" 2>/dev/null || true
    chown --reference="$rules_file" "$tmpfile" 2>/dev/null || true
    if ! mv "$tmpfile" "$rules_file"; then
        rm -f "$tmpfile" 2>/dev/null || true
        _tmp_unregister "$tmpfile"
        return 1
    fi
    _tmp_unregister "$tmpfile"
    return 0
}

_firewall_save_after_iptables_change() {
    local backend="$1" rc
    case "$backend" in
        iptables)
            if _firewall_iptables_save_rules iptables-save /etc/iptables/rules.v4; then rc=0; else rc=$?; fi
            case "$rc" in
                0) print_info "已同步持久化 /etc/iptables/rules.v4" ;;
                1) print_warn "IPv4 运行时规则已更新，但持久化 /etc/iptables/rules.v4 失败，请手动检查。" ;;
                2) print_warn "IPv4 运行时规则已更新，但未检测到 /etc/iptables/rules.v4；重启后可能丢失。" ;;
            esac
            ;;
        ip6tables)
            if _firewall_iptables_save_rules ip6tables-save /etc/iptables/rules.v6; then rc=0; else rc=$?; fi
            case "$rc" in
                0) print_info "已同步持久化 /etc/iptables/rules.v6" ;;
                1) print_warn "IPv6 运行时规则已更新，但持久化 /etc/iptables/rules.v6 失败，请手动检查。" ;;
                2) print_warn "IPv6 运行时规则已更新，但未检测到 /etc/iptables/rules.v6；重启后可能丢失。" ;;
            esac
            ;;
    esac
}

# firewall_prepare_non_ufw_ssh_port <port> [comment]
# 在 UFW 未启用时，为 SSH 改端口场景处理常见的本地防火墙：
# - firewalld: 运行时 + permanent 放行
# - iptables/ip6tables(nft backend 也兼容): INPUT 存在 DROP/REJECT 时插入新端口 ACCEPT，并在已存在
#   /etc/iptables/rules.v4/v6 时同步持久化
#
# 返回值:
#   0 = 已确保或未检测到本地阻断
#   1 = 自动放行失败
#   2 = 检测到可能阻断但用户取消/无法自动确认
firewall_prepare_non_ufw_ssh_port() {
    local port="$1" comment="${2:-SSH-New}"
    FIREWALL_SSH_OPEN_BACKENDS=""
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    [[ "$PLATFORM" == "openwrt" ]] && return 0

    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行；SSH 新端口必须同步放行。"
        if ! command_exists firewall-cmd; then
            print_error "firewalld 活跃但 firewall-cmd 不可用，拒绝继续修改 SSH 端口。"
            return 1
        fi
        if ! confirm "是否通过 firewalld 放行 ${port}/tcp（运行时 + permanent）？"; then
            return 2
        fi
        firewall-cmd --add-port="${port}/tcp" >/dev/null || return 1
        firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || \
            print_warn "firewalld permanent 规则写入失败；本次运行时已放行，但重启后可能丢失。"
        FIREWALL_SSH_OPEN_BACKENDS+=" firewalld"
        print_success "firewalld 已放行 ${port}/tcp。"
        return 0
    fi

    local restrictive=0 changed=0 backend
    for backend in iptables ip6tables; do
        command_exists "$backend" || continue
        _firewall_iptables_input_restrictive "$backend" || continue
        restrictive=1
        if _firewall_iptables_has_tcp_accept "$backend" "$port"; then
            print_info "${backend} 已存在 ${port}/tcp 放行规则。"
            continue
        fi
        print_warn "检测到 ${backend} INPUT 链存在 DROP/REJECT，且未放行新 SSH 端口 ${port}/tcp。"
        if ! confirm "是否自动插入 ${backend} 放行规则并尽量持久化？"; then
            [[ -n "$FIREWALL_SSH_OPEN_BACKENDS" ]] && firewall_rollback_ssh_port "$port" "$FIREWALL_SSH_OPEN_BACKENDS" "$comment"
            return 2
        fi
        if ! _firewall_iptables_insert_tcp_accept "$backend" "$port" "$comment"; then
            print_error "${backend} 插入 ${port}/tcp 放行规则失败。"
            [[ -n "$FIREWALL_SSH_OPEN_BACKENDS" ]] && firewall_rollback_ssh_port "$port" "$FIREWALL_SSH_OPEN_BACKENDS" "$comment"
            return 1
        fi
        FIREWALL_SSH_OPEN_BACKENDS+=" ${backend}"
        changed=1
        print_success "${backend} 已放行 ${port}/tcp。"
        _firewall_save_after_iptables_change "$backend"
    done

    if [[ $restrictive -eq 0 ]]; then
        print_info "未检测到 UFW 以外的本地 INPUT DROP/REJECT；仍请确认云安全组已放行 ${port}/tcp。"
    elif [[ $changed -eq 0 ]]; then
        print_info "检测到本地防火墙限制，但新端口已有放行规则。"
    fi
    return 0
}

firewall_rollback_ssh_port() {
    local port="$1" backends="${2:-}" comment="${3:-SSH-New}" backend
    validate_port "$port" || return 0
    for backend in $backends; do
        case "$backend" in
            iptables|ip6tables)
                _firewall_iptables_delete_tcp_accept "$backend" "$port" "$comment"
                _firewall_save_after_iptables_change "$backend"
                ;;
            firewalld)
                if command_exists firewall-cmd; then
                    firewall-cmd --remove-port="${port}/tcp" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --remove-port="${port}/tcp" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done
}

# firewall_prepare_non_ufw_udp_port <port> [comment]
# UFW 未启用/不存在时，为必须可入站的 UDP 服务处理常见本机防火墙。
# 返回值同 firewall_prepare_non_ufw_ssh_port。
firewall_prepare_non_ufw_udp_port() {
    local port="$1" comment="${2:-Managed-UDP}"
    FIREWALL_UDP_OPEN_BACKENDS=""
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    [[ "$PLATFORM" == "openwrt" ]] && return 0

    if is_systemd && systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warn "检测到 firewalld 正在运行；UDP 端口 ${port} 必须同步放行。"
        if ! command_exists firewall-cmd; then
            print_error "firewalld 活跃但 firewall-cmd 不可用，拒绝继续。"
            return 1
        fi
        if ! confirm "是否通过 firewalld 放行 ${port}/udp（运行时 + permanent）？"; then
            return 2
        fi
        firewall-cmd --add-port="${port}/udp" >/dev/null || return 1
        firewall-cmd --permanent --add-port="${port}/udp" >/dev/null 2>&1 || \
            print_warn "firewalld permanent 规则写入失败；本次运行时已放行，但重启后可能丢失。"
        FIREWALL_UDP_OPEN_BACKENDS+=" firewalld"
        print_success "firewalld 已放行 ${port}/udp。"
        return 0
    fi

    local restrictive=0 changed=0 backend
    for backend in iptables ip6tables; do
        command_exists "$backend" || continue
        _firewall_iptables_input_restrictive "$backend" || continue
        restrictive=1
        if _firewall_iptables_has_udp_accept "$backend" "$port"; then
            print_info "${backend} 已存在 ${port}/udp 放行规则。"
            continue
        fi
        print_warn "检测到 ${backend} INPUT 链存在 DROP/REJECT，且未放行 ${port}/udp。"
        if ! confirm "是否自动插入 ${backend} 放行规则并尽量持久化？"; then
            [[ -n "$FIREWALL_UDP_OPEN_BACKENDS" ]] && firewall_rollback_udp_port "$port" "$FIREWALL_UDP_OPEN_BACKENDS" "$comment"
            return 2
        fi
        if ! _firewall_iptables_insert_udp_accept "$backend" "$port" "$comment"; then
            print_error "${backend} 插入 ${port}/udp 放行规则失败。"
            [[ -n "$FIREWALL_UDP_OPEN_BACKENDS" ]] && firewall_rollback_udp_port "$port" "$FIREWALL_UDP_OPEN_BACKENDS" "$comment"
            return 1
        fi
        FIREWALL_UDP_OPEN_BACKENDS+=" ${backend}"
        changed=1
        print_success "${backend} 已放行 ${port}/udp。"
        _firewall_save_after_iptables_change "$backend"
    done

    if [[ $restrictive -eq 0 ]]; then
        print_info "未检测到 UFW 以外的本地 INPUT DROP/REJECT；仍请确认云安全组已放行 ${port}/udp。"
    elif [[ $changed -eq 0 ]]; then
        print_info "检测到本地防火墙限制，但 ${port}/udp 已有放行规则。"
    fi
    return 0
}

firewall_rollback_udp_port() {
    local port="$1" backends="${2:-}" comment="${3:-Managed-UDP}" backend
    validate_port "$port" || return 0
    for backend in $backends; do
        case "$backend" in
            iptables|ip6tables)
                _firewall_iptables_delete_udp_accept "$backend" "$port" "$comment"
                _firewall_save_after_iptables_change "$backend"
                ;;
            firewalld)
                if command_exists firewall-cmd; then
                    firewall-cmd --remove-port="${port}/udp" >/dev/null 2>&1 || true
                    firewall-cmd --permanent --remove-port="${port}/udp" >/dev/null 2>&1 || true
                fi
                ;;
        esac
    done
}

# firewall_allow_tcp_port <port> [comment]
# 返回值:
#   0 = 已成功放行
#   1 = 真实错误（参数无效 / ufw 命令失败）
#   2 = UFW 不可用（未安装 / 未启用）—— 业务流程应仅警告，不要中断；启用 UFW 由用户主动进防火墙菜单完成
#
# 设计原则：业务模块（Reality/Realm/Email 等）不在自动流程里启用或重置 UFW，
# 以免与云安全组、用户已有规则、SSH 端口产生冲突。需要启用 UFW 的请走【防火墙模块】。
firewall_allow_tcp_port() {
    local port="$1" comment="${2:-Managed-TCP}"
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "OpenWrt 防火墙请在 LuCI/fw4 中放行 ${port}/tcp"
        return 0
    fi

    if ! command_exists ufw; then
        print_warn "未检测到 UFW — 本脚本不会自动安装。"
        print_info "如需本地防火墙，请进入【防火墙管理】菜单完成 UFW 安装与启用；"
        print_info "或在云厂商安全组放行 ${port}/tcp。"
        log_action "UFW absent during firewall_allow_tcp_port port=${port}" "INFO"
        return 2
    fi

    if ! ufw_is_active; then
        print_warn "UFW 已安装但未启用 — 本脚本不会在业务流程里自动启用 UFW。"
        print_info "如需本地防火墙保护，请进入【防火墙管理】→ 安装并启用 UFW；"
        print_info "或在云厂商安全组放行 ${port}/tcp。"
        log_action "UFW inactive during firewall_allow_tcp_port port=${port}" "INFO"
        return 2
    fi

    # UFW 已启用 — 仅追加规则
    if ufw allow "${port}/tcp" comment "$comment" >/dev/null 2>&1; then
        log_action "UFW allowed ${port}/tcp comment=${comment}"
        return 0
    fi
    print_error "UFW 添加规则失败: ${port}/tcp"
    return 1
}

# firewall_allow_udp_port <port> [comment]
# 返回值同 firewall_allow_tcp_port；业务模块只追加规则，不自动启用/重置 UFW。
firewall_allow_udp_port() {
    local port="$1" comment="${2:-Managed-UDP}"
    validate_port "$port" || { print_error "端口无效: $port"; return 1; }
    if [[ "$PLATFORM" == "openwrt" ]]; then
        print_warn "OpenWrt 防火墙请在 LuCI/fw4 中放行 ${port}/udp"
        return 0
    fi

    if ! command_exists ufw; then
        print_warn "未检测到 UFW — 本脚本不会自动安装。"
        print_info "如需本地防火墙，请进入【防火墙管理】菜单完成 UFW 安装与启用；"
        print_info "或在云厂商安全组放行 ${port}/udp。"
        log_action "UFW absent during firewall_allow_udp_port port=${port}" "INFO"
        return 2
    fi

    if ! ufw_is_active; then
        print_warn "UFW 已安装但未启用 — 本脚本不会在业务流程里自动启用 UFW。"
        print_info "如需本地防火墙保护，请进入【防火墙管理】→ 安装并启用 UFW；"
        print_info "或在云厂商安全组放行 ${port}/udp。"
        log_action "UFW inactive during firewall_allow_udp_port port=${port}" "INFO"
        return 2
    fi

    # UFW 已启用 — 仅追加规则
    if ufw allow "${port}/udp" comment "$comment" >/dev/null 2>&1; then
        log_action "UFW allowed ${port}/udp comment=${comment}"
        return 0
    fi
    print_error "UFW 添加规则失败: ${port}/udp"
    return 1
}

firewall_apply_reality_port() {
    local port="$1"
    firewall_allow_tcp_port "$port" "SingBox-Reality"
}

firewall_apply_realm_port() {
    local port="$1"
    firewall_allow_tcp_port "$port" "Realm-Relay"
}

# ── GeoIP 国家级 IP 白/黑名单 ──
readonly GEOIP_CONF_DIR="/etc/server-manage"
readonly GEOIP_CONF="${GEOIP_CONF_DIR}/geoip.conf"
readonly GEOIP_DATA_DIR="${GEOIP_CONF_DIR}/geoip-data"
readonly GEOIP_CHAIN="GEOIP_FILTER"
readonly GEOIP6_CHAIN="GEOIP6_FILTER"
readonly GEOIP_URL="https://www.ipdeny.com/ipblocks/data/aggregated"
readonly GEOIP6_URL="https://www.ipdeny.com/ipv6/ipaddresses/aggregated"

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
    local line key value mode="" countries="" last_update="" cc
    GEOIP_MODE="" GEOIP_COUNTRIES="" GEOIP_LAST_UPDATE=""
    [[ -f "$GEOIP_CONF" ]] || return 1
    validate_conf_file "$GEOIP_CONF" || return 1
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"
        [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
        key="${line%%=*}"
        key="${key//[[:space:]]/}"
        value="${line#*=}"
        case "$key" in
            GEOIP_MODE|GEOIP_COUNTRIES|GEOIP_LAST_UPDATE) ;;
            *) return 1 ;;
        esac
        if [[ "$value" =~ ^\"(.*)\"$ ]]; then
            value="${BASH_REMATCH[1]}"
        elif [[ "$value" =~ ^\'([^\']*)\'$ ]]; then
            value="${BASH_REMATCH[1]}"
        fi
        case "$key" in
            GEOIP_MODE) mode="$value" ;;
            GEOIP_COUNTRIES) countries="$value" ;;
            GEOIP_LAST_UPDATE) last_update="$value" ;;
        esac
    done < "$GEOIP_CONF"
    [[ -z "$mode" || "$mode" =~ ^(whitelist|blacklist)$ ]] || return 1
    for cc in $countries; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || return 1
    done
    GEOIP_MODE="$mode"
    GEOIP_COUNTRIES="$countries"
    GEOIP_LAST_UPDATE="$last_update"
    return 0
}

_geoip_service_file_path() {
    printf '%s' "${GEOIP_SERVICE_FILE:-/etc/systemd/system/geoip-firewall.service}"
}

_geoip_apply_script_path() {
    printf '%s' "${GEOIP_APPLY_SCRIPT:-/usr/local/bin/geoip-apply.sh}"
}

_geoip_update_script_path() {
    printf '%s' "${GEOIP_UPDATE_SCRIPT:-/usr/local/bin/geoip-update.sh}"
}

_geoip_render_conf() {
    local mode="$1" countries="$2" last_update="$3" cc
    [[ "$mode" =~ ^(whitelist|blacklist)$ ]] || return 1
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    for cc in $countries; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || return 1
    done
    printf 'GEOIP_MODE="%s"\n' "$mode"
    printf 'GEOIP_COUNTRIES="%s"\n' "$countries"
    printf 'GEOIP_LAST_UPDATE="%s"\n' "$last_update"
}

_geoip_write_conf() {
    local mode="$1" countries="$2" last_update="$3" content
    content="$(_geoip_render_conf "$mode" "$countries" "$last_update")" || return 1
    write_private_file_atomic "$GEOIP_CONF" "$content"
}

_geoip_render_conf_last_update() {
    local conf_file="$1" last_update="$2"
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    if [[ -f "$conf_file" ]]; then
        awk -v last_update="$last_update" '
            BEGIN { done=0 }
            /^[[:space:]]*GEOIP_LAST_UPDATE[[:space:]]*=/ {
                if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
                done=1
                next
            }
            { print }
            END {
                if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
            }
        ' "$conf_file"
    else
        printf 'GEOIP_LAST_UPDATE="%s"\n' "$last_update"
    fi
}

_geoip_update_last_update() {
    local conf_file="$1" last_update="${2:-$(date +%Y-%m-%d)}" content
    validate_conf_file "$conf_file" || return 1
    content="$(_geoip_render_conf_last_update "$conf_file" "$last_update")" || return 1
    write_private_file_atomic "$conf_file" "$content"
}

_geoip_render_service_unit() {
    local apply_script="${1:-/usr/local/bin/geoip-apply.sh}"
    cat <<SVC_EOF
[Unit]
Description=GeoIP Firewall Rules
After=network.target
Before=ufw.service

[Service]
Type=oneshot
ExecStart=${apply_script}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
}

_geoip_install_service_unit() {
    local service_file content
    service_file="$(_geoip_service_file_path)"
    content="$(_geoip_render_service_unit "$(_geoip_apply_script_path)")" || return 1
    write_file_atomic "$service_file" "$content" || return 1
    chmod 644 "$service_file" 2>/dev/null || true
}

_geoip_download() {
    local countries="$1"
    mkdir -p "$GEOIP_DATA_DIR"
    local ok=0 fail=0
    for cc in $countries; do
        cc="${cc,,}"
        local url="${GEOIP_URL}/${cc}-aggregated.zone"
        local url6="${GEOIP6_URL}/${cc}-aggregated.zone"
        local dest="${GEOIP_DATA_DIR}/${cc}.zone"
        local dest6="${GEOIP_DATA_DIR}/${cc}.zone6"
        local tmp tmp6 count count6
        tmp=$(mktemp "${GEOIP_DATA_DIR}/.${cc}.zone.XXXXXX") || { print_error "${cc^^}: 创建临时文件失败"; ((fail++)) || true; continue; }
        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp" "$url" 2>/dev/null; then
            count=$(grep -c '^[0-9]' "$tmp" 2>/dev/null)
            if [[ "$count" -gt 0 ]]; then
                mv "$tmp" "$dest"
                echo -e "  ${C_GREEN}✓${C_RESET} ${cc^^} ($(_geoip_country_name "$cc")) IPv4: ${count} 条 IP 段"
                ((ok++)) || true
            else
                print_warn "${cc^^}: 文件为空或格式异常，保留旧数据"
                rm -f "$tmp"
                ((fail++)) || true
            fi
        else
            print_error "${cc^^}: 下载失败，保留旧数据"
            rm -f "$tmp"
            ((fail++)) || true
        fi
        tmp6=$(mktemp "${GEOIP_DATA_DIR}/.${cc}.zone6.XXXXXX") || { print_error "${cc^^}: 创建 IPv6 临时文件失败"; ((fail++)) || true; continue; }
        if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp6" "$url6" 2>/dev/null; then
            count6=$(grep -c ':' "$tmp6" 2>/dev/null)
            if [[ "$count6" -gt 0 ]]; then
                mv "$tmp6" "$dest6"
                echo -e "  ${C_GREEN}✓${C_RESET} ${cc^^} ($(_geoip_country_name "$cc")) IPv6: ${count6} 条 IP 段"
            else
                print_warn "${cc^^}: IPv6 文件为空或格式异常，保留旧数据"
                rm -f "$tmp6"
                ((fail++)) || true
            fi
        else
            print_error "${cc^^}: IPv6 下载失败，保留旧数据"
            rm -f "$tmp6"
            ((fail++)) || true
        fi
    done
    [[ $fail -eq 0 ]] && [[ $ok -gt 0 ]]
}

_geoip_apply() {
    local mode="$1" countries="$2"
    local set_name="geoip_${mode}"
    local tmp_set="${set_name}_tmp"
    local set6_name="geoip_${mode}6"
    local tmp6_set="${set6_name}_tmp"
    local total_entries=0 total6_entries=0 use_ip6tables=0 swapped4=0
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        if [[ -f "$f" ]]; then
            local count
            count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
            total_entries=$((total_entries + count))
        fi
        local f6="${GEOIP_DATA_DIR}/${cc,,}.zone6"
        if [[ -f "$f6" ]]; then
            local count6
            count6=$(grep -c ':' "$f6" 2>/dev/null)
            total6_entries=$((total6_entries + count6))
        fi
    done
    if [[ "$total_entries" -le 0 ]]; then
        print_error "GeoIP 有效 IP 段为空，拒绝应用规则以避免清空集合。"
        return 1
    fi
    if [[ -e /proc/net/if_inet6 ]] && ! command_exists ip6tables; then
        print_error "检测到 IPv6 栈但缺少 ip6tables，拒绝应用 GeoIP 以避免 IPv6 绕过。"
        return 1
    fi
    command_exists ip6tables && use_ip6tables=1
    # Bulk load into temp set
    ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set" || return 1
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] || continue
        if ! sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null; then
            print_error "GeoIP 写入 ipset 失败: ${cc}"
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
    done

    if [[ "$use_ip6tables" -eq 1 ]]; then
        if ! ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null && ! ipset flush "$tmp6_set"; then
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
        for cc in $countries; do
            local f6="${GEOIP_DATA_DIR}/${cc,,}.zone6"
            [[ -f "$f6" ]] || continue
            if ! sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null; then
                print_error "GeoIP 写入 IPv6 ipset 失败: ${cc}"
                ipset destroy "$tmp6_set" 2>/dev/null || true
                ipset destroy "$tmp_set" 2>/dev/null || true
                return 1
            fi
        done
    fi

    # Swap only after both families have been populated. If IPv6 swap fails after
    # IPv4 has moved, swap IPv4 back so an update failure does not half-commit.
    ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
    if ! ipset swap "$tmp_set" "$set_name"; then
        print_error "GeoIP ipset swap 失败，保留旧集合。"
        ipset destroy "$tmp_set" 2>/dev/null || true
        [[ "$use_ip6tables" -eq 1 ]] && ipset destroy "$tmp6_set" 2>/dev/null || true
        return 1
    fi
    swapped4=1
    if [[ "$use_ip6tables" -eq 1 ]]; then
        ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
        if ! ipset swap "$tmp6_set" "$set6_name"; then
            print_error "GeoIP IPv6 ipset swap 失败，保留旧集合。"
            if [[ "$swapped4" -eq 1 ]]; then
                ipset swap "$tmp_set" "$set_name" 2>/dev/null || \
                    print_warn "GeoIP IPv4 集合回滚失败，请手动检查 ipset: ${set_name}/${tmp_set}"
            fi
            ipset destroy "$tmp6_set" 2>/dev/null || true
            ipset destroy "$tmp_set" 2>/dev/null || true
            return 1
        fi
        ipset destroy "$tmp6_set" 2>/dev/null || true
        if [[ "$total6_entries" -le 0 ]]; then
            print_warn "GeoIP IPv6 数据为空；白名单模式将默认拦截公网 IPv6。"
        fi
    fi
    ipset destroy "$tmp_set" 2>/dev/null || true
    # Build iptables chain
    iptables -N "$GEOIP_CHAIN" 2>/dev/null || iptables -F "$GEOIP_CHAIN" || return 1
    iptables -A "$GEOIP_CHAIN" -i lo -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 127.0.0.0/8 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 10.0.0.0/8 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 172.16.0.0/12 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -s 192.168.0.0/16 -j RETURN || return 1
    iptables -A "$GEOIP_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
    if [[ "$mode" == "whitelist" ]]; then
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j RETURN || return 1
        iptables -A "$GEOIP_CHAIN" -j DROP || return 1
    else
        iptables -A "$GEOIP_CHAIN" -m set --match-set "$set_name" src -j DROP || return 1
    fi
    # Insert into INPUT chain at position 1 (before UFW)
    iptables -C INPUT -j "$GEOIP_CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$GEOIP_CHAIN" || return 1
    if command_exists ip6tables; then
        ip6tables -N "$GEOIP6_CHAIN" 2>/dev/null || ip6tables -F "$GEOIP6_CHAIN" || return 1
        ip6tables -A "$GEOIP6_CHAIN" -i lo -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s ::1/128 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s fc00::/7 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -s fe80::/10 -j RETURN || return 1
        ip6tables -A "$GEOIP6_CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || return 1
        if [[ "$mode" == "whitelist" ]]; then
            ip6tables -A "$GEOIP6_CHAIN" -m set --match-set "$set6_name" src -j RETURN || return 1
            ip6tables -A "$GEOIP6_CHAIN" -j DROP || return 1
        else
            ip6tables -A "$GEOIP6_CHAIN" -m set --match-set "$set6_name" src -j DROP || return 1
        fi
        ip6tables -C INPUT -j "$GEOIP6_CHAIN" 2>/dev/null || ip6tables -I INPUT 1 -j "$GEOIP6_CHAIN" || return 1
    fi
}

_geoip_clear() {
    iptables -D INPUT -j "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -F "$GEOIP_CHAIN" 2>/dev/null || true
    iptables -X "$GEOIP_CHAIN" 2>/dev/null || true
    ip6tables -D INPUT -j "$GEOIP6_CHAIN" 2>/dev/null || true
    ip6tables -F "$GEOIP6_CHAIN" 2>/dev/null || true
    ip6tables -X "$GEOIP6_CHAIN" 2>/dev/null || true
    ipset destroy geoip_whitelist 2>/dev/null || true
    ipset destroy geoip_blacklist 2>/dev/null || true
    ipset destroy geoip_whitelist6 2>/dev/null || true
    ipset destroy geoip_blacklist6 2>/dev/null || true
}

_geoip_install_persistence() {
    local apply_script update_script apply_content update_content
    apply_script="$(_geoip_apply_script_path)"
    update_script="$(_geoip_update_script_path)"
    # Apply script (runs on boot)
    apply_content="$(cat << 'APPLY_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
CHAIN="GEOIP_FILTER"
CHAIN6="GEOIP6_FILTER"
[ -f "$CONF" ] || exit 0

# 安全解析：拒绝 source，避免被替换为恶意 conf 触发 root 命令执行
fown=$(stat -c '%U' "$CONF" 2>/dev/null || echo "")
fmode=$(stat -c '%a' "$CONF" 2>/dev/null || echo "")
[ "$fown" = "root" ] || exit 0
if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then exit 0; fi
GEOIP_MODE="" GEOIP_COUNTRIES=""
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^(GEOIP_MODE|GEOIP_COUNTRIES|GEOIP_LAST_UPDATE)=\"([A-Za-z0-9\ _.-]*)\"$ ]]; then
        case "${BASH_REMATCH[1]}" in
            GEOIP_MODE)        GEOIP_MODE="${BASH_REMATCH[2]}" ;;
            GEOIP_COUNTRIES)   GEOIP_COUNTRIES="${BASH_REMATCH[2]}" ;;
            GEOIP_LAST_UPDATE) : ;;
        esac
    else
        exit 0
    fi
done < "$CONF"

[ -z "$GEOIP_MODE" ] && exit 0
[[ "$GEOIP_MODE" =~ ^(whitelist|blacklist)$ ]] || exit 0
set_name="geoip_${GEOIP_MODE}"
tmp_set="${set_name}_tmp"
set6_name="geoip_${GEOIP_MODE}6"
tmp6_set="${set6_name}_tmp"
total_entries=0
total6_entries=0
use_ip6tables=0
swapped4=0
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
    total_entries=$((total_entries + count))
    f6="${DATA}/${cc,,}.zone6"
    [ -f "$f6" ] || continue
    count6=$(grep -c ':' "$f6" 2>/dev/null)
    total6_entries=$((total6_entries + count6))
done
[ "$total_entries" -gt 0 ] || exit 1
[ -e /proc/net/if_inet6 ] && ! command -v ip6tables >/dev/null 2>&1 && exit 1
command -v ip6tables >/dev/null 2>&1 && use_ip6tables=1
ipset create "$tmp_set" hash:net maxelem 131072 2>/dev/null || ipset flush "$tmp_set" || exit 1
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    f="${DATA}/${cc,,}.zone"
    [ -f "$f" ] || continue
    sed -e '/^#/d' -e '/^$/d' -e '/^[^0-9]/d' -e "s/^/add ${tmp_set} /" "$f" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
done
if [ "$use_ip6tables" -eq 1 ]; then
    if ! ipset create "$tmp6_set" hash:net family inet6 maxelem 131072 2>/dev/null && ! ipset flush "$tmp6_set"; then
        ipset destroy "$tmp_set" 2>/dev/null || true
        exit 1
    fi
    for cc in $GEOIP_COUNTRIES; do
        [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
        f6="${DATA}/${cc,,}.zone6"
        [ -f "$f6" ] || continue
        sed -e '/^#/d' -e '/^$/d' -e '/:/!d' -e "s/^/add ${tmp6_set} /" "$f6" | ipset restore -exist 2>/dev/null || { ipset destroy "$tmp6_set" 2>/dev/null || true; ipset destroy "$tmp_set" 2>/dev/null || true; exit 1; }
    done
fi
ipset create "$set_name" hash:net maxelem 131072 2>/dev/null || true
ipset swap "$tmp_set" "$set_name" || { ipset destroy "$tmp_set" 2>/dev/null || true; [ "$use_ip6tables" -eq 1 ] && ipset destroy "$tmp6_set" 2>/dev/null || true; exit 1; }
swapped4=1
if [ "$use_ip6tables" -eq 1 ]; then
    ipset create "$set6_name" hash:net family inet6 maxelem 131072 2>/dev/null || true
    if ! ipset swap "$tmp6_set" "$set6_name"; then
        [ "$swapped4" -eq 1 ] && ipset swap "$tmp_set" "$set_name" 2>/dev/null || true
        ipset destroy "$tmp6_set" 2>/dev/null || true
        ipset destroy "$tmp_set" 2>/dev/null || true
        exit 1
    fi
    ipset destroy "$tmp6_set" 2>/dev/null || true
fi
ipset destroy "$tmp_set" 2>/dev/null || true
iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN" || exit 1
iptables -A "$CHAIN" -i lo -j RETURN || exit 1
iptables -A "$CHAIN" -s 127.0.0.0/8 -j RETURN || exit 1
iptables -A "$CHAIN" -s 10.0.0.0/8 -j RETURN || exit 1
iptables -A "$CHAIN" -s 172.16.0.0/12 -j RETURN || exit 1
iptables -A "$CHAIN" -s 192.168.0.0/16 -j RETURN || exit 1
iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || exit 1
if [ "$GEOIP_MODE" = "whitelist" ]; then
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j RETURN || exit 1
    iptables -A "$CHAIN" -j DROP || exit 1
else
    iptables -A "$CHAIN" -m set --match-set "$set_name" src -j DROP || exit 1
fi
iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN" || exit 1
if command -v ip6tables >/dev/null 2>&1; then
    ip6tables -N "$CHAIN6" 2>/dev/null || ip6tables -F "$CHAIN6" || exit 1
    ip6tables -A "$CHAIN6" -i lo -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s ::1/128 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s fc00::/7 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -s fe80::/10 -j RETURN || exit 1
    ip6tables -A "$CHAIN6" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN || exit 1
    if [ "$GEOIP_MODE" = "whitelist" ]; then
        ip6tables -A "$CHAIN6" -m set --match-set "$set6_name" src -j RETURN || exit 1
        ip6tables -A "$CHAIN6" -j DROP || exit 1
    else
        ip6tables -A "$CHAIN6" -m set --match-set "$set6_name" src -j DROP || exit 1
    fi
    ip6tables -C INPUT -j "$CHAIN6" 2>/dev/null || ip6tables -I INPUT 1 -j "$CHAIN6" || exit 1
fi
APPLY_EOF
)"
    write_file_atomic "$apply_script" "$apply_content" || return 1
    chmod 700 "$apply_script"
    # Update script (cron weekly)
    update_content="$(cat << 'UPDATE_EOF'
#!/bin/bash
CONF="/etc/server-manage/geoip.conf"
DATA="/etc/server-manage/geoip-data"
URL="https://www.ipdeny.com/ipblocks/data/aggregated"
URL6="https://www.ipdeny.com/ipv6/ipaddresses/aggregated"
[ -f "$CONF" ] || exit 0

# 安全解析（同 apply 脚本）
fown=$(stat -c '%U' "$CONF" 2>/dev/null || echo "")
fmode=$(stat -c '%a' "$CONF" 2>/dev/null || echo "")
[ "$fown" = "root" ] || exit 0
if [[ "$fmode" =~ ^[0-7]+$ ]] && (( 8#${fmode} & 022 )); then exit 0; fi
GEOIP_COUNTRIES=""
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    [[ -z "${line// }" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^GEOIP_COUNTRIES=\"([A-Za-z0-9\ _.-]*)\"$ ]]; then
        GEOIP_COUNTRIES="${BASH_REMATCH[1]}"
    fi
done < "$CONF"
[ -z "$GEOIP_COUNTRIES" ] && exit 0

mkdir -p "$DATA"
for cc in $GEOIP_COUNTRIES; do
    [[ "$cc" =~ ^[A-Za-z]{2}$ ]] || continue
    cc="${cc,,}"
    tmp=$(mktemp "${DATA}/.${cc}.zone.XXXXXX") || exit 1
    tmp6=$(mktemp "${DATA}/.${cc}.zone6.XXXXXX") || { rm -f "$tmp"; exit 1; }
    if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp" "${URL}/${cc}-aggregated.zone" 2>/dev/null; then
        count=$(grep -c '^[0-9]' "$tmp" 2>/dev/null)
        if [ "$count" -gt 0 ]; then
            mv "$tmp" "${DATA}/${cc}.zone" || { rm -f "$tmp"; exit 1; }
        else
            rm -f "$tmp" "$tmp6"
            exit 1
        fi
    else
        rm -f "$tmp" "$tmp6"
        exit 1
    fi
    if curl -fsSL --connect-timeout 10 --max-time 30 -o "$tmp6" "${URL6}/${cc}-aggregated.zone" 2>/dev/null; then
        count6=$(grep -c ':' "$tmp6" 2>/dev/null)
        if [ "$count6" -gt 0 ]; then
            mv "$tmp6" "${DATA}/${cc}.zone6" || { rm -f "$tmp6"; exit 1; }
        else
            rm -f "$tmp6"
            exit 1
        fi
    else
        rm -f "$tmp6"
        exit 1
    fi
done
/usr/local/bin/geoip-apply.sh || exit 1
update_last_update() {
    last_update="$(date +%Y-%m-%d)"
    [[ "$last_update" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || exit 1
    dir="$(dirname "$CONF")"
    tmp="$(mktemp "${dir}/.tmp.server-manage.geoip.XXXXXX")" || exit 1
    if awk -v last_update="$last_update" '
        BEGIN { done=0 }
        /^[[:space:]]*GEOIP_LAST_UPDATE[[:space:]]*=/ {
            if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
            done=1
            next
        }
        { print }
        END {
            if (!done) print "GEOIP_LAST_UPDATE=\"" last_update "\""
        }
    ' "$CONF" > "$tmp"; then
        chmod 600 "$tmp" 2>/dev/null || true
        chown root:root "$tmp" 2>/dev/null || true
        mv "$tmp" "$CONF" || { rm -f "$tmp"; exit 1; }
    else
        rm -f "$tmp"
        exit 1
    fi
}
update_last_update
UPDATE_EOF
)"
    write_file_atomic "$update_script" "$update_content" || return 1
    chmod 700 "$update_script"
    # Systemd boot service
    if is_systemd; then
        _geoip_install_service_unit || return 1
        systemctl daemon-reload || return 1
        systemctl enable geoip-firewall >/dev/null 2>&1 || return 1
    fi
    # Weekly cron (Sunday 04:00)
    cron_add_job "$(basename "$update_script")" "0 4 * * 0 ${update_script} >/dev/null 2>&1"
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
    if ! _geoip_apply "$mode" "$countries"; then
        print_error "GeoIP 规则应用失败，未写入持久化配置。"
        pause; return
    fi
    local total=0
    for cc in $countries; do
        local f="${GEOIP_DATA_DIR}/${cc,,}.zone"
        [[ -f "$f" ]] && total=$((total + $(grep -c '^[0-9]' "$f" 2>/dev/null)))
    done
    if ! _geoip_write_conf "$mode" "$countries" "$(date +%Y-%m-%d)"; then
        print_error "GeoIP 配置写入失败，未安装持久化任务。"
        pause; return 1
    fi
    local persistence_ok=1
    if ! _geoip_install_persistence; then
        persistence_ok=0
        print_warn "GeoIP 当前规则已生效，但持久化/自动更新任务安装失败。"
        print_warn "请检查文件权限、crontab 或 systemd 状态；重启后规则可能不会自动恢复。"
    fi
    print_success "GeoIP 当前规则已生效！"
    echo "  模式: $([[ "$mode" == "whitelist" ]] && echo "白名单" || echo "黑名单")"
    echo "  国家: $countries"
    echo "  IP段: ${total} 条"
    if [[ "$persistence_ok" -eq 1 ]]; then
        echo "  自动更新: 每周日 04:00"
        log_action "GeoIP configured: mode=$mode countries=$countries entries=$total"
    else
        echo "  自动更新: 未安装成功"
        log_action "GeoIP configured without persistence: mode=$mode countries=$countries entries=$total"
        pause
        return 1
    fi
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
            local count=$(grep -c '^[0-9]' "$f" 2>/dev/null)
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
        local entries=$(ipset list "$set_name" 2>/dev/null | grep -c '^[0-9]')
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
        if ! _geoip_apply "$GEOIP_MODE" "$GEOIP_COUNTRIES"; then
            print_error "GeoIP 规则重新加载失败，已保留旧规则"
            pause; return 1
        fi
        if ! _geoip_update_last_update "$GEOIP_CONF"; then
            print_error "GeoIP 更新时间写入失败"
            pause; return 1
        fi
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
    rm -f "$(_geoip_apply_script_path)" "$(_geoip_update_script_path)"
    cron_remove_job "$(basename "$(_geoip_update_script_path)")"
    if is_systemd; then
        systemctl disable geoip-firewall 2>/dev/null || true
        rm -f "$(_geoip_service_file_path)"
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
