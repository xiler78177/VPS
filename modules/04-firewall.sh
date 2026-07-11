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
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
