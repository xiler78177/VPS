# modules/06-ssh.sh - SSH 端口修改与密钥管理
# 仅更新 Fail2ban [sshd] jail 的 port，避免误改 nginx/http 等其他 jail。
_fail2ban_set_sshd_port() {
    local jail_file="$1" port="$2"
    [[ -f "$jail_file" ]] || return 1
    validate_port "$port" || return 1
    local tmpfile
    tmpfile=$(mktemp "$(dirname "$jail_file")/.tmp.fail2ban-sshd.XXXXXX") || return 1
    awk -v port="$port" '
        BEGIN { seen_sshd=0 }
        /^\[[^]]+\]/ {
            if (in_sshd && !done) { print "port = " port; done=1 }
            in_sshd=($0 == "[sshd]")
            if (in_sshd) seen_sshd=1
            print
            next
        }
        in_sshd && /^[[:space:]]*port[[:space:]]*=/ {
            print "port = " port
            done=1
            next
        }
        { print }
        END {
            if (in_sshd && !done) print "port = " port
            if (!seen_sshd) exit 2
        }
    ' "$jail_file" > "$tmpfile" || { rm -f "$tmpfile"; return 1; }
    chmod --reference="$jail_file" "$tmpfile" 2>/dev/null || true
    chown --reference="$jail_file" "$tmpfile" 2>/dev/null || true
    mv "$tmpfile" "$jail_file"
}

_ssh_socket_dropin_path() {
    local socket_unit="$1"
    printf '/etc/systemd/system/%s.d/server-manage-port.conf' "$socket_unit"
}

_ssh_socket_dropin_rollback() {
    local socket_dropin="${1:-}" socket_backup="${2:-}" socket_created="${3:-0}"
    [[ -n "$socket_dropin" ]] || return 0
    if [[ -n "$socket_backup" && -f "$socket_backup" ]]; then
        mv "$socket_backup" "$socket_dropin" 2>/dev/null || true
    elif [[ "$socket_created" -eq 1 ]]; then
        rm -f "$socket_dropin" 2>/dev/null || true
    fi
    systemctl daemon-reload 2>/dev/null || true
}

ssh_change_port() {
    print_title "修改 SSH 端口"
    refresh_ssh_port
    echo -e "${C_GRAY}当前生效端口 (sshd -T 解析): ${CURRENT_SSH_PORT}${C_RESET}"
    read -e -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    if ! validate_port "$port"; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi
    if [[ "$port" == "$CURRENT_SSH_PORT" ]]; then
        print_warn "新端口与当前端口相同，无需修改。"
        pause; return
    fi

    # 检查 drop-in 是否设置了 Port — 若设置了，sed 改主配是无效的
    local dropin_port_file=""
    if [[ -d /etc/ssh/sshd_config.d ]]; then
        dropin_port_file=$(grep -lE "^[[:space:]]*Port[[:space:]]+" /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -1)
    fi
    local target_conf="$SSHD_CONFIG"
    if [[ -n "$dropin_port_file" ]]; then
        print_warn "Port 已在 drop-in 中配置（OpenSSH 优先生效）："
        echo "  - $dropin_port_file"
        echo ""
        echo "  1. 修改 drop-in 文件 (推荐)"
        echo "  2. 修改主配置 $SSHD_CONFIG（drop-in 仍会覆盖，可能无效）"
        echo "  0. 取消"
        read -e -r -p "选择 [1]: " dch
        case "${dch:-1}" in
            1) target_conf="$dropin_port_file" ;;
            2) target_conf="$SSHD_CONFIG" ;;
            *) print_warn "已取消"; pause; return ;;
        esac
    fi

    local socket_unit="" socket_dropin="" socket_backup="" socket_created=0
    if _ssh_socket_activation_active; then
        socket_unit=$(_ssh_socket_unit)
        print_warn "检测到 systemd ${socket_unit} socket activation。"
        print_warn "仅修改 sshd_config 不会改变真实监听端口，必须同步修改 ${socket_unit}。"
        if ! confirm "是否同步修改 ${socket_unit} 监听端口为 ${port}？"; then
            pause; return
        fi
    fi

    # 检查端口是否已被其他服务占用
    if command_exists ss && ss -tlpn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"; then
        local occupier=$(ss -tlpn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $NF}' | head -1)
        print_error "端口 $port 已被占用: $occupier"
        if ! confirm "是否强制继续修改？(可能导致冲突)"; then
            pause; return
        fi
    fi

    local backup_file="${target_conf}.bak.$(date +%s)"
    cp "$target_conf" "$backup_file"

    if [[ -n "$socket_unit" ]]; then
        socket_dropin=$(_ssh_socket_dropin_path "$socket_unit")
        local socket_dropin_dir
        socket_dropin_dir=$(dirname "$socket_dropin")
        mkdir -p "$socket_dropin_dir"
        if [[ -f "$socket_dropin" ]]; then
            socket_backup="${socket_dropin}.bak.$(date +%s)"
            cp "$socket_dropin" "$socket_backup"
        else
            socket_created=1
        fi
        local socket_tmp
        socket_tmp=$(mktemp "${socket_dropin_dir}/.tmp.server-manage.ssh-socket.XXXXXX") || {
            print_error "创建 SSH socket drop-in 临时文件失败，已回滚。"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        }
        _tmp_register "$socket_tmp"
        if ! cat > "$socket_tmp" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${port}
ListenStream=[::]:${port}
EOF
        then
            print_error "写入 SSH socket drop-in 失败，已回滚。"
            rm -f "$socket_tmp" 2>/dev/null || true
            _tmp_unregister "$socket_tmp"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        fi
        chmod 0644 "$socket_tmp" 2>/dev/null || true
        if ! mv "$socket_tmp" "$socket_dropin"; then
            print_error "安装 SSH socket drop-in 失败，已回滚。"
            rm -f "$socket_tmp" 2>/dev/null || true
            _tmp_unregister "$socket_tmp"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ -n "$socket_backup" ]] && rm -f "$socket_backup"
            pause; return 1
        fi
        _tmp_unregister "$socket_tmp"
        systemctl daemon-reload 2>/dev/null || true
    fi

    # 先放行新端口（防止改完连不上）
    local ufw_opened=0 firewall_opened_backends=""
    if ufw_is_active; then
        if ! ufw allow "$port/tcp" comment "SSH-New" >/dev/null; then
            print_error "UFW 放行新 SSH 端口失败，已中止修改。"
            [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
            rm -f "$backup_file"
            pause; return 1
        fi
        ufw_opened=1
        print_success "UFW 已放行新端口 $port。"
    else
        if declare -F firewall_prepare_non_ufw_ssh_port >/dev/null; then
            if ! firewall_prepare_non_ufw_ssh_port "$port" "SSH-New"; then
                print_error "无法确认本地防火墙已放行新 SSH 端口，拒绝继续修改以避免失联。"
                print_info "请先手动放行 ${port}/tcp（云安全组 + 本机防火墙），再重试。"
                [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
                rm -f "$backup_file"
                pause; return 1
            fi
            firewall_opened_backends="$FIREWALL_SSH_OPEN_BACKENDS"
        else
            print_warn "未找到非 UFW 防火墙检测 helper；请确认云安全组/iptables/nftables 已放行 ${port}/tcp。"
            if ! confirm "仍要继续修改 SSH 端口？"; then
                pause; return
            fi
        fi
    fi

    # 写入端口配置。必须插入到首个 Match 块之前，否则只会作用于匹配块并导致 sshd -t 失败/配置无效。
    if ! _sshd_set_directive "Port" "$port" "$target_conf" 1; then
        print_error "写入 SSH 端口配置失败，已回滚。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        pause; return
    fi

    # 校验配置语法
    if ! sshd -t 2>/dev/null; then
        print_error "sshd 配置校验失败！已回滚。"
        mv "$backup_file" "$target_conf"
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        pause; return
    fi

    if ! _restart_sshd; then
        print_error "重启失败！已回滚配置。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        _restart_sshd || true
        pause; return
    fi

    local listen_ok=0 _try
    for _try in 1 2 3 4 5; do
        if _ssh_port_is_listening "$port"; then
            listen_ok=1
            break
        fi
        sleep 1
    done
    if [[ $listen_ok -ne 1 ]]; then
        print_error "重启后未检测到 SSH 在新端口 ${port}/tcp 监听，已回滚配置。"
        mv "$backup_file" "$target_conf" 2>/dev/null || true
        [[ -n "$socket_unit" ]] && _ssh_socket_dropin_rollback "$socket_dropin" "$socket_backup" "$socket_created"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
        _restart_sshd || true
        pause; return
    fi

    # 非 socket activation 模式下，再用 sshd -T 校验配置解析端口；socket 模式以真实监听为准。
    if [[ -z "$socket_unit" ]]; then
        local effective_port
        effective_port=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')
        if [[ "$effective_port" != "$port" ]]; then
            print_error "重启后 sshd -T 解析端口仍为 ${effective_port:-未知}，与目标 $port 不一致。"
            print_error "可能仍被其他 drop-in 文件覆盖。已回滚配置和本次新增防火墙规则。"
            mv "$backup_file" "$target_conf" 2>/dev/null || true
            [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
            [[ -n "$firewall_opened_backends" ]] && firewall_rollback_ssh_port "$port" "$firewall_opened_backends" "SSH-New"
            _restart_sshd || true
            pause; return
        fi
    fi

    print_success "SSH 重启成功，已确认新端口真实监听: $port"
    if [[ $ufw_opened -eq 1 ]]; then
        ufw delete allow "$CURRENT_SSH_PORT/tcp" 2>/dev/null || true
    fi
    # 同步更新 Fail2ban jail 端口
    if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
        if _fail2ban_set_sshd_port "$FAIL2BAN_JAIL_LOCAL" "$port"; then
            systemctl restart fail2ban 2>/dev/null || true
            print_info "Fail2ban [sshd] 已同步新端口 $port"
        else
            print_warn "Fail2ban [sshd] 端口同步失败，请手动检查 $FAIL2BAN_JAIL_LOCAL"
        fi
    fi
    CURRENT_SSH_PORT=$port
    log_action "SSH port changed to $port (file=$target_conf socket=${socket_unit:-none})"
    rm -f "$backup_file" "$socket_backup"
    pause
}


ssh_keys() {
    print_title "SSH 密钥管理"
    echo "1. 导入公钥
2. 查看已部署的公钥
3. 删除指定公钥
4. 生成服务器密钥对
5. 禁用密码登录
0. 返回"
    read -e -r -p "选择: " c
    case $c in
    1)
        read -e -r -p "用户名: " user
        if ! id "$user" >/dev/null 2>&1; then 
            print_error "用户不存在"
            pause; return
        fi
        read -e -r -p "粘贴公钥: " key
        [[ -z "$key" ]] && return
        if [[ ! "$key" =~ ^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256))\ [A-Za-z0-9+/=]+ ]]; then
            print_error "公钥格式无效 (应以 ssh-rsa/ssh-ed25519/ecdsa-sha2 等开头)"
            pause; return
        fi
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        mkdir -p "$dir"
        if grep -qF "$key" "$dir/authorized_keys" 2>/dev/null; then
            print_warn "该公钥已存在，无需重复添加。"
            pause; return
        fi
        chmod 700 "$dir" 2>/dev/null || true
        chown "$user:$user" "$dir" 2>/dev/null || true
        _ssh_authorized_keys_append "$dir/authorized_keys" "$key" "$user:$user" || {
            print_error "公钥写入失败"
            pause; return
        }
        print_success "公钥已添加。"
        log_action "SSH key added for user $user"
        ;;
    2)
        read -e -r -p "用户名 [root]: " user
        user=${user:-root}
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        local ak="$dir/authorized_keys"
        if [[ ! -f "$ak" ]] || [[ ! -s "$ak" ]]; then
            print_warn "该用户没有部署任何公钥。"
            pause; return
        fi
        echo -e "${C_CYAN}[$user 的公钥列表]${C_RESET}"
        local idx=1
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            local fp=$(echo "$line" | ssh-keygen -l -f - 2>/dev/null)
            if [[ -n "$fp" ]]; then
                local bits=$(echo "$fp" | awk '{print $1}')
                local hash=$(echo "$fp" | awk '{print $2}')
                local comment=$(echo "$line" | awk '{print $NF}')
                local ktype=$(echo "$line" | awk '{print $1}')
                printf "  ${C_GREEN}%d.${C_RESET} %-12s %s位  %s  ${C_GRAY}%s${C_RESET}\n" "$idx" "$ktype" "$bits" "$hash" "$comment"
            else
                printf "  ${C_GREEN}%d.${C_RESET} %s\n" "$idx" "${line:0:80}"
            fi
            ((idx++)) || true
        done < "$ak"
        [[ $idx -eq 1 ]] && print_warn "无有效公钥"
        ;;
    3)
        read -e -r -p "用户名 [root]: " user
        user=${user:-root}
        local dir="/home/$user/.ssh"
        [[ "$user" == "root" ]] && dir="/root/.ssh"
        local ak="$dir/authorized_keys"
        if [[ ! -f "$ak" ]] || [[ ! -s "$ak" ]]; then
            print_warn "该用户没有部署任何公钥。"; pause; return
        fi
        # Show keys with index
        local keys=() idx=1
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            keys+=("$line")
            local comment=$(echo "$line" | awk '{print $NF}')
            local ktype=$(echo "$line" | awk '{print $1}')
            printf "  %d. %-12s %s\n" "$idx" "$ktype" "$comment"
            ((idx++)) || true
        done < "$ak"
        [[ ${#keys[@]} -eq 0 ]] && { print_warn "无公钥"; pause; return; }
        read -e -r -p "输入要删除的序号: " didx
        if [[ "$didx" =~ ^[0-9]+$ ]] && [[ "$didx" -ge 1 && "$didx" -le ${#keys[@]} ]]; then
            local target_key="${keys[$((didx-1))]}"
            if confirm "确认删除第 ${didx} 个公钥?"; then
                _ssh_authorized_keys_remove "$ak" "$target_key" "$user:$user" || { print_error "写入失败"; pause; return; }
                print_success "已删除。"
                log_action "SSH key deleted for user $user (index=$didx)"
            fi
        else
            print_error "无效序号"
        fi
        ;;
    4)
        echo -e "${C_CYAN}生成 Ed25519 密钥对 (用于服务器主动连接其他主机)${C_RESET}"
        read -e -r -p "备注信息 [留空跳过]: " comment
        local key_file="/root/.ssh/id_ed25519_server"
        if [[ -f "$key_file" ]]; then
            print_warn "密钥已存在: $key_file"
            if ! confirm "覆盖现有密钥?"; then pause; return; fi
        fi
        local args=(ssh-keygen -t ed25519 -f "$key_file" -N "")
        [[ -n "$comment" ]] && args+=(-C "$comment")
        "${args[@]}"
        echo ""
        print_success "密钥对已生成。"
        echo -e "${C_CYAN}私钥:${C_RESET} $key_file"
        echo -e "${C_CYAN}公钥:${C_RESET} ${key_file}.pub"
        echo ""
        echo -e "${C_CYAN}公钥内容 (复制到目标服务器的 authorized_keys):${C_RESET}"
        cat "${key_file}.pub"
        log_action "SSH keypair generated: $key_file"
        echo ""
        if confirm "是否将公钥导入本服务器的 authorized_keys?"; then
            read -e -r -p "导入到哪个用户 [root]: " imp_user
            imp_user=${imp_user:-root}
            if ! id "$imp_user" >/dev/null 2>&1; then
                print_error "用户不存在"; pause; return
            fi
            local imp_dir="/home/$imp_user/.ssh"
            [[ "$imp_user" == "root" ]] && imp_dir="/root/.ssh"
            mkdir -p "$imp_dir"
            local pub_key
            pub_key=$(cat "${key_file}.pub")
            if grep -qF "$pub_key" "$imp_dir/authorized_keys" 2>/dev/null; then
                print_warn "该公钥已存在，无需重复添加。"
            else
                chmod 700 "$imp_dir" 2>/dev/null || true
                chown "$imp_user:$imp_user" "$imp_dir" 2>/dev/null || true
                _ssh_authorized_keys_append "$imp_dir/authorized_keys" "$pub_key" "$imp_user:$imp_user" || {
                    print_error "公钥导入失败"
                    pause; return
                }
                print_success "公钥已导入 ${imp_user} 的 authorized_keys。"
                log_action "SSH pubkey auto-imported for user $imp_user from $key_file"
            fi
        fi
        ;;
    5)
        if ! _ssh_authorized_keys_available; then
            print_error "未检测到任何可登录用户的 authorized_keys，禁止关闭密码登录以避免锁外。"
            print_info "请先通过 [导入公钥] 部署并测试密钥登录。"
            pause; return
        fi
        if confirm "确认已测试密钥登录成功？"; then
            local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
            cp "$SSHD_CONFIG" "$backup_file"
            _sshd_set_directive "PasswordAuthentication" "no" "$SSHD_CONFIG" || { mv "$backup_file" "$SSHD_CONFIG"; pause; return; }
            if ! sshd -t 2>/dev/null; then
                print_error "sshd 配置校验失败！已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                pause; return
            fi
            local effective_password_auth
            effective_password_auth=$(_sshd_effective_value "passwordauthentication")
            if [[ "$effective_password_auth" != "no" ]]; then
                print_error "sshd -T 复验失败：PasswordAuthentication 实际为 ${effective_password_auth:-未知}，未生效。"
                print_error "可能被 /etc/ssh/sshd_config.d/*.conf 覆盖，已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                pause; return
            fi
            if ! _restart_sshd; then
                print_error "SSH 重启失败，已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                _restart_sshd || true
                pause; return
            fi
            rm -f "$backup_file"
            print_success "密码登录已禁用，并已通过 sshd -T 复验。"
            log_action "SSH password authentication disabled"
        fi
        ;;
    0|q) return ;;
    esac
    pause
}

menu_ssh() {
    fix_terminal
    while true; do
        print_title "SSH 安全管理 (当前端口: $CURRENT_SSH_PORT)"
        echo "1. 修改 SSH 端口
2. 创建 Sudo 用户
3. 禁用 Root 远程登录
4. 密钥管理 (导入/查看/删除/生成)
5. 修改用户密码
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) ssh_change_port ;;
            2) 
                read -e -r -p "新用户名: " u
                if [[ -n "$u" ]]; then
                    adduser "$u" && usermod -aG sudo "$u" && \
                    print_success "用户创建成功。" && \
                    log_action "Created sudo user: $u"
                fi
                pause ;;
            3)
                if ! _ssh_non_root_sudo_available; then
                    print_error "未检测到非 root sudo 用户，禁止禁用 Root 登录以避免锁外。"
                    print_info "请先通过 [创建 Sudo 用户] 创建并测试可登录用户。"
                    pause; continue
                fi
                if confirm "禁用 Root 登录？"; then
                    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
                    cp "$SSHD_CONFIG" "$backup_file"
                    _sshd_set_directive "PermitRootLogin" "no" "$SSHD_CONFIG" || { mv "$backup_file" "$SSHD_CONFIG"; pause; continue; }
                    if ! sshd -t 2>/dev/null; then
                        print_error "sshd 配置校验失败！已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        pause; continue
                    fi
                    local effective_root_login
                    effective_root_login=$(_sshd_effective_value "permitrootlogin")
                    if [[ "$effective_root_login" != "no" ]]; then
                        print_error "sshd -T 复验失败：PermitRootLogin 实际为 ${effective_root_login:-未知}，未生效。"
                        print_error "可能被 /etc/ssh/sshd_config.d/*.conf 覆盖，已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        pause; continue
                    fi
                    if ! _restart_sshd; then
                        print_error "SSH 重启失败，已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        _restart_sshd || true
                        pause; continue
                    fi
                    rm -f "$backup_file"
                    print_success "Root 登录已禁用，并已通过 sshd -T 复验。"
                    log_action "SSH root login disabled"
                fi
                pause ;;
            4) ssh_keys ;;
            5) 
                read -e -r -p "用户名 [root]: " u
                u=${u:-root}
                passwd "$u"
                pause ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
        refresh_ssh_port
    done
}
