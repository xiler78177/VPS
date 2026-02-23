# modules/06-ssh.sh - SSH 端口修改与密钥管理
ssh_change_port() {
    print_title "修改 SSH 端口"
    read -e -r -p "请输入新端口 [$CURRENT_SSH_PORT]: " port
    [[ -z "$port" ]] && return
    if ! validate_port "$port"; then
        print_error "端口无效 (1-65535)。"
        pause; return
    fi

    # 检查端口是否已被其他服务占用
    if command_exists ss && ss -tlpn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${port}$"; then
        local occupier=$(ss -tlpn 2>/dev/null | awk -v p=":${port}$" '$4 ~ p {print $NF}' | head -1)
        print_error "端口 $port 已被占用: $occupier"
        if ! confirm "是否强制继续修改？(可能导致冲突)"; then
            pause; return
        fi
    fi
    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
    cp "$SSHD_CONFIG" "$backup_file"
    # 先放行新端口（防止改完连不上）
    local ufw_opened=0
    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "$port/tcp" comment "SSH-New" >/dev/null
        ufw_opened=1
        print_success "UFW 已放行新端口 $port。"
    fi
    if grep -qE "^\s*#?\s*Port\s" "$SSHD_CONFIG"; then
        sed -i -E "s|^\s*#?\s*Port\s+.*|Port ${port}|" "$SSHD_CONFIG"
    else
        echo "Port ${port}" >> "$SSHD_CONFIG"
    fi

    # 校验配置语法
    if ! sshd -t 2>/dev/null; then
        print_error "sshd 配置校验失败！已回滚。"
        mv "$backup_file" "$SSHD_CONFIG"
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        pause; return
    fi
    if _restart_sshd; then
        print_success "SSH 重启成功。请使用新端口 $port 连接。"
        if [[ $ufw_opened -eq 1 ]]; then
            ufw delete allow "$CURRENT_SSH_PORT/tcp" 2>/dev/null || true
        fi
        # 同步更新 Fail2ban jail 端口
        if [[ -f "$FAIL2BAN_JAIL_LOCAL" ]]; then
            sed -i "s/^port = .*/port = $port/" "$FAIL2BAN_JAIL_LOCAL"
            systemctl restart fail2ban 2>/dev/null || true
            print_info "Fail2ban 已同步新端口 $port"
        fi
        CURRENT_SSH_PORT=$port
        log_action "SSH port changed to $port"
        rm -f "$backup_file"
    else
        print_error "重启失败！已回滚配置。"
        mv "$backup_file" "$SSHD_CONFIG" 2>/dev/null || true
        [[ $ufw_opened -eq 1 ]] && { ufw delete allow "$port/tcp" 2>/dev/null || true; }
        _restart_sshd || true
    fi
    pause
}


ssh_keys() {
    print_title "SSH 密钥管理"
    echo "1. 导入公钥
2. 禁用密码登录"
    read -e -r -p "选择: " c
    if [[ "$c" == "1" ]]; then
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
        echo "$key" >> "$dir/authorized_keys"
        chmod 700 "$dir"
        chmod 600 "$dir/authorized_keys"
        chown -R "$user:$user" "$dir"
        print_success "公钥已添加。"
        log_action "SSH key added for user $user"
    elif [[ "$c" == "2" ]]; then
        if confirm "确认已测试密钥登录成功？"; then
            local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
            cp "$SSHD_CONFIG" "$backup_file"
            sed -i -E "s|^\s*#?\s*PasswordAuthentication\s+.*|PasswordAuthentication no|" "$SSHD_CONFIG"
            if ! sshd -t 2>/dev/null; then
                print_error "sshd 配置校验失败！已回滚。"
                mv "$backup_file" "$SSHD_CONFIG"
                pause; return
            fi
            _restart_sshd || true
            rm -f "$backup_file"
            print_success "密码登录已禁用。"
            log_action "SSH password authentication disabled"
        fi
    fi
    pause
}

menu_ssh() {
    fix_terminal
    while true; do
        print_title "SSH 安全管理 (当前端口: $CURRENT_SSH_PORT)"
        echo "1. 修改 SSH 端口
2. 创建 Sudo 用户
3. 禁用 Root 远程登录
4. 密钥/密码设置
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
                if confirm "禁用 Root 登录？"; then
                    local backup_file="${SSHD_CONFIG}.bak.$(date +%s)"
                    cp "$SSHD_CONFIG" "$backup_file"
                    sed -i -E "s|^\s*#?\s*PermitRootLogin\s+.*|PermitRootLogin no|" "$SSHD_CONFIG"
                    if ! sshd -t 2>/dev/null; then
                        print_error "sshd 配置校验失败！已回滚。"
                        mv "$backup_file" "$SSHD_CONFIG"
                        pause; break
                    fi
                    _restart_sshd || true
                    rm -f "$backup_file"
                    print_success "Root 登录已禁用。"
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
