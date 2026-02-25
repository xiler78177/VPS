# modules/12-backup.sh - 备份与恢复
backup_create() {
    print_title "创建备份"
    print_info "正在扫描 VPS 可备份项..."
    local -a scan_names=()
    local -a scan_paths=()
    local -a scan_types=()   # dir / file / cmd
    local -a scan_tags=()    # 存档内目录名
    local -a scan_selected=()
    
    _scan_add() {
        scan_names+=("$1"); scan_paths+=("$2")
        scan_types+=("$3"); scan_tags+=("$4")
        scan_selected+=(1)
    }
    [[ -d /etc/nginx ]] && _scan_add "Nginx 配置" "/etc/nginx" "dir" "nginx"
    [[ -d /etc/wireguard ]] && _scan_add "WireGuard 配置" "/etc/wireguard" "dir" "wireguard"
    [[ -d "$DDNS_CONFIG_DIR" ]] && _scan_add "DDNS 配置" "$DDNS_CONFIG_DIR" "dir" "ddns"
    [[ -d "$SAAS_CONFIG_DIR" ]] && _scan_add "SaaS CDN 配置" "$SAAS_CONFIG_DIR" "dir" "saas-cdn"
    [[ -d "$CONFIG_DIR" ]] && _scan_add "域名管理配置" "$CONFIG_DIR" "dir" "domain-configs"
    [[ -f /etc/fail2ban/jail.local ]] && _scan_add "Fail2ban 规则" "/etc/fail2ban/jail.local" "file" "fail2ban/jail.local"
    [[ -d "$CERT_PATH_PREFIX" ]] && _scan_add "SSL 证书" "$CERT_PATH_PREFIX" "dir" "certs"
    [[ -d "$CERT_HOOKS_DIR" ]] && _scan_add "证书续签 Hooks" "$CERT_HOOKS_DIR" "dir" "cert-hooks"
    command -v crontab >/dev/null 2>&1 && _scan_add "Crontab 定时任务" "crontab" "cmd" "crontab.bak"
    if command_exists docker; then
        # Docker 运行时配置 (daemon.json/镜像加速等)
        [[ -d /etc/docker ]] && _scan_add "Docker 配置" "/etc/docker" "dir" "docker-config"
        # Docker Compose 项目目录 (包含 compose 文件+挂载数据)
        for dc_dir in /opt /root /home/*; do
            for dc_file in "$dc_dir"/*/docker-compose.{yml,yaml} "$dc_dir"/*/compose.{yml,yaml}; do
                [[ -f "$dc_file" ]] || continue
                local pdir=$(dirname "$dc_file")
                _scan_add "Docker: $(basename "$pdir")" "$pdir" "dir" "docker-$(basename "$pdir")"
            done
        done 2>/dev/null
    fi
    [[ -d /etc/x-ui ]]              && _scan_add "3X-UI 面板"        "/etc/x-ui"              "dir" "x-ui"
    [[ -d /usr/local/x-ui ]]        && _scan_add "3X-UI 程序目录"    "/usr/local/x-ui"        "dir" "x-ui-app"
    [[ -d /opt/alist ]]             && _scan_add "Alist"             "/opt/alist"             "dir" "alist"
    [[ -d /opt/1panel ]]            && _scan_add "1Panel"            "/opt/1panel"            "dir" "1panel"
    [[ -d /root/.acme.sh ]]         && _scan_add "ACME.sh 证书"     "/root/.acme.sh"         "dir" "acme-sh"
    [[ -d /etc/hysteria ]]          && _scan_add "Hysteria"          "/etc/hysteria"          "dir" "hysteria"
    [[ -d /usr/local/etc/xray ]]    && _scan_add "Xray"             "/usr/local/etc/xray"    "dir" "xray"
    [[ -d /usr/local/etc/v2ray ]]   && _scan_add "V2Ray"            "/usr/local/etc/v2ray"   "dir" "v2ray"
    [[ -d /etc/sing-box ]]          && _scan_add "Sing-box"          "/etc/sing-box"          "dir" "sing-box"
    [[ -d /etc/caddy ]]             && _scan_add "Caddy"             "/etc/caddy"             "dir" "caddy"
    [[ -d /etc/haproxy ]]           && _scan_add "HAProxy"           "/etc/haproxy"           "dir" "haproxy"
    [[ -d /etc/frp ]]               && _scan_add "FRP 内网穿透"      "/etc/frp"               "dir" "frp"
    [[ -d /etc/nezha ]]             && _scan_add "哪吒监控"          "/etc/nezha"             "dir" "nezha"
    [[ -d /opt/nezha ]]             && _scan_add "哪吒监控(opt)"     "/opt/nezha"             "dir" "nezha-opt"
    [[ -f "$CONFIG_FILE" ]]         && _scan_add "脚本自身配置"      "$CONFIG_FILE"           "file" "script-config"
    [[ -f /usr/local/bin/ddns-update.sh ]] && _scan_add "DDNS更新脚本" "/usr/local/bin/ddns-update.sh" "file" "ddns-update.sh"
    local total=${#scan_names[@]}
    if [[ $total -eq 0 ]]; then
        print_warn "未发现任何可备份项。"
        pause; return 1
    fi
    echo -e "${C_CYAN}发现 ${total} 项可备份内容:${C_RESET}"
    draw_line
    local i
    for ((i=0; i<total; i++)); do
        local mark="✓"; [[ "${scan_selected[$i]}" -eq 0 ]] && mark=" "
        printf "  [${C_GREEN}%s${C_RESET}] %2d. %-28s ${C_GRAY}%s${C_RESET}\n" "$mark" "$((i+1))" "${scan_names[$i]}" "${scan_paths[$i]}"
    done
    draw_line
    echo -e "  ${C_GRAY}输入序号切换选中 | a=全选 | n=全不选 | Enter=开始备份 | 0=取消${C_RESET}"
    
    while true; do
        read -e -r -p "操作: " sel_input
        case "$sel_input" in
            "") break ;;
            0) return ;;
            a|A) for ((i=0; i<total; i++)); do scan_selected[$i]=1; done ;;
            n|N) for ((i=0; i<total; i++)); do scan_selected[$i]=0; done ;;
            *)
                if [[ "$sel_input" =~ ^[0-9]+$ ]] && (( sel_input >= 1 && sel_input <= total )); then
                    local ti=$((sel_input - 1))
                    scan_selected[$ti]=$(( 1 - scan_selected[ti] ))
                else
                    print_warn "无效输入"; continue
                fi ;;
        esac
        for ((i=0; i<total; i++)); do
            local mark="✓"; [[ "${scan_selected[$i]}" -eq 0 ]] && mark=" "
            printf "  [${C_GREEN}%s${C_RESET}] %2d. %-28s\n" "$mark" "$((i+1))" "${scan_names[$i]}"
        done
    done
    local selected_count=0
    for ((i=0; i<total; i++)); do
        [[ "${scan_selected[$i]}" -eq 1 ]] && selected_count=$((selected_count + 1))
    done
    [[ $selected_count -eq 0 ]] && { print_warn "未选择任何项。"; pause; return; }
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local backup_name="${SCRIPT_NAME}-backup-${timestamp}"
    local backup_file="${BACKUP_LOCAL_DIR}/${backup_name}.tar.gz"
    local tmp_dir=$(mktemp -d "/tmp/${SCRIPT_NAME}-backup.XXXXXX")
    trap "rm -rf '$tmp_dir'" RETURN
    mkdir -p "$BACKUP_LOCAL_DIR" "${tmp_dir}/data"
    print_info "正在收集 $selected_count 项备份数据..."
    local items_backed=0
    for ((i=0; i<total; i++)); do
        [[ "${scan_selected[$i]}" -eq 0 ]] && continue
        local name="${scan_names[$i]}" path="${scan_paths[$i]}"
        local type="${scan_types[$i]}" tag="${scan_tags[$i]}"
        case "$type" in
            dir)
                cp -r "$path" "${tmp_dir}/data/${tag}" 2>/dev/null && {
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"
                    items_backed=$((items_backed + 1))
                } || echo -e "  ${C_RED}✗${C_RESET} $name (失败)"
                ;;
            file)
                mkdir -p "${tmp_dir}/data/$(dirname "$tag")" 2>/dev/null
                cp -L "$path" "${tmp_dir}/data/${tag}" 2>/dev/null && {
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"
                    items_backed=$((items_backed + 1))
                } || echo -e "  ${C_RED}✗${C_RESET} $name (失败)"
                ;;
            cmd)
                if [[ "$tag" == "crontab.bak" ]]; then
                    crontab -l 2>/dev/null > "${tmp_dir}/data/crontab.bak" && {
                        echo -e "  ${C_GREEN}✓${C_RESET} $name"; items_backed=$((items_backed + 1))
                    }
                elif [[ "$tag" == "docker-volumes" ]]; then
                    mkdir -p "${tmp_dir}/data/docker-volumes"
                    local vol
                    for vol in $(docker volume ls -q 2>/dev/null); do
                        local vp=$(docker volume inspect "$vol" --format '{{.Mountpoint}}' 2>/dev/null)
                        [[ -n "$vp" && -d "$vp" ]] && cp -r "$vp" "${tmp_dir}/data/docker-volumes/${vol}" 2>/dev/null || true
                    done
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"; items_backed=$((items_backed + 1))
                fi ;;
        esac
    done
    
    # 元信息
    printf "VERSION=%s\nDATE=%s\nHOSTNAME=%s\nITEMS=%d\n" \
        "$VERSION" "$(date '+%Y-%m-%d %H:%M:%S')" "$(hostname)" "$items_backed" \
        > "${tmp_dir}/data/backup_meta.txt"
    print_info "正在压缩..."
    tar -czf "$backup_file" -C "${tmp_dir}/data" . 2>/dev/null || {
        print_error "压缩失败"; pause; return 1
    }
    local file_size=$(du -h "$backup_file" 2>/dev/null | awk '{print $1}')
    echo ""
    print_success "备份完成！"
    echo -e "  文件: ${C_GREEN}$backup_file${C_RESET}"
    echo -e "  大小: $file_size | 项目: $items_backed 项"
    if [[ -f "$BACKUP_CONFIG_FILE" ]] && validate_conf_file "$BACKUP_CONFIG_FILE"; then
        source "$BACKUP_CONFIG_FILE" 2>/dev/null
        if [[ -n "$WEBDAV_URL" ]]; then
            if [[ "${BACKUP_NON_INTERACTIVE:-}" == "1" ]] || confirm "是否上传到 WebDAV 远程存储?"; then
                backup_webdav_upload "$backup_file"
            fi
        fi
    fi
    log_action "Backup created: $backup_file ($file_size, $items_backed items)"
    pause
}

backup_webdav_upload() {
    local file="$1"
    [[ ! -f "$file" ]] && { print_error "文件不存在: $file"; return 1; }
    if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
        print_error "WebDAV 未配置。请先使用菜单配置 WebDAV 参数。"
        return 1
    fi
    validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; return 1; }
    source "$BACKUP_CONFIG_FILE" 2>/dev/null
    if [[ -z "$WEBDAV_URL" || -z "$WEBDAV_USER" || -z "$WEBDAV_PASS" ]]; then
        print_error "WebDAV 配置不完整。"
        return 1
    fi
    local upload_file="$file"
    local filename=$(basename "$file")
    local encrypted=0
    
    # 加密选项
    if [[ "${WEBDAV_ENCRYPT:-}" == "true" ]] || { [[ "${BACKUP_NON_INTERACTIVE:-}" != "1" ]] && confirm "是否加密后再上传? (AES-256, 推荐启用)"; }; then
        if ! command_exists openssl; then
            print_warn "openssl 未安装，跳过加密直接上传。"
        else
            local enc_pass="${WEBDAV_ENC_KEY:-}"
            if [[ -z "$enc_pass" ]]; then
                read -s -r -p "设置加密密码 (用于解密恢复): " enc_pass
                echo ""
                if [[ -z "$enc_pass" ]]; then
                    print_warn "密码为空，跳过加密。"
                else
                    echo ""
                    print_guide "提示: 可在 WebDAV 配置中设置 WEBDAV_ENC_KEY 免去每次输入。"
                fi
            fi
            if [[ -n "$enc_pass" ]]; then
                upload_file="${file}.enc"
                print_info "正在加密..."
                if printf '%s' "${enc_pass}" | openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
                    -in "$file" -out "$upload_file" -pass stdin 2>/dev/null; then
                    filename="${filename}.enc"
                    encrypted=1
                    local enc_size=$(du -h "$upload_file" 2>/dev/null | awk '{print $1}')
                    print_success "加密完成 (加密后: $enc_size)"
                else
                    print_error "加密失败，使用明文上传。"
                    upload_file="$file"
                fi
            fi
        fi
    fi
    local upload_url="${WEBDAV_URL%/}/${filename}"
    print_info "正在上传: ${filename}..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        -L \
        -T "$upload_file" \
        -u "${WEBDAV_USER}:${WEBDAV_PASS}" \
        --connect-timeout 10 \
        --max-time 600 \
        "$upload_url" 2>/dev/null)
    
    # 清理加密临时文件
    [[ $encrypted -eq 1 ]] && rm -f "$upload_file"
    if [[ "$http_code" =~ ^(200|201|204)$ ]]; then
        print_success "上传成功！(HTTP $http_code)"
        [[ $encrypted -eq 1 ]] && print_info "文件已加密传输 (AES-256-CBC)。恢复时需要解密密码。"
        log_action "Backup uploaded to WebDAV: $filename (encrypted=$encrypted)"
    else
        print_error "上传失败 (HTTP $http_code)"
        return 1
    fi
}

backup_webdav_config() {
    print_title "WebDAV 远程存储配置"
    if [[ -f "$BACKUP_CONFIG_FILE" ]] && validate_conf_file "$BACKUP_CONFIG_FILE"; then
        source "$BACKUP_CONFIG_FILE" 2>/dev/null
        echo -e "当前配置:"
        echo -e "  URL:  ${C_CYAN}${WEBDAV_URL:-未设置}${C_RESET}"
        echo -e "  用户: ${C_CYAN}${WEBDAV_USER:-未设置}${C_RESET}"
        echo -e "  密码: ${C_CYAN}${WEBDAV_PASS:+****}${C_RESET}"
        echo -e "  加密: ${C_CYAN}${WEBDAV_ENCRYPT:-false}${C_RESET}"
        [[ -n "${WEBDAV_ENC_KEY:-}" ]] && echo -e "  密钥: ${C_CYAN}****${C_RESET}"
        echo ""
    fi
    echo "1. 设置/修改 WebDAV 参数
2. 测试 WebDAV 连通性
3. 配置传输加密
4. 清除 WebDAV 配置
0. 返回
"
    read -e -r -p "选择: " wc
    case $wc in
        1)
            local url user pass
            echo ""
            print_guide "输入 WebDAV 地址 (例如 https://dav.jianguoyun.com/dav/backups)"
            read -e -r -p "WebDAV URL: " url
            [[ -z "$url" ]] && { print_warn "已取消"; pause; return; }
            read -e -r -p "用户名: " user
            [[ -z "$user" ]] && { print_warn "已取消"; pause; return; }
            read -s -r -p "密码/应用密钥: " pass
            echo ""
            [[ -z "$pass" ]] && { print_warn "已取消"; pause; return; }
            # 转义特殊字符防止 source 时执行
            local safe_url safe_user safe_pass
            safe_url=$(printf '%s' "$url" | sed 's/["\\$`]/\\&/g')
            safe_user=$(printf '%s' "$user" | sed 's/["\\$`]/\\&/g')
            safe_pass=$(printf '%s' "$pass" | sed 's/["\\$`]/\\&/g')
            write_file_atomic "$BACKUP_CONFIG_FILE" "# WebDAV 备份配置
# Generated by $SCRIPT_NAME $VERSION
WEBDAV_URL=\"$safe_url\"
WEBDAV_USER=\"$safe_user\"
WEBDAV_PASS=\"$safe_pass\"
WEBDAV_ENCRYPT=\"false\"
WEBDAV_ENC_KEY=\"\""
            chmod 600 "$BACKUP_CONFIG_FILE"
            print_success "WebDAV 配置已保存。"
            ;;
        2)
            if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
                print_error "未配置 WebDAV"; pause; return
            fi
            validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; pause; return; }
            source "$BACKUP_CONFIG_FILE" 2>/dev/null
            print_info "正在测试连通性..."
            local code
            code=$(curl -s -o /dev/null -w "%{http_code}" \
                -L \
                -u "${WEBDAV_USER}:${WEBDAV_PASS}" \
                --connect-timeout 10 \
                -X PROPFIND "$WEBDAV_URL" 2>/dev/null)
            if [[ "$code" =~ ^(200|207|301|405)$ ]]; then
                print_success "连接成功 (HTTP $code)"
            else
                print_error "连接失败 (HTTP $code)"
            fi
            ;;
        3)
            if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
                print_error "未配置 WebDAV"; pause; return
            fi
            validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; pause; return; }
            source "$BACKUP_CONFIG_FILE" 2>/dev/null
            echo -e "当前加密状态: $( [[ "${WEBDAV_ENCRYPT:-}" == "true" ]] && echo -e "${C_GREEN}已启用${C_RESET}" || echo -e "${C_YELLOW}未启用${C_RESET}" )"
            echo "  1. 启用加密上传 (每次上传前自动 AES-256-CBC 加密)
  2. 关闭加密上传
  3. 设置加密密钥 (免去每次输入)
"
            read -e -r -p "选择: " ec
            case $ec in
                1)
                    sed -i 's/^WEBDAV_ENCRYPT=.*/WEBDAV_ENCRYPT="true"/' "$BACKUP_CONFIG_FILE" 2>/dev/null
                    print_success "加密已启用。上传时将自动加密。"
                    ;;
                2)
                    sed -i 's/^WEBDAV_ENCRYPT=.*/WEBDAV_ENCRYPT="false"/' "$BACKUP_CONFIG_FILE" 2>/dev/null
                    print_success "加密已关闭。"
                    ;;
                3)
                    read -s -r -p "输入加密密钥: " ekey
                    echo ""
                    if [[ -n "$ekey" ]]; then
                        # 完整转义: 双引号、反斜杠、$、反引号、sed分隔符
                        local escaped_key
                        escaped_key=$(printf '%s' "$ekey" | sed 's/[\\/"$`&]/\\&/g')
                        sed -i "s/^WEBDAV_ENC_KEY=.*/WEBDAV_ENC_KEY=\"${escaped_key}\"/" "$BACKUP_CONFIG_FILE" 2>/dev/null
                        print_success "加密密钥已保存。"
                    fi
                    ;;
            esac
            ;;
        4)
            if [[ -f "$BACKUP_CONFIG_FILE" ]]; then
                rm -f "$BACKUP_CONFIG_FILE"
                print_success "WebDAV 配置已清除。"
            else
                print_warn "无配置可清除。"
            fi
            ;;
    esac
    pause
}

backup_schedule() {
    print_title "定时备份设置"
    local current_cron=""
    current_cron=$(crontab -l 2>/dev/null | grep "${SCRIPT_NAME}.*--backup" || true)
    if [[ -n "$current_cron" ]]; then
        echo -e "当前定时备份: ${C_GREEN}已启用${C_RESET}"
        echo -e "  ${C_GRAY}$current_cron${C_RESET}"
        echo "1. 修改定时频率
2. 停用定时备份
0. 返回"
    else
        echo -e "当前定时备份: ${C_YELLOW}未启用${C_RESET}"
        echo "1. 启用定时备份
0. 返回"
    fi
    read -e -r -p "选择: " sc
    case $sc in
        1)
            echo ""
            echo "选择备份频率:
  1. 每日 4:00 AM
  2. 每周日 4:00 AM
  3. 每月1日 4:00 AM
"
            read -e -r -p "选择 [1]: " freq
            freq=${freq:-1}
            local cron_expr=""
            case $freq in
                1) cron_expr="0 4 * * *" ;;
                2) cron_expr="0 4 * * 0" ;;
                3) cron_expr="0 4 1 * *" ;;
                *) print_error "无效选项"; pause; return ;;
            esac
            
            # 获取脚本实际路径
            local script_path=$(readlink -f "$0" 2>/dev/null || echo "$0")
            cron_add_job "${SCRIPT_NAME}.*--backup" "$cron_expr bash $script_path --backup >/dev/null 2>&1"
            print_success "定时备份已设置。"
            ;;
        2)
            cron_remove_job "${SCRIPT_NAME}.*--backup"
            print_success "定时备份已停用。"
            ;;
    esac
    pause
}

backup_restore() {
    print_title "恢复备份"
    echo "选择恢复来源:
  1. 本地备份
  2. WebDAV 远程备份
  0. 返回
"
    read -e -r -p "选择: " src
    local restore_file=""
    case $src in
        1)
            # 列出本地备份
            if [[ ! -d "$BACKUP_LOCAL_DIR" ]] || [[ -z "$(ls -A "$BACKUP_LOCAL_DIR" 2>/dev/null)" ]]; then
                print_warn "本地无备份文件。"
                pause; return
            fi
            echo -e "${C_CYAN}本地备份列表:${C_RESET}"
            local i=1 files=()
            for f in $(ls -t "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null); do
                local fsize=$(du -h "$f" 2>/dev/null | awk '{print $1}')
                local fname=$(basename "$f")
                echo "  $i. $fname ($fsize)"
                files+=("$f")
                i=$((i + 1))
                [[ $i -gt 20 ]] && break
            done
            echo "  0. 返回"
            read -e -r -p "选择要恢复的备份序号: " idx
            [[ "$idx" == "0" || -z "$idx" ]] && return
            if [[ "$idx" =~ ^[0-9]+$ ]] && [[ $idx -ge 1 && $idx -le ${#files[@]} ]]; then
                restore_file="${files[$((idx - 1))]}"
            else
                print_error "无效序号"; pause; return
            fi
            ;;
        2)
            if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
                print_error "WebDAV 未配置。请先配置 WebDAV 参数。"
                pause; return
            fi
            validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; pause; return; }
            source "$BACKUP_CONFIG_FILE" 2>/dev/null
            print_info "正在获取远程备份列表..."
            local remote_list
            remote_list=$(curl -s -u "${WEBDAV_USER}:${WEBDAV_PASS}" --connect-timeout 10 \
                -X PROPFIND "$WEBDAV_URL" 2>/dev/null | grep -oP "${SCRIPT_NAME}-backup-[^<\"]+\.tar\.gz(\.enc)?" | sort -ur | head -20)
            if [[ -z "$remote_list" ]]; then
                print_warn "远程无备份文件或无法连接。"
                pause; return
            fi
            echo -e "${C_CYAN}远程备份列表:${C_RESET}"
            local i=1 rfiles=()
            while IFS= read -r fname; do
                echo "  $i. $fname"
                rfiles+=("$fname")
                i=$((i + 1))
            done <<< "$remote_list"
            echo "  0. 返回"
            read -e -r -p "选择要恢复的备份序号: " idx
            [[ "$idx" == "0" || -z "$idx" ]] && return
            if [[ "$idx" =~ ^[0-9]+$ ]] && [[ $idx -ge 1 && $idx -le ${#rfiles[@]} ]]; then
                local remote_fname="${rfiles[$((idx - 1))]}"
                restore_file="/tmp/${remote_fname}"
                print_info "正在下载 ${remote_fname}..."
                if ! curl -s -u "${WEBDAV_USER}:${WEBDAV_PASS}" \
                    -o "$restore_file" --connect-timeout 10 --max-time 300 \
                    "${WEBDAV_URL%/}/${remote_fname}" 2>/dev/null; then
                    print_error "下载失败"
                    pause; return
                fi
                print_success "下载完成。"
            else
                print_error "无效序号"; pause; return
            fi
            ;;
        *) return ;;
    esac
    [[ -z "$restore_file" || ! -f "$restore_file" ]] && { print_error "备份文件不存在"; pause; return; }
    
    # 如果是加密文件，先解密
    if [[ "$restore_file" == *.enc ]]; then
        print_warn "检测到加密备份文件，需要解密。"
        local dec_pass="${WEBDAV_ENC_KEY:-}"
        if [[ -z "$dec_pass" ]]; then
            read -s -r -p "输入解密密码: " dec_pass
            echo ""
        fi
        [[ -z "$dec_pass" ]] && { print_error "密码不能为空"; pause; return; }
        local dec_file="${restore_file%.enc}"
        print_info "正在解密..."
        if ! printf '%s' "${dec_pass}" | openssl enc -aes-256-cbc -d -salt -pbkdf2 -iter 100000 \
            -in "$restore_file" -out "$dec_file" -pass stdin 2>/dev/null; then
            print_error "解密失败，密码可能不正确。"
            rm -f "$dec_file"
            pause; return
        fi
        restore_file="$dec_file"
        print_success "解密完成。"
    fi
    print_warn "恢复操作将覆盖现有配置。"
    if ! confirm "确认恢复? (建议先备份当前配置)"; then
        pause; return
    fi
    local tmp_restore=$(mktemp -d "/tmp/${SCRIPT_NAME}-restore.XXXXXX")
    trap "rm -rf '$tmp_restore'" RETURN
    print_info "正在解压..."
    if ! tar -xzf "$restore_file" -C "$tmp_restore" 2>/dev/null; then
        print_error "解压失败，文件可能已损坏。"
        pause; return 1
    fi
    
    # 逐项恢复
    local restored=0
    [[ -d "${tmp_restore}/nginx" ]] && {
        cp -r "${tmp_restore}/nginx/"* /etc/nginx/ 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} /etc/nginx"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/wireguard" ]] && {
        cp -r "${tmp_restore}/wireguard/"* /etc/wireguard/ 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} /etc/wireguard"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/ddns" ]] && {
        mkdir -p "$DDNS_CONFIG_DIR"
        cp -r "${tmp_restore}/ddns/"* "$DDNS_CONFIG_DIR/" 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} $DDNS_CONFIG_DIR"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/saas-cdn" ]] && {
        mkdir -p "$SAAS_CONFIG_DIR"
        cp -r "${tmp_restore}/saas-cdn/"* "$SAAS_CONFIG_DIR/" 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} $SAAS_CONFIG_DIR"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/fail2ban" ]] && {
        cp "${tmp_restore}/fail2ban/jail.local" /etc/fail2ban/ 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} /etc/fail2ban/jail.local"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/certs" ]] && {
        mkdir -p "$CERT_PATH_PREFIX"
        cp -r "${tmp_restore}/certs/"* "$CERT_PATH_PREFIX/" 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} $CERT_PATH_PREFIX"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/cert-hooks" ]] && {
        mkdir -p "$CERT_HOOKS_DIR"
        cp -r "${tmp_restore}/cert-hooks/"* "$CERT_HOOKS_DIR/" 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} $CERT_HOOKS_DIR"
        restored=$((restored + 1))
    }
    [[ -d "${tmp_restore}/domain-configs" ]] && {
        mkdir -p "$CONFIG_DIR"
        cp -r "${tmp_restore}/domain-configs/"* "$CONFIG_DIR/" 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} $CONFIG_DIR"
        restored=$((restored + 1))
    }
    [[ -f "${tmp_restore}/crontab.bak" ]] && {
        if confirm "是否恢复 crontab? (将替换当前所有 cron 定时任务)"; then
            crontab "${tmp_restore}/crontab.bak" 2>/dev/null
            echo -e "  ${C_GREEN}✓${C_RESET} crontab"
            restored=$((restored + 1))
        fi
    }
    [[ -f "${tmp_restore}/ddns-update.sh" ]] && {
        cp "${tmp_restore}/ddns-update.sh" /usr/local/bin/ 2>/dev/null
        chmod +x /usr/local/bin/ddns-update.sh 2>/dev/null
        echo -e "  ${C_GREEN}✓${C_RESET} ddns-update.sh"
    }
    
    # 重载服务（必须在清理临时目录之前检查）
    if command_exists nginx && [[ -d "${tmp_restore}/nginx" ]]; then
        nginx -t >/dev/null 2>&1 && {
            is_systemd && systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null
            print_info "Nginx 已重载。"
        }
    fi
    rm -rf "$tmp_restore"
    trap - RETURN
    echo ""
    print_success "恢复完成！共恢复 $restored 项。"
    log_action "Backup restored from: $(basename "$restore_file") ($restored items)"
    pause
}

backup_list() {
    print_title "备份文件列表"
    if [[ ! -d "$BACKUP_LOCAL_DIR" ]] || [[ -z "$(ls -A "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null)" ]]; then
        print_warn "本地无备份文件。"
        echo -e "  备份目录: ${C_GRAY}$BACKUP_LOCAL_DIR${C_RESET}"
        pause; return
    fi
    echo -e "${C_CYAN}本地备份:${C_RESET}"
    echo -e "  路径: ${C_GRAY}${BACKUP_LOCAL_DIR}${C_RESET}"
    draw_line
    for f in $(ls -t "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null | head -20); do
        local fsize=$(du -h "$f" 2>/dev/null | awk '{print $1}')
        local fdate=$(stat -c '%y' "$f" 2>/dev/null | cut -d'.' -f1 || stat -f '%Sm' "$f" 2>/dev/null)
        printf "  ${C_GREEN}%s${C_RESET}\n" "$f"
        printf "    大小: %s  日期: %s\n" "$fsize" "$fdate"
    done
    draw_line
    local total=$(ls -1 "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null | wc -l)
    local total_size=$(du -sh "$BACKUP_LOCAL_DIR" 2>/dev/null | awk '{print $1}')
    echo -e "  共 ${C_GREEN}${total}${C_RESET} 个备份, 占用 ${total_size}"
    pause
}

backup_clean() {
    print_title "清理旧备份"
    echo "1. 清理本地备份
2. 清理 WebDAV 远程备份
0. 返回
"
    read -e -r -p "选择: " clean_scope
    case $clean_scope in
        1) _backup_clean_local ;;
        2) _backup_clean_webdav ;;
        *) return ;;
    esac
}

_backup_clean_local() {
    if [[ ! -d "$BACKUP_LOCAL_DIR" ]] || [[ -z "$(ls -A "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null)" ]]; then
        print_warn "本地无备份文件。"
        pause; return
    fi
    local total=$(ls -1 "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null | wc -l)
    echo "本地共 $total 个备份。"
    echo ""
    echo "1. 保留最近 5 个，删除其余
2. 保留最近 10 个，删除其余
3. 删除全部备份
0. 返回
"
    read -e -r -p "选择: " cc
    local keep=0
    case $cc in
        1) keep=5 ;;
        2) keep=10 ;;
        3) keep=0 ;;
        *) return ;;
    esac
    if [[ $keep -eq 0 ]]; then
        confirm "确认删除全部本地备份?" || return
        rm -f "$BACKUP_LOCAL_DIR"/*.tar.gz
        print_success "全部本地备份已清除。"
    else
        local count=0
        for f in $(ls -t "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null); do
            count=$((count + 1))
            if [[ $count -gt $keep ]]; then
                rm -f "$f"
            fi
        done
        local deleted=$((count > keep ? count - keep : 0))
        print_success "已清理 $deleted 个本地旧备份，保留最近 $keep 个。"
    fi
    log_action "Local backup cleanup: kept=$keep"
    pause
}

_backup_clean_webdav() {
    if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
        print_error "WebDAV 未配置。请先使用菜单配置 WebDAV 参数。"
        pause; return
    fi
    validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; pause; return; }
    source "$BACKUP_CONFIG_FILE" 2>/dev/null
    if [[ -z "$WEBDAV_URL" || -z "$WEBDAV_USER" || -z "$WEBDAV_PASS" ]]; then
        print_error "WebDAV 配置不完整。"
        pause; return
    fi
    print_info "正在获取远程备份列表..."
    local remote_list
    remote_list=$(curl -s -u "${WEBDAV_USER}:${WEBDAV_PASS}" --connect-timeout 10 \
        -X PROPFIND "$WEBDAV_URL" 2>/dev/null | grep -oP "${SCRIPT_NAME}-backup-[^<\"]+\.tar\.gz(\.enc)?" | sort -ur)
    if [[ -z "$remote_list" ]]; then
        print_warn "远程无备份文件。"
        pause; return
    fi
    local total=$(echo "$remote_list" | wc -l)
    echo "远程共 $total 个备份。"
    echo ""
    echo "1. 保留最近 5 个，删除其余
2. 保留最近 10 个，删除其余
3. 删除全部远程备份
0. 返回
"
    read -e -r -p "选择: " cc
    local keep=0
    case $cc in
        1) keep=5 ;;
        2) keep=10 ;;
        3) keep=0 ;;
        *) return ;;
    esac
    if [[ $keep -eq 0 ]]; then
        confirm "确认删除全部远程备份?" || return
    fi
    local count=0 deleted=0
    while IFS= read -r fname; do
        count=$((count + 1))
        if [[ $keep -eq 0 ]] || [[ $count -gt $keep ]]; then
            local del_url="${WEBDAV_URL%/}/${fname}"
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" \
                -X DELETE -u "${WEBDAV_USER}:${WEBDAV_PASS}" \
                --connect-timeout 10 "$del_url" 2>/dev/null)
            if [[ "$http_code" =~ ^(200|204)$ ]]; then
                deleted=$((deleted + 1))
            else
                print_warn "删除失败: $fname (HTTP $http_code)"
            fi
        fi
    done <<< "$remote_list"
    if [[ $deleted -gt 0 ]]; then
        print_success "已清理 $deleted 个远程旧备份$([ $keep -gt 0 ] && echo "，保留最近 $keep 个")。"
    else
        print_warn "无需清理。"
    fi
    log_action "WebDAV backup cleanup: deleted=$deleted kept=$keep"
    pause
}

backup_manual_upload() {
    print_title "手动上传备份到 WebDAV"
    if [[ ! -f "$BACKUP_CONFIG_FILE" ]]; then
        print_error "WebDAV 未配置。请先使用菜单配置 WebDAV 参数。"
        pause; return
    fi
    validate_conf_file "$BACKUP_CONFIG_FILE" || { print_error "备份配置文件格式异常"; pause; return; }
    if [[ ! -d "$BACKUP_LOCAL_DIR" ]] || [[ -z "$(ls -A "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null)" ]]; then
        print_warn "本地无备份文件可上传。"
        pause; return
    fi
    echo -e "${C_CYAN}选择要上传的本地备份:${C_RESET}"
    local i=1 files=()
    for f in $(ls -t "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null); do
        local fsize=$(du -h "$f" 2>/dev/null | awk '{print $1}')
        printf "  %2d. %-50s (%s)\n" "$i" "$(basename "$f")" "$fsize"
        files+=("$f")
        i=$((i + 1))
        [[ $i -gt 20 ]] && break
    done
    echo "   0. 返回"
    read -e -r -p "选择序号: " idx
    [[ "$idx" == "0" || -z "$idx" ]] && return
    if [[ "$idx" =~ ^[0-9]+$ ]] && [[ $idx -ge 1 && $idx -le ${#files[@]} ]]; then
        local selected="${files[$((idx - 1))]}"
        print_info "已选择: $(basename "$selected")"
        backup_webdav_upload "$selected"
    else
        print_error "无效序号"
    fi
    pause
}

menu_backup() {
    while true; do
        print_title "备份与恢复 (支持 WebDAV)"
        local backup_count=$(ls -1 "$BACKUP_LOCAL_DIR"/*.tar.gz 2>/dev/null | wc -l)
        local webdav_status="未配置"
        [[ -f "$BACKUP_CONFIG_FILE" ]] && validate_conf_file "$BACKUP_CONFIG_FILE" 2>/dev/null && source "$BACKUP_CONFIG_FILE" 2>/dev/null && [[ -n "$WEBDAV_URL" ]] && webdav_status="已配置"
        echo -e "本地备份: ${C_GREEN}${backup_count}${C_RESET} 个 | WebDAV: ${C_GREEN}${webdav_status}${C_RESET}"
        echo "1. 立即创建备份
2. 恢复备份
3. 查看备份列表
4. 清理旧备份
5. 配置 WebDAV 远程存储
6. 定时备份设置
7. 手动上传备份到 WebDAV
0. 返回主菜单
"
        read -e -r -p "选择: " bc
        case $bc in
            1) backup_create ;;
            2) backup_restore ;;
            3) backup_list ;;
            4) backup_clean ;;
            5) backup_webdav_config ;;
            6) backup_schedule ;;
            7) backup_manual_upload ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}

