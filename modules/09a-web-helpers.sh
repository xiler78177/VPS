# modules/09a-web-helpers.sh - Web 模块基础设施（依赖管理 + 通用辅助函数）
_web_dep_check_results=()

_web_dep_run_check() {
    local check_id="$1"
    case "$check_id" in
        jq) command_exists jq ;;
        nginx) command_exists nginx ;;
        nginx_dirs) _check_nginx_dirs ;;
        certbot) command_exists certbot ;;
        certbot_dns_cf) _check_certbot_dns_cf ;;
        *) return 1 ;;
    esac
}

_web_dep_run_install() {
    local install_id="$1"
    case "$install_id" in
        jq) install_package jq silent ;;
        nginx) _install_nginx ;;
        nginx_dirs) mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets ;;
        certbot) _install_certbot ;;
        certbot_dns_cf) _install_certbot_dns_cf ;;
        *) return 1 ;;
    esac
}

_web_dep_verify() {
    local name="$1" check_id="$2"
    if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
        _web_dep_check_results+=("${C_GREEN}✓${C_RESET} $name")
        return 0
    else
        _web_dep_check_results+=("${C_RED}✗${C_RESET} $name")
        return 1
    fi
}

_web_dep_fix() {
    local name="$1" check_id="$2" install_id="$3"
    if ! _web_dep_run_check "$check_id" >/dev/null 2>&1; then
        print_info "修复: $name ..."
        if _web_dep_run_install "$install_id"; then
            if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
                print_success "$name 修复成功"
                return 0
            fi
        fi
        print_error "$name 修复失败"
        return 1
    fi
    return 0
}

_purge_snap_certbot() {
    if snap list certbot &>/dev/null 2>&1; then
        print_info "检测到 snap 版 certbot，正在清理..."
        snap remove certbot 2>/dev/null || true
        snap remove certbot-dns-cloudflare 2>/dev/null || true
        local link target
        for link in /usr/bin/certbot /snap/bin/certbot; do
            if [[ -L "$link" ]]; then
                target=$(readlink "$link" 2>/dev/null || true)
                if [[ "$link" == "/snap/bin/certbot" || "$target" == "/snap/bin/certbot" || "$target" == *"/snap/certbot/"* ]]; then
                    rm -f "$link" 2>/dev/null || true
                fi
            fi
        done
        if [[ $(snap list 2>/dev/null | tail -n +2 | wc -l) -eq 0 ]]; then
            print_info "snap 中无其他软件包，清理 snapd..."
            systemctl stop snapd snapd.socket 2>/dev/null || true
            apt-get purge -y snapd 2>/dev/null || true
            print_success "snapd 已清理"
        fi
        log_action "Purged snap certbot"
    fi
}

_install_certbot_apt() {
    _purge_snap_certbot
    update_apt_cache
    apt-get install -y certbot >/dev/null 2>&1
}

_install_certbot_snap() {
    install_package "snapd" "silent" || return 1
    snap install --classic certbot >/dev/null 2>&1 || return 1
    ln -sf /snap/bin/certbot /usr/bin/certbot
}

_install_certbot_dns_cf_apt() {
    _purge_snap_certbot
    update_apt_cache
    if ! dpkg -s certbot &>/dev/null; then
        apt-get install -y certbot >/dev/null 2>&1 || return 1
    fi
    apt-get install -y python3-certbot-dns-cloudflare >/dev/null 2>&1
}

_install_certbot_dns_cf_snap() {
    if ! command_exists snap; then
        install_package "snapd" "silent" || { print_error "snapd 安装失败"; return 1; }
        if is_systemd; then
            systemctl enable --now snapd.socket >/dev/null 2>&1 || true
            print_info "等待 snapd 初始化 (低配机器可能需要几分钟)..."
            local wait=0
            while [[ $wait -lt 120 ]]; do
                snap version &>/dev/null && break
                echo -ne "\r  已等待 ${wait}s..."
                sleep 3; wait=$((wait + 3))
            done
            if ! snap version &>/dev/null; then
                print_error "snapd 未就绪 (等待 ${wait}s 超时)"
                return 1
            fi
        fi
    fi
    snap install core 2>/dev/null || true
    snap refresh core 2>/dev/null || true
    print_info "snap 安装 certbot (可能需要几分钟，请耐心等待)..."
    if ! snap install --classic certbot 2>&1; then
        print_error "snap install certbot 失败"
        return 1
    fi
    ln -sf /snap/bin/certbot /usr/bin/certbot
    # 授权插件 root 权限（snap 强制要求）
    snap set certbot trust-plugin-with-root=ok 2>/dev/null || true
    print_info "snap 安装 certbot-dns-cloudflare..."
    if ! snap install certbot-dns-cloudflare 2>&1; then
        print_error "snap install certbot-dns-cloudflare 失败"
        return 1
    fi
    snap connect certbot:plugin certbot-dns-cloudflare >/dev/null 2>&1 || true
    print_success "snap 安装完成"
    return 0
}

_install_certbot_dns_cf() {
    # 先尝试 apt 安装
    _install_certbot_dns_cf_apt || true

    # 检查 apt 装的版本是否可用（版本号 >= 1.0）
    if _check_certbot_dns_cf; then
        return 0
    fi

    # apt 版本不可用（如 20.04 的 0.39），切换 snap
    print_warn "apt 版本不兼容，切换 snap 安装..."
    apt-get remove -y certbot python3-certbot-dns-cloudflare 2>/dev/null || true
    _install_certbot_dns_cf_snap
}

# 统一的 certbot 安装入口（先 apt 后 snap）
_install_certbot() {
    _install_certbot_apt && return 0
    print_warn "apt 安装 certbot 失败，尝试 snap..."
    _install_certbot_snap
}

_install_nginx() {
    update_apt_cache
    apt-get install -y nginx >/dev/null 2>&1 || return 1
    is_systemd && systemctl enable --now nginx >/dev/null 2>&1 || true
}

# 检测 nginx 是否具备 stream 模块（ssl_preread 分流依赖）。
# 三种可用形态：静态编入(--with-stream)、动态模块已加载(modules-enabled 下有 stream so),
# 或发行版把 stream so 装在 modules 目录但未 load（此时需 load_module，交给 _ensure_nginx_stream 处理）。
_check_nginx_stream() {
    command_exists nginx || return 1
    local vout; vout="$(nginx -V 2>&1)"
    # 静态编入：nginx -V 中出现独立 token "--with-stream"。
    # 关键：必须逐 token 精确匹配（tr 空格换行 + grep -x），否则会把
    #   --with-stream=dynamic（动态模块，需 .so + load_module，非静态可用）
    #   --with-stream_ssl_module / --with-stream_ssl_preread_module（子模块 token）
    # 这类子串误判为「静态编入可用」——Debian 12 官方 nginx 正是 --with-stream=dynamic
    # 且 /usr/lib/nginx/modules 为空，误判会导致 stream{} 加载失败却报可用。
    if tr ' ' '\n' <<< "$vout" | grep -qx -- '--with-stream'; then
        return 0
    fi
    # 动态模块：必须「已在 modules-enabled 下 load」且「对应 .so 真实存在」才算当前可用。
    if ls /etc/nginx/modules-enabled/ 2>/dev/null | grep -q 'stream' && _nginx_stream_module_available; then
        return 0
    fi
    return 1
}

# 动态 stream 模块的 so 是否存在（用于判断能否走 load_module 而无需换源）
_nginx_stream_module_available() {
    ls /usr/lib/nginx/modules/ngx_stream_module.so \
       /usr/share/nginx/modules/ngx_stream_module.so 2>/dev/null | grep -q . && return 0
    return 1
}

# 安装官方 nginx.org 源（带 stream 模块，静态编入）。仅 Debian/Ubuntu。
_nginx_keyring_path() {
    printf '%s' "${NGINX_KEYRING_FILE:-/usr/share/keyrings/nginx-archive-keyring.gpg}"
}

_nginx_source_list_path() {
    printf '%s' "${NGINX_SOURCE_LIST_FILE:-/etc/apt/sources.list.d/nginx.list}"
}

_nginx_preferences_path() {
    printf '%s' "${NGINX_APT_PIN_FILE:-/etc/apt/preferences.d/99nginx}"
}

_nginx_stream_module_conf_path() {
    printf '%s' "${NGINX_STREAM_MODULE_CONF:-/etc/nginx/modules-enabled/50-mod-stream.conf}"
}

_nginx_render_official_source() {
    local distro="$1" codename="$2" keyring="$3"
    [[ "$distro" =~ ^(debian|ubuntu)$ ]] || return 1
    [[ "$codename" =~ ^[A-Za-z0-9._+-]+$ ]] || return 1
    [[ "$keyring" == /* && "$keyring" != *$'\n'* ]] || return 1
    printf 'deb [signed-by=%s] http://nginx.org/packages/%s %s nginx\n' "$keyring" "$distro" "$codename"
}

_nginx_render_official_pin() {
    printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n'
}

_nginx_install_official_keyring() {
    local keyring dir tmp_key tmp_ring
    command_exists curl || return 1
    command_exists gpg || return 1
    keyring="$(_nginx_keyring_path)"
    dir="$(dirname "$keyring")"
    mkdir -p "$dir" || return 1
    tmp_key=$(mktemp "${dir}/.tmp.server-manage.nginx-key.XXXXXX") || return 1
    _tmp_register "$tmp_key"
    tmp_ring=$(mktemp "${dir}/.tmp.server-manage.nginx-keyring.XXXXXX") || {
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    }
    _tmp_register "$tmp_ring"
    if ! curl -fsSL https://nginx.org/keys/nginx_signing.key -o "$tmp_key"; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    if ! gpg --batch --yes --dearmor -o "$tmp_ring" "$tmp_key" 2>/dev/null; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    chmod 644 "$tmp_ring" 2>/dev/null || true
    chown root:root "$tmp_ring" 2>/dev/null || true
    if ! mv "$tmp_ring" "$keyring"; then
        rm -f "$tmp_key" "$tmp_ring" 2>/dev/null || true
        _tmp_unregister "$tmp_key"; _tmp_unregister "$tmp_ring"
        return 1
    fi
    _tmp_unregister "$tmp_ring"
    rm -f "$tmp_key" 2>/dev/null || true
    _tmp_unregister "$tmp_key"
    return 0
}

_nginx_write_official_apt_files() {
    local distro="$1" codename="$2" keyring source_file pin_file source_content pin_content
    keyring="$(_nginx_keyring_path)"
    source_file="$(_nginx_source_list_path)"
    pin_file="$(_nginx_preferences_path)"
    source_content="$(_nginx_render_official_source "$distro" "$codename" "$keyring")" || return 1
    pin_content="$(_nginx_render_official_pin)" || return 1
    write_file_atomic "$source_file" "$source_content" || return 1
    chmod 644 "$source_file" 2>/dev/null || true
    write_file_atomic "$pin_file" "$pin_content" || return 1
    chmod 644 "$pin_file" 2>/dev/null || true
}

_nginx_write_stream_module_conf() {
    local so="$1" conf_file content
    [[ -f "$so" && "$so" == /* && "$so" != *$'\n'* ]] || return 1
    conf_file="$(_nginx_stream_module_conf_path)"
    content="$(printf 'load_module %s;\n' "$so")" || return 1
    write_file_atomic "$conf_file" "$content" || return 1
    chmod 644 "$conf_file" 2>/dev/null || true
}

_install_nginx_official() {
    [[ "$PLATFORM" == "debian" ]] || return 1
    command_exists curl || install_package "curl" "silent" || return 1
    install_package "gnupg2" "silent" || install_package "gnupg" "silent" || true
    install_package "ca-certificates" "silent" || true
    install_package "lsb-release" "silent" || true
    local codename; codename=$(lsb_release -cs 2>/dev/null || true)
    [[ -n "$codename" ]] || { print_error "无法获取发行版代号 (lsb_release)"; return 1; }
    local distro="ubuntu"
    grep -qi debian /etc/os-release 2>/dev/null && distro="debian"
    if ! _nginx_install_official_keyring; then
        print_error "下载 nginx.org 签名密钥失败"
        return 1
    fi
    if ! _nginx_write_official_apt_files "$distro" "$codename"; then
        print_error "写入 nginx.org apt 源失败"
        return 1
    fi
    APT_UPDATED=0
    update_apt_cache
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx >/dev/null 2>&1 || return 1
    # enable --now 对已运行的 nginx 是 no-op（不会重启），换源装的带 stream 新二进制不会生效；
    # 显式 restart 确保运行态换成新二进制，再复核 stream 可用。
    if is_systemd; then
        systemctl enable nginx >/dev/null 2>&1 || true
        systemctl restart nginx >/dev/null 2>&1 || true
    else
        service nginx restart >/dev/null 2>&1 || nginx -s reload >/dev/null 2>&1 || true
    fi
    _check_nginx_stream
}

# 确保 nginx 具备可用的 stream 模块。返回 0 表示可用。
# 策略：已可用→直接返回；有动态 so→注入 load_module；否则装官方源（静态编入）。
_ensure_nginx_stream() {
    if _check_nginx_stream; then
        return 0
    fi
    # 发行版自带 libnginx-mod-stream 的情况：先尝试装该包
    if [[ "$PLATFORM" == "debian" ]]; then
        if ! _nginx_stream_module_available; then
            update_apt_cache
            apt-get install -y libnginx-mod-stream >/dev/null 2>&1 || true
        fi
    fi
    # 有动态 so 但未加载 → 注入 load_module 到 nginx.conf 顶部
    if _nginx_stream_module_available; then
        local so=""
        for so in /usr/lib/nginx/modules/ngx_stream_module.so /usr/share/nginx/modules/ngx_stream_module.so; do
            [[ -f "$so" ]] && break
        done
        # Debian 的 libnginx-mod-stream 会在 modules-enabled 放 .conf 自动 load，
        # 若已如此则 _check_nginx_stream 已返回 0；这里兜底手动 load。
        if ! ls /etc/nginx/modules-enabled/ 2>/dev/null | grep -q stream; then
            _nginx_write_stream_module_conf "$so" || return 1
        fi
        # 关键：load_module 只在 nginx 启动时处理，reload(SIGHUP) 不会把新动态模块加载进
        # 正在运行的 master 进程。若此处只 reload，运行态 nginx 仍无 stream，而调用方（enable）
        # 随后会让 sing-box 下沉释放 443，届时公网 443 无人监听 → 节点全废却可能误报成功。
        # 故写入 load_module 后必须 restart（而非 reload），让模块真正加载，再复核。
        if nginx -t >/dev/null 2>&1; then
            if is_systemd; then
                systemctl restart nginx >/dev/null 2>&1 || true
            else
                service nginx restart >/dev/null 2>&1 || { nginx -s stop 2>/dev/null; nginx 2>/dev/null; } || true
            fi
            # restart 后用运行态证据复核：nginx -V 含 stream 模块，或已能实际解析 stream{}。
            # _check_nginx_stream 只看配置文件存在偏乐观，这里叠加 nginx -t 通过 + 服务在跑。
            if _check_nginx_stream && nginx -t >/dev/null 2>&1 \
               && { ! is_systemd || systemctl is-active --quiet nginx; }; then
                return 0
            fi
        fi
    fi
    # 最后手段：换官方源装带 stream 的 nginx
    print_warn "当前 nginx 无 stream 模块，尝试安装官方 nginx.org 源版本 (含 stream)..."
    _install_nginx_official
}

_check_certbot_dns_cf() {
    command_exists certbot || return 1
    certbot plugins 2>/dev/null | grep -q dns-cloudflare || return 1
    # Ubuntu 20.04: certbot-dns-cloudflare 0.39 与 cloudflare 2.1 不兼容
    local cb_ver=$(certbot --version 2>&1 | grep -oP '[\d.]+')
    if [[ "${cb_ver%%.*}" == "0" ]]; then
        print_warn "certbot $cb_ver 版本过旧，不支持 API Token"
        return 1
    fi
    return 0
}

_check_nginx_dirs() {
    [[ -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]
}

# ── 通用辅助函数 ──

# 安全加载 .conf 配置文件（避免 source 注入风险）
_safe_source_conf() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    # 仅读取 KEY="VALUE" 格式的行，忽略其他内容
    while IFS='=' read -r key val; do
        # 跳过注释和空行
        [[ "$key" =~ ^[[:space:]]*# ]] && continue
        [[ -z "$key" ]] && continue
        # 去除首尾引号和空格
        key=$(echo "$key" | xargs)
        val=$(echo "$val" | sed 's/^"//;s/"$//' | sed "s/^'//;s/'$//")
        # 仅允许合法变量名
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        printf -v "$key" '%s' "$val"
    done < "$file"
}

# Nginx 安全重载
_nginx_reload() {
    if is_systemd; then
        systemctl reload nginx
    else
        nginx -s reload 2>/dev/null || service nginx reload
    fi
}

# Reality 443 共存：建站请求的 HTTPS 端口下沉。
# 共存启用且用户请求 443 时，改写为 web 内部端口（真站退到 loopback，443 归 nginx stream）。
# 回显最终生效端口（stdout）；说明打到 stderr，不污染回显。未启用或非 443 原样返回。
# 依赖 15-singbox-reality.sh 的 reality_coexist_enabled / reality_coexist_web_port（构建时同脚本）。
_web_coexist_https_port() {
    local requested="$1" web_port
    if ! declare -F reality_coexist_enabled >/dev/null 2>&1 || ! reality_coexist_enabled; then
        printf '%s' "$requested"; return 0
    fi
    [[ "$requested" == "443" ]] || { printf '%s' "$requested"; return 0; }
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$web_port" || { printf '%s' "$requested"; return 0; }
    print_warn "本机已启用 Reality 443 共存，网站自动使用 ${web_port}，由 nginx 分流层统一对外提供 443。" >&2
    printf '%s' "$web_port"
}

# Reality 443 共存：计算 80→HTTPS 跳转应带的端口后缀。
# 常规：非 443 端口跳转要带 ":端口"。但共存下真站虽监听 web 内部端口(如 12443)，
# 对外仍由 nginx stream 经 443 提供，故此时后缀必须为空（跳到隐含 443），否则会 301 到
# 公网不可达的内部端口导致真站 HTTP 入口失效。回显后缀（空或 ":端口"）到 stdout。
_web_coexist_redir_suffix() {
    local https_port="$1" web_port
    if declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled; then
        web_port="$(reality_coexist_web_port 2>/dev/null || true)"
        # 该站监听的正是共存 web 内部端口 → 对外是 443，后缀留空
        [[ -n "$web_port" && "$https_port" == "$web_port" ]] && { printf '%s' ""; return 0; }
    fi
    [[ "$https_port" != "443" ]] && printf ':%s' "$https_port"
    return 0
}

# Reality 443 共存：判断某端口是否为共存 web 内部端口（仅 loopback，不应对公网放行）。
# 返回 0 表示"是内部端口，调用方应跳过 ufw allow"；否则返回 1（正常放行）。
_web_coexist_is_inner_port() {
    local port="$1" web_port
    declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled || return 1
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    [[ -n "$web_port" && "$port" == "$web_port" ]]
}

_web_allow_public_tcp_port() {
    local port="$1" comment="${2:-Web}" label="${3:-${port}/tcp}" rc
    if ! declare -F firewall_allow_tcp_port >/dev/null 2>&1; then
        print_warn "未找到防火墙放行 helper，请手动确认 ${label} 已放行。"
        return 2
    fi
    firewall_allow_tcp_port "$port" "$comment"
    rc=$?
    case "$rc" in
        0)
            print_success "已放行端口 ${label}"
            return 0
            ;;
        2)
            print_info "请确认服务器防火墙/云安全组已放行 ${label}"
            return 0
            ;;
        *)
            print_error "防火墙放行失败: ${label}"
            return 1
            ;;
    esac
}

# 把 deploy/renew hook 持久化进证书的 renewal 配置（/etc/letsencrypt/renewal/<domain>.conf 的
# [renewalparams] renew_hook）。这样单条共享 `certbot renew` 就会自动为每个证书跑各自的 hook，
# 无需再给每个域名单独挂 --cert-name cron（避免多域名撞 certbot 全局锁）。
# 做法：先删除所有旧 renew_hook 行，再把新值插到 [renewalparams] 段头之后（configobj 要求
# key 落在 section 内才生效）；若该 conf 无 [renewalparams] 段则补建段头再写。
_cert_persist_renew_hook() {
    local domain="$1" hook="$2" conf tmp renewal_dir
    [[ -n "$domain" && -n "$hook" ]] || return 1
    renewal_dir="${LETSENCRYPT_RENEWAL_DIR:-/etc/letsencrypt/renewal}"
    conf="${renewal_dir}/${domain}.conf"
    [[ -f "$conf" ]] || return 1   # certonly 成功后必然存在；不存在说明签发异常
    tmp=$(mktemp "$(dirname "$conf")/.tmp.server-manage.renewal.XXXXXX") || return 1
    _tmp_register "$tmp"
    # certbot 的 renewal conf 用 configobj 解析：renew_hook 必须落在 [renewalparams] 段内才生效。
    # 先删除所有旧 renew_hook 行，再把新值插到 [renewalparams] 段头之后；若无该段则追加到末尾并补段头。
    if ! awk -v hook="$hook" '
        /^[[:space:]]*renew_hook[[:space:]]*=/ { next }
        /^\[renewalparams\]/ { print; print "renew_hook = " hook; injected=1; next }
        { print }
        END { if (!injected) { print "[renewalparams]"; print "renew_hook = " hook } }
    ' "$conf" > "$tmp"; then
        rm -f "$tmp"; _tmp_unregister "$tmp"; return 1
    fi
    chmod --reference="$conf" "$tmp" 2>/dev/null || chmod 644 "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$conf"; then
        rm -f "$tmp"; _tmp_unregister "$tmp"; return 1
    fi
    _tmp_unregister "$tmp"
    return 0
}

# 安装单条共享的每日续期 cron（官方推荐：一条 `certbot renew` 覆盖所有证书，各证书跑自己
# 持久化的 renew_hook）。幂等——cron_add_job 会先按 tag 去重。避开整点分钟分散负载。
# tag/minute 由 00-constants.sh 定义（readonly）；此处仅在未定义时兜底，供单模块测试隔离用。
_cert_ensure_shared_renew_cron() {
    local tag="${CERT_RENEW_SHARED_CRON_TAG:-CertRenewShared}"
    local minute="${CERT_RENEW_SHARED_CRON_MINUTE:-17}"
    cron_add_job "$tag" \
        "${minute} 3 * * * certbot renew --quiet # ${tag}"
}

# 确保 SSL 参数文件存在
_ensure_ssl_params() {
    [[ -f /etc/nginx/snippets/ssl-params.conf ]] && return 0
    mkdir -p /etc/nginx/snippets
    local ssl_params="ssl_session_timeout 1d;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
add_header Strict-Transport-Security \"max-age=15768000\" always;"
    write_file_atomic "/etc/nginx/snippets/ssl-params.conf" "$ssl_params"
}

# 生成 HTTPS listen + HTTP/2 配置块。
# Nginx 1.25.1 起官方将 `listen ... http2` 标记为 deprecated，推荐独立 `http2 on;`。
# Debian/Ubuntu 稳定仓库仍可能是旧版 Nginx，旧版又不认识 `http2 on;`，因此按运行时版本选择语法。
_nginx_tls_http2_block() {
    local port="$1" version raw major minor patch
    raw=$(nginx -v 2>&1 || true)
    version=$(echo "$raw" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    major=${version%%.*}
    minor=${version#*.}; minor=${minor%%.*}
    patch=${version##*.}

    # Reality 443 共存：若本 server 监听的正是共存 web 内部端口，则只绑 loopback
    # （127.0.0.1 + [::1]），使该站仅能经 nginx stream 443 分流到达，杜绝内部端口公网暴露。
    # 非共存 / 非内部端口保持原样绑全地址。
    local host_v4="" host_v6="[::]:"
    if declare -F reality_coexist_enabled >/dev/null 2>&1 && reality_coexist_enabled; then
        local _wp; _wp="$(reality_coexist_web_port 2>/dev/null || true)"
        if [[ -n "$_wp" && "$port" == "$_wp" ]]; then
            host_v4="127.0.0.1:"; host_v6="[::1]:"
        fi
    fi

    if [[ -n "$version" ]] && {
        (( major > 1 )) ||
        (( major == 1 && minor > 25 )) ||
        (( major == 1 && minor == 25 && patch >= 1 ))
    }; then
        printf '    listen %s%s ssl;\n' "$host_v4" "$port"
        printf '    listen %s%s ssl;\n' "$host_v6" "$port"
        printf '    http2 on;\n'
    else
        printf '    listen %s%s ssl %s;\n' "$host_v4" "$port" "http2"
        printf '    listen %s%s ssl %s;\n' "$host_v6" "$port" "http2"
    fi
}

_nginx_deploy_conf_restore() {
    local avail="$1" enabled="$2" had_avail="$3" had_enabled="$4" enabled_was_symlink="$5" old_enabled_target="$6" backup_avail="$7" backup_enabled="$8"
    rm -f "$enabled"
    if [[ "$had_enabled" -eq 1 ]]; then
        if [[ "$enabled_was_symlink" -eq 1 && -n "$old_enabled_target" ]]; then
            ln -s "$old_enabled_target" "$enabled" 2>/dev/null || true
        elif [[ -n "$backup_enabled" && -e "$backup_enabled" ]]; then
            mv "$backup_enabled" "$enabled" 2>/dev/null || true
        fi
    fi
    if [[ "$had_avail" -eq 1 && -n "$backup_avail" && -e "$backup_avail" ]]; then
        mv "$backup_avail" "$avail" 2>/dev/null || true
    else
        rm -f "$avail"
    fi
}

# Nginx 配置部署（写入 + 测试 + 加载，失败自动回滚）
# 用法: _nginx_deploy_conf "域名" "配置内容" 成功返回0，失败返回1
_nginx_deploy_conf() {
    local domain="$1" conf_content="$2"
    local sites_available="${NGINX_SITES_AVAILABLE_DIR:-/etc/nginx/sites-available}"
    local sites_enabled="${NGINX_SITES_ENABLED_DIR:-/etc/nginx/sites-enabled}"
    local avail="${sites_available}/${domain}.conf"
    local enabled="${sites_enabled}/${domain}.conf"
    local backup_avail="" backup_enabled="" old_enabled_target=""
    local had_avail=0 had_enabled=0 enabled_was_symlink=0

    if [[ -e "$avail" ]]; then
        had_avail=1
        backup_avail=$(mktemp "/etc/nginx/sites-available/.${domain}.conf.bak.XXXXXX") || return 1
        cp -a "$avail" "$backup_avail" || { rm -f "$backup_avail"; return 1; }
    fi
    if [[ -L "$enabled" ]]; then
        had_enabled=1
        enabled_was_symlink=1
        old_enabled_target=$(readlink "$enabled" 2>/dev/null || true)
    elif [[ -e "$enabled" ]]; then
        had_enabled=1
        backup_enabled=$(mktemp "/etc/nginx/sites-enabled/.${domain}.conf.bak.XXXXXX") || { rm -f "$backup_avail"; return 1; }
        cp -a "$enabled" "$backup_enabled" || { rm -f "$backup_avail" "$backup_enabled"; return 1; }
    fi

    write_file_atomic "$avail" "$conf_content" || { print_error "写入 Nginx 配置失败"; rm -f "$backup_avail" "$backup_enabled"; return 1; }
    if ! ln -sfn "$avail" "$enabled"; then
        print_error "启用 Nginx 配置失败"
        _nginx_deploy_conf_restore "$avail" "$enabled" "$had_avail" "$had_enabled" "$enabled_was_symlink" "$old_enabled_target" "$backup_avail" "$backup_enabled"
        nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
        rm -f "$backup_avail" "$backup_enabled"
        return 1
    fi

    if nginx -t >/dev/null 2>&1 && _nginx_reload; then
        rm -f "$backup_avail" "$backup_enabled"
        return 0
    fi

    print_error "Nginx 配置测试或重载失败，正在恢复旧配置！"
    nginx -t 2>&1 | tail -5
    _nginx_deploy_conf_restore "$avail" "$enabled" "$had_avail" "$had_enabled" "$enabled_was_symlink" "$old_enabled_target" "$backup_avail" "$backup_enabled"
    nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
    rm -f "$backup_avail" "$backup_enabled"
    return 1
}

web_env_check() {
    if [[ "$PLATFORM" == "openwrt" ]]; then
        for pkg in jq curl openssl-util ca-bundle; do
            if ! opkg list-installed 2>/dev/null | grep -q "^${pkg} "; then
                opkg update >/dev/null 2>&1
                opkg install "$pkg" >/dev/null 2>&1 || true
            fi
        done
        if ! command_exists certbot; then
            print_warn "OpenWrt 上 certbot 可能不可用。"
            print_info "建议使用 opkg install acme acme-dnsapi 或手动安装 certbot。"
            if ! confirm "是否继续尝试？"; then
                return 1
            fi
        fi
        if ! command_exists nginx; then
            print_info "安装 nginx..."
            opkg update >/dev/null 2>&1
            opkg install nginx-ssl >/dev/null 2>&1 || opkg install nginx >/dev/null 2>&1 || {
                print_warn "nginx 安装失败，反代功能可能不可用"
            }
        fi
        mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets 2>/dev/null || true
        mkdir -p "$CONFIG_DIR"
        chmod 700 "$CONFIG_DIR"
        return 0
    fi
    print_info "Web 环境依赖自检..."
    local deps=(
        "jq|jq|jq"
        "nginx|nginx|nginx"
        "nginx 目录结构|nginx_dirs|nginx_dirs"
        "certbot|certbot|certbot"
        "certbot dns-cloudflare 插件|certbot_dns_cf|certbot_dns_cf"
    )

    # 第一轮: 检查
    _web_dep_check_results=()
    local need_fix=0
    for dep in "${deps[@]}"; do
        IFS='|' read -r name check_id install_id <<< "$dep"
        if ! _web_dep_verify "$name" "$check_id"; then
            need_fix=1
        fi
    done
    echo -e "${C_CYAN}依赖检查结果:${C_RESET}"
    for r in "${_web_dep_check_results[@]}"; do
        echo -e "  $r"
    done

    # 第二轮: 修复
    if [[ $need_fix -eq 1 ]]; then
        print_warn "检测到缺失依赖，正在自动修复..."
        local fix_failed=0
        for dep in "${deps[@]}"; do
            IFS='|' read -r name check_id install_id <<< "$dep"
            if ! _web_dep_fix "$name" "$check_id" "$install_id"; then
                fix_failed=1
            fi
        done

        # 第三轮: 最终验证
        if [[ $fix_failed -eq 1 ]]; then
            print_error "部分依赖修复失败，最终验证:"
            local final_ok=1
            for dep in "${deps[@]}"; do
                IFS='|' read -r name check_id install_id <<< "$dep"
                if _web_dep_run_check "$check_id" >/dev/null 2>&1; then
                    echo -e "  ${C_GREEN}✓${C_RESET} $name"
                else
                    echo -e "  ${C_RED}✗${C_RESET} $name"
                    final_ok=0
                fi
            done
            if [[ $final_ok -eq 0 ]]; then
                print_error "关键依赖缺失，无法继续。请手动修复后重试。"
                echo "手动修复参考:
  apt-get update
  apt-get install -y certbot python3-certbot-dns-cloudflare nginx jq
或使用 snap:
  snap install --classic certbot
  snap install certbot-dns-cloudflare
  snap connect certbot:plugin certbot-dns-cloudflare"
                return 1
            fi
        fi
        print_success "所有依赖已就绪"
    else
        print_success "所有依赖检查通过"
    fi
    mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/snippets
    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"
    return 0
}

# ── 通用域名清理 ──
# 一次性清除指定域名的所有关联配置
# 用法: _web_cleanup_domain "域名" [quiet]
# quiet 模式仅打印摘要，不打印每项细节
_web_cleanup_domain() {
    local domain="$1" quiet="${2:-}"
    [[ -z "$domain" ]] && return 1
    if ! validate_domain "$domain"; then
        [[ -z "$quiet" ]] && print_error "域名格式无效，拒绝清理: $domain"
        return 1
    fi
    local cleaned=0
    local cert_prefix="${CERT_PATH_PREFIX%/}"
    if [[ -z "$cert_prefix" || "$cert_prefix" == "/" ]]; then
        [[ -z "$quiet" ]] && print_error "证书目录前缀异常，拒绝清理"
        return 1
    fi

    # Certbot 证书
    if certbot certificates 2>/dev/null | grep -Fq -- "$domain"; then
        certbot delete --cert-name "$domain" --non-interactive 2>/dev/null && cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "证书已删除"
    fi
    # 本地证书拷贝
    rm -rf "${cert_prefix}/${domain}" 2>/dev/null

    # Nginx 配置
    local ng_en="/etc/nginx/sites-enabled/${domain}.conf"
    local ng_av="/etc/nginx/sites-available/${domain}.conf"
    if [[ -f "$ng_en" || -f "$ng_av" ]]; then
        rm -f "$ng_en" "$ng_av"
        nginx -t >/dev/null 2>&1 && _nginx_reload 2>/dev/null
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "Nginx 配置已删除"
        # 443 共存：站点 conf 已删，刷新 stream SNI 白名单剔除该域名（未启用则 no-op）。
        # 与建站三处（09c/09d/09e）对称，避免白名单残留指向已消失 web server 的死映射。
        declare -F reality_coexist_refresh >/dev/null && reality_coexist_refresh || true
    fi

    # Hook 脚本
    local hook hook_cleaned=false
    for hook in "${CERT_HOOKS_DIR}/renew-${domain}.sh" "/root/cert-renew-hook-${domain}.sh"; do
        if [[ -f "$hook" ]]; then
            rm -f "$hook" && hook_cleaned=true
        fi
    done
    if [[ "$hook_cleaned" == "true" ]]; then
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "Hook 脚本已删除"
    fi

    # Cron 任务 (续签)
    cron_remove_job "CertRenew_${domain}" 2>/dev/null
    cron_remove_job "cert-renew-hook-${domain}.sh" 2>/dev/null

    # CF 凭据
    rm -f "/root/.cloudflare-${domain}.ini" 2>/dev/null

    # DDNS 配置 (域名本身 + origin.${domain} 子域；不要用通配，避免误删其他域名的 origin DDNS)
    local ddns_cleaned=false
    for ddns_f in "${DDNS_CONFIG_DIR}/${domain}.conf" "${DDNS_CONFIG_DIR}/origin.${domain}.conf"; do
        if [[ -f "$ddns_f" ]]; then
            rm -f "$ddns_f"; ddns_cleaned=true
        fi
    done
    # 根域 origin DDNS（仅当 root_part 与 domain 不同才单独删）
    local root_part="${domain#*.}"
    if [[ "$root_part" != "$domain" && -f "${DDNS_CONFIG_DIR}/origin.${root_part}.conf" ]]; then
        rm -f "${DDNS_CONFIG_DIR}/origin.${root_part}.conf"; ddns_cleaned=true
    fi
    if [[ "$ddns_cleaned" == "true" ]]; then
        cleaned=$((cleaned+1))
        ddns_rebuild_cron 2>/dev/null
        [[ -z "$quiet" ]] && print_success "DDNS 配置已清理"
    fi

    # 提示: CF Origin Rule 无法自动清理 (需 API Token)
    [[ -z "$quiet" ]] && print_info "提示: 如有 CF Origin Rule，请通过菜单 [12.删除回源规则] 手动清理"

    # 域名管理配置
    if [[ -f "${CONFIG_DIR}/${domain}.conf" ]]; then
        rm -f "${CONFIG_DIR}/${domain}.conf"
        cleaned=$((cleaned+1))
        [[ -z "$quiet" ]] && print_success "域名管理配置已删除"
    fi

    if [[ $cleaned -gt 0 ]]; then
        [[ -n "$quiet" ]] && print_success "已清理 ${domain} 的 ${cleaned} 项旧配置"
        log_action "Cleanup domain: $domain ($cleaned items)"
    fi
    return 0
}
