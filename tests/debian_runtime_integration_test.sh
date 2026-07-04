#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR" || exit 99

PASS=0
FAIL=0
SKIP=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
skip() { echo "  [SKIP] $1"; SKIP=$((SKIP + 1)); }

if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
    skip "非 Linux 环境，跳过 Debian 实机集成测试"
    echo "debian_runtime_integration_test: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
    exit 0
fi

source modules/00-constants.sh
source modules/01-utils.sh
source modules/02-network.sh
source modules/03-sysinfo.sh
source modules/04-firewall.sh
source modules/05-fail2ban.sh
source modules/06-ssh.sh
source modules/07-system.sh
source modules/08-network-tools.sh
source modules/09a-web-helpers.sh
source modules/09b-web-cloudflare.sh
source modules/09c-web-domain.sh
source modules/09d-web-proxy.sh
source modules/09e-web-home-expose.sh
source modules/10-docker.sh
source modules/11a-wireguard-netcheck.sh
source modules/11-wireguard.sh
source modules/11c-wireguard-server.sh
source modules/11d-wireguard-peers.sh
source modules/11e-wireguard-clash.sh
source modules/12a-wireguard-deb-netcheck.sh
source modules/12b-wireguard-deb.sh
source modules/12c-wireguard-deb-server.sh
source modules/12d-wireguard-deb-peers.sh
source modules/12e-wireguard-deb-extra.sh
source modules/14a-email-state.sh
source modules/14b-email-cf.sh
source modules/14c-email-deploy.sh
source modules/14d-email-manage.sh
source modules/14e-email-uninstall.sh
source modules/14-email.sh
source modules/15-singbox-reality.sh

echo "== Debian runtime integration =="

tmp_root="$(mktemp -d)"
conf_pwned="$tmp_root/conf-pwned"
ddns_pwned="$tmp_root/ddns-pwned"
sysinfo_pwned="$tmp_root/sysinfo-pwned"
netdiag_pwned="$tmp_root/netdiag-pwned"
old_path="$PATH"
saved_cron=""
had_cron=0
cron_touched=0
wg_touched=0
wg_backup=""
cache_touched=0
cache_backup=""
log_touched=0
log_backup=""
docker_proxy_touched=0
docker_proxy_backup=""
docker_etc_touched=0
docker_etc_backup=""
docker_apt_source_touched=0
docker_apt_source_backup=""
docker_keyring_touched=0
docker_keyring_backup=""
email_state_touched=0
email_state_backup=""
email_module_log_touched=0
email_module_log_backup=""
email_admin_touched=0
email_admin_backup=""
email_install_touched=0
email_install_backup=""
web_home_domain="home.example.com"
web_home_hook_touched=0
web_home_hook_backup=""
web_home_cred_touched=0
web_home_cred_backup=""
web_home_le_touched=0
web_home_le_backup=""
web_domain_domain="panel.example.com"
web_domain_hook_touched=0
web_domain_hook_backup=""
web_domain_cred_touched=0
web_domain_cred_backup=""
web_domain_le_touched=0
web_domain_le_backup=""
web_cleanup_domain="cleanup.example.com"
web_cleanup_hook_touched=0
web_cleanup_hook_backup=""
web_cleanup_legacy_hook_touched=0
web_cleanup_legacy_hook_backup=""
web_cleanup_cred_touched=0
web_cleanup_cred_backup=""
web_cleanup_nginx_avail_touched=0
web_cleanup_nginx_avail_backup=""
web_cleanup_nginx_enabled_touched=0
web_cleanup_nginx_enabled_backup=""
nginx_site_touched=0
nginx_site_domain="runtime-audit.invalid"
cleanup() {
    PATH="$old_path"
    if [[ "$log_touched" -eq 1 && "$LOG_FILE" == "/var/log/server-manage.log" ]]; then
        rm -f "$LOG_FILE"
        if [[ -n "$log_backup" && -f "$log_backup" ]]; then
            mkdir -p "$(dirname "$LOG_FILE")"
            cp -a "$log_backup" "$LOG_FILE"
        fi
    fi
    if [[ "$cache_touched" -eq 1 && "$CACHE_DIR" == "/var/cache/server-manage" ]]; then
        rm -rf "$CACHE_DIR"
        if [[ -n "$cache_backup" && -d "$cache_backup" ]]; then
            mkdir -p "$(dirname "$CACHE_DIR")"
            cp -a "$cache_backup" "$CACHE_DIR"
        fi
    fi
    if [[ "$cron_touched" -eq 1 ]] && command_exists crontab; then
        if [[ "$had_cron" -eq 1 ]]; then
            crontab "$saved_cron" >/dev/null 2>&1 || true
        else
            crontab -r >/dev/null 2>&1 || true
        fi
    fi
    if [[ "$wg_touched" -eq 1 ]]; then
        rm -rf /etc/wireguard
        if [[ -n "$wg_backup" && -d "$wg_backup" ]]; then
            mkdir -p /etc
            cp -a "$wg_backup" /etc/wireguard
        fi
    fi
    if [[ "$docker_proxy_touched" -eq 1 && "$DOCKER_PROXY_DIR" == "/etc/systemd/system/docker.service.d" ]]; then
        rm -rf "$DOCKER_PROXY_DIR"
        if [[ -n "$docker_proxy_backup" && -d "$docker_proxy_backup" ]]; then
            mkdir -p "$(dirname "$DOCKER_PROXY_DIR")"
            cp -a "$docker_proxy_backup" "$DOCKER_PROXY_DIR"
        fi
    fi
    if [[ "$docker_etc_touched" -eq 1 ]]; then
        rm -rf /etc/docker
        if [[ -n "$docker_etc_backup" && -d "$docker_etc_backup" ]]; then
            mkdir -p /etc
            cp -a "$docker_etc_backup" /etc/docker
        fi
    fi
    if [[ "$docker_apt_source_touched" -eq 1 ]]; then
        rm -f /etc/apt/sources.list.d/docker.list
        if [[ -n "$docker_apt_source_backup" && -f "$docker_apt_source_backup" ]]; then
            mkdir -p /etc/apt/sources.list.d
            cp -a "$docker_apt_source_backup" /etc/apt/sources.list.d/docker.list
        fi
    fi
    if [[ "$docker_keyring_touched" -eq 1 ]]; then
        rm -f /etc/apt/keyrings/docker.gpg
        if [[ -n "$docker_keyring_backup" && -f "$docker_keyring_backup" ]]; then
            mkdir -p /etc/apt/keyrings
            cp -a "$docker_keyring_backup" /etc/apt/keyrings/docker.gpg
        fi
    fi
    if [[ "$email_state_touched" -eq 1 && "$EMAIL_STATE_DIR" == "/etc/server-manage/email" ]]; then
        rm -rf "$EMAIL_STATE_DIR"
        if [[ -n "$email_state_backup" && -d "$email_state_backup" ]]; then
            mkdir -p "$(dirname "$EMAIL_STATE_DIR")"
            cp -a "$email_state_backup" "$EMAIL_STATE_DIR"
        fi
    fi
    if [[ "$email_module_log_touched" -eq 1 && "$EMAIL_LOG_FILE" == "/var/log/server-manage-email.log" ]]; then
        rm -f "$EMAIL_LOG_FILE"
        if [[ -n "$email_module_log_backup" && -f "$email_module_log_backup" ]]; then
            mkdir -p "$(dirname "$EMAIL_LOG_FILE")"
            cp -a "$email_module_log_backup" "$EMAIL_LOG_FILE"
        fi
    fi
    if [[ "$email_admin_touched" -eq 1 && "$EMAIL_ADMIN_FILE" == "/root/.email-admin.txt" ]]; then
        rm -f "$EMAIL_ADMIN_FILE"
        if [[ -n "$email_admin_backup" && -f "$email_admin_backup" ]]; then
            mkdir -p "$(dirname "$EMAIL_ADMIN_FILE")"
            cp -a "$email_admin_backup" "$EMAIL_ADMIN_FILE"
        fi
    fi
    if [[ "$email_install_touched" -eq 1 && "$EMAIL_INSTALL_DIR" == "/root/cloudflare_temp_email" ]]; then
        rm -rf "$EMAIL_INSTALL_DIR"
        if [[ -n "$email_install_backup" && -d "$email_install_backup" ]]; then
            mkdir -p "$(dirname "$EMAIL_INSTALL_DIR")"
            cp -a "$email_install_backup" "$EMAIL_INSTALL_DIR"
        fi
    fi
    if [[ "$web_home_hook_touched" -eq 1 ]]; then
        rm -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
        if [[ -n "$web_home_hook_backup" && -f "$web_home_hook_backup" ]]; then
            mkdir -p "$CERT_HOOKS_DIR"
            cp -a "$web_home_hook_backup" "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
        fi
    fi
    if [[ "$web_home_cred_touched" -eq 1 ]]; then
        rm -f "/root/.cloudflare-${web_home_domain}.ini"
        if [[ -n "$web_home_cred_backup" && -f "$web_home_cred_backup" ]]; then
            cp -a "$web_home_cred_backup" "/root/.cloudflare-${web_home_domain}.ini"
        fi
    fi
    if [[ "$web_home_le_touched" -eq 1 ]]; then
        rm -rf "/etc/letsencrypt/live/${web_home_domain}"
        if [[ -n "$web_home_le_backup" && -e "$web_home_le_backup" ]]; then
            mkdir -p /etc/letsencrypt/live
            cp -a "$web_home_le_backup" "/etc/letsencrypt/live/${web_home_domain}"
        fi
    fi
    if [[ "$web_domain_hook_touched" -eq 1 ]]; then
        rm -f "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh"
        if [[ -n "$web_domain_hook_backup" && -f "$web_domain_hook_backup" ]]; then
            mkdir -p "$CERT_HOOKS_DIR"
            cp -a "$web_domain_hook_backup" "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh"
        fi
    fi
    if [[ "$web_domain_cred_touched" -eq 1 ]]; then
        rm -f "/root/.cloudflare-${web_domain_domain}.ini"
        if [[ -n "$web_domain_cred_backup" && -f "$web_domain_cred_backup" ]]; then
            cp -a "$web_domain_cred_backup" "/root/.cloudflare-${web_domain_domain}.ini"
        fi
    fi
    if [[ "$web_domain_le_touched" -eq 1 ]]; then
        rm -rf "/etc/letsencrypt/live/${web_domain_domain}"
        if [[ -n "$web_domain_le_backup" && -e "$web_domain_le_backup" ]]; then
            mkdir -p /etc/letsencrypt/live
            cp -a "$web_domain_le_backup" "/etc/letsencrypt/live/${web_domain_domain}"
        fi
    fi
    if [[ "$web_cleanup_hook_touched" -eq 1 ]]; then
        rm -f "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh"
        if [[ -n "$web_cleanup_hook_backup" && -f "$web_cleanup_hook_backup" ]]; then
            mkdir -p "$CERT_HOOKS_DIR"
            cp -a "$web_cleanup_hook_backup" "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh"
        fi
    fi
    if [[ "$web_cleanup_legacy_hook_touched" -eq 1 ]]; then
        rm -f "/root/cert-renew-hook-${web_cleanup_domain}.sh"
        if [[ -n "$web_cleanup_legacy_hook_backup" && -f "$web_cleanup_legacy_hook_backup" ]]; then
            cp -a "$web_cleanup_legacy_hook_backup" "/root/cert-renew-hook-${web_cleanup_domain}.sh"
        fi
    fi
    if [[ "$web_cleanup_cred_touched" -eq 1 ]]; then
        rm -f "/root/.cloudflare-${web_cleanup_domain}.ini"
        if [[ -n "$web_cleanup_cred_backup" && -f "$web_cleanup_cred_backup" ]]; then
            cp -a "$web_cleanup_cred_backup" "/root/.cloudflare-${web_cleanup_domain}.ini"
        fi
    fi
    if [[ "$web_cleanup_nginx_avail_touched" -eq 1 ]]; then
        rm -f "/etc/nginx/sites-available/${web_cleanup_domain}.conf"
        if [[ -n "$web_cleanup_nginx_avail_backup" && -e "$web_cleanup_nginx_avail_backup" ]]; then
            mkdir -p /etc/nginx/sites-available
            cp -a "$web_cleanup_nginx_avail_backup" "/etc/nginx/sites-available/${web_cleanup_domain}.conf"
        fi
    fi
    if [[ "$web_cleanup_nginx_enabled_touched" -eq 1 ]]; then
        rm -f "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf"
        if [[ -n "$web_cleanup_nginx_enabled_backup" && -e "$web_cleanup_nginx_enabled_backup" ]]; then
            mkdir -p /etc/nginx/sites-enabled
            cp -a "$web_cleanup_nginx_enabled_backup" "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf"
        fi
    fi
    if [[ "$nginx_site_touched" -eq 1 ]]; then
        rm -f "/etc/nginx/sites-enabled/${nginx_site_domain}.conf" \
              "/etc/nginx/sites-available/${nginx_site_domain}.conf" \
              /etc/nginx/sites-available/.runtime-audit.invalid.conf.bak.* \
              /etc/nginx/sites-enabled/.runtime-audit.invalid.conf.bak.* \
              /etc/nginx/sites-available/.tmp.server-manage.* 2>/dev/null || true
        if command_exists nginx; then
            nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
        fi
    fi
    rm -rf "$tmp_root"
}
trap cleanup EXIT

echo ""
echo "== SSH runtime =="
if command_exists sshd; then
    refresh_ssh_port
    if [[ -n "${CURRENT_SSH_PORTS:-}" ]] && validate_port "${CURRENT_SSH_PORTS%% *}"; then
        pass "refresh_ssh_port 使用真实 sshd -T 得到有效端口: ${CURRENT_SSH_PORTS}"
    else
        fail "refresh_ssh_port 未能从真实 sshd -T 得到有效端口"
    fi
    if _sshd_effective_value port | grep -Eq '^[0-9]+$'; then
        pass "_sshd_effective_value 可读取真实 sshd 有效配置"
    else
        fail "_sshd_effective_value 不能读取真实 sshd 有效配置"
    fi
    if _ssh_port_is_listening "${CURRENT_SSH_PORTS%% *}"; then
        pass "_ssh_port_is_listening 命中真实 SSH 监听端口"
    else
        fail "_ssh_port_is_listening 未命中真实 SSH 监听端口"
    fi
    if [[ " ${CURRENT_SSH_PORTS:-} " == *" 2 "* ]]; then
        skip "SSH 当前包含端口 2，跳过后缀误匹配实测"
    elif _ssh_port_is_listening 2; then
        fail "_ssh_port_is_listening 将端口 2 误判为监听（可能匹配了 22 后缀）"
    else
        pass "_ssh_port_is_listening 不把 22 误匹配为 2"
    fi
    ssh_match_conf="$tmp_root/sshd-match-port.conf"
    cat > "$ssh_match_conf" <<'EOF'
AuthorizedKeysFile .ssh/authorized_keys
Match User runtime-audit
    AllowTcpForwarding no
EOF
    if _sshd_set_directive "Port" "65022" "$ssh_match_conf" 1 \
       && awk 'BEGIN{ok=0} /^Port 65022$/{port=NR} /^Match /{matchline=NR} END{exit !(port && matchline && port < matchline)}' "$ssh_match_conf" \
       && sshd -t -f "$ssh_match_conf" >/dev/null 2>&1; then
        pass "_sshd_set_directive 将 Port 插入 Match 前且真实 sshd 接受"
    else
        fail "_sshd_set_directive Port/Match 处理未通过真实 sshd 校验"
        sshd -t -f "$ssh_match_conf" 2>&1 | sed 's/^/    /' || true
        sed 's/^/    /' "$ssh_match_conf" 2>/dev/null || true
    fi
else
    skip "sshd 不存在，跳过 SSH 实机项"
fi

echo ""
echo "== Certificate pair copy runtime =="
cert_src_dir="$tmp_root/cert-src"
cert_dst_dir="$tmp_root/cert-dst"
mkdir -p "$cert_src_dir" "$cert_dst_dir"
printf 'runtime-fullchain\n' > "$cert_src_dir/fullchain.pem"
printf 'runtime-privkey\n' > "$cert_src_dir/privkey.pem"
chmod 666 "$cert_src_dir/fullchain.pem" "$cert_src_dir/privkey.pem" 2>/dev/null || true
if copy_cert_pair_atomic "$cert_src_dir/fullchain.pem" "$cert_src_dir/privkey.pem" "$cert_dst_dir" \
   && grep -Fxq 'runtime-fullchain' "$cert_dst_dir/fullchain.pem" \
   && grep -Fxq 'runtime-privkey' "$cert_dst_dir/privkey.pem" \
   && [[ "$(stat -c '%a' "$cert_dst_dir/fullchain.pem" 2>/dev/null)" == "644" ]] \
   && [[ "$(stat -c '%a' "$cert_dst_dir/privkey.pem" 2>/dev/null)" == "600" ]] \
   && [[ "$(stat -c '%U:%G' "$cert_dst_dir/privkey.pem" 2>/dev/null)" == "root:root" ]] \
   && ! find "$cert_dst_dir" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.bak.server-manage.*' \) -print -quit | grep -q .; then
    pass "copy_cert_pair_atomic 在真实文件系统上原子复制证书对并收紧私钥权限"
else
    fail "copy_cert_pair_atomic 真实文件系统复制/权限/清理异常"
    ls -la "$cert_dst_dir" 2>/dev/null | sed 's/^/    /' || true
fi
hook_cert_src="$tmp_root/hook-cert-src"
hook_cert_dst="$tmp_root/hook-cert-dst"
hook_cert_script="$tmp_root/hook-cert-rollback.sh"
mkdir -p "$hook_cert_src" "$hook_cert_dst"
printf 'old-runtime-hook-full\n' > "$hook_cert_dst/fullchain.pem"
printf 'old-runtime-hook-key\n' > "$hook_cert_dst/privkey.pem"
printf 'new-runtime-hook-full\n' > "$hook_cert_src/fullchain.pem"
printf 'new-runtime-hook-key\n' > "$hook_cert_src/privkey.pem"
{
    printf '#!/usr/bin/env bash\nset -u\n'
    printf 'SRC=%q\nDST=%q\n' "$hook_cert_src" "$hook_cert_dst"
    render_cert_pair_hook_helper
    cat <<'EOF'
mv() {
    if [[ "${1:-}" == "$DST/.tmp.server-manage.privkey."* && "${2:-}" == "$DST/privkey.pem" ]]; then
        return 92
    fi
    command mv "$@"
}
copy_cert_pair_atomic "$SRC/fullchain.pem" "$SRC/privkey.pem" "$DST"
EOF
} > "$hook_cert_script"
chmod +x "$hook_cert_script"
if bash -n "$hook_cert_script" \
   && ! bash "$hook_cert_script" >/dev/null 2>&1 \
   && grep -Fxq 'old-runtime-hook-full' "$hook_cert_dst/fullchain.pem" \
   && grep -Fxq 'old-runtime-hook-key' "$hook_cert_dst/privkey.pem" \
   && ! find "$hook_cert_dst" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.bak.server-manage.*' \) -print -quit | grep -q .; then
    pass "续期 hook 内嵌证书 helper 在真实文件系统上失败回滚证书对"
else
    fail "续期 hook 内嵌证书 helper 回滚异常"
    ls -la "$hook_cert_dst" 2>/dev/null | sed 's/^/    /' || true
fi

echo ""
echo "== SSH authorized_keys runtime =="
ak_dir="$tmp_root/ssh-authorized/.ssh"
ak_file="$ak_dir/authorized_keys"
ak_old_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB old@example'
ak_new_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA appended@example'
mkdir -p "$ak_dir"
printf '%s' "$ak_old_key" > "$ak_file"
chmod 666 "$ak_file" 2>/dev/null || true
if _ssh_authorized_keys_append "$ak_file" "$ak_new_key" root:root \
   && _ssh_authorized_keys_append "$ak_file" "$ak_new_key" root:root \
   && [[ "$(stat -c '%a' "$ak_file" 2>/dev/null)" == "600" ]] \
   && [[ "$(stat -c '%U:%G' "$ak_file" 2>/dev/null)" == "root:root" ]] \
   && [[ "$(grep -Fxc "$ak_new_key" "$ak_file")" -eq 1 ]] \
   && [[ "$(grep -cve '^[[:space:]]*$' "$ak_file")" -eq 2 ]] \
   && ! find "$ak_dir" -maxdepth 1 -name '.tmp.server-manage.authorized-keys.*' -print -quit | grep -q .; then
    pass "_ssh_authorized_keys_append 在真实文件系统上原子追加、收紧权限并去重"
else
    fail "_ssh_authorized_keys_append 真实文件系统行为异常"
    ls -la "$ak_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$ak_file" 2>/dev/null || true
fi

echo ""
echo "== Public IP runtime =="
if command_exists curl; then
    runtime_ipv4="$(get_public_ipv4 2>/dev/null || true)"
    if [[ -n "$runtime_ipv4" ]]; then
        if validate_ip "$runtime_ipv4" && [[ "$runtime_ipv4" != *:* ]]; then
            pass "get_public_ipv4 在实体机获取到合法 IPv4: $runtime_ipv4"
        else
            fail "get_public_ipv4 返回非法 IPv4: $runtime_ipv4"
        fi
    else
        skip "公网 IPv4 探测无结果，跳过真实 IPv4 获取项"
    fi
    runtime_ipv6="$(get_public_ipv6 2>/dev/null || true)"
    if [[ -n "$runtime_ipv6" ]]; then
        if validate_ip "$runtime_ipv6" && [[ "$runtime_ipv6" == *:* ]]; then
            pass "get_public_ipv6 在实体机获取到合法 IPv6"
        else
            fail "get_public_ipv6 返回非法 IPv6: $runtime_ipv6"
        fi
    else
        skip "未检测到公网 IPv6，跳过真实 IPv6 获取项"
    fi
else
    skip "curl 不存在，跳过公网 IP 实机项"
fi

echo ""
echo "== systemd SSH socket runtime =="
if is_systemd && command_exists systemctl; then
    active_socket=""
    for unit in ssh.socket sshd.socket; do
        if systemctl is-active --quiet "$unit" 2>/dev/null \
           && systemctl show "$unit" -p Listen 2>/dev/null | grep -q 'Stream'; then
            active_socket="$unit"
            break
        fi
    done
    detected_socket="$(_ssh_socket_unit 2>/dev/null || true)"
    if [[ -n "$active_socket" ]]; then
        if [[ "$detected_socket" == "$active_socket" ]]; then
            pass "_ssh_socket_unit 命中真实 active SSH socket: $detected_socket"
        else
            fail "_ssh_socket_unit 与真实 active SSH socket 不一致: expected=$active_socket actual=${detected_socket:-<none>}"
        fi
    else
        if [[ -z "$detected_socket" ]]; then
            pass "_ssh_socket_unit 未误判 inactive/absent SSH socket"
        else
            fail "_ssh_socket_unit 误判 SSH socket activation: $detected_socket"
        fi
    fi
else
    skip "非 systemd 或无 systemctl，跳过 SSH socket 实机项"
fi

echo ""
echo "== Nginx runtime template =="
if command_exists nginx; then
    if [[ "$(id -u)" -eq 0 && -d /etc/nginx/sites-available && -d /etc/nginx/sites-enabled ]]; then
        nginx_site_touched=1
        nginx_audit_avail="/etc/nginx/sites-available/${nginx_site_domain}.conf"
        nginx_audit_enabled="/etc/nginx/sites-enabled/${nginx_site_domain}.conf"
        rm -f "$nginx_audit_avail" "$nginx_audit_enabled" \
              /etc/nginx/sites-available/.runtime-audit.invalid.conf.bak.* \
              /etc/nginx/sites-enabled/.runtime-audit.invalid.conf.bak.* 2>/dev/null || true
        nginx_good_conf='server {
    listen 127.0.0.1:18081;
    server_name runtime-audit.invalid;
    location / { return 204; }
}'
        if _nginx_deploy_conf "$nginx_site_domain" "$nginx_good_conf" \
           && [[ -f "$nginx_audit_avail" ]] \
           && [[ -L "$nginx_audit_enabled" ]] \
           && [[ "$(readlink "$nginx_audit_enabled" 2>/dev/null)" == "$nginx_audit_avail" ]] \
           && grep -qF 'listen 127.0.0.1:18081;' "$nginx_audit_avail" \
           && nginx -t >/dev/null 2>&1 \
           && ! find /etc/nginx/sites-available /etc/nginx/sites-enabled -maxdepth 1 \
                \( -name '.runtime-audit.invalid.conf.bak.*' -o -name '.tmp.server-manage.*' \) -print -quit 2>/dev/null | grep -q .; then
            pass "_nginx_deploy_conf 在真实 nginx 站点目录部署配置并启用 symlink"
        else
            fail "_nginx_deploy_conf 真实部署成功路径异常"
            nginx -t 2>&1 | sed 's/^/    /' || true
            ls -la /etc/nginx/sites-available /etc/nginx/sites-enabled 2>/dev/null | sed 's/^/    /' || true
            sed 's/^/    /' "$nginx_audit_avail" 2>/dev/null || true
        fi
        nginx_bad_conf='server {
    listen 127.0.0.1:18081;
    server_name runtime-audit.invalid;
    invalid_directive_runtime_audit on;
}'
        if ! _nginx_deploy_conf "$nginx_site_domain" "$nginx_bad_conf" >/dev/null 2>&1 \
           && [[ -f "$nginx_audit_avail" ]] \
           && [[ -L "$nginx_audit_enabled" ]] \
           && grep -qF 'listen 127.0.0.1:18081;' "$nginx_audit_avail" \
           && ! grep -qF 'invalid_directive_runtime_audit' "$nginx_audit_avail" \
           && nginx -t >/dev/null 2>&1 \
           && ! find /etc/nginx/sites-available /etc/nginx/sites-enabled -maxdepth 1 \
                \( -name '.runtime-audit.invalid.conf.bak.*' -o -name '.tmp.server-manage.*' \) -print -quit 2>/dev/null | grep -q .; then
            pass "_nginx_deploy_conf 在真实 nginx 目录中 nginx -t 失败时恢复旧站点"
        else
            fail "_nginx_deploy_conf 真实失败回滚路径异常"
            nginx -t 2>&1 | sed 's/^/    /' || true
            ls -la /etc/nginx/sites-available /etc/nginx/sites-enabled 2>/dev/null | sed 's/^/    /' || true
            sed 's/^/    /' "$nginx_audit_avail" 2>/dev/null || true
        fi
        rm -f "$nginx_audit_enabled" "$nginx_audit_avail" 2>/dev/null || true
        nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
    else
        skip "非 root 或 nginx sites 目录不存在，跳过 _nginx_deploy_conf 真实目录实测"
    fi
    cert="$tmp_root/runtime.crt"
    key="$tmp_root/runtime.key"
    if openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
        -subj "/CN=runtime.invalid" -keyout "$key" -out "$cert" >/dev/null 2>&1; then
        block="$(_nginx_tls_http2_block 18443)"
        if grep -q 'listen \[::\]:18443 ssl' <<< "$block"; then
            pass "_nginx_tls_http2_block 生成合法 IPv6 全地址 listen 前缀"
        else
            fail "_nginx_tls_http2_block 未生成 [::]:18443 listen: $block"
        fi
        if grep -q 'listen :18443' <<< "$block"; then
            fail "_nginx_tls_http2_block 仍生成非法空主机 listen"
        else
            pass "_nginx_tls_http2_block 不生成 listen :port"
        fi
        nginx_conf="$tmp_root/nginx.conf"
        cat > "$nginx_conf" <<EOF
events {}
http {
  server {
$(printf '%s\n' "$block")
    server_name runtime.invalid;
    ssl_certificate $cert;
    ssl_certificate_key $key;
    location / { return 204; }
  }
}
EOF
        if nginx -t -c "$nginx_conf" -p "$tmp_root" >/dev/null 2>&1; then
            pass "真实 nginx 接受生成的 HTTPS/HTTP2 listen 模板"
        else
            fail "真实 nginx 拒绝生成的 HTTPS/HTTP2 listen 模板"
            nginx -t -c "$nginx_conf" -p "$tmp_root" 2>&1 | sed 's/^/    /'
        fi
    else
        skip "openssl 无法生成临时证书，跳过 nginx 模板实测"
    fi
else
    skip "nginx 不存在，跳过 nginx 模板实测"
fi

echo ""
echo "== Config validation runtime =="
if [[ "$(id -u)" -eq 0 ]]; then
    conf_dir="$tmp_root/conf-validation"
    mkdir -p "$conf_dir"
    good_main_conf="$conf_dir/good.conf"
    bad_mode_conf="$conf_dir/bad-mode.conf"
    bad_expand_conf="$conf_dir/bad-expand.conf"
    bad_owner_conf="$conf_dir/bad-owner.conf"
    cat > "$good_main_conf" <<'EOF'
TOKEN="literal-value"
SAFE_PATH=/opt/example
SINGLE='$(kept literal)'
EOF
    chmod 600 "$good_main_conf"
    if validate_conf_file "$good_main_conf" >/dev/null 2>&1; then
        pass "validate_conf_file 接受 root:600 合法配置"
    else
        fail "validate_conf_file 拒绝 root:600 合法配置"
    fi
    cp "$good_main_conf" "$bad_mode_conf"
    chmod 666 "$bad_mode_conf"
    if validate_conf_file "$bad_mode_conf" >/dev/null 2>&1; then
        fail "validate_conf_file 接受了 group/other 可写配置"
    else
        pass "validate_conf_file 拒绝 group/other 可写配置"
    fi
    printf 'TOKEN="$(touch %s)"\n' "$conf_pwned" > "$bad_expand_conf"
    chmod 600 "$bad_expand_conf"
    rm -f "$conf_pwned"
    if validate_conf_file "$bad_expand_conf" >/dev/null 2>&1; then
        fail "validate_conf_file 接受了命令替换配置"
    elif [[ -e "$conf_pwned" ]]; then
        fail "validate_conf_file 校验恶意配置时发生命令执行"
    else
        pass "validate_conf_file 拒绝命令替换且未执行"
    fi
    if id -u nobody >/dev/null 2>&1; then
        cp "$good_main_conf" "$bad_owner_conf"
        chmod 600 "$bad_owner_conf"
        if chown nobody "$bad_owner_conf" 2>/dev/null; then
            if validate_conf_file "$bad_owner_conf" >/dev/null 2>&1; then
                fail "validate_conf_file 接受了非 root owner 配置"
            else
                pass "validate_conf_file 拒绝非 root owner 配置"
            fi
        else
            skip "无法 chown nobody，跳过 owner 拒绝实测"
        fi
    else
        skip "系统无 nobody 用户，跳过 owner 拒绝实测"
    fi
else
    skip "非 root，跳过 validate_conf_file owner/mode 实测"
fi

echo ""
echo "== Cloudflare web API runtime mocks =="
if command_exists jq; then
    cf_mock_dir="$tmp_root/cf-web-mock-bin"
    cf_mock_log="$tmp_root/cf-web-curl.log"
    cf_mock_data="$tmp_root/cf-web-data"
    mkdir -p "$cf_mock_dir" "$cf_mock_data"
    cat > "$cf_mock_dir/curl" <<'EOF_CF_WEB_CURL'
#!/usr/bin/env bash
set -u
log="${CF_WEB_MOCK_LOG:?}"
data_dir="${CF_WEB_MOCK_DATA:?}"
method="GET"
write_code=0
payload=""
url=""
prev=""
for arg in "$@"; do
    if [[ "$prev" == "-X" ]]; then method="$arg"; prev=""; continue; fi
    if [[ "$prev" == "--data" || "$prev" == "-d" ]]; then payload="$arg"; prev=""; continue; fi
    case "$arg" in
        -X|--data|-d) prev="$arg" ;;
        -w) write_code=1; prev="-w" ;;
        http*) url="$arg" ;;
        *) [[ "$prev" == "-w" ]] && prev="" ;;
    esac
done
printf '%s %s\n' "$method" "$url" >> "$log"
[[ -n "$payload" ]] && printf '%s\n' "$payload" > "$data_dir/last-payload.json"
path="${url#https://api.cloudflare.com/client/v4}"
if [[ "$path" == */rulesets/phases/http_request_origin/entrypoint ]]; then
    case "$method:$CF_WEB_MOCK_ORIGIN_MODE" in
        GET:timeout)
            exit 28
            ;;
        GET:missing)
            printf ''
            [[ "$write_code" -eq 1 ]] && printf '\n404'
            exit 0
            ;;
        GET:ok)
            printf '{"success":true,"result":{"rules":[{"id":"r1","expression":"http.host eq \"old.example.com\"","action_parameters":{"origin":{"port":8443}}}]}}'
            [[ "$write_code" -eq 1 ]] && printf '\n200'
            exit 0
            ;;
        PUT:*)
            printf '{"success":true,"result":{"id":"rs1"}}'
            exit 0
            ;;
    esac
fi
if [[ "$path" == /zones* ]]; then
    if [[ "$path" == *"dns_records"* ]]; then
        case "$path" in
            *"fail.example.com"*)
                printf '{"success":false,"errors":[{"message":"record read failed"}]}'
                exit 0
                ;;
            *"new.example.com"*)
                if [[ "$method" == "GET" ]]; then
                    printf '{"success":true,"result":[]}'
                else
                    printf '{"success":true,"result":{"id":"created-id"}}'
                fi
                exit 0
                ;;
            *)
                if [[ "$method" == "GET" ]]; then
                    printf '{"success":true,"result":[{"id":"existing-id"},{"id":"extra-id"}]}'
                else
                    printf '{"success":true,"result":{"id":"updated-id"}}'
                fi
                exit 0
                ;;
        esac
    fi
    case "$path" in
        *"per_page=1&page=1"*)
            printf '{"success":true,"result":[{"id":"z1","name":"example.com"}],"result_info":{"total_pages":2}}'
            ;;
        *"per_page=1&page=2"*)
            printf '{"success":true,"result":[{"id":"z2","name":"sub.example.net"}],"result_info":{"total_pages":2}}'
            ;;
        *"name=api.sub.example.net"*)
            printf '{"success":true,"result":[]}'
            ;;
        *"name=sub.example.net"*)
            printf '{"success":true,"result":[]}'
            ;;
        *"name=example.net"*)
            printf '{"success":true,"result":[{"id":"z-example-net","name":"example.net"}]}'
            ;;
        *)
            printf '{"success":true,"result":[{"id":"z-example-com","name":"example.com"},{"id":"z-example-net","name":"example.net"}],"result_info":{"total_pages":1}}'
            ;;
    esac
    exit 0
fi
printf '{"success":false,"errors":[{"message":"unhandled mock"}]}'
exit 0
EOF_CF_WEB_CURL
    chmod +x "$cf_mock_dir/curl"
    PATH="$cf_mock_dir:$old_path"
    CF_WEB_MOCK_LOG="$cf_mock_log"
    CF_WEB_MOCK_DATA="$cf_mock_data"
    export CF_WEB_MOCK_LOG CF_WEB_MOCK_DATA

    rm -f "$cf_mock_log"
    zones_json=$(_cf_list_zones "tok-runtime" "status=active" 1)
    if _cf_api_ok "$zones_json" \
       && jq -e '.result | length == 2 and .[0].id == "z1" and .[1].id == "z2"' >/dev/null <<< "$zones_json" \
       && grep -q 'per_page=1&page=1&status=active' "$cf_mock_log" \
       && grep -q 'per_page=1&page=2&status=active' "$cf_mock_log"; then
        pass "Cloudflare Web zone 分页在实体机 mock API 上聚合所有页"
    else
        fail "Cloudflare Web zone 分页聚合异常"
        sed 's/^/    /' "$cf_mock_log" 2>/dev/null || true
        printf '%s\n' "$zones_json" | sed 's/^/    /'
    fi

    if [[ "$(_cf_get_zone_id "api.sub.example.net" "tok-runtime")" == "z-example-net" ]]; then
        pass "Cloudflare Web zone lookup 可逐级回退到托管根 zone"
    else
        fail "Cloudflare Web zone lookup 未能逐级回退"
    fi

    rm -f "$cf_mock_log" "$cf_mock_data/last-payload.json"
    if _cf_update_dns_record "zone-runtime" "tok-runtime" "www.example.com" "A" "198.51.100.10" "true" >/dev/null 2>&1 \
       && grep -q 'PUT .*dns_records/existing-id' "$cf_mock_log" \
       && jq -e '.ttl == 1 and .proxied == true and .content == "198.51.100.10"' "$cf_mock_data/last-payload.json" >/dev/null; then
        pass "Cloudflare Web DNS 更新实体机 mock 下保留 ttl=1/proxied 并使用 PUT"
    else
        fail "Cloudflare Web DNS 更新 PUT/payload 异常"
        sed 's/^/    /' "$cf_mock_log" 2>/dev/null || true
        sed 's/^/    /' "$cf_mock_data/last-payload.json" 2>/dev/null || true
    fi

    rm -f "$cf_mock_log" "$cf_mock_data/last-payload.json"
    if _cf_update_dns_record "zone-runtime" "tok-runtime" "new.example.com" "AAAA" "2001:db8::10" "false" >/dev/null 2>&1 \
       && grep -q 'POST .*dns_records$' "$cf_mock_log" \
       && jq -e '.type == "AAAA" and .proxied == false and .content == "2001:db8::10"' "$cf_mock_data/last-payload.json" >/dev/null; then
        pass "Cloudflare Web DNS 缺记录时实体机 mock 下使用 POST 创建"
    else
        fail "Cloudflare Web DNS 创建 POST/payload 异常"
        sed 's/^/    /' "$cf_mock_log" 2>/dev/null || true
        sed 's/^/    /' "$cf_mock_data/last-payload.json" 2>/dev/null || true
    fi

    rm -f "$cf_mock_log"
    if _cf_update_dns_record "zone-runtime" "tok-runtime" "fail.example.com" "A" "198.51.100.11" "false" >/dev/null 2>&1; then
        fail "Cloudflare Web DNS 读取记录失败时仍继续写入"
    elif ! grep -Eq 'PUT|POST' "$cf_mock_log"; then
        pass "Cloudflare Web DNS 读取失败时 fail-closed 且不写记录"
    else
        fail "Cloudflare Web DNS 读取失败后仍发起写操作"
        sed 's/^/    /' "$cf_mock_log" 2>/dev/null || true
    fi

    CF_WEB_MOCK_ORIGIN_MODE="missing"
    export CF_WEB_MOCK_ORIGIN_MODE
    if [[ -z "$(_cf_get_origin_ruleset "tok-runtime" "zone-runtime")" ]]; then
        pass "Cloudflare Web Origin Rules 404 在实体机 mock 下按空规则处理"
    else
        fail "Cloudflare Web Origin Rules 404 未按空规则处理"
    fi
    CF_WEB_MOCK_ORIGIN_MODE="timeout"
    export CF_WEB_MOCK_ORIGIN_MODE
    if _cf_get_origin_ruleset "tok-runtime" "zone-runtime" >/dev/null 2>&1; then
        fail "Cloudflare Web Origin Rules curl 超时时未失败"
    else
        pass "Cloudflare Web Origin Rules curl 超时会 fail-closed"
    fi
    CF_WEB_MOCK_ORIGIN_MODE="ok"
    export CF_WEB_MOCK_ORIGIN_MODE
    rm -f "$cf_mock_data/last-payload.json"
    if _cf_put_origin_ruleset "tok-runtime" "zone-runtime" '[{"expression":"http.host eq \"www.example.com\"","action":"route","action_parameters":{"origin":{"port":8443}}}]' >/dev/null 2>&1 \
       && jq -e '.rules | length == 1 and .[0].action_parameters.origin.port == 8443' "$cf_mock_data/last-payload.json" >/dev/null; then
        pass "Cloudflare Web Origin Rules PUT 在实体机 mock 下包裹 rules payload"
    else
        fail "Cloudflare Web Origin Rules PUT payload 异常"
        sed 's/^/    /' "$cf_mock_data/last-payload.json" 2>/dev/null || true
    fi
    PATH="$old_path"
    unset CF_WEB_MOCK_LOG CF_WEB_MOCK_DATA CF_WEB_MOCK_ORIGIN_MODE
else
    skip "缺 jq，跳过 Cloudflare Web API runtime mock"
fi

echo ""
echo "== Built script runtime entrypoint =="
if [[ "$(id -u)" -eq 0 && -f dist/v4-built.sh && "$CACHE_DIR" == "/var/cache/server-manage" && "$LOG_FILE" == "/var/log/server-manage.log" ]]; then
    entry_cache_backup="$tmp_root/entry-cache.backup"
    entry_log_backup="$tmp_root/entry-log.backup"
    if [[ "$cache_touched" -eq 0 && -d "$CACHE_DIR" ]]; then
        cp -a "$CACHE_DIR" "$entry_cache_backup"
        cache_backup="$entry_cache_backup"
    fi
    cache_touched=1
    rm -rf "$CACHE_DIR"
    mkdir -p "$CACHE_DIR"
    cat > "$CACHE_FILE" <<'EOF'
CACHED_IPV4="198.51.100.8"
CACHED_IPV6="2001:db8::8"
CACHED_ISP="Entrypoint ISP"
CACHED_LOCATION="ZZ Entrypoint"
EOF
    chmod 600 "$CACHE_FILE"
    if [[ "$log_touched" -eq 0 && -f "$LOG_FILE" ]]; then
        cp -a "$LOG_FILE" "$entry_log_backup"
        log_backup="$entry_log_backup"
    fi
    log_touched=1
    entry_harness="$tmp_root/dist-entrypoint-harness.sh"
    entry_out="$tmp_root/dist-entrypoint.out"
    entry_err="$tmp_root/dist-entrypoint.err"
    entry_reality_harness="$tmp_root/dist-reality-cli-harness.sh"
    entry_reality_out="$tmp_root/dist-reality-cli.out"
    entry_reality_err="$tmp_root/dist-reality-cli.err"
    entry_reality_status_harness="$tmp_root/dist-reality-status-harness.sh"
    entry_reality_status_out="$tmp_root/dist-reality-status.out"
    entry_reality_status_err="$tmp_root/dist-reality-status.err"
    entry_reality_info_harness="$tmp_root/dist-reality-info-harness.sh"
    entry_reality_info_out="$tmp_root/dist-reality-info.out"
    entry_reality_info_err="$tmp_root/dist-reality-info.err"
    entry_menu_route_harness="$tmp_root/dist-menu-route-harness.sh"
    entry_menu_route_out="$tmp_root/dist-menu-route.out"
    entry_menu_route_err="$tmp_root/dist-menu-route.err"
    {
        sed '$d' dist/v4-built.sh
        cat <<'ENTRY_HARNESS'
auto_deps() { :; }
main
ENTRY_HARNESS
    } > "$entry_harness"
    chmod +x "$entry_harness"
    if printf '0\n' | TERM=dumb bash "$entry_harness" >"$entry_out" 2>"$entry_err"; then
        if grep -qF 'server-manage' "$entry_out" \
           && grep -qF '0. 退出脚本' "$entry_out" \
           && grep -qF '感谢使用 server-manage' "$entry_out"; then
            pass "构建产物 dist/v4-built.sh 可真实初始化、渲染主菜单并正常退出"
        else
            fail "构建产物入口输出缺少主菜单或退出确认"
            sed 's/^/    /' "$entry_out" 2>/dev/null | head -80 || true
            sed 's/^/    /' "$entry_err" 2>/dev/null | head -80 || true
        fi
    else
        fail "构建产物入口执行失败"
        sed 's/^/    /' "$entry_out" 2>/dev/null | head -80 || true
        sed 's/^/    /' "$entry_err" 2>/dev/null | head -80 || true
    fi
    {
        sed '$d' dist/v4-built.sh
        cat <<'REALITY_CLI_HARNESS'
auto_deps() { :; }
main --reality __server_manage_unknown_runtime_probe__
REALITY_CLI_HARNESS
    } > "$entry_reality_harness"
    chmod +x "$entry_reality_harness"
    if TERM=dumb bash "$entry_reality_harness" >"$entry_reality_out" 2>"$entry_reality_err"; then
        fail "构建产物 --reality 未知命令应返回失败"
        sed 's/^/    /' "$entry_reality_out" 2>/dev/null | head -80 || true
        sed 's/^/    /' "$entry_reality_err" 2>/dev/null | head -80 || true
    else
        reality_cli_rc=$?
        if [[ "$reality_cli_rc" -eq 1 ]] \
           && grep -qF '未知 Reality 命令' "$entry_reality_err"; then
            pass "构建产物 --reality CLI 可真实初始化并 fail-closed 分发未知命令"
        else
            fail "构建产物 --reality CLI 未按预期 fail-closed"
            printf '    rc=%s\n' "$reality_cli_rc"
            sed 's/^/    /' "$entry_reality_out" 2>/dev/null | head -80 || true
            sed 's/^/    /' "$entry_reality_err" 2>/dev/null | head -80 || true
        fi
    fi
    {
        sed '$d' dist/v4-built.sh
        cat <<'REALITY_STATUS_HARNESS'
auto_deps() { :; }
main --reality status
REALITY_STATUS_HARNESS
    } > "$entry_reality_status_harness"
    chmod +x "$entry_reality_status_harness"
    if TERM=dumb bash "$entry_reality_status_harness" >"$entry_reality_status_out" 2>"$entry_reality_status_err"; then
        entry_reality_status_text="$(cat "$entry_reality_status_out" "$entry_reality_status_err" 2>/dev/null)"
        if grep -qF 'Reality 服务状态' "$entry_reality_status_out" \
           && grep -Eq 'sing-box|realm' <<< "$entry_reality_status_text"; then
            pass "构建产物 --reality status 可真实查询服务状态"
        else
            fail "构建产物 --reality status 输出缺少服务状态信息"
            sed 's/^/    /' "$entry_reality_status_out" 2>/dev/null | head -100 || true
            sed 's/^/    /' "$entry_reality_status_err" 2>/dev/null | head -100 || true
        fi
    else
        fail "构建产物 --reality status 执行失败"
        sed 's/^/    /' "$entry_reality_status_out" 2>/dev/null | head -100 || true
        sed 's/^/    /' "$entry_reality_status_err" 2>/dev/null | head -100 || true
    fi
    {
        sed '$d' dist/v4-built.sh
        cat <<'REALITY_INFO_HARNESS'
auto_deps() { :; }
REALITY_CONFIG_DIR="${ENTRY_REALITY_INFO_DIR:?}"
REALITY_STATE_FILE="${REALITY_CONFIG_DIR}/state.conf"
REALITY_LINK_FILE="${REALITY_CONFIG_DIR}/client-link.txt"
REALITY_CLIENT_JSON="${REALITY_CONFIG_DIR}/client.json"
REALITY_LINK_FILE_V4="${REALITY_CONFIG_DIR}/client-link-v4.txt"
REALITY_LINK_FILE_V6="${REALITY_CONFIG_DIR}/client-link-v6.txt"
REALITY_CLIENT_JSON_V4="${REALITY_CONFIG_DIR}/client-v4.json"
REALITY_CLIENT_JSON_V6="${REALITY_CONFIG_DIR}/client-v6.json"
REALITY_BACKUP_DIR="${REALITY_CONFIG_DIR}/backups"
REALITY_RELAY_DIR="${REALITY_CONFIG_DIR}/relays"
REALITY_CDN_STATE_FILE="${REALITY_CONFIG_DIR}/cdn.conf"
REALITY_CDN_LINK_FILE="${REALITY_CONFIG_DIR}/cdn-link.txt"
REALITY_CDN_CLIENT_JSON="${REALITY_CONFIG_DIR}/cdn-client.json"
REALITY_COEXIST_STATE_FILE="${REALITY_CONFIG_DIR}/coexist.conf"
mkdir -p "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR"
cat > "$REALITY_STATE_FILE" <<'EOF_STATE'
REALITY_ROLE="landing"
REALITY_NODE_NAME="runtime-node"
REALITY_NODE_DOMAIN="node.runtime.example.com"
REALITY_DNS_MODE="auto"
REALITY_NODE_DOMAIN_V4=""
REALITY_NODE_DOMAIN_V6=""
REALITY_NODE_NAME_V4=""
REALITY_NODE_NAME_V6=""
REALITY_SNI="www.microsoft.com"
REALITY_PORT="24443"
REALITY_PORT_V6=""
REALITY_UUID="11111111-1111-1111-1111-111111111111"
REALITY_PRIVATE_KEY="private-runtime"
REALITY_PUBLIC_KEY="public-runtime"
REALITY_SHORT_ID="abcd1234"
REALITY_FINGERPRINT="chrome"
REALITY_LISTEN_HOST="0.0.0.0"
REALITY_LISTEN_HOST_V4=""
REALITY_LISTEN_HOST_V6=""
REALITY_RELAY_DOMAIN=""
REALITY_RELAY_PORT=""
REALITY_RELAY_TARGET_HOST=""
REALITY_RELAY_TARGET_PORT=""
EOF_STATE
chmod 600 "$REALITY_STATE_FILE"
printf '%s\n' 'vless://runtime-info@node.runtime.example.com:24443?security=reality&sni=www.microsoft.com' > "$REALITY_LINK_FILE"
main --reality info
REALITY_INFO_HARNESS
    } > "$entry_reality_info_harness"
    chmod +x "$entry_reality_info_harness"
    if ENTRY_REALITY_INFO_DIR="$tmp_root/reality-info-state" TERM=dumb bash "$entry_reality_info_harness" >"$entry_reality_info_out" 2>"$entry_reality_info_err"; then
        if grep -qF '节点名称: runtime-node' "$entry_reality_info_out" \
           && grep -qF '落地域名: node.runtime.example.com' "$entry_reality_info_out" \
           && grep -qF 'Reality端口: 24443' "$entry_reality_info_out" \
           && grep -qF 'SNI: www.microsoft.com' "$entry_reality_info_out" \
           && grep -qF 'vless://runtime-info@node.runtime.example.com:24443' "$entry_reality_info_out"; then
            pass "构建产物 --reality info 可真实读取临时状态并输出节点信息"
        else
            fail "构建产物 --reality info 输出缺少预期节点信息"
            sed 's/^/    /' "$entry_reality_info_out" 2>/dev/null | head -100 || true
            sed 's/^/    /' "$entry_reality_info_err" 2>/dev/null | head -100 || true
        fi
    else
        fail "构建产物 --reality info 执行失败"
        sed 's/^/    /' "$entry_reality_info_out" 2>/dev/null | head -100 || true
        sed 's/^/    /' "$entry_reality_info_err" 2>/dev/null | head -100 || true
    fi
    {
        sed '$d' dist/v4-built.sh
        cat <<'MENU_ROUTE_HARNESS'
auto_deps() { :; }
menu_update() {
    print_title "依赖检查与修复"
    echo "entry-menu-update-stub"
    pause
}
eval "$(declare -f validate_conf_file | sed '1s/^validate_conf_file/_entry_orig_validate_conf_file/')"
validate_conf_file() {
    [[ "${1:-}" == "${EMAIL_STATE_FILE:-__no_email_state__}" ]] && return 1
    _entry_orig_validate_conf_file "$@"
}
email_state_load() { return 1; }
wg_deb_is_installed() { return 1; }
reality_coexist_enabled() { return 1; }
main
MENU_ROUTE_HARNESS
    } > "$entry_menu_route_harness"
    chmod +x "$entry_menu_route_harness"
    if printf '1\n\n2\n0\n3\n0\n4\n0\n5\n0\n6\n0\n7\n0\n8\n0\n9\n0\n10\n0\n11\n0\n12\n0\n' \
        | TERM=dumb bash "$entry_menu_route_harness" >"$entry_menu_route_out" 2>"$entry_menu_route_err"; then
        if grep -qF 'entry-menu-update-stub' "$entry_menu_route_out" \
           && grep -qF 'UFW 防火墙管理' "$entry_menu_route_out" \
           && grep -qF 'Fail2ban 入侵防御' "$entry_menu_route_out" \
           && grep -qF 'SSH 安全管理' "$entry_menu_route_out" \
           && grep -qF '系统优化' "$entry_menu_route_out" \
           && grep -qF '网络管理工具' "$entry_menu_route_out" \
           && grep -qF 'Web 服务管理' "$entry_menu_route_out" \
           && grep -qF 'Docker 管理' "$entry_menu_route_out" \
           && grep -qF 'WireGuard VPN' "$entry_menu_route_out" \
           && grep -qF 'Cloudflare 临时邮箱' "$entry_menu_route_out" \
           && grep -qF 'Sing-box Reality 节点' "$entry_menu_route_out" \
           && grep -qF '操作日志' "$entry_menu_route_out" \
           && grep -qF '感谢使用 server-manage' "$entry_menu_route_out"; then
            pass "构建产物主菜单可真实分发到各一级菜单(含依赖检查)并逐级返回"
        else
            fail "构建产物主菜单一级路由输出缺少预期菜单"
            sed 's/^/    /' "$entry_menu_route_out" 2>/dev/null | head -160 || true
            sed 's/^/    /' "$entry_menu_route_err" 2>/dev/null | head -120 || true
        fi
	    else
	        fail "构建产物主菜单一级路由执行失败"
	        sed 's/^/    /' "$entry_menu_route_out" 2>/dev/null | head -160 || true
	        sed 's/^/    /' "$entry_menu_route_err" 2>/dev/null | head -120 || true
	    fi

	    secondary_menu_out="$tmp_root/secondary-menu-smoke.out"
	    secondary_menu_err="$tmp_root/secondary-menu-smoke.err"
	    if (
	        pause() { :; }
	        sleep() { :; }
	        draw_line() { :; }
	        log_action() { :; }
	        fix_terminal() { :; }
	        confirm() { return 1; }
	        auto_deps() { :; }
	        command_exists() {
	            case "${1:-}" in
	                ufw|fail2ban-client|docker|certbot|crontab) return 1 ;;
	                *) command -v "$1" >/dev/null 2>&1 ;;
	            esac
	        }
	        ufw_is_active() { return 1; }
	        systemctl() { return 3; }
	        refresh_ssh_port() { CURRENT_SSH_PORT=22; CURRENT_SSH_PORTS="22"; }
	        get_public_ipv4() { printf '198.51.100.10\n'; }
	        get_public_ipv6() { printf '2001:db8::10\n'; }
	        email_state_load() { return 1; }
	        validate_conf_file() { return 1; }
	        wg_deb_is_installed() { return 1; }
	        reality_coexist_enabled() { return 1; }
	        menu_update() { print_title "依赖检查与修复"; echo "secondary-menu-update-stub"; pause; }
	        printf '0\n' | menu_ufw
	        printf '8\n0\n0\n' | menu_ufw
	        printf '0\n' | menu_f2b
	        printf '0\n' | menu_ssh
	        printf '0\n' | menu_opt
	        printf '0\n' | menu_net
	        printf '0\n' | menu_web
	        printf '0\n' | menu_docker
	        printf '0\n' | wg_deb_main_menu
	        printf '0\n' | menu_email
	        printf '0\n' | reality_menu
	    ) > "$secondary_menu_out" 2> "$secondary_menu_err"; then
	        if grep -qF 'UFW 防火墙管理' "$secondary_menu_out" \
	           && grep -qF 'GeoIP 国家级 IP 白/黑名单' "$secondary_menu_out" \
	           && grep -qF 'Fail2ban 入侵防御' "$secondary_menu_out" \
	           && grep -qF 'SSH 安全管理' "$secondary_menu_out" \
	           && grep -qF '系统优化' "$secondary_menu_out" \
	           && grep -qF '网络管理工具' "$secondary_menu_out" \
	           && grep -qF 'Web 服务管理' "$secondary_menu_out" \
	           && grep -qF 'Docker 管理' "$secondary_menu_out" \
	           && grep -qF 'WireGuard VPN' "$secondary_menu_out" \
	           && grep -qF 'Cloudflare 临时邮箱' "$secondary_menu_out" \
	           && grep -qF 'Sing-box Reality 节点' "$secondary_menu_out"; then
	            pass "二级菜单在实体机 shell 中可渲染并安全返回"
	        else
	            fail "二级菜单 smoke 输出缺少预期菜单"
	            sed 's/^/    /' "$secondary_menu_out" 2>/dev/null | head -220 || true
	            sed 's/^/    /' "$secondary_menu_err" 2>/dev/null | head -120 || true
	        fi
	    else
	        fail "二级菜单 smoke 执行失败"
	        sed 's/^/    /' "$secondary_menu_out" 2>/dev/null | head -220 || true
	        sed 's/^/    /' "$secondary_menu_err" 2>/dev/null | head -120 || true
	    fi
	else
	    skip "缺少 root、dist/v4-built.sh 或预期系统路径，跳过构建产物入口实测"
	fi

echo ""
echo "== Dependency repair menu runtime mock =="
menu_update_mock_bin="$tmp_root/menu-update-bin"
menu_update_log="$tmp_root/menu-update.log"
mkdir -p "$menu_update_mock_bin"
cat > "$menu_update_mock_bin/apt-get" <<'EOF_MENU_UPDATE_APT'
#!/usr/bin/env bash
printf 'apt-get|%s\n' "$*" >> "$MENU_UPDATE_LOG"
exit 0
EOF_MENU_UPDATE_APT
cat > "$menu_update_mock_bin/dpkg" <<'EOF_MENU_UPDATE_DPKG'
#!/usr/bin/env bash
printf 'dpkg|%s\n' "$*" >> "$MENU_UPDATE_LOG"
if [[ "${1:-}" == "-s" && "${2:-}" == "fail2ban" ]]; then
    exit 1
fi
exit 0
EOF_MENU_UPDATE_DPKG
cat > "$menu_update_mock_bin/systemctl" <<'EOF_MENU_UPDATE_SYSTEMCTL'
#!/usr/bin/env bash
printf 'systemctl|%s\n' "$*" >> "$MENU_UPDATE_LOG"
if [[ "${1:-}" == "is-active" && "${2:-}" == "fail2ban" ]]; then
    exit 3
fi
exit 0
EOF_MENU_UPDATE_SYSTEMCTL
cat > "$menu_update_mock_bin/ufw" <<'EOF_MENU_UPDATE_UFW'
#!/usr/bin/env bash
printf 'ufw|%s\n' "$*" >> "$MENU_UPDATE_LOG"
exit 0
EOF_MENU_UPDATE_UFW
chmod +x "$menu_update_mock_bin/apt-get" "$menu_update_mock_bin/dpkg" "$menu_update_mock_bin/systemctl" "$menu_update_mock_bin/ufw"
if (
        export MENU_UPDATE_LOG="$menu_update_log"
        PATH="$menu_update_mock_bin:$PATH"
        pause() { :; }
        log_action() { printf 'log-action|%s\n' "$*" >> "$MENU_UPDATE_LOG"; }
        _deps_save_state() { printf 'deps-save|%s\n' "$1" >> "$MENU_UPDATE_LOG"; }
        ufw_is_active() { return 0; }
        menu_update
    ) > "$tmp_root/menu-update.out" 2>&1 \
   && grep -Fxq 'apt-get|update' "$menu_update_log" \
   && grep -Fxq 'dpkg|-s fail2ban' "$menu_update_log" \
   && grep -Fxq 'apt-get|install -y fail2ban' "$menu_update_log" \
   && grep -Fxq 'ufw|--force enable' "$menu_update_log" \
   && grep -Fxq 'systemctl|disable --now fail2ban' "$menu_update_log" \
   && grep -Fq 'deps-save|curl wget jq unzip openssl ca-certificates ufw fail2ban ipset iproute2 net-tools procps' "$menu_update_log" \
   && grep -Fxq 'log-action|Dependencies checked/repaired manually' "$menu_update_log"; then
    pass "menu_update 在实体机 mock 下执行依赖检查、状态记录和 fail2ban 新装停用分支"
else
    fail "menu_update 实体机 mock 行为异常"
    sed 's/^/    /' "$tmp_root/menu-update.out" 2>/dev/null | head -120 || true
    sed 's/^/    /' "$menu_update_log" 2>/dev/null | head -160 || true
fi

echo ""
echo "== Sysinfo cache runtime =="
if [[ "$(id -u)" -eq 0 && "$CACHE_DIR" == "/var/cache/server-manage" ]]; then
    cache_backup="$tmp_root/sysinfo-cache.backup"
    if [[ -d "$CACHE_DIR" ]]; then
        cp -a "$CACHE_DIR" "$cache_backup"
    fi
    cache_touched=1
    rm -rf "$CACHE_DIR"
    mkdir -p "$CACHE_DIR"
    cat > "$CACHE_FILE" <<'EOF'
CACHED_IPV4="198.51.100.7"
CACHED_IPV6="2001:db8::7"
CACHED_ISP="Runtime ISP"
CACHED_LOCATION="ZZ Runtime"
EOF
    chmod 600 "$CACHE_FILE"
    CACHED_IPV4="" CACHED_IPV6="" CACHED_ISP="" CACHED_LOCATION=""
    if load_cache && [[ "$CACHED_IPV4" == "198.51.100.7" && "$CACHED_IPV6" == "2001:db8::7" ]]; then
        pass "load_cache 接受真实 root:600 新鲜缓存"
    else
        fail "load_cache 未能读取真实安全缓存"
    fi
    touch -d '1970-01-01 UTC' "$CACHE_FILE" 2>/dev/null || touch -t 197001010000 "$CACHE_FILE" 2>/dev/null || true
    CACHED_IPV4="" CACHED_IPV6="" CACHED_ISP="" CACHED_LOCATION=""
    if ! load_cache && load_cache_stale && [[ "$CACHED_ISP" == "Runtime ISP" ]]; then
        pass "load_cache 拒绝过期缓存且 load_cache_stale 可安全读取"
    else
        fail "load_cache/load_cache_stale 过期缓存行为异常"
    fi
    printf 'CACHED_IPV4="$(touch %s)"\n' "$sysinfo_pwned" > "$CACHE_FILE"
    chmod 600 "$CACHE_FILE"
    rm -f "$sysinfo_pwned"
    if load_cache_stale >/dev/null 2>&1; then
        fail "load_cache_stale 接受了命令替换缓存"
    elif [[ -e "$sysinfo_pwned" ]]; then
        fail "load_cache_stale 校验恶意缓存时发生命令执行"
    else
        pass "load_cache_stale 拒绝恶意缓存且未执行"
    fi
    if [[ "$(get_ip_location_cached 192.168.1.1)" == "本地网络" ]]; then
        pass "get_ip_location_cached 对内网地址不触发外部查询"
    else
        fail "get_ip_location_cached 内网地址判定异常"
    fi
else
    skip "非 root 或 CACHE_DIR 非预期路径，跳过 sysinfo cache 实机项"
fi

echo ""
echo "== Atomic file writes =="
count_restart_log() {
    awk '$0 == "restart" { c++ } END { print c + 0 }' "${1:-/dev/null}" 2>/dev/null || echo 0
}
atomic_dir="$tmp_root/atomic"
atomic_file="$atomic_dir/runtime.conf"
mkdir -p "$atomic_dir"
printf 'old-value\n' > "$atomic_file"
chmod 640 "$atomic_file"
atomic_mode_before="$(stat -c '%a' "$atomic_file" 2>/dev/null || echo "")"
atomic_owner_before="$(stat -c '%u:%g' "$atomic_file" 2>/dev/null || echo "")"
atomic_content=$'new-value\nsecond-line'
if write_file_atomic "$atomic_file" "$atomic_content" \
   && cmp -s "$atomic_file" <(printf '%s\n' "$atomic_content"); then
    pass "write_file_atomic 在真实文件系统中原子替换内容"
else
    fail "write_file_atomic 未能正确写入内容"
    sed 's/^/    /' "$atomic_file" 2>/dev/null || true
fi
atomic_mode_after="$(stat -c '%a' "$atomic_file" 2>/dev/null || echo "")"
atomic_owner_after="$(stat -c '%u:%g' "$atomic_file" 2>/dev/null || echo "")"
if [[ "$atomic_mode_before" == "$atomic_mode_after" && "$atomic_owner_before" == "$atomic_owner_after" ]]; then
    pass "write_file_atomic 保留既有文件权限和属主"
else
    fail "write_file_atomic 权限/属主保留异常: ${atomic_mode_before}/${atomic_owner_before} -> ${atomic_mode_after}/${atomic_owner_after}"
fi
swap_runtime_dir="$tmp_root/swap-runtime"
swap_runtime_file="$swap_runtime_dir/swapfile"
swap_runtime_fstab="$swap_runtime_dir/fstab"
mkdir -p "$swap_runtime_dir"
cat > "$swap_runtime_fstab" <<EOF_SWAP_RUNTIME
# keep managed path in comment: $swap_runtime_file
/dev/sda2 none swap sw 0 0
$swap_runtime_file none ext4 defaults 0 0
EOF_SWAP_RUNTIME
chmod 640 "$swap_runtime_fstab" 2>/dev/null || true
swap_mode_before="$(stat -c '%a' "$swap_runtime_fstab" 2>/dev/null || echo "")"
_swap_file_path() { printf '%s' "$swap_runtime_file"; }
_swap_fstab_path() { printf '%s' "$swap_runtime_fstab"; }
if _swap_fstab_add_swapfile \
   && _swap_fstab_add_swapfile \
   && [[ "$(awk -v sf="$swap_runtime_file" '$1 == sf && $3 == "swap" { c++ } END { print c + 0 }' "$swap_runtime_fstab")" == "1" ]] \
   && grep -qF '/dev/sda2 none swap sw 0 0' "$swap_runtime_fstab" \
   && grep -qF "$swap_runtime_file none ext4 defaults 0 0" "$swap_runtime_fstab" \
   && [[ -z "$swap_mode_before" || "$(stat -c '%a' "$swap_runtime_fstab" 2>/dev/null || echo "")" == "$swap_mode_before" ]] \
   && ! find "$swap_runtime_dir" -maxdepth 1 -name '.tmp.server-manage.fstab.*' -print -quit | grep -q .; then
    pass "Swap fstab 添加在真实文件系统上原子追加且幂等"
else
    fail "Swap fstab 添加真实文件系统验证失败"
    ls -la "$swap_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$swap_runtime_fstab" 2>/dev/null || true
fi
if _swap_fstab_remove_swapfile \
   && ! awk -v sf="$swap_runtime_file" '$1 == sf && $3 == "swap" { found=1 } END { exit(found ? 0 : 1) }' "$swap_runtime_fstab" \
   && grep -qF "$swap_runtime_file none ext4 defaults 0 0" "$swap_runtime_fstab" \
   && ! find "$swap_runtime_dir" -maxdepth 1 -name '.tmp.server-manage.fstab.*' -print -quit | grep -q .; then
    pass "Swap fstab 删除在真实文件系统上仅移除受管行"
else
    fail "Swap fstab 删除真实文件系统验证失败"
    ls -la "$swap_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$swap_runtime_fstab" 2>/dev/null || true
fi
_swap_file_path() { printf '%s' "/swapfile"; }
_swap_fstab_path() { printf '%s' "/etc/fstab"; }
f2b_runtime_dir="$tmp_root/fail2ban-runtime"
f2b_runtime_conf="$f2b_runtime_dir/jail.local"
f2b_restart_log="$f2b_runtime_dir/restart.log"
mkdir -p "$f2b_runtime_dir"
cat > "$f2b_runtime_conf" <<'EOF_F2B_RUNTIME'
[sshd]
port = 22
EOF_F2B_RUNTIME
chmod 640 "$f2b_runtime_conf" 2>/dev/null || true
f2b_mode_before="$(stat -c '%a' "$f2b_runtime_conf" 2>/dev/null || echo "")"
FAIL2BAN_JAIL_LOCAL="$f2b_runtime_conf"
f2b_validate_rc=0
f2b_restart_rc=0
fail2ban-client() {
    [[ "${1:-}" == "-d" ]] && return "$f2b_validate_rc"
    return 1
}
systemctl() {
    case "${1:-} ${2:-}" in
        "enable fail2ban") return 0 ;;
        "restart fail2ban") printf 'restart\n' >> "$f2b_restart_log"; return "$f2b_restart_rc" ;;
        *) command systemctl "$@" ;;
    esac
}
if _f2b_apply_jail_local $'[sshd]\nport = 2222' 'runtime-action' >/dev/null 2>&1 \
   && grep -q '^port = 2222$' "$f2b_runtime_conf" \
   && [[ -z "$f2b_mode_before" || "$(stat -c '%a' "$f2b_runtime_conf" 2>/dev/null || echo "")" == "$f2b_mode_before" ]] \
   && [[ "$(count_restart_log "$f2b_restart_log")" -eq 1 ]] \
   && ! find "$f2b_runtime_dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
    pass "Fail2ban jail.local 在真实文件系统上校验后提交并重启"
else
    fail "Fail2ban jail.local 真实文件系统提交异常"
    ls -la "$f2b_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$f2b_runtime_conf" 2>/dev/null || true
fi
cat > "$f2b_runtime_conf" <<'EOF_F2B_RUNTIME'
[sshd]
port = 22
EOF_F2B_RUNTIME
: > "$f2b_restart_log"
f2b_validate_rc=1
f2b_restart_rc=0
if ! _f2b_apply_jail_local $'[sshd]\nport = 2223' 'runtime-action' >/dev/null 2>&1 \
   && grep -q '^port = 22$' "$f2b_runtime_conf" \
   && ! grep -q '^port = 2223$' "$f2b_runtime_conf" \
   && [[ ! -s "$f2b_restart_log" ]] \
   && ! find "$f2b_runtime_dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
    pass "Fail2ban jail.local 校验失败时真实回滚并跳过重启"
else
    fail "Fail2ban jail.local 校验失败回滚异常"
    ls -la "$f2b_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$f2b_runtime_conf" 2>/dev/null || true
fi
f2b_validate_rc=0
f2b_restart_rc=1
if ! _f2b_apply_jail_local $'[sshd]\nport = 2224' 'runtime-action' >/dev/null 2>&1 \
   && grep -q '^port = 22$' "$f2b_runtime_conf" \
   && ! grep -q '^port = 2224$' "$f2b_runtime_conf" \
   && [[ "$(count_restart_log "$f2b_restart_log")" -eq 1 ]] \
   && ! find "$f2b_runtime_dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
    pass "Fail2ban jail.local 重启失败时真实回滚"
else
    fail "Fail2ban jail.local 重启失败回滚异常"
    ls -la "$f2b_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$f2b_runtime_conf" 2>/dev/null || true
fi
unset -f fail2ban-client systemctl
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
web_proxy_runtime_dir="$tmp_root/web-proxy-runtime"
web_proxy_conf="$web_proxy_runtime_dir/site.conf"
mkdir -p "$web_proxy_runtime_dir"
cat > "$web_proxy_conf" <<'EOF_WEB_PROXY_RUNTIME'
server {
    location / {
        proxy_pass http://127.0.0.1:8080/base;
    }
}
EOF_WEB_PROXY_RUNTIME
chmod 640 "$web_proxy_conf" 2>/dev/null || true
web_proxy_mode_before="$(stat -c '%a' "$web_proxy_conf" 2>/dev/null || echo "")"
web_nginx_rc=0
web_reload_rc=0
nginx() { return "$web_nginx_rc"; }
_nginx_reload() { return "$web_reload_rc"; }
if _web_update_reverse_proxy_backend "$web_proxy_conf" 'http://127.0.0.1:9090/a&b|c' \
   && grep -Fq 'proxy_pass http://127.0.0.1:9090/a&b|c;' "$web_proxy_conf" \
   && [[ -z "$web_proxy_mode_before" || "$(stat -c '%a' "$web_proxy_conf" 2>/dev/null || echo "")" == "$web_proxy_mode_before" ]] \
   && ! find "$web_proxy_runtime_dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
    pass "Web 反代后端更新在真实文件系统上原子替换并保留权限"
else
    fail "Web 反代后端更新真实文件系统成功路径异常"
    ls -la "$web_proxy_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$web_proxy_conf" 2>/dev/null || true
fi
cat > "$web_proxy_conf" <<'EOF_WEB_PROXY_RUNTIME'
server {
    location / {
        proxy_pass http://127.0.0.1:8080/base;
    }
}
EOF_WEB_PROXY_RUNTIME
chmod 640 "$web_proxy_conf" 2>/dev/null || true
web_nginx_rc=1
web_reload_rc=0
if ! _web_update_reverse_proxy_backend "$web_proxy_conf" 'http://127.0.0.1:9091' >/dev/null 2>&1 \
   && grep -Fq 'proxy_pass http://127.0.0.1:8080/base;' "$web_proxy_conf" \
   && ! grep -Fq 'proxy_pass http://127.0.0.1:9091;' "$web_proxy_conf" \
   && ! find "$web_proxy_runtime_dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
    pass "Web 反代后端更新 nginx -t 失败时真实回滚并清理临时文件"
else
    fail "Web 反代后端更新 nginx -t 失败回滚异常"
    ls -la "$web_proxy_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$web_proxy_conf" 2>/dev/null || true
fi
web_nginx_rc=0
web_reload_rc=1
if ! _web_update_reverse_proxy_backend "$web_proxy_conf" 'http://127.0.0.1:9092' >/dev/null 2>&1 \
   && grep -Fq 'proxy_pass http://127.0.0.1:8080/base;' "$web_proxy_conf" \
   && ! grep -Fq 'proxy_pass http://127.0.0.1:9092;' "$web_proxy_conf" \
   && ! find "$web_proxy_runtime_dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
    pass "Web 反代后端更新 reload 失败时真实回滚并清理临时文件"
else
    fail "Web 反代后端更新 reload 失败回滚异常"
    ls -la "$web_proxy_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$web_proxy_conf" 2>/dev/null || true
fi
unset -f nginx _nginx_reload
f2b_sshd_runtime_dir="$tmp_root/fail2ban-sshd-port"
f2b_sshd_conf="$f2b_sshd_runtime_dir/jail.local"
f2b_no_sshd_conf="$f2b_sshd_runtime_dir/no-sshd.local"
mkdir -p "$f2b_sshd_runtime_dir"
cat > "$f2b_sshd_conf" <<'EOF_F2B_SSHD_RUNTIME'
[DEFAULT]
bantime = 1h

[sshd]
enabled = true
filter = sshd

[nginx-http-auth]
port = http,https
EOF_F2B_SSHD_RUNTIME
chmod 640 "$f2b_sshd_conf" 2>/dev/null || true
f2b_sshd_mode_before="$(stat -c '%a' "$f2b_sshd_conf" 2>/dev/null || echo "")"
if _fail2ban_set_sshd_port "$f2b_sshd_conf" "22222" \
   && awk '
        /^\[sshd\]$/ { in_sshd=1; next }
        /^\[[^]]+\]$/ { in_sshd=0 }
        in_sshd && /^port = 22222$/ { ok=1 }
        END { exit(ok ? 0 : 1) }
      ' "$f2b_sshd_conf" \
   && grep -q '^port = http,https$' "$f2b_sshd_conf" \
   && [[ -z "$f2b_sshd_mode_before" || "$(stat -c '%a' "$f2b_sshd_conf" 2>/dev/null || echo "")" == "$f2b_sshd_mode_before" ]] \
   && ! find "$f2b_sshd_runtime_dir" -maxdepth 1 -name '.tmp.fail2ban-sshd.*' -print -quit | grep -q .; then
    pass "Fail2ban sshd 端口 helper 在真实文件系统上只更新 [sshd] 并保留权限"
else
    fail "Fail2ban sshd 端口 helper 真实文件系统更新异常"
    ls -la "$f2b_sshd_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$f2b_sshd_conf" 2>/dev/null || true
fi
cat > "$f2b_no_sshd_conf" <<'EOF_F2B_NO_SSHD_RUNTIME'
[nginx-http-auth]
port = http,https
EOF_F2B_NO_SSHD_RUNTIME
if ! _fail2ban_set_sshd_port "$f2b_no_sshd_conf" "22223" >/dev/null 2>&1 \
   && grep -q '^port = http,https$' "$f2b_no_sshd_conf" \
   && ! grep -q '^port = 22223$' "$f2b_no_sshd_conf" \
   && ! find "$f2b_sshd_runtime_dir" -maxdepth 1 -name '.tmp.fail2ban-sshd.*' -print -quit | grep -q .; then
    pass "Fail2ban sshd 端口 helper 未命中 [sshd] 时真实失败且不污染文件"
else
    fail "Fail2ban sshd 端口 helper 未命中 [sshd] 的失败路径异常"
    ls -la "$f2b_sshd_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$f2b_no_sshd_conf" 2>/dev/null || true
fi
private_atomic_file="$atomic_dir/private-token.conf"
printf 'old-token\n' > "$private_atomic_file"
chmod 666 "$private_atomic_file"
if write_private_file_atomic "$private_atomic_file" 'SECRET_TOKEN="new-token"' \
   && grep -Fxq 'SECRET_TOKEN="new-token"' "$private_atomic_file" \
   && [[ "$(stat -c '%a' "$private_atomic_file" 2>/dev/null)" == "600" ]] \
   && [[ "$(stat -c '%U' "$private_atomic_file" 2>/dev/null)" == "root" ]]; then
    pass "write_private_file_atomic 覆盖旧宽权限敏感文件后强制 root:600"
else
    fail "write_private_file_atomic 未强制 root:600 或内容异常"
    ls -l "$private_atomic_file" 2>/dev/null | sed 's/^/    /' || true
fi
sysctl_base="$tmp_root/sysctl-base.conf"
sysctl_candidate="$tmp_root/sysctl-candidate.conf"
sysctl_bbr_candidate="$tmp_root/sysctl-bbr-candidate.conf"
sysctl_wg_base="$tmp_root/sysctl-wg-base.conf"
sysctl_wg_candidate="$tmp_root/sysctl-wg-candidate.conf"
sysctl_wg_disabled="$tmp_root/sysctl-wg-disabled.conf"
resolved_base="$tmp_root/resolved-base.conf"
resolved_candidate="$tmp_root/resolved-candidate.conf"
gai_base="$tmp_root/gai-base.conf"
gai_ipv4="$tmp_root/gai-ipv4.conf"
gai_ipv6="$tmp_root/gai-ipv6.conf"
hosts_base="$tmp_root/hosts-base"
hosts_candidate="$tmp_root/hosts-candidate"
geoip_base="$tmp_root/geoip.conf"
geoip_candidate="$tmp_root/geoip-updated.conf"
geoip_unit="$tmp_root/geoip-firewall.service"
geoip_apply="$tmp_root/geoip-apply.sh"
nginx_keyring="$tmp_root/nginx/keyrings/nginx.gpg"
nginx_source="$tmp_root/nginx/sources/nginx.list"
nginx_pin="$tmp_root/nginx/preferences/99nginx"
nginx_stream_conf="$tmp_root/nginx/modules-enabled/50-mod-stream.conf"
nginx_module_so="$tmp_root/nginx/modules/ngx_stream_module.so"
sagernet_keyring="$tmp_root/sagernet/keyrings/sagernet.asc"
sagernet_source="$tmp_root/sagernet/sources/sagernet.sources"
realm_unit="$tmp_root/systemd/realm.service"
realm_bin="$tmp_root/realm/bin/realm"
realm_config="$tmp_root/realm/config.toml"
cat > "$sysctl_base" <<'EOF'
# runtime sysctl base
EOF
safe_syncookies="$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null || true)"
if [[ "$safe_syncookies" =~ ^[0-9]+$ ]]; then
    _sysctl_render_tuned_conf "$sysctl_base" "# BEGIN server-manage sysctl tuning: runtime
net.ipv4.tcp_syncookies = ${safe_syncookies}
# END server-manage sysctl tuning" > "$sysctl_candidate"
    if grep -qF '# runtime sysctl base' "$sysctl_candidate" \
       && grep -q '^# BEGIN server-manage sysctl tuning' "$sysctl_candidate" \
       && sysctl -p "$sysctl_candidate" >/dev/null 2>&1; then
        pass "sysctl 调优候选配置可先由真实 sysctl -p 临时文件验证"
    else
        fail "sysctl 调优候选配置未通过真实 sysctl -p 验证"
        sysctl -p "$sysctl_candidate" 2>&1 | sed 's/^/    /' || true
        sed 's/^/    /' "$sysctl_candidate" 2>/dev/null || true
    fi
else
    skip "无法读取 net.ipv4.tcp_syncookies，跳过 sysctl 候选验证"
fi
safe_qdisc="$(sysctl -n net.core.default_qdisc 2>/dev/null || true)"
safe_cc="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)"
if [[ -n "$safe_qdisc" && -n "$safe_cc" ]]; then
    _sysctl_render_bbr_conf "$sysctl_base" "$safe_qdisc" "$safe_cc" > "$sysctl_bbr_candidate"
    if grep -qF '# runtime sysctl base' "$sysctl_bbr_candidate" \
       && grep -q '^# BEGIN server-manage bbr$' "$sysctl_bbr_candidate" \
       && grep -q "^net.core.default_qdisc = ${safe_qdisc}$" "$sysctl_bbr_candidate" \
       && grep -q "^net.ipv4.tcp_congestion_control = ${safe_cc}$" "$sysctl_bbr_candidate" \
       && sysctl -p "$sysctl_bbr_candidate" >/dev/null 2>&1; then
        pass "BBR 候选配置可先由真实 sysctl -p 临时文件验证"
    else
        fail "BBR 候选配置未通过真实 sysctl -p 验证"
        sysctl -p "$sysctl_bbr_candidate" 2>&1 | sed 's/^/    /' || true
        sed 's/^/    /' "$sysctl_bbr_candidate" 2>/dev/null || true
    fi
else
    skip "无法读取当前 qdisc/拥塞控制，跳过 BBR 候选验证"
fi
safe_forward="$(sysctl -n net.ipv4.ip_forward 2>/dev/null || true)"
if [[ "$safe_forward" =~ ^[0-9]+$ ]]; then
    cat > "$sysctl_wg_base" <<EOF
# runtime wg forward base
net.ipv4.ip_forward = ${safe_forward}
EOF
    _sysctl_render_wireguard_forward_conf "$sysctl_wg_base" 1 > "$sysctl_wg_candidate"
    _sysctl_render_wireguard_forward_conf "$sysctl_wg_candidate" 0 > "$sysctl_wg_disabled"
    if grep -qF '# runtime wg forward base' "$sysctl_wg_candidate" \
       && grep -q "^net.ipv4.ip_forward = ${safe_forward}$" "$sysctl_wg_candidate" \
       && grep -q '^# BEGIN server-manage wireguard ip-forward$' "$sysctl_wg_candidate" \
       && grep -q '^net.ipv4.ip_forward = 1$' "$sysctl_wg_candidate" \
       && grep -q "^net.ipv4.ip_forward = ${safe_forward}$" "$sysctl_wg_disabled" \
       && ! grep -q '^# BEGIN server-manage wireguard ip-forward$' "$sysctl_wg_disabled" \
       && sysctl -p "$sysctl_wg_candidate" >/dev/null 2>&1 \
       && sysctl -p "$sysctl_wg_disabled" >/dev/null 2>&1; then
        pass "WireGuard IP 转发候选配置可真实验证且禁用只移除托管块"
    else
        fail "WireGuard IP 转发候选配置/禁用渲染异常"
        sysctl -p "$sysctl_wg_candidate" 2>&1 | sed 's/^/    candidate: /' || true
        sysctl -p "$sysctl_wg_disabled" 2>&1 | sed 's/^/    disabled: /' || true
        sed 's/^/    candidate: /' "$sysctl_wg_candidate" 2>/dev/null || true
        sed 's/^/    disabled: /' "$sysctl_wg_disabled" 2>/dev/null || true
    fi
else
    skip "无法读取 net.ipv4.ip_forward，跳过 WireGuard IP 转发候选验证"
fi
cat > "$resolved_base" <<'EOF'
# runtime resolved base
[Resolve]
DNS=9.9.9.9
FallbackDNS=1.0.0.1
[DHCP]
UseDNS=yes
EOF
if _net_render_resolved_dns_conf "$resolved_base" "1.1.1.1 2606:4700:4700::1111" > "$resolved_candidate" \
   && grep -qF '# runtime resolved base' "$resolved_candidate" \
   && grep -q '^DNS=1.1.1.1 2606:4700:4700::1111$' "$resolved_candidate" \
   && grep -q '^FallbackDNS=1.0.0.1$' "$resolved_candidate" \
   && grep -q '^\[DHCP\]$' "$resolved_candidate" \
   && grep -q '^UseDNS=yes$' "$resolved_candidate" \
   && ! grep -q '^DNS=9.9.9.9$' "$resolved_candidate"; then
    pass "systemd-resolved DNS 候选渲染只替换 Resolve DNS"
else
    fail "systemd-resolved DNS 候选渲染异常"
    sed 's/^/    /' "$resolved_candidate" 2>/dev/null || true
fi
cat > "$gai_base" <<'EOF'
# runtime gai base
#precedence ::ffff:0:0/96  100
precedence 2002::/16  30
precedence ::ffff:0:0/96  100
EOF
_net_render_gai_conf "$gai_base" ipv4 > "$gai_ipv4"
_net_render_gai_conf "$gai_ipv4" ipv6 > "$gai_ipv6"
if grep -qF '# runtime gai base' "$gai_ipv4" \
   && grep -q '^#precedence ::ffff:0:0/96  100$' "$gai_ipv4" \
   && grep -q '^precedence 2002::/16  30$' "$gai_ipv4" \
   && grep -q '^# BEGIN server-manage ip-priority$' "$gai_ipv4" \
   && grep -q '^precedence ::ffff:0:0/96  100$' "$gai_ipv4" \
   && grep -q '^#precedence ::ffff:0:0/96  100$' "$gai_ipv6" \
   && grep -q '^precedence 2002::/16  30$' "$gai_ipv6" \
   && ! grep -q '^# BEGIN server-manage ip-priority$' "$gai_ipv6" \
   && ! grep -q '^precedence ::ffff:0:0/96  100$' "$gai_ipv6"; then
    pass "gai.conf IP 优先级候选只维护托管 IPv4 优先行"
else
    fail "gai.conf IP 优先级候选渲染异常"
    sed 's/^/    ipv4: /' "$gai_ipv4" 2>/dev/null || true
    sed 's/^/    ipv6: /' "$gai_ipv6" 2>/dev/null || true
fi
hostname_runtime_dir="$tmp_root/hostname-runtime"
hostname_runtime_file="$hostname_runtime_dir/hostname"
hosts_runtime_file="$hostname_runtime_dir/hosts"
mkdir -p "$hostname_runtime_dir"
printf 'oldbox\n' > "$hostname_runtime_file"
chmod 640 "$hostname_runtime_file" 2>/dev/null || true
cat > "$hosts_runtime_file" <<'EOF_HOSTS_RUNTIME'
# oldbox comment must remain
127.0.0.1 localhost oldbox oldbox
127.0.1.1 oldbox.example.com oldbox-other oldbox
::1 localhost ip6-localhost
EOF_HOSTS_RUNTIME
chmod 640 "$hosts_runtime_file" 2>/dev/null || true
hostname_mode_before="$(stat -c '%a' "$hostname_runtime_file" 2>/dev/null || echo "")"
hosts_mode_before="$(stat -c '%a' "$hosts_runtime_file" 2>/dev/null || echo "")"
_hostname_file_path() { printf '%s' "$hostname_runtime_file"; }
_hosts_file_path() { printf '%s' "$hosts_runtime_file"; }
if _hostname_write_file "newbox" \
   && grep -Fxq "newbox" "$hostname_runtime_file" \
   && [[ -z "$hostname_mode_before" || "$(stat -c '%a' "$hostname_runtime_file" 2>/dev/null || echo "")" == "$hostname_mode_before" ]] \
   && ! find "$hostname_runtime_dir" -maxdepth 1 -name '.tmp.server-manage.*' -print -quit | grep -q .; then
    pass "hostname 文件 helper 在真实文件系统上原子写入并保留权限"
else
    fail "hostname 文件 helper 真实写入/权限/清理异常"
    ls -la "$hostname_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$hostname_runtime_file" 2>/dev/null || true
fi
if _hostname_update_hosts "oldbox" "newbox" \
   && grep -qF '# oldbox comment must remain' "$hosts_runtime_file" \
   && grep -q '^127\.0\.0\.1 localhost newbox$' "$hosts_runtime_file" \
   && grep -q '^127\.0\.1\.1 oldbox.example.com oldbox-other newbox$' "$hosts_runtime_file" \
   && [[ -z "$hosts_mode_before" || "$(stat -c '%a' "$hosts_runtime_file" 2>/dev/null || echo "")" == "$hosts_mode_before" ]] \
   && ! awk 'NF && $1 !~ /^#/ { for (i=2; i<=NF; i++) if ($i == "oldbox") found=1 } END { exit found ? 0 : 1 }' "$hosts_runtime_file" \
   && ! find "$hostname_runtime_dir" -maxdepth 1 -name '.tmp.server-manage.*' -print -quit | grep -q .; then
    pass "hosts 更新 helper 在真实文件系统上精确替换 hostname token 并保留权限"
else
    fail "hosts 更新 helper 真实写入/权限/精确替换异常"
    ls -la "$hostname_runtime_dir" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$hosts_runtime_file" 2>/dev/null || true
fi
_hostname_file_path() { printf '%s' "/etc/hostname"; }
_hosts_file_path() { printf '%s' "/etc/hosts"; }
cat > "$hosts_base" <<'EOF'
# oldbox comment must remain
127.0.0.1 localhost oldbox oldbox
127.0.1.1 oldbox.example.com oldbox-other oldbox
::1 localhost ip6-localhost
EOF
if _hostname_render_hosts_conf "$hosts_base" oldbox newbox > "$hosts_candidate" \
   && grep -qF '# oldbox comment must remain' "$hosts_candidate" \
   && grep -q '^127\.0\.0\.1 localhost newbox$' "$hosts_candidate" \
   && grep -q '^127\.0\.1\.1 oldbox.example.com oldbox-other newbox$' "$hosts_candidate" \
   && ! awk 'NF && $1 !~ /^#/ { for (i=2; i<=NF; i++) if ($i == "oldbox") found=1 } END { exit found ? 0 : 1 }' "$hosts_candidate"; then
    pass "hosts 主机名候选只替换精确 hostname token"
else
    fail "hosts 主机名候选渲染异常"
    sed 's/^/    /' "$hosts_candidate" 2>/dev/null || true
fi
cat > "$geoip_base" <<'EOF'
# runtime geoip base
GEOIP_MODE="blacklist"
GEOIP_COUNTRIES="CN US"
GEOIP_LAST_UPDATE="2026-07-02"
GEOIP_LAST_UPDATE="2026-07-01"
EOF
if _geoip_render_conf_last_update "$geoip_base" "2026-07-03" > "$geoip_candidate" \
   && grep -qF '# runtime geoip base' "$geoip_candidate" \
   && grep -Fxq 'GEOIP_MODE="blacklist"' "$geoip_candidate" \
   && grep -Fxq 'GEOIP_COUNTRIES="CN US"' "$geoip_candidate" \
   && [[ "$(grep -c '^GEOIP_LAST_UPDATE=' "$geoip_candidate")" == "1" ]] \
   && grep -Fxq 'GEOIP_LAST_UPDATE="2026-07-03"' "$geoip_candidate"; then
    pass "GeoIP LAST_UPDATE 候选渲染保留双引号并去重"
else
    fail "GeoIP LAST_UPDATE 候选渲染异常"
    sed 's/^/    /' "$geoip_candidate" 2>/dev/null || true
fi
printf '#!/bin/sh\nexit 0\n' > "$geoip_apply"
chmod 700 "$geoip_apply"
if _geoip_render_service_unit "$geoip_apply" > "$geoip_unit" \
   && grep -q '^ExecStart='"$geoip_apply"'$' "$geoip_unit"; then
    if command_exists systemd-analyze; then
        if systemd-analyze verify "$geoip_unit" >/dev/null 2>&1; then
            pass "systemd 接受 GeoIP firewall unit 候选"
        else
            fail "systemd 拒绝 GeoIP firewall unit 候选"
            systemd-analyze verify "$geoip_unit" 2>&1 | sed 's/^/    /' || true
        fi
    else
        pass "GeoIP firewall unit 候选包含正确 ExecStart"
    fi
else
    fail "GeoIP firewall unit 候选渲染异常"
    sed 's/^/    /' "$geoip_unit" 2>/dev/null || true
fi
if [[ "$(id -u)" -eq 0 ]]; then
    geoip_apply_runtime_dir="$tmp_root/geoip-apply-runtime"
    geoip_apply_generated="$geoip_apply_runtime_dir/geoip-apply.generated.sh"
    geoip_update_generated="$geoip_apply_runtime_dir/geoip-update.generated.sh"
    geoip_service_generated="$geoip_apply_runtime_dir/geoip-firewall.service"
    geoip_apply_conf_dir="$geoip_apply_runtime_dir/etc-server-manage"
    geoip_apply_conf="$geoip_apply_conf_dir/geoip.conf"
    geoip_apply_data="$geoip_apply_conf_dir/geoip-data"
    geoip_apply_bin="$geoip_apply_runtime_dir/bin"
    geoip_ipset_log="$geoip_apply_runtime_dir/ipset.log"
    geoip_restore_log="$geoip_apply_runtime_dir/ipset-restore.log"
    geoip_iptables_log="$geoip_apply_runtime_dir/iptables.log"
    geoip_ip6tables_log="$geoip_apply_runtime_dir/ip6tables.log"
    geoip_apply_run_out="$geoip_apply_runtime_dir/apply.out"
    mkdir -p "$geoip_apply_conf_dir" "$geoip_apply_data" "$geoip_apply_bin"
    if (
        is_systemd() { return 1; }
        cron_add_job() { return 0; }
        GEOIP_APPLY_SCRIPT="$geoip_apply_generated" \
        GEOIP_UPDATE_SCRIPT="$geoip_update_generated" \
        GEOIP_SERVICE_FILE="$geoip_service_generated" \
            _geoip_install_persistence
    ) && sed -i \
        -e "s|^CONF=.*|CONF=\"$geoip_apply_conf\"|" \
        -e "s|^DATA=.*|DATA=\"$geoip_apply_data\"|" \
        "$geoip_apply_generated"; then
        cat > "$geoip_apply_conf" <<'EOF_GEOIP_RUNTIME_CONF'
GEOIP_MODE="blacklist"
GEOIP_COUNTRIES="CN"
GEOIP_LAST_UPDATE="2026-07-03"
EOF_GEOIP_RUNTIME_CONF
        chmod 600 "$geoip_apply_conf"
        chown root:root "$geoip_apply_conf" 2>/dev/null || true
        cat > "$geoip_apply_data/cn.zone" <<'EOF_GEOIP_RUNTIME_ZONE4'
1.2.3.0/24
# comment
not-a-cidr
EOF_GEOIP_RUNTIME_ZONE4
        cat > "$geoip_apply_data/cn.zone6" <<'EOF_GEOIP_RUNTIME_ZONE6'
2001:db8::/32
# comment
EOF_GEOIP_RUNTIME_ZONE6
        cat > "$geoip_apply_bin/ipset" <<'EOF_GEOIP_RUNTIME_IPSET'
#!/usr/bin/env bash
printf 'ipset|%s\n' "$*" >> "$GEOIP_IPSET_LOG"
if [[ "${1:-}" == "restore" ]]; then
    cat >> "$GEOIP_IPSET_RESTORE_LOG"
fi
exit 0
EOF_GEOIP_RUNTIME_IPSET
        cat > "$geoip_apply_bin/iptables" <<'EOF_GEOIP_RUNTIME_IPTABLES'
#!/usr/bin/env bash
printf 'iptables|%s\n' "$*" >> "$GEOIP_IPTABLES_LOG"
if [[ "${1:-}" == "-C" && "${2:-}" == "INPUT" && "${3:-}" == "-j" && "${4:-}" == "GEOIP_FILTER" ]]; then
    exit 1
fi
exit 0
EOF_GEOIP_RUNTIME_IPTABLES
        cat > "$geoip_apply_bin/ip6tables" <<'EOF_GEOIP_RUNTIME_IP6TABLES'
#!/usr/bin/env bash
printf 'ip6tables|%s\n' "$*" >> "$GEOIP_IP6TABLES_LOG"
if [[ "${1:-}" == "-C" && "${2:-}" == "INPUT" && "${3:-}" == "-j" && "${4:-}" == "GEOIP6_FILTER" ]]; then
    exit 1
fi
exit 0
EOF_GEOIP_RUNTIME_IP6TABLES
        chmod +x "$geoip_apply_bin/ipset" "$geoip_apply_bin/iptables" "$geoip_apply_bin/ip6tables"
        : > "$geoip_ipset_log"
        : > "$geoip_restore_log"
        : > "$geoip_iptables_log"
        : > "$geoip_ip6tables_log"
        if GEOIP_IPSET_LOG="$geoip_ipset_log" \
           GEOIP_IPSET_RESTORE_LOG="$geoip_restore_log" \
           GEOIP_IPTABLES_LOG="$geoip_iptables_log" \
           GEOIP_IP6TABLES_LOG="$geoip_ip6tables_log" \
           PATH="$geoip_apply_bin:$PATH" \
              "$geoip_apply_generated" >"$geoip_apply_run_out" 2>&1 \
           && grep -Fq 'ipset|create geoip_blacklist_tmp hash:net maxelem 131072' "$geoip_ipset_log" \
           && grep -Fq 'ipset|swap geoip_blacklist_tmp geoip_blacklist' "$geoip_ipset_log" \
           && grep -Fq 'ipset|swap geoip_blacklist6_tmp geoip_blacklist6' "$geoip_ipset_log" \
           && grep -Fq 'add geoip_blacklist_tmp 1.2.3.0/24' "$geoip_restore_log" \
           && grep -Fq 'add geoip_blacklist6_tmp 2001:db8::/32' "$geoip_restore_log" \
           && grep -Fq 'iptables|-I INPUT 1 -j GEOIP_FILTER' "$geoip_iptables_log" \
           && grep -Fq 'iptables|-A GEOIP_FILTER -m set --match-set geoip_blacklist src -j DROP' "$geoip_iptables_log" \
           && grep -Fq 'ip6tables|-I INPUT 1 -j GEOIP6_FILTER' "$geoip_ip6tables_log" \
           && grep -Fq 'ip6tables|-A GEOIP6_FILTER -m set --match-set geoip_blacklist6 src -j DROP' "$geoip_ip6tables_log"; then
            pass "GeoIP 持久化 apply 生成脚本在实体机 mock 下应用 IPv4/IPv6 规则"
        else
            fail "GeoIP 持久化 apply 生成脚本未正确应用 IPv4/IPv6 规则"
            sed 's/^/    out: /' "$geoip_apply_run_out" 2>/dev/null || true
            sed 's/^/    ipset: /' "$geoip_ipset_log" 2>/dev/null || true
            sed 's/^/    restore: /' "$geoip_restore_log" 2>/dev/null || true
            sed 's/^/    iptables: /' "$geoip_iptables_log" 2>/dev/null || true
            sed 's/^/    ip6tables: /' "$geoip_ip6tables_log" 2>/dev/null || true
        fi
        : > "$geoip_ipset_log"
        : > "$geoip_restore_log"
        : > "$geoip_iptables_log"
        : > "$geoip_ip6tables_log"
        chmod 666 "$geoip_apply_conf"
        if GEOIP_IPSET_LOG="$geoip_ipset_log" \
           GEOIP_IPSET_RESTORE_LOG="$geoip_restore_log" \
           GEOIP_IPTABLES_LOG="$geoip_iptables_log" \
           GEOIP_IP6TABLES_LOG="$geoip_ip6tables_log" \
           PATH="$geoip_apply_bin:$PATH" \
              "$geoip_apply_generated" >"$geoip_apply_run_out" 2>&1 \
           && [[ ! -s "$geoip_ipset_log" ]] \
           && [[ ! -s "$geoip_restore_log" ]] \
           && [[ ! -s "$geoip_iptables_log" ]] \
           && [[ ! -s "$geoip_ip6tables_log" ]]; then
            pass "GeoIP 持久化 apply 生成脚本拒绝宽权限配置且不触碰防火墙"
        else
            fail "GeoIP 持久化 apply 生成脚本宽权限配置保护异常"
            sed 's/^/    out: /' "$geoip_apply_run_out" 2>/dev/null || true
            sed 's/^/    ipset: /' "$geoip_ipset_log" 2>/dev/null || true
            sed 's/^/    restore: /' "$geoip_restore_log" 2>/dev/null || true
            sed 's/^/    iptables: /' "$geoip_iptables_log" 2>/dev/null || true
            sed 's/^/    ip6tables: /' "$geoip_ip6tables_log" 2>/dev/null || true
        fi
    else
        fail "GeoIP 持久化 apply 生成脚本生成或临时路径重定向失败"
        sed 's/^/    /' "$geoip_apply_generated" 2>/dev/null | head -120 || true
    fi
else
    skip "非 root，跳过 GeoIP 持久化 apply 生成脚本实体机 mock 测试"
fi
mkdir -p "$(dirname "$nginx_module_so")"
: > "$nginx_module_so"
NGINX_KEYRING_FILE="$nginx_keyring"
NGINX_SOURCE_LIST_FILE="$nginx_source"
NGINX_APT_PIN_FILE="$nginx_pin"
NGINX_STREAM_MODULE_CONF="$nginx_stream_conf"
if _nginx_write_official_apt_files debian bookworm \
   && grep -Fxq "deb [signed-by=$nginx_keyring] http://nginx.org/packages/debian bookworm nginx" "$nginx_source" \
   && grep -Fxq 'Pin: origin nginx.org' "$nginx_pin" \
   && grep -Fxq 'Pin-Priority: 900' "$nginx_pin" \
   && [[ "$(stat -c '%a' "$nginx_source" 2>/dev/null || echo "")" == "644" ]] \
   && [[ "$(stat -c '%a' "$nginx_pin" 2>/dev/null || echo "")" == "644" ]]; then
    pass "nginx.org apt source/pin 候选通过原子写入并为 0644"
else
    fail "nginx.org apt source/pin 候选渲染或权限异常"
    sed 's/^/    source: /' "$nginx_source" 2>/dev/null || true
    sed 's/^/    pin: /' "$nginx_pin" 2>/dev/null || true
fi
if _nginx_write_stream_module_conf "$nginx_module_so" \
   && grep -Fxq "load_module $nginx_module_so;" "$nginx_stream_conf" \
   && [[ "$(stat -c '%a' "$nginx_stream_conf" 2>/dev/null || echo "")" == "644" ]]; then
    pass "nginx stream module load 配置候选通过原子写入并为 0644"
else
    fail "nginx stream module load 配置候选异常"
    sed 's/^/    /' "$nginx_stream_conf" 2>/dev/null || true
fi
unset NGINX_KEYRING_FILE NGINX_SOURCE_LIST_FILE NGINX_APT_PIN_FILE NGINX_STREAM_MODULE_CONF

docker_keyring="$tmp_root/docker/keyrings/docker.gpg"
docker_source="$tmp_root/docker/sources/docker.list"
docker_compose_bin="$tmp_root/docker/bin/docker-compose"
docker_compose_payload="$tmp_root/docker-compose.payload"
docker_curl_log="$tmp_root/docker-curl.log"
cat > "$docker_compose_payload" <<'EOF'
#!/bin/sh
echo "Docker Compose mock"
EOF
docker_compose_hash="$(sha256sum "$docker_compose_payload" | awk '{print $1}')"
curl() {
    local out="" url="" arg
    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            -o)
                shift
                out="${1:-}"
                ;;
            http://*|https://*)
                url="$arg"
                ;;
        esac
        shift || break
    done
    [[ -n "$out" && -n "$url" ]] || return 2
    printf '%s\n' "$url" >> "$docker_curl_log"
    case "$url" in
        https://download.docker.com/linux/debian/gpg)
            printf 'mock armored docker key\n' > "$out"
            ;;
        https://github.com/docker/compose/releases/download/v9.9.9/docker-compose-linux-x86_64)
            cp "$docker_compose_payload" "$out"
            ;;
        https://github.com/docker/compose/releases/download/v9.9.9/docker-compose-linux-x86_64.sha256)
            printf '%s  docker-compose-linux-x86_64\n' "$docker_compose_hash" > "$out"
            ;;
        *)
            return 7
            ;;
    esac
}
gpg() {
    [[ "${1:-}" == "--dearmor" ]] || return 1
    printf 'dearmored:'
    cat
}
DOCKER_KEYRING_FILE="$docker_keyring"
DOCKER_SOURCE_LIST_FILE="$docker_source"
DOCKER_COMPOSE_BIN="$docker_compose_bin"
if _docker_install_keyring debian "$docker_keyring" \
   && grep -qF 'dearmored:mock armored docker key' "$docker_keyring" \
   && [[ "$(stat -c '%a' "$docker_keyring" 2>/dev/null || echo "")" == "644" ]] \
   && ! find "$(dirname "$docker_keyring")" -maxdepth 1 -name '.tmp.server-manage.docker-gpg*' -print -quit | grep -q .; then
    pass "Docker GPG keyring 通过同目录候选文件原子落地并清理"
else
    fail "Docker GPG keyring 原子落地或清理异常"
    ls -la "$(dirname "$docker_keyring")" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$docker_keyring" 2>/dev/null || true
fi
if _docker_write_apt_source "$docker_source" amd64 "$docker_keyring" debian bookworm \
   && grep -Fxq "deb [arch=amd64 signed-by=$docker_keyring] https://download.docker.com/linux/debian bookworm stable" "$docker_source" \
   && [[ "$(stat -c '%a' "$docker_source" 2>/dev/null || echo "")" == "644" ]] \
   && ! find "$(dirname "$docker_source")" -maxdepth 1 -name '.tmp.server-manage.*' -print -quit | grep -q .; then
    pass "Docker apt source 通过 write_file_atomic 落地为 0644"
else
    fail "Docker apt source 原子写入或权限异常"
    ls -la "$(dirname "$docker_source")" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$docker_source" 2>/dev/null || true
fi
if ( DOCKER_SOURCE_LIST_FILE="relative/docker.list"; _docker_write_apt_source "$DOCKER_SOURCE_LIST_FILE" amd64 "$docker_keyring" debian bookworm >/dev/null 2>&1 ); then
    fail "Docker apt source helper 接受了非绝对 docker.list 路径"
else
    pass "Docker apt source helper 拒绝非绝对 docker.list 路径"
fi
if _docker_compose_install_standalone "https://github.com/docker/compose/releases/download/v9.9.9/docker-compose-linux-x86_64" \
   && cmp -s "$docker_compose_bin" "$docker_compose_payload" \
   && [[ "$(stat -c '%a' "$docker_compose_bin" 2>/dev/null || echo "")" == "755" ]] \
   && ! find "$(dirname "$docker_compose_bin")" -maxdepth 1 -name '.tmp.server-manage.docker-compose*' -print -quit | grep -q .; then
    pass "Docker Compose standalone 校验 sha256 后同目录原子安装"
else
    fail "Docker Compose standalone 原子安装或校验异常"
    ls -la "$(dirname "$docker_compose_bin")" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$docker_curl_log" 2>/dev/null || true
fi
if ( DOCKER_COMPOSE_BIN="relative/docker-compose"; _docker_compose_install_standalone "https://github.com/docker/compose/releases/download/v9.9.9/docker-compose-linux-x86_64" >/dev/null 2>&1 ); then
    fail "Docker Compose standalone helper 接受了非绝对目标路径"
else
    pass "Docker Compose standalone helper 拒绝非绝对目标路径"
fi
docker_install_fail_log="$tmp_root/docker-install-fail.log"
if (
    pause() { :; }
    update_apt_cache() { printf 'update-cache\n' >> "$docker_install_fail_log"; }
    install_package() { printf 'install-package|%s|%s\n' "$1" "${2:-}" >> "$docker_install_fail_log"; return 0; }
    command_exists() { [[ "${1:-}" == "docker" ]] && return 1; command -v "$1" >/dev/null 2>&1; }
    dpkg() { [[ "${1:-}" == "--print-architecture" ]] && { printf 'amd64\n'; return 0; }; command dpkg "$@"; }
    apt-get() {
        printf 'apt-get|%s\n' "$*" >> "$docker_install_fail_log"
        [[ "${1:-}" == "install" ]] && return 77
        return 0
    }
    is_systemd() { return 0; }
    systemctl() { printf 'systemctl-should-not-run|%s\n' "$*" >> "$docker_install_fail_log"; return 0; }
    docker() { printf 'docker-should-not-run|%s\n' "$*" >> "$docker_install_fail_log"; return 0; }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_install_fail_log"; }
    docker_install
) > "$tmp_root/docker-install-apt-fail.out" 2>&1; then
    fail "Docker 安装 apt install 失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/docker-install-apt-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_install_fail_log" 2>/dev/null || true
elif grep -Fxq 'apt-get|install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' "$docker_install_fail_log" \
     && ! grep -q 'systemctl-should-not-run\|docker-should-not-run\|log-action' "$docker_install_fail_log"; then
    pass "Docker 安装 apt install 失败时返回非 0 且不继续启动/记成功日志"
else
    fail "Docker 安装 apt install 失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-install-apt-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_install_fail_log" 2>/dev/null || true
fi
: > "$docker_install_fail_log"
if (
    pause() { :; }
    update_apt_cache() { printf 'update-cache\n' >> "$docker_install_fail_log"; }
    install_package() { printf 'install-package|%s|%s\n' "$1" "${2:-}" >> "$docker_install_fail_log"; return 0; }
    command_exists() { [[ "${1:-}" == "docker" ]] && return 1; command -v "$1" >/dev/null 2>&1; }
    dpkg() { [[ "${1:-}" == "--print-architecture" ]] && { printf 'amd64\n'; return 0; }; command dpkg "$@"; }
    apt-get() {
        printf 'apt-get|%s\n' "$*" >> "$docker_install_fail_log"
        return 0
    }
    is_systemd() { return 0; }
    systemctl() {
        printf 'systemctl|%s\n' "$*" >> "$docker_install_fail_log"
        [[ "${1:-}" == "start" && "${2:-}" == "docker" ]] && return 31
        return 0
    }
    docker() { printf 'docker-should-not-run|%s\n' "$*" >> "$docker_install_fail_log"; return 0; }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_install_fail_log"; }
    docker_install
) > "$tmp_root/docker-install-start-fail.out" 2>&1; then
    fail "Docker 安装后 systemd start 失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/docker-install-start-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_install_fail_log" 2>/dev/null || true
elif grep -Fxq 'systemctl|enable docker' "$docker_install_fail_log" \
     && grep -Fxq 'systemctl|start docker' "$docker_install_fail_log" \
     && ! grep -q 'docker-should-not-run\|log-action' "$docker_install_fail_log"; then
    pass "Docker 安装后 systemd start 失败时返回非 0 且不输出成功版本/日志"
else
    fail "Docker 安装 systemd start 失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-install-start-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_install_fail_log" 2>/dev/null || true
fi
docker_compose_fail_log="$tmp_root/docker-compose-fail.log"
if (
    pause() { :; }
    update_apt_cache() { printf 'update-cache\n' >> "$docker_compose_fail_log"; }
    command_exists() {
        case "${1:-}" in
            docker) return 0 ;;
            docker-compose|jq) return 1 ;;
            *) command -v "$1" >/dev/null 2>&1 ;;
        esac
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_compose_fail_log"
        [[ "${1:-}" == "compose" && "${2:-}" == "version" ]] && return 1
        return 0
    }
    apt-get() {
        local last_arg="${!#}"
        printf 'apt-get|%s\n' "$*" >> "$docker_compose_fail_log"
        [[ "${1:-}" == "install" && "$last_arg" == "docker-compose-plugin" ]] && return 12
        return 0
    }
    curl() { printf 'curl-fail|%s\n' "$*" >> "$docker_compose_fail_log"; return 8; }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_compose_fail_log"; }
    docker_compose_install
) > "$tmp_root/docker-compose-fail.out" 2>&1; then
    fail "Docker Compose plugin+standalone 均失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/docker-compose-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_compose_fail_log" 2>/dev/null || true
elif grep -Fxq 'apt-get|install -y docker-compose-plugin' "$docker_compose_fail_log" \
     && grep -q 'curl-fail|' "$docker_compose_fail_log" \
     && ! grep -q 'log-action' "$docker_compose_fail_log"; then
    pass "Docker Compose plugin+standalone 均失败时返回非 0 且不写成功日志"
else
    fail "Docker Compose 完全失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-compose-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_compose_fail_log" 2>/dev/null || true
fi
docker_images_fail_log="$tmp_root/docker-images-fail.log"
if (
    pause() { :; }
    confirm() { return 0; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_images_fail_log"
        [[ "${1:-}" == "image" && "${2:-}" == "prune" ]] && return 41
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_images_fail_log"; }
    printf '2\n' | docker_images_manage
) > "$tmp_root/docker-images-prune-fail.out" 2>&1; then
    fail "Docker 镜像 prune 失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/docker-images-prune-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_images_fail_log" 2>/dev/null || true
elif grep -Fxq 'docker|image prune -a -f' "$docker_images_fail_log" \
     && ! grep -q 'log-action' "$docker_images_fail_log" \
     && ! grep -q '清理完成' "$tmp_root/docker-images-prune-fail.out"; then
    pass "Docker 镜像 prune 失败时返回非 0 且不写成功日志"
else
    fail "Docker 镜像 prune 失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-images-prune-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_images_fail_log" 2>/dev/null || true
fi
: > "$docker_images_fail_log"
if (
    pause() { :; }
    confirm() { return 0; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_images_fail_log"
        [[ "${1:-}" == "images" && "${2:-}" == "-q" ]] && { printf 'img-runtime\n'; return 0; }
        [[ "${1:-}" == "rmi" ]] && return 42
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_images_fail_log"; }
    printf '3\n' | docker_images_manage
) > "$tmp_root/docker-images-rmi-fail.out" 2>&1; then
    fail "Docker 镜像 rmi 失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/docker-images-rmi-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_images_fail_log" 2>/dev/null || true
elif grep -Fxq 'docker|images -q' "$docker_images_fail_log" \
     && grep -Fxq 'docker|rmi -f img-runtime' "$docker_images_fail_log" \
     && ! grep -q 'log-action' "$docker_images_fail_log" \
     && ! grep -q '所有镜像已删除' "$tmp_root/docker-images-rmi-fail.out"; then
    pass "Docker 镜像 rmi 失败时返回非 0 且不写成功日志"
else
    fail "Docker 镜像 rmi 失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-images-rmi-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_images_fail_log" 2>/dev/null || true
fi
docker_containers_fail_log="$tmp_root/docker-containers-fail.log"
if (
    pause() { :; }
    confirm() { return 0; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_containers_fail_log"
        case "$*" in
            "ps -a --format "*)
                printf 'cid-runtime\tweb\tnginx:latest\tUp 1 minute\t80/tcp\n'
                ;;
            "ps -q"|"ps -aq")
                printf 'cid-runtime\n'
                ;;
            "stats "*)
                printf 'web\t0.1%%\t10MiB / 512MiB\n'
                ;;
            "stop cid-runtime")
                return 51
                ;;
        esac
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_containers_fail_log"; }
    printf '6\n0\n' | docker_containers_manage
) > "$tmp_root/docker-containers-stop-fail.out" 2>&1 \
   && grep -Fxq 'docker|stop cid-runtime' "$docker_containers_fail_log" \
   && ! grep -q 'log-action|Docker all containers stopped' "$docker_containers_fail_log" \
   && ! grep -q '已停止' "$tmp_root/docker-containers-stop-fail.out"; then
    pass "Docker 批量停止失败时不写成功日志"
else
    fail "Docker 批量停止失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-containers-stop-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_containers_fail_log" 2>/dev/null || true
fi
: > "$docker_containers_fail_log"
if (
    pause() { :; }
    confirm() { return 0; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_containers_fail_log"
        case "$*" in
            "ps -a --format "*)
                printf 'cid-runtime\tweb\tnginx:latest\tExited\t80/tcp\n'
                ;;
            "ps -q")
                return 0
                ;;
            "ps -aq")
                printf 'cid-runtime\n'
                ;;
            "rm -f cid-runtime")
                return 52
                ;;
        esac
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_containers_fail_log"; }
    printf '7\n0\n' | docker_containers_manage
) > "$tmp_root/docker-containers-rm-all-fail.out" 2>&1 \
   && grep -Fxq 'docker|rm -f cid-runtime' "$docker_containers_fail_log" \
   && ! grep -q 'log-action|Docker all containers removed' "$docker_containers_fail_log" \
   && ! grep -q '已删除' "$tmp_root/docker-containers-rm-all-fail.out"; then
    pass "Docker 批量删除容器失败时不写成功日志"
else
    fail "Docker 批量删除容器失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-containers-rm-all-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_containers_fail_log" 2>/dev/null || true
fi
: > "$docker_containers_fail_log"
if (
    pause() { :; }
    confirm() { return 0; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_containers_fail_log"
        case "$*" in
            "ps -a --format "*)
                printf 'cid-runtime\tweb\tnginx:latest\tExited\t80/tcp\n'
                ;;
            "ps -q")
                return 0
                ;;
            "rm -f cid-runtime")
                return 53
                ;;
        esac
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_containers_fail_log"; }
    printf '5 1\n0\n' | docker_containers_manage
) > "$tmp_root/docker-container-rm-one-fail.out" 2>&1 \
   && grep -Fxq 'docker|rm -f cid-runtime' "$docker_containers_fail_log" \
   && ! grep -q 'log-action|Docker container removed' "$docker_containers_fail_log" \
   && ! grep -q '已删除: web' "$tmp_root/docker-container-rm-one-fail.out"; then
    pass "Docker 单容器删除失败时不写成功日志"
else
    fail "Docker 单容器删除失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-container-rm-one-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_containers_fail_log" 2>/dev/null || true
fi
docker_prune_fail_log="$tmp_root/docker-prune-fail.log"
if (
    pause() { :; }
    confirm() { return 0; }
    fix_terminal() { :; }
    command_exists() {
        [[ "${1:-}" == "docker" ]] && return 0
        command -v "$1" >/dev/null 2>&1
    }
    docker() {
        printf 'docker|%s\n' "$*" >> "$docker_prune_fail_log"
        case "$*" in
            "--version")
                printf 'Docker version 99.0.0\n'
                ;;
            "compose version")
                printf 'Docker Compose version v99.0.0\n'
                ;;
            "system prune -a -f --volumes")
                return 54
                ;;
        esac
        return 0
    }
    log_action() { printf 'log-action|%s\n' "$1" >> "$docker_prune_fail_log"; }
    printf '7\n0\n' | menu_docker
) > "$tmp_root/docker-prune-fail.out" 2>&1 \
   && grep -Fxq 'docker|system prune -a -f --volumes' "$docker_prune_fail_log" \
   && ! grep -q 'log-action|Docker system pruned' "$docker_prune_fail_log" \
   && ! grep -q '清理完成' "$tmp_root/docker-prune-fail.out"; then
    pass "Docker system prune 失败时不写成功日志"
else
    fail "Docker system prune 失败路径异常"
    sed 's/^/    /' "$tmp_root/docker-prune-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$docker_prune_fail_log" 2>/dev/null || true
fi
unset DOCKER_KEYRING_FILE DOCKER_SOURCE_LIST_FILE DOCKER_COMPOSE_BIN
unset -f curl gpg
if [[ "$(id -u)" -eq 0 \
      && "$DOCKER_PROXY_DIR" == "/etc/systemd/system/docker.service.d" \
      && "$DOCKER_PROXY_CONF" == "/etc/systemd/system/docker.service.d/http-proxy.conf" ]]; then
    if [[ "$docker_proxy_touched" -eq 0 && -d "$DOCKER_PROXY_DIR" ]]; then
        docker_proxy_backup="$tmp_root/docker-proxy.backup"
        cp -a "$DOCKER_PROXY_DIR" "$docker_proxy_backup"
    fi
    docker_proxy_touched=1
    rm -rf "$DOCKER_PROXY_DIR"
    docker_proxy_flow_log="$tmp_root/docker-proxy-flow.log"
    if (
        pause() { :; }
        command_exists() {
            [[ "${1:-}" == "docker" || "${1:-}" == "systemctl" ]] && return 0
            command -v "$1" >/dev/null 2>&1
        }
        is_systemd() { return 0; }
        systemctl() {
            printf 'systemctl|%s\n' "$*" >> "$docker_proxy_flow_log"
            return 0
        }
        docker() { return 0; }
        printf '1\nhttp://proxy.example.com:3128\n' | docker_proxy_config
    ) > "$tmp_root/docker-proxy-set.out" 2>&1 \
       && [[ -f "$DOCKER_PROXY_CONF" ]] \
       && grep -Fxq 'Environment="HTTP_PROXY=http://proxy.example.com:3128"' "$DOCKER_PROXY_CONF" \
       && grep -Fxq 'Environment="NO_PROXY=localhost,127.0.0.1,::1"' "$DOCKER_PROXY_CONF" \
       && grep -Fxq 'systemctl|daemon-reload' "$docker_proxy_flow_log" \
       && grep -Fxq 'systemctl|restart docker' "$docker_proxy_flow_log" \
       && ! find "$DOCKER_PROXY_DIR" -maxdepth 1 -name '.tmp.server-manage.*' -print -quit | grep -q .; then
        pass "Docker 代理配置在真实 systemd drop-in 路径原子写入并 reload/restart"
    else
        fail "Docker 代理配置真实路径写入异常"
        sed 's/^/    /' "$tmp_root/docker-proxy-set.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_flow_log" 2>/dev/null || true
        find "$DOCKER_PROXY_DIR" -maxdepth 1 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
    if (
        pause() { :; }
        command_exists() {
            [[ "${1:-}" == "docker" || "${1:-}" == "systemctl" ]] && return 0
            command -v "$1" >/dev/null 2>&1
        }
        is_systemd() { return 0; }
        systemctl() {
            printf 'systemctl|%s\n' "$*" >> "$docker_proxy_flow_log"
            return 0
        }
        docker() { return 0; }
        printf '2\n' | docker_proxy_config
    ) > "$tmp_root/docker-proxy-clear.out" 2>&1 \
       && [[ ! -e "$DOCKER_PROXY_CONF" ]] \
       && grep -Fxq 'systemctl|daemon-reload' "$docker_proxy_flow_log" \
       && grep -Fxq 'systemctl|restart docker' "$docker_proxy_flow_log"; then
        pass "Docker 代理清除在真实 systemd drop-in 路径删除配置并 reload/restart"
    else
        fail "Docker 代理清除真实路径异常"
        sed 's/^/    /' "$tmp_root/docker-proxy-clear.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_flow_log" 2>/dev/null || true
        find "$DOCKER_PROXY_DIR" -maxdepth 1 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
    mkdir -p "$DOCKER_PROXY_DIR"
    printf 'old-proxy-config\n' > "$DOCKER_PROXY_CONF"
    docker_proxy_fail_log="$tmp_root/docker-proxy-fail.log"
    if (
        pause() { :; }
        command_exists() {
            [[ "${1:-}" == "docker" || "${1:-}" == "systemctl" ]] && return 0
            command -v "$1" >/dev/null 2>&1
        }
        is_systemd() { return 0; }
        systemctl() {
            printf 'systemctl|%s\n' "$*" >> "$docker_proxy_fail_log"
            [[ "${1:-}" == "restart" && "${2:-}" == "docker" ]] && return 19
            return 0
        }
        docker() { return 0; }
        printf '1\nhttp://proxy-fail.example.com:3128\n' | docker_proxy_config
    ) > "$tmp_root/docker-proxy-set-fail.out" 2>&1; then
        fail "Docker 代理配置 restart 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/docker-proxy-set-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_fail_log" 2>/dev/null || true
    elif grep -Fxq 'old-proxy-config' "$DOCKER_PROXY_CONF" \
         && ! grep -Fq 'proxy-fail.example.com' "$DOCKER_PROXY_CONF" \
         && grep -Fxq 'systemctl|restart docker' "$docker_proxy_fail_log" \
         && ! find "$DOCKER_PROXY_DIR" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.http-proxy.conf.bak.*' \) -print -quit | grep -q .; then
        pass "Docker 代理配置 restart 失败时返回非 0 并恢复旧 drop-in"
    else
        fail "Docker 代理配置 restart 失败回滚异常"
        sed 's/^/    /' "$tmp_root/docker-proxy-set-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_fail_log" 2>/dev/null || true
        find "$DOCKER_PROXY_DIR" -maxdepth 1 -ls 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$DOCKER_PROXY_CONF" 2>/dev/null || true
    fi
    printf 'old-proxy-config\n' > "$DOCKER_PROXY_CONF"
    : > "$docker_proxy_fail_log"
    if (
        pause() { :; }
        command_exists() {
            [[ "${1:-}" == "docker" || "${1:-}" == "systemctl" ]] && return 0
            command -v "$1" >/dev/null 2>&1
        }
        is_systemd() { return 0; }
        systemctl() {
            printf 'systemctl|%s\n' "$*" >> "$docker_proxy_fail_log"
            [[ "${1:-}" == "restart" && "${2:-}" == "docker" ]] && return 23
            return 0
        }
        docker() { return 0; }
        printf '2\n' | docker_proxy_config
    ) > "$tmp_root/docker-proxy-clear-fail.out" 2>&1; then
        fail "Docker 代理清除 restart 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/docker-proxy-clear-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_fail_log" 2>/dev/null || true
    elif grep -Fxq 'old-proxy-config' "$DOCKER_PROXY_CONF" \
         && grep -Fxq 'systemctl|restart docker' "$docker_proxy_fail_log" \
         && ! find "$DOCKER_PROXY_DIR" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.http-proxy.conf.bak.*' \) -print -quit | grep -q .; then
        pass "Docker 代理清除 restart 失败时返回非 0 并恢复旧 drop-in"
    else
        fail "Docker 代理清除 restart 失败回滚异常"
        sed 's/^/    /' "$tmp_root/docker-proxy-clear-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_proxy_fail_log" 2>/dev/null || true
        find "$DOCKER_PROXY_DIR" -maxdepth 1 -ls 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$DOCKER_PROXY_CONF" 2>/dev/null || true
    fi
    if [[ "$docker_etc_touched" -eq 0 && -d /etc/docker ]]; then
        docker_etc_backup="$tmp_root/docker-etc.backup"
        cp -a /etc/docker "$docker_etc_backup"
    fi
    docker_etc_touched=1
    if [[ "$docker_apt_source_touched" -eq 0 && -f /etc/apt/sources.list.d/docker.list ]]; then
        docker_apt_source_backup="$tmp_root/docker-source.backup"
        cp -a /etc/apt/sources.list.d/docker.list "$docker_apt_source_backup"
    fi
    docker_apt_source_touched=1
    if [[ "$docker_keyring_touched" -eq 0 && -f /etc/apt/keyrings/docker.gpg ]]; then
        docker_keyring_backup="$tmp_root/docker-keyring.backup"
        cp -a /etc/apt/keyrings/docker.gpg "$docker_keyring_backup"
    fi
    docker_keyring_touched=1
    mkdir -p /etc/docker "$DOCKER_PROXY_DIR"
    printf 'runtime-daemon\n' > /etc/docker/daemon.json
    printf 'runtime-proxy\n' > "$DOCKER_PROXY_CONF"
    mkdir -p /etc/apt/sources.list.d /etc/apt/keyrings
    printf 'runtime docker source\n' > /etc/apt/sources.list.d/docker.list
    printf 'runtime docker keyring\n' > /etc/apt/keyrings/docker.gpg
    docker_uninstall_log="$tmp_root/docker-uninstall.log"
    if (
        pause() { :; }
        confirm() {
            printf 'confirm|%s\n' "$1" >> "$docker_uninstall_log"
            if [[ "$1" == *"/var/lib/docker"* ]]; then
                printf 'confirm-data-delete|no\n' >> "$docker_uninstall_log"
                return 1
            fi
            return 0
        }
        command_exists() {
            [[ "${1:-}" == "docker" ]] && return 0
            command -v "$1" >/dev/null 2>&1
        }
        is_systemd() { return 0; }
        systemctl() {
            printf 'systemctl|%s\n' "$*" >> "$docker_uninstall_log"
            return 0
        }
        apt-get() {
            printf 'apt-get|%s\n' "$*" >> "$docker_uninstall_log"
            return 0
        }
        docker() {
            printf 'docker|%s\n' "$*" >> "$docker_uninstall_log"
            return 0
        }
        docker_uninstall
    ) > "$tmp_root/docker-uninstall.out" 2>&1 \
       && [[ ! -e "$DOCKER_PROXY_CONF" ]] \
       && [[ ! -e "$DOCKER_PROXY_DIR" ]] \
       && [[ ! -e /etc/docker ]] \
       && [[ ! -e /etc/apt/sources.list.d/docker.list ]] \
       && [[ ! -e /etc/apt/keyrings/docker.gpg ]] \
       && grep -Fxq 'systemctl|stop docker docker.socket containerd' "$docker_uninstall_log" \
       && grep -Fxq 'systemctl|disable docker docker.socket containerd' "$docker_uninstall_log" \
       && grep -Fxq 'apt-get|purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin' "$docker_uninstall_log" \
       && grep -Fxq 'apt-get|autoremove -y' "$docker_uninstall_log" \
       && grep -Fxq 'confirm-data-delete|no' "$docker_uninstall_log"; then
        pass "Docker 卸载流程在真实路径清理 drop-in、/etc/docker 和 apt 残留且调用 stop/purge"
    else
        fail "Docker 卸载流程真实路径清理异常"
        sed 's/^/    /' "$tmp_root/docker-uninstall.out" 2>/dev/null || true
        sed 's/^/    /' "$docker_uninstall_log" 2>/dev/null || true
        ls -ld "$DOCKER_PROXY_DIR" /etc/docker /etc/apt/sources.list.d/docker.list /etc/apt/keyrings/docker.gpg 2>/dev/null | sed 's/^/    /' || true
    fi
else
    skip "非 root 或 Docker 系统路径非预期，跳过 Docker 真实 drop-in 测试"
fi

REALITY_SAGERNET_KEYRING_FILE="$sagernet_keyring"
REALITY_SAGERNET_SOURCE_FILE="$sagernet_source"
if _reality_write_sagernet_source \
   && grep -Fxq 'URIs: https://deb.sagernet.org/' "$sagernet_source" \
   && grep -Fxq "Signed-By: $sagernet_keyring" "$sagernet_source" \
   && [[ "$(stat -c '%a' "$sagernet_source" 2>/dev/null || echo "")" == "644" ]]; then
    pass "SagerNet apt source 候选通过原子写入并为 0644"
else
    fail "SagerNet apt source 候选渲染或权限异常"
    sed 's/^/    /' "$sagernet_source" 2>/dev/null || true
fi
if ( REALITY_SAGERNET_KEYRING_FILE="relative/sagernet.asc"; _reality_write_sagernet_source >/dev/null 2>&1 ); then
    fail "SagerNet apt source 接受了非绝对 keyring 路径"
else
    pass "SagerNet apt source 拒绝非绝对 keyring 路径"
fi
unset REALITY_SAGERNET_KEYRING_FILE REALITY_SAGERNET_SOURCE_FILE
mkdir -p "$(dirname "$realm_bin")" "$(dirname "$realm_config")"
printf '#!/usr/bin/env bash\nexit 0\n' > "$realm_bin"
chmod 755 "$realm_bin"
printf 'log.level = "warn"\n' > "$realm_config"
REALITY_REALM_SERVICE_FILE="$realm_unit"
REALITY_REALM_BIN="$realm_bin"
old_reality_realm_config="${REALITY_REALM_CONFIG:-}"
REALITY_REALM_CONFIG="$realm_config"
realm_src="$tmp_root/realm-src"
printf '#!/bin/sh\necho realm mock\n' > "$realm_src"
chmod 0644 "$realm_src"
if _reality_install_realm_binary_file "$realm_src" \
   && cmp -s "$realm_bin" "$realm_src" \
   && [[ "$(stat -c '%a' "$realm_bin" 2>/dev/null || echo "")" == "755" ]] \
   && ! find "$(dirname "$realm_bin")" -maxdepth 1 -name '.tmp.server-manage.realm.*' -print -quit | grep -q .; then
    pass "Realm 二进制通过同目录候选文件原子安装为 0755"
else
    fail "Realm 二进制原子安装或权限/清理异常"
    ls -la "$(dirname "$realm_bin")" 2>/dev/null | sed 's/^/    /' || true
fi
if ( REALITY_REALM_BIN="relative/realm"; _reality_install_realm_binary_file "$realm_src" >/dev/null 2>&1 ); then
    fail "Realm 二进制安装 helper 接受了非绝对目标路径"
else
    pass "Realm 二进制安装 helper 拒绝非绝对目标路径"
fi
realm_download_tmp="$tmp_root/realm-download-tmp"
realm_download_target="$tmp_root/realm-download-install/realm"
realm_mock_bin="$tmp_root/realm-mock-bin"
mkdir -p "$realm_download_tmp" "$(dirname "$realm_download_target")" "$realm_mock_bin"
cat > "$realm_mock_bin/curl" <<'EOF'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$out" ]] || exit 2
printf 'mock realm archive\n' > "$out"
mode=$(stat -c '%a' "$(dirname "$out")" 2>/dev/null || echo "")
printf '%s\n' "$mode" > "${REALM_TMP_MODE_LOG:?}"
case "$(dirname "$out")" in
    "${TMPDIR:?}"/server-manage-realm.*) ;;
    *) exit 3 ;;
esac
EOF
cat > "$realm_mock_bin/sha256sum" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "-c" ]]; then
    cat >/dev/null
    exit 0
fi
printf 'mock-sha256  -\n'
EOF
cat > "$realm_mock_bin/tar" <<'EOF'
#!/usr/bin/env bash
dest=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -C) dest="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$dest" ]] || exit 2
printf '#!/bin/sh\nexit 0\n' > "$dest/realm"
chmod +x "$dest/realm"
EOF
chmod +x "$realm_mock_bin/curl" "$realm_mock_bin/sha256sum" "$realm_mock_bin/tar"
old_path_realm="$PATH"
old_tmpdir_realm="${TMPDIR-__unset__}"
old_command_exists_def="$(declare -f command_exists)"
PATH="$realm_mock_bin:$PATH"
REALITY_REALM_BIN="$realm_download_target"
TMPDIR="$realm_download_tmp"
REALM_TMP_MODE_LOG="$tmp_root/realm-download-mode.log"
export TMPDIR REALM_TMP_MODE_LOG
command_exists() {
    [[ "$1" == "realm" ]] && return 1
    command -v "$1" >/dev/null 2>&1
}
if reality_install_realm_binary \
   && [[ -x "$realm_download_target" ]] \
   && [[ "$(stat -c '%a' "$realm_download_target" 2>/dev/null || echo "")" == "755" ]] \
   && grep -Fxq '700' "$REALM_TMP_MODE_LOG" \
   && ! find "$realm_download_tmp" -maxdepth 1 -name 'server-manage-realm.*' -print -quit | grep -q .; then
    pass "Realm 下载/校验/解包链路使用 0700 临时目录并清理"
else
    fail "Realm 下载/校验/解包链路临时目录或安装结果异常"
    ls -la "$realm_download_tmp" "$(dirname "$realm_download_target")" 2>/dev/null | sed 's/^/    /' || true
    [[ -f "$REALM_TMP_MODE_LOG" ]] && sed 's/^/    mode: /' "$REALM_TMP_MODE_LOG"
fi
PATH="$old_path_realm"
eval "$old_command_exists_def"
if [[ "$old_tmpdir_realm" == "__unset__" ]]; then unset TMPDIR; else TMPDIR="$old_tmpdir_realm"; fi
REALITY_REALM_BIN="$realm_bin"
unset REALM_TMP_MODE_LOG
if _reality_install_realm_service_unit \
   && grep -Fxq "ExecStart=$realm_bin -c $realm_config" "$realm_unit" \
   && [[ "$(stat -c '%a' "$realm_unit" 2>/dev/null || echo "")" == "644" ]]; then
    if command_exists systemd-analyze; then
        if systemd-analyze verify "$realm_unit" >/dev/null 2>&1; then
            pass "systemd 接受 Realm service unit 候选"
        else
            fail "systemd 拒绝 Realm service unit 候选"
            systemd-analyze verify "$realm_unit" 2>&1 | sed 's/^/    /' || true
        fi
    else
        pass "Realm service unit 候选包含正确 ExecStart 且为 0644"
    fi
else
    fail "Realm service unit 候选渲染或权限异常"
    sed 's/^/    /' "$realm_unit" 2>/dev/null || true
fi
if ( REALITY_REALM_SERVICE_FILE="relative-realm.service"; _reality_install_realm_service_unit >/dev/null 2>&1 ); then
    fail "Realm service unit 接受了非绝对 unit 路径"
else
    pass "Realm service unit 拒绝非绝对 unit 路径"
fi
unset REALITY_REALM_SERVICE_FILE REALITY_REALM_BIN
REALITY_REALM_CONFIG="$old_reality_realm_config"

runtime_nginx_conf="$tmp_root/runtime-nginx.conf"
runtime_stream_dir="$tmp_root/runtime-stream-enabled"
cat > "$runtime_nginx_conf" <<'EOF'
user www-data;
events { worker_connections 768; }
http {
    include /etc/nginx/sites-enabled/*.conf;
}
EOF
chmod 640 "$runtime_nginx_conf"
old_reality_stream_dir="$REALITY_STREAM_ENABLED_DIR"
REALITY_STREAM_ENABLED_DIR="$runtime_stream_dir"
reality_backup_file() { :; }
if reality_coexist_inject_nginx_include "$runtime_nginx_conf" \
   && grep -q 'reality-coexist-stream-include' "$runtime_nginx_conf" \
   && grep -q "include ${runtime_stream_dir}/\\*.conf;" "$runtime_nginx_conf" \
   && [[ "$(grep -c 'reality-coexist-stream-include' "$runtime_nginx_conf")" -eq 1 ]] \
   && [[ "$(stat -c '%a' "$runtime_nginx_conf" 2>/dev/null)" == "640" ]] \
   && ! find "$(dirname "$runtime_nginx_conf")" -maxdepth 1 -name '.tmp.server-manage.nginx-stream-include.*' -print -quit | grep -q .; then
    pass "Reality nginx stream include 在真实文件系统上同目录候选原子注入并清理"
else
    fail "Reality nginx stream include 原子注入或权限/清理异常"
    ls -la "$(dirname "$runtime_nginx_conf")" 2>/dev/null | sed 's/^/    /' || true
    sed 's/^/    /' "$runtime_nginx_conf" 2>/dev/null || true
fi
REALITY_STREAM_ENABLED_DIR="$old_reality_stream_dir"
unset -f reality_backup_file

echo ""
echo "== UFW inactive firewall wrapper =="
if command_exists ufw; then
    if ufw_is_active; then
        skip "UFW 已启用，避免修改真实防火墙规则"
    else
        ufw_before_status="$(LANG=C ufw status 2>&1 || true)"
        ufw_before_added="$(LANG=C ufw show added 2>&1 || true)"
        ufw_output="$(
            {
                log_action() { :; }
                firewall_allow_tcp_port 65001 "Runtime-Noop"
                tcp_rc=$?
                firewall_allow_udp_port 65002 "Runtime-Noop-UDP"
                udp_rc=$?
                printf 'tcp_rc=%s udp_rc=%s\n' "$tcp_rc" "$udp_rc"
            } 2>&1
        )"
        ufw_tcp_rc="$(printf '%s\n' "$ufw_output" | sed -nE 's/.*tcp_rc=([0-9]+).*/\1/p' | tail -1)"
        ufw_udp_rc="$(printf '%s\n' "$ufw_output" | sed -nE 's/.*udp_rc=([0-9]+).*/\1/p' | tail -1)"
        ufw_after_status="$(LANG=C ufw status 2>&1 || true)"
        ufw_after_added="$(LANG=C ufw show added 2>&1 || true)"
        if [[ "$ufw_tcp_rc" -eq 2 && "$ufw_udp_rc" -eq 2 ]]; then
            pass "firewall_allow_tcp_port/udp_port 在 UFW inactive 时返回非破坏性状态 2"
        else
            fail "firewall_allow_tcp_port/udp_port 在 UFW inactive 时返回码异常: tcp=${ufw_tcp_rc:-空} udp=${ufw_udp_rc:-空}"
            printf '%s\n' "$ufw_output" | sed 's/^/    /'
        fi
        if [[ "$ufw_before_status" == "$ufw_after_status" \
              && "$ufw_before_added" == "$ufw_after_added" \
              && "$ufw_after_added" != *"65001"* \
              && "$ufw_after_added" != *"65002"* ]]; then
            pass "firewall_allow_tcp_port/udp_port 未在 UFW inactive 时追加规则"
        else
            fail "firewall_allow_tcp_port/udp_port 修改了 inactive UFW 状态或规则"
            diff -u <(printf '%s\n' "$ufw_before_status") <(printf '%s\n' "$ufw_after_status") 2>/dev/null | sed 's/^/    /' || true
            diff -u <(printf '%s\n' "$ufw_before_added") <(printf '%s\n' "$ufw_after_added") 2>/dev/null | sed 's/^/    /' || true
        fi
    fi
else
    skip "ufw 不存在，跳过 UFW inactive 实机项"
fi

echo ""
echo "== Reality port probing =="
occupied_port=""
if command_exists ss; then
    occupied_port="$(ss -H -ltn 2>/dev/null | awk '{print $4}' | sed -nE 's/.*:([0-9]+)$/\1/p' | head -n1)"
elif command_exists netstat; then
    occupied_port="$(netstat -ltn 2>/dev/null | awk 'NR>2 {print $4}' | sed -nE 's/.*:([0-9]+)$/\1/p' | head -n1)"
fi
free_port=""
for p in 65000 65001 65002 65003 65004; do
    if validate_port "$p" && ! reality_port_in_use "$p"; then
        free_port="$p"
        break
    fi
done
if [[ -n "$occupied_port" ]] && validate_port "$occupied_port"; then
    if reality_port_in_use "$occupied_port"; then
        pass "reality_port_in_use 命中真实监听端口: $occupied_port"
    else
        fail "reality_port_in_use 未命中真实监听端口: $occupied_port"
    fi
    if reality_wait_port_free "$occupied_port" 1; then
        fail "reality_wait_port_free 对占用端口错误返回成功: $occupied_port"
    else
        pass "reality_wait_port_free 对占用端口有界失败"
    fi
else
    skip "未发现真实 TCP 监听端口，跳过 Reality 占用端口探测"
fi
if [[ -n "$free_port" ]]; then
    if reality_port_in_use "$free_port"; then
        fail "reality_port_in_use 将空闲端口误判为占用: $free_port"
    else
        pass "reality_port_in_use 正确识别空闲端口: $free_port"
    fi
    if reality_wait_port_free "$free_port" 1; then
        pass "reality_wait_port_free 对空闲端口立即成功"
    else
        fail "reality_wait_port_free 对空闲端口返回失败: $free_port"
    fi
else
    skip "未找到空闲高位端口，跳过 Reality 空闲端口探测"
fi
old_reality_port_set=0
old_reality_port=""
if [[ ${REALITY_PORT+x} ]]; then
    old_reality_port_set=1
    old_reality_port="$REALITY_PORT"
fi
REALITY_PORT=65005
if reality_port_reserved 65005; then
    pass "reality_port_reserved 识别当前落地端口保留"
else
    fail "reality_port_reserved 未识别当前落地端口保留"
fi
if reality_port_reserved 65005 65005; then
    fail "reality_port_reserved 未排除当前端口"
else
    pass "reality_port_reserved 支持排除当前端口"
fi
if [[ "$old_reality_port_set" -eq 1 ]]; then
    REALITY_PORT="$old_reality_port"
else
    unset REALITY_PORT
fi

echo ""
echo "== Reality SNI verification log safety =="
sni_mock_dir="$tmp_root/sni-mock-bin"
sni_tmp_dir="$tmp_root/sni-tmp"
sni_mode_log="$tmp_root/sni-mode.log"
mkdir -p "$sni_mock_dir" "$sni_tmp_dir"
cat > "$sni_mock_dir/openssl" <<'EOF'
#!/usr/bin/env bash
printf 'mock openssl s_client\n'
printf 'args:'
for arg in "$@"; do
    printf ' <%s>' "$arg"
done
printf '\n'
exit "${SNI_OPENSSL_RC:-0}"
EOF
chmod +x "$sni_mock_dir/openssl"
old_path_sni="$PATH"
old_tmpdir_sni="${TMPDIR-__unset__}"
PATH="$sni_mock_dir:$PATH"
TMPDIR="$sni_tmp_dir"
export TMPDIR
SNI_OPENSSL_RC=0
export SNI_OPENSSL_RC
if reality_verify_sni "example.com"; then
    sni_log="$REALITY_SNI_CHECK_LOG"
    sni_dir="$REALITY_SNI_CHECK_DIR"
    sni_dir_mode="$(stat -c '%a' "$sni_dir" 2>/dev/null || echo "")"
    sni_log_mode="$(stat -c '%a' "$sni_log" 2>/dev/null || echo "")"
    if [[ "$sni_dir" == "$sni_tmp_dir"/reality-sni-check.* ]] \
       && [[ "$sni_dir_mode" == "700" ]] \
       && [[ "$sni_log_mode" == "600" ]] \
       && grep -Fq '<-verify_return_error>' "$sni_log"; then
        pass "reality_verify_sni 使用 0700 私有目录记录 openssl 校验日志"
    else
        fail "reality_verify_sni 日志目录/权限/参数异常"
        ls -la "$sni_tmp_dir" "$sni_dir" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$sni_log" 2>/dev/null || true
    fi
    reality_cleanup_sni_check_log
    if [[ -z "${REALITY_SNI_CHECK_LOG:-}" && -z "${REALITY_SNI_CHECK_DIR:-}" ]] \
       && ! find "$sni_tmp_dir" -maxdepth 1 -name 'reality-sni-check.*' -print -quit | grep -q .; then
        pass "reality_cleanup_sni_check_log 清理私有 SNI 日志目录"
    else
        fail "reality_cleanup_sni_check_log 未清理 SNI 日志目录"
        ls -la "$sni_tmp_dir" 2>/dev/null | sed 's/^/    /' || true
    fi
else
    fail "reality_verify_sni mock 成功路径返回失败"
fi
SNI_OPENSSL_RC=42
if reality_verify_sni "example.org"; then
    fail "reality_verify_sni mock 失败路径返回成功"
else
    sni_log="${REALITY_SNI_CHECK_LOG:-}"
    if [[ -f "$sni_log" ]] && grep -Fq 'mock openssl s_client' "$sni_log"; then
        pass "reality_verify_sni 失败路径保留私有日志供诊断读取"
    else
        fail "reality_verify_sni 失败路径未保留可读诊断日志"
        ls -la "${REALITY_SNI_CHECK_DIR:-$sni_tmp_dir}" 2>/dev/null | sed 's/^/    /' || true
    fi
    reality_cleanup_sni_check_log
fi
PATH="$old_path_sni"
if [[ "$old_tmpdir_sni" == "__unset__" ]]; then unset TMPDIR; else TMPDIR="$old_tmpdir_sni"; fi
unset SNI_OPENSSL_RC

echo ""
echo "== Network diagnostics input safety =="
net_mock_dir="$tmp_root/net-mock-bin"
net_mock_log="$tmp_root/net-mock.log"
mkdir -p "$net_mock_dir"
cat > "$net_mock_dir/nc" <<'EOF'
#!/usr/bin/env bash
printf 'nc' > "$NET_MOCK_LOG"
for arg in "$@"; do
    printf '\n<%s>' "$arg" >> "$NET_MOCK_LOG"
done
printf '\n' >> "$NET_MOCK_LOG"
exit 0
EOF
cat > "$net_mock_dir/ping" <<'EOF'
#!/usr/bin/env bash
printf 'ping invoked\n' >> "$NET_MOCK_LOG"
exit 0
EOF
chmod +x "$net_mock_dir/nc" "$net_mock_dir/ping"
PATH="$net_mock_dir:$old_path"
export NET_MOCK_LOG="$net_mock_log"
rm -f "$net_mock_log" "$netdiag_pwned"
if printf '3\nbad;touch %s\n' "$netdiag_pwned" | net_diag >/dev/null 2>&1; then :; fi
if [[ ! -e "$net_mock_log" && ! -e "$netdiag_pwned" ]]; then
    pass "net_diag 拒绝非法 host 且未调用网络命令"
else
    fail "net_diag 非法 host 仍调用了网络命令"
    sed 's/^/    /' "$net_mock_log" 2>/dev/null || true
fi
rm -f "$net_mock_log"
if printf '3\nexample.com\n70000\n' | net_diag >/dev/null 2>&1; then :; fi
if [[ ! -e "$net_mock_log" ]]; then
    pass "net_diag 拒绝非法端口且未调用 nc"
else
    fail "net_diag 非法端口仍调用了 nc"
    sed 's/^/    /' "$net_mock_log" 2>/dev/null || true
fi
rm -f "$net_mock_log"
if printf '3\nexample.com\n443\n' | net_diag >/dev/null 2>&1 \
   && grep -Fxq '<example.com>' "$net_mock_log" \
   && grep -Fxq '<443>' "$net_mock_log"; then
    pass "net_diag 对合法 host/port 使用独立参数调用 nc"
else
    fail "net_diag 合法端口诊断未按预期调用 nc"
    sed 's/^/    /' "$net_mock_log" 2>/dev/null || true
fi
PATH="$old_path"

echo ""
echo "== iPerf3 runtime failure handling =="
iperf_mock_dir="$tmp_root/iperf-mock-bin"
iperf_mock_log="$tmp_root/iperf-mock.log"
mkdir -p "$iperf_mock_dir"
cat > "$iperf_mock_dir/iperf3" <<'EOF'
#!/usr/bin/env bash
printf 'iperf3|%s\n' "$*" >> "$IPERF_MOCK_LOG"
exit 33
EOF
chmod +x "$iperf_mock_dir/iperf3"
old_path_iperf="$PATH"
PATH="$iperf_mock_dir:$old_path"
export IPERF_MOCK_LOG="$iperf_mock_log"
if (
    pause() { :; }
    install_package() { printf 'install-package|%s\n' "$1" >> "$IPERF_MOCK_LOG"; return 0; }
    ufw_is_active() { return 0; }
    ufw() {
        printf 'ufw|%s\n' "$*" >> "$IPERF_MOCK_LOG"
        case "$*" in
            "status")
                return 0
                ;;
            "allow 5201/tcp comment iPerf3-Temp")
                return 0
                ;;
            "delete allow 5201/tcp")
                return 0
                ;;
        esac
        return 0
    }
    get_public_ipv4() { printf '198.51.100.10\n'; }
    get_public_ipv6() { return 1; }
    log_action() { printf 'log-action|%s\n' "$1" >> "$IPERF_MOCK_LOG"; }
    printf '\n' | net_iperf3
) > "$tmp_root/iperf-fail.out" 2>&1; then
    fail "iPerf3 服务启动失败时仍返回成功"
    sed 's/^/    /' "$tmp_root/iperf-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$iperf_mock_log" 2>/dev/null || true
elif grep -Fxq 'install-package|iperf3' "$iperf_mock_log" \
     && grep -Fxq 'iperf3|-s -p 5201' "$iperf_mock_log" \
     && grep -Fxq 'ufw|delete allow 5201/tcp' "$iperf_mock_log" \
     && ! grep -q 'log-action|iPerf3 test completed' "$iperf_mock_log" \
     && ! grep -q '客户端测速命令' "$tmp_root/iperf-fail.out"; then
    pass "iPerf3 服务启动失败时返回非 0、清理临时 UFW 且不写完成日志"
else
    fail "iPerf3 服务启动失败清理/日志路径异常"
    sed 's/^/    /' "$tmp_root/iperf-fail.out" 2>/dev/null || true
    sed 's/^/    /' "$iperf_mock_log" 2>/dev/null || true
fi
PATH="$old_path_iperf"
unset IPERF_MOCK_LOG

echo ""
echo "== Email deploy environment script =="
email_env_body=$(declare -f _email_deploy_check_env)
if grep -q 'mktemp -d "\${TMPDIR:-/tmp}/server-manage-email-node.XXXXXX"' <<< "$email_env_body" \
   && grep -q 'chmod 700 "\$tmp_dir"' <<< "$email_env_body" \
   && grep -q 'chmod 600 "\$tmp"' <<< "$email_env_body" \
   && grep -q 'rm -rf "\$tmp_dir"' <<< "$email_env_body" \
   && ! grep -q 'tmp=$(mktemp)' <<< "$email_env_body"; then
    pass "Email NodeSource 安装脚本使用私有临时目录"
else
    fail "Email NodeSource 安装脚本仍可能落公共临时文件"
fi

echo ""
echo "== Email state/runtime files =="
if [[ "$(id -u)" -eq 0 \
      && "$EMAIL_STATE_DIR" == "/etc/server-manage/email" \
      && "$EMAIL_LOG_FILE" == "/var/log/server-manage-email.log" \
      && "$EMAIL_ADMIN_FILE" == "/root/.email-admin.txt" \
      && "$EMAIL_INSTALL_DIR" == "/root/cloudflare_temp_email" ]]; then
    if [[ "$email_state_touched" -eq 0 && -d "$EMAIL_STATE_DIR" ]]; then
        email_state_backup="$tmp_root/email-state.backup"
        cp -a "$EMAIL_STATE_DIR" "$email_state_backup"
    fi
    email_state_touched=1
    rm -rf "$EMAIL_STATE_DIR"
    if [[ "$email_module_log_touched" -eq 0 && -f "$EMAIL_LOG_FILE" ]]; then
        email_module_log_backup="$tmp_root/email-log.backup"
        cp -a "$EMAIL_LOG_FILE" "$email_module_log_backup"
    fi
    email_module_log_touched=1
    rm -f "$EMAIL_LOG_FILE"
    if [[ "$email_admin_touched" -eq 0 && -f "$EMAIL_ADMIN_FILE" ]]; then
        email_admin_backup="$tmp_root/email-admin.backup"
        cp -a "$EMAIL_ADMIN_FILE" "$email_admin_backup"
    fi
    email_admin_touched=1
    rm -f "$EMAIL_ADMIN_FILE"
    if [[ "$email_install_touched" -eq 0 && -d "$EMAIL_INSTALL_DIR" ]]; then
        email_install_backup="$tmp_root/email-install.backup"
        cp -a "$EMAIL_INSTALL_DIR" "$email_install_backup"
    fi
    email_install_touched=1
    rm -rf "$EMAIL_INSTALL_DIR"
    mkdir -p "$EMAIL_INSTALL_DIR/worker"

    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=1
    EMAIL_CATCH_ALL_ENABLED=1
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:00:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-123"
    EMAIL_CF_ACCOUNT_ID="account-123"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_ADDRESS_PREFIX="audit"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_PAGES_DOMAIN="runtime-pages.pages.dev"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    EMAIL_RESEND_SEND_DOMAIN="send.example.com"
    EMAIL_PATCHES_APPLIED="001-init.sql 002-runtime.sql"
    if email_state_write \
       && [[ -d "$EMAIL_STATE_DIR" ]] \
       && [[ "$(stat -c '%a' "$EMAIL_STATE_DIR" 2>/dev/null)" == "700" ]] \
       && [[ -f "$EMAIL_STATE_FILE" ]] \
       && [[ "$(stat -c '%a' "$EMAIL_STATE_FILE" 2>/dev/null)" == "600" ]] \
       && [[ "$(stat -c '%U' "$EMAIL_STATE_FILE" 2>/dev/null)" == "root" ]] \
       && validate_conf_file "$EMAIL_STATE_FILE" >/dev/null 2>&1 \
       && ! find "$EMAIL_STATE_DIR" -maxdepth 1 -name '.state.*' -print -quit | grep -q .; then
        pass "Email state 在真实系统路径写入 root:600 配置并清理临时文件"
    else
        fail "Email state 真实写入/权限/临时文件清理异常"
        ls -la "$EMAIL_STATE_DIR" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$EMAIL_STATE_FILE" 2>/dev/null || true
    fi
    _email_state_reset_vars
    if email_state_load \
       && [[ "$EMAIL_DOMAIN" == "mail.example.com" ]] \
       && [[ "$EMAIL_WORKER_NAME" == "runtime-worker" ]] \
       && [[ "$EMAIL_PATCHES_APPLIED" == "001-init.sql 002-runtime.sql" ]]; then
        pass "Email state 可通过真实 validate_conf_file 后安全加载"
    else
        fail "Email state 真实加载结果异常"
        sed 's/^/    /' "$EMAIL_STATE_FILE" 2>/dev/null || true
    fi
    chmod 666 "$EMAIL_STATE_FILE"
    _email_state_reset_vars
    if email_state_load >/dev/null 2>&1; then
        fail "Email state 接受了 group/other 可写权限"
    else
        pass "Email state 拒绝权限过宽的真实 state 文件"
    fi
    chmod 600 "$EMAIL_STATE_FILE"
    email_state_pwned="$tmp_root/email-state-pwned"
    {
        printf 'EMAIL_INSTALLED=1\n'
        printf 'EMAIL_DOMAIN="$(touch %s)"\n' "$email_state_pwned"
    } > "$EMAIL_STATE_FILE"
    chmod 600 "$EMAIL_STATE_FILE"
    rm -f "$email_state_pwned"
    _email_state_reset_vars
    if email_state_load >/dev/null 2>&1; then
        fail "Email state 接受了命令替换 payload"
    elif [[ -e "$email_state_pwned" ]]; then
        fail "Email state 校验恶意配置时发生命令执行"
    else
        pass "Email state 拒绝命令替换且未执行"
    fi

    email_private_file="$EMAIL_STATE_DIR/secrets/token.txt"
    mkdir -p "$(dirname "$email_private_file")"
    printf 'old-token\n' > "$email_private_file"
    chmod 666 "$email_private_file"
    if _email_write_private_file "$email_private_file" "runtime-secret" \
       && grep -Fxq "runtime-secret" "$email_private_file" \
       && [[ "$(stat -c '%a' "$email_private_file" 2>/dev/null)" == "600" ]] \
       && [[ "$(stat -c '%U' "$email_private_file" 2>/dev/null)" == "root" ]] \
       && ! find "$(dirname "$email_private_file")" -maxdepth 1 -name '.tmp.server-manage.email.*' -print -quit | grep -q .; then
        pass "Email 私密文件 helper 在真实路径强制 root:600 并清理临时文件"
    else
        fail "Email 私密文件 helper 真实写入/权限/清理异常"
        ls -la "$(dirname "$email_private_file")" 2>/dev/null | sed 's/^/    /' || true
    fi
    if email_save_admin_password "runtime-admin-pass" \
       && grep -Fxq 'admin_password=runtime-admin-pass' "$EMAIL_ADMIN_FILE" \
       && [[ "$(stat -c '%a' "$EMAIL_ADMIN_FILE" 2>/dev/null)" == "600" ]] \
       && [[ "$(stat -c '%U' "$EMAIL_ADMIN_FILE" 2>/dev/null)" == "root" ]]; then
        pass "Email 管理员密码真实文件强制 root:600"
    else
        fail "Email 管理员密码真实文件权限或内容异常"
        ls -l "$EMAIL_ADMIN_FILE" 2>/dev/null | sed 's/^/    /' || true
    fi
    CF_API_TOKEN="cf-runtime-token"
    CF_ACCOUNT_ID="cf-runtime-account"
    EMAIL_RESEND_TOKEN="resend-runtime-token"
    _email_export_wrangler_env
    if [[ "${CLOUDFLARE_API_TOKEN:-}" == "cf-runtime-token" \
          && "${CLOUDFLARE_ACCOUNT_ID:-}" == "cf-runtime-account" ]]; then
        pass "Email Wrangler 环境变量同步导出新版 CLOUDFLARE_* 名称"
    else
        fail "Email Wrangler 环境变量导出异常"
    fi
    _email_clear_sensitive_env
    if [[ -z "${CF_API_TOKEN+x}" \
          && -z "${CF_ACCOUNT_ID+x}" \
          && -z "${CLOUDFLARE_API_TOKEN+x}" \
          && -z "${CLOUDFLARE_ACCOUNT_ID+x}" \
          && -z "${EMAIL_RESEND_TOKEN+x}" ]]; then
        pass "Email 敏感环境变量清理覆盖 Cloudflare/Resend 变量"
    else
        fail "Email 敏感环境变量未完全清理"
    fi
    email_pages_dir="$tmp_root/email-pages"
    mkdir -p "$email_pages_dir"
    cat > "$email_pages_dir/wrangler.toml" <<'EOF_EMAIL_PAGES_TOML'
name = "pages-app"
[[services]]
binding = "TEMP_EMAIL"
service = "cloudflare_temp_email"
EOF_EMAIL_PAGES_TOML
    chmod 640 "$email_pages_dir/wrangler.toml"
    EMAIL_WORKER_NAME="runtime-worker"
    if _email_patch_pages_service_binding "$email_pages_dir" \
       && [[ "${EMAIL_PAGES_TOML_BACKUP:-}" == "$email_pages_dir"/.wrangler.toml.bak.* ]] \
       && [[ "${EMAIL_PAGES_TOML_BACKUP_TARGET:-}" == "$email_pages_dir/wrangler.toml" ]] \
       && grep -Fxq 'service = "runtime-worker"' "$email_pages_dir/wrangler.toml"; then
        pass "Email Pages service binding 在真实文件系统上同目录 patch 并记录备份"
    else
        fail "Email Pages service binding patch 异常"
        ls -la "$email_pages_dir" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$email_pages_dir/wrangler.toml" 2>/dev/null || true
    fi
    if _email_restore_pages_service_binding \
       && grep -Fxq 'service = "cloudflare_temp_email"' "$email_pages_dir/wrangler.toml" \
       && [[ -z "${EMAIL_PAGES_TOML_BACKUP+x}" ]] \
       && [[ -z "${EMAIL_PAGES_TOML_BACKUP_TARGET+x}" ]] \
       && ! find "$email_pages_dir" -maxdepth 1 -name '.wrangler.toml.*' -print -quit | grep -q .; then
        pass "Email Pages service binding 可真实回滚且不残留备份"
    else
        fail "Email Pages service binding 回滚或清理异常"
        ls -la "$email_pages_dir" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$email_pages_dir/wrangler.toml" 2>/dev/null || true
    fi

    email_manage_log="$tmp_root/email-manage-update.log"
    rm -rf "$EMAIL_INSTALL_DIR"
    mkdir -p "$EMAIL_INSTALL_DIR/worker"
    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'EOF_EMAIL_MANAGE_TOML'
name = "runtime-worker"
[vars]
DOMAINS = ["mail.example.com"]
DEFAULT_DOMAINS = ["mail.example.com"]
ADMIN_PASSWORDS = ["old-pass"]
JWT_SECRET = "jwt-runtime"
EOF_EMAIL_MANAGE_TOML
    chmod 640 "$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    if (
        email_run() {
            local label="$1"; shift
            printf '%s|%s\n' "$label" "$*" >> "$email_manage_log"
            "$@"
        }
        _email_wrangler() {
            printf 'wrangler|%s\n' "$*" >> "$email_manage_log"
            return 0
        }
        pnpm() {
            printf 'pnpm|%s\n' "$*" >> "$email_manage_log"
            return 0
        }
        _email_manage_update_admin_passwords_var '["runtime-new-pass"]'
    ) >/dev/null 2>&1 \
       && grep -Fxq 'ADMIN_PASSWORDS = ["runtime-new-pass"]' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" \
       && [[ "$(grep -c '^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=' "$EMAIL_INSTALL_DIR/worker/wrangler.toml")" == "1" ]] \
       && [[ "$(stat -c '%a' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null)" == "600" ]] \
       && find "$EMAIL_INSTALL_DIR/worker" -maxdepth 1 -name 'wrangler.toml.adminpw.bak.*' -print -quit | grep -q . \
       && grep -Fxq 'wrangler|deploy' "$email_manage_log"; then
        pass "Email 管理密码 fallback 在真实安装目录更新 wrangler.toml 并触发部署"
    else
        fail "Email 管理密码 fallback 未能安全更新真实 wrangler.toml"
        ls -la "$EMAIL_INSTALL_DIR/worker" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null || true
        sed 's/^/    /' "$email_manage_log" 2>/dev/null || true
    fi

    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=0
    EMAIL_CATCH_ALL_ENABLED=0
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:10:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-123"
    EMAIL_CF_ACCOUNT_ID="account-123"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_ADDRESS_PREFIX="audit"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_PAGES_DOMAIN="runtime-pages.pages.dev"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    email_state_write
    rm -rf "$EMAIL_INSTALL_DIR"
    mkdir -p "$EMAIL_INSTALL_DIR/worker"
    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'EOF_EMAIL_DOMAINS_TOML'
name = "runtime-worker"
[vars]
DEFAULT_DOMAINS = ["mail.example.com"]
DOMAINS = ["mail.example.com"]
JWT_SECRET = "jwt-runtime"
EOF_EMAIL_DOMAINS_TOML
    chmod 600 "$EMAIL_INSTALL_DIR/worker/wrangler.toml"
    email_domains_before="$tmp_root/email-domains-before.toml"
    email_domains_out="$tmp_root/email-manage-domains.out"
    email_domains_log="$tmp_root/email-manage-domains.log"
    cp -a "$EMAIL_INSTALL_DIR/worker/wrangler.toml" "$email_domains_before"
    if (
        email_run() {
            local label="$1"; shift
            printf '%s|%s\n' "$label" "$*" >> "$email_domains_log"
            if [[ "$label" == "重新部署 Worker" ]]; then
                return 17
            fi
            "$@"
        }
        _email_wrangler() {
            printf 'wrangler|%s\n' "$*" >> "$email_domains_log"
            return 0
        }
        pnpm() {
            printf 'pnpm|%s\n' "$*" >> "$email_domains_log"
            return 0
        }
        pause() { :; }
        CF_API_TOKEN="cf-runtime-token"
        unset CF_ACCOUNT_ID CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
        printf '1\nnew.example.com\n' | email_manage_domains
    ) > "$email_domains_out" 2>&1; then
        fail "Email 域名管理在部署失败时仍返回成功"
        sed 's/^/    /' "$email_domains_out" 2>/dev/null || true
    else
        email_domains_leftovers=$(find "$EMAIL_INSTALL_DIR/worker" -maxdepth 1 \( -name 'wrangler.toml.domains.*' -o -name 'wrangler.toml.domains.bak.*' \) -print -quit)
        if cmp -s "$email_domains_before" "$EMAIL_INSTALL_DIR/worker/wrangler.toml" \
           && [[ -z "$email_domains_leftovers" ]] \
           && grep -Fq '重新部署 Worker|_email_wrangler deploy' "$email_domains_log"; then
            pass "Email 域名管理部署失败时真实回滚 wrangler.toml 并清理临时文件"
        else
            fail "Email 域名管理部署失败回滚真实 wrangler.toml 异常"
            ls -la "$EMAIL_INSTALL_DIR/worker" 2>/dev/null | sed 's/^/    /' || true
            diff -u "$email_domains_before" "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null | sed 's/^/    /' || true
            sed 's/^/    /' "$email_domains_log" 2>/dev/null || true
            sed 's/^/    /' "$email_domains_out" 2>/dev/null || true
        fi
    fi

    email_dns_log="$tmp_root/email-uninstall-dns.log"
    _email_state_reset_vars
    EMAIL_RESEND_ENABLED=1
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_DNS_FRONTEND_ID="front-id"
    EMAIL_DNS_MX1_ID="mx1-id"
    EMAIL_DNS_DKIM_ID="dkim-id"
    EMAIL_DNS_SPF_ID="spf-id"
    EMAIL_DNS_SEND_MX_ID="sendmx-id"
    EMAIL_DNS_DMARC_ID="dmarc-id"
    if (
        _email_cf_dns_delete() {
            printf 'delete|%s|%s\n' "$1" "$2" >> "$email_dns_log"
            [[ "$2" != "mx1-id" ]]
        }
        _email_cf_dns_purge() {
            printf 'purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_dns_log"
            return 0
        }
        _email_uninstall_delete_dns
    ) >/dev/null 2>&1; then
        fail "Email 卸载 DNS helper 未透出 state ID 删除失败"
        sed 's/^/    /' "$email_dns_log" 2>/dev/null || true
	    elif grep -Fxq 'delete|zone-runtime|front-id' "$email_dns_log" \
	         && grep -Fxq 'delete|zone-runtime|mx1-id' "$email_dns_log" \
	         && grep -Fxq 'purge|zone-runtime|CNAME|mail.mail.example.com' "$email_dns_log" \
         && grep -Fxq 'purge|zone-runtime|MX|mail.example.com' "$email_dns_log" \
         && grep -Fxq 'purge|zone-runtime|TXT|resend._domainkey.mail.example.com' "$email_dns_log" \
         && grep -Fxq 'purge|zone-runtime|MX|send.mail.example.com' "$email_dns_log" \
         && grep -Fxq 'purge|zone-runtime|TXT|_dmarc.mail.example.com' "$email_dns_log"; then
        pass "Email 卸载 DNS helper 按 state ID 删除并在失败时继续兜底清理"
    else
	        fail "Email 卸载 DNS helper 删除/兜底调用不完整"
	        sed 's/^/    /' "$email_dns_log" 2>/dev/null || true
	    fi

	    email_dns_purge_fail_log="$tmp_root/email-uninstall-dns-purge-fail.log"
	    _email_state_reset_vars
	    EMAIL_RESEND_ENABLED=1
	    EMAIL_ZONE_ID="zone-runtime"
	    EMAIL_DOMAIN="mail.example.com"
	    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
	    if (
	        _email_cf_dns_delete() {
	            printf 'delete|%s|%s\n' "$1" "$2" >> "$email_dns_purge_fail_log"
	            return 0
	        }
	        _email_cf_dns_purge() {
	            printf 'purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_dns_purge_fail_log"
	            [[ "$3" != "send.mail.example.com" ]]
	        }
	        _email_uninstall_delete_dns
	    ) >/dev/null 2>&1; then
	        fail "Email 卸载 DNS helper 未透出兜底 purge 失败"
	        sed 's/^/    /' "$email_dns_purge_fail_log" 2>/dev/null || true
	    elif grep -Fxq 'purge|zone-runtime|CNAME|mail.mail.example.com' "$email_dns_purge_fail_log" \
	         && grep -Fxq 'purge|zone-runtime|TXT|send.mail.example.com' "$email_dns_purge_fail_log" \
	         && grep -Fxq 'purge|zone-runtime|TXT|_dmarc.mail.example.com' "$email_dns_purge_fail_log"; then
	        pass "Email 卸载 DNS helper 兜底 purge 失败会返回非 0 且继续尝试清理"
	    else
	        fail "Email 卸载 DNS helper 兜底 purge 失败路径调用异常"
	        sed 's/^/    /' "$email_dns_purge_fail_log" 2>/dev/null || true
	    fi

	    email_resend_setup_log="$tmp_root/email-resend-setup.log"
	    email_resend_setup_out="$tmp_root/email-resend-setup.out"
	    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=0
    EMAIL_CATCH_ALL_ENABLED=0
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:16:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_CF_ACCOUNT_ID="account-runtime"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    email_state_write
    if (
        email_read_secret() {
            printf -v "$2" '%s' 'resend-runtime-token'
            return 0
        }
        email_run() {
            local label="$1"; shift
            printf 'run|%s|%s\n' "$label" "$*" >> "$email_resend_setup_log"
            "$@"
        }
        _email_cf_worker_secret_put() {
            printf 'secret|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_setup_log"
            return 0
        }
        _email_cf_dns_purge() {
            printf 'purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_setup_log"
            [[ "$3" != "send.mail.example.com" ]]
        }
        _email_cf_dns_create_record_into() {
            printf 'create-should-not-run|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$email_resend_setup_log"
            return 0
        }
        _email_manage_resend_setup <<< 'runtime-dkim-value'
    ) > "$email_resend_setup_out" 2>&1; then
        fail "Email Resend 启用清旧 DNS 失败时仍返回成功"
        sed 's/^/    /' "$email_resend_setup_out" 2>/dev/null || true
    else
        _email_state_reset_vars
        if email_state_load \
           && [[ "${EMAIL_RESEND_ENABLED:-1}" == "0" ]] \
           && [[ -z "${EMAIL_RESEND_SEND_DOMAIN:-}" ]] \
           && grep -Fxq 'secret|runtime-worker|RESEND_TOKEN|resend-runtime-token' "$email_resend_setup_log" \
           && grep -Fxq 'purge|zone-runtime|TXT|send.mail.example.com' "$email_resend_setup_log" \
           && ! grep -q 'create-should-not-run' "$email_resend_setup_log"; then
            pass "Email Resend 启用清旧 DNS 失败时停止创建并保留未启用 state"
        else
            fail "Email Resend 启用清旧 DNS 失败保护异常"
            sed 's/^/    /' "$EMAIL_STATE_FILE" 2>/dev/null || true
            sed 's/^/    /' "$email_resend_setup_log" 2>/dev/null || true
	            sed 's/^/    /' "$email_resend_setup_out" 2>/dev/null || true
	        fi
	    fi

	    email_resend_create_fail_log="$tmp_root/email-resend-create-fail.log"
	    email_resend_create_fail_out="$tmp_root/email-resend-create-fail.out"
	    _email_state_reset_vars
	    EMAIL_INSTALLED=1
	    EMAIL_RESEND_ENABLED=0
	    EMAIL_CATCH_ALL_ENABLED=0
	    EMAIL_INSTALL_VERSION="runtime-v1"
	    EMAIL_INSTALL_DATE="2026-07-03 12:17:00"
	    EMAIL_DOMAIN="mail.example.com"
	    EMAIL_ZONE_ID="zone-runtime"
	    EMAIL_CF_ACCOUNT_ID="account-runtime"
	    EMAIL_API_PREFIX="api"
	    EMAIL_API_DOMAIN="api.mail.example.com"
	    EMAIL_FRONTEND_PREFIX="mail"
	    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
	    EMAIL_WORKER_NAME="runtime-worker"
	    EMAIL_PAGES_PROJECT="runtime-pages"
	    EMAIL_D1_NAME="runtime-d1"
	    EMAIL_D1_ID="d1-123"
	    email_state_write
	    if (
	        email_read_secret() {
	            printf -v "$2" '%s' 'resend-runtime-token'
	            return 0
	        }
	        email_run() {
	            local label="$1"; shift
	            printf 'run|%s|%s\n' "$label" "$*" >> "$email_resend_create_fail_log"
	            "$@"
	        }
	        _email_cf_worker_secret_put() {
	            printf 'secret|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_create_fail_log"
	            return 0
	        }
	        _email_cf_dns_purge() {
	            printf 'purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_create_fail_log"
	            return 0
	        }
	        _email_cf_dns_create_record_into() {
	            printf 'create|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$email_resend_create_fail_log"
	            printf -v "$1" '%s-id' "$3"
	            [[ "$1" != "EMAIL_DNS_SPF_ID" ]]
	        }
	        _email_manage_resend_setup <<< 'runtime-dkim-value'
	    ) > "$email_resend_create_fail_out" 2>&1; then
	        fail "Email Resend 启用 DNS 创建失败时仍返回成功"
	        sed 's/^/    /' "$email_resend_create_fail_out" 2>/dev/null || true
	    else
	        _email_state_reset_vars
	        if email_state_load \
	           && [[ "${EMAIL_RESEND_ENABLED:-1}" == "0" ]] \
	           && [[ -z "${EMAIL_RESEND_SEND_DOMAIN:-}" ]] \
	           && [[ "$EMAIL_DNS_DKIM_ID" == "TXT-id" ]] \
	           && [[ "$EMAIL_DNS_SEND_MX_ID" == "MX-id" ]] \
	           && [[ "$EMAIL_DNS_DMARC_ID" == "TXT-id" ]] \
	           && grep -Fxq 'create|EMAIL_DNS_SPF_ID|zone-runtime|TXT|send.mail.example.com' "$email_resend_create_fail_log" \
	           && ! grep -q 'Email Resend enabled' "$email_resend_create_fail_log"; then
	            pass "Email Resend 启用 DNS 创建失败时不标记启用并保留可清理记录 ID"
	        else
	            fail "Email Resend 启用 DNS 创建失败保护异常"
	            sed 's/^/    /' "$EMAIL_STATE_FILE" 2>/dev/null || true
	            sed 's/^/    /' "$email_resend_create_fail_log" 2>/dev/null || true
	            sed 's/^/    /' "$email_resend_create_fail_out" 2>/dev/null || true
	        fi
	    fi

	    email_resend_token_fail_log="$tmp_root/email-resend-token-fail.log"
	    if (
	        email_read_secret() {
	            printf -v "$2" '%s' 'resend-runtime-token-2'
	            return 0
	        }
	        email_run() {
	            local label="$1"; shift
	            printf 'run|%s|%s\n' "$label" "$*" >> "$email_resend_token_fail_log"
	            return 28
	        }
	        _email_cf_worker_secret_put() {
	            printf 'secret-should-not-run-directly|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_token_fail_log"
	            return 0
	        }
	        log_action() { printf 'log-action|%s\n' "$1" >> "$email_resend_token_fail_log"; }
	        _email_manage_resend_token_only
	    ) >/dev/null 2>&1; then
	        fail "Email Resend token-only secret 更新失败时仍返回成功"
	        sed 's/^/    /' "$email_resend_token_fail_log" 2>/dev/null || true
	    elif grep -Fxq 'run|更新 RESEND_TOKEN secret|_email_cf_worker_secret_put runtime-worker RESEND_TOKEN resend-runtime-token-2' "$email_resend_token_fail_log" \
	         && ! grep -q 'Email Resend token rotated' "$email_resend_token_fail_log"; then
	        pass "Email Resend token-only secret 更新失败会返回非 0 且不记录成功日志"
	    else
	        fail "Email Resend token-only 失败路径异常"
	        sed 's/^/    /' "$email_resend_token_fail_log" 2>/dev/null || true
	    fi

	    email_resend_disable_log="$tmp_root/email-resend-disable.log"
	    email_resend_disable_out="$tmp_root/email-resend-disable.out"
    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=1
    EMAIL_CATCH_ALL_ENABLED=0
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:18:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_CF_ACCOUNT_ID="account-runtime"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    EMAIL_RESEND_SEND_DOMAIN="send.mail.example.com"
    EMAIL_DNS_DKIM_ID="dkim-id"
    EMAIL_DNS_SPF_ID="spf-id"
    EMAIL_DNS_SEND_MX_ID="sendmx-id"
    EMAIL_DNS_DMARC_ID="dmarc-id"
    email_state_write
    if (
        confirm() { return 0; }
        _email_cf_dns_delete() {
            printf 'delete|%s|%s\n' "$1" "$2" >> "$email_resend_disable_log"
            [[ "$2" != "spf-id" ]]
        }
        _email_cf_dns_purge() {
            printf 'purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_resend_disable_log"
            return 0
        }
        _email_manage_resend_disable
    ) > "$email_resend_disable_out" 2>&1; then
        fail "Email Resend 禁用 DNS 删除失败时仍返回成功"
        sed 's/^/    /' "$email_resend_disable_out" 2>/dev/null || true
    else
        _email_state_reset_vars
        if email_state_load \
           && [[ "${EMAIL_RESEND_ENABLED:-0}" == "1" ]] \
           && [[ "$EMAIL_DNS_DKIM_ID" == "dkim-id" ]] \
           && [[ "$EMAIL_DNS_SPF_ID" == "spf-id" ]] \
           && [[ "$EMAIL_DNS_SEND_MX_ID" == "sendmx-id" ]] \
           && [[ "$EMAIL_DNS_DMARC_ID" == "dmarc-id" ]] \
           && grep -Fxq 'delete|zone-runtime|spf-id' "$email_resend_disable_log" \
           && grep -Fxq 'purge|zone-runtime|TXT|_dmarc.mail.example.com' "$email_resend_disable_log"; then
            pass "Email Resend 禁用 DNS 删除失败时保留 state/记录 ID 供重试"
        else
            fail "Email Resend 禁用失败保护异常"
            sed 's/^/    /' "$EMAIL_STATE_FILE" 2>/dev/null || true
            sed 's/^/    /' "$email_resend_disable_log" 2>/dev/null || true
            sed 's/^/    /' "$email_resend_disable_out" 2>/dev/null || true
        fi
    fi

    if [[ "$log_touched" -eq 0 && -f "$LOG_FILE" && "$LOG_FILE" == "/var/log/server-manage.log" ]]; then
        log_backup="$tmp_root/email-main-log.backup"
        cp -a "$LOG_FILE" "$log_backup"
    fi
    [[ "$LOG_FILE" == "/var/log/server-manage.log" ]] && log_touched=1
    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=1
    EMAIL_CATCH_ALL_ENABLED=1
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:20:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_CF_ACCOUNT_ID="account-runtime"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_ADDRESS_PREFIX="audit"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_PAGES_DOMAIN="runtime-pages.pages.dev"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    EMAIL_RESEND_SEND_DOMAIN="send.example.com"
    EMAIL_DNS_FRONTEND_ID="front-id"
    EMAIL_DNS_MX1_ID="mx1-id"
    EMAIL_DNS_MX2_ID="mx2-id"
    EMAIL_DNS_MX3_ID="mx3-id"
    EMAIL_DNS_DKIM_ID="dkim-id"
    EMAIL_DNS_SPF_ID="spf-id"
    EMAIL_DNS_SEND_MX_ID="sendmx-id"
    EMAIL_DNS_DMARC_ID="dmarc-id"
    email_state_write
    rm -rf "$EMAIL_INSTALL_DIR"
    mkdir -p "$EMAIL_INSTALL_DIR/worker"
    printf 'runtime worker\n' > "$EMAIL_INSTALL_DIR/worker/README"
    email_save_admin_password "runtime-admin-pass"
    email_uninstall_log="$tmp_root/email-uninstall.log"
    email_uninstall_out="$tmp_root/email-uninstall.out"
    if (
        confirm() {
            printf 'confirm|%s\n' "$1" >> "$email_uninstall_log"
            return 0
        }
        pause() { :; }
        email_run() {
            local label="$1"; shift
            printf 'run|%s|%s\n' "$label" "$*" >> "$email_uninstall_log"
            "$@"
        }
        _email_cf_catch_all_disable() {
            printf 'catchall|%s\n' "$1" >> "$email_uninstall_log"
            return 0
        }
        _email_cf_dns_delete() {
            printf 'dns_delete|%s|%s\n' "$1" "$2" >> "$email_uninstall_log"
            return 0
        }
        _email_cf_dns_purge() {
            printf 'dns_purge|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_uninstall_log"
            return 0
        }
        _email_cf_worker_delete() {
            printf 'worker|%s\n' "$1" >> "$email_uninstall_log"
            return 0
        }
        _email_cf_pages_project_delete() {
            printf 'pages|%s\n' "$1" >> "$email_uninstall_log"
            return 0
        }
        _email_cf_d1_delete() {
            printf 'd1|%s\n' "$1" >> "$email_uninstall_log"
            return 0
        }
        CF_API_TOKEN="cf-runtime-token"
        unset CF_ACCOUNT_ID CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
        email_uninstall <<< "mail.example.com"
    ) > "$email_uninstall_out" 2>&1 \
       && [[ ! -e "$EMAIL_INSTALL_DIR" ]] \
       && [[ ! -e "$EMAIL_ADMIN_FILE" ]] \
       && [[ ! -e "$EMAIL_STATE_FILE" ]] \
       && grep -Fxq 'catchall|zone-runtime' "$email_uninstall_log" \
       && grep -Fxq 'dns_delete|zone-runtime|front-id' "$email_uninstall_log" \
       && grep -Fxq 'dns_delete|zone-runtime|mx3-id' "$email_uninstall_log" \
       && grep -Fxq 'dns_purge|zone-runtime|TXT|_dmarc.mail.example.com' "$email_uninstall_log" \
       && grep -Fxq 'worker|runtime-worker' "$email_uninstall_log" \
       && grep -Fxq 'pages|runtime-pages' "$email_uninstall_log" \
       && grep -Fxq 'd1|d1-123' "$email_uninstall_log"; then
        pass "Email 完整卸载在真实路径删除本地目录/state/admin 并调用远端回收步骤"
    else
        fail "Email 完整卸载真实路径清理或远端回收步骤异常"
        ls -la "$EMAIL_INSTALL_DIR" 2>/dev/null | sed 's/^/    /' || true
        ls -la "$EMAIL_STATE_DIR" 2>/dev/null | sed 's/^/    /' || true
        ls -l "$EMAIL_ADMIN_FILE" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$email_uninstall_log" 2>/dev/null || true
        sed 's/^/    /' "$email_uninstall_out" 2>/dev/null || true
    fi

    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=0
    EMAIL_CATCH_ALL_ENABLED=1
    EMAIL_INSTALL_VERSION="runtime-v1"
    EMAIL_INSTALL_DATE="2026-07-03 12:25:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_CF_ACCOUNT_ID="account-runtime"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    email_state_write
    rm -rf "$EMAIL_INSTALL_DIR"
    mkdir -p "$EMAIL_INSTALL_DIR/worker"
    printf 'runtime worker\n' > "$EMAIL_INSTALL_DIR/worker/README"
    email_save_admin_password "runtime-admin-pass"
    email_uninstall_fail_log="$tmp_root/email-uninstall-catchall-fail.log"
    email_uninstall_fail_out="$tmp_root/email-uninstall-catchall-fail.out"
    if (
        confirm() { return 0; }
        pause() { :; }
        email_run() {
            local label="$1"; shift
            printf 'run|%s|%s\n' "$label" "$*" >> "$email_uninstall_fail_log"
            "$@"
        }
        _email_cf_catch_all_disable() {
            printf 'catchall-fail|%s\n' "$1" >> "$email_uninstall_fail_log"
            return 44
        }
        _email_cf_dns_delete() {
            printf 'dns-delete-should-not-run|%s|%s\n' "$1" "$2" >> "$email_uninstall_fail_log"
            return 0
        }
        _email_cf_dns_purge() {
            printf 'dns-purge-should-not-run|%s|%s|%s\n' "$1" "$2" "$3" >> "$email_uninstall_fail_log"
            return 0
        }
        _email_cf_worker_delete() {
            printf 'worker-should-not-run|%s\n' "$1" >> "$email_uninstall_fail_log"
            return 0
        }
        _email_cf_pages_project_delete() {
            printf 'pages-should-not-run|%s\n' "$1" >> "$email_uninstall_fail_log"
            return 0
        }
        _email_cf_d1_delete() {
            printf 'd1-should-not-run|%s\n' "$1" >> "$email_uninstall_fail_log"
            return 0
        }
        CF_API_TOKEN="cf-runtime-token"
        unset CF_ACCOUNT_ID CLOUDFLARE_API_TOKEN CLOUDFLARE_ACCOUNT_ID
        email_uninstall <<< "mail.example.com"
    ) > "$email_uninstall_fail_out" 2>&1; then
        fail "Email 卸载 catch-all 关闭失败时仍返回成功"
        sed 's/^/    /' "$email_uninstall_fail_out" 2>/dev/null || true
    elif [[ -d "$EMAIL_INSTALL_DIR" ]] \
         && [[ -f "$EMAIL_STATE_FILE" ]] \
         && [[ -f "$EMAIL_ADMIN_FILE" ]] \
         && grep -Fxq 'catchall-fail|zone-runtime' "$email_uninstall_fail_log" \
         && ! grep -q 'should-not-run' "$email_uninstall_fail_log"; then
        pass "Email 卸载 catch-all 失败时保留 state/本地文件且不中途继续删除资源"
    else
        fail "Email 卸载 catch-all 失败保护异常"
        ls -la "$EMAIL_INSTALL_DIR" 2>/dev/null | sed 's/^/    /' || true
        ls -la "$EMAIL_STATE_DIR" 2>/dev/null | sed 's/^/    /' || true
        ls -l "$EMAIL_ADMIN_FILE" 2>/dev/null | sed 's/^/    /' || true
        sed 's/^/    /' "$email_uninstall_fail_log" 2>/dev/null || true
        sed 's/^/    /' "$email_uninstall_fail_out" 2>/dev/null || true
    fi

    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_DOMAIN="mail.example.com"
    email_state_write
    email_state_clear
    if [[ ! -f "$EMAIL_STATE_FILE" && "${EMAIL_INSTALLED:-1}" == "0" && -z "${EMAIL_DOMAIN:-}" ]]; then
        pass "Email state_clear 删除真实 state 并重置内存变量"
    else
        fail "Email state_clear 未删除 state 或未重置变量"
    fi

    email_menu_out="$tmp_root/email-menu.out"
    email_menu_log="$tmp_root/email-menu.log"
    rm -f "$EMAIL_STATE_FILE" "$EMAIL_LOG_FILE"
    if (
        pause() { :; }
        email_deploy() { printf 'deploy-called\n' >> "$email_menu_log"; }
        printf '0\n' | menu_email
    ) > "$email_menu_out" 2>&1 \
       && grep -qF '状态: 未部署' "$email_menu_out" \
       && grep -qF '1. 一键部署' "$email_menu_out" \
       && grep -qF '2. 查看部署日志' "$email_menu_out"; then
        pass "Email 菜单未部署态在实体机上可渲染并返回"
    else
        fail "Email 菜单未部署态渲染异常"
        sed 's/^/    /' "$email_menu_out" 2>/dev/null | head -80 || true
        sed 's/^/    /' "$email_menu_log" 2>/dev/null || true
    fi

    _email_state_reset_vars
    EMAIL_INSTALLED=0
    EMAIL_DOMAIN="partial.example.com"
    EMAIL_ZONE_ID="zone-partial"
    EMAIL_WORKER_NAME="partial-worker"
    email_state_write
    if (
        pause() { :; }
        email_uninstall() { printf 'uninstall-called\n' >> "$email_menu_log"; }
        email_deploy() { printf 'deploy-called\n' >> "$email_menu_log"; }
        printf '0\n' | menu_email
    ) > "$email_menu_out" 2>&1 \
       && grep -qF '状态: 部署未完成' "$email_menu_out" \
       && grep -qF '域名: partial.example.com' "$email_menu_out" \
       && grep -qF '1. 强制卸载' "$email_menu_out" \
       && grep -qF '2. 重新部署' "$email_menu_out"; then
        pass "Email 菜单 partial 态在实体机上可渲染安全操作顺序"
    else
        fail "Email 菜单 partial 态渲染异常"
        sed 's/^/    /' "$email_menu_out" 2>/dev/null | head -100 || true
        sed 's/^/    /' "$email_menu_log" 2>/dev/null || true
    fi

    _email_state_reset_vars
    EMAIL_INSTALLED=1
    EMAIL_RESEND_ENABLED=1
    EMAIL_CATCH_ALL_ENABLED=1
    EMAIL_INSTALL_VERSION="runtime-v2"
    EMAIL_INSTALL_DATE="2026-07-03 13:00:00"
    EMAIL_DOMAIN="mail.example.com"
    EMAIL_ZONE_ID="zone-runtime"
    EMAIL_CF_ACCOUNT_ID="account-runtime"
    EMAIL_API_PREFIX="api"
    EMAIL_API_DOMAIN="api.mail.example.com"
    EMAIL_FRONTEND_PREFIX="mail"
    EMAIL_FRONTEND_DOMAIN="mail.mail.example.com"
    EMAIL_ADDRESS_PREFIX="audit"
    EMAIL_WORKER_NAME="runtime-worker"
    EMAIL_PAGES_PROJECT="runtime-pages"
    EMAIL_D1_NAME="runtime-d1"
    EMAIL_D1_ID="d1-123"
    email_state_write
    : > "$email_menu_log"
    if (
        pause() { :; }
        email_status() { printf 'status-called\n' >> "$email_menu_log"; }
        email_manage_change_admin_password() { printf 'change-admin-called\n' >> "$email_menu_log"; }
        email_manage_domains() { printf 'domains-called\n' >> "$email_menu_log"; }
        email_manage_resend() { printf 'resend-called\n' >> "$email_menu_log"; }
        email_manage_upgrade() { printf 'upgrade-called\n' >> "$email_menu_log"; }
        email_manage_redeploy() { printf 'redeploy-called\n' >> "$email_menu_log"; }
        email_uninstall() { printf 'uninstall-called\n' >> "$email_menu_log"; }
        printf '0\n' | menu_email
    ) > "$email_menu_out" 2>&1 \
       && grep -qF '状态: 已部署' "$email_menu_out" \
       && grep -qF 'mail.mail.example.com' "$email_menu_out" \
       && grep -qF '1. 查看部署状态 + 健康检查' "$email_menu_out" \
       && grep -qF '8. 完全卸载' "$email_menu_out"; then
        pass "Email 菜单已部署态在实体机上可渲染管理入口"
    else
        fail "Email 菜单已部署态渲染异常"
        sed 's/^/    /' "$email_menu_out" 2>/dev/null | head -120 || true
        sed 's/^/    /' "$email_menu_log" 2>/dev/null || true
    fi

    {
        printf 'Authorization: Bearer secret-token-123456\n'
        printf 'TOKEN=super-secret-value\n'
        printf '{"name":"ADMIN_PASSWORDS","type":"secret_text","text":"plain-password"}\n'
    } > "$EMAIL_LOG_FILE"
    chmod 600 "$EMAIL_LOG_FILE"
    if (
        pause() { :; }
        email_view_log
    ) > "$tmp_root/email-view-log.out" 2>&1 \
       && ! grep -qF 'secret-token-123456' "$tmp_root/email-view-log.out" \
       && ! grep -qF 'super-secret-value' "$tmp_root/email-view-log.out" \
       && ! grep -qF 'plain-password' "$tmp_root/email-view-log.out" \
       && grep -Eq '\\*\\*\\*|REDACTED|secret_text' "$tmp_root/email-view-log.out"; then
        pass "Email 日志查看在实体机上输出脱敏内容"
    else
        fail "Email 日志查看脱敏异常"
        sed 's/^/    /' "$tmp_root/email-view-log.out" 2>/dev/null | head -100 || true
    fi
else
    skip "非 root 或 Email 系统路径非预期，跳过 Email state 真实路径测试"
fi

echo ""
echo "== Web home expose runtime mock =="
if [[ "$(id -u)" -eq 0 ]]; then
    if [[ "$web_home_hook_touched" -eq 0 && -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" ]]; then
        web_home_hook_backup="$tmp_root/web-home-hook.backup"
        cp -a "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" "$web_home_hook_backup"
    fi
    web_home_hook_touched=1
    rm -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
    if [[ "$web_home_cred_touched" -eq 0 && -f "/root/.cloudflare-${web_home_domain}.ini" ]]; then
        web_home_cred_backup="$tmp_root/web-home-cred.backup"
        cp -a "/root/.cloudflare-${web_home_domain}.ini" "$web_home_cred_backup"
    fi
    web_home_cred_touched=1
    rm -f "/root/.cloudflare-${web_home_domain}.ini"
    if [[ "$web_home_le_touched" -eq 0 && -e "/etc/letsencrypt/live/${web_home_domain}" ]]; then
        web_home_le_backup="$tmp_root/web-home-le.backup"
        cp -a "/etc/letsencrypt/live/${web_home_domain}" "$web_home_le_backup"
    fi
    web_home_le_touched=1
    rm -rf "/etc/letsencrypt/live/${web_home_domain}"

    web_home_root="$tmp_root/web-home"
    web_home_cert_prefix="$web_home_root/cert"
    web_home_config_dir="$web_home_root/managed"
    web_home_ddns_dir="$web_home_root/ddns"
    web_home_ddns_script="$web_home_root/ddns-update.sh"
    web_home_le_live="/etc/letsencrypt/live/${web_home_domain}"
    mkdir -p "$web_home_cert_prefix" "$web_home_config_dir" "$web_home_ddns_dir" "$web_home_le_live"
    printf 'home-runtime-fullchain\n' > "$web_home_le_live/fullchain.pem"
    printf 'home-runtime-privkey\n' > "$web_home_le_live/privkey.pem"

    web_home_log="$tmp_root/web-home.log"
    if (
        CERT_PATH_PREFIX="$web_home_cert_prefix"
        CONFIG_DIR="$web_home_config_dir"
        DDNS_CONFIG_DIR="$web_home_ddns_dir"
        DDNS_UPDATE_SCRIPT="$web_home_ddns_script"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_verify_token() { [[ "$1" == "tok-home-runtime" ]]; }
        _cf_list_zones() {
            printf '{"success":true,"result":[{"name":"example.com","id":"zone-home-runtime"}]}\n'
        }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        _cf_dns_snapshot_records() { printf '[]\n'; }
        _cf_dns_restore_records() { printf 'unexpected-dns-restore\n' >> "$web_home_log"; return 1; }
        _cf_origin_rules_restore() { printf 'unexpected-origin-restore\n' >> "$web_home_log"; return 1; }
        _cf_dns_delete() { printf 'cf-delete|%s|%s|%s\n' "$2" "$3" "$4" >> "$web_home_log"; return 0; }
        _cf_update_dns_record() { printf 'cf-upsert|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$web_home_log"; return 0; }
        _cf_get_origin_ruleset() { printf '{"success":true,"result":{"rules":[]}}\n'; }
        _cf_put_origin_ruleset() { printf 'cf-origin-put|%s|%s|%s\n' "$1" "$2" "$3" >> "$web_home_log"; return 0; }
        _cf_api() { printf '{"success":true}\n'; }
        get_public_ipv4() { printf '198.51.100.45\n'; }
        _nginx_deploy_conf() { printf 'nginx-deploy|%s\n%s\n' "$1" "$2" >> "$web_home_log"; return 0; }
        _ensure_ssl_params() { printf 'ensure-ssl\n' >> "$web_home_log"; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n    listen [::]:%s ssl http2;\n' "$1" "$1"; }
        ufw_is_active() { return 1; }
        certbot() { printf 'certbot|%s\n' "$*" >> "$web_home_log"; return 0; }
        ddns_create_script() { printf '#!/usr/bin/env bash\nexit 0\n' > "$DDNS_UPDATE_SCRIPT"; chmod 755 "$DDNS_UPDATE_SCRIPT"; }
        ddns_rebuild_cron() { printf 'ddns-rebuild-cron\n' >> "$web_home_log"; return 0; }
        cron_add_job() { printf 'cron-add|%s|%s\n' "$1" "$2" >> "$web_home_log"; return 0; }
        confirm() {
            printf 'confirm|%s\n' "$1" >> "$web_home_log"
            case "$1" in
                *"开始执行"*) return 0 ;;
                *"内网 DNS"*) return 1 ;;
                *) return 0 ;;
            esac
        }
        printf 'tok-home-runtime\n1\nhome\n5244\n8443\n7\n' | web_home_expose
    ) > "$tmp_root/web-home.out" 2>&1 \
       && [[ -f "$web_home_cert_prefix/${web_home_domain}/fullchain.pem" ]] \
       && [[ -f "$web_home_cert_prefix/${web_home_domain}/privkey.pem" ]] \
       && [[ "$(stat -c '%a' "$web_home_cert_prefix/${web_home_domain}/privkey.pem" 2>/dev/null)" == "600" ]] \
       && [[ -x "$web_home_ddns_script" ]] \
       && [[ "$(stat -c '%a' "$web_home_ddns_dir/${web_home_domain}.conf" 2>/dev/null)" == "600" ]] \
       && grep -Fxq 'DDNS_INTERVAL="7"' "$web_home_ddns_dir/${web_home_domain}.conf" \
       && grep -Fxq 'DDNS_PROXIED="true"' "$web_home_ddns_dir/${web_home_domain}.conf" \
       && [[ -x "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" ]] \
       && grep -Fq "copy_cert_pair_atomic" "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" \
       && grep -Fq 'HOME_EXPOSE="true"' "$web_home_config_dir/${web_home_domain}.conf" \
       && grep -Fq "LOCAL_PROXY_PASS=\"http://127.0.0.1:5244\"" "$web_home_config_dir/${web_home_domain}.conf" \
       && grep -Fxq 'cf-upsert|zone-home-runtime|tok-home-runtime|home.example.com|A|198.51.100.45|true' "$web_home_log" \
       && grep -Fq 'cf-origin-put|tok-home-runtime|zone-home-runtime|' "$web_home_log" \
       && grep -Fq "cron-add|CertRenew_${web_home_domain}|" "$web_home_log" \
       && ! find "$web_home_root" -name '.tmp.server-manage.*' -print -quit | grep -q .; then
        pass "Web 家宽暴露在实体机 mock 下落地证书/DDNS/hook/domain 配置并调用 CF/Nginx"
    else
        fail "Web 家宽暴露实体机 mock 成功路径异常"
        sed 's/^/    /' "$tmp_root/web-home.out" 2>/dev/null || true
        sed 's/^/    /' "$web_home_log" 2>/dev/null || true
        find "$web_home_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi

    rm -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
    web_home_origin_fail_log="$tmp_root/web-home-origin-fail.log"
    web_home_origin_fail_root="$tmp_root/web-home-origin-fail"
    mkdir -p "$web_home_origin_fail_root/cert" "$web_home_origin_fail_root/managed" "$web_home_origin_fail_root/ddns" "$web_home_le_live"
    printf 'home-runtime-fullchain\n' > "$web_home_le_live/fullchain.pem"
    printf 'home-runtime-privkey\n' > "$web_home_le_live/privkey.pem"
    if (
        CERT_PATH_PREFIX="$web_home_origin_fail_root/cert"
        CONFIG_DIR="$web_home_origin_fail_root/managed"
        DDNS_CONFIG_DIR="$web_home_origin_fail_root/ddns"
        DDNS_UPDATE_SCRIPT="$web_home_origin_fail_root/ddns-update.sh"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_verify_token() { return 0; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-home-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        _cf_dns_snapshot_records() { printf '[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]\n'; }
        _cf_dns_restore_records() { printf 'dns-restore|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$web_home_origin_fail_log"; return 0; }
        _cf_origin_rules_restore() { printf 'origin-restore-should-not-run\n' >> "$web_home_origin_fail_log"; return 1; }
        _cf_dns_delete() { return 0; }
        _cf_update_dns_record() { return 0; }
        get_public_ipv4() { printf '198.51.100.45\n'; }
        _nginx_deploy_conf() { return 0; }
        _ensure_ssl_params() { :; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n' "$1"; }
        ufw_is_active() { return 1; }
        certbot() { return 0; }
        ddns_create_script() { printf '#!/usr/bin/env bash\nexit 0\n' > "$DDNS_UPDATE_SCRIPT"; chmod 755 "$DDNS_UPDATE_SCRIPT"; }
        ddns_rebuild_cron() { return 0; }
        _cf_get_origin_ruleset() { printf 'origin-read-fail\n' >> "$web_home_origin_fail_log"; return 1; }
        _cf_put_origin_ruleset() { printf 'origin-put-should-not-run\n' >> "$web_home_origin_fail_log"; return 0; }
        _cf_api() { printf 'ssl-should-not-run\n' >> "$web_home_origin_fail_log"; printf '{"success":true}\n'; }
        cron_add_job() { printf 'cert-cron-should-not-run\n' >> "$web_home_origin_fail_log"; return 0; }
        _web_cleanup_domain() {
            printf 'cleanup-domain|%s|%s\n' "$1" "${2:-}" >> "$web_home_origin_fail_log"
            rm -f "${CERT_HOOKS_DIR}/renew-${1}.sh" "$CONFIG_DIR/${1}.conf" "$DDNS_CONFIG_DIR/${1}.conf" "/root/.cloudflare-${1}.ini"
            rm -rf "${CERT_PATH_PREFIX}/${1}"
            return 0
        }
        confirm() { [[ "$1" == *"开始执行"* ]]; }
        printf 'tok-home-runtime\n1\nhome\n5244\n8443\n7\n' | web_home_expose
    ) > "$tmp_root/web-home-origin-fail.out" 2>&1; then
        fail "Web 家宽暴露 Origin Rule 读取失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-home-origin-fail.out" 2>/dev/null || true
    elif grep -Fxq 'origin-read-fail' "$web_home_origin_fail_log" \
         && grep -Fq 'dns-restore|zone-home-runtime|tok-home-runtime|home.example.com|[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]' "$web_home_origin_fail_log" \
         && grep -Fxq "cleanup-domain|${web_home_domain}|quiet" "$web_home_origin_fail_log" \
         && [[ ! -e "$web_home_origin_fail_root/managed/${web_home_domain}.conf" ]] \
         && [[ ! -e "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" ]] \
         && ! grep -q 'cert-cron-should-not-run\|ssl-should-not-run\|origin-put-should-not-run\|origin-restore-should-not-run' "$web_home_origin_fail_log"; then
        pass "Web 家宽暴露 Origin Rule 读取失败时中止、恢复 DNS 且不继续写最终配置"
    else
        fail "Web 家宽暴露 Origin Rule 读取失败中止路径异常"
        sed 's/^/    /' "$tmp_root/web-home-origin-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$web_home_origin_fail_log" 2>/dev/null || true
        find "$web_home_origin_fail_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi

    web_home_fail_log="$tmp_root/web-home-fail.log"
    web_home_fail_root="$tmp_root/web-home-fail"
    mkdir -p "$web_home_fail_root/cert" "$web_home_fail_root/managed" "$web_home_fail_root/ddns" "$web_home_le_live"
    printf 'home-runtime-fullchain\n' > "$web_home_le_live/fullchain.pem"
    printf 'home-runtime-privkey\n' > "$web_home_le_live/privkey.pem"
    if (
        CERT_PATH_PREFIX="$web_home_fail_root/cert"
        CONFIG_DIR="$web_home_fail_root/managed"
        DDNS_CONFIG_DIR="$web_home_fail_root/ddns"
        DDNS_UPDATE_SCRIPT="$web_home_fail_root/ddns-update.sh"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_verify_token() { return 0; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-home-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        _cf_dns_snapshot_records() { printf '[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]\n'; }
        _cf_dns_restore_records() { printf 'dns-restore|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$web_home_fail_log"; return 0; }
        _cf_origin_rules_restore() { printf 'origin-restore-should-not-run\n' >> "$web_home_fail_log"; return 1; }
        _cf_dns_delete() { return 0; }
        _cf_update_dns_record() { return 0; }
        get_public_ipv4() { printf '198.51.100.45\n'; }
        _nginx_deploy_conf() { return 0; }
        _ensure_ssl_params() { :; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n' "$1"; }
        ufw_is_active() { return 1; }
        certbot() { return 0; }
        ddns_create_script() { printf 'ddns-create\n' >> "$web_home_fail_log"; return 0; }
        ddns_rebuild_cron() { printf 'ddns-cron-fail\n' >> "$web_home_fail_log"; return 9; }
        _cf_get_origin_ruleset() { printf 'origin-rules-should-not-run\n' >> "$web_home_fail_log"; return 1; }
        _cf_put_origin_ruleset() { printf 'origin-put-should-not-run\n' >> "$web_home_fail_log"; return 0; }
        _cf_api() { printf 'ssl-should-not-run\n' >> "$web_home_fail_log"; printf '{"success":true}\n'; }
        cron_add_job() { printf 'cert-cron-should-not-run\n' >> "$web_home_fail_log"; return 0; }
        _web_cleanup_domain() {
            printf 'cleanup-domain|%s|%s\n' "$1" "${2:-}" >> "$web_home_fail_log"
            rm -f "${CERT_HOOKS_DIR}/renew-${1}.sh" "$CONFIG_DIR/${1}.conf" "$DDNS_CONFIG_DIR/${1}.conf" "/root/.cloudflare-${1}.ini"
            rm -rf "${CERT_PATH_PREFIX}/${1}"
            return 0
        }
        confirm() { [[ "$1" == *"开始执行"* ]]; }
        printf 'tok-home-runtime\n1\nhome\n5244\n8443\n7\n' | web_home_expose
    ) > "$tmp_root/web-home-fail.out" 2>&1; then
        fail "Web 家宽暴露 DDNS cron 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-home-fail.out" 2>/dev/null || true
    elif grep -Fxq 'ddns-cron-fail' "$web_home_fail_log" \
         && grep -Fq 'dns-restore|zone-home-runtime|tok-home-runtime|home.example.com|[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]' "$web_home_fail_log" \
         && grep -Fxq "cleanup-domain|${web_home_domain}|quiet" "$web_home_fail_log" \
         && [[ ! -e "$web_home_fail_root/managed/${web_home_domain}.conf" ]] \
         && ! grep -q 'cert-cron-should-not-run\|ssl-should-not-run\|origin-put-should-not-run\|origin-restore-should-not-run' "$web_home_fail_log"; then
        pass "Web 家宽暴露 DDNS cron 失败时中止、恢复 DNS 且不继续写最终配置"
    else
        fail "Web 家宽暴露 DDNS cron 失败中止路径异常"
        sed 's/^/    /' "$tmp_root/web-home-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$web_home_fail_log" 2>/dev/null || true
        find "$web_home_fail_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi

    rm -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
    web_home_tail_cron_log="$tmp_root/web-home-tail-cron.log"
    web_home_tail_cron_root="$tmp_root/web-home-tail-cron"
    mkdir -p "$web_home_tail_cron_root/cert" "$web_home_tail_cron_root/managed" "$web_home_tail_cron_root/ddns" "$web_home_le_live"
    printf 'home-runtime-fullchain\n' > "$web_home_le_live/fullchain.pem"
    printf 'home-runtime-privkey\n' > "$web_home_le_live/privkey.pem"
    if (
        CERT_PATH_PREFIX="$web_home_tail_cron_root/cert"
        CONFIG_DIR="$web_home_tail_cron_root/managed"
        DDNS_CONFIG_DIR="$web_home_tail_cron_root/ddns"
        DDNS_UPDATE_SCRIPT="$web_home_tail_cron_root/ddns-update.sh"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_verify_token() { return 0; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-home-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        _cf_dns_snapshot_records() { printf '[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]\n'; }
        _cf_dns_restore_records() { printf 'dns-restore|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$web_home_tail_cron_log"; return 0; }
        _cf_origin_rules_restore() { printf 'origin-restore|%s|%s|%s\n' "$1" "$2" "$3" >> "$web_home_tail_cron_log"; return 0; }
        _cf_dns_delete() { return 0; }
        _cf_update_dns_record() { return 0; }
        get_public_ipv4() { printf '198.51.100.45\n'; }
        _nginx_deploy_conf() { return 0; }
        _ensure_ssl_params() { :; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n' "$1"; }
        firewall_allow_tcp_port() { return 2; }
        certbot() { return 0; }
        ddns_create_script() { printf '#!/usr/bin/env bash\nexit 0\n' > "$DDNS_UPDATE_SCRIPT"; chmod 755 "$DDNS_UPDATE_SCRIPT"; }
        ddns_rebuild_cron() { return 0; }
        _cf_get_origin_ruleset() { printf '{"success":true,"result":{"rules":[]}}\n'; }
        _cf_put_origin_ruleset() { return 0; }
        _cf_api() { printf '{"success":true}\n'; }
        cron_add_job() { printf 'cert-cron-fail|%s|%s\n' "$1" "$2" >> "$web_home_tail_cron_log"; return 17; }
        _web_cleanup_domain() {
            printf 'cleanup-domain|%s|%s\n' "$1" "${2:-}" >> "$web_home_tail_cron_log"
            rm -f "${CERT_HOOKS_DIR}/renew-${1}.sh" "$CONFIG_DIR/${1}.conf" "$DDNS_CONFIG_DIR/${1}.conf" "/root/.cloudflare-${1}.ini"
            rm -rf "${CERT_PATH_PREFIX}/${1}"
            return 0
        }
        confirm() { [[ "$1" == *"开始执行"* ]]; }
        printf 'tok-home-runtime\n1\nhome\n5244\n8443\n7\n' | web_home_expose
    ) > "$tmp_root/web-home-tail-cron.out" 2>&1; then
        fail "Web 家宽暴露续签 cron 安装失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-home-tail-cron.out" 2>/dev/null || true
    elif grep -Fq "cert-cron-fail|CertRenew_${web_home_domain}|" "$web_home_tail_cron_log" \
         && grep -Fq 'origin-restore|tok-home-runtime|zone-home-runtime|[]' "$web_home_tail_cron_log" \
         && grep -Fq 'dns-restore|zone-home-runtime|tok-home-runtime|home.example.com|[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]' "$web_home_tail_cron_log" \
         && grep -Fxq "cleanup-domain|${web_home_domain}|quiet" "$web_home_tail_cron_log" \
         && [[ ! -e "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" ]] \
         && [[ ! -e "$web_home_tail_cron_root/managed/${web_home_domain}.conf" ]] \
         && ! grep -q '家宽公网暴露配置完成' "$tmp_root/web-home-tail-cron.out"; then
        pass "Web 家宽暴露续签 cron 安装失败时中止、恢复 CF 远端并清理本地半成品"
    else
        fail "Web 家宽暴露续签 cron 安装失败清理路径异常"
        sed 's/^/    /' "$tmp_root/web-home-tail-cron.out" 2>/dev/null || true
        sed 's/^/    /' "$web_home_tail_cron_log" 2>/dev/null || true
        find "$web_home_tail_cron_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi

    rm -f "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh"
    web_home_tail_config_log="$tmp_root/web-home-tail-config.log"
    web_home_tail_config_root="$tmp_root/web-home-tail-config"
    mkdir -p "$web_home_tail_config_root/cert" "$web_home_tail_config_root/managed" "$web_home_tail_config_root/ddns" "$web_home_le_live"
    printf 'home-runtime-fullchain\n' > "$web_home_le_live/fullchain.pem"
    printf 'home-runtime-privkey\n' > "$web_home_le_live/privkey.pem"
    if (
        CERT_PATH_PREFIX="$web_home_tail_config_root/cert"
        CONFIG_DIR="$web_home_tail_config_root/managed"
        DDNS_CONFIG_DIR="$web_home_tail_config_root/ddns"
        DDNS_UPDATE_SCRIPT="$web_home_tail_config_root/ddns-update.sh"
        EMAIL="ops@example.com"
        real_write_file_atomic_def="$(declare -f write_file_atomic)"
        eval "${real_write_file_atomic_def/write_file_atomic/_real_write_file_atomic}"
        write_file_atomic() {
            if [[ "${1:-}" == "$CONFIG_DIR/${web_home_domain}.conf" ]]; then
                printf 'config-write-fail|%s\n' "$1" >> "$web_home_tail_config_log"
                return 23
            fi
            _real_write_file_atomic "$@"
        }
        pause() { :; }
        web_env_check() { return 0; }
        _cf_verify_token() { return 0; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-home-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        _cf_dns_snapshot_records() { printf '[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]\n'; }
        _cf_dns_restore_records() { printf 'dns-restore|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$web_home_tail_config_log"; return 0; }
        _cf_origin_rules_restore() { printf 'origin-restore|%s|%s|%s\n' "$1" "$2" "$3" >> "$web_home_tail_config_log"; return 0; }
        _cf_dns_delete() { return 0; }
        _cf_update_dns_record() { return 0; }
        get_public_ipv4() { printf '198.51.100.45\n'; }
        _nginx_deploy_conf() { return 0; }
        _ensure_ssl_params() { :; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n' "$1"; }
        firewall_allow_tcp_port() { return 2; }
        certbot() { return 0; }
        ddns_create_script() { printf '#!/usr/bin/env bash\nexit 0\n' > "$DDNS_UPDATE_SCRIPT"; chmod 755 "$DDNS_UPDATE_SCRIPT"; }
        ddns_rebuild_cron() { return 0; }
        _cf_get_origin_ruleset() { printf '{"success":true,"result":{"rules":[]}}\n'; }
        _cf_put_origin_ruleset() { return 0; }
        _cf_api() { printf '{"success":true}\n'; }
        cron_add_job() { printf 'cert-cron-ok|%s|%s\n' "$1" "$2" >> "$web_home_tail_config_log"; return 0; }
        _web_cleanup_domain() {
            printf 'cleanup-domain|%s|%s\n' "$1" "${2:-}" >> "$web_home_tail_config_log"
            rm -f "${CERT_HOOKS_DIR}/renew-${1}.sh" "$CONFIG_DIR/${1}.conf" "$DDNS_CONFIG_DIR/${1}.conf" "/root/.cloudflare-${1}.ini"
            rm -rf "${CERT_PATH_PREFIX}/${1}"
            return 0
        }
        confirm() { [[ "$1" == *"开始执行"* ]]; }
        printf 'tok-home-runtime\n1\nhome\n5244\n8443\n7\n' | web_home_expose
    ) > "$tmp_root/web-home-tail-config.out" 2>&1; then
        fail "Web 家宽暴露管理配置写入失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-home-tail-config.out" 2>/dev/null || true
    elif grep -Fxq "config-write-fail|$web_home_tail_config_root/managed/${web_home_domain}.conf" "$web_home_tail_config_log" \
         && grep -Fq 'origin-restore|tok-home-runtime|zone-home-runtime|[]' "$web_home_tail_config_log" \
         && grep -Fq 'dns-restore|zone-home-runtime|tok-home-runtime|home.example.com|[{"type":"A","name":"home.example.com","content":"198.51.100.7","ttl":1,"proxied":true}]' "$web_home_tail_config_log" \
         && grep -Fxq "cleanup-domain|${web_home_domain}|quiet" "$web_home_tail_config_log" \
         && [[ ! -e "${CERT_HOOKS_DIR}/renew-${web_home_domain}.sh" ]] \
         && [[ ! -e "$web_home_tail_config_root/managed/${web_home_domain}.conf" ]] \
         && ! grep -q '家宽公网暴露配置完成' "$tmp_root/web-home-tail-config.out"; then
        pass "Web 家宽暴露管理配置写入失败时中止、恢复 CF 远端并清理本地半成品"
    else
        fail "Web 家宽暴露管理配置写入失败清理路径异常"
        sed 's/^/    /' "$tmp_root/web-home-tail-config.out" 2>/dev/null || true
        sed 's/^/    /' "$web_home_tail_config_log" 2>/dev/null || true
        find "$web_home_tail_config_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
else
    skip "非 root，跳过 Web 家宽暴露实体机 mock"
fi

echo ""
echo "== Web add domain runtime mock =="
if [[ "$(id -u)" -eq 0 ]]; then
    if [[ "$web_domain_hook_touched" -eq 0 && -f "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" ]]; then
        web_domain_hook_backup="$tmp_root/web-domain-hook.backup"
        cp -a "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" "$web_domain_hook_backup"
    fi
    web_domain_hook_touched=1
    rm -f "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh"
    if [[ "$web_domain_cred_touched" -eq 0 && -f "/root/.cloudflare-${web_domain_domain}.ini" ]]; then
        web_domain_cred_backup="$tmp_root/web-domain-cred.backup"
        cp -a "/root/.cloudflare-${web_domain_domain}.ini" "$web_domain_cred_backup"
    fi
    web_domain_cred_touched=1
    rm -f "/root/.cloudflare-${web_domain_domain}.ini"
    if [[ "$web_domain_le_touched" -eq 0 && -e "/etc/letsencrypt/live/${web_domain_domain}" ]]; then
        web_domain_le_backup="$tmp_root/web-domain-le.backup"
        cp -a "/etc/letsencrypt/live/${web_domain_domain}" "$web_domain_le_backup"
    fi
    web_domain_le_touched=1
    rm -rf "/etc/letsencrypt/live/${web_domain_domain}"

    web_domain_root="$tmp_root/web-domain"
    web_domain_cert_prefix="$web_domain_root/cert"
    web_domain_config_dir="$web_domain_root/managed"
    web_domain_ddns_dir="$web_domain_root/ddns"
    web_domain_le_live="/etc/letsencrypt/live/${web_domain_domain}"
    mkdir -p "$web_domain_cert_prefix" "$web_domain_config_dir" "$web_domain_ddns_dir"
    rm -rf "$web_domain_le_live"

    web_domain_log="$tmp_root/web-domain.log"
    if (
        CERT_PATH_PREFIX="$web_domain_cert_prefix"
        CONFIG_DIR="$web_domain_config_dir"
        DDNS_CONFIG_DIR="$web_domain_ddns_dir"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_read_token() { printf -v "$1" '%s' 'tok-domain-runtime'; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-domain-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        get_public_ipv4() { printf '198.51.100.46\n'; }
        get_public_ipv6() { return 1; }
        _cf_dns_snapshot_records() { printf '[]\n'; }
        _cf_dns_restore_records() { printf 'unexpected-dns-restore\n' >> "$web_domain_log"; return 1; }
        _cf_update_dns_record() { printf 'cf-upsert|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$web_domain_log"; return 0; }
        _ensure_ssl_params() { printf 'ensure-ssl\n' >> "$web_domain_log"; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n    listen [::]:%s ssl http2;\n' "$1" "$1"; }
        _nginx_deploy_conf() { printf 'nginx-deploy|%s\n%s\n' "$1" "$2" >> "$web_domain_log"; return 0; }
        ufw_is_active() { return 1; }
        certbot() {
            printf 'certbot|%s\n' "$*" >> "$web_domain_log"
            case "$*" in
                certonly*)
                    mkdir -p "$web_domain_le_live"
                    printf 'domain-runtime-fullchain\n' > "$web_domain_le_live/fullchain.pem"
                    printf 'domain-runtime-privkey\n' > "$web_domain_le_live/privkey.pem"
                    ;;
                certificates)
                    [[ -e "$web_domain_le_live" ]] && printf 'Certificate Name: %s\n' "$web_domain_domain"
                    ;;
                delete*)
                    rm -rf "$web_domain_le_live"
                    ;;
            esac
            return 0
        }
        cron_add_job() { printf 'cron-add|%s|%s\n' "$1" "$2" >> "$web_domain_log"; return 0; }
        ddns_setup() {
            local domain="$1" token="$2" zone_id="$3" ipv4="$4" ipv6="$5" proxied="$6"
            printf 'ddns-setup|%s|%s|%s|%s|%s|%s\n' "$domain" "$token" "$zone_id" "$ipv4" "$ipv6" "$proxied" >> "$web_domain_log"
            mkdir -p "$DDNS_CONFIG_DIR"
            write_private_file_atomic "$DDNS_CONFIG_DIR/${domain}.conf" "DDNS_DOMAIN=\"$domain\"
DDNS_TOKEN=\"$token\"
DDNS_ZONE_ID=\"$zone_id\"
DDNS_IPV4=\"$ipv4\"
DDNS_IPV6=\"$ipv6\"
DDNS_PROXIED=\"$proxied\"
DDNS_INTERVAL=\"5\""
        }
        confirm() {
            printf 'confirm|%s\n' "$1" >> "$web_domain_log"
            return 0
        }
        printf '1\npanel\n\n\n1\n8080\n1\ny\n' | web_add_domain
    ) > "$tmp_root/web-domain.out" 2>&1 \
       && [[ -f "$web_domain_cert_prefix/${web_domain_domain}/fullchain.pem" ]] \
       && [[ -f "$web_domain_cert_prefix/${web_domain_domain}/privkey.pem" ]] \
       && [[ "$(stat -c '%a' "$web_domain_cert_prefix/${web_domain_domain}/privkey.pem" 2>/dev/null)" == "600" ]] \
       && [[ -x "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" ]] \
       && grep -Fq 'copy_cert_pair_atomic' "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" \
       && grep -Fq 'LOCAL_PROXY_PASS="http://127.0.0.1:8080"' "$web_domain_config_dir/${web_domain_domain}.conf" \
       && grep -Fxq 'DDNS_PROXIED="true"' "$web_domain_ddns_dir/${web_domain_domain}.conf" \
       && grep -Fxq 'cf-upsert|zone-domain-runtime|tok-domain-runtime|panel.example.com|A|198.51.100.46|true' "$web_domain_log" \
       && grep -Fq "nginx-deploy|${web_domain_domain}" "$web_domain_log" \
       && grep -Fq "cron-add|CertRenew_${web_domain_domain}|" "$web_domain_log" \
       && grep -Fxq 'ddns-setup|panel.example.com|tok-domain-runtime|zone-domain-runtime|true|false|true' "$web_domain_log" \
       && ! find "$web_domain_root" -name '.tmp.server-manage.*' -print -quit | grep -q .; then
        pass "Web 添加域名在实体机 mock 下落地证书/Nginx/hook/domain/DDNS 配置"
    else
        fail "Web 添加域名实体机 mock 成功路径异常"
        sed 's/^/    /' "$tmp_root/web-domain.out" 2>/dev/null || true
        sed 's/^/    /' "$web_domain_log" 2>/dev/null || true
        find "$web_domain_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi

    web_domain_fail_root="$tmp_root/web-domain-fail"
    web_domain_fail_log="$tmp_root/web-domain-fail.log"
    rm -rf "$web_domain_le_live" \
           "$web_domain_cert_prefix/${web_domain_domain}" \
           "$web_domain_config_dir/${web_domain_domain}.conf" \
           "$web_domain_ddns_dir/${web_domain_domain}.conf"
    rm -f "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" "/root/.cloudflare-${web_domain_domain}.ini"
    mkdir -p "$web_domain_fail_root/cert" "$web_domain_fail_root/managed" "$web_domain_fail_root/ddns"
    if (
        CERT_PATH_PREFIX="$web_domain_fail_root/cert"
        CONFIG_DIR="$web_domain_fail_root/managed"
        DDNS_CONFIG_DIR="$web_domain_fail_root/ddns"
        EMAIL="ops@example.com"
        pause() { :; }
        web_env_check() { return 0; }
        _cf_read_token() { printf -v "$1" '%s' 'tok-domain-runtime'; }
        _cf_list_zones() { printf '{"success":true,"result":[{"name":"example.com","id":"zone-domain-runtime"}]}\n'; }
        _cf_api_ok() { jq -e '.success == true' >/dev/null 2>&1 <<< "${1:-}"; }
        _cf_api_err() { printf 'mock-error'; }
        get_public_ipv4() { printf '198.51.100.46\n'; }
        get_public_ipv6() { return 1; }
        _cf_dns_snapshot_records() { printf '[{"type":"A","name":"panel.example.com","content":"198.51.100.9","ttl":1,"proxied":false}]\n'; }
        _cf_dns_restore_records() {
            printf 'dns-restore|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" >> "$web_domain_fail_log"
            return 0
        }
        _cf_update_dns_record() { printf 'cf-upsert|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$web_domain_fail_log"; return 0; }
        _ensure_ssl_params() { :; }
        _nginx_tls_http2_block() { printf '    listen %s ssl http2;\n' "$1"; }
        _nginx_deploy_conf() { printf 'nginx-deploy|%s\n' "$1" >> "$web_domain_fail_log"; return 0; }
        nginx() { printf 'cleanup-nginx|%s\n' "$*" >> "$web_domain_fail_log"; return 0; }
        _nginx_reload() { printf 'cleanup-nginx-reload\n' >> "$web_domain_fail_log"; return 0; }
        ufw_is_active() { return 1; }
        certbot() {
            printf 'certbot|%s\n' "$*" >> "$web_domain_fail_log"
            case "$*" in
                certonly*)
                    mkdir -p "$web_domain_le_live"
                    printf 'domain-runtime-fullchain\n' > "$web_domain_le_live/fullchain.pem"
                    printf 'domain-runtime-privkey\n' > "$web_domain_le_live/privkey.pem"
                    ;;
                certificates)
                    [[ -e "$web_domain_le_live" ]] && printf 'Certificate Name: %s\n' "$web_domain_domain"
                    ;;
                delete*)
                    rm -rf "$web_domain_le_live"
                    ;;
            esac
            return 0
        }
        cron_add_job() { printf 'cert-cron|%s\n' "$1" >> "$web_domain_fail_log"; return 0; }
        cron_remove_job() { printf 'cleanup-cron-remove|%s\n' "$1" >> "$web_domain_fail_log"; return 0; }
        ddns_rebuild_cron() { printf 'cleanup-ddns-rebuild\n' >> "$web_domain_fail_log"; return 0; }
        reality_coexist_refresh() { printf 'cleanup-coexist-refresh\n' >> "$web_domain_fail_log"; return 0; }
        log_action() { printf 'cleanup-log|%s\n' "$1" >> "$web_domain_fail_log"; }
        ddns_setup() { printf 'ddns-fail\n' >> "$web_domain_fail_log"; return 23; }
        confirm() { return 0; }
        printf '1\npanel\n\n\n1\n8080\n1\ny\n' | web_add_domain
    ) > "$tmp_root/web-domain-fail.out" 2>&1; then
        fail "Web 添加域名 DDNS 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-domain-fail.out" 2>/dev/null || true
    elif grep -Fxq 'ddns-fail' "$web_domain_fail_log" \
         && grep -Fxq 'cf-upsert|zone-domain-runtime|tok-domain-runtime|panel.example.com|A|198.51.100.46|true' "$web_domain_fail_log" \
         && grep -Fq 'dns-restore|zone-domain-runtime|tok-domain-runtime|panel.example.com|[{"type":"A","name":"panel.example.com","content":"198.51.100.9","ttl":1,"proxied":false}]' "$web_domain_fail_log" \
         && grep -Fxq "cleanup-cron-remove|CertRenew_${web_domain_domain}" "$web_domain_fail_log" \
         && grep -Fq "certbot|delete --cert-name ${web_domain_domain} --non-interactive" "$web_domain_fail_log" \
         && [[ ! -e "$web_domain_fail_root/cert/${web_domain_domain}" ]] \
         && [[ ! -e "$web_domain_fail_root/managed/${web_domain_domain}.conf" ]] \
         && [[ ! -e "$web_domain_fail_root/ddns/${web_domain_domain}.conf" ]] \
         && [[ ! -e "${CERT_HOOKS_DIR}/renew-${web_domain_domain}.sh" ]] \
         && [[ ! -e "/root/.cloudflare-${web_domain_domain}.ini" ]] \
         && [[ ! -e "$web_domain_le_live" ]]; then
        pass "Web 添加域名 DDNS 失败时返回非 0、恢复 CF DNS 并清理本地半成品"
    else
        fail "Web 添加域名 DDNS 失败路径未恢复 CF DNS 或未清理本地半成品"
        sed 's/^/    /' "$tmp_root/web-domain-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$web_domain_fail_log" 2>/dev/null || true
        find "$web_domain_fail_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
else
    skip "非 root，跳过 Web 添加域名实体机 mock"
fi

echo ""
echo "== Web cleanup runtime mock =="
if [[ "$(id -u)" -eq 0 ]]; then
    mkdir -p "$CERT_HOOKS_DIR" /etc/nginx/sites-available /etc/nginx/sites-enabled
    if [[ "$web_cleanup_hook_touched" -eq 0 && -f "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh" ]]; then
        web_cleanup_hook_backup="$tmp_root/web-cleanup-hook.backup"
        cp -a "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh" "$web_cleanup_hook_backup"
    fi
    web_cleanup_hook_touched=1
    rm -f "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh"
    if [[ "$web_cleanup_legacy_hook_touched" -eq 0 && -f "/root/cert-renew-hook-${web_cleanup_domain}.sh" ]]; then
        web_cleanup_legacy_hook_backup="$tmp_root/web-cleanup-legacy-hook.backup"
        cp -a "/root/cert-renew-hook-${web_cleanup_domain}.sh" "$web_cleanup_legacy_hook_backup"
    fi
    web_cleanup_legacy_hook_touched=1
    rm -f "/root/cert-renew-hook-${web_cleanup_domain}.sh"
    if [[ "$web_cleanup_cred_touched" -eq 0 && -f "/root/.cloudflare-${web_cleanup_domain}.ini" ]]; then
        web_cleanup_cred_backup="$tmp_root/web-cleanup-cred.backup"
        cp -a "/root/.cloudflare-${web_cleanup_domain}.ini" "$web_cleanup_cred_backup"
    fi
    web_cleanup_cred_touched=1
    rm -f "/root/.cloudflare-${web_cleanup_domain}.ini"
    if [[ "$web_cleanup_nginx_avail_touched" -eq 0 && ( -e "/etc/nginx/sites-available/${web_cleanup_domain}.conf" || -L "/etc/nginx/sites-available/${web_cleanup_domain}.conf" ) ]]; then
        web_cleanup_nginx_avail_backup="$tmp_root/web-cleanup-nginx-avail.backup"
        cp -a "/etc/nginx/sites-available/${web_cleanup_domain}.conf" "$web_cleanup_nginx_avail_backup"
    fi
    web_cleanup_nginx_avail_touched=1
    rm -f "/etc/nginx/sites-available/${web_cleanup_domain}.conf"
    if [[ "$web_cleanup_nginx_enabled_touched" -eq 0 && ( -e "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf" || -L "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf" ) ]]; then
        web_cleanup_nginx_enabled_backup="$tmp_root/web-cleanup-nginx-enabled.backup"
        cp -a "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf" "$web_cleanup_nginx_enabled_backup"
    fi
    web_cleanup_nginx_enabled_touched=1
    rm -f "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf"

    web_cleanup_root="$tmp_root/web-cleanup"
    web_cleanup_cert_prefix="$web_cleanup_root/cert"
    web_cleanup_config_dir="$web_cleanup_root/managed"
    web_cleanup_ddns_dir="$web_cleanup_root/ddns"
    mkdir -p "$web_cleanup_cert_prefix/${web_cleanup_domain}" \
             "$web_cleanup_cert_prefix/${web_cleanup_domain}.keep" \
             "$web_cleanup_config_dir" "$web_cleanup_ddns_dir"
    printf 'cleanup-fullchain\n' > "$web_cleanup_cert_prefix/${web_cleanup_domain}/fullchain.pem"
    printf 'keep-cert\n' > "$web_cleanup_cert_prefix/${web_cleanup_domain}.keep/marker"
    printf 'DOMAIN="%s"\n' "$web_cleanup_domain" > "$web_cleanup_config_dir/${web_cleanup_domain}.conf"
    printf 'DOMAIN="%s.keep"\n' "$web_cleanup_domain" > "$web_cleanup_config_dir/${web_cleanup_domain}.keep.conf"
    printf 'ddns-domain\n' > "$web_cleanup_ddns_dir/${web_cleanup_domain}.conf"
    printf 'ddns-origin-domain\n' > "$web_cleanup_ddns_dir/origin.${web_cleanup_domain}.conf"
    printf 'ddns-origin-root\n' > "$web_cleanup_ddns_dir/origin.example.com.conf"
    printf 'ddns-similar\n' > "$web_cleanup_ddns_dir/${web_cleanup_domain}.evil.conf"
    printf 'ddns-other-origin\n' > "$web_cleanup_ddns_dir/origin.other.example.com.conf"
    printf '#!/bin/sh\n' > "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh"
    printf '#!/bin/sh\n' > "/root/cert-renew-hook-${web_cleanup_domain}.sh"
    printf 'dns_cloudflare_api_token = cleanup\n' > "/root/.cloudflare-${web_cleanup_domain}.ini"
    printf 'server_name %s;\n' "$web_cleanup_domain" > "/etc/nginx/sites-available/${web_cleanup_domain}.conf"
    printf 'server_name %s;\n' "$web_cleanup_domain" > "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf"

    web_cleanup_log="$tmp_root/web-cleanup.log"
    if (
        CERT_PATH_PREFIX="$web_cleanup_cert_prefix"
        CONFIG_DIR="$web_cleanup_config_dir"
        DDNS_CONFIG_DIR="$web_cleanup_ddns_dir"
        certbot() {
            if [[ "${1:-}" == "certificates" ]]; then
                printf 'Certificate Name: %s\n' "$web_cleanup_domain"
                return 0
            fi
            printf 'certbot-delete|%s\n' "$*" >> "$web_cleanup_log"
            return 0
        }
        nginx() {
            [[ "${1:-}" == "-t" ]] || return 1
            printf 'nginx-test\n' >> "$web_cleanup_log"
            return 0
        }
        _nginx_reload() { printf 'nginx-reload\n' >> "$web_cleanup_log"; return 0; }
        cron_remove_job() { printf 'cron-remove|%s\n' "$1" >> "$web_cleanup_log"; return 0; }
        ddns_rebuild_cron() { printf 'ddns-rebuild\n' >> "$web_cleanup_log"; return 0; }
        reality_coexist_refresh() { printf 'coexist-refresh\n' >> "$web_cleanup_log"; return 0; }
        log_action() { printf 'log-action|%s\n' "$1" >> "$web_cleanup_log"; }
        _web_cleanup_domain "$web_cleanup_domain" quiet
    ) > "$tmp_root/web-cleanup.out" 2>&1 \
       && [[ ! -e "$web_cleanup_cert_prefix/${web_cleanup_domain}" ]] \
       && [[ -f "$web_cleanup_cert_prefix/${web_cleanup_domain}.keep/marker" ]] \
       && [[ ! -e "$web_cleanup_config_dir/${web_cleanup_domain}.conf" ]] \
       && [[ -f "$web_cleanup_config_dir/${web_cleanup_domain}.keep.conf" ]] \
       && [[ ! -e "$web_cleanup_ddns_dir/${web_cleanup_domain}.conf" ]] \
       && [[ ! -e "$web_cleanup_ddns_dir/origin.${web_cleanup_domain}.conf" ]] \
       && [[ ! -e "$web_cleanup_ddns_dir/origin.example.com.conf" ]] \
       && [[ -f "$web_cleanup_ddns_dir/${web_cleanup_domain}.evil.conf" ]] \
       && [[ -f "$web_cleanup_ddns_dir/origin.other.example.com.conf" ]] \
       && [[ ! -e "${CERT_HOOKS_DIR}/renew-${web_cleanup_domain}.sh" ]] \
       && [[ ! -e "/root/cert-renew-hook-${web_cleanup_domain}.sh" ]] \
       && [[ ! -e "/root/.cloudflare-${web_cleanup_domain}.ini" ]] \
       && [[ ! -e "/etc/nginx/sites-available/${web_cleanup_domain}.conf" ]] \
       && [[ ! -e "/etc/nginx/sites-enabled/${web_cleanup_domain}.conf" ]] \
       && grep -Fxq "certbot-delete|delete --cert-name ${web_cleanup_domain} --non-interactive" "$web_cleanup_log" \
       && grep -Fxq "cron-remove|CertRenew_${web_cleanup_domain}" "$web_cleanup_log" \
       && grep -Fxq "cron-remove|cert-renew-hook-${web_cleanup_domain}.sh" "$web_cleanup_log" \
       && grep -Fxq 'ddns-rebuild' "$web_cleanup_log" \
       && grep -Fxq 'nginx-test' "$web_cleanup_log" \
       && grep -Fxq 'nginx-reload' "$web_cleanup_log" \
       && grep -Fxq 'coexist-refresh' "$web_cleanup_log" \
       && grep -Fxq "log-action|Cleanup domain: ${web_cleanup_domain} (5 items)" "$web_cleanup_log"; then
        pass "Web 域名清理实体机 mock 精确删除目标证书/Nginx/hook/DDNS/配置并保留相似文件"
    else
        fail "Web 域名清理实体机 mock 行为异常"
        sed 's/^/    /' "$tmp_root/web-cleanup.out" 2>/dev/null || true
        sed 's/^/    /' "$web_cleanup_log" 2>/dev/null || true
        find "$web_cleanup_root" -maxdepth 4 -ls 2>/dev/null | sed 's/^/    /' || true
        ls -la "$CERT_HOOKS_DIR" "/etc/nginx/sites-available" "/etc/nginx/sites-enabled" 2>/dev/null | sed 's/^/    /' || true
    fi

    web_delete_root="$tmp_root/web-delete"
    web_delete_log="$tmp_root/web-delete.log"
    mkdir -p "$web_delete_root/managed"
    printf 'DOMAIN="delete-fail.example.com"\n' > "$web_delete_root/managed/delete-fail.example.com.conf"
    if (
        CONFIG_DIR="$web_delete_root/managed"
        pause() { :; }
        confirm() { return 0; }
        _web_cleanup_domain() { printf 'cleanup-fail|%s\n' "$1" >> "$web_delete_log"; return 12; }
        log_action() { printf 'log-action|%s\n' "$1" >> "$web_delete_log"; }
        printf '1\n' | web_delete_domain
    ) > "$tmp_root/web-delete.out" 2>&1; then
        fail "Web 删除域名在底层清理失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/web-delete.out" 2>/dev/null || true
        sed 's/^/    /' "$web_delete_log" 2>/dev/null || true
    elif grep -Fxq 'cleanup-fail|delete-fail.example.com' "$web_delete_log" \
         && ! grep -q 'log-action|Deleted domain config' "$web_delete_log"; then
        pass "Web 删除域名会传播底层清理失败且不写成功日志"
    else
        fail "Web 删除域名清理失败路径日志/返回异常"
        sed 's/^/    /' "$tmp_root/web-delete.out" 2>/dev/null || true
        sed 's/^/    /' "$web_delete_log" 2>/dev/null || true
    fi
else
    skip "非 root，跳过 Web 域名清理实体机 mock"
fi

echo ""
echo "== DDNS generated parser =="
ddns_dir="$tmp_root/ddns"
ddns_log="$tmp_root/ddns.log"
ddns_script="$tmp_root/ddns-update.sh"
DDNS_CONFIG_DIR="$ddns_dir"
DDNS_LOG="$ddns_log"
DDNS_UPDATE_SCRIPT="$ddns_script"
ddns_create_script >/dev/null 2>&1
if [[ -x "$ddns_script" ]] && bash -n "$ddns_script"; then
    pass "DDNS 生成脚本可执行且语法有效"
else
    fail "DDNS 生成脚本不可执行或语法无效"
fi
if grep -q 'DDNS_RUNTIME_DIR="/var/lib/server-manage/ddns"' "$ddns_script" \
   && grep -q 'DDNS_STAMP_DIR="\$DDNS_RUNTIME_DIR/stamps"' "$ddns_script" \
   && grep -q 'exec 200>"\$DDNS_RUNTIME_DIR/update.lock"' "$ddns_script" \
   && grep -q 'chmod 700 /var/lib/server-manage "\$DDNS_RUNTIME_DIR" "\$DDNS_STAMP_DIR"' "$ddns_script" \
   && ! grep -q '/tmp/ddns-state\|/tmp/ddns-update.lock' "$ddns_script"; then
    pass "DDNS 生成脚本运行时锁和 stamp 使用 root 私有目录"
else
    fail "DDNS 生成脚本仍可能使用公共 /tmp 运行时状态"
    sed -n '1,35p' "$ddns_script" | sed 's/^/    /'
fi
if grep -q 'BASH_SOURCE\[0\].*==.*"\$0"' "$ddns_script" \
   && grep -q 'exit "\$failed"' "$ddns_script"; then
    pass "DDNS 生成脚本只在直接执行时跑主循环并汇总失败码"
else
    fail "DDNS 生成脚本缺少 source guard 或失败码汇总"
fi
ddns_lib="$tmp_root/ddns-lib.sh"
{
    grep -m1 '^log()' "$ddns_script"
    awk '/^extract_ipv4\(\)/ { emit=1 } /^if \[\[ "\$\{BASH_SOURCE\[0\]\}" == "\$0" \]\]; then$/ { exit } emit { print }' "$ddns_script"
} > "$ddns_lib"
if [[ "$(id -u)" -eq 0 ]]; then
    good_conf="$ddns_dir/good.conf"
    bad_mode_conf="$ddns_dir/bad-mode.conf"
    bad_syntax_conf="$ddns_dir/bad-syntax.conf"
    cat > "$good_conf" <<'EOF'
DDNS_DOMAIN="good.example.com"
DDNS_TOKEN="token"
DDNS_ZONE_ID="zone"
DDNS_IPV4="true"
DDNS_IPV6="false"
DDNS_PROXIED="false"
DDNS_INTERVAL="5"
EOF
    cp "$good_conf" "$bad_mode_conf"
    {
        printf 'DDNS_DOMAIN="$(touch %s)"\n' "$ddns_pwned"
        printf 'DDNS_TOKEN="token"\n'
        printf 'DDNS_ZONE_ID="zone"\n'
    } > "$bad_syntax_conf"
    chmod 600 "$good_conf" "$bad_syntax_conf"
    chmod 666 "$bad_mode_conf"
    if bash -c 'DDNS_LOG="$1"; source "$2"; parse_ddns_conf "$3"' \
        _ "$ddns_log" "$ddns_lib" "$good_conf" >/dev/null 2>&1; then
        pass "DDNS 生成脚本接受 root:600 合法配置"
    else
        fail "DDNS 生成脚本拒绝合法配置"
    fi
    if bash -c 'DDNS_LOG="$1"; source "$2"; parse_ddns_conf "$3"' \
        _ "$ddns_log" "$ddns_lib" "$bad_mode_conf" >/dev/null 2>&1; then
        fail "DDNS 生成脚本接受了权限过宽配置"
    else
        pass "DDNS 生成脚本拒绝权限过宽配置"
    fi
    rm -f "$ddns_pwned"
    if bash -c 'DDNS_LOG="$1"; source "$2"; parse_ddns_conf "$3"' \
        _ "$ddns_log" "$ddns_lib" "$bad_syntax_conf" >/dev/null 2>&1; then
        fail "DDNS 生成脚本接受了命令替换配置"
    elif [[ -e "$ddns_pwned" ]]; then
        fail "DDNS 生成脚本解析恶意配置时发生命令执行"
        rm -f "$ddns_pwned"
    else
        pass "DDNS 生成脚本拒绝命令替换且未执行"
    fi
    if bash -c 'source "$1"; DDNS_STAMP_DIR="$2"; DDNS_INTERVAL=59; mkdir -p "$DDNS_STAMP_DIR"; ddns_should_run "$3" && ! ddns_should_run "$3"' \
        _ "$ddns_lib" "$tmp_root/ddns-state" "$good_conf" >/dev/null 2>&1; then
        pass "DDNS 生成脚本按 interval 节流且写入临时 stamp"
    else
        fail "DDNS 生成脚本 interval 节流行为异常"
    fi
    ddns_exec_dir="$tmp_root/ddns-exec"
    ddns_exec_log="$tmp_root/ddns-exec.log"
    ddns_exec_script="$tmp_root/ddns-exec-update.sh"
    ddns_exec_mock="$tmp_root/ddns-exec-bin"
    mkdir -p "$ddns_exec_dir" "$ddns_exec_mock"
    sed \
        -e "s|^DDNS_CONFIG_DIR=.*|DDNS_CONFIG_DIR=\"$ddns_exec_dir\"|" \
        -e "s|^DDNS_LOG=.*|DDNS_LOG=\"$ddns_exec_log\"|" \
        -e "s|^DDNS_RUNTIME_DIR=.*|DDNS_RUNTIME_DIR=\"$tmp_root/ddns-exec-runtime\"|" \
        "$ddns_script" > "$ddns_exec_script"
    chmod 755 "$ddns_exec_script"
    cat > "$ddns_exec_dir/fail.example.com.conf" <<'EOF'
DDNS_DOMAIN="fail.example.com"
DDNS_TOKEN="token"
DDNS_ZONE_ID="zone"
DDNS_IPV4="true"
DDNS_IPV6="false"
DDNS_PROXIED="false"
DDNS_INTERVAL="1"
EOF
    chmod 600 "$ddns_exec_dir/fail.example.com.conf"
    cat > "$ddns_exec_mock/curl" <<'EOF'
#!/usr/bin/env bash
case "$*" in
    *4.ipw.cn*) printf '198.51.100.42'; exit 0 ;;
    *dns_records?type=A*) printf '{"success":true,"result":[{"id":"rid","content":"198.51.100.1"}]}'; exit 0 ;;
    *-X\ PUT*|*-X\ POST*) printf '{"success":false}'; exit 0 ;;
esac
printf '{"success":false}'
exit 0
EOF
    chmod 755 "$ddns_exec_mock/curl"
    if PATH="$ddns_exec_mock:$PATH" "$ddns_exec_script" >/dev/null 2>&1; then
        fail "DDNS 生成脚本在 Cloudflare 更新失败时仍返回成功"
    elif grep -q 'update failed' "$ddns_exec_log"; then
        pass "DDNS 生成脚本在 Cloudflare 更新失败时返回非 0"
    else
        fail "DDNS 生成脚本失败路径未写入预期日志"
        sed 's/^/    /' "$ddns_exec_log" 2>/dev/null || true
    fi
    if command -v flock >/dev/null 2>&1; then
        ddns_lock_dir="$tmp_root/ddns-lock"
        ddns_lock_runtime="$tmp_root/ddns-lock-runtime"
        ddns_lock_log="$tmp_root/ddns-lock.log"
        ddns_lock_script="$tmp_root/ddns-lock-update.sh"
        ddns_lock_mock="$tmp_root/ddns-lock-bin"
        ddns_lock_probe="$tmp_root/ddns-lock-curl-ran"
        mkdir -p "$ddns_lock_dir" "$ddns_lock_runtime" "$ddns_lock_mock"
        sed \
            -e "s|^DDNS_CONFIG_DIR=.*|DDNS_CONFIG_DIR=\"$ddns_lock_dir\"|" \
            -e "s|^DDNS_LOG=.*|DDNS_LOG=\"$ddns_lock_log\"|" \
            -e "s|^DDNS_RUNTIME_DIR=.*|DDNS_RUNTIME_DIR=\"$ddns_lock_runtime\"|" \
            "$ddns_script" > "$ddns_lock_script"
        chmod 755 "$ddns_lock_script"
        cat > "$ddns_lock_dir/lock.example.com.conf" <<'EOF'
DDNS_DOMAIN="lock.example.com"
DDNS_TOKEN="token"
DDNS_ZONE_ID="zone"
DDNS_IPV4="true"
DDNS_IPV6="false"
DDNS_PROXIED="false"
DDNS_INTERVAL="1"
EOF
        chmod 600 "$ddns_lock_dir/lock.example.com.conf"
        cat > "$ddns_lock_mock/curl" <<'EOF'
#!/usr/bin/env bash
printf 'curl-ran\n' >> "$DDNS_LOCK_PROBE"
case "$*" in
    *4.ipw.cn*) printf '198.51.100.77'; exit 0 ;;
    *dns_records?type=A*) printf '{"success":true,"result":[{"id":"rid","content":"198.51.100.1"}]}'; exit 0 ;;
    *-X\ PUT*|*-X\ POST*) printf '{"success":true}'; exit 0 ;;
esac
printf '{"success":true,"result":[]}'
EOF
        chmod 755 "$ddns_lock_mock/curl"
        exec 201>"$ddns_lock_runtime/update.lock"
        if flock -n 201; then
            if DDNS_LOCK_PROBE="$ddns_lock_probe" PATH="$ddns_lock_mock:$PATH" "$ddns_lock_script" >/dev/null 2>&1 \
               && [[ ! -e "$ddns_lock_probe" ]]; then
                pass "DDNS 生成脚本已有任务持锁时立即跳过且不触发 curl"
            else
                fail "DDNS 生成脚本持锁跳过行为异常"
                sed 's/^/    /' "$ddns_lock_log" 2>/dev/null || true
                [[ -e "$ddns_lock_probe" ]] && sed 's/^/    /' "$ddns_lock_probe" 2>/dev/null || true
            fi
            flock -u 201 || true
        else
            fail "DDNS 并发锁测试无法建立前置 flock"
        fi
        exec 201>&-
    else
        skip "flock 不存在，跳过 DDNS 并发锁实测"
    fi
else
    skip "非 root，跳过 DDNS owner/mode 实测"
fi

echo ""
echo "== Real crontab command matching =="
if command_exists crontab; then
    find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'server-manage-cron.*' -exec rm -rf {} + 2>/dev/null || true
    saved_cron="$tmp_root/root.cron"
    if crontab -l > "$saved_cron" 2>/dev/null; then
        had_cron=1
    else
        : > "$saved_cron"
    fi
    cron_touched=1
    cron_seed="$tmp_root/seed.cron"
    cat > "$cron_seed" <<'EOF'
# keep wg-watchdog.sh in comment
* * * * * /opt/custom/wg-watchdog.sh --notify
* * * * * /usr/local/bin/wg-watchdog.sh >/dev/null 2>&1
EOF
    if crontab "$cron_seed" >/dev/null 2>&1 \
       && cron_has_job_command /usr/local/bin/wg-watchdog.sh \
       && cron_remove_job_command /usr/local/bin/wg-watchdog.sh >/dev/null 2>&1 \
       && crontab -l | grep -qF '/opt/custom/wg-watchdog.sh --notify' \
       && crontab -l | grep -qF '# keep wg-watchdog.sh in comment' \
       && ! crontab -l | grep -qF '/usr/local/bin/wg-watchdog.sh >/dev/null'; then
        pass "真实 crontab 精确删除目标命令且保留相似行"
    else
        fail "真实 crontab 命令路径删除行为异常"
        crontab -l 2>/dev/null | sed 's/^/    /'
    fi
    if cron_add_job_command /usr/local/bin/wg-watchdog.sh '* * * * * /usr/local/bin/wg-watchdog.sh >/dev/null 2>&1' >/dev/null 2>&1 \
       && [[ "$(crontab -l 2>/dev/null | grep -cF '/usr/local/bin/wg-watchdog.sh')" -eq 1 ]] \
       && crontab -l | grep -qF '/opt/custom/wg-watchdog.sh --notify'; then
        pass "真实 crontab 精确添加/替换目标命令"
    else
        fail "真实 crontab 命令路径添加行为异常"
        crontab -l 2>/dev/null | sed 's/^/    /'
    fi
    if ! find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'server-manage-cron.*' -print -quit 2>/dev/null | grep -q .; then
        pass "真实 crontab helper 未残留公共临时目录"
    else
        fail "真实 crontab helper 残留临时目录"
        find "${TMPDIR:-/tmp}" -maxdepth 1 -type d -name 'server-manage-cron.*' -print 2>/dev/null | sed 's/^/    /'
    fi
    ddns_real_dir="$tmp_root/ddns-real"
    ddns_real_script="$tmp_root/bin/ddns-update.sh"
    DDNS_CONFIG_DIR="$ddns_real_dir"
    DDNS_UPDATE_SCRIPT="$ddns_real_script"
    mkdir -p "$ddns_real_dir"
    printf 'old-token\n' > "$ddns_real_dir/runtime.example.com.conf"
    chmod 666 "$ddns_real_dir/runtime.example.com.conf"
    if ddns_setup_noninteractive "runtime.example.com" "token" "zone" true false false 1 >/dev/null 2>&1 \
       && [[ -f "$ddns_real_dir/runtime.example.com.conf" ]] \
       && [[ "$(stat -c '%a' "$ddns_real_dir/runtime.example.com.conf" 2>/dev/null)" == "600" ]] \
       && [[ -x "$ddns_real_script" ]] \
       && crontab -l 2>/dev/null | grep -qF "* * * * * $ddns_real_script >/dev/null 2>&1"; then
        pass "ddns_setup_noninteractive 真实写入安全配置/脚本并安装 cron"
    else
        fail "ddns_setup_noninteractive 真实落地或 cron 安装异常"
        ls -l "$ddns_real_dir" "$ddns_real_script" 2>/dev/null | sed 's/^/    /' || true
        crontab -l 2>/dev/null | sed 's/^/    /'
    fi
else
    skip "crontab 不存在，跳过真实 cron 实测"
fi

echo ""
echo "== WireGuard Clash template safety =="
wg_clash_runtime_body=$(declare -f _wg_generate_clash_config_impl)
if grep -q 'mktemp "\${output_dir}/.clash-config.yaml.policy.XXXXXX"' <<< "$wg_clash_runtime_body" \
   && grep -q 'chmod 600 "\$_tmpf"' <<< "$wg_clash_runtime_body" \
   && ! grep -q '_tmpf=$(mktemp)' <<< "$wg_clash_runtime_body" \
   && ! grep -q '> "\$_tmpf" && mv "\$_tmpf"' <<< "$wg_clash_runtime_body"; then
    pass "WireGuard Clash nameserver-policy 二次写回使用私有同目录临时文件"
else
    fail "WireGuard Clash nameserver-policy 二次写回仍可能落公共临时文件"
fi

echo ""
echo "== WireGuard compatibility checks =="
if [[ "$PLATFORM" == "debian" ]]; then
    wg_deb_compat_out="$tmp_root/wg-deb-compat.out"
    if wg_deb_check_compat > "$wg_deb_compat_out" 2>&1 \
       && grep -qF 'Debian/Ubuntu 环境兼容性检测' "$wg_deb_compat_out" \
       && grep -qF '平台: Debian/Ubuntu' "$wg_deb_compat_out" \
       && grep -qF 'apt 包管理器可用' "$wg_deb_compat_out" \
       && grep -Eq '本机网络地址|未检测到任何 scope global 的 IPv4 地址' "$wg_deb_compat_out"; then
        pass "Debian WireGuard 兼容性检查在实体机上可完成只读检测"
    else
        fail "Debian WireGuard 兼容性检查实体机输出异常"
        sed 's/^/    /' "$wg_deb_compat_out" 2>/dev/null | head -140 || true
    fi
else
    skip "当前平台非 debian，跳过 Debian WireGuard 兼容性实测"
fi
wg_openwrt_compat_bin="$tmp_root/wg-openwrt-compat-bin"
wg_openwrt_compat_root="$tmp_root/wg-openwrt-root"
wg_openwrt_compat_out="$tmp_root/wg-openwrt-compat.out"
mkdir -p "$wg_openwrt_compat_bin" "$wg_openwrt_compat_root/sys/module/wireguard"
cat > "$wg_openwrt_compat_bin/opkg" <<'EOF_WG_OPENWRT_OPKG'
#!/usr/bin/env bash
case "$*" in
    "list")
        printf 'jq - lightweight JSON processor\n'
        printf 'kmod-wireguard - WireGuard kernel module\n'
        ;;
    "list-installed")
        printf 'wireguard-tools - userspace tooling\n'
        ;;
esac
exit 0
EOF_WG_OPENWRT_OPKG
cat > "$wg_openwrt_compat_bin/uci" <<'EOF_WG_OPENWRT_OK'
#!/usr/bin/env sh
exit 0
EOF_WG_OPENWRT_OK
cat > "$wg_openwrt_compat_bin/nft" <<'EOF_WG_OPENWRT_NFT'
#!/usr/bin/env bash
case "$*" in
    "list tables")
        printf 'table inet fw4\n'
        ;;
    "list chain inet fw4 mangle_prerouting")
        printf 'table inet fw4 { chain mangle_prerouting { type filter hook prerouting priority mangle; policy accept; } }\n'
        ;;
esac
exit 0
EOF_WG_OPENWRT_NFT
cat > "$wg_openwrt_compat_bin/ip" <<'EOF_WG_OPENWRT_IP'
#!/usr/bin/env bash
case "$*" in
    "-4 addr show scope global")
        printf '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n'
        printf '    inet 203.0.113.8/24 brd 203.0.113.255 scope global eth0\n'
        ;;
    "-4 addr show br-lan")
        printf '3: br-lan: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n'
        printf '    inet 192.168.1.1/24 brd 192.168.1.255 scope global br-lan\n'
        ;;
esac
exit 0
EOF_WG_OPENWRT_IP
cat > "$wg_openwrt_compat_bin/sysctl" <<'EOF_WG_OPENWRT_SYSCTL'
#!/usr/bin/env bash
[[ "$*" == "-n net.ipv4.ip_forward" ]] && { printf '1\n'; exit 0; }
exit 0
EOF_WG_OPENWRT_SYSCTL
cat > "$wg_openwrt_compat_bin/lsmod" <<'EOF_WG_OPENWRT_LSMOD'
#!/usr/bin/env bash
printf 'wireguard 90112 0\n'
EOF_WG_OPENWRT_LSMOD
cat > "$wg_openwrt_compat_bin/jq" <<'EOF_WG_OPENWRT_OK'
#!/usr/bin/env sh
exit 0
EOF_WG_OPENWRT_OK
cat > "$wg_openwrt_compat_bin/qrencode" <<'EOF_WG_OPENWRT_OK'
#!/usr/bin/env sh
exit 0
EOF_WG_OPENWRT_OK
cat > "$wg_openwrt_compat_bin/wg" <<'EOF_WG_OPENWRT_OK'
#!/usr/bin/env sh
exit 0
EOF_WG_OPENWRT_OK
chmod +x "$wg_openwrt_compat_bin"/*
old_platform="$PLATFORM"
if (
        PATH="$wg_openwrt_compat_bin:$PATH"
        PLATFORM="openwrt"
        wg_check_openwrt_compat
    ) > "$wg_openwrt_compat_out" 2>&1 \
   && grep -qF 'OpenWrt 环境兼容性检测' "$wg_openwrt_compat_out" \
   && grep -qF '平台: OpenWrt' "$wg_openwrt_compat_out" \
   && grep -qF 'opkg 包管理器可用' "$wg_openwrt_compat_out" \
   && grep -qF 'nftables 可用且有权限' "$wg_openwrt_compat_out" \
   && grep -qF 'fw4 mangle_prerouting 链存在' "$wg_openwrt_compat_out" \
   && grep -qF 'br-lan 网段: 192.168.1.1/24' "$wg_openwrt_compat_out" \
   && grep -qF 'eth0: 203.0.113.8 (公网)' "$wg_openwrt_compat_out"; then
    pass "OpenWrt WireGuard 兼容性检查在实体机 mock 下覆盖健康路径"
else
    fail "OpenWrt WireGuard 兼容性检查实体机 mock 输出异常"
    sed 's/^/    /' "$wg_openwrt_compat_out" 2>/dev/null | head -180 || true
fi
PLATFORM="$old_platform"

echo ""
echo "== WireGuard Debian config generation =="
if [[ "$(id -u)" -eq 0 ]] && command_exists jq; then
    wg_backup="$tmp_root/wireguard.backup"
    if [[ -d /etc/wireguard ]]; then
        cp -a /etc/wireguard "$wg_backup"
    fi
    wg_touched=1
    rm -rf /etc/wireguard
    if wg_deb_db_init && [[ -f "$WG_DEB_DB_FILE" ]] && [[ "$(stat -c '%a' "$WG_DEB_DB_FILE" 2>/dev/null)" == "600" ]]; then
        pass "WireGuard 共享 DB 初始化权限为 600"
    else
        fail "WireGuard 共享 DB 初始化权限异常"
        ls -l "$WG_DEB_DB_FILE" 2>/dev/null || true
    fi
    cat > "$WG_DEB_DB_FILE" <<'EOF'
{
  "server": {
    "name": "runtime-wg",
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "port": "51820",
    "endpoint": "2001:db8::10",
    "subnet": "10.77.0.0/24",
    "ip": "10.77.0.1",
    "dns": "1.1.1.1",
    "mtu": "1420",
    "default_iface": "eth0"
  },
  "peers": [
    {
      "name": "client1",
      "private_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
      "public_key": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
      "preshared_key": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
      "ip": "10.77.0.2",
      "enabled": true,
      "is_gateway": false,
      "client_allowed_ips": "0.0.0.0/0, ::/0"
    }
  ]
}
EOF
    printf 'server\n' > "$WG_DEB_ROLE_FILE"
    if wg_deb_rebuild_conf && wg_deb_regenerate_client_confs; then
        pass "Debian WireGuard 函数可在真实 /etc/wireguard 生成配置"
    else
        fail "Debian WireGuard 函数生成配置失败"
    fi
    if [[ -f "$WG_DEB_CONF" ]] && [[ "$(stat -c '%a' "$WG_DEB_CONF" 2>/dev/null)" == "600" ]]; then
        pass "Debian WireGuard 服务端配置权限为 600"
    else
        fail "Debian WireGuard 服务端配置权限异常"
        ls -l "$WG_DEB_CONF" 2>/dev/null || true
    fi
    client_conf="${WG_DEB_CLIENT_DIR}/client1.conf"
    if [[ -f "$client_conf" ]] && grep -q 'Endpoint = \[2001:db8::10\]:51820' "$client_conf"; then
        pass "Debian WireGuard 客户端配置安全格式化 IPv6 endpoint"
    else
        fail "Debian WireGuard 客户端配置未正确格式化 IPv6 endpoint"
        sed 's/^/    /' "$client_conf" 2>/dev/null || true
    fi
    if [[ -f "$client_conf" ]] && [[ "$(stat -c '%a' "$client_conf" 2>/dev/null)" == "600" ]]; then
        pass "Debian WireGuard 客户端配置权限为 600"
    else
        fail "Debian WireGuard 客户端配置权限异常"
        ls -l "$client_conf" 2>/dev/null || true
    fi
    export_dir="$tmp_root/wg-exports"
    export_log="$tmp_root/wg-export.out"
    pause() { :; }
    if (
        wg_deb_check_server() { return 0; }
        WG_EXPORT_DIR="$export_dir" wg_deb_export_peers
    ) >"$export_log" 2>&1; then
        export_file=$(find "$export_dir" -maxdepth 1 -type f -name 'server-manage-wg-peers.*' -print | head -1)
        if [[ -n "$export_file" ]] \
           && [[ -f "$export_file" ]] \
           && [[ "$(stat -c '%a' "$export_dir" 2>/dev/null)" == "700" ]] \
           && [[ "$(stat -c '%a' "$export_file" 2>/dev/null)" == "600" ]] \
           && grep -qF 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=' "$export_file" \
           && [[ "$export_file" == "$export_dir"/server-manage-wg-peers.* ]]; then
            pass "Debian WireGuard 导出含私钥 JSON 使用 0700 目录/0600 文件"
        else
            fail "Debian WireGuard 导出文件权限或路径异常"
            sed 's/^/    /' "$export_log" 2>/dev/null || true
            ls -ld "$export_dir" "$export_dir"/* 2>/dev/null | sed 's/^/    /' || true
        fi
    else
        fail "Debian WireGuard 导出执行失败"
        sed 's/^/    /' "$export_log" 2>/dev/null || true
    fi
    export_fail_log="$tmp_root/wg-export-fail.log"
    export_fail_dir="$tmp_root/wg-exports-fail"
    if (
        wg_deb_check_server() { return 0; }
        jq() {
            printf 'jq-count-fail|%s\n' "$*" >> "$export_fail_log"
            return 65
        }
        log_action() { printf 'log-action|%s\n' "$1" >> "$export_fail_log"; }
        WG_EXPORT_DIR="$export_fail_dir" wg_deb_export_peers
    ) > "$tmp_root/wg-export-count-fail.out" 2>&1; then
        fail "Debian WireGuard 导出读取 peer 数量失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-export-count-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$export_fail_log" 2>/dev/null || true
    elif grep -q '^jq-count-fail|' "$export_fail_log" \
         && ! grep -q '暂无设备可导出' "$tmp_root/wg-export-count-fail.out" \
         && ! grep -q 'log-action|WireGuard(deb) peers exported' "$export_fail_log"; then
        pass "Debian WireGuard 导出读取 peer 数量失败时返回非 0"
    else
        fail "Debian WireGuard 导出读取 peer 数量失败路径异常"
        sed 's/^/    /' "$tmp_root/wg-export-count-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$export_fail_log" 2>/dev/null || true
    fi
    : > "$export_fail_log"
    if (
        wg_deb_check_server() { return 0; }
        wg_deb_db_get() {
            [[ "${1:-}" == ".peers | length" ]] && { echo 1; return 0; }
            return 65
        }
        jq() {
            printf 'jq-fail|%s\n' "$*" >> "$export_fail_log"
            return 65
        }
        log_action() { printf 'log-action|%s\n' "$1" >> "$export_fail_log"; }
        WG_EXPORT_DIR="$export_fail_dir" wg_deb_export_peers
    ) > "$tmp_root/wg-export-fail.out" 2>&1; then
        fail "Debian WireGuard 导出 jq 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-export-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$export_fail_log" 2>/dev/null || true
    elif grep -q '^jq-fail|' "$export_fail_log" \
         && ! grep -q 'log-action|WireGuard(deb) peers exported' "$export_fail_log" \
         && ! grep -q '已导出' "$tmp_root/wg-export-fail.out" \
         && ! find "$export_fail_dir" -maxdepth 1 -type f -name 'server-manage-wg-peers.*' -print -quit | grep -q .; then
        pass "Debian WireGuard 导出 jq 失败时返回非 0 且不写成功日志/残留文件"
    else
        fail "Debian WireGuard 导出失败路径异常"
        sed 's/^/    /' "$tmp_root/wg-export-fail.out" 2>/dev/null || true
        sed 's/^/    /' "$export_fail_log" 2>/dev/null || true
        find "$export_fail_dir" -maxdepth 1 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
    unset -f pause
    sync_tmp_root="$tmp_root/wg-sync-tmp"
    mkdir -p "$sync_tmp_root"
    sync_seen="$tmp_root/wg-sync-seen.txt"
    wg_deb_is_running() { return 0; }
    wg() {
        if [[ "${1:-}" == "syncconf" && -n "${3:-}" ]]; then
            local cfg="$3" dir mode_dir mode_file
            dir="$(dirname "$cfg")"
            mode_dir="$(stat -c '%a' "$dir" 2>/dev/null || true)"
            mode_file="$(stat -c '%a' "$cfg" 2>/dev/null || true)"
            {
                printf 'cfg=%s\n' "$cfg"
                printf 'mode_dir=%s\n' "$mode_dir"
                printf 'mode_file=%s\n' "$mode_file"
            } > "$sync_seen"
            grep -qF 'PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' "$cfg" || return 11
            grep -qF 'PresharedKey = EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=' "$cfg" || return 12
            return 0
        fi
        return 1
    }
    if TMPDIR="$sync_tmp_root" wg_deb_apply_conf \
       && grep -q '^mode_dir=700$' "$sync_seen" \
       && grep -q '^mode_file=600$' "$sync_seen" \
       && ! find "$sync_tmp_root" -maxdepth 1 -name "${SCRIPT_NAME}-wg-deb-sync.*" -print -quit | grep -q .; then
        pass "Debian WireGuard syncconf 敏感临时文件使用 0700 目录/0600 文件并清理"
    else
        fail "Debian WireGuard syncconf 敏感临时文件权限或清理异常"
        sed 's/^/    /' "$sync_seen" 2>/dev/null || true
        find "$sync_tmp_root" -maxdepth 2 -ls 2>/dev/null | sed 's/^/    /' || true
    fi
    unset -f wg wg_deb_is_running
    deb_route_log="$tmp_root/wg-deb-route-sync.log"
    deb_route_tmp="$tmp_root/wg-deb-route-db.tmp"
    deb_route_db_before="$tmp_root/wg-deb-route-db-before.json"
    cp -p "$WG_DEB_DB_FILE" "$deb_route_db_before"
    jq '.peers += [{
        "name": "route-gw",
        "private_key": "LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL=",
        "public_key": "MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM=",
        "preshared_key": "NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN=",
        "ip": "10.77.0.3",
        "enabled": true,
        "is_gateway": true,
        "lan_subnets": "192.168.88.0/24, 2001:db8:88::/64"
    }]' "$WG_DEB_DB_FILE" > "$deb_route_tmp" && mv "$deb_route_tmp" "$WG_DEB_DB_FILE"
    printf '192.168.88.0/24\n192.168.99.0/24\n2001:db8:99::/64\n' > "$WG_SHARED_ROUTE_STATE_FILE"
    : > "$deb_route_log"
    wg_deb_is_running() { return 0; }
    wg() {
        [[ "${1:-}" == "syncconf" && -f "${3:-}" ]]
    }
    ip() {
        if [[ "${1:-}" == "-6" ]]; then
            [[ "${2:-}" == "route" ]] || return 1
        else
            [[ "${1:-}" == "route" ]] || return 1
        fi
        printf 'ip|%s\n' "$*" >> "$deb_route_log"
        return 0
    }
    if TMPDIR="$sync_tmp_root" wg_deb_apply_conf \
       && grep -Fxq 'ip|route del 192.168.99.0/24 dev wg0' "$deb_route_log" \
       && grep -Fxq 'ip|-6 route del 2001:db8:99::/64 dev wg0' "$deb_route_log" \
       && grep -Fxq 'ip|route replace 192.168.88.0/24 dev wg0' "$deb_route_log" \
       && grep -Fxq 'ip|-6 route replace 2001:db8:88::/64 dev wg0' "$deb_route_log" \
       && grep -Fxq '192.168.88.0/24' "$WG_SHARED_ROUTE_STATE_FILE" \
       && grep -Fxq '2001:db8:88::/64' "$WG_SHARED_ROUTE_STATE_FILE" \
       && ! grep -q '192.168.99.0/24' "$WG_SHARED_ROUTE_STATE_FILE"; then
        pass "Debian WireGuard syncconf 后同步网关 LAN 路由并清理 stale managed route"
    else
        fail "Debian WireGuard syncconf 后网关 LAN 路由同步异常"
        sed 's/^/    route: /' "$deb_route_log" 2>/dev/null || true
        sed 's/^/    state: /' "$WG_SHARED_ROUTE_STATE_FILE" 2>/dev/null || true
    fi
    cp -p "$deb_route_db_before" "$WG_DEB_DB_FILE"
    wg_deb_rebuild_conf >/dev/null 2>&1 || true
    wg_deb_regenerate_client_confs >/dev/null 2>&1 || true
    unset -f wg wg_deb_is_running ip
    wg_control_log="$tmp_root/wg-deb-control.log"
    if (
        pause() { :; }
        log_action() { printf 'log|%s\n' "$1" >> "$wg_control_log"; }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$wg_control_log"; return 0; }
        wg_deb_is_running() { return 1; }
        if wg_deb_start >/dev/null 2>&1; then
            exit 10
        fi
        if wg_deb_restart >/dev/null 2>&1; then
            exit 11
        fi
        exit 0
    ) && grep -qF "systemctl|start wg-quick@${WG_DEB_INTERFACE}" "$wg_control_log" \
       && grep -qF "systemctl|restart wg-quick@${WG_DEB_INTERFACE}" "$wg_control_log" \
       && grep -qF 'log|WireGuard(deb) start failed' "$wg_control_log" \
       && grep -qF 'log|WireGuard(deb) restart failed' "$wg_control_log"; then
        pass "Debian WireGuard start/restart 失败时返回非 0 并记录日志"
    else
        fail "Debian WireGuard start/restart 失败返回码或日志异常"
        sed 's/^/    /' "$wg_control_log" 2>/dev/null || true
    fi
    if (
        pause() { :; }
        log_action() { printf 'log|%s\n' "$1" >> "$wg_control_log"; }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$wg_control_log"; return 0; }
        wg_deb_is_running() { return 0; }
        if wg_deb_stop >/dev/null 2>&1; then
            exit 12
        fi
        exit 0
    ) && grep -qF "systemctl|stop wg-quick@${WG_DEB_INTERFACE}" "$wg_control_log" \
       && grep -qF 'log|WireGuard(deb) stop failed' "$wg_control_log"; then
        pass "Debian WireGuard stop 失败时返回非 0 并记录日志"
    else
        fail "Debian WireGuard stop 失败返回码或日志异常"
        sed 's/^/    /' "$wg_control_log" 2>/dev/null || true
    fi
    if (
        pause() { :; }
        log_action() { printf 'log|%s\n' "$1" >> "$wg_control_log"; }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$wg_control_log"; return 0; }
        wg_deb_is_running() {
            local cmd
            cmd=$(tail -n 1 "$wg_control_log" 2>/dev/null || true)
            [[ "$cmd" == *"start wg-quick@${WG_DEB_INTERFACE}"* || "$cmd" == *"restart wg-quick@${WG_DEB_INTERFACE}"* ]]
        }
        wg_deb_start >/dev/null 2>&1 && wg_deb_restart >/dev/null 2>&1
    ) && grep -qF 'log|WireGuard(deb) started' "$wg_control_log" \
       && grep -qF 'log|WireGuard(deb) restarted' "$wg_control_log"; then
        pass "Debian WireGuard start/restart 成功时返回 0"
    else
       fail "Debian WireGuard start/restart 成功返回码异常"
        sed 's/^/    /' "$wg_control_log" 2>/dev/null || true
    fi
    wg_port_modify_log="$tmp_root/wg-port-modify.log"
    wg_port_ufw_state="$tmp_root/wg-port-ufw-state"
    : > "$wg_port_modify_log"
    : > "$wg_port_ufw_state"
    if (
        pause() { :; }
        print_info() { :; }
        print_warn() { :; }
        print_error() { :; }
        log_action() { printf 'log|%s\n' "$1" >> "$wg_port_modify_log"; }
        wg_deb_check_server() { return 0; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$wg_port_modify_log"
            case "$*" in
                "show added")
                    grep -q '^51821$' "$wg_port_ufw_state" && echo "ufw allow 51821/udp comment 'WireGuard-Debian'"
                    return 0
                    ;;
                "allow 51821/udp comment WireGuard-Debian")
                    printf '51821\n' > "$wg_port_ufw_state"
                    return 0
                    ;;
                "delete allow 51821/udp")
                    : > "$wg_port_ufw_state"
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$wg_port_modify_log"; return 1; }
        wg_deb_is_running() { return 0; }
        printf '51821\n\n\n\n\n' | wg_deb_modify_server
    ) > "$tmp_root/wg-port-modify.out" 2>&1; then
        fail "Debian WireGuard 改端口在 systemctl 失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-port-modify.out" 2>/dev/null || true
    elif [[ "$(wg_deb_db_get '.server.port')" == "51820" ]] \
         && grep -q '^ufw|allow 51821/udp comment WireGuard-Debian$' "$wg_port_modify_log" \
         && grep -q '^ufw|delete allow 51821/udp$' "$wg_port_modify_log" \
         && [[ ! -s "$wg_port_ufw_state" ]]; then
        pass "Debian WireGuard 改端口后续失败会回滚 DB 并清理本次新增 UDP 规则"
    else
        fail "Debian WireGuard 改端口失败回滚异常"
        sed 's/^/    /' "$tmp_root/wg-port-modify.out" 2>/dev/null || true
        sed 's/^/    log: /' "$wg_port_modify_log" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    ufw-state: /' "$wg_port_ufw_state" 2>/dev/null || true
    fi
    peer_lifecycle_log="$tmp_root/wg-peer-lifecycle.log"
    if (
        pause() { :; }
        confirm() {
            printf 'confirm|%s\n' "$1" >> "$peer_lifecycle_log"
            return 0
        }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg_deb_generate_clash_config() {
            printf 'generate-clash\n' >> "$peer_lifecycle_log"
            return 0
        }
        wg() {
            case "${1:-}" in
                genkey)
                    printf '%s\n' 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF='
                    ;;
                genpsk)
                    printf '%s\n' 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG='
                    ;;
                pubkey)
                    cat >/dev/null
                    printf '%s\n' 'HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH='
                    ;;
                syncconf)
                    printf 'syncconf|%s|%s\n' "${2:-}" "${3:-}" >> "$peer_lifecycle_log"
                    test -f "${3:-}"
                    ;;
                *)
                    return 1
                    ;;
            esac
        }
        ip() {
            [[ "${1:-}" == "route" ]] || return 1
            printf 'ip|%s\n' "$*" >> "$peer_lifecycle_log"
            return 0
        }
        printf 'runtime-peer\n3\n4\n10.77.0.0/24, 192.168.88.0/24\n' | wg_deb_add_peer
    ) > "$tmp_root/wg-add-peer.out" 2>&1 \
       && [[ "$(wg_deb_db_get '.peers | length')" == "2" ]] \
       && [[ "$(wg_deb_db_get '.peers[1].name')" == "runtime-peer" ]] \
       && [[ "$(wg_deb_db_get '.peers[1].ip')" == "10.77.0.3" ]] \
       && [[ "$(wg_deb_db_get '.peers[1].route_mode')" == "custom" ]] \
       && [[ -f "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" ]] \
       && [[ "$(stat -c '%a' "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" 2>/dev/null)" == "600" ]] \
       && grep -qF 'AllowedIPs = 10.77.0.0/24, 192.168.88.0/24' "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" \
       && grep -qF '# runtime-peer' "$WG_DEB_CONF" \
       && grep -q '^syncconf|wg0|' "$peer_lifecycle_log"; then
        pass "Debian WireGuard 添加 peer 在真实 /etc/wireguard 写 DB/server/client 并热应用"
    else
        fail "Debian WireGuard 添加 peer 生命周期真实路径异常"
        sed 's/^/    /' "$tmp_root/wg-add-peer.out" 2>/dev/null || true
        sed 's/^/    /' "$peer_lifecycle_log" 2>/dev/null || true
        sed 's/^/    /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    /' "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" 2>/dev/null || true
    fi
    if (
        pause() { :; }
        confirm() { return 0; }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg() {
            [[ "${1:-}" == "syncconf" ]] && test -f "${3:-}"
        }
        ip() { [[ "${1:-}" == "route" ]]; }
        printf '2\n' | wg_deb_toggle_peer
    ) > "$tmp_root/wg-toggle-peer.out" 2>&1 \
       && [[ "$(wg_deb_db_get '.peers[1].enabled')" == "false" ]] \
       && ! grep -qF '# runtime-peer' "$WG_DEB_CONF" \
       && [[ -f "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" ]]; then
        pass "Debian WireGuard 禁用 peer 真实更新 DB 并从服务端配置移除"
    else
        fail "Debian WireGuard 禁用 peer 真实路径异常"
        sed 's/^/    /' "$tmp_root/wg-toggle-peer.out" 2>/dev/null || true
        sed 's/^/    /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    /' "$WG_DEB_CONF" 2>/dev/null || true
    fi
    if (
        pause() { :; }
        confirm() { return 0; }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg() {
            [[ "${1:-}" == "syncconf" ]] && test -f "${3:-}"
        }
        ip() { [[ "${1:-}" == "route" ]]; }
        printf '2\n' | wg_deb_delete_peer
    ) > "$tmp_root/wg-delete-peer.out" 2>&1 \
       && [[ "$(wg_deb_db_get '.peers | length')" == "1" ]] \
       && [[ -z "$(wg_deb_db_get '.peers[] | select(.name == "runtime-peer") | .name')" ]] \
       && [[ ! -e "${WG_DEB_CLIENT_DIR}/runtime-peer.conf" ]] \
       && ! grep -qF '# runtime-peer' "$WG_DEB_CONF"; then
        pass "Debian WireGuard 删除 peer 真实更新 DB 并删除客户端配置"
    else
        fail "Debian WireGuard 删除 peer 真实路径异常"
        sed 's/^/    /' "$tmp_root/wg-delete-peer.out" 2>/dev/null || true
        sed 's/^/    /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        ls -la "$WG_DEB_CLIENT_DIR" 2>/dev/null | sed 's/^/    /' || true
    fi
    if (
        pause() { :; }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg() {
            case "${1:-}" in
                genkey)
                    printf '%s\n' 'IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII='
                    ;;
                genpsk)
                    printf '%s\n' 'JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ='
                    ;;
                pubkey)
                    cat >/dev/null
                    printf '%s\n' 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK='
                    ;;
                syncconf)
                    return 91
                    ;;
                *)
                    return 1
                    ;;
            esac
        }
        ip() { [[ "${1:-}" == "route" ]]; }
        printf 'fail-peer\n3\n2\n' | wg_deb_add_peer
    ) > "$tmp_root/wg-add-peer-fail.out" 2>&1; then
        fail "Debian WireGuard 添加 peer 热应用失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-add-peer-fail.out" 2>/dev/null || true
    elif [[ "$(wg_deb_db_get '.peers | length')" == "1" ]] \
         && [[ -z "$(wg_deb_db_get '.peers[] | select(.name == "fail-peer") | .name')" ]] \
         && [[ ! -e "${WG_DEB_CLIENT_DIR}/fail-peer.conf" ]] \
         && ! grep -qF '# fail-peer' "$WG_DEB_CONF"; then
        pass "Debian WireGuard 添加 peer 热应用失败会回滚 DB/server/client"
    else
        fail "Debian WireGuard 添加 peer 热应用失败回滚异常"
        sed 's/^/    /' "$tmp_root/wg-add-peer-fail.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    conf: /' "$WG_DEB_CONF" 2>/dev/null || true
        ls -la "$WG_DEB_CLIENT_DIR" 2>/dev/null | sed 's/^/    /' || true
    fi
    if (
        pause() { :; }
        confirm() { return 0; }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg() {
            [[ "${1:-}" == "syncconf" ]] && return 92
            return 1
        }
        ip() { [[ "${1:-}" == "route" ]]; }
        printf '1\n' | wg_deb_toggle_peer
    ) > "$tmp_root/wg-toggle-peer-fail.out" 2>&1; then
        fail "Debian WireGuard peer 热应用失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-toggle-peer-fail.out" 2>/dev/null || true
    elif [[ "$(wg_deb_db_get '.peers[0].enabled')" == "true" ]] \
         && [[ -f "${WG_DEB_CLIENT_DIR}/client1.conf" ]] \
         && grep -qF '# client1' "$WG_DEB_CONF"; then
        pass "Debian WireGuard peer 热应用失败会回滚 DB 并保留客户端配置"
    else
        fail "Debian WireGuard peer 热应用失败回滚异常"
        sed 's/^/    /' "$tmp_root/wg-toggle-peer-fail.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    conf: /' "$WG_DEB_CONF" 2>/dev/null || true
        ls -la "$WG_DEB_CLIENT_DIR" 2>/dev/null | sed 's/^/    /' || true
    fi
    if (
        pause() { :; }
        confirm() { return 0; }
        wg_deb_check_server() { return 0; }
        wg_deb_is_running() { return 0; }
        wg() {
            [[ "${1:-}" == "syncconf" ]] && return 93
            return 1
        }
        ip() { [[ "${1:-}" == "route" ]]; }
        printf '1\n' | wg_deb_delete_peer
    ) > "$tmp_root/wg-delete-peer-fail.out" 2>&1; then
        fail "Debian WireGuard 删除 peer 热应用失败时仍返回成功"
        sed 's/^/    /' "$tmp_root/wg-delete-peer-fail.out" 2>/dev/null || true
    elif [[ "$(wg_deb_db_get '.peers | length')" == "1" ]] \
         && [[ "$(wg_deb_db_get '.peers[0].name')" == "client1" ]] \
         && [[ -f "${WG_DEB_CLIENT_DIR}/client1.conf" ]] \
         && grep -qF '# client1' "$WG_DEB_CONF"; then
        pass "Debian WireGuard 删除 peer 热应用失败会回滚并保留客户端配置"
    else
        fail "Debian WireGuard 删除 peer 热应用失败回滚异常"
        sed 's/^/    /' "$tmp_root/wg-delete-peer-fail.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    conf: /' "$WG_DEB_CONF" 2>/dev/null || true
        ls -la "$WG_DEB_CLIENT_DIR" 2>/dev/null | sed 's/^/    /' || true
    fi

    echo ""
    echo "== WireGuard OpenWrt runtime mock on Debian =="
    openwrt_mock_dir="$tmp_root/openwrt-mock"
    openwrt_mock_bin="$openwrt_mock_dir/bin"
    openwrt_mock_log="$openwrt_mock_dir/mock.log"
    openwrt_nft_input="$openwrt_mock_dir/nft-input_wan.rules"
    openwrt_nft_mangle="$openwrt_mock_dir/nft-mangle_prerouting.rules"
    openwrt_uci_log="$openwrt_mock_dir/uci.log"
    openwrt_rc_log="$openwrt_mock_dir/rc.log"
    mkdir -p "$openwrt_mock_bin"
    : > "$openwrt_mock_log"
    : > "$openwrt_nft_input"
    : > "$openwrt_nft_mangle"
    : > "$openwrt_uci_log"
    : > "$openwrt_rc_log"
    printf '100\n' > "$openwrt_mock_dir/nft-next-handle"
    printf '0\n' > "$openwrt_mock_dir/uci-wg-peer-count"

    cat > "$openwrt_mock_bin/nft" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
log="$dir/mock.log"
input="$dir/nft-input_wan.rules"
mangle="$dir/nft-mangle_prerouting.rules"
next="$dir/nft-next-handle"
printf 'nft|%s\n' "$*" >> "$log"
chain_file() {
    case "$1" in
        input_wan) printf '%s\n' "$input" ;;
        mangle_prerouting) printf '%s\n' "$mangle" ;;
        *) return 1 ;;
    esac
}
if [[ "${1:-}" == "-a" && "${2:-}" == "list" && "${3:-}" == "chain" && "${4:-}" == "inet" && "${5:-}" == "fw4" ]]; then
    file=$(chain_file "${6:-}") || exit 1
    cat "$file"
    exit 0
fi
if [[ "${1:-}" == "list" && "${2:-}" == "chain" && "${3:-}" == "inet" && "${4:-}" == "fw4" ]]; then
    file=$(chain_file "${5:-}") || exit 1
    cat "$file"
    exit 0
fi
if [[ "${1:-}" == "insert" && "${2:-}" == "rule" && "${3:-}" == "inet" && "${4:-}" == "fw4" ]]; then
    chain="${5:-}"
    handle=$(cat "$next" 2>/dev/null || echo 100)
    printf '%s\n' $((handle + 1)) > "$next"
    if [[ "$chain" == "input_wan" ]]; then
        port=""
        prev=""
        for arg in "$@"; do
            if [[ "$prev" == "dport" ]]; then port="$arg"; break; fi
            prev="$arg"
        done
        printf 'udp dport %s counter accept comment "wg_allow_port" # handle %s\n' "$port" "$handle" >> "$input"
        exit 0
    fi
    if [[ "$chain" == "mangle_prerouting" ]]; then
        if printf '%s\n' "$*" | grep -q 'wg_bypass_iface'; then
            printf 'iifname "wg0" counter return comment "wg_bypass_iface" # handle %s\n' "$handle" >> "$mangle"
        else
            cidr=""
            prev=""
            for arg in "$@"; do
                if [[ "$prev" == "daddr" ]]; then cidr="$arg"; break; fi
                prev="$arg"
            done
            printf 'ip daddr %s counter return comment "wg_bypass_subnet" # handle %s\n' "$cidr" "$handle" >> "$mangle"
        fi
        exit 0
    fi
fi
if [[ "${1:-}" == "delete" && "${2:-}" == "rule" && "${3:-}" == "inet" && "${4:-}" == "fw4" && "${6:-}" == "handle" ]]; then
    file=$(chain_file "${5:-}") || exit 1
    handle="${7:-}"
    sed -i "/handle ${handle}$/d" "$file"
    exit 0
fi
exit 1
EOF

    cat > "$openwrt_mock_bin/uci" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
log="$dir/uci.log"
count_file="$dir/uci-wg-peer-count"
network_state_file="$dir/uci-network-state"
firewall_state_file="$dir/uci-firewall-state"
if [[ "${1:-}" == "-q" ]]; then shift; fi
printf 'uci|%s\n' "$*" >> "$log"
cmd="${1:-}"
case "$cmd" in
    export)
        if [[ "${2:-}" == "network" ]]; then
            if [[ -f "$network_state_file" ]]; then
                cat "$network_state_file"
            else
                printf "config interface 'wg0'\n"
            fi
            exit 0
        fi
        if [[ "${2:-}" == "firewall" ]]; then
            if [[ -f "$firewall_state_file" ]]; then
                cat "$firewall_state_file"
            else
                printf "config defaults\n"
            fi
            exit 0
        fi
        exit 1
        ;;
    import)
        if [[ "${2:-}" == "network" ]]; then
            cat > "$network_state_file"
            exit 0
        fi
        if [[ "${2:-}" == "firewall" ]]; then
            cat > "$firewall_state_file"
            exit 0
        fi
        exit 1
        ;;
    revert)
        exit 0
        ;;
    get)
        key="${2:-}"
        if [[ "$key" == "network.@wireguard_wg0[0]" ]]; then
            count=$(cat "$count_file" 2>/dev/null || echo 0)
            [[ "$count" -gt 0 ]]
            exit $?
        fi
        exit 1
        ;;
    add)
        if [[ "${2:-}" == "network" && "${3:-}" == "wireguard_wg0" ]]; then
            count=$(cat "$count_file" 2>/dev/null || echo 0)
            printf '%s\n' $((count + 1)) > "$count_file"
        fi
        exit 0
        ;;
    delete)
        if [[ "${2:-}" == "network.@wireguard_wg0[0]" ]]; then
            count=$(cat "$count_file" 2>/dev/null || echo 0)
            [[ "$count" -gt 0 ]] && printf '%s\n' $((count - 1)) > "$count_file"
        fi
        exit 0
        ;;
    set|add_list)
        exit 0
        ;;
    commit)
        if [[ "${2:-}" == "network" && "${OPENWRT_MOCK_UCI_FAIL_NETWORK:-0}" == "1" ]]; then exit 1; fi
        if [[ "${2:-}" == "firewall" && "${OPENWRT_MOCK_UCI_FAIL_FIREWALL:-0}" == "1" ]]; then exit 1; fi
        exit 0
        ;;
esac
exit 0
EOF

    cat > "$openwrt_mock_bin/ip" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
printf 'ip|%s\n' "$*" >> "$dir/mock.log"
if [[ "${1:-}" == "link" && "${2:-}" == "show" && "${3:-}" == "wg0" ]]; then
    [[ -f "$dir/running_wg0" ]]
    exit $?
fi
if [[ "${1:-}" == "route" && "${2:-}" == "replace" ]]; then exit 0; fi
if [[ "${1:-}" == "-4" && "${2:-}" == "addr" && "${3:-}" == "show" ]]; then exit 1; fi
exit 0
EOF

    cat > "$openwrt_mock_bin/ifup" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
printf 'ifup|%s\n' "$*" >> "$dir/mock.log"
[[ "${OPENWRT_MOCK_IFUP_FAIL:-0}" == "1" ]] && exit 1
[[ "${1:-}" == "wg0" ]] && : > "$dir/running_wg0"
exit 0
EOF

    cat > "$openwrt_mock_bin/ifdown" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
printf 'ifdown|%s\n' "$*" >> "$dir/mock.log"
[[ "${1:-}" == "wg0" ]] && rm -f "$dir/running_wg0"
exit 0
EOF

    cat > "$openwrt_mock_bin/wg" <<'EOF'
#!/usr/bin/env bash
set -u
dir="${OPENWRT_MOCK_DIR:?}"
printf 'wg|%s\n' "$*" >> "$dir/mock.log"
case "${1:-}" in
    genkey) printf 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=\n' ;;
    genpsk) printf 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=\n' ;;
    pubkey) cat >/dev/null; printf 'HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=\n' ;;
    syncconf)
        [[ "${OPENWRT_MOCK_SYNC_FAIL:-0}" == "1" ]] && exit 1
        test -f "${3:-}"
        ;;
    show) exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod +x "$openwrt_mock_bin/nft" "$openwrt_mock_bin/uci" "$openwrt_mock_bin/ip" "$openwrt_mock_bin/ifup" "$openwrt_mock_bin/ifdown" "$openwrt_mock_bin/wg"

    openwrt_old_path="$PATH"
    openwrt_old_platform="$PLATFORM"
    openwrt_rc_clean_def=$(declare -f _wg_rc_local_cleanup_managed_entries)
    openwrt_rc_insert_def=$(declare -f _wg_rc_local_insert_block)
    openwrt_confirm_def=$(declare -f confirm)
    PATH="$openwrt_mock_bin:$PATH"
    PLATFORM="openwrt"
    export OPENWRT_MOCK_DIR="$openwrt_mock_dir"
    pause() { :; }
    _wg_rc_local_cleanup_managed_entries() { printf 'rc-clean|%s\n' "${1:-}" >> "$openwrt_rc_log"; return 0; }
    _wg_rc_local_insert_block() { printf 'rc-insert|%s\n' "${1:-}" >> "$openwrt_rc_log"; return 0; }

    rm -rf /etc/wireguard
    mkdir -p /etc/wireguard/db
    cat > "$WG_DB_FILE" <<'EOF'
{
  "role": "server",
  "schema_version": 2,
  "server": {
    "name": "openwrt-runtime",
    "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "ip": "10.66.66.1",
    "subnet": "10.66.66.0/24",
    "port": 51820,
    "dns": "1.1.1.1",
    "endpoint": "vpn.example.com",
    "listen_address": "0.0.0.0",
    "mtu": 1420,
    "ddns_domain": "",
    "server_lan_subnet": "192.168.1.0/24"
  },
  "peers": [],
  "client": {}
}
EOF
    chmod 600 "$WG_DB_FILE"
    printf 'server\n' > "$WG_ROLE_FILE"
    : > "$openwrt_mock_dir/running_wg0"

    if _wg_openwrt_apply_allow_port 51820 >/dev/null 2>&1 \
       && wg_setup_mihomo_bypass "10.66.66.0/24" >/dev/null 2>&1 \
       && grep -q 'udp dport 51820 .*wg_allow_port' "$openwrt_nft_input" \
       && grep -q 'wg_bypass_iface' "$openwrt_nft_mangle" \
       && ! grep -q 'nft|delete rule inet fw4 input_wan' "$openwrt_mock_log"; then
        pass "OpenWrt WireGuard bypass 配置不会误删实时 UDP 放行"
    else
        fail "OpenWrt WireGuard bypass 配置误删或未保留 UDP 放行"
        sed 's/^/    input: /' "$openwrt_nft_input" 2>/dev/null || true
        sed 's/^/    mangle: /' "$openwrt_nft_mangle" 2>/dev/null || true
        sed 's/^/    log: /' "$openwrt_mock_log" 2>/dev/null || true
    fi

    if printf '51821\n1.1.1.1\nvpn.example.com\n192.168.1.0/24\n' | wg_modify_server > "$tmp_root/openwrt-modify.out" 2>&1 \
       && [[ "$(wg_db_get '.server.port')" == "51821" ]] \
       && grep -q 'udp dport 51821 .*wg_allow_port' "$openwrt_nft_input" \
       && ! grep -q 'udp dport 51820 .*wg_allow_port' "$openwrt_nft_input" \
       && grep -qF 'uci|commit network' "$openwrt_uci_log" \
       && grep -qF 'ifup|wg0' "$openwrt_mock_log"; then
        pass "OpenWrt WireGuard 服务端改端口在实体机 mock 下更新 DB/UCI/nft"
    else
        fail "OpenWrt WireGuard 服务端改端口实体机 mock 路径异常"
        sed 's/^/    out: /' "$tmp_root/openwrt-modify.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DB_FILE" 2>/dev/null || true
        sed 's/^/    input: /' "$openwrt_nft_input" 2>/dev/null || true
        sed 's/^/    uci: /' "$openwrt_uci_log" 2>/dev/null || true
        sed 's/^/    log: /' "$openwrt_mock_log" 2>/dev/null || true
    fi

    if printf 'owrt-peer\n3\n2\n' | wg_add_peer > "$tmp_root/openwrt-add-peer.out" 2>&1 \
       && [[ "$(wg_db_get '.peers | length')" == "1" ]] \
       && [[ "$(wg_db_get '.peers[0].name')" == "owrt-peer" ]] \
       && [[ "$(wg_db_get '.peers[0].route_mode')" == "vpn" ]] \
       && [[ -f /etc/wireguard/clients/owrt-peer.conf ]] \
       && [[ "$(stat -c '%a' /etc/wireguard/clients/owrt-peer.conf 2>/dev/null)" == "600" ]] \
       && grep -qF 'Endpoint = vpn.example.com:51821' /etc/wireguard/clients/owrt-peer.conf \
       && grep -q '^wg|syncconf wg0 ' "$openwrt_mock_log"; then
        pass "OpenWrt WireGuard 添加 peer 在实体机 mock 下写 DB/server/client 并热应用"
    else
        fail "OpenWrt WireGuard 添加 peer 实体机 mock 路径异常"
        sed 's/^/    out: /' "$tmp_root/openwrt-add-peer.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DB_FILE" 2>/dev/null || true
        sed 's/^/    client: /' /etc/wireguard/clients/owrt-peer.conf 2>/dev/null || true
        sed 's/^/    log: /' "$openwrt_mock_log" 2>/dev/null || true
    fi

    confirm() { return 0; }
    if (
        export OPENWRT_MOCK_SYNC_FAIL=1
        printf '1\n' | wg_toggle_peer
    ) > "$tmp_root/openwrt-toggle-fail.out" 2>&1; then
        fail "OpenWrt WireGuard peer 热应用失败时仍返回成功"
        sed 's/^/    out: /' "$tmp_root/openwrt-toggle-fail.out" 2>/dev/null || true
    elif [[ "$(wg_db_get '.peers[0].enabled')" == "true" ]] \
         && [[ -f /etc/wireguard/clients/owrt-peer.conf ]]; then
        pass "OpenWrt WireGuard peer 热应用失败会回滚 DB 并保留客户端配置"
    else
        fail "OpenWrt WireGuard peer 热应用失败回滚异常"
        sed 's/^/    out: /' "$tmp_root/openwrt-toggle-fail.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DB_FILE" 2>/dev/null || true
        ls -la /etc/wireguard/clients 2>/dev/null | sed 's/^/    /' || true
    fi
    if printf '1\n' | wg_toggle_peer > "$tmp_root/openwrt-toggle-ok.out" 2>&1 \
       && [[ "$(wg_db_get '.peers[0].enabled')" == "false" ]] \
       && printf '1\n' | wg_delete_peer > "$tmp_root/openwrt-delete-peer.out" 2>&1 \
       && [[ "$(wg_db_get '.peers | length')" == "0" ]] \
       && [[ ! -e /etc/wireguard/clients/owrt-peer.conf ]]; then
        pass "OpenWrt WireGuard peer 禁用/删除在实体机 mock 下更新 DB 和客户端配置"
    else
        fail "OpenWrt WireGuard peer 禁用/删除实体机 mock 路径异常"
        sed 's/^/    toggle: /' "$tmp_root/openwrt-toggle-ok.out" 2>/dev/null || true
        sed 's/^/    delete: /' "$tmp_root/openwrt-delete-peer.out" 2>/dev/null || true
        sed 's/^/    db: /' "$WG_DB_FILE" 2>/dev/null || true
        ls -la /etc/wireguard/clients 2>/dev/null | sed 's/^/    /' || true
    fi

    eval "$openwrt_confirm_def"
    eval "$openwrt_rc_clean_def"
    eval "$openwrt_rc_insert_def"
    unset -f pause
    PATH="$openwrt_old_path"
    PLATFORM="$openwrt_old_platform"
    unset OPENWRT_MOCK_DIR
else
    skip "非 root 或缺 jq，跳过 Debian WireGuard 真实路径生成"
fi

echo ""
echo "== result =="
echo "debian_runtime_integration_test: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
exit "$FAIL"
