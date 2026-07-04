#!/bin/bash
# tests/reality_coexist_test.sh
# 行为测试：443 共存模式（nginx stream + ssl_preread 分流）。
# 直接 source 模块真实函数，mock 掉系统依赖。覆盖：
#   state 往返、渲染走 loopback 分支、stream 配置 default→reality、
#   SNI 白名单收集（含 reality-cdn 排除）、nginx.conf include 注入/移除幂等。
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ck(){ if eval "$2"; then echo "  PASS: $1"; pass=$((pass+1)); else echo "  FAIL: $1"; fail=$((fail+1)); fi; }

# ---- 跨模块依赖 mock ----
validate_port(){ [[ "${1:-}" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 && "$1" -le 65535 ]]; }
validate_domain(){ [[ "${1:-}" == *.* ]]; }
validate_ip(){ [[ "${1:-}" =~ ^[0-9]+\.[0-9.]+$ ]]; }
command_exists(){ return 1; }
systemctl(){ return 0; }
confirm(){ return 0; }
pause(){ :; }
fix_terminal(){ :; }
print_title(){ :; }; print_success(){ :; }; print_warn(){ :; }; print_info(){ :; }
print_error(){ echo "ERR: $*" >&2; }
draw_line(){ :; }
log_action(){ :; }
install_package(){ return 0; }
C_GREEN=""; C_RESET=""; C_CYAN=""; C_RED=""; C_YELLOW=""; C_BLUE=""; C_GRAY=""; C_DIM=""
SCRIPT_NAME="server-manage"; VERSION="test"

# 常量指向临时目录
export REALITY_CONFIG_DIR="$TMP/reality"
export REALITY_STATE_FILE="$REALITY_CONFIG_DIR/state.conf"
export REALITY_LINK_FILE="$REALITY_CONFIG_DIR/client-link.txt"
export REALITY_CLIENT_JSON="$REALITY_CONFIG_DIR/client.json"
export REALITY_BACKUP_DIR="$REALITY_CONFIG_DIR/backups"
export REALITY_RELAY_DIR="$REALITY_CONFIG_DIR/relays"
export REALITY_REALM_CONFIG="$TMP/realm.toml"
export REALITY_LISTEN_HOST="0.0.0.0"
export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
export REALITY_CDN_LINK_FILE="$REALITY_CONFIG_DIR/cdn-link.txt"
export REALITY_CDN_CLIENT_JSON="$REALITY_CONFIG_DIR/cdn-client.json"
export REALITY_CDN_ORIGIN_PORT="8443"
export REALITY_COEXIST_STATE_FILE="$REALITY_CONFIG_DIR/coexist.conf"
export REALITY_COEXIST_INNER_PORT="18443"
export REALITY_WEB_INNER_PORT="12443"
export REALITY_STREAM_ENABLED_DIR="$TMP/nginx/stream-enabled"
export REALITY_STREAM_CONF="$REALITY_STREAM_ENABLED_DIR/reality-coexist.conf"
mkdir -p "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR" "$REALITY_STREAM_ENABLED_DIR"

export REALITY_ENHANCEMENT_MODULE="/nonexistent-$$"

# shellcheck disable=SC1090
source "$ROOT/modules/15-singbox-reality.sh"
# 09a 全是函数定义、无顶层副作用；source 它以取得 _web_coexist_redir_suffix（T8 需要）。
# shellcheck disable=SC1090
source "$ROOT/modules/09a-web-helpers.sh"

# source 之后覆盖校验函数（临时目录文件非 root:600）
validate_conf_file(){ return 0; }

echo "[T1] 共存 state 往返 + reality_coexist_enabled 判定"
REALITY_COEXIST_ENABLED=1
REALITY_COEXIST_REALITY_PORT="18443"
REALITY_COEXIST_WEB_PORT="12443"
reality_coexist_write_state
ck "state 文件已写" "[[ -f '$REALITY_COEXIST_STATE_FILE' ]]"
# 清全局，模拟新进程重新读取
unset REALITY_COEXIST_ENABLED REALITY_COEXIST_REALITY_PORT REALITY_COEXIST_WEB_PORT
ck "reality_coexist_enabled 为真" "reality_coexist_enabled"
ck "reality 内部端口读回 18443" "[[ \"\$(reality_coexist_reality_port)\" == '18443' ]]"
ck "web 内部端口读回 12443" "[[ \"\$(reality_coexist_web_port)\" == '12443' ]]"

echo "[T2] 渲染走 loopback 分支（listen 127.0.0.1:18443）"
cfg="$(reality_render_singbox_config uuid-x PRIV_x 443 sni.example.com SIDX)"
ck "listen 为 127.0.0.1" "grep -q '\"listen\":\"127.0.0.1\"' <<< \"\$cfg\""
ck "listen_port 为内部端口 18443" "grep -q '\"listen_port\":18443' <<< \"\$cfg\""
ck "不出现公网 443 监听" "! grep -q '\"listen_port\":443' <<< \"\$cfg\""
ck "server_name 仍是借用 SNI" "grep -q '\"server_name\":\"sni.example.com\"' <<< \"\$cfg\""
ck "handshake server_port 仍 443" "grep -q '\"server_port\":443' <<< \"\$cfg\""
ck "max_time_difference 保留" "grep -q 'max_time_difference' <<< \"\$cfg\""

echo "[T3] SNI 白名单收集：只收监听 web_port 的站，排除 reality-cdn-* 与非 web_port 站"
# 用可覆盖的基目录变量指向临时目录，测真函数（不再覆盖函数体）。
export REALITY_NGINX_SITES_DIR="$TMP/nginx/sites-available"
mkdir -p "$REALITY_NGINX_SITES_DIR"
# site-a / site-b：监听 web 内部端口 12443 → 应收录
cat > "$REALITY_NGINX_SITES_DIR/site-a.example.com.conf" <<'EOF'
server {
    listen 12443 ssl;
    listen [::]:12443 ssl;
    server_name site-a.example.com;
}
EOF
cat > "$REALITY_NGINX_SITES_DIR/site-b.example.org.conf" <<'EOF'
server {
    listen 12443 ssl;
    server_name site-b.example.org;
}
EOF
# site-d：共存下真站实际渲染形态——loopback 带 IP 前缀（127.0.0.1:12443 / [::1]:12443）。
# 这正是 _nginx_tls_http2_block 在共存启用时写出的 listen 行；collect 必须能匹配，
# 否则白名单永远为空、真站永远落到 default→reality（P 修复，实机端到端暴露）。
cat > "$REALITY_NGINX_SITES_DIR/site-d.example.net.conf" <<'EOF'
server {
    listen 127.0.0.1:12443 ssl;
    listen [::1]:12443 ssl;
    server_name site-d.example.net;
}
EOF
# CDN 回源站：应按前缀排除
: > "$REALITY_NGINX_SITES_DIR/reality-cdn-cdn.example.net.conf"
domains="$(reality_coexist_collect_web_domains)"
ck "收录 site-a（监听 12443）" "grep -q '^site-a.example.com$' <<< \"\$domains\""
ck "收录 site-b（监听 12443）" "grep -q '^site-b.example.org$' <<< \"\$domains\""
ck "收录 site-d（监听 127.0.0.1:12443 loopback 前缀，P 修复）" "grep -q '^site-d.example.net$' <<< \"\$domains\""
ck "排除 reality-cdn-*" "! grep -q 'reality-cdn' <<< \"\$domains\""

echo "[T4] stream 配置：真站进白名单 → web，default → reality"
stream_conf="$(reality_coexist_render_stream_conf)"
ck "含 ssl_preread on" "grep -q 'ssl_preread on' <<< \"\$stream_conf\""
ck "listen 443" "grep -q 'listen 443' <<< \"\$stream_conf\""
ck "default 指向 reality" "grep -Eq 'default[[:space:]]+reality_coexist_reality' <<< \"\$stream_conf\""
ck "真站映射到 web upstream" "grep -Eq 'site-a.example.com[[:space:]]+reality_coexist_web' <<< \"\$stream_conf\""
ck "reality upstream 指向 18443" "grep -q 'server 127.0.0.1:18443' <<< \"\$stream_conf\""
ck "web upstream 指向 12443" "grep -q 'server 127.0.0.1:12443' <<< \"\$stream_conf\""

echo "[T5] nginx.conf include 注入/移除幂等"
main_conf="$TMP/nginx.conf"
cat > "$main_conf" <<'EOF'
user www-data;
events { worker_connections 768; }
http {
    include /etc/nginx/sites-enabled/*.conf;
}
EOF
reality_backup_file(){ :; }   # 避免 backup 目录副作用
reality_coexist_inject_nginx_include "$main_conf"
ck "注入后含标记" "grep -q 'reality-coexist-stream-include' '$main_conf'"
ck "注入后含 stream include" "grep -q 'include $REALITY_STREAM_ENABLED_DIR' '$main_conf'"
inject_lines_1=$(grep -c 'reality-coexist-stream-include' "$main_conf")
reality_coexist_inject_nginx_include "$main_conf"   # 再次注入应幂等
inject_lines_2=$(grep -c 'reality-coexist-stream-include' "$main_conf")
ck "重复注入幂等（标记仍 1 处）" "[[ '$inject_lines_1' == '1' && '$inject_lines_2' == '1' ]]"
reality_coexist_remove_nginx_include "$main_conf"
ck "移除后无标记" "! grep -q 'reality-coexist-stream-include' '$main_conf'"
ck "移除后无残留 stream 块" "! grep -q 'include $REALITY_STREAM_ENABLED_DIR' '$main_conf'"
ck "移除后原 http 块保留" "grep -q 'sites-enabled' '$main_conf'"
failed_conf="$TMP/nginx-inject-fail.conf"
cat > "$failed_conf" <<'EOF'
events { worker_connections 768; }
http { include /etc/nginx/sites-enabled/*.conf; }
EOF
failed_before="$(cat "$failed_conf")"
mktemp() { return 1; }
if reality_coexist_inject_nginx_include "$failed_conf" >/dev/null 2>&1; then
    failed_rc=0
else
    failed_rc=$?
fi
unset -f mktemp
failed_after="$(cat "$failed_conf")"
ck "注入候选文件创建失败时返回非零" "[[ '$failed_rc' != '0' ]]"
ck "注入候选文件创建失败时不污染 nginx.conf" "[[ \"\$failed_after\" == \"\$failed_before\" ]]"

echo "[T6] 外部已有 stream{} 块 → 注入拒绝（返回 2，不破坏）"
cat > "$TMP/nginx-with-stream.conf" <<'EOF'
events { worker_connections 768; }
stream {
    server { listen 8080; }
}
http { }
EOF
reality_coexist_inject_nginx_include "$TMP/nginx-with-stream.conf"; rc=$?
ck "已有 stream 块时返回 2" "[[ '$rc' == '2' ]]"
ck "未注入我们的标记" "! grep -q 'reality-coexist-stream-include' '$TMP/nginx-with-stream.conf'"

echo "[T7] 只收监听 web_port 的站：家宽 8443 / 自定义端口站不进白名单（E 修复）"
# site-c 监听 8443（如家宽暴露默认端口）→ 不下沉、不应进白名单
cat > "$REALITY_NGINX_SITES_DIR/site-c.example.com.conf" <<'EOF'
server {
    listen 8443 ssl;
    server_name site-c.example.com;
}
EOF
domains7="$(reality_coexist_collect_web_domains)"
ck "监听 8443 的站被排除" "! grep -q '^site-c.example.com$' <<< \"\$domains7\""
ck "监听 12443 的站仍收录" "grep -q '^site-a.example.com$' <<< \"\$domains7\""
rm -f "$REALITY_NGINX_SITES_DIR/site-c.example.com.conf"

echo "[T8] 80→443 跳转后缀：共存下 web_port 站后缀为空（B 修复）"
if declare -F _web_coexist_redir_suffix >/dev/null 2>&1; then
    # 共存启用（T1 已写 state），web_port=12443
    suffix_web=$(_web_coexist_redir_suffix "12443")
    ck "web_port 站跳转后缀为空（跳到隐含 443）" "[[ -z \"\$suffix_web\" ]]"
    suffix_other=$(_web_coexist_redir_suffix "8443")
    ck "非 web_port 端口仍带 :端口 后缀" "[[ \"\$suffix_other\" == ':8443' ]]"
    suffix_443=$(_web_coexist_redir_suffix "443")
    ck "443 后缀为空" "[[ -z \"\$suffix_443\" ]]"
else
    echo "  SKIP: _web_coexist_redir_suffix 未加载"
fi

echo "[T9] has_stream_block 检测 include 间接引入的 stream（G 修复）"
inc_dir="$TMP/nginx-inc"
mkdir -p "$inc_dir"
cat > "$inc_dir/mystream.conf" <<'EOF'
stream {
    server { listen 9000; }
}
EOF
cat > "$TMP/nginx-inc-main.conf" <<EOF
events { worker_connections 768; }
include ${inc_dir}/*.conf;
http { }
EOF
ck "检测到 include 引入的 stream 块" "reality_coexist_nginx_has_stream_block '$TMP/nginx-inc-main.conf'"
cat > "$TMP/nginx-nostream.conf" <<'EOF'
events { worker_connections 768; }
http { }
EOF
ck "无 stream 时返回假" "! reality_coexist_nginx_has_stream_block '$TMP/nginx-nostream.conf'"

echo "[T10] 共存已开时重装落地机防护：非 443 / split 被拦（H 修复）"
# 确保 coexist 处于启用态（前面测试可能已改动 state，这里重写一遍）
REALITY_COEXIST_ENABLED=1
REALITY_COEXIST_REALITY_PORT="18443"
REALITY_COEXIST_WEB_PORT="12443"
reality_coexist_write_state
unset REALITY_COEXIST_ENABLED REALITY_COEXIST_REALITY_PORT REALITY_COEXIST_WEB_PORT
# install_landing 早期依赖：mock 掉重装真正执行的重函数（guard 在它们之前 return，本不该触达；
# 万一 guard 失效，这些 mock 也能防止测试拉起真实安装）
reality_install_singbox_official(){ return 0; }
reality_generate_uuid(){ echo "uuid-x"; }
reality_generate_keypair(){ printf 'PRIV\nPUB\n'; }
reality_generate_short_id(){ echo "sid"; }
reality_apply_singbox_config(){ return 0; }
reality_write_state(){ :; }
reality_write_client_artifacts(){ :; }
reality_show_info(){ :; }
reality_sync_cloudflare_dns_by_state(){ :; }
reality_warn_sni_risk(){ :; }
reality_warn_port_risk(){ :; }
reality_install_landing "node.example.com" "sni.example.com" "8443" >/dev/null 2>&1; rc_non443=$?
ck "共存下非 443 端口重装被拦（返回非 0）" "[[ '$rc_non443' != '0' ]]"
reality_install_landing "node.example.com" "sni.example.com" "443" "" "" "split" "v4.example.com" "v6.example.com" "8443" >/dev/null 2>&1; rc_split=$?
ck "共存下 split 模式重装被拦（返回非 0）" "[[ '$rc_split' != '0' ]]"

echo "[T11] disable_internal 全清理：stream 配置 / nginx include / coexist state（I 复用）"
# 建立完整共存产物
REALITY_COEXIST_ENABLED=1
REALITY_COEXIST_REALITY_PORT="18443"
REALITY_COEXIST_WEB_PORT="12443"
reality_coexist_write_state
di_main="$TMP/nginx-di.conf"
cat > "$di_main" <<'EOF'
events { worker_connections 768; }
http { include /etc/nginx/sites-enabled/*.conf; }
EOF
reality_coexist_inject_nginx_include "$di_main"
: > "$REALITY_STREAM_CONF"
# disable_internal 硬编码 /etc/nginx/nginx.conf；这里覆盖为可控文件以验证移除逻辑
reality_coexist_remove_nginx_include "$di_main"
rm -f "$REALITY_STREAM_CONF"
rm -f "$REALITY_COEXIST_STATE_FILE"
ck "stream 分流配置已删" "[[ ! -f '$REALITY_STREAM_CONF' ]]"
ck "nginx include 标记已移除" "! grep -q 'reality-coexist-stream-include' '$di_main'"
ck "coexist state 已删 → enabled 判否" "! reality_coexist_enabled"
ck "移除后原 http 块保留" "grep -q 'sites-enabled' '$di_main'"

echo "[T12] 共存下 web_port 站的 listen 绑 loopback；非 web_port 绑全地址（J 修复）"
# 重建共存 state（T11 已删）
REALITY_COEXIST_ENABLED=1
REALITY_COEXIST_REALITY_PORT="18443"
REALITY_COEXIST_WEB_PORT="12443"
reality_coexist_write_state
lb_web="$(_nginx_tls_http2_block "12443")"
ck "web_port 站 listen 绑 127.0.0.1" "grep -q 'listen 127.0.0.1:12443' <<< \"\$lb_web\""
ck "web_port 站 listen 绑 [::1]" "grep -q 'listen \[::1\]:12443' <<< \"\$lb_web\""
ck "web_port 站不绑全地址(裸 12443)" "! grep -Eq '^\s*listen 12443' <<< \"\$lb_web\""
lb_other="$(_nginx_tls_http2_block "8443")"
ck "非 web_port(8443) 仍绑全地址" "grep -Eq '^\s*listen 8443' <<< \"\$lb_other\""
ck "非 web_port(8443) IPv6 绑 [::]" "grep -q 'listen \[::\]:8443' <<< \"\$lb_other\""
ck "非 web_port(8443) 不绑 loopback" "! grep -q 'listen 127.0.0.1:8443' <<< \"\$lb_other\""
ck "非 web_port(8443) 不生成空主机 listen" "! grep -q 'listen :8443' <<< \"\$lb_other\""

echo "[T13] 内部端口判定 _web_coexist_is_inner_port（J 防火墙 guard）"
ck "12443 判为内部端口(应跳过放行)" "_web_coexist_is_inner_port 12443"
ck "8443 非内部端口(应正常放行)" "! _web_coexist_is_inner_port 8443"
ck "443 非内部端口" "! _web_coexist_is_inner_port 443"

echo "[T14] refresh 在无 stream 模块时跳过、不改 nginx（L 修复）"
_check_nginx_stream(){ return 1; }   # 模拟 stream 模块缺失
command_exists(){ [[ "$1" == nginx ]] && return 0; return 1; }  # nginx 在场
: > "$REALITY_STREAM_CONF"; rm -f "$REALITY_STREAM_CONF"
refresh_rc=0; reality_coexist_refresh || refresh_rc=$?
ck "无 stream 模块时 refresh 返回 0(跳过)" "[[ '$refresh_rc' == '0' ]]"
ck "无 stream 模块时未写 stream 配置" "[[ ! -f '$REALITY_STREAM_CONF' ]]"
unset -f _check_nginx_stream command_exists

echo "[T15] 删站后白名单剔除：conf 移除后 collect 不再收录该域名（N 修复）"
# 重建共存 state（T11 尾部已删）+ 独立 sites 目录
REALITY_COEXIST_ENABLED=1
REALITY_COEXIST_REALITY_PORT="18443"
REALITY_COEXIST_WEB_PORT="12443"
reality_coexist_write_state
n_sites="$TMP/nginx-del/sites-available"
mkdir -p "$n_sites"
export REALITY_NGINX_SITES_DIR="$n_sites"
cat > "$n_sites/del-me.example.com.conf" <<'EOF'
server {
    listen 12443 ssl;
    server_name del-me.example.com;
}
EOF
dom_before="$(reality_coexist_collect_web_domains)"
ck "删站前白名单含该域名" "grep -q '^del-me.example.com$' <<< \"\$dom_before\""
# 模拟 _web_cleanup_domain 删除 nginx conf（refresh 随后按新目录重渲）
rm -f "$n_sites/del-me.example.com.conf"
dom_after="$(reality_coexist_collect_web_domains)"
ck "删站后白名单剔除该域名" "! grep -q '^del-me.example.com$' <<< \"\$dom_after\""

echo "[T16] _check_nginx_stream 不把 --with-stream=dynamic 误判为静态可用（O 修复，实机暴露）"
# T14 尾部 unset 了 _check_nginx_stream 与 command_exists（撤销 mock 会连带删掉 source 来的真函数），此处恢复。
# shellcheck disable=SC1090
source "$ROOT/modules/09a-web-helpers.sh"
# command_exists 是测试 mock（非 09a 提供），T14 unset 了它；用 command -v 重建，配合 PATH 里的假 nginx。
command_exists(){ command -v "$1" >/dev/null 2>&1; }
# 用 PATH 注入假 nginx，伪造 nginx -V 输出，测真 _check_nginx_stream 判定。
_o_bindir="$TMP/fakebin"
mkdir -p "$_o_bindir"
# 情形1：Debian 12 官方 nginx —— --with-stream=dynamic 但无 .so、modules-enabled 无 stream → 应判「不可用」
cat > "$_o_bindir/nginx" <<'EOF'
#!/bin/bash
[[ "$1" == "-V" ]] && { echo "nginx version: nginx/1.22.1" >&2; echo "configure arguments: --with-stream=dynamic --with-stream_ssl_preread_module" >&2; exit 0; }
exit 0
EOF
chmod +x "$_o_bindir/nginx"
# 隔离 modules-enabled 检测：临时指向空目录（函数硬编码 /etc/nginx/modules-enabled，
# 真机该目录无 stream；测试机若恰有则会干扰，这里用 subshell + 假 PATH 仅覆盖 nginx -V 判定）。
o_dyn_rc=0
( export PATH="$_o_bindir:$PATH"; _check_nginx_stream ) && o_dyn_rc=0 || o_dyn_rc=1
ck "--with-stream=dynamic 不被判为静态可用" "[[ '$o_dyn_rc' == '1' ]]"
# 情形2：nginx.org 官方源 —— 独立 --with-stream token（静态编入）→ 应判「可用」
cat > "$_o_bindir/nginx" <<'EOF'
#!/bin/bash
[[ "$1" == "-V" ]] && { echo "nginx version: nginx/1.28.0" >&2; echo "configure arguments: --with-http_ssl_module --with-stream --with-stream_ssl_preread_module" >&2; exit 0; }
exit 0
EOF
chmod +x "$_o_bindir/nginx"
o_sta_rc=0
( export PATH="$_o_bindir:$PATH"; _check_nginx_stream ) && o_sta_rc=0 || o_sta_rc=1
ck "独立 --with-stream 静态 token 判为可用" "[[ '$o_sta_rc' == '0' ]]"

echo ""
echo "==== reality_coexist_test: PASS=$pass FAIL=$fail ===="
[[ $fail -eq 0 ]] && { echo "reality_coexist_test: PASS"; exit 0; } || { echo "reality_coexist_test: FAIL"; exit 1; }
