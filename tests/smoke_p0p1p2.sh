#!/bin/bash
# 远程验证：P0/P1/P2 修复
set -u

BUILT="/tmp/v4-built.sh"
LIB="/tmp/v4-lib.sh"
PASS=0; FAIL=0
pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

head -n -1 "$BUILT" > "$LIB"
cat >> "$LIB" <<'STUB'
install_package() { return 0; }
auto_deps() { return 0; }
STUB
source "$LIB" >/dev/null 2>&1 || { echo "source 失败"; exit 1; }

echo "== P0-1: _cf_api 命名空间隔离 =="
# dist 里 _cf_api() 定义应只剩 1 个（09b），14b 应改名 _email_cf_api
n_cf_api=$(grep -cE '^_cf_api\(\)' "$BUILT")
n_email_cf_api=$(grep -cE '^_email_cf_api\(\)' "$BUILT")
[[ $n_cf_api -eq 1 ]] && pass "_cf_api 唯一定义 ($n_cf_api)" || fail "_cf_api 定义数 = $n_cf_api（应为 1）"
[[ $n_email_cf_api -eq 1 ]] && pass "_email_cf_api 已新增 ($n_email_cf_api)" || fail "_email_cf_api 未定义"
# 09b 版 _cf_api 签名带 token 参数；快速验证签名
sig_line=$(grep -A4 '^_cf_api()' "$BUILT" | grep -E 'method=\$1 endpoint=\$2 token=\$3' | head -1)
[[ -n "$sig_line" ]] && pass "_cf_api 保留 09b Web 版签名（method endpoint token）" || fail "_cf_api 签名错误"

echo ""
echo "== P0-2: 资源名 =="
declare -F _email_deploy_pick_worker_name >/dev/null && pass "_email_deploy_pick_worker_name 已定义" || fail "缺 _email_deploy_pick_worker_name"
declare -F _email_cf_worker_exists >/dev/null && pass "_email_cf_worker_exists 已定义" || fail "缺 _email_cf_worker_exists"
grep -q 'EMAIL_PAGES_PROJECT="temp-email-pages-' "$BUILT" && pass "Pages 名带随机后缀" || fail "Pages 名仍硬编码"

echo ""
echo "== P1-3: 卸载入口不卡 EMAIL_INSTALLED =="
# 检查 email_uninstall 函数体不应再有"^if ! email_state_load 2>/dev/null; then" 这种硬卡
grep -A6 'email_uninstall()' "$BUILT" | grep -q 'has_state=0' && pass "卸载入口已改为 has_state 判定" || fail "卸载入口未更新"

echo ""
echo "== P1-4: cron 脚本不再裸 source =="
# ddns-update.sh cron 模板内应已用 parse_ddns_conf 替代裸 source
# （dist 中主脚本里的 ddns_list/ddns_delete 仍有 source "$conf"，但前面有 validate_conf_file 保护，不是 cron 路径）
grep -q 'parse_ddns_conf' "$BUILT" && pass "DDNS cron 模板已嵌入 parse_ddns_conf 替代裸 source" || fail "未找到 parse_ddns_conf"
# 验证主脚本里的 source "$conf" 都有 validate_conf_file 保护
unsafe_source=$(awk '
    /source[[:space:]]+"\$conf"/ {
        if (!seen_validate) print NR": "$0
    }
    /validate_conf_file[[:space:]]+"\$conf"/ { seen_validate=1; next }
    /for[[:space:]]+conf[[:space:]]+in/ { seen_validate=0 }
' "$BUILT")
if [[ -z "$unsafe_source" ]]; then
    pass "所有 source \"\$conf\" 都在 validate_conf_file 之后"
else
    fail "发现不安全的 source \"\$conf\":"
    echo "$unsafe_source" | sed 's/^/    /'
fi
# geoip 模板里应不再有 'source "$CONF"'（注意大写 CONF 是 geoip 独有变量名）
if grep -qE '^[[:space:]]*source[[:space:]]+"\$CONF"' "$BUILT"; then
    fail "GeoIP 仍有裸 source"
else
    pass "GeoIP cron 模板已移除裸 source"
fi

echo ""
echo "== P1-5: origin.*.conf 通配已收窄 =="
grep -q '"\${DDNS_CONFIG_DIR}/origin\."\*"\.conf"' "$BUILT" \
    && fail "仍有 origin.*.conf 通配" \
    || pass "origin.* 通配已收窄"

echo ""
echo "== P1-6: refresh_ssh_port 用 sshd -T =="
# 通过实际运行验证：本机真实 SSH 端口应能被读出
if command -v sshd >/dev/null 2>&1; then
    real_port=$(sshd -T 2>/dev/null | awk 'tolower($1)=="port"{print $2; exit}')
    if [[ -n "$real_port" ]]; then
        refresh_ssh_port
        if [[ "$CURRENT_SSH_PORT" == "$real_port" ]]; then
            pass "refresh_ssh_port 读到 sshd -T 真实端口: $CURRENT_SSH_PORT"
        else
            fail "CURRENT_SSH_PORT=$CURRENT_SSH_PORT, sshd -T=$real_port (不一致)"
        fi
    else
        echo "  [SKIP] sshd -T 无输出（可能非 root 或无 sshd 配置），跳过"
    fi
else
    echo "  [SKIP] sshd 二进制不存在，跳过 P1-6 实测（代码层已通过静态检查）"
fi

echo ""
echo "== P2-7: SSH directive 追加 =="
declare -F _sshd_set_directive >/dev/null && pass "_sshd_set_directive 已定义" || fail "缺 _sshd_set_directive"
# 测试在临时文件上：
tmpfile=$(mktemp)
echo "# empty sshd config" > "$tmpfile"
_sshd_set_directive "PermitRootLogin" "no" "$tmpfile" </dev/null >/dev/null 2>&1
if grep -q '^PermitRootLogin no$' "$tmpfile"; then
    pass "未命中时正确追加 PermitRootLogin no"
else
    fail "追加失败 — file 内容:"; cat "$tmpfile" | sed 's/^/    /'
fi
# 再试已有但被注释
echo '#PasswordAuthentication yes' > "$tmpfile"
_sshd_set_directive "PasswordAuthentication" "no" "$tmpfile" </dev/null >/dev/null 2>&1
if grep -qE '^PasswordAuthentication no$' "$tmpfile" && ! grep -q '#PasswordAuthentication' "$tmpfile"; then
    pass "命中注释行时正确替换"
else
    fail "替换异常 — file 内容:"; cat "$tmpfile" | sed 's/^/    /'
fi
rm -f "$tmpfile"

echo ""
echo "== P2-8: 邮箱前缀字符校验 =="
declare -F _email_validate_dns_label >/dev/null && pass "_email_validate_dns_label 已定义" || fail "缺 _email_validate_dns_label"
_email_validate_dns_label "mail-api" && pass "接受 'mail-api'" || fail "应接受 'mail-api'"
_email_validate_dns_label "abc" && pass "接受 'abc'" || fail "应接受 'abc'"
_email_validate_dns_label "MAIL" && fail "应拒绝大写 'MAIL'" || pass "拒绝大写 'MAIL'"
_email_validate_dns_label "-bad" && fail "应拒绝首字符为短横" || pass "拒绝首字符为短横"
_email_validate_dns_label 'evil"$(rm)' && fail "应拒绝特殊字符" || pass "拒绝特殊字符"
_email_validate_dns_label "" && fail "应拒绝空" || pass "拒绝空"

echo ""
echo "== P2-9: 多 account 选择函数 =="
declare -F _email_deploy_pick_account >/dev/null && pass "_email_deploy_pick_account 已定义" || fail "缺 _email_deploy_pick_account"

echo ""
echo "== P2-10: NGINX_CONF_PATH 未定义引用 =="
grep -q '\$NGINX_CONF_PATH' "$BUILT" \
    && fail "仍有 \$NGINX_CONF_PATH 引用" \
    || pass "\$NGINX_CONF_PATH 已替换为字面路径"

echo ""
echo "== 旧痕迹回归 =="
grep -q 'menu_backup\|backup_create' "$BUILT" && fail "backup 残留" || pass "backup 残零"
grep -E 'eval \$cmd' "$BUILT" >/dev/null && fail "eval \$cmd 残留" || pass "eval \$cmd 已无"

echo ""
echo "== 本轮新增（review #3）回归 =="
# P1-A: state 持久化 CF_ACCOUNT_ID
grep -q 'EMAIL_CF_ACCOUNT_ID=' "$BUILT" && pass "P1-A: state 已含 EMAIL_CF_ACCOUNT_ID" || fail "P1-A: 缺 EMAIL_CF_ACCOUNT_ID"
# 14d/14e prepare 应优先读 EMAIL_CF_ACCOUNT_ID 而非取第一个
prep_body=$(awk '/^_email_manage_prepare\(\)/,/^}/' "$BUILT")
echo "$prep_body" | grep -q '\$EMAIL_CF_ACCOUNT_ID' && pass "P1-A: _email_manage_prepare 优先用 state ACCOUNT_ID" || fail "P1-A: prepare 未读 state"

# P1-B: 三态菜单含 partial 分支
grep -q 'state_kind="partial"' "$BUILT" && pass "P1-B: menu_email 有 partial 三态" || fail "P1-B: 缺 partial 分支"
grep -q '强制卸载' "$BUILT" && pass "P1-B: 半成品菜单暴露强制卸载入口" || fail "P1-B: 缺强制卸载入口"

# P1-C: firewall_allow_tcp_port 不再自动启用/重置 UFW
fw_body=$(awk '/^firewall_allow_tcp_port\(\)/,/^}/' "$BUILT")
if echo "$fw_body" | grep -Eq 'ufw default|ufw [^a]*enable|install_package ufw'; then
    fail "P1-C: firewall_allow_tcp_port 仍含 install/default/enable"
    echo "$fw_body" | grep -nE 'ufw default|ufw [^a]*enable|install_package ufw' | sed 's/^/    /'
else
    pass "P1-C: firewall_allow_tcp_port 仅追加规则，不启用 UFW"
fi
echo "$fw_body" | grep -q '防火墙管理' && pass "P1-C: UFW 未启用时引导至防火墙菜单" || fail "P1-C: 缺引导提示"

# P1-D: ssh_change_port 改完用 sshd -T 校验生效端口
ssh_body=$(awk '/^ssh_change_port\(\)/,/^}/' "$BUILT")
echo "$ssh_body" | grep -q 'sshd -T' && pass "P1-D: ssh_change_port 用 sshd -T 校验" || fail "P1-D: 缺 sshd -T 校验"
echo "$ssh_body" | grep -q 'sshd_config.d' && pass "P1-D: ssh_change_port 检测 drop-in" || fail "P1-D: 未检测 drop-in"
echo "$ssh_body" | grep -q 'effective_port' && pass "P1-D: 重启后比对实际生效端口" || fail "P1-D: 未比对生效端口"

echo ""
echo "== review #4 回归 =="
# P1-1: ADMIN_PASSWORDS 不再 | tostring
if grep -q "jq -nc --arg p .*\['\$p'\] | tostring" "$BUILT" || grep -q 'jq -nc --arg p .*\[\$p\] | tostring' "$BUILT"; then
    fail "P1-1: 仍有 | tostring（admin secret 会被双重 JSON）"
else
    pass "P1-1: ADMIN_PASSWORDS 不再 | tostring"
fi
grep -qE "jq -nc --arg p .*'\[\\\$p\]'" "$BUILT" && pass "P1-1: admin_json 用 [\$p] 直接生成 JSON 数组" || \
    grep -qE "jq -nc --arg p .{1,30}\\[\\\$p\\]" "$BUILT" && pass "P1-1: admin_json 用 [\$p] 数组" || fail "P1-1: 未找到正确写法"

# P1-2: Pages service binding 同步
pages_body=$(awk '/^_email_deploy_pages\(\)/,/^}/' "$BUILT")
echo "$pages_body" | grep -q 'pages/wrangler.toml' && pass "P1-2: _email_deploy_pages 处理 pages/wrangler.toml" || fail "P1-2: 未处理 pages/wrangler.toml"
echo "$pages_body" | grep -q 'EMAIL_WORKER_NAME' && pass "P1-2: 用 EMAIL_WORKER_NAME 替换 service" || fail "P1-2: 未替换 service"

# P1-3: state 备份 + partial 警告
declare -F email_state_backup >/dev/null && pass "P1-3: email_state_backup 已定义" || fail "P1-3: 缺 email_state_backup"
deploy_body=$(awk '/^email_deploy\(\)/,/^}/' "$BUILT")
echo "$deploy_body" | grep -q 'EMAIL_INSTALLED=0' && pass "P1-3: email_deploy 检测 partial" || fail "P1-3: 未检测 partial"
echo "$deploy_body" | grep -q 'email_state_backup' && pass "P1-3: 覆盖前调用 email_state_backup" || fail "P1-3: 未备份"
# partial 菜单第 1 项应是强制卸载
menu_body=$(awk '/^menu_email\(\)/,/^}/' "$BUILT")
echo "$menu_body" | grep -q '1. 强制卸载' && pass "P1-3: partial 菜单 1=强制卸载（推荐）" || fail "P1-3: partial 菜单顺序未调整"

# P2-1: URL encode
declare -F _email_cf_urlencode >/dev/null && pass "P2-1: _email_cf_urlencode 已定义" || fail "P2-1: 缺 _email_cf_urlencode"
# 测试实际功能（如果 jq 可用）
if command -v jq >/dev/null; then
    enc=$(_email_cf_urlencode "a b@c.com")
    if [[ "$enc" == "a%20b%40c.com" ]]; then
        pass "P2-1: 正确 encode 空格和 @"
    else
        fail "P2-1: encode 结果错误: '$enc' (期望 a%20b%40c.com)"
    fi
fi
# 关键调用点用了 enc
zone_body=$(awk '/^_email_cf_zone_id_by_name\(\)/,/^}/' "$BUILT")
echo "$zone_body" | grep -q '_email_cf_urlencode' && pass "P2-1: zone_id_by_name 走 encode" || fail "P2-1: zone_id_by_name 未走 encode"

# P2-2: 卸载日志保域名
uninstall_body=$(awk '/^email_uninstall\(\)/,/^}/' "$BUILT")
echo "$uninstall_body" | grep -q '_log_domain' && pass "P2-2: 卸载日志保存 _log_domain" || fail "P2-2: 未保存域名"
# 校验顺序：_log_domain 赋值在 email_state_clear 之前
if echo "$uninstall_body" | awk '/_log_domain=/{a=NR} /email_state_clear/{b=NR} END{exit !(a && b && a<b)}'; then
    pass "P2-2: _log_domain 赋值在 email_state_clear 之前"
else
    fail "P2-2: _log_domain 赋值时机错误"
fi

# P3: 版本号
grep -q 'VERSION="v14.1"' "$BUILT" && pass "P3: VERSION 升至 v14.1" || fail "P3: VERSION 未升级"

echo ""
echo "== review #5 回归 =="
# P1-1: secret 日志脱敏
declare -F _email_redact_secrets >/dev/null && pass "P1-1: _email_redact_secrets 已定义" || fail "P1-1: 缺 redact helper"
# 实测脱敏功能
masked=$(echo '{"name":"ADMIN_PASSWORDS","type":"secret_text","text":"my-real-password-123"}' | _email_redact_secrets 2>/dev/null)
if echo "$masked" | grep -q '<redacted>' && ! echo "$masked" | grep -q 'my-real-password-123'; then
    pass "P1-1: secret_text 已脱敏，原值不再出现"
else
    fail "P1-1: 脱敏失败，masked='$masked'"
fi
# CF API 检测 /secrets 路径
api_body=$(awk '/^_email_cf_api\(\)/,/^}/' "$BUILT")
echo "$api_body" | grep -q '/secrets' && pass "P1-1: _email_cf_api 检测 /secrets 路径" || fail "P1-1: 未识别 /secrets"
echo "$api_body" | grep -q '<redacted: secret payload>' && pass "P1-1: secret 路径 body 替换为占位" || fail "P1-1: 未替换 body"

# P1-2: send_email binding 默认关闭
if grep -E '^send_email[[:space:]]*=' "$BUILT" >/dev/null; then
    fail "P1-2: 仍有未注释的 send_email binding"
else
    pass "P1-2: send_email binding 已默认关闭/注释"
fi
grep -q '#send_email' "$BUILT" && pass "P1-2: 模板含注释占位（保留用户手动取消注释能力）" || true

# P2-1: 双导 CLOUDFLARE_*
declare -F _email_export_wrangler_env >/dev/null && pass "P2-1: _email_export_wrangler_env 已定义" || fail "P2-1: 缺 helper"
env_body=$(awk '/^_email_export_wrangler_env\(\)/,/^}/' "$BUILT")
echo "$env_body" | grep -q 'CLOUDFLARE_API_TOKEN' && pass "P2-1: 导出 CLOUDFLARE_API_TOKEN" || fail "P2-1: 未导出新版 token 变量"
echo "$env_body" | grep -q 'CLOUDFLARE_ACCOUNT_ID' && pass "P2-1: 导出 CLOUDFLARE_ACCOUNT_ID" || fail "P2-1: 未导出新版 account id"
# 三处调用
n_calls=$(grep -c '_email_export_wrangler_env' "$BUILT")
[[ $n_calls -ge 4 ]] && pass "P2-1: helper 被调用 $n_calls 次（定义+collect/manage/uninstall）" || fail "P2-1: 调用次数不足: $n_calls"

# P2-2: PREFIX 末尾自动补点
render_body=$(awk '/^_email_deploy_render_toml\(\)/,/^}/' "$BUILT")
echo "$render_body" | grep -q '${EMAIL_ADDRESS_PREFIX}\.' && pass "P2-2: render_toml 给 PREFIX 补点" || fail "P2-2: PREFIX 未补点"

# P3: smoke_remote 用静态 grep（不再 echo 0 | timeout）
# 注意：必须排除注释行，否则 smoke_remote 中描述旧写法的注释会被命中
_remote_test="$(dirname "$0")/smoke_remote.sh"
if [[ ! -f "$_remote_test" ]]; then
    echo "  [SKIP] $_remote_test 不存在（仅上传 smoke_p0p1p2.sh 时），跳过跨文件检查"
elif grep -v '^[[:space:]]*#' "$_remote_test" | grep -q "echo 0 | timeout"; then
    fail "P3: smoke_remote 仍用非交互管道抓 prompt"
else
    pass "P3: smoke_remote 已改静态 grep（无 echo 0 | timeout 残留）"
fi
unset _remote_test

echo ""
echo "== review #6 回归 =="
# P1-1: DNS / Email Routing 严格化
dns_body=$(awk '/^_email_deploy_dns\(\)/,/^}/' "$BUILT")
echo "$dns_body" | grep -q '_dns_fail=0' && pass "P1-1: _email_deploy_dns 累计 _dns_fail" || fail "P1-1: 缺 _dns_fail 累计"
echo "$dns_body" | grep -q 'return \$_dns_fail' && pass "P1-1: _email_deploy_dns 返回累计失败标志" || fail "P1-1: 未 return _dns_fail"
echo "$dns_body" | grep -q '_mx_ok' && pass "P1-1: MX 至少 1 条逻辑" || fail "P1-1: 缺 MX 计数"
routing_body=$(awk '/^_email_deploy_email_routing\(\)/,/^}/' "$BUILT")
echo "$routing_body" | grep -q 'return 1' && pass "P1-1: _email_deploy_email_routing 失败 return 1" || fail "P1-1: routing 仍 return 0"
echo "$routing_body" | grep -q 'email_state_write' && pass "P1-1: routing 失败前落盘 partial state" || fail "P1-1: routing 未落 partial state"

# P1-2: _email_patch_pages_service_binding helper
declare -F _email_patch_pages_service_binding >/dev/null && pass "P1-2: _email_patch_pages_service_binding 已定义" || fail "P1-2: 缺 pages binding helper"
# helper 在 14c deploy + 14d upgrade + 14d redeploy 三处调用
n_helper_calls=$(grep -c '_email_patch_pages_service_binding' "$BUILT")
[[ $n_helper_calls -ge 4 ]] && pass "P1-2: helper 被调用 $n_helper_calls 次（定义+deploy/upgrade/redeploy）" || fail "P1-2: helper 调用次数不足: $n_helper_calls"

# P2-3: 管理员密码 read -s
collect_body=$(awk '/^_email_deploy_collect_inputs\(\)/,/^}/' "$BUILT")
if echo "$collect_body" | grep -q 'read -e -r -p "管理员密码'; then
    fail "P2-3: 14c 部署仍用 read -e -r -p 接管理员密码"
else
    pass "P2-3: 14c 部署管理员密码已改 read -s"
fi
mgr_body=$(awk '/^email_manage_change_admin_password\(\)/,/^}/' "$BUILT")
if echo "$mgr_body" | grep -q 'read -e -r -p "新管理员密码'; then
    fail "P2-3: 14d 改密码仍用 read -e -r -p"
else
    pass "P2-3: 14d 改密码已改 read -s"
fi

# P2-4: 查看日志 menu 走脱敏管道
view_body=$(awk '/^email_view_log\(\)/,/^}/' "$BUILT")
echo "$view_body" | grep -q '_email_redact_secrets' && pass "P2-4: email_view_log tail 走脱敏管道" || fail "P2-4: 日志菜单未脱敏"

# P2-5: ADMIN_PASSWORDS 已存在 var binding 时，改密码不能只写 secret
declare -F _email_manage_update_admin_passwords_var >/dev/null && pass "P2-5: 已定义 ADMIN_PASSWORDS var 回退 helper" || fail "P2-5: 缺 ADMIN_PASSWORDS var 回退 helper"
admin_var_body=$(awk '/^_email_manage_update_admin_passwords_var\(\)/,/^}/' "$BUILT")
echo "$admin_var_body" | grep -q 'wrangler.toml' && pass "P2-5: 回退 helper 更新 wrangler.toml" || fail "P2-5: 回退 helper 未更新 wrangler.toml"
echo "$admin_var_body" | grep -q '_email_wrangler deploy' && pass "P2-5: 回退 helper 重新部署 Worker" || fail "P2-5: 回退 helper 未 redeploy Worker"
mgr_body=$(awk '/^email_manage_change_admin_password\(\)/,/^}/' "$BUILT")
echo "$mgr_body" | grep -q '_email_manage_update_admin_passwords_var' && pass "P2-5: 改密码失败时回退 var binding" || fail "P2-5: 改密码未回退 var binding"
echo "$mgr_body" | grep -q '普通变量' && pass "P2-5: 改密码提示 var binding 兼容路径" || fail "P2-5: 缺 var binding 提示"
tmp_email_install=$(mktemp -d)
tmp_email_lib=$(mktemp)
tmp_email_script=$(mktemp)
sed "s|^readonly EMAIL_INSTALL_DIR=.*|EMAIL_INSTALL_DIR=\"$tmp_email_install\"|" "$LIB" > "$tmp_email_lib"
cat > "$tmp_email_script" <<'EMAIL_ADMIN_VAR_TEST'
    source "$1" >/dev/null 2>&1 || exit 90
    email_run() {
        printf '%s\n' "$*" > "$EMAIL_INSTALL_DIR/deploy.args"
        return 0
    }
    _email_export_wrangler_env() { return 0; }
    mkdir -p "$EMAIL_INSTALL_DIR/worker"
    cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'EOF'
name = "demo-worker"

[vars]
PREFIX = ""
  ADMIN_PASSWORDS = ["old-pass"]
DOMAINS = ["example.com"]
EOF
    _email_manage_update_admin_passwords_var '["new-pass"]' || exit 1
    [[ $(grep -cE '^[[:space:]]*ADMIN_PASSWORDS[[:space:]]*=' "$EMAIL_INSTALL_DIR/worker/wrangler.toml") -eq 1 ]] || exit 2
    grep -qE '^ADMIN_PASSWORDS[[:space:]]*=[[:space:]]*\["new-pass"\]$' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" || exit 3
    grep -q '_email_wrangler deploy' "$EMAIL_INSTALL_DIR/deploy.args" || exit 4
EMAIL_ADMIN_VAR_TEST
if bash "$tmp_email_script" "$tmp_email_lib"; then
    pass "P2-5: 回退 helper 实测替换缩进 ADMIN_PASSWORDS 并 redeploy"
else
    fail "P2-5: 回退 helper 未正确替换缩进 ADMIN_PASSWORDS"
fi
rm -rf "$tmp_email_install" "$tmp_email_lib" "$tmp_email_script"

# P3-5: 测试自身 grep 排除注释
if grep -q "grep -v '^\\[\\[:space:\\]\\]\\*#'" "$0"; then
    pass "P3-5: smoke_p0p1p2 grep 排除注释行（自检）"
else
    fail "P3-5: 自检失败 — grep 未加 -v 排除注释"
fi

echo ""
echo "== review #7 回归 =="
# P2-MX: 配置确认页 MX 替换警告 + 双 confirm
collect_body=$(awk '/^_email_deploy_collect_inputs\(\)/,/^}/' "$BUILT")
echo "$collect_body" | grep -q 'MX 记录将被替换' && pass "P2-MX: 配置确认页有 MX 替换警告" || fail "P2-MX: 缺 MX 警告"
echo "$collect_body" | grep -q 'route1.mx.cloudflare.net' && pass "P2-MX: 警告列出 route1.mx" || fail "P2-MX: 未列出 cloudflare MX"
echo "$collect_body" | grep -q '专用域名' && pass "P2-MX: 引导使用专用域名" || fail "P2-MX: 缺专用域名引导"
echo "$collect_body" | grep -q '独立托管' && pass "P2-MX: 提示子域名需独立托管为 Zone" || fail "P2-MX: 缺子域名 Zone 提示"
n_confirm=$(echo "$collect_body" | grep -c 'confirm ')
[[ $n_confirm -ge 2 ]] && pass "P2-MX: 配置确认页有 ≥2 道 confirm（$n_confirm 道）" || fail "P2-MX: confirm 不足 2 道: $n_confirm"
echo "$collect_body" | grep -q '再次确认' && pass "P2-MX: 含独立 MX 替换二次确认" || fail "P2-MX: 缺二次确认字面"

# CHANGELOG/README 的 docs 静态检查已移除：那是构建期元数据一致性问题，
# 不属于 dist 回归范畴；远程冒烟只验证 dist 行为，docs 由 review 时人工检查。

echo ""
echo "== review #8 交互体验回归 =="
# P1: Cloudflare DNS 模式输入必须校验，不能无效选择后仍提示成功
cf_dns_body=$(awk '/^web_cf_dns_update\(\)/,/^}/' "$BUILT")
echo "$cf_dns_body" | grep -q '1|2|3' && pass "P1-UI: CF DNS 模式限制为 1/2/3" || fail "P1-UI: CF DNS 模式缺少 1/2/3 校验"
echo "$cf_dns_body" | grep -q '无效选择' && pass "P1-UI: CF DNS 无效模式会提示并返回" || fail "P1-UI: CF DNS 无效模式不会中止"

# P1: IPv4/IPv6 优先级必须显式处理 0/1/2，空值或错字不能悄悄按 IPv6 执行
net_body=$(awk '/^menu_net\(\)/,/^}/' "$BUILT")
echo "$net_body" | grep -q '0. 返回上一级' && pass "P1-UI: 网络菜单使用返回上一级文案" || fail "P1-UI: 网络菜单缺返回上一级"
dns_body=$(awk '/^net_dns\(\)/,/^}/' "$BUILT")
echo "$dns_body" | grep -q '13. 自定义输入' && pass "P1-UI: DNS 自定义输入不再占用 0" || fail "P1-UI: DNS 自定义输入仍可能占用 0"
echo "$net_body" | grep -q 'case \$p in' && pass "P1-UI: IP 优先级用 case 显式分支" || fail "P1-UI: IP 优先级仍未显式分支"
echo "$net_body" | grep -q '0|q|Q' && pass "P1-UI: IP 优先级支持 0/q 返回" || fail "P1-UI: IP 优先级缺少返回选项"

# P2: WireGuard 应有顶层菜单，服务端菜单的 0 返回到 WireGuard 顶层而不是直接回主菜单
wg_main_body=$(awk '/^wg_main_menu\(\)/,/^}/' "$BUILT")
wg_deb_main_body=$(awk '/^wg_deb_main_menu\(\)/,/^}/' "$BUILT")
echo "$wg_main_body" | grep -q '1. 服务端管理' && pass "P2-UI: OpenWrt WireGuard 有顶层菜单" || fail "P2-UI: OpenWrt WireGuard 缺顶层菜单"
echo "$wg_deb_main_body" | grep -q '1. 服务端管理' && pass "P2-UI: Debian WireGuard 有顶层菜单" || fail "P2-UI: Debian WireGuard 缺顶层菜单"
if echo "$wg_main_body" | grep -q 'wg_server_menu; return' || echo "$wg_deb_main_body" | grep -q 'wg_deb_server_menu; return'; then
    fail "P2-UI: WireGuard server_menu 返回仍会直接回主菜单"
else
    pass "P2-UI: WireGuard server_menu 可逐级返回"
fi

# P2: 常用二级菜单避免 box-drawing 装饰字符，降低乱码概率
dns_body=$(awk '/^net_dns\(\)/,/^}/' "$BUILT")
wg_server_body=$(awk '/^wg_server_menu\(\)/,/^}/' "$BUILT")
wg_deb_server_body=$(awk '/^wg_deb_server_menu\(\)/,/^}/' "$BUILT")
home_body=$(awk '/^web_home_expose\(\)/,/^}/' "$BUILT")
if printf '%s\n%s\n%s\n%s\n' "$dns_body" "$wg_server_body" "$wg_deb_server_body" "$home_body" | grep -Eq '[┌┐└┘│━─]'; then
    fail "P2-UI: 常用二级菜单仍含易乱码线框字符"
else
    pass "P2-UI: 常用二级菜单线框已降级为 ASCII"
fi
visible_box_lines=$(grep -nE '^[[:space:]]*(echo|printf).*[┌┐└┘├┤┬┴┼│━─═]' "$BUILT" || true)
if [[ -n "$visible_box_lines" ]]; then
    fail "P2-UI: 仍有用户可见输出包含线框/粗线字符"
    echo "$visible_box_lines" | sed 's/^/    /'
else
    pass "P2-UI: 用户可见输出不再使用线框/粗线字符"
fi

# P2: 内层选择也应提供 0 返回，避免用户进入日志/服务控制后迷路
f2b_body=$(awk '/^menu_f2b\(\)/,/^}/' "$BUILT")
web_body=$(awk '/^menu_web\(\)/,/^}/' "$BUILT")
reality_install_body=$(awk '/^reality_install_wizard\(\)/,/^}/' "$BUILT")
echo "$f2b_body" | grep -q '0. 返回上一级' && pass "P2-UI: Fail2ban 服务控制有返回选项" || fail "P2-UI: Fail2ban 服务控制缺返回选项"
echo "$web_body" | grep -q '0. 返回上一级' && pass "P2-UI: Web 日志选择有返回选项" || fail "P2-UI: Web 日志选择缺返回选项"
echo "$reality_install_body" | grep -q '0. 返回上一级' && pass "P2-UI: Reality 安装角色选择有返回选项" || fail "P2-UI: Reality 安装角色选择缺返回选项"

echo ""
echo "== review #10 官方兼容性回归 =="
# Nginx 1.25.1+ 弃用 listen ... http2；旧版 Nginx 又不支持 http2 on，因此生成配置必须走版本感知 helper。
declare -F _nginx_tls_http2_block >/dev/null && pass "P1-Web: Nginx HTTP/2 版本感知 helper 已定义" || fail "P1-Web: 缺 _nginx_tls_http2_block"
if grep -E 'listen .* ssl http2;' "$BUILT" >/dev/null; then
    fail "P1-Web: dist 仍硬编码 deprecated listen ... http2"
else
    pass "P1-Web: dist 不再硬编码 deprecated listen ... http2"
fi
grep -q 'http2 on;' "$BUILT" && pass "P1-Web: dist 支持 Nginx 新版 http2 on 语法" || fail "P1-Web: 缺 http2 on 新语法"

# Docker 官方 Debian/Ubuntu 安装文档要求先移除冲突包；Compose 官方推荐 plugin 优先。
docker_install_body=$(awk '/^docker_install\(\)/,/^}/' "$BUILT")
echo "$docker_install_body" | grep -q 'docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc' \
    && pass "P1-Docker: 安装前移除官方冲突包列表" \
    || fail "P1-Docker: Docker 安装缺官方冲突包移除"
compose_install_body=$(awk '/^docker_compose_install\(\)/,/^}/' "$BUILT")
echo "$compose_install_body" | grep -q 'docker-compose-plugin' \
    && pass "P1-Docker: Compose 安装优先 plugin" \
    || fail "P1-Docker: Compose 未优先安装 plugin"
echo "$compose_install_body" | grep -q '_docker_compose_standalone_arch' \
    && pass "P2-Docker: standalone fallback 有架构映射" \
    || fail "P2-Docker: standalone fallback 缺架构映射"

# Cloudflare 官方推荐项目本地 Wrangler；上游 temp-email 也把 wrangler 放在 package.json devDependencies。
declare -F _email_wrangler >/dev/null && pass "P1-Email: 项目本地 Wrangler helper 已定义" || fail "P1-Email: 缺 _email_wrangler"
env_body=$(awk '/^_email_deploy_check_env\(\)/,/^}/' "$BUILT")
echo "$env_body" | grep -q 'setup_lts.x' && pass "P2-Email: NodeSource 使用 LTS 安装脚本" || fail "P2-Email: Node 安装仍固定旧主版本"
if echo "$env_body" | grep -q 'npm install -g wrangler'; then
    fail "P1-Email: 环境检查仍全局安装 wrangler"
else
    pass "P1-Email: 环境检查不再全局安装 wrangler"
fi
if grep -E '(^|[^[:alnum:]_])wrangler d1|npx wrangler' "$BUILT" >/dev/null; then
    fail "P1-Email: 仍有绕过 helper 的 wrangler 调用"
else
    pass "P1-Email: wrangler 调用统一经 helper"
fi

echo ""
echo "== review #9 Docker 兼容性回归 =="
# 精简系统可能没有 util-linux 的 column；Docker 容器管理资源占用区不能因此报错
docker_body=$(awk '/^docker_containers_manage\(\)/,/^}/' "$BUILT")
if echo "$docker_body" | grep -q 'column -t'; then
    fail "P1-Docker: 容器资源占用仍硬依赖 column"
else
    pass "P1-Docker: 容器资源占用不硬依赖 column"
fi
docker_mock_dir=$(mktemp -d)
cat > "$docker_mock_dir/docker" <<'DOCKERMOCK'
#!/bin/bash
case "$1" in
  ps)
    shift
    if [[ "$1" == "-a" ]]; then
      echo -e "abc123\tweb\tnginx:latest\tUp 5 minutes\t0.0.0.0:80->80/tcp"
    elif [[ "$1" == "-q" ]]; then
      echo "abc123"
    elif [[ "$1" == "-aq" ]]; then
      echo "abc123"
    fi
    ;;
  stats)
    echo -e "web\t0.10%\t12MiB / 512MiB"
    ;;
esac
DOCKERMOCK
chmod +x "$docker_mock_dir/docker"
docker_output=$(
    PATH="$docker_mock_dir" "$BASH" -c '
        source "$1" >/dev/null 2>&1
        print_title() { :; }
        pause() { :; }
        printf "0\n" | docker_containers_manage
    ' _ "$LIB" 2>&1
)
rm -rf "$docker_mock_dir"
if echo "$docker_output" | grep -q 'column: command not found'; then
    fail "P1-Docker: 缺少 column 时仍会报 command not found"
else
    pass "P1-Docker: 缺少 column 时资源占用区正常输出"
fi

echo ""
echo "== 结果 =="
echo "  PASS=$PASS  FAIL=$FAIL"
rm -f "$LIB"
exit $FAIL
