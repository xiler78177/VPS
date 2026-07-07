#!/bin/bash
# 远程验证：P0/P1/P2 修复
set -u
export LC_ALL=C.UTF-8

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILT="${BUILT:-$ROOT/dist/v4-built.sh}"
TMP_SMOKE_ROOT=$(mktemp -d)
LIB="$TMP_SMOKE_ROOT/v4-lib.sh"
PASS=0; FAIL=0
pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
mode_is_600() {
    local file="$1" mode
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
    esac
    mode="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)"
    [[ "$mode" == "600" ]]
}

[[ -f "$BUILT" ]] || { echo "构建产物不存在: $BUILT，请先运行 bash build.sh"; exit 1; }
head -n -1 "$BUILT" > "$LIB"
cat >> "$LIB" <<'STUB'
install_package() { return 0; }
auto_deps() { return 0; }
STUB
source "$LIB" >/dev/null 2>&1 || { echo "source 失败"; exit 1; }

# --- hermetic 包装：隔离对宿主机 SSH 环境的耦合，避免在真实服务器上误报 ---
# _sshd_set_directive 会检查宿主机 /etc/ssh/sshd_config.d/*.conf 是否已有同名 directive，
# 命中则走 confirm；而本测试非交互（confirm 见 [[ ! -t 0 ]] 即 return 1），会导致函数
# 不改文件而报失败。这里临时把 confirm 置为自动接受，只验证指令写入逻辑本身（与宿主机
# 是否存在同名 drop-in 解耦），调用后立即恢复原 confirm。
run_set_directive() {
    local __sv; __sv=$(declare -f confirm)
    confirm() { return 0; }
    _sshd_set_directive "$@"
    local __rc=$?
    eval "$__sv"
    return $__rc
}

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
# ddns-update.sh cron 模板和管理端列表/删除都应使用 parse_ddns_conf，避免解析逻辑漂移。
grep -q 'parse_ddns_conf' "$BUILT" && pass "DDNS cron 模板已嵌入 parse_ddns_conf 替代裸 source" || fail "未找到 parse_ddns_conf"
if grep -qE '^[[:space:]]*source[[:space:]]+"\$conf"' "$BUILT"; then
    fail "DDNS 管理端仍有 source \"\$conf\"，与 cron 白名单解析逻辑漂移"
else
    pass "DDNS 管理端不再 source 配置文件"
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
run_set_directive "PermitRootLogin" "no" "$tmpfile" >/dev/null 2>&1
if grep -q '^PermitRootLogin no$' "$tmpfile"; then
    pass "未命中时正确追加 PermitRootLogin no"
else
    fail "追加失败 — file 内容:"; cat "$tmpfile" | sed 's/^/    /'
fi
# 再试已有但被注释
echo '#PasswordAuthentication yes' > "$tmpfile"
run_set_directive "PasswordAuthentication" "no" "$tmpfile" >/dev/null 2>&1
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
if grep -qF 'eval "$check_cmd"' "$BUILT" || grep -qF 'eval "$install_func"' "$BUILT"; then
    fail "Web 依赖检查仍用 eval 执行字符串"
else
    pass "Web 依赖检查不再用 eval 执行字符串"
fi
grep -q 'swapoff -a' "$BUILT" \
    && fail "Swap 删除仍会 swapoff -a 关闭全机 swap" \
    || pass "Swap 删除只关闭受管 /swapfile"
grep -q '^_swap_fstab_remove_swapfile()' "$BUILT" \
    && pass "Swap fstab 删除使用精确 helper" \
    || fail "Swap fstab 删除缺少精确 helper"
swap_add_body=$(awk '/^_swap_fstab_add_swapfile\(\)/,/^_swap_fstab_remove_swapfile\(\)/' "$BUILT")
if echo "$swap_add_body" | grep -Fq 'mktemp "${fstab_dir}/.tmp.server-manage.fstab.XXXXXX"' \
   && echo "$swap_add_body" | grep -Fq 'mv "$tmp" "$fstab"' \
   && ! echo "$swap_add_body" | grep -q '>> "\$fstab"'; then
    pass "Swap fstab 添加使用候选文件原子替换"
else
    fail "Swap fstab 添加仍可能直接追加污染 /etc/fstab"
fi
if grep -q 'SERVER_MANAGE_SWAP_FILE\|SERVER_MANAGE_FSTAB_FILE' "$BUILT"; then
    fail "Swap 生产路径仍可被环境变量覆盖"
else
    pass "Swap 生产路径固定为 /swapfile 与 /etc/fstab"
fi

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
fw_udp_body=$(awk '/^firewall_allow_udp_port\(\)/,/^firewall_apply_reality_port\(\)/' "$BUILT")
if echo "$fw_body" | grep -Eq 'ufw default|ufw [^a]*enable|install_package ufw'; then
    fail "P1-C: firewall_allow_tcp_port 仍含 install/default/enable"
    echo "$fw_body" | grep -nE 'ufw default|ufw [^a]*enable|install_package ufw' | sed 's/^/    /'
else
    pass "P1-C: firewall_allow_tcp_port 仅追加规则，不启用 UFW"
fi
echo "$fw_body" | grep -q '防火墙管理' && pass "P1-C: UFW 未启用时引导至防火墙菜单" || fail "P1-C: 缺引导提示"
if echo "$fw_udp_body" | grep -q 'ufw allow "\${port}/udp" comment "\$comment"' \
   && echo "$fw_udp_body" | grep -q 'return 2' \
   && ! echo "$fw_udp_body" | grep -Eq 'ufw default|ufw [^a]*enable|install_package ufw'; then
    pass "P1-C: firewall_allow_udp_port 仅追加 UDP 规则，不启用 UFW"
else
    fail "P1-C: firewall_allow_udp_port 缺失或仍会自动启用/重置 UFW"
fi

# P1-D: ssh_change_port 改完用 sshd -T 校验生效端口
ssh_body=$(awk '/^ssh_change_port\(\)/,/^}/' "$BUILT")
echo "$ssh_body" | grep -q 'sshd -T' && pass "P1-D: ssh_change_port 用 sshd -T 校验" || fail "P1-D: 缺 sshd -T 校验"
echo "$ssh_body" | grep -q 'sshd_config.d' && pass "P1-D: ssh_change_port 检测 drop-in" || fail "P1-D: 未检测 drop-in"
echo "$ssh_body" | grep -q 'effective_port' && pass "P1-D: 重启后比对实际生效端口" || fail "P1-D: 未比对生效端口"
echo "$ssh_body" | grep -q '_sshd_set_directive "Port" "$port" "$target_conf" 1' \
    && ! echo "$ssh_body" | grep -q 'sed -i.*Port' \
    && pass "P1-D: ssh_change_port 使用全局 directive helper 写 Port" \
    || fail "P1-D: ssh_change_port 可能把 Port 写入 Match 块"

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
email_dns_find_body=$(awk '/^_email_cf_dns_find_ids\(\)/,/^}/' "$BUILT")
echo "$email_dns_find_body" | grep -q 'page=1' \
    && echo "$email_dns_find_body" | grep -q 'per_page=\$per_page&page=\$page' \
    && pass "P2-1: Email DNS 记录查找支持分页" \
    || fail "P2-1: Email DNS 记录查找仍可能只读第一页"

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
grep -qE 'VERSION="v[0-9]+\.[0-9]+"' "$BUILT" && pass "P3: VERSION 格式合法 (v<主>.<次>)" || fail "P3: VERSION 缺失或格式异常"

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
masked_token=$(printf '%s\n' 'TOKEN=super-secret-value' 'CF_API_TOKEN: cf-secret-value' | _email_redact_secrets 2>/dev/null)
if echo "$masked_token" | grep -q '<redacted>' \
   && ! echo "$masked_token" | grep -q 'super-secret-value' \
   && ! echo "$masked_token" | grep -q 'cf-secret-value'; then
    pass "P1-1: TOKEN 形式日志已脱敏"
else
    fail "P1-1: TOKEN 形式日志脱敏失败，masked='$masked_token'"
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
min_render_body=$(awk '/^_email_render_min_toml\(\)/,/^}/' "$BUILT")
if grep -q '^_email_write_private_file()' "$BUILT" \
   && echo "$min_render_body" | grep -q '_email_write_private_file "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"' \
   && echo "$render_body" | grep -q '_email_write_private_file "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"' \
   && ! echo "$min_render_body$render_body" | grep -q 'cat > "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"'; then
    pass "P2-2: wrangler.toml 通过私有原子写入"
else
    fail "P2-2: wrangler.toml 仍可能先宽权限写入再 chmod"
fi
patch_pages_body=$(awk '/^_email_patch_pages_service_binding\(\)/,/^_email_restore_pages_service_binding\(\)/' "$BUILT")
if echo "$patch_pages_body" | grep -q 'mktemp "\${pages_dir}/.wrangler.toml.bak.XXXXXX"' \
   && ! echo "$patch_pages_body" | grep -q '/tmp/server-manage-pages-wrangler'; then
    pass "P2-2: pages/wrangler.toml 临时备份使用同目录 mktemp"
else
    fail "P2-2: pages/wrangler.toml 临时备份仍可能落公共 /tmp"
fi

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
echo "$dns_body" | grep -qF 'if ! _email_cf_dns_purge "$zid" MX "$EMAIL_DOMAIN"; then' \
    && pass "P1-1: MX purge 失败时停止创建新 MX" \
    || fail "P1-1: MX purge 失败仍可能继续创建新 MX"
echo "$dns_body" | grep -q '_resend_purge_fail=0' \
    && echo "$dns_body" | grep -q '_resend_create_fail=0' \
    && echo "$dns_body" | grep -q 'EMAIL_RESEND_ENABLED=0' \
    && pass "P1-1: 首次部署 Resend DNS 失败会取消启用状态" \
    || fail "P1-1: 首次部署 Resend DNS 失败未 fail-closed"
secrets_body=$(awk '/^_email_deploy_secrets\(\)/,/^}/' "$BUILT")
echo "$secrets_body" | grep -q 'RESEND_TOKEN 配置失败' \
    && echo "$secrets_body" | grep -q 'EMAIL_RESEND_ENABLED=0' \
    && echo "$secrets_body" | grep -q 'return 1' \
    && pass "P1-1: 首次部署 RESEND_TOKEN secret 失败会中止部署" \
    || fail "P1-1: RESEND_TOKEN secret 失败仍可能继续部署"
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
echo "$admin_var_body" | grep -q '_email_write_private_file "\$toml" "\$content"' \
    && pass "P2-5: 回退 helper 使用私有原子写入 wrangler.toml" \
    || fail "P2-5: 回退 helper 未使用私有原子写入"
if echo "$admin_var_body" | grep -q 'wrangler.toml.tmp'; then
    fail "P2-5: 回退 helper 仍使用可预测 wrangler.toml.tmp"
else
    pass "P2-5: 回退 helper 无可预测 wrangler.toml.tmp"
fi
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
docker_install_helpers_body=$(awk '/^_docker_keyring_path\(\)/,/^docker_install\(\)/' "$BUILT")
echo "$docker_install_body" | grep -q 'docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc' \
    && pass "P1-Docker: 安装前移除官方冲突包列表" \
    || fail "P1-Docker: Docker 安装缺官方冲突包移除"
if echo "$docker_install_body" | grep -Fq 'apt-get update -qq >/dev/null 2>&1' \
   && echo "$docker_install_body" | grep -Fq 'pause; return 1' \
   && echo "$docker_install_body" | grep -Fq 'Docker 已安装但服务启动失败。'; then
    pass "P1-Docker: Docker 安装失败分支返回非 0"
else
    fail "P1-Docker: Docker 安装失败分支仍可能返回成功"
fi
compose_install_body=$(awk '/^docker_compose_install\(\)/,/^}/' "$BUILT")
echo "$compose_install_body" | grep -q 'docker-compose-plugin' \
    && pass "P1-Docker: Compose 安装优先 plugin" \
    || fail "P1-Docker: Compose 未优先安装 plugin"
echo "$compose_install_body" | grep -q '_docker_compose_standalone_arch' \
    && pass "P2-Docker: standalone fallback 有架构映射" \
    || fail "P2-Docker: standalone fallback 缺架构映射"
if echo "$compose_install_body" | grep -Fq '_docker_compose_install_standalone "$compose_url"' \
   && echo "$compose_install_body" | grep -Fq 'pause; return 1'; then
    pass "P2-Docker: Compose plugin+standalone 均失败时返回非 0"
else
    fail "P2-Docker: Compose 安装完全失败仍可能返回成功"
fi

# Cloudflare 官方推荐项目本地 Wrangler；上游 temp-email 也把 wrangler 放在 package.json devDependencies。
declare -F _email_wrangler >/dev/null && pass "P1-Email: 项目本地 Wrangler helper 已定义" || fail "P1-Email: 缺 _email_wrangler"
env_body=$(awk '/^_email_deploy_check_env\(\)/,/^}/' "$BUILT")
echo "$env_body" | grep -q 'setup_lts.x' && pass "P2-Email: NodeSource 使用 LTS 安装脚本" || fail "P2-Email: Node 安装仍固定旧主版本"
if echo "$env_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/server-manage-email-node.XXXXXX"' \
   && echo "$env_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$env_body" | grep -q 'rm -rf "\$tmp_dir"' \
   && ! echo "$env_body" | grep -q 'tmp=$(mktemp)'; then
    pass "P2-Email: NodeSource setup 脚本使用私有临时目录"
else
    fail "P2-Email: NodeSource setup 脚本仍可能落公共临时文件"
fi
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
echo "== review #11 审计报告高风险回归 =="
# H6: Web 子域名前缀必须按 DNS label 校验，避免路径/nginx/crontab 注入。
declare -F validate_dns_label >/dev/null && pass "H6: validate_dns_label 已定义" || fail "H6: 缺 validate_dns_label"
validate_dns_label "mail-api" && pass "H6: DNS label 接受 mail-api" || fail "H6: DNS label 应接受 mail-api"
validate_dns_label "-bad" && fail "H6: DNS label 不应接受首字符短横" || pass "H6: DNS label 拒绝首字符短横"
validate_dns_label 'bad;root' && fail "H6: DNS label 不应接受注入字符" || pass "H6: DNS label 拒绝注入字符"
web_add_body=$(awk '/^web_add_domain\(\)/,/^}/' "$BUILT")
home_expose_body=$(awk '/^web_home_expose\(\)/,/^_replace_proxy_pass_backend\(\)/' "$BUILT")
echo "$web_add_body" | grep -q 'validate_dns_label "$sub_prefix"' \
    && pass "H6: 添加域名校验子域名前缀" \
    || fail "H6: 添加域名未校验子域名前缀"
echo "$home_expose_body" | grep -q 'validate_dns_label "$sub_prefix"' \
    && pass "H6: 家宽公网暴露校验子域名前缀" \
    || fail "H6: 家宽公网暴露未校验子域名前缀"

# H7/H8: WG 新增网关展示必须使用新增 peer 的真实索引；导入 peer 必须校验 name/ip。
wg_add_body=$(awk '/^wg_add_peer\(\)/,/^}/' "$BUILT")
echo "$wg_add_body" | grep -q 'local target_idx="$pc"' \
    && pass "H7: wg_add_peer 记录新增 peer 索引" \
    || fail "H7: wg_add_peer 未记录新增 peer 索引"
wg_import_body=$(awk '/^wg_import_peers\(\)/,/^}/' "$BUILT")
echo "$wg_import_body" | grep -q '名称格式无效' \
    && pass "H8: WG 导入校验 peer name" \
    || fail "H8: WG 导入缺 peer name 校验"
echo "$wg_import_body" | grep -q 'IP 格式无效' \
    && pass "H8: WG 导入校验 peer IP" \
    || fail "H8: WG 导入缺 peer IP 校验"

# P2: 错误/警告应写 stderr，避免命令替换吞掉诊断文本或污染返回值。
stdout_file=$(mktemp); stderr_file=$(mktemp)
print_error "stderr-check" >"$stdout_file" 2>"$stderr_file"
if [[ ! -s "$stdout_file" && -s "$stderr_file" ]]; then
    pass "P2: print_error 输出到 stderr"
else
    fail "P2: print_error 未只输出到 stderr"
fi
>"$stdout_file"; >"$stderr_file"
print_warn "stderr-check" >"$stdout_file" 2>"$stderr_file"
if [[ ! -s "$stdout_file" && -s "$stderr_file" ]]; then
    pass "P2: print_warn 输出到 stderr"
else
    fail "P2: print_warn 未只输出到 stderr"
fi
rm -f "$stdout_file" "$stderr_file"

# P3/P4: UFW active 检测集中到 LANG=C helper；grep -c 不再接 `|| echo 0`。
declare -F ufw_is_active >/dev/null && pass "P3: ufw_is_active helper 已定义" || fail "P3: 缺 ufw_is_active helper"
if grep -R 'ufw status .*grep -q "Status: active"\|ufw status | grep -q "Status: active"' modules >/dev/null 2>&1; then
    fail "P3: 仍有 locale 敏感的 ufw status active 检测"
else
    pass "P3: 无 locale 敏感的 ufw status active 检测"
fi
if grep -R 'grep -c .*|| echo 0' modules >/dev/null 2>&1; then
    fail "P4: 仍有 grep -c ... || echo 0 反模式"
else
    pass "P4: grep -c 反模式已清理"
fi


echo ""
echo "== review #12 审计报告锁外/Cloudflare 回归 =="
# H2: socket activation 环境不能只信 sshd_config/sshd -T，删旧端口前必须确认新端口真实监听。
declare -F _ssh_socket_activation_active >/dev/null && pass "H2: SSH socket activation 检测 helper 已定义" || fail "H2: 缺 _ssh_socket_activation_active"
declare -F _ssh_port_is_listening >/dev/null && pass "H2: SSH 监听端口检测 helper 已定义" || fail "H2: 缺 _ssh_port_is_listening"
restart_body=$(awk '/^_restart_sshd\(\)/,/^}/' "$BUILT")
echo "$restart_body" | grep -q 'ssh.socket' \
    && pass "H2: _restart_sshd 识别 ssh.socket" \
    || fail "H2: _restart_sshd 未处理 ssh.socket"
ssh_change_body=$(awk '/^ssh_change_port\(\)/,/^}/' "$BUILT")
echo "$ssh_change_body" | grep -q '_ssh_port_is_listening "$port"' \
    && pass "H2: ssh_change_port 校验真实监听端口" \
    || fail "H2: ssh_change_port 未校验真实监听端口"
if awk '
    /^ssh_change_port\(\)/ { in_fn=1 }
    in_fn && /_ssh_port_is_listening "\$port"/ { listen=NR }
    in_fn && /ufw delete allow "\$CURRENT_SSH_PORT\/tcp"/ { del=NR }
    in_fn && /^}/ { exit !(listen && del && listen < del) }
' "$BUILT"; then
    pass "H2: 删除旧 UFW 端口规则发生在真实监听校验之后"
else
    fail "H2: 旧 UFW 端口规则删除顺序不安全"
fi

# H2b: socket activation 误判回归（锁机事故根因）。
# ssh.socket enabled-but-inactive 是 Debian/Ubuntu 默认常态，真正监听 22 的是 ssh.service。
# _ssh_socket_unit 绝不能因 is-enabled 命中就把普通机器误判为 socket activation，
# 否则会写 socket drop-in + 重启 ssh.socket，造成 socket/service 冲突锁死（只能 DD）。
_h2b_tmp=$(mktemp)
(
    is_systemd() { return 0; }
    systemctl() {
        local verb="" unit=""
        for a in "$@"; do
            case "$a" in
                is-active|is-enabled) verb="$a" ;;
                ssh.socket|sshd.socket) unit="$a" ;;
            esac
        done
        case "$verb:$unit" in
            is-active:ssh.socket)  return 3 ;;   # inactive（普通机器常态）
            is-enabled:ssh.socket) return 0 ;;   # enabled
            *) return 3 ;;
        esac
    }
    if _ssh_socket_unit >/dev/null 2>&1; then echo FAIL; else echo PASS; fi
) > "$_h2b_tmp" 2>/dev/null
[[ "$(cat "$_h2b_tmp")" == PASS ]] \
    && pass "H2b: enabled-but-inactive ssh.socket 不被误判为 socket activation（锁机事故根因）" \
    || fail "H2b: ssh.socket enabled-but-inactive 被误判为 activation —— 会锁死机器"
rm -f "$_h2b_tmp"

# H2c: 真正 active 的 ssh.socket 仍须被识别为 socket activation
_h2c_tmp=$(mktemp)
(
    is_systemd() { return 0; }
    systemctl() {
        local verb="" unit=""
        for a in "$@"; do
            case "$a" in
                is-active|is-enabled|show) verb="$a" ;;
                ssh.socket|sshd.socket) unit="$a" ;;
            esac
        done
        case "$verb:$unit" in
            is-active:ssh.socket) return 0 ;;    # active → 真 socket activation
            show:ssh.socket) echo "Listen=[::]:22 (Stream)"; return 0 ;;
            *) return 3 ;;
        esac
    }
    if [[ "$(_ssh_socket_unit 2>/dev/null)" == ssh.socket ]]; then echo PASS; else echo FAIL; fi
) > "$_h2c_tmp" 2>/dev/null
[[ "$(cat "$_h2c_tmp")" == PASS ]] \
    && pass "H2c: active 的 ssh.socket 仍被识别为 socket activation" \
    || fail "H2c: active 的 ssh.socket 未被识别"
rm -f "$_h2c_tmp"

# H2d: 源码层面断言 _ssh_socket_unit 不再用 is-enabled 判据（排除注释行，注释里会引用该词解释原因）
socket_unit_body=$(awk '/^_ssh_socket_unit\(\)/,/^}/' "$BUILT")
echo "$socket_unit_body" | grep -v '^[[:space:]]*#' | grep -q 'is-enabled' \
    && fail "H2d: _ssh_socket_unit 仍含 is-enabled —— enabled-but-inactive 会误判锁机" \
    || pass "H2d: _ssh_socket_unit 已移除 is-enabled 判据"

# H2e/H2f: UFW 未启用但 iptables/nft INPUT 有 REJECT/DROP 时，SSH 改端口必须先放行新端口。
declare -F firewall_prepare_non_ufw_ssh_port >/dev/null \
    && pass "H2e: 非 UFW 本地防火墙预放行 helper 已定义" \
    || fail "H2e: 缺 firewall_prepare_non_ufw_ssh_port"
declare -F firewall_rollback_ssh_port >/dev/null \
    && pass "H2e: 非 UFW 防火墙回滚 helper 已定义" \
    || fail "H2e: 缺 firewall_rollback_ssh_port"
declare -F firewall_prepare_non_ufw_udp_port >/dev/null \
    && pass "H2e: 非 UFW UDP 防火墙预放行 helper 已定义" \
    || fail "H2e: 缺 firewall_prepare_non_ufw_udp_port"
declare -F firewall_rollback_udp_port >/dev/null \
    && pass "H2e: 非 UFW UDP 防火墙回滚 helper 已定义" \
    || fail "H2e: 缺 firewall_rollback_udp_port"
echo "$ssh_change_body" | grep -q 'firewall_prepare_non_ufw_ssh_port' \
    && pass "H2e: ssh_change_port 在 UFW 未启用时检查 iptables/nftables" \
    || fail "H2e: ssh_change_port 未处理 UFW 以外的本地防火墙"
echo "$ssh_change_body" | grep -Fq 'ListenStream=0.0.0.0:${port}' \
    && echo "$ssh_change_body" | grep -Fq 'ListenStream=[::]:${port}' \
    && pass "H2e: socket activation drop-in 同时监听 IPv4 和 IPv6" \
    || fail "H2e: socket drop-in 不能只写裸 ListenStream=\${port}（会在 BindIPv6Only=ipv6-only 下丢 IPv4）"
echo "$ssh_change_body" | grep -Fq 'mktemp "${socket_dropin_dir}/.tmp.server-manage.ssh-socket.XXXXXX"' \
    && echo "$ssh_change_body" | grep -Fq 'mv "$socket_tmp" "$socket_dropin"' \
    && ! echo "$ssh_change_body" | grep -q 'cat > "$socket_dropin"' \
    && pass "H2e: socket activation drop-in 通过临时文件原子替换" \
    || fail "H2e: socket activation drop-in 仍可能直写最终 systemd 配置"

_h2e_tmp=$(mktemp)
(
    command_exists() { [[ "$1" == "iptables" ]]; }
    iptables() {
        if [[ "$1" == "-S" && "$2" == "INPUT" ]]; then
            cat <<'EOF_FW'
-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
EOF_FW
            return 0
        fi
        return 1
    }
    if _firewall_iptables_input_restrictive iptables &&
       _firewall_iptables_has_tcp_accept iptables 22 &&
       ! _firewall_iptables_has_tcp_accept iptables 22222; then
        echo PASS
    else
        echo FAIL
    fi
) > "$_h2e_tmp" 2>/dev/null
[[ "$(cat "$_h2e_tmp")" == PASS ]] \
    && pass "H2e: 能识别 Oracle/iptables 风格 INPUT REJECT 只放行旧 22 的锁外场景" \
    || fail "H2e: 未识别 iptables INPUT REJECT 导致的新端口阻断"
rm -f "$_h2e_tmp"

_h2f_tmp=$(mktemp)
_h2f_insert=$(mktemp)
(
    PLATFORM=debian
    is_systemd() { return 1; }
    command_exists() { [[ "$1" == "iptables" ]]; }
    confirm() { return 0; }
    iptables() {
        if [[ "$1" == "-S" && "$2" == "INPUT" ]]; then
            cat <<'EOF_FW'
-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
EOF_FW
            return 0
        fi
        if [[ "$1" == "-I" && "$2" == "INPUT" ]]; then
            printf '%s\n' "$*" > "$_h2f_insert"
            return 0
        fi
        return 1
    }
    if firewall_prepare_non_ufw_ssh_port 22222 >/dev/null 2>&1 &&
       [[ " $FIREWALL_SSH_OPEN_BACKENDS " == *" iptables "* ]] &&
       grep -q -- '--dport 22222' "$_h2f_insert"; then
        echo PASS
    else
        echo FAIL
    fi
) > "$_h2f_tmp" 2>/dev/null
[[ "$(cat "$_h2f_tmp")" == PASS ]] \
    && pass "H2f: UFW inactive + iptables REJECT 时会先插入新 SSH 端口 ACCEPT" \
    || fail "H2f: 未在 iptables REJECT 前预放行新 SSH 端口"
rm -f "$_h2f_tmp" "$_h2f_insert"

_h2g_tmp=$(mktemp)
_h2g_insert=$(mktemp)
(
    PLATFORM=debian
    is_systemd() { return 1; }
    command_exists() { [[ "$1" == "iptables" ]]; }
    confirm() { return 0; }
    iptables() {
        if [[ "$1" == "-S" && "$2" == "INPUT" ]]; then
            cat <<'EOF_FW'
-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
EOF_FW
            return 0
        fi
        if [[ "$1" == "-I" && "$2" == "INPUT" ]]; then
            printf '%s\n' "$*" > "$_h2g_insert"
            return 0
        fi
        return 1
    }
    if firewall_prepare_non_ufw_udp_port 51820 "WireGuard-Debian" >/dev/null 2>&1 &&
       [[ " $FIREWALL_UDP_OPEN_BACKENDS " == *" iptables "* ]] &&
       grep -q -- '-p udp' "$_h2g_insert" &&
       grep -q -- '--dport 51820' "$_h2g_insert"; then
        echo PASS
    else
        echo FAIL
    fi
) > "$_h2g_tmp" 2>/dev/null
[[ "$(cat "$_h2g_tmp")" == PASS ]] \
    && pass "H2g: UFW inactive + iptables REJECT 时会先插入 WireGuard UDP ACCEPT" \
    || fail "H2g: 未在 iptables REJECT 前预放行 WireGuard UDP 端口"
rm -f "$_h2g_tmp" "$_h2g_insert"

# H4: 禁用密码/root 登录前必须做技术前置校验，并用 sshd -T 复验最终有效值。
declare -F _ssh_authorized_keys_available >/dev/null && pass "H4: authorized_keys 前置校验 helper 已定义" || fail "H4: 缺 _ssh_authorized_keys_available"
declare -F _ssh_non_root_sudo_available >/dev/null && pass "H4: 非 root sudo 用户校验 helper 已定义" || fail "H4: 缺 _ssh_non_root_sudo_available"
declare -F _sshd_effective_value >/dev/null && pass "H4: sshd -T 有效值读取 helper 已定义" || fail "H4: 缺 _sshd_effective_value"
ssh_tmp=$(mktemp -d)
mkdir -p "$ssh_tmp/root/.ssh" "$ssh_tmp/home/alice/.ssh"
cat > "$ssh_tmp/passwd" <<EOF_PASSWD
root:x:0:0:root:$ssh_tmp/root:/bin/bash
alice:x:1000:1000:Alice:$ssh_tmp/home/alice:/bin/bash
nolog:x:1001:1001:No Login:$ssh_tmp/home/nolog:/usr/sbin/nologin
EOF_PASSWD
cat > "$ssh_tmp/group" <<EOF_GROUP
sudo:x:27:alice
EOF_GROUP
SSH_ROOT_HOME="$ssh_tmp/root" SSH_PASSWD_FILE="$ssh_tmp/passwd" _ssh_authorized_keys_available \
    && fail "H4: 空 authorized_keys 不应通过" \
    || pass "H4: 空 authorized_keys 被拒绝"
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA test@example' > "$ssh_tmp/home/alice/.ssh/authorized_keys"
SSH_ROOT_HOME="$ssh_tmp/root" SSH_PASSWD_FILE="$ssh_tmp/passwd" _ssh_authorized_keys_available \
    && pass "H4: 存在登录用户公钥时通过" \
    || fail "H4: 有效 authorized_keys 未通过"
SSH_PASSWD_FILE="$ssh_tmp/passwd" SSH_GROUP_FILE="$ssh_tmp/group" _ssh_non_root_sudo_available \
    && pass "H4: 存在非 root sudo 用户时通过" \
    || fail "H4: 非 root sudo 用户未识别"
rm -rf "$ssh_tmp"
grep -q '_ssh_authorized_keys_available' "$BUILT" \
    && pass "H4: 禁用密码流程调用 authorized_keys 校验" \
    || fail "H4: 禁用密码流程未调用 authorized_keys 校验"
grep -q '_sshd_effective_value "passwordauthentication"' "$BUILT" \
    && pass "H4: 禁用密码后复验 PasswordAuthentication" \
    || fail "H4: 禁用密码后未复验 PasswordAuthentication"
grep -q '_ssh_non_root_sudo_available' "$BUILT" \
    && pass "H4: 禁用 root 流程调用非 root sudo 校验" \
    || fail "H4: 禁用 root 流程未校验非 root sudo 用户"
grep -q '_sshd_effective_value "permitrootlogin"' "$BUILT" \
    && pass "H4: 禁用 root 后复验 PermitRootLogin" \
    || fail "H4: 禁用 root 后未复验 PermitRootLogin"

# H3: GeoIP 自动更新必须 fail-closed，下载到临时文件且校验非空，避免白名单集合被 cron 清空。
geoip_download_body=$(awk '/^_geoip_download\(\)/,/^}/' "$BUILT")
echo "$geoip_download_body" | grep -q 'curl -fsSL' \
    && pass "H3: GeoIP 交互下载使用 curl -f" \
    || fail "H3: GeoIP 交互下载未使用 curl -f"
echo "$geoip_download_body" | grep -q 'mktemp' \
    && pass "H3: GeoIP 交互下载使用临时文件" \
    || fail "H3: GeoIP 交互下载未使用临时文件"
echo "$geoip_download_body" | grep -q '\[\[ \$fail -eq 0 \]\]' \
    && pass "H3: GeoIP 任一国家失败即拒绝应用" \
    || fail "H3: GeoIP 仍允许部分国家失败后继续"
geoip_apply_body=$(awk '/^_geoip_apply\(\)/,/^}/' "$BUILT")
echo "$geoip_apply_body" | grep -q 'total_entries' \
    && pass "H3: GeoIP apply 统计有效条目" \
    || fail "H3: GeoIP apply 未统计有效条目"
echo "$geoip_apply_body" | grep -q 'return 1' \
    && pass "H3: GeoIP apply 可拒绝空集合/失败 swap" \
    || fail "H3: GeoIP apply 失败路径缺失"
grep -q 'curl -fsSL --connect-timeout 10 --max-time 30' "$BUILT" \
    && pass "H3: GeoIP cron 下载使用 curl -f/超时" \
    || fail "H3: GeoIP cron 下载仍不安全"
grep -q '/usr/local/bin/geoip-apply.sh || exit 1' "$BUILT" \
    && pass "H3: GeoIP cron apply 失败会中止" \
    || fail "H3: GeoIP cron 未检查 apply 结果"

# H5/P1: Cloudflare GET 失败必须与“不存在”区分，Origin Rules 不允许读取失败后全量 PUT 空数组。
cf_get_origin_body=$(awk '/^_cf_get_origin_ruleset\(\)/,/^}/' "$BUILT")
echo "$cf_get_origin_body" | grep -q -- '--max-time 30' \
    && pass "H5: Origin Rules GET 设置超时" \
    || fail "H5: Origin Rules GET 缺超时"
echo "$cf_get_origin_body" | grep -q 'curl_rc' \
    && pass "H5: Origin Rules GET 检查 curl 返回码" \
    || fail "H5: Origin Rules GET 未检查 curl 返回码"
echo "$cf_get_origin_body" | grep -q '_cf_api_ok "$body"' \
    && pass "H5: Origin Rules GET 校验 Cloudflare success" \
    || fail "H5: Origin Rules GET 未校验 success"
home_origin_block=$(awk '/existing=\$\(_cf_get_origin_ruleset "\$token" "\$zone_id"\)/,/local final_rules=/' "$BUILT")
echo "$home_origin_block" | grep -q 'if ! existing=' \
    && pass "H5: 家宽一键流程检查 Origin Rules 读取结果" \
    || fail "H5: 家宽一键流程未检查 Origin Rules 读取结果"
list_body=$(awk '/^web_cf_origin_rule_list\(\)/,/^}/' "$BUILT")
delete_body=$(awk '/^web_cf_origin_rule_delete\(\)/,/^web_cf_main_menu\(\)/' "$BUILT")
echo "$list_body" | grep -q 'if ! resp=' \
    && pass "P1: Origin Rules 列表检查 GET 失败" \
    || fail "P1: Origin Rules 列表未检查 GET 失败"
echo "$delete_body" | grep -q 'if ! resp=' \
    && pass "P1: Origin Rules 删除检查 GET 失败" \
    || fail "P1: Origin Rules 删除未检查 GET 失败"
echo "$delete_body" | grep -Fq '[[ ! "$choice" =~ ^[0-9]+$ ]]' \
    && pass "P1: Origin Rules 删除拒绝非纯数字编号" \
    || fail "P1: Origin Rules 删除仍可能接受算术表达式编号"
cf_update_body=$(awk '/^_cf_update_dns_record\(\)/,/^}/' "$BUILT")
echo "$cf_update_body" | grep -q '_cf_api_ok "$records"' \
    && pass "P1: DNS 更新检查 GET success" \
    || fail "P1: DNS 更新未检查 GET success"
echo "$cf_update_body" | grep -q '记录缺少目标 IP' \
    && pass "P1: DNS 更新拒绝空目标 IP" \
    || fail "P1: DNS 更新仍可能空 IP 静默成功"
cf_put_origin_body=$(awk '/^_cf_put_origin_ruleset\(\)/,/^}/' "$BUILT")
echo "$cf_put_origin_body" | grep -q -- '--connect-timeout 10 --max-time 30 -X PUT' \
    && pass "P1: Origin Rules PUT 设置超时" \
    || fail "P1: Origin Rules PUT 缺少超时"
cf_delete_body=$(awk '/^_cf_dns_delete\(\)/,/^}/' "$BUILT")
echo "$cf_delete_body" | grep -q 'resp=\$(_cf_api DELETE' \
    && echo "$cf_delete_body" | grep -q '_cf_api_ok "$resp"' \
    && pass "P1: DNS 删除检查 DELETE success" \
    || fail "P1: DNS 删除未检查 DELETE success"
reality_cf_delete_dns_body=$(awk '/^reality_cf_delete_dns_type\(\)/,/^reality_sync_cloudflare_dns\(\)/' "$BUILT")
echo "$reality_cf_delete_dns_body" | grep -q 'page=1' \
    && echo "$reality_cf_delete_dns_body" | grep -q 'per_page=\$per_page&page=\$page' \
    && echo "$reality_cf_delete_dns_body" | grep -q 'del_resp=\$(_cf_api DELETE' \
    && echo "$reality_cf_delete_dns_body" | grep -q '_cf_api_ok "\$del_resp"' \
    && pass "P1: Reality DNS 清理分页且检查 DELETE success" \
    || fail "P1: Reality DNS 清理仍可能漏页或吞 DELETE success=false"
web_home_expose_body=$(awk '/^web_home_expose\(\)/,/^web_view_config\(\)/' "$BUILT")
echo "$web_home_expose_body" | grep -q 'if ! _cf_dns_delete "\$zone_id" "\$token" "CNAME" "\$full_domain"' \
    && pass "P1: 家宽暴露清理旧 CNAME 失败会中止" \
    || fail "P1: 家宽暴露仍可能吞掉旧 CNAME 删除失败"
echo "$web_home_expose_body" | grep -q 'Origin Rules 读取失败，端口回源规则未创建' \
    && echo "$web_home_expose_body" | grep -q 'return 1' \
    && pass "P1: 家宽暴露必要 Origin Rule 失败会中止" \
    || fail "P1: 家宽暴露 Origin Rule 必要失败仍可能继续完成"


echo ""
echo "== review #13 审计报告安全细节回归 =="
# S2: 修改 sshd_config 指令时不得改写 Match 块内缩进例外。
ssh_match_tmp=$(mktemp)
cat > "$ssh_match_tmp" <<'EOF_SSHD_MATCH'
PasswordAuthentication yes
Match User alice
    PasswordAuthentication yes
EOF_SSHD_MATCH
run_set_directive "PasswordAuthentication" "no" "$ssh_match_tmp" >/dev/null 2>&1
if grep -q '^PasswordAuthentication no$' "$ssh_match_tmp" && grep -q '^    PasswordAuthentication yes$' "$ssh_match_tmp"; then
    pass "S2: _sshd_set_directive 只改全局指令，不改 Match 块"
else
    fail "S2: _sshd_set_directive 误改 Match 块"
    sed 's/^/    /' "$ssh_match_tmp"
fi
cat > "$ssh_match_tmp" <<'EOF_SSHD_ONLY_MATCH'
Match User alice
    PermitRootLogin yes
EOF_SSHD_ONLY_MATCH
run_set_directive "PermitRootLogin" "no" "$ssh_match_tmp" >/dev/null 2>&1
if awk 'BEGIN{ok=0} /^PermitRootLogin no$/{global=NR} /^Match /{matchline=NR} END{exit !(global && matchline && global < matchline)}' "$ssh_match_tmp"; then
    pass "S2: 无全局指令时插入到首个 Match 之前"
else
    fail "S2: 无全局指令时未插入到 Match 之前"
    sed 's/^/    /' "$ssh_match_tmp"
fi
rm -f "$ssh_match_tmp"

# S1: SSH 改端口同步 Fail2ban 时只能改 [sshd] jail，不能污染 nginx/http jail。
declare -F _fail2ban_set_sshd_port >/dev/null && pass "S1: Fail2ban sshd 端口 helper 已定义" || fail "S1: 缺 _fail2ban_set_sshd_port"
f2b_tmp=$(mktemp)
cat > "$f2b_tmp" <<'EOF_F2B'
[sshd]
enabled = true
port = ssh

[nginx-http-auth]
enabled = true
port = http,https
EOF_F2B
_fail2ban_set_sshd_port "$f2b_tmp" "22222" >/dev/null 2>&1 || true
if awk '
    /^\[sshd\]/{sec="sshd"; next} /^\[/{sec="other"}
    sec=="sshd" && /^port = 22222$/ {ssh_ok=1}
    sec=="other" && /^port = http,https$/ {nginx_ok=1}
    END{exit !(ssh_ok && nginx_ok)}
' "$f2b_tmp"; then
    pass "S1: Fail2ban 仅更新 [sshd] port"
else
    fail "S1: Fail2ban port 更新污染其他 jail"
    sed 's/^/    /' "$f2b_tmp"
fi
rm -f "$f2b_tmp"

# S9: 端口测试不得把 host 拼进 bash -c /dev/tcp 字符串；需校验 host 字面。
declare -F validate_host >/dev/null && pass "S9: validate_host helper 已定义" || fail "S9: 缺 validate_host"
validate_host "example.com" && pass "S9: host 接受普通域名" || fail "S9: host 应接受普通域名"
validate_host 'bad;touch /tmp/pwn' && fail "S9: host 不应接受命令分隔符" || pass "S9: host 拒绝命令分隔符"
net_diag_body=$(awk '/^net_diag\(\)/,/^}/' "$BUILT")
if echo "$net_diag_body" | grep -q 'bash -c "echo >/dev/tcp/'; then
    fail "S9: net_diag 仍拼接 bash -c /dev/tcp"
else
    pass "S9: net_diag 不再拼接 bash -c /dev/tcp"
fi
echo "$net_diag_body" | grep -q 'validate_host "$host"' \
    && pass "S9: 端口测试校验 host" \
    || fail "S9: 端口测试未校验 host"

# 低危：validate_ip 应拒绝多个 :: 的非法 IPv6。
validate_ip '2001:db8::1' && pass "LOW: validate_ip 接受合法压缩 IPv6" || fail "LOW: validate_ip 应接受合法压缩 IPv6"
validate_ip '1::2::3' && fail "LOW: validate_ip 不应接受多个 ::" || pass "LOW: validate_ip 拒绝多个 ::"

# P5/P1: DDNS token 配置写入不能有 chmod 600 窗口；cron update_cf 必须检查 CF GET success。
if grep -q 'cat > "\$DDNS_CONFIG_DIR/.*\.conf" << EOF' "$BUILT"; then
    fail "P5: DDNS 配置仍用 cat > 后 chmod 600"
else
    pass "P5: DDNS 配置不再使用 cat > 创建密钥文件"
fi
if grep -q '^write_private_file_atomic()' "$BUILT" \
   && grep -q 'write_private_file_atomic "\$DDNS_CONFIG_DIR/' "$BUILT" \
   && grep -q 'write_private_file_atomic "\$CLOUDFLARE_CREDENTIALS"' "$BUILT" \
   && grep -q 'write_private_file_atomic "\$cf_cred"' "$BUILT" \
   && ! grep -q 'write_file_atomic "\$DDNS_CONFIG_DIR/' "$BUILT" \
   && ! grep -q 'write_file_atomic "\$CLOUDFLARE_CREDENTIALS"' "$BUILT" \
   && ! grep -q 'write_file_atomic "\$cf_cred"' "$BUILT"; then
    pass "P5: DDNS/Cloudflare Token 配置走私有原子写 helper"
else
    fail "P5: DDNS/Cloudflare Token 配置仍可能继承旧宽权限"
fi
update_cf_body=$(awk '/^update_cf\(\)/,/^}/' "$BUILT")
echo "$update_cf_body" | grep -q '"\.success // false"' \
    && pass "P1: DDNS cron update_cf 检查 GET success" \
    || fail "P1: DDNS cron update_cf 未检查 GET success"
echo "$update_cf_body" | grep -q 'return 1' \
    && pass "P1: DDNS cron GET 失败会返回失败" \
    || fail "P1: DDNS cron GET 失败仍继续"


echo ""
echo "== review #15 审计报告核心基础回归 =="
# C1: 非 tty/管道场景 confirm 不得因 read EOF + 空回复而自动确认。
if confirm "non-tty should not auto-confirm" </dev/null >/dev/null 2>&1; then
    fail "C1: confirm 在非 tty EOF 场景仍自动确认"
else
    pass "C1: confirm 非 tty 不自动确认"
fi

# C2: --reality CLI 路径需与菜单一致，在 OpenWrt 上拦截。
main_reality_block=$(awk '/if \[\[ "\$\{1:-\}" == "--reality" \]\]/,/exit \$\?/' "$BUILT")
echo "$main_reality_block" | grep -q 'PLATFORM.*openwrt' \
    && pass "C2: --reality CLI 含 OpenWrt 平台判断" \
    || fail "C2: --reality CLI 缺 OpenWrt 平台判断"
echo "$main_reality_block" | grep -q 'feature_blocked "Sing-box Reality 节点"' \
    && pass "C2: --reality CLI 在 OpenWrt 走 feature_blocked" \
    || fail "C2: --reality CLI 未复用 Reality feature_blocked"

# C5: cron 添加/删除应按固定字符串匹配并检查 crontab 安装失败。
cron_mock_file=$(mktemp)
cron_tmp_seen_file=$(mktemp)
printf '%s\n' '1 * * * * keep aXb' '2 * * * * remove a.b' > "$cron_mock_file"
crontab() {
    if [[ "${1:-}" == "-l" ]]; then
        cat "$cron_mock_file"
    else
        printf '%s\n' "$1" >> "$cron_tmp_seen_file"
        [[ "${CRON_FAIL_INSTALL:-0}" == "1" ]] && return 1
        cp "$1" "$cron_mock_file"
    fi
}
cron_helpers_body=$(awk '/^cron_remove_job\(\)/,/^init_environment\(\)/' "$BUILT")
if echo "$cron_helpers_body" | grep -q '^_cron_tmp_create()' \
   && echo "$cron_helpers_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/\${SCRIPT_NAME:-server-manage}-cron.XXXXXX"' \
   && ! echo "$cron_helpers_body" | grep -q 'cron_tmp=$(mktemp)'; then
    pass "C5: cron 候选文件使用私有临时目录"
else
    fail "C5: cron 候选文件仍可能直接落公共临时文件"
fi
cron_remove_job 'a.b' >/dev/null 2>&1 || true
if grep -qF 'keep aXb' "$cron_mock_file" && ! grep -qF 'remove a.b' "$cron_mock_file"; then
    pass "C5: cron_remove_job 使用固定字符串，不误删正则相似项"
else
    fail "C5: cron_remove_job 仍按正则删除或删除失败"
    sed 's/^/    /' "$cron_mock_file"
fi
CRON_FAIL_INSTALL=1
if cron_add_job 'new-job' '* * * * * new-job' >/dev/null 2>&1; then
    fail "C5: cron_add_job 吞掉 crontab 安装失败"
else
    pass "C5: cron_add_job 返回 crontab 安装失败"
fi
unset CRON_FAIL_INSTALL
printf '%s\n' \
    '# keep wg-watchdog.sh in a comment' \
    '* * * * * /opt/custom/wg-watchdog.sh --notify' \
    '* * * * * /usr/local/bin/wg-watchdog.sh >/dev/null 2>&1' > "$cron_mock_file"
if cron_has_job_command '/usr/local/bin/wg-watchdog.sh' \
   && cron_remove_job_command '/usr/local/bin/wg-watchdog.sh' >/dev/null 2>&1 \
   && grep -qF '# keep wg-watchdog.sh in a comment' "$cron_mock_file" \
   && grep -qF '/opt/custom/wg-watchdog.sh --notify' "$cron_mock_file" \
   && ! grep -qF '/usr/local/bin/wg-watchdog.sh >/dev/null' "$cron_mock_file"; then
    pass "C5: cron 命令路径清理不误删相似 watchdog 行"
else
    fail "C5: cron 命令路径清理仍会误删相似 watchdog 行"
    sed 's/^/    /' "$cron_mock_file"
fi
if cron_add_job_command '/usr/local/bin/wg-watchdog.sh' '* * * * * /usr/local/bin/wg-watchdog.sh >/dev/null 2>&1' >/dev/null 2>&1 \
   && [[ "$(grep -cF '/usr/local/bin/wg-watchdog.sh' "$cron_mock_file")" -eq 1 ]] \
   && grep -qF '/opt/custom/wg-watchdog.sh --notify' "$cron_mock_file"; then
    pass "C5: cron 命令路径添加只替换同路径任务"
else
    fail "C5: cron 命令路径添加仍影响相似 watchdog 行"
    sed 's/^/    /' "$cron_mock_file"
fi
if grep -Eq '/server-manage-cron\.[^/]+/crontab$' "$cron_tmp_seen_file"; then
    pass "C5: cron helper 传给 crontab 的是私有目录候选文件"
else
    fail "C5: cron helper 未使用私有目录候选文件"
    sed 's/^/    /' "$cron_tmp_seen_file"
fi
cron_tmp_left=0
while IFS= read -r cron_tmp_seen; do
    [[ -n "$cron_tmp_seen" ]] || continue
    [[ -e "$(dirname "$cron_tmp_seen")" ]] && cron_tmp_left=1
done < "$cron_tmp_seen_file"
[[ "$cron_tmp_left" -eq 0 ]] \
    && pass "C5: cron helper 成功/失败后清理私有临时目录" \
    || fail "C5: cron helper 留下私有临时目录"
unset -f crontab
rm -f "$cron_mock_file" "$cron_tmp_seen_file"

# C6: DDNS_PROXIED 缺省/空值必须归一化为 false，避免 update_cf 生成非法 JSON。
update_cf_body=$(awk '/^update_cf\(\)/,/^}/' "$BUILT")
echo "$update_cf_body" | grep -q 'proxied=${6:-false}' \
    && pass "C6: update_cf proxied 参数默认 false" \
    || fail "C6: update_cf proxied 空值未默认 false"
echo "$update_cf_body" | grep -q 'proxied="false"' \
    && pass "C6: update_cf 会把非法 proxied 归一化 false" \
    || fail "C6: update_cf 未归一化非法 proxied"
parse_ddns_body=$(awk '/^parse_ddns_conf\(\)/,/^}/' "$BUILT")
echo "$parse_ddns_body" | grep -q 'DDNS_PROXIED=${DDNS_PROXIED:-false}' \
    && pass "C6: parse_ddns_conf 缺省 DDNS_PROXIED=false" \
    || fail "C6: parse_ddns_conf 未设置 DDNS_PROXIED 默认值"
echo "$parse_ddns_body" | grep -q 'DDNS_PROXIED="false"' \
    && pass "C6: parse_ddns_conf 归一化非法 DDNS_PROXIED" \
    || fail "C6: parse_ddns_conf 未归一化非法 DDNS_PROXIED"

echo ""
echo "== review #16 审计报告核心基础剩余回归 =="
# C3: 主菜单系统信息不得在前台串行刷新公网 IP / 登录 IP 归属地，避免无网环境卡顿。
sysinfo_body=$(awk '/^show_dual_column_sysinfo\(\)/,/^}/' "$BUILT")
grep -q '^ensure_network_cache_async()' "$BUILT" \
    && pass "C3: 存在异步网络缓存刷新 helper" \
    || fail "C3: 缺少异步网络缓存刷新 helper"
echo "$sysinfo_body" | grep -q 'ensure_network_cache_async' \
    && pass "C3: 主菜单系统信息使用异步网络缓存" \
    || fail "C3: 主菜单仍未使用异步网络缓存"
if echo "$sysinfo_body" | grep -q 'load_cache || refresh_network_cache'; then
    fail "C3: 主菜单仍会前台同步 refresh_network_cache"
else
    pass "C3: 主菜单不再前台同步刷新公网 IP"
fi
grep -q '^get_ip_location_cached()' "$BUILT" \
    && pass "C3: 登录 IP 归属地有缓存 helper" \
    || fail "C3: 缺少登录 IP 归属地缓存 helper"
echo "$sysinfo_body" | grep -q 'get_ip_location_cached "$login_ip"' \
    && pass "C3: 登录记录使用缓存/后台查询归属地" \
    || fail "C3: 登录记录仍实时查询 ip-api"

# C4: 中断清理应覆盖 write_file_atomic 在任意目标目录创建的临时文件。
write_atomic_body=$(awk '/^write_file_atomic\(\)/,/^}/' "$BUILT")
interrupt_body=$(awk '/^handle_interrupt\(\)/,/^}/' "$BUILT")
grep -q '^_tmp_register()' "$BUILT" \
    && pass "C4: 临时文件注册 helper 已定义" \
    || fail "C4: 缺少临时文件注册 helper"
echo "$write_atomic_body" | grep -q '_tmp_register "$tmpfile"' \
    && pass "C4: write_file_atomic 注册临时文件" \
    || fail "C4: write_file_atomic 未注册临时文件"
echo "$write_atomic_body" | grep -q '_tmp_unregister "$tmpfile"' \
    && pass "C4: write_file_atomic 完成后注销临时文件" \
    || fail "C4: write_file_atomic 未注销临时文件"
echo "$interrupt_body" | grep -q '_cleanup_tmpfiles' \
    && pass "C4: handle_interrupt 调用统一临时文件清理" \
    || fail "C4: handle_interrupt 未调用统一临时文件清理"
if grep -q 'mktemp /etc/resolv.conf.tmp' "$BUILT"; then
    fail "C4: DNS 修改仍创建未注册的 resolv.conf.tmp"
else
    pass "C4: DNS 修改不再创建未注册 resolv.conf.tmp"
fi

# C7: build.sh 不应再用“注释标记到首个顶格 fi”的脆弱 sed 范围删除。
build_script="${BUILD_SCRIPT:-build.sh}"
reality_module="${REALITY_MODULE:-modules/15-singbox-reality.sh}"
if [[ -f "$build_script" && -f "$reality_module" ]]; then
    if grep -q "sed '/^# Source SNI 测速增强模块/,/^fi\$/d'" "$build_script"; then
        fail "C7: build.sh 仍用脆弱 sed 范围删除 Reality source 块"
    else
        pass "C7: build.sh 不再依赖注释到 fi 的 sed 范围删除"
    fi
    grep -q 'BEGIN BUILD-OMIT reality-sni-runtime-source' "$reality_module" \
        && grep -q 'END BUILD-OMIT reality-sni-runtime-source' "$reality_module" \
        && pass "C7: Reality runtime source 块有显式构建省略边界" \
        || fail "C7: Reality runtime source 块缺显式构建省略边界"
    run_all_script="${RUN_ALL_SCRIPT:-tests/run_all.sh}"
    run_all_body=$(cat "$run_all_script" 2>/dev/null || true)
    if echo "$run_all_body" | grep -q 'PASS=$PASS FAIL=$FAIL' \
       && echo "$run_all_body" | grep -q 'exit 0' \
       && echo "$run_all_body" | grep -q 'exit 1'; then
        pass "C7: run_all 测试矩阵失败时显式非零退出"
    else
        fail "C7: run_all 测试矩阵缺少显式失败退出码"
    fi
    if grep -q 'mktemp .*OUTPUT' "$build_script" && grep -q 'mv -f "$TMP_OUTPUT" "$OUTPUT"' "$build_script"; then
        pass "C7: build.sh 使用临时文件原子替换输出"
    else
        fail "C7: build.sh 未使用临时文件原子替换输出"
    fi
    build_race_dir=$(mktemp -d)
    build_race_out="$build_race_dir/v4-built.sh"
    (bash "$build_script" "$build_race_out" >/dev/null 2>&1) &
    build_pid1=$!
    (bash "$build_script" "$build_race_out" >/dev/null 2>&1) &
    build_pid2=$!
    wait "$build_pid1"; build_rc1=$?
    wait "$build_pid2"; build_rc2=$?
    if [[ $build_rc1 -eq 0 && $build_rc2 -eq 0 ]] \
       && [[ "$(grep -c '^main "\$@"$' "$build_race_out" 2>/dev/null || true)" -eq 1 ]] \
       && [[ "$(grep -c '^readonly VERSION=' "$build_race_out" 2>/dev/null || true)" -eq 1 ]] \
       && [[ "$(tail -n 1 "$build_race_out" 2>/dev/null)" == 'main "$@"' ]] \
       && head -n -1 "$build_race_out" > "$build_race_dir/lib.sh" \
       && bash -n "$build_race_dir/lib.sh"; then
        pass "C7: 并发构建同一输出不会交错污染产物"
    else
        fail "C7: 并发构建同一输出仍可能污染产物"
        {
            echo "build rc: $build_rc1/$build_rc2"
            grep -nE '^main "\$@"$|^#!/bin/bash$|^readonly VERSION=' "$build_race_out" 2>/dev/null || true
            tail -20 "$build_race_out" 2>/dev/null || true
        } | sed 's/^/    /'
    fi
    rm -rf "$build_race_dir"
else
    echo "  [SKIP] 缺少 build.sh 或 15-singbox-reality.sh，跳过 C7 构建脚本静态检查"
fi

echo ""
echo "== review #17 审计报告安全防护回归 =="
# S3: Fail2ban UFW 旧规则迁移不得直接 sed /etc/ufw/user.rules，避免破坏 tuple 配对。
f2b_migrate_body=$(awk '/^f2b_migrate_ufw_to_ipset\(\)/,/^}/' "$BUILT")
if echo "$f2b_migrate_body" | grep -q "sed -i.*f2b"; then
    fail "S3: f2b_migrate_ufw_to_ipset 仍直接 sed 删除 UFW 规则文件"
else
    pass "S3: f2b_migrate_ufw_to_ipset 不再直接 sed UFW 规则文件"
fi
echo "$f2b_migrate_body" | grep -q 'ufw status numbered' \
    && pass "S3: Fail2ban 旧规则迁移通过 UFW numbered 规则定位" \
    || fail "S3: Fail2ban 旧规则迁移未使用 UFW numbered 规则"
echo "$f2b_migrate_body" | grep -q 'ufw delete' \
    && pass "S3: Fail2ban 旧规则迁移通过 ufw delete 删除规则" \
    || fail "S3: Fail2ban 旧规则迁移未通过 ufw delete 删除规则"
if echo "$f2b_migrate_body" | grep -q 'ufw reload .*|| true'; then
    fail "S3: Fail2ban 旧规则迁移仍吞掉 ufw reload 失败"
else
    pass "S3: Fail2ban 旧规则迁移不吞 ufw reload 失败"
fi

# S6: auto_deps 新安装 fail2ban 后不得让默认 sshd jail 静默运行。
auto_deps_body=$(awk '/^auto_deps\(\)/,/^}/' "$BUILT")
echo "$auto_deps_body" | grep -q 'systemctl disable --now fail2ban' \
    && pass "S6: auto_deps 会停用本次新装且此前未运行的 fail2ban" \
    || fail "S6: auto_deps 未停用本次新装 fail2ban"

# S7: UFW setup/reset 放行 SSH 前必须刷新真实 SSH 端口。
ufw_setup_body=$(awk '/^ufw_setup\(\)/,/^}/' "$BUILT")
ufw_reset_body=$(awk '/^ufw_safe_reset\(\)/,/^}/' "$BUILT")
ufw_apply_ssh_body=$(awk '/^_ufw_apply_default_ssh_rules\(\)/,/^}/' "$BUILT")
echo "$ufw_setup_body" | grep -q 'refresh_ssh_port' \
    && echo "$ufw_setup_body" | grep -q '_ufw_apply_default_ssh_rules ||' \
    && pass "S7: ufw_setup 放行前刷新 SSH 端口" \
    || fail "S7: ufw_setup 未刷新 SSH 端口"
echo "$ufw_reset_body" | grep -q 'refresh_ssh_port' \
    && echo "$ufw_reset_body" | grep -q '_ufw_apply_default_ssh_rules ||' \
    && pass "S7: ufw_safe_reset 放行前刷新 SSH 端口" \
    || fail "S7: ufw_safe_reset 未刷新 SSH 端口"
echo "$ufw_apply_ssh_body" | grep -q 'for _ssh_port in \$CURRENT_SSH_PORTS' \
    && echo "$ufw_apply_ssh_body" | grep -q 'if ! ufw allow "\$_ssh_port/tcp" comment "SSH-Access"' \
    && pass "S7: UFW SSH 放行 helper 检查每个端口放行结果" \
    || fail "S7: UFW SSH 放行 helper 未检查所有 SSH 端口"

# S8: Fail2ban 解封应覆盖所有活跃 jail，不限 sshd。
f2b_unban_body=$(awk '/^f2b_unban\(\)/,/^}/' "$BUILT")
grep -q '^_f2b_active_jails()' "$BUILT" \
    && pass "S8: Fail2ban 活跃 jail helper 已定义" \
    || fail "S8: 缺少 Fail2ban 活跃 jail helper"
if echo "$f2b_unban_body" | grep -q 'status sshd'; then
    fail "S8: f2b_unban 仍只读取 sshd jail"
else
    pass "S8: f2b_unban 不再只读取 sshd jail"
fi
echo "$f2b_unban_body" | grep -q 'set "$jail" unbanip' \
    && pass "S8: f2b_unban 会按 jail 执行 unbanip" \
    || fail "S8: f2b_unban 未按 jail 执行 unbanip"

echo ""
echo "== review #18 审计报告 OpenWrt 系统优化回归 =="
# S10: OpenWrt 上主机名/时区/BBR 不能用 Debian 路径假报成功。
opt_hostname_body=$(awk '/^opt_hostname\(\)/,/^}/' "$BUILT")
select_timezone_body=$(awk '/^select_timezone\(\)/,/^}/' "$BUILT")
opt_bbr_body=$(awk '/^opt_bbr\(\)/,/^}/' "$BUILT")
echo "$opt_hostname_body" | grep -q 'PLATFORM.*openwrt' \
    && echo "$opt_hostname_body" | grep -q 'uci set system.@system\[0\].hostname' \
    && pass "S10: OpenWrt 主机名通过 uci 持久化" \
    || fail "S10: OpenWrt 主机名未通过 uci 持久化"
if grep -q '^_hostname_render_hosts_conf()' "$BUILT" \
   && grep -q '^_hostname_update_hosts()' "$BUILT" \
   && echo "$opt_hostname_body" | grep -q '_hostname_write_file "\$new_name"' \
   && echo "$opt_hostname_body" | grep -q '_hostname_update_hosts "\$old_name" "\$new_name"' \
   && ! echo "$opt_hostname_body" | grep -q 'sed -i.*hosts' \
   && ! echo "$opt_hostname_body" | grep -q 'echo "\$new_name" > /etc/hostname'; then
    pass "S10: 主机名 fallback/hosts 通过原子写入和精确渲染"
else
    fail "S10: 主机名仍可能直接 sed hosts 或重定向 hostname"
fi
echo "$select_timezone_body" | grep -q 'PLATFORM.*openwrt' \
    && echo "$select_timezone_body" | grep -q 'uci set system.@system\[0\].timezone' \
    && pass "S10: OpenWrt 时区通过 uci 持久化 timezone" \
    || fail "S10: OpenWrt 时区未通过 uci timezone 持久化"
echo "$select_timezone_body" | grep -q 'uci set system.@system\[0\].zonename' \
    && pass "S10: OpenWrt 时区写入 zonename" \
    || fail "S10: OpenWrt 时区未写入 zonename"
echo "$select_timezone_body" | grep -q '\[\[ -f "/usr/share/zoneinfo/\$z" \]\]' \
    && pass "S10: 非 OpenWrt 时区回退前检查 zoneinfo 存在" \
    || fail "S10: 非 OpenWrt 时区回退未检查 zoneinfo，可能创建悬空 symlink"
echo "$opt_bbr_body" | grep -Fq 'if ! sysctl -p "$tmp_candidate"' \
    && pass "S10: BBR 应用检查 sysctl -p 返回值" \
    || fail "S10: BBR 未检查 sysctl -p 返回值"
echo "$opt_bbr_body" | grep -q 'verify_cc' \
    && pass "S10: BBR 应用后复验拥塞控制算法" \
    || fail "S10: BBR 应用后未复验拥塞控制算法"

echo ""
echo "== review #19 审计报告 GeoIP IPv6 回归 =="
# S4: GeoIP 国家规则必须覆盖 IPv6，避免 IPv6 绕过白/黑名单。
geoip_download_body=$(awk '/^_geoip_download\(\)/,/^}/' "$BUILT")
geoip_apply_body=$(awk '/^_geoip_apply\(\)/,/^}/' "$BUILT")
geoip_clear_body=$(awk '/^_geoip_clear\(\)/,/^}/' "$BUILT")
geoip_persist_body=$(awk '/^_geoip_install_persistence\(\)/,/^}/' "$BUILT")
grep -q '^readonly GEOIP6_URL=' "$BUILT" \
    && pass "S4: GeoIP IPv6 数据源常量已定义" \
    || fail "S4: 缺少 GeoIP IPv6 数据源常量"
echo "$geoip_download_body" | grep -q 'GEOIP6_URL' \
    && echo "$geoip_download_body" | grep -q '\.zone6' \
    && pass "S4: GeoIP 下载 IPv6 zone6 数据" \
    || fail "S4: GeoIP 下载未覆盖 IPv6 zone6 数据"
echo "$geoip_apply_body" | grep -q 'family inet6' \
    && pass "S4: GeoIP IPv6 ipset 使用 family inet6" \
    || fail "S4: GeoIP IPv6 ipset 未使用 family inet6"
echo "$geoip_apply_body" | grep -q 'ip6tables' \
    && echo "$geoip_apply_body" | grep -q 'GEOIP6_CHAIN' \
    && pass "S4: GeoIP 应用 ip6tables IPv6 链" \
    || fail "S4: GeoIP 应用未配置 ip6tables IPv6 链"
echo "$geoip_clear_body" | grep -q 'GEOIP6_CHAIN' \
    && echo "$geoip_clear_body" | grep -q 'geoip_whitelist6' \
    && pass "S4: GeoIP 清理 IPv6 链和集合" \
    || fail "S4: GeoIP 清理未覆盖 IPv6 链和集合"
echo "$geoip_persist_body" | grep -q 'ip6tables' \
    && echo "$geoip_persist_body" | grep -q 'family inet6' \
    && pass "S4: GeoIP 持久化 apply 脚本覆盖 IPv6" \
    || fail "S4: GeoIP 持久化 apply 脚本未覆盖 IPv6"

echo ""
echo "== review #20 审计报告 Web 安全回归 =="
nginx_reload_body=$(awk '/^_nginx_reload\(\)/,/^}/' "$BUILT")
nginx_deploy_restore_body=$(awk '/^_nginx_deploy_conf_restore\(\)/,/^}/' "$BUILT")
nginx_deploy_body=$(awk '/^_nginx_deploy_conf\(\)/,/^}/' "$BUILT")
web_view_body=$(awk '/^web_view_config\(\)/,/^}/' "$BUILT")
web_delete_body=$(awk '/^web_delete_domain\(\)/,/^}/' "$BUILT")
web_add_body=$(awk '/^web_add_domain\(\)/,/^}/' "$BUILT")
web_edit_proxy_body=$(awk '/^web_edit_reverse_proxy\(\)/,/^}/' "$BUILT")

# W1/W2: Nginx 配置部署失败要恢复旧配置；reload 失败不能升级为 restart。
if echo "$nginx_reload_body" | grep -q 'restart nginx'; then
    fail "W2: _nginx_reload 仍会 reload 失败后 restart nginx"
else
    pass "W2: _nginx_reload 不再自动 restart nginx"
fi
echo "$nginx_deploy_body" | grep -q 'backup_avail' \
    && pass "W1: _nginx_deploy_conf 记录旧配置备份" \
    || fail "W1: _nginx_deploy_conf 未记录旧配置备份"
if echo "$nginx_deploy_body" | grep -q 'rm -f "\$enabled" "\$avail"'; then
    fail "W1: _nginx_deploy_conf 失败时仍直接删除新旧配置"
else
    pass "W1: _nginx_deploy_conf 失败时不直接删除新旧配置"
fi
echo "$nginx_deploy_restore_body" | grep -q 'mv "\$backup_avail" "\$avail"' \
    && echo "$nginx_deploy_body" | grep -q '_nginx_deploy_conf_restore' \
    && pass "W1: _nginx_deploy_conf 失败会恢复旧 sites-available 配置" \
    || fail "W1: _nginx_deploy_conf 失败未恢复旧 sites-available 配置"

# W3: 序号 00 必须无效，不能变成 bash 负索引。
echo "$web_view_body" | grep -q '"\$idx" -lt 1' \
    && pass "W3: web_view_config 拒绝 00/小于 1 序号" \
    || fail "W3: web_view_config 未拒绝 00/小于 1 序号"
echo "$web_delete_body" | grep -q '"\$idx" -lt 1' \
    && pass "W3: web_delete_domain 拒绝 00/小于 1 序号" \
    || fail "W3: web_delete_domain 未拒绝 00/小于 1 序号"
if echo "$web_delete_body" | grep -Fq 'if ! _web_cleanup_domain "$target_domain"; then' \
   && echo "$web_delete_body" | grep -Fq 'return 1'; then
    pass "W3: web_delete_domain 会传播域名清理失败"
else
    fail "W3: web_delete_domain 未检查域名清理返回值"
fi

# W6: 覆盖重配域名时 DDNS conf 已存在也应更新新 token/zone/proxied。
if grep -qF '[[ "$dns_mode" != "0" ]] && [[ ! -f "$DDNS_CONFIG_DIR/${DOMAIN}.conf" ]]' "$BUILT"; then
    fail "W6: web_add_domain 仍在 DDNS conf 已存在时跳过更新"
else
    pass "W6: web_add_domain 不再因 DDNS conf 已存在而跳过更新"
fi

# W7: 修改反代后端不能把 &/| 当替换元字符。
grep -q '^_replace_proxy_pass_backend()' "$BUILT" \
    && pass "W7: 已定义安全 proxy_pass 替换 helper" \
    || fail "W7: 缺少安全 proxy_pass 替换 helper"
grep -q '^_web_update_reverse_proxy_backend()' "$BUILT" \
    && pass "W7: 已定义反代后端原子更新 helper" \
    || fail "W7: 缺少反代后端原子更新 helper"
if echo "$web_edit_proxy_body" | grep -q 'sed -i "s|proxy_pass'; then
    fail "W7: web_edit_reverse_proxy 仍用未转义 sed 替换 proxy_pass"
else
    pass "W7: web_edit_reverse_proxy 不再使用未转义 sed 替换"
fi
echo "$web_edit_proxy_body" | grep -q '_web_update_reverse_proxy_backend "\$target_conf" "\$new_backend"' \
    && pass "W7: web_edit_reverse_proxy 使用原子 helper 更新后端" \
    || fail "W7: web_edit_reverse_proxy 未使用安全 helper 更新后端"
web_update_proxy_body=$(awk '/^_web_update_reverse_proxy_backend\(\)/,/^_cert_name_matches_domain\(\)/' "$BUILT")
if echo "$web_update_proxy_body" | grep -Fq 'mktemp "${conf_dir}/.${base}.bak.XXXXXX"' \
   && echo "$web_update_proxy_body" | grep -Fq 'mktemp "${conf_dir}/.${base}.tmp.XXXXXX"' \
   && echo "$web_update_proxy_body" | grep -Fq 'chmod --reference="$target_conf" "$tmp_conf"' \
   && echo "$web_update_proxy_body" | grep -q 'nginx -t >/dev/null 2>&1 && _nginx_reload' \
   && echo "$web_update_proxy_body" | grep -Fq 'mv "$backup_conf" "$target_conf"' \
   && ! echo "$web_edit_proxy_body" | grep -q 'target_conf}.bak' \
   && ! echo "$web_edit_proxy_body" | grep -Fq 'mv "$tmp_conf" "$target_conf"'; then
    pass "W7: 反代后端更新通过随机备份/候选文件并失败回滚"
else
    fail "W7: 反代后端更新仍可能固定备份、非原子提交或失败不回滚"
fi

nginx_official_body=$(awk '/^_install_nginx_official\(\)/,/^_ensure_nginx_stream\(\)/' "$BUILT")
nginx_stream_body=$(awk '/^_ensure_nginx_stream\(\)/,/^_check_certbot_dns_cf\(\)/' "$BUILT")
if grep -q '^_nginx_write_official_apt_files()' "$BUILT" \
   && grep -q '^_nginx_install_official_keyring()' "$BUILT" \
   && echo "$nginx_official_body" | grep -q '_nginx_install_official_keyring' \
   && echo "$nginx_official_body" | grep -q '_nginx_write_official_apt_files "\$distro" "\$codename"' \
   && ! echo "$nginx_official_body" | grep -q '>/etc/apt/sources.list.d/nginx.list' \
   && ! echo "$nginx_official_body" | grep -q '>/etc/apt/preferences.d/99nginx' \
   && ! echo "$nginx_official_body" | grep -q 'curl .*| gpg'; then
    pass "W8: nginx.org apt 源/keyring 通过候选与原子写入"
else
    fail "W8: nginx.org apt 源/keyring 仍可能直接写系统路径"
fi
if grep -q '^_nginx_write_stream_module_conf()' "$BUILT" \
   && echo "$nginx_stream_body" | grep -q '_nginx_write_stream_module_conf "\$so"' \
   && ! echo "$nginx_stream_body" | grep -q '>/etc/nginx/modules-enabled/50-mod-stream.conf'; then
    pass "W8: nginx stream 动态模块 load 配置通过原子写入"
else
    fail "W8: nginx stream 动态模块 load 配置仍可能直接写系统路径"
fi

echo ""
echo "== review #21 审计报告 Web 剩余回归 =="
cf_list_zones_body=$(awk '/^_cf_list_zones\(\)/,/^}/' "$BUILT")
cf_get_zone_body=$(awk '/^_cf_get_zone_id\(\)/,/^}/' "$BUILT")
web_home_body=$(awk '/^web_home_expose\(\)/,/^_replace_proxy_pass_backend\(\)/' "$BUILT")
web_proxy_body=$(awk '/^web_reverse_proxy_site\(\)/,/^}/' "$BUILT")

# W4: Cloudflare zone 列表必须分页读取，不能只取前 50 个。
grep -q '^_cf_list_zones()' "$BUILT" \
    && pass "W4: Cloudflare zone 分页 helper 已定义" \
    || fail "W4: 缺少 Cloudflare zone 分页 helper"
echo "$cf_list_zones_body" | grep -q 'page=' \
    && echo "$cf_list_zones_body" | grep -q 'total_pages' \
    && pass "W4: zone helper 按 page/total_pages 迭代分页" \
    || fail "W4: zone helper 未按 page/total_pages 迭代分页"
echo "$web_add_body" | grep -q '_cf_list_zones "\$CF_API_TOKEN" "status=active"' \
    && pass "W4: 添加域名使用分页 zone 列表" \
    || fail "W4: 添加域名仍未使用分页 zone 列表"
echo "$web_home_body" | grep -q '_cf_list_zones "\$token" "status=active"' \
    && pass "W4: 家宽暴露使用分页 zone 列表" \
    || fail "W4: 家宽暴露仍未使用分页 zone 列表"
echo "$cf_get_zone_body" | grep -q '_cf_list_zones "\$token"' \
    && pass "W4: zone id fallback 使用分页 zone 列表" \
    || fail "W4: zone id fallback 仍只读取单页 zone"
if declare -F _cf_list_zones >/dev/null && command -v jq >/dev/null 2>&1; then
    orig_cf_api_def=$(declare -f _cf_api)
    zone_call_log=$(mktemp)
    _cf_api() {
        local method="$1" endpoint="$2" token="$3"
        echo "$endpoint" >> "$zone_call_log"
        case "$endpoint" in
            *"&page=2"*)
                echo '{"success":true,"result":[{"name":"b.example","id":"z2"}],"result_info":{"page":2,"per_page":1,"count":1,"total_count":2,"total_pages":2}}'
                ;;
            *"&page=1"*)
                echo '{"success":true,"result":[{"name":"a.example","id":"z1"}],"result_info":{"page":1,"per_page":1,"count":1,"total_count":2,"total_pages":2}}'
                ;;
            *)
                echo '{"success":false,"errors":[{"message":"bad endpoint"}]}'
                ;;
        esac
    }
    zones_page_json=$(_cf_list_zones "tok" "status=active" 1)
    if _cf_api_ok "$zones_page_json" && jq -e '(.result | length) == 2 and (.result[1].id == "z2")' >/dev/null <<< "$zones_page_json"; then
        pass "W4: zone helper 实测合并多页结果"
    else
        fail "W4: zone helper 未正确合并多页结果"
    fi
    if grep -q 'page=2.*status=active' "$zone_call_log"; then
        pass "W4: zone helper 实测请求后续页并保留查询条件"
    else
        fail "W4: zone helper 未请求后续页或丢失查询条件"
    fi
    rm -f "$zone_call_log"
    eval "$orig_cf_api_def"
else
    echo "  [SKIP] jq 不存在，跳过 W4 zone helper 分页合并实测"
fi

# W5: 子域反代只能复用覆盖目标域名的证书（SAN exact 或单级 wildcard）。
grep -q '^_cert_name_matches_domain()' "$BUILT" \
    && pass "W5: 证书域名匹配 helper 已定义" \
    || fail "W5: 缺少证书域名匹配 helper"
if declare -F _cert_name_matches_domain >/dev/null; then
    _cert_name_matches_domain "*.example.com" "api.example.com" \
        && pass "W5: 通配符证书匹配单级子域" \
        || fail "W5: 通配符证书未匹配单级子域"
    if _cert_name_matches_domain "*.example.com" "deep.api.example.com"; then
        fail "W5: 通配符证书错误匹配多级子域"
    else
        pass "W5: 通配符证书不匹配多级子域"
    fi
fi
grep -q '^_cert_covers_domain()' "$BUILT" \
    && pass "W5: 证书 SAN 覆盖校验 helper 已定义" \
    || fail "W5: 缺少证书 SAN 覆盖校验 helper"
if declare -F _cert_covers_domain >/dev/null; then
    cert_mock_dir=$(mktemp -d)
    touch "$cert_mock_dir/fullchain.pem"
    cat > "$cert_mock_dir/openssl" <<'OPENSSLMOCK'
#!/bin/bash
echo "X509v3 Subject Alternative Name:"
echo "    DNS:example.com, DNS:*.example.org"
OPENSSLMOCK
    chmod +x "$cert_mock_dir/openssl"
    if PATH="$cert_mock_dir:$PATH" _cert_covers_domain "$cert_mock_dir/fullchain.pem" "api.example.org"; then
        pass "W5: SAN 通配符证书实测覆盖单级子域"
    else
        fail "W5: SAN 通配符证书未覆盖单级子域"
    fi
    if PATH="$cert_mock_dir:$PATH" _cert_covers_domain "$cert_mock_dir/fullchain.pem" "deep.api.example.org"; then
        fail "W5: SAN 通配符证书错误覆盖多级子域"
    else
        pass "W5: SAN 通配符证书不覆盖多级子域"
    fi
    rm -rf "$cert_mock_dir"
fi
echo "$web_proxy_body" | grep -q '_cert_covers_domain .*"\$DOMAIN"' \
    && pass "W5: 子域反代复用父域证书前校验覆盖目标域名" \
    || fail "W5: 子域反代复用父域证书前未校验证书覆盖范围"
if echo "$web_proxy_body" | grep -q 'print_success "使用主域证书'; then
    fail "W5: 子域反代仍无条件提示使用主域证书"
else
    pass "W5: 子域反代不再无条件提示使用主域证书"
fi

echo ""
echo "== review #22 审计报告 WireGuard 回归 =="
wg_add_body=$(awk '/^wg_add_peer\(\)/,/^}/' "$BUILT")
wg_deb_add_body=$(awk '/^wg_deb_add_peer\(\)/,/^}/' "$BUILT")
wg_add_full_body=$(awk '/^wg_add_peer\(\)/,/^_wg_update_peer_routes\(\)/' "$BUILT")
wg_toggle_full_body=$(awk '/^wg_toggle_peer\(\)/,/^wg_delete_peer\(\)/' "$BUILT")
wg_delete_full_body=$(awk '/^wg_delete_peer\(\)/,/^wg_show_peer_conf\(\)/' "$BUILT")
wg_update_routes_body=$(awk '/^_wg_update_peer_routes\(\)/,/^}/' "$BUILT")
wg_deb_update_routes_body=$(awk '/^_wg_deb_update_peer_routes\(\)/,/^}/' "$BUILT")
wg_install_body=$(awk '/^wg_server_install\(\)/,/^}/' "$BUILT")
wg_modify_body=$(awk '/^wg_modify_server\(\)/,/^}/' "$BUILT")
wg_deb_modify_body=$(awk '/^wg_deb_modify_server\(\)/,/^}/' "$BUILT")
wg_deb_modify_full_body=$(awk '/^wg_deb_modify_server\(\)/,/^wg_deb_server_status\(\)/' "$BUILT")
wg_watchdog_body=$(awk '/^wg_setup_watchdog\(\)/,/^wg_export_peers\(\)/' "$BUILT")
wg_deb_install_body=$(awk '/^wg_deb_server_install\(\)/,/^}/' "$BUILT")
wg_deb_install_full_body=$(awk '/^wg_deb_server_install\(\)/,/^wg_deb_modify_server\(\)/' "$BUILT")
wg_openwrt_install_full_body=$(awk '/^wg_server_install\(\)/,/^wg_modify_server\(\)/' "$BUILT")
wg_openwrt_modify_full_body=$(awk '/^wg_modify_server\(\)/,/^wg_server_status\(\)/' "$BUILT")
wg_deb_import_body=$(awk '/^wg_deb_import_peers\(\)/,/^}/' "$BUILT")
wg_export_body=$(awk '/^wg_export_peers\(\)/,/^wg_import_peers\(\)/' "$BUILT")
wg_deb_export_body=$(awk '/^wg_deb_export_peers\(\)/,/^wg_deb_import_peers\(\)/' "$BUILT")
wg_main_body=$(awk '/^wg_main_menu\(\)/,/^}/' "$BUILT")
wg_deb_main_body=$(awk '/^wg_deb_main_menu\(\)/,/^}/' "$BUILT")

# G3: 修改服务端 LAN 子网必须校验 CIDR，并联动刷新 peer routes。
grep -q '^validate_cidr()' "$BUILT" \
    && grep -q '^validate_cidr_list()' "$BUILT" \
    && pass "G3: CIDR 校验 helper 已定义" \
    || fail "G3: 缺少 CIDR 校验 helper"
if declare -F validate_cidr >/dev/null; then
    validate_cidr "192.168.1.0/24" \
        && pass "G3: CIDR helper 接受合法 IPv4 CIDR" \
        || fail "G3: CIDR helper 未接受合法 IPv4 CIDR"
    if validate_cidr "192.168.1.0/33"; then
        fail "G3: CIDR helper 错误接受 /33"
    else
        pass "G3: CIDR helper 拒绝非法前缀"
    fi
fi
echo "$wg_modify_body" | grep -q 'validate_cidr_list "\$new_lan"' \
    && echo "$wg_modify_body" | grep -q '_wg_update_peer_routes' \
    && pass "G3: OpenWrt 修改服务端 LAN 会校验并联动刷新 peer routes" \
    || fail "G3: OpenWrt 修改服务端 LAN 未校验或未联动刷新 peer routes"
if grep -q '^_wg_openwrt_apply_allow_port()' "$BUILT" \
   && grep -q 'if ! _wg_openwrt_apply_allow_port "\$wg_port"; then' <<< "$wg_openwrt_install_full_body" \
   && grep -q '_wg_openwrt_rollback_server_install "\$wg_install_snapshot_dir" "\$wg_forward_changed"' <<< "$wg_openwrt_install_full_body" \
   && grep -q 'return 1' <<< "$wg_openwrt_install_full_body" \
   && ! grep -q 'nft insert rule inet fw4 input_wan udp dport "\$wg_port".*|| true' <<< "$wg_openwrt_install_full_body"; then
    pass "G3: OpenWrt 服务端安装会校验 UDP 端口放行失败"
else
    fail "G3: OpenWrt 服务端安装仍可能吞掉 UDP 端口放行失败"
fi
if awk '
    /_wg_openwrt_apply_allow_port "\$new_port"/ { allow=NR }
    /wg_db_set --argjson p "\$new_port"/ { db=NR }
    END { exit (allow && db && allow < db) ? 0 : 1 }
' <<< "$wg_openwrt_modify_full_body" \
   && grep -q '_wg_openwrt_rollback_server_modify "\$cur_port" "\$cur_dns" "\$cur_ep" "\$cur_lan" "\$port_firewall_changed"' <<< "$wg_openwrt_modify_full_body" \
   && ! grep -q 'nft insert rule inet fw4 input_wan udp dport "\$new_port".*|| true' <<< "$wg_openwrt_modify_full_body"; then
    pass "G3: OpenWrt 修改服务端端口先预放行并在失败时回滚"
else
    fail "G3: OpenWrt 修改服务端端口仍可能 DB/防火墙状态漂移"
fi
echo "$wg_deb_modify_body" | grep -q 'validate_cidr_list "\$new_lan"' \
    && echo "$wg_deb_modify_body" | grep -q '_wg_deb_update_peer_routes' \
    && pass "G3: Debian 修改服务端 LAN 会校验并联动刷新 peer routes" \
    || fail "G3: Debian 修改服务端 LAN 未校验或未联动刷新 peer routes"

if grep -q '^_wg_openwrt_snapshot_db()' "$BUILT" \
   && grep -q '^_wg_openwrt_restore_peer_snapshot()' "$BUILT" \
   && awk '
       /wg_db_set --arg name "\$peer_name"/ { db=NR }
       /wg_regenerate_client_confs/ && !clients { clients=NR }
       END { exit (db && clients && db < clients) ? 0 : 1 }
   ' <<< "$wg_add_full_body" \
   && ! awk '
       /write_file_atomic "\$conf_file" "\$client_conf"/ { prewrite=NR }
       /wg_db_set --arg name "\$peer_name"/ { db=NR }
       END { exit (prewrite && db && prewrite < db) ? 0 : 1 }
   ' <<< "$wg_add_full_body"; then
    pass "G3: OpenWrt 添加 peer 先写 DB 后生成客户端配置"
else
    fail "G3: OpenWrt 添加 peer 仍可能 DB 前写配置或缺少快照回滚"
fi
if grep -q '_wg_openwrt_restore_peer_snapshot "\$db_snapshot"' <<< "$wg_toggle_full_body" \
   && grep -q 'if ! wg_db_set --argjson idx "\$target_idx" .*enabled = false' <<< "$wg_toggle_full_body" \
   && grep -q 'if ! wg_db_set --argjson idx "\$target_idx" .*enabled = true' <<< "$wg_toggle_full_body"; then
    pass "G3: OpenWrt peer 启停检查 DB 写入并在运行应用失败时回滚"
else
    fail "G3: OpenWrt peer 启停仍缺 DB 检查或失败回滚"
fi
if grep -q '_wg_openwrt_restore_peer_snapshot "\$db_snapshot"' <<< "$wg_delete_full_body" \
   && grep -q 'if ! wg_db_set --argjson idx "\$target_idx" .*del(.peers' <<< "$wg_delete_full_body" \
   && awk '
       /wg_apply_runtime_conf/ && !apply { apply=NR }
       /rm -f -- "\$conf_file"/ { rm=NR }
       END { exit (apply && rm && apply < rm) ? 0 : 1 }
   ' <<< "$wg_delete_full_body"; then
    pass "G3: OpenWrt 删除 peer 应用成功后才删除客户端配置，失败会回滚"
else
    fail "G3: OpenWrt 删除 peer 仍可能运行态失败后丢 DB/配置"
fi

# G4: 自定义路由 peer 不能被网关增删时的 route 刷新覆盖。
echo "$wg_add_body" | grep -q 'route_mode: \$route_mode' \
    && echo "$wg_deb_add_body" | grep -q 'route_mode: \$route_mode' \
    && pass "G4: 新增 peer 持久化 route_mode" \
    || fail "G4: 新增 peer 未持久化 route_mode"
echo "$wg_update_routes_body" | grep -q 'route_mode.*custom' \
    && { echo "$wg_deb_update_routes_body" | grep -q 'route_mode.*custom' \
         || { echo "$wg_deb_update_routes_body" | grep -q 'case "\$_route_mode"' \
              && echo "$wg_deb_update_routes_body" | grep -q 'custom|full|vpn'; }; } \
    && pass "G4: route 刷新跳过自定义路由 peer" \
    || fail "G4: route 刷新未跳过自定义路由 peer"
grep -q '^wg_shared_normalize_endpoint_host()' "$BUILT" \
    && pass "G4: WireGuard endpoint 归一化校验 helper 已定义" \
    || fail "G4: 缺少 WireGuard endpoint 归一化校验 helper"
echo "$wg_install_body" | grep -q 'wg_shared_normalize_endpoint_host "\$wg_endpoint"' \
    && echo "$wg_deb_install_body" | grep -q 'wg_shared_normalize_endpoint_host "\$wg_endpoint"' \
    && pass "G4: WireGuard 服务端安装校验 endpoint" \
    || fail "G4: WireGuard 服务端安装未校验 endpoint"
echo "$wg_modify_body" | grep -q 'wg_shared_normalize_endpoint_host "\$new_ep"' \
    && echo "$wg_deb_modify_body" | grep -q 'wg_shared_normalize_endpoint_host "\$new_ep"' \
    && pass "G4: WireGuard 服务端修改校验 endpoint" \
    || fail "G4: WireGuard 服务端修改未校验 endpoint"

# G8: OpenWrt 自动安装尾声调用 wg_setup_watchdog true 时不应进入交互/清屏暂停。
echo "$wg_watchdog_body" | grep -q 'auto_mode="\${1:-}"' \
    && echo "$wg_watchdog_body" | grep -q '\[\[ -z "\$auto_mode" \]\] && cron_has_job_command "\$watchdog_script"' \
    && echo "$wg_watchdog_body" | grep -q 'cron_add_job_command "\$watchdog_script"' \
    && echo "$wg_watchdog_body" | grep -q '\[\[ -z "\$auto_mode" \]\] && pause' \
    && pass "G8: OpenWrt watchdog 支持 auto_mode 非交互安装" \
    || fail "G8: OpenWrt watchdog 仍忽略 auto_mode"
echo "$wg_watchdog_body" | grep -Fq 'mktemp "$(dirname "$watchdog_script")/.tmp.server-manage.wg-watchdog.XXXXXX"' \
    && echo "$wg_watchdog_body" | grep -Fq 'mv "$watchdog_tmp" "$watchdog_script"' \
    && ! echo "$wg_watchdog_body" | grep -q 'cat > "$watchdog_script"' \
    && pass "G8: OpenWrt watchdog 脚本通过临时文件原子替换" \
    || fail "G8: OpenWrt watchdog 脚本仍可能直写最终路径"

# G11: Debian 线关键 DB 写入失败不能继续假成功。
echo "$wg_deb_install_body" | grep -q 'if ! wg_deb_db_set' \
    && pass "G11: Debian 服务端安装检查 DB 写入失败" \
    || fail "G11: Debian 服务端安装未检查 DB 写入失败"
echo "$wg_deb_add_body" | grep -q 'if ! wg_deb_db_set' \
    && echo "$wg_deb_add_body" | grep -q 'rm -f "\$conf_file"' \
    && pass "G11: Debian 添加 peer 检查 DB 写入失败并清理配置" \
    || fail "G11: Debian 添加 peer 未检查 DB 写入失败"
echo "$wg_deb_import_body" | grep -q 'if ! wg_deb_db_set' \
    && echo "$wg_deb_import_body" | grep -q 'skipped=\$((skipped + 1))' \
    && pass "G11: Debian 导入 peer 检查 DB 写入失败并计入跳过" \
    || fail "G11: Debian 导入 peer 未检查 DB 写入失败"

# G12: BusyBox mktemp 要求 X 位于模板末尾，导出文件模板不能是 XXXXXX.json。
if grep -q 'mktemp "/tmp/\${SCRIPT_NAME}-wg-peers-XXXXXX\.json"' "$BUILT"; then
    fail "G12: WireGuard 导出仍使用 BusyBox 不兼容 mktemp 模板"
else
    pass "G12: WireGuard 导出 mktemp 模板兼容 BusyBox"
fi
wg_export_helper_body=$(awk '/^wg_shared_export_file\(\)/,/^wg_shared_db_init\(\)/' "$BUILT")
if echo "$wg_export_helper_body" | grep -q 'WG_EXPORT_DIR:-/root/wireguard-exports' \
   && echo "$wg_export_helper_body" | grep -q 'chmod 700 "\$dir"' \
   && echo "$wg_export_helper_body" | grep -q 'umask 077' \
   && echo "$wg_export_helper_body" | grep -q 'chmod 600 "\$tmp"'; then
    pass "G12: WireGuard 导出敏感 JSON 使用 root 私有目录/0600 文件"
else
    fail "G12: WireGuard 导出 helper 缺少私有目录或权限保护"
fi
if echo "$wg_export_body" | grep -q 'wg_shared_export_file' \
   && echo "$wg_deb_export_body" | grep -q 'wg_shared_export_file' \
   && ! echo "$wg_export_body$wg_deb_export_body" | grep -q 'mktemp "/tmp/\${SCRIPT_NAME}-wg-peers'; then
    pass "G12: OpenWrt/Debian WireGuard 导出不再落公共 /tmp"
else
    fail "G12: WireGuard 导出仍可能把含私钥 JSON 放到公共 /tmp"
fi

# G13: 不得仅凭 wg0.conf 存在就把角色强制改成 server。
if echo "$wg_main_body" | grep -q 'role" == "server" || -f "\$WG_CONF"'; then
    fail "G13: OpenWrt 主菜单仍仅凭 wg0.conf 强制 server"
else
    pass "G13: OpenWrt 主菜单不再仅凭 wg0.conf 强制 server"
fi
echo "$wg_main_body" | grep -q 'server.private_key' \
    && pass "G13: OpenWrt 主菜单检查 server state 后才识别服务端" \
    || fail "G13: OpenWrt 主菜单未检查 server state"
if echo "$wg_deb_main_body" | grep -q 'role" == "server" || -f "\$WG_DEB_CONF"'; then
    fail "G13: Debian 主菜单仍仅凭 wg0.conf 强制 server"
else
    pass "G13: Debian 主菜单不再仅凭 wg0.conf 强制 server"
fi
echo "$wg_deb_main_body" | grep -q 'server.private_key' \
    && pass "G13: Debian 主菜单检查 server state 后才识别服务端" \
    || fail "G13: Debian 主菜单未检查 server state"

echo ""
echo "== review #23 审计报告 WireGuard Clash 回归 =="
wg_clash_body=$(awk '/^_wg_generate_clash_config_impl\(\)/,/^}/' "$BUILT")

# G5: 自动注入 YAML 时，如果原配置没有 proxy-groups:，必须生成顶级 proxy-groups: key，
# 不能把 group 条目追加到 rules: 后导致 YAML 损坏。
echo "$wg_clash_body" | grep -q 'has_proxy_groups' \
    && echo "$wg_clash_body" | grep -q 'print "proxy-groups:"' \
    && pass "G5: Clash 自动注入缺少 proxy-groups 时会补顶级 key" \
    || fail "G5: Clash 自动注入缺少 proxy-groups 时未补顶级 key"

# G6: proxy-providers block 提取不能用起止都匹配顶级 key 的 awk 范围。
if echo "$wg_clash_body" | grep -q "awk '/\\^proxy-providers:/,/\\^\\[a-zA-Z_-" ; then
    fail "G6: proxy-providers 提取仍使用起始行即终止的 awk 范围"
else
    pass "G6: proxy-providers 提取不再使用错误 awk 范围"
fi
echo "$wg_clash_body" | grep -q 'in_providers' \
    && pass "G6: proxy-providers 提取使用显式状态机" \
    || fail "G6: proxy-providers 提取未使用显式状态机"

# G7: 含 WireGuard 私钥/PSK 的 Clash YAML 输出文件必须 600。
echo "$wg_clash_body" | grep -q 'umask 077' \
    && echo "$wg_clash_body" | grep -q 'chmod 600 "\$output_file"' \
    && pass "G7: Clash YAML 输出以 0600 权限创建/收紧" \
    || fail "G7: Clash YAML 输出未保证 0600 权限"
if echo "$wg_clash_body" | grep -q '/tmp/clash-wg-\${peer_name}-'; then
    fail "G7: Clash YAML 输出路径仍拼接 peer 名和时间戳到 /tmp"
else
    pass "G7: Clash YAML 输出路径不再拼接 peer 名到 /tmp"
fi
echo "$wg_clash_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/clash-wg.XXXXXX"' \
    && echo "$wg_clash_body" | grep -q 'chmod 700 "\$output_dir"' \
    && echo "$wg_clash_body" | grep -q 'output_file="\${output_dir}/clash-config.yaml"' \
    && echo "$wg_clash_body" | grep -q 'rm -rf "\$output_dir"' \
    && pass "G7: Clash YAML 输出使用随机 0700 目录并在失败时清理" \
    || fail "G7: Clash YAML 输出缺少安全随机目录或失败清理"
if echo "$wg_clash_body" | grep -q 'mktemp "\${output_dir}/.clash-config.yaml.policy.XXXXXX"' \
   && echo "$wg_clash_body" | grep -q 'chmod 600 "\$_tmpf"' \
   && ! echo "$wg_clash_body" | grep -q '_tmpf=$(mktemp)' \
   && ! echo "$wg_clash_body" | grep -q '> "\$_tmpf" && mv "\$_tmpf"'; then
    pass "G7: Clash nameserver-policy 二次写回使用同目录私有临时文件"
else
    fail "G7: Clash nameserver-policy 二次写回仍可能落公共临时文件"
fi

echo ""
echo "== review #24 审计报告 WireGuard 运行时回归 =="
wg_bypass_body=$(awk '/^wg_setup_mihomo_bypass\(\)/,/^}/' "$BUILT")
wg_bypass_rebuild_body=$(awk '/^wg_mihomo_bypass_rebuild\(\)/,/^}/' "$BUILT")
wg_bypass_clean_body=$(awk '/^wg_mihomo_bypass_clean\(\)/,/^wg_mihomo_bypass_rebuild\(\)/' "$BUILT")
wg_modify_server_body=$(awk '/^wg_modify_server\(\)/,/^wg_setup_mihomo_bypass\(\)/' "$BUILT")

# G2: Debian 修改出口网卡后必须清理旧 iface 的 NAT MASQUERADE 规则。
grep -q '^_wg_deb_cleanup_nat_iface()' "$BUILT" \
    && pass "G2: Debian NAT 旧出口清理 helper 已定义" \
    || fail "G2: 缺少 Debian NAT 旧出口清理 helper"
echo "$wg_deb_modify_body" | grep -q 'iface_changed=true' \
    && echo "$wg_deb_modify_body" | grep -q '_wg_deb_cleanup_nat_iface "\$cur_subnet" "\$cur_iface"' \
    && pass "G2: Debian 修改出口网卡后清理旧 NAT 规则" \
    || fail "G2: Debian 修改出口网卡后未清理旧 NAT 规则"

# G9: OpenWrt watchdog 不能只 grep wg_bypass 子串；要分别自愈 iface/subnet 规则。
if echo "$wg_watchdog_body" | grep -q 'grep -q "wg_bypass"'; then
    fail "G9: OpenWrt watchdog 仍用 wg_bypass 子串判断，可能漏修 subnet"
else
    pass "G9: OpenWrt watchdog 不再用 wg_bypass 子串判断"
fi
echo "$wg_watchdog_body" | grep -q 'wg_bypass_iface' \
    && echo "$wg_watchdog_body" | grep -q 'wg_bypass_subnet' \
    && pass "G9: OpenWrt watchdog 分别检查 iface/subnet bypass 规则" \
    || fail "G9: OpenWrt watchdog 未分别检查 iface/subnet bypass 规则"
if echo "$wg_watchdog_body" | grep -q 'wg_nft_addr_family_for_cidr' \
   && echo "$wg_watchdog_body" | grep -q '"\$NFT_FAMILY" daddr "\$sub"' \
   && ! echo "$wg_watchdog_body" | grep -q 'ip daddr "\$sub"'; then
    pass "G9: OpenWrt watchdog subnet bypass 按 IPv4/IPv6 选择 nft 地址族"
else
    fail "G9: OpenWrt watchdog subnet bypass 仍可能把 IPv6 CIDR 写入 ip daddr"
fi
if echo "$wg_watchdog_body" | grep -q '&>/dev/null'; then
    fail "G9: OpenWrt sh watchdog 仍含 Bash-only &> 重定向"
else
    pass "G9: OpenWrt sh watchdog 使用 POSIX 重定向"
fi

# G10: rc.local 多行持久化不能依赖 busybox sed 不兼容的 i\\ 多行插入。
grep -q '^_wg_rc_local_insert_block()' "$BUILT" \
    && pass "G10: rc.local 块插入 helper 已定义" \
    || fail "G10: 缺少 rc.local 块插入 helper"
if echo "$wg_bypass_body" | grep -q 'sed -i "/\^exit 0/i\\'; then
    fail "G10: wg_setup_mihomo_bypass 仍用 busybox 不兼容 sed 多行插入"
else
    pass "G10: wg_setup_mihomo_bypass 不再用 sed 多行插入"
fi
if echo "$wg_bypass_rebuild_body" | grep -q 'sed -i "/\^exit 0/i\\'; then
    fail "G10: wg_mihomo_bypass_rebuild 仍用 busybox 不兼容 sed 多行插入"
else
    pass "G10: wg_mihomo_bypass_rebuild 不再用 sed 多行插入"
fi
if echo "$wg_modify_server_body" | grep -q 'sed -i "/\^exit 0/i'; then
    fail "G10: wg_modify_server 端口变更仍用 BusyBox 不兼容 sed 插入 rc.local"
else
    pass "G10: wg_modify_server 端口变更不再用 sed 插入 rc.local"
fi
grep -q '_wg_rc_local_insert_block "\$rc_block"' <<< "$wg_bypass_body" \
    && grep -q '_wg_openwrt_apply_allow_port "\$wg_port" || return 1' <<< "$wg_bypass_rebuild_body" \
    && grep -q '_wg_openwrt_write_allow_port_rc_local "\$port"' "$BUILT" \
    && pass "G10: Mihomo bypass/端口持久化使用 rc.local helper" \
    || fail "G10: Mihomo bypass/端口持久化未使用 rc.local helper"
if grep -q 'wg_allow_port' <<< "$wg_bypass_clean_body" \
   || grep -q '_wg_rc_local_cleanup_managed_entries all' <<< "$wg_bypass_clean_body"; then
    fail "G10: wg_mihomo_bypass_clean 仍会误删 OpenWrt UDP 端口放行"
else
    pass "G10: wg_mihomo_bypass_clean 只清 bypass，不误删 UDP 端口放行"
fi
if grep -q '^nft_addr_family_for_cidr()' "$BUILT" \
   && echo "$wg_bypass_body" | grep -q 'nft_addr_family_for_cidr "\$cidr"' \
   && echo "$wg_bypass_body" | grep -q '"\$nft_family" daddr "\$cidr"' \
   && ! echo "$wg_bypass_body" | grep -q 'ip daddr "\$cidr"'; then
    pass "G10: OpenWrt Mihomo bypass IPv6 CIDR 使用 ip6 daddr"
else
    fail "G10: OpenWrt Mihomo bypass 仍可能把 IPv6 CIDR 写入 ip daddr"
fi

echo ""
echo "== review #25 第二轮审计 fix_broken 回归 =="
# N1: geoip-update.sh 写回 GEOIP_LAST_UPDATE 时必须保留 KEY=\"value\" 格式，
# 且不能原地 sed 修改配置，避免中断/异常时留下半写状态。
geoip_update_body=$(awk '/^geoip_update\(\)/,/^geoip_disable\(\)/' "$BUILT")
geoip_persistence_body=$(awk '/^_geoip_install_persistence\(\)/,/^geoip_setup\(\)/' "$BUILT")
geoip_setup_body=$(awk '/^geoip_setup\(\)/,/^geoip_status\(\)/' "$BUILT")
if grep -q '^_geoip_update_last_update()' "$BUILT" \
   && grep -q '^_geoip_render_conf_last_update()' "$BUILT" \
   && grep -q 'write_private_file_atomic "\$conf_file" "\$content"' "$BUILT" \
   && ! echo "$geoip_update_body" | grep -q 'sed -i.*GEOIP_LAST_UPDATE' \
   && ! echo "$geoip_persistence_body" | grep -q 'sed -i.*GEOIP_LAST_UPDATE'; then
    pass "N1: GeoIP update 通过原子写入维护 LAST_UPDATE 双引号"
else
    fail "N1: GeoIP update 仍可能原地改写 LAST_UPDATE 或破坏 KEY=\"value\" 格式"
fi
if echo "$geoip_persistence_body" | grep -q 'cat > /etc/systemd/system/geoip-firewall.service' \
   || echo "$geoip_persistence_body" | grep -q 'cat > /usr/local/bin/geoip'; then
    fail "N1: GeoIP 持久化脚本/unit 仍直接重定向到系统路径"
else
    pass "N1: GeoIP 持久化脚本/unit 不再直接重定向到系统路径"
fi
if echo "$geoip_persistence_body" | grep -q 'systemctl daemon-reload || return 1' \
   && echo "$geoip_persistence_body" | grep -q 'systemctl enable geoip-firewall >/dev/null 2>&1 || return 1'; then
    pass "N1: GeoIP 持久化检查 systemd reload/enable 失败"
else
    fail "N1: GeoIP 持久化仍可能忽略 systemd reload/enable 失败"
fi
if echo "$geoip_setup_body" | grep -q 'persistence_ok=1' \
   && echo "$geoip_setup_body" | grep -q '自动更新: 未安装成功' \
   && echo "$geoip_setup_body" | grep -q 'return 1'; then
    pass "N1: GeoIP 持久化失败时不再提示完整成功"
else
    fail "N1: GeoIP 持久化失败仍可能提示完整成功"
fi

# N2: DDNS 新建配置必须真实写出双引号，匹配 cron parse_ddns_conf 白名单格式。
ddns_tmp=$(mktemp -d)
DDNS_CONFIG_DIR="$ddns_tmp/conf"
DDNS_UPDATE_SCRIPT="$ddns_tmp/ddns-update.sh"
cron_remove_job() { :; }
cron_add_job() { :; }
log_action() { :; }
print_error() { echo "ERROR: $*" >&2; }
if ddns_setup_noninteractive "example.com" "tok_123" "zone_456" true false false 7 >/dev/null 2>&1; then
    ddns_conf="$DDNS_CONFIG_DIR/example.com.conf"
    if grep -Fxq 'DDNS_DOMAIN="example.com"' "$ddns_conf" \
        && grep -Fxq 'DDNS_TOKEN="tok_123"' "$ddns_conf" \
        && grep -Fxq 'DDNS_ZONE_ID="zone_456"' "$ddns_conf" \
        && grep -Fxq 'DDNS_IPV4="true"' "$ddns_conf" \
        && grep -Fxq 'DDNS_IPV6="false"' "$ddns_conf" \
        && grep -Fxq 'DDNS_PROXIED="false"' "$ddns_conf" \
        && grep -Fxq 'DDNS_INTERVAL="7"' "$ddns_conf"; then
        pass "N2: ddns_setup_noninteractive 写出 KEY=\"value\" 配置"
    else
        fail "N2: ddns_setup_noninteractive 配置缺少双引号"
        sed 's/^/    /' "$ddns_conf" 2>/dev/null || true
    fi
else
    fail "N2: ddns_setup_noninteractive 调用失败"
fi
printf 'old-token\n' > "$DDNS_CONFIG_DIR/example.com.conf"
chmod 666 "$DDNS_CONFIG_DIR/example.com.conf" 2>/dev/null || true
if ddns_setup_noninteractive "example.com" "tok_789" "zone_999" true false false 7 >/dev/null 2>&1 \
   && mode_is_600 "$DDNS_CONFIG_DIR/example.com.conf" \
   && grep -Fxq 'DDNS_TOKEN="tok_789"' "$DDNS_CONFIG_DIR/example.com.conf"; then
    pass "N2: DDNS 配置覆盖旧宽权限文件后仍为 0600"
else
    fail "N2: DDNS 配置覆盖旧宽权限文件后未收紧为 0600"
    ls -l "$DDNS_CONFIG_DIR/example.com.conf" 2>/dev/null | sed 's/^/    /' || true
fi
rm -rf "$ddns_tmp"

# DDNS interval=59 不能写成 */59（每小时第 0/59 分钟，间隔会出现 1 分钟）。
# cron 应每分钟触发，由更新脚本按每个配置的 DDNS_INTERVAL 节流。
ddns_cron_tmp=$(mktemp -d)
DDNS_CONFIG_DIR="$ddns_cron_tmp/conf"
DDNS_UPDATE_SCRIPT="$ddns_cron_tmp/ddns-update.sh"
mkdir -p "$DDNS_CONFIG_DIR"
cat > "$DDNS_CONFIG_DIR/example.com.conf" <<'DDNSCONF'
DDNS_DOMAIN="example.com"
DDNS_TOKEN="tok"
DDNS_ZONE_ID="zone"
DDNS_IPV4="true"
DDNS_IPV6="false"
DDNS_PROXIED="false"
DDNS_INTERVAL="59"
DDNSCONF
cron_line=""
cron_remove_job() { :; }
cron_add_job() { cron_line="$2"; }
ddns_rebuild_cron >/dev/null 2>&1 || true
if [[ "$cron_line" == "* * * * * "* ]]; then
    pass "DDNS: cron 每分钟触发，由脚本按 interval 节流"
else
    fail "DDNS: cron 仍使用 */N，interval=59 语义错误: ${cron_line:-<empty>}"
fi
ddns_create_script >/dev/null 2>&1
if grep -q 'DDNS_STAMP_DIR' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'DDNS_INTERVAL' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'interval \* 60' "$DDNS_UPDATE_SCRIPT"; then
    pass "DDNS: 更新脚本按配置 interval 做节流"
else
    fail "DDNS: 更新脚本缺少 per-config interval 节流"
fi
if grep -q 'DDNS_RUNTIME_DIR="/var/lib/server-manage/ddns"' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'DDNS_STAMP_DIR="\$DDNS_RUNTIME_DIR/stamps"' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'exec 200>"\$DDNS_RUNTIME_DIR/update.lock"' "$DDNS_UPDATE_SCRIPT" \
   && ! grep -q '/tmp/ddns-state\|/tmp/ddns-update.lock' "$DDNS_UPDATE_SCRIPT"; then
    pass "DDNS: 运行时锁和 stamp 使用 root 私有目录"
else
    fail "DDNS: 运行时锁或 stamp 仍可能落公共 /tmp"
fi
if grep -q '^[[:space:]]*failed=0$' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'BASH_SOURCE\[0\].*==.*"\$0"' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'update_cf "\$DDNS_DOMAIN" A .* || failed=1' "$DDNS_UPDATE_SCRIPT" \
   && grep -q '获取公网 IPv4 失败' "$DDNS_UPDATE_SCRIPT" \
   && grep -q 'exit "\$failed"' "$DDNS_UPDATE_SCRIPT"; then
    pass "DDNS: 更新脚本汇总 get_ip/update_cf 失败并返回非 0"
else
    fail "DDNS: 更新脚本仍可能吞掉 get_ip/update_cf 失败"
fi
ddns_force_body=$(awk '/^ddns_force_update\(\)/,/^}/' "$BUILT")
if echo "$ddns_force_body" | grep -q 'if DDNS_FORCE=1 "\$DDNS_UPDATE_SCRIPT"; then' \
   && echo "$ddns_force_body" | grep -q 'print_error "DDNS 更新失败' \
   && echo "$ddns_force_body" | grep -q 'return "\$rc"'; then
    pass "DDNS: 手动强制更新检查脚本退出码"
else
    fail "DDNS: 手动强制更新仍可能无条件提示成功"
fi
ddns_create_body=$(awk '/^ddns_create_script\(\)/,/^ddns_setup\(\)/' "$BUILT")
echo "$ddns_create_body" | grep -Fq 'mktemp "$(dirname "$DDNS_UPDATE_SCRIPT")/.tmp.server-manage.ddns-update.XXXXXX"' \
    && echo "$ddns_create_body" | grep -Fq 'mv "$ddns_script_tmp" "$DDNS_UPDATE_SCRIPT"' \
    && ! echo "$ddns_create_body" | grep -q 'cat > "$DDNS_UPDATE_SCRIPT"' \
    && pass "DDNS: 更新脚本通过临时文件原子替换" \
    || fail "DDNS: 更新脚本仍可能直写最终脚本路径"
if echo "$ddns_create_body" | grep -q 'DDNS_RUNTIME_DIR="/var/lib/server-manage/ddns"' \
   && echo "$ddns_create_body" | grep -q 'chmod 700 /var/lib/server-manage "\$DDNS_RUNTIME_DIR" "\$DDNS_STAMP_DIR"' \
   && ! echo "$ddns_create_body" | grep -q '/tmp/ddns-state\|/tmp/ddns-update.lock'; then
    pass "DDNS: 生成模板不再包含公共 /tmp 状态路径"
else
    fail "DDNS: 生成模板仍包含公共 /tmp 状态路径"
fi
rm -rf "$ddns_cron_tmp"

echo ""
echo "== review #26 第二轮审计行级安全回归 =="
# N3: SSH 监听端口检测只能匹配 :port 结尾，不能把 1022/2022 误判为 22。
ssh_port_mock_dir=$(mktemp -d)
cat > "$ssh_port_mock_dir/ss" <<'SSMOCK'
#!/bin/bash
case "${SSH_MOCK_PORT_CASE:-suffix}" in
  suffix)
    echo 'LISTEN 0 128 0.0.0.0:1022 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
    ;;
  exact)
    echo 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))'
    ;;
esac
SSMOCK
chmod +x "$ssh_port_mock_dir/ss"
if PATH="$ssh_port_mock_dir:$PATH" SSH_MOCK_PORT_CASE=suffix _ssh_port_is_listening 22; then
    fail "N3: _ssh_port_is_listening 将 1022 误判为 22"
else
    pass "N3: _ssh_port_is_listening 不匹配端口后缀"
fi
if PATH="$ssh_port_mock_dir:$PATH" SSH_MOCK_PORT_CASE=exact _ssh_port_is_listening 2222; then
    pass "N3: _ssh_port_is_listening 仍匹配精确 :port"
else
    fail "N3: _ssh_port_is_listening 未匹配精确 :port"
fi
rm -rf "$ssh_port_mock_dir"

# N4: 家宽暴露自动配置路由器 DNS 劫持前必须校验 nginx_ip，并把 router_ssh 当作单个 SSH 目标参数。
grep -qF 'validate_ip "$nginx_ip"' "$BUILT" \
    && pass "N4: 家宽 DNS 劫持校验 nginx_ip" \
    || fail "N4: 家宽 DNS 劫持未校验 nginx_ip"
grep -qF '"$router_ssh" "${uci_cmds}"' "$BUILT" \
    && pass "N4: 路由器 SSH 目标已加引号" \
    || fail "N4: 路由器 SSH 目标仍未加引号"

# N5: Reality landing/relay 角色合并要按包含关系判断，避免 landing+relay 二次安装降级。
landing_body=$(awk '/^reality_install_landing\(\)/,/^reality_install_relay\(\)/' "$BUILT")
relay_body=$(awk '/^reality_install_relay\(\)/,/^reality_prompt_port\(\)/' "$BUILT")
echo "$landing_body" | grep -q 'reality_load_state || true' \
    && pass "N5: 安装落地机会先加载现有 relay 状态" \
    || fail "N5: 安装落地机未加载现有 relay 状态"
echo "$landing_body" | grep -qF '== *"relay"*' \
    && pass "N5: 落地机安装保留 relay 复合角色" \
    || fail "N5: 落地机安装未按包含关系保留 relay 角色"
echo "$relay_body" | grep -qF '== *"landing"*' \
    && pass "N5: 中转安装保留 landing 复合角色" \
    || fail "N5: 中转安装未按包含关系保留 landing 角色"

echo ""
echo "== review #27 第二轮审计 WireGuard 导入回归 =="
wg_import_full_body=$(awk '/^wg_import_peers\(\)/,/^wg_server_menu\(\)/' "$BUILT")
wg_deb_import_full_body=$(awk '/^wg_deb_import_peers\(\)/,/^wg_deb_server_menu\(\)/' "$BUILT")

# N6: 导入导出的 peer 时必须保留 route_mode，否则 custom peer 迁移后会被自动路由覆盖。
echo "$wg_import_full_body" | grep -q 'route_mode=$(jq -r ".peers\[$i\].route_mode // empty"' \
    && echo "$wg_import_full_body" | grep -q -- '--arg route_mode "\$route_mode"' \
    && echo "$wg_import_full_body" | grep -q 'route_mode: \$route_mode' \
    && pass "N6: OpenWrt WG 导入保留 route_mode" \
    || fail "N6: OpenWrt WG 导入未保留 route_mode"
echo "$wg_deb_import_full_body" | grep -q 'route_mode=$(jq -r ".peers\[$i\].route_mode // empty"' \
    && echo "$wg_deb_import_full_body" | grep -q -- '--arg route_mode "\$route_mode"' \
    && echo "$wg_deb_import_full_body" | grep -q 'route_mode: \$route_mode' \
    && pass "N6: Debian WG 导入保留 route_mode" \
    || fail "N6: Debian WG 导入未保留 route_mode"

# N7: 导入 JSON 的路由和密钥字段必须校验后入库。
grep -q '^validate_wg_key()' "$BUILT" \
    && pass "N7: WireGuard key 校验 helper 已定义" \
    || fail "N7: 缺少 WireGuard key 校验 helper"
if declare -F validate_wg_key >/dev/null; then
    valid_wg_key="$(printf 'A%.0s' {1..43})="
    validate_wg_key "$valid_wg_key" \
        && pass "N7: validate_wg_key 接受 44 字符 base64 key" \
        || fail "N7: validate_wg_key 拒绝合法形态 key"
    if validate_wg_key "bad key;reboot"; then
        fail "N7: validate_wg_key 错误接受命令字符"
    else
        pass "N7: validate_wg_key 拒绝命令字符"
    fi
fi
echo "$wg_import_full_body" | grep -q 'validate_cidr_list "\$allowed"' \
    && echo "$wg_import_full_body" | grep -q 'validate_cidr_list "\$lans"' \
    && echo "$wg_import_full_body" | grep -q 'validate_wg_key "\$privkey"' \
    && echo "$wg_import_full_body" | grep -q 'validate_wg_key "\$pubkey"' \
    && echo "$wg_import_full_body" | grep -q 'validate_wg_key "\$psk"' \
    && pass "N7: OpenWrt WG 导入校验 allowed/lans/keys" \
    || fail "N7: OpenWrt WG 导入未完整校验 allowed/lans/keys"
echo "$wg_deb_import_full_body" | grep -q 'validate_ip "\$ip"' \
    && echo "$wg_deb_import_full_body" | grep -q 'validate_cidr_list "\$allowed"' \
    && echo "$wg_deb_import_full_body" | grep -q 'validate_cidr_list "\$lans"' \
    && echo "$wg_deb_import_full_body" | grep -q 'validate_wg_key "\$privkey"' \
    && echo "$wg_deb_import_full_body" | grep -q 'validate_wg_key "\$pubkey"' \
    && echo "$wg_deb_import_full_body" | grep -q 'validate_wg_key "\$psk"' \
    && pass "N7: Debian WG 导入校验 name/ip/allowed/lans/keys" \
    || fail "N7: Debian WG 导入未完整校验 name/ip/allowed/lans/keys"

echo ""
echo "== review #28 第二轮审计工作区/测试环境回归 =="
# N9: smoke 测试自身要强制 UTF-8 locale，避免 C/POSIX 下中文 UTF-8 字节被线框字符 grep 误命中。
if head -20 "$0" | grep -q 'export LC_ALL=.*UTF-8'; then
    pass "N9: smoke_p0p1p2 开头显式设置 UTF-8 locale"
else
    fail "N9: smoke_p0p1p2 未在脚本开头设置 UTF-8 locale"
fi

# N8: 可执行脚本/项目文档在工作区保持 LF，避免 scp 到 VPS 后出现 $'\\r'。
crlf_files=$(
    if command -v perl >/dev/null 2>&1; then
        {
            printf '%s\0' build.sh CHANGELOG.md README.md dist/v4-built.sh
            find modules tests docs -type f \( -name '*.sh' -o -name '*.md' \) -print0
        } | while IFS= read -r -d '' _crlf_file; do
            [[ -f "$_crlf_file" ]] || continue
            if perl -ne 'if (/\r/) { $found=1; last } END { exit($found ? 0 : 1) }' "$_crlf_file"; then
                printf '%s\n' "$_crlf_file"
            fi
        done
    fi
)
if [[ -z "$crlf_files" ]]; then
    pass "N8: 工作区关键 sh/md 文件无 CRLF"
else
    fail "N8: 工作区仍有 CRLF 文件"
    echo "$crlf_files" | sed 's/^/    /' | head -20
fi

integration_example="${ROOT:-.}/docs/integration-example.sh"
if [[ -f "$integration_example" ]] \
   && bash "$integration_example" 2>/dev/null | grep -q 'documentation example' \
   && bash -c 'source "$1"; echo sourced-ok' _ "$integration_example" 2>/dev/null | grep -qx 'sourced-ok'; then
    pass "N8: docs/integration-example.sh 执行/source 均为无副作用文档示例"
else
    fail "N8: docs/integration-example.sh 仍可能被误执行到示例副作用"
fi

echo ""
echo "== review #29 第二轮审计 Web gawk 替换回归 =="
# N10: gawk 的 sub() replacement 会展开 &；反代后端替换应通过拼接 substr 保留字面量。
if declare -F _replace_proxy_pass_backend >/dev/null; then
    proxy_tmp=$(mktemp)
    printf '    proxy_pass http://old.example;\n' > "$proxy_tmp"
    proxy_out=$(_replace_proxy_pass_backend 'http://127.0.0.1:8080/a&b' "$proxy_tmp")
    rm -f "$proxy_tmp"
    if grep -Fxq '    proxy_pass http://127.0.0.1:8080/a&b;' <<< "$proxy_out"; then
        pass "N10: proxy_pass helper 保留 & 字面量"
    else
        fail "N10: proxy_pass helper 未保留 & 字面量"
        echo "$proxy_out" | sed 's/^/    /'
    fi
else
    fail "N10: 缺少 proxy_pass 安全替换 helper"
fi
if echo "$web_edit_proxy_body" | grep -q 'sub(/proxy_pass.*new_backend_escaped'; then
    fail "N10: web_edit_reverse_proxy 仍依赖 awk sub replacement 转义"
else
    pass "N10: web_edit_reverse_proxy 不再依赖 awk sub replacement 转义"
fi

echo ""
echo "== review #30 第二轮审计剩余高优先回归 =="
# R1: Reality 初次安装不能先直写最终 sing-box 配置；应复用原子校验/回滚 apply helper。
reality_install_landing_body=$(awk '/^reality_install_landing\(\)/,/^reality_realm_arch\(\)/' "$BUILT")
echo "$reality_install_landing_body" | grep -q 'reality_apply_singbox_config "\$new_config"' \
    && pass "R1: Reality 安装路径复用 apply helper" \
    || fail "R1: Reality 安装路径未复用 apply helper"
if echo "$reality_install_landing_body" | grep -q '> "\$REALITY_SINGBOX_CONFIG"'; then
    fail "R1: Reality 安装仍直写最终 sing-box 配置"
else
    pass "R1: Reality 安装不直写最终 sing-box 配置"
fi
if echo "$reality_install_landing_body" | grep -q 'sing-box check -c "\$REALITY_SINGBOX_CONFIG"'; then
    fail "R1: Reality 安装仍直接校验最终 sing-box 配置"
else
    pass "R1: Reality 安装不直接校验最终 sing-box 配置"
fi

# G10 漏项：输出给 OpenWrt 用户执行的部署命令也不能使用 BusyBox sed 不兼容的多行 i\ 插入。
wg_openwrt_deploy_body=$(awk '/^_wg_show_openwrt_deploy\(\)/,/^wg_setup_watchdog\(\)/' "$BUILT")
wg_openwrt_endpoint_migrate_body=$(awk '/^wg_show_openwrt_endpoint_migrate_cmd\(\)/,0' "$BUILT")
if echo "$wg_openwrt_deploy_body" | grep -q 'sed -i "/\^exit 0/i'; then
    fail "G10: OpenWrt 部署命令仍用 BusyBox 不兼容 sed 多行插入"
else
    pass "G10: OpenWrt 部署命令不再用 sed 多行插入"
fi
echo "$wg_openwrt_deploy_body" | grep -q 'WG_RC_BLOCK=' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'FNR == NR { block = block \\\$0 ORS; next }' \
    && echo "$wg_openwrt_deploy_body" | grep -q '\[\[:space:\]\]\*exit' \
    && pass "G10: OpenWrt 部署命令使用 awk/临时文件兼容插入 rc.local" \
    || fail "G10: OpenWrt 部署命令缺少兼容 rc.local 插入逻辑"
if echo "$wg_openwrt_deploy_body" | grep -q 'ip rule.*prio 100/d'; then
    fail "G10: OpenWrt 部署命令仍会从 rc.local 粗暴删除第三方 prio 100 规则"
else
    pass "G10: OpenWrt 部署命令不再从 rc.local 粗暴删除 prio 100 规则"
fi
echo "$wg_openwrt_deploy_body" | grep -q 'BEGIN server-manage wireguard bypass' \
    && echo "$wg_openwrt_deploy_body" | grep -q '^wg_rc_local_cleanup_managed()' \
    && pass "G10: OpenWrt 部署命令使用托管标记清理 rc.local" \
    || fail "G10: OpenWrt 部署命令缺少托管标记 rc.local 清理"
echo "$wg_openwrt_deploy_body" | grep -q '^wg_resolve_real()' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'EP_IP=\$(wg_resolve_real' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_EP=\$(wg_resolve_real' \
    && ! echo "$wg_openwrt_deploy_body" | grep -Fq "awk '/^Address:/{a=" \
    && pass "G10: OpenWrt 部署命令使用兼容 BusyBox/fake-ip 的 endpoint 解析 helper" \
    || fail "G10: OpenWrt 部署命令仍可能误解析 endpoint DNS 输出"
echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_RC_TMP="\$(mktemp /etc/.rc.local.XXXXXX' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'mv "\$WG_RC_TMP" /etc/rc.local' \
    && pass "G10: OpenWrt 部署命令原子替换 rc.local" \
    || fail "G10: OpenWrt 部署命令仍可能非原子覆盖 rc.local"
echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_RC_BLOCK="\$(mktemp /etc/.wg-rc-block.XXXXXX' \
    && ! echo "$wg_openwrt_deploy_body" | grep -Eq '\|\| echo [^[:space:]]*\$\$' \
    && pass "G10: OpenWrt 部署命令临时文件无可预测 fallback" \
    || fail "G10: OpenWrt 部署命令仍有可预测临时文件 fallback"
if { echo "$wg_openwrt_deploy_body" | grep -Fq 'die() { echo "[!] $*" >&2; exit 1; }' \
     || echo "$wg_openwrt_deploy_body" | grep -Fq 'die() { echo "[!] \$*" >&2; exit 1; }'; } \
   && echo "$wg_openwrt_deploy_body" | grep -Fq '|| die_restore "写入 WireGuard UCI 配置失败"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'die_restore "安装 wg-client init 失败"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'ifup wg0 || die_restore "启动 wg0 失败"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'die_restore "安装 wg-watchdog 失败"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq '|| die_restore "安装 wg-watchdog cron 失败"'; then
    pass "G10: OpenWrt 部署命令关键步骤失败即中止"
else
    fail "G10: OpenWrt 部署命令关键步骤仍可能静默失败"
fi
if echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_UCI_SNAPSHOT_DIR="\$(mktemp -d /tmp/server-manage-wg-deploy-uci.XXXXXX' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'uci export network > "\$WG_UCI_SNAPSHOT_DIR/network.uci"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'uci export firewall > "\$WG_UCI_SNAPSHOT_DIR/firewall.uci"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'uci import network < "\$WG_UCI_SNAPSHOT_DIR/network.uci"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'uci import firewall < "\$WG_UCI_SNAPSHOT_DIR/firewall.uci"' \
   && printf '%s\n' "$wg_openwrt_deploy_body" | awk 'index($0, "WG_UCI_SNAPSHOT_DIR=") && index($0, "server-manage-wg-deploy-uci.XXXXXX") { snap=NR } /while uci -q get network\.@wireguard_wg0\[0\]/ { clean=NR } END { exit !(snap > 0 && clean > 0 && snap < clean) }' \
   && echo "$wg_openwrt_deploy_body" | grep -q '^write_wg_uci()' \
   && echo "$wg_openwrt_deploy_body" | grep -q '^[[:space:]]*restore_wg_uci()' \
   && ! echo "$wg_openwrt_deploy_body" | grep -q 'set -e'; then
    pass "G10: OpenWrt 部署命令 UCI 写入具备快照恢复且不依赖 set -e"
else
    fail "G10: OpenWrt 部署命令 UCI 写入缺少快照恢复或仍依赖 set -e"
fi
echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_CLIENT_TMP="\$(mktemp /etc/init.d/.wg-client.XXXXXX' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'mv "\$WG_CLIENT_TMP" /etc/init.d/wg-client' \
    && pass "G10: OpenWrt 部署命令原子安装 wg-client init 脚本" \
    || fail "G10: OpenWrt 部署命令仍直接覆盖 wg-client init 脚本"
echo "$wg_openwrt_deploy_body" | grep -Fq 'WG_WATCHDOG_TMP="$(mktemp /usr/bin/.wg-watchdog.XXXXXX' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'mv "$WG_WATCHDOG_TMP" /usr/bin/wg-watchdog.sh' \
    && pass "G10: OpenWrt 部署命令原子安装 wg-watchdog 脚本" \
    || fail "G10: OpenWrt 部署命令仍直接覆盖 wg-watchdog 脚本"
if echo "$wg_openwrt_deploy_body" | grep -Fq 'LOG_DIR="/var/run/server-manage"' \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX"' \
   && ! echo "$wg_openwrt_deploy_body" | grep -Fq 'LOG_FILE="/tmp/wg-watchdog.log"' \
   && ! echo "$wg_openwrt_deploy_body" | grep -Fq '${LOG_FILE}.tmp'; then
    pass "G10: OpenWrt watchdog 日志不再使用公共 /tmp 固定文件"
else
    fail "G10: OpenWrt watchdog 日志仍可能使用公共 /tmp 固定文件"
fi
if echo "$wg_openwrt_deploy_body" | grep -Eq 'cat "\$WG_RC_[A-Z_]*" > /etc/rc.local|cat > /etc/init.d/wg-client|cat > /usr/bin/wg-watchdog.sh'; then
    fail "G10: OpenWrt 部署命令残留直接覆盖系统脚本"
else
    pass "G10: OpenWrt 部署命令无直接覆盖系统脚本残留"
fi

# P6: Web/CF 公网 IP 探测结果必须经过 validate_ip 后才能写 DNS，不能把劫持页/错误页当 A/AAAA 记录。
echo "$cf_dns_body" | grep -q 'get_public_ipv4' \
    && echo "$cf_dns_body" | grep -q 'get_public_ipv6' \
    && pass "P6: Cloudflare DNS 使用统一公网 IP helper" \
    || fail "P6: Cloudflare DNS 仍使用裸 curl 探测公网 IP"
echo "$cf_dns_body" | grep -q 'validate_ip "\$ipv4"' \
    && echo "$cf_dns_body" | grep -q 'validate_ip "\$ipv6"' \
    && pass "P6: Cloudflare DNS 校验探测到的公网 IP" \
    || fail "P6: Cloudflare DNS 未校验探测到的公网 IP"
echo "$cf_dns_body" | grep -q '仅 IPv4 模式未检测到 IPv4' \
    && echo "$cf_dns_body" | grep -q '仅 IPv6 模式未检测到 IPv6' \
    && echo "$cf_dns_body" | grep -q '双栈解析需要同时检测到 IPv4 和 IPv6' \
    && pass "P6: Cloudflare DNS 选择缺失地址族时中止" \
    || fail "P6: Cloudflare DNS 缺失所选地址族仍可能继续"
echo "$web_add_body" | grep -q 'get_public_ipv4' \
    && echo "$web_add_body" | grep -q 'get_public_ipv6' \
    && pass "P6: 添加 Web 域名使用统一公网 IP helper" \
    || fail "P6: 添加 Web 域名仍使用裸 curl 探测公网 IP"
echo "$web_add_body" | grep -q 'validate_ip "\$ipv4"' \
    && echo "$web_add_body" | grep -q 'validate_ip "\$ipv6"' \
    && pass "P6: 添加 Web 域名校验探测到的公网 IP" \
    || fail "P6: 添加 Web 域名未校验探测到的公网 IP"

echo ""
echo "== review #33 Reality/Docker 剩余回归 =="
reality_delete_body=$(awk '/^reality_delete_node_info\(\)/,/^reality_uninstall\(\)/' "$BUILT")
reality_verify_sni_body=$(awk '/^reality_verify_sni\(\)/,/^reality_pick_sni_candidates\(\)/' "$BUILT")
reality_install_singbox_body=$(awk '/^reality_install_singbox_official\(\)/,/^reality_verify_sni\(\)/' "$BUILT")
sagernet_helpers_body=$(awk '/^_reality_sagernet_keyring_path\(\)/,/^reality_install_singbox_official\(\)/' "$BUILT")
reality_realm_install_body=$(awk '/^reality_install_realm_binary\(\)/,/^reality_install_relay\(\)/' "$BUILT")
reality_realm_binary_helper_body=$(awk '/^_reality_install_realm_binary_file\(\)/,/^reality_install_singbox_official\(\)/' "$BUILT")
reality_realm_service_body=$(awk '/^reality_relay_ensure_service\(\)/,/^reality_relay_migrate_legacy\(\)/' "$BUILT")
realm_service_helpers_body=$(awk '/^_reality_realm_service_path\(\)/,/^reality_install_singbox_official\(\)/' "$BUILT")
reality_diag_body=$(awk '/^reality_diagnose\(\)/,/^reality_sync_dns_menu\(\)/' "$BUILT")
docker_uninstall_body=$(awk '/^docker_uninstall\(\)/,/^_docker_compose_standalone_arch\(\)/' "$BUILT")
docker_compose_standalone_body=$(awk '/^_docker_compose_install_standalone\(\)/,/^docker_compose_install\(\)/' "$BUILT")
docker_compose_body=$(awk '/^docker_compose_install\(\)/,/^docker_proxy_config\(\)/' "$BUILT")
docker_proxy_helper_body=$(awk '/^_docker_systemd_reload_restart\(\)/,/^docker_compose_install\(\)/' "$BUILT")
docker_proxy_config_body=$(awk '/^docker_proxy_config\(\)/,/^docker_images_manage\(\)/' "$BUILT")
docker_images_body=$(awk '/^docker_images_manage\(\)/,/^docker_print_stats_table\(\)/' "$BUILT")
docker_containers_body=$(awk '/^docker_containers_manage\(\)/,/^menu_docker\(\)/' "$BUILT")

grep -q '^firewall_remove_reality_ports()' "$BUILT" \
    && echo "$reality_delete_body" | grep -q 'firewall_remove_reality_ports' \
    && pass "R2: 删除 Reality/Realm 节点会回收 UFW 端口规则" \
    || fail "R2: 删除 Reality/Realm 节点未回收 UFW 端口规则"
if echo "$reality_delete_body" | grep -q 'rm -rf "\$REALITY_CONFIG_DIR"'; then
    fail "R3: 删除节点仍会 rm -rf 整个 REALITY_CONFIG_DIR 导致备份目录自删"
else
    pass "R3: 删除节点不再自删备份目录"
fi
echo "$reality_verify_sni_body" | grep -q -- '-verify_return_error' \
    && pass "R4: SNI 校验启用 verify_return_error" \
    || fail "R4: SNI 校验未启用 verify_return_error"
if echo "$reality_verify_sni_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/reality-sni-check.XXXXXX"' \
   && echo "$reality_verify_sni_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$reality_verify_sni_body" | grep -q 'chmod 600 "\$REALITY_SNI_CHECK_LOG"' \
   && ! echo "$reality_verify_sni_body" | grep -q 'mktemp /tmp/reality-sni-check'; then
    pass "R4: SNI 校验日志使用私有 0700 临时目录"
else
    fail "R4: SNI 校验日志仍可能落公共 /tmp"
fi
echo "$reality_realm_install_body" | grep -q 'reality_verify_sha256_file' \
    && grep -q '^reality_verify_sha256_file()' "$BUILT" \
    && grep -q 'sha256sum -c' "$BUILT" \
    && pass "R5: Realm 下载后执行 sha256 校验" \
    || fail "R5: Realm 下载缺少 sha256 校验"
if echo "$reality_realm_install_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/server-manage-realm.XXXXXX"' \
   && echo "$reality_realm_install_body" | grep -q 'chmod 700 "\$tmp"' \
   && echo "$reality_realm_install_body" | grep -q 'umask 077' \
   && ! echo "$reality_realm_install_body" | grep -q 'tmp=\$(mktemp -d)'; then
    pass "R5: Realm 下载解包使用私有 0700 临时目录"
else
    fail "R5: Realm 下载解包仍可能使用裸临时目录"
fi
if echo "$reality_realm_install_body" | grep -q '_reality_install_realm_binary_file "$bin" "$(_reality_realm_bin_path)"' \
   && echo "$reality_realm_binary_helper_body" | grep -q 'mktemp "\${dir}/.tmp.server-manage.realm.XXXXXX"' \
   && echo "$reality_realm_binary_helper_body" | grep -q 'mv "\$tmp_bin" "\$target"' \
   && ! echo "$reality_realm_install_body" | grep -q 'install -m 0755 "\$bin" /usr/local/bin/realm'; then
    pass "R5: Realm 二进制通过同目录候选文件原子安装"
else
    fail "R5: Realm 二进制仍可能非原子安装到 /usr/local/bin/realm"
fi
echo "$reality_install_singbox_body" | grep -q '_reality_install_sagernet_keyring' \
    && echo "$reality_install_singbox_body" | grep -q '_reality_write_sagernet_source' \
    && pass "R5b: sing-box 官方源安装走 SagerNet 原子写入 helper" \
    || fail "R5b: sing-box 官方源安装未走 SagerNet 原子写入 helper"
if echo "$reality_install_singbox_body" | grep -Eq '(/etc/apt/keyrings/sagernet\.asc|/etc/apt/sources\.list\.d/sagernet\.sources)|cat > /etc/apt|curl .* -o /etc/apt'; then
    fail "R5b: sing-box 官方源安装仍直写 /etc/apt 路径"
else
    pass "R5b: sing-box 官方源安装不直写 /etc/apt 路径"
fi
echo "$sagernet_helpers_body" | grep -q 'write_file_atomic "\$source_file" "\$content"' \
    && echo "$sagernet_helpers_body" | grep -q 'chmod 644 "\$source_file"' \
    && pass "R5b: SagerNet sources 文件使用原子写入并固定 0644" \
    || fail "R5b: SagerNet sources 文件缺少原子写入或 0644"
echo "$sagernet_helpers_body" | grep -q 'mktemp "\${dir}/.tmp.server-manage.sagernet-key' \
    && echo "$sagernet_helpers_body" | grep -q 'mv "\$tmp_key" "\$keyring"' \
    && pass "R5b: SagerNet keyring 下载到同目录临时文件后原子替换" \
    || fail "R5b: SagerNet keyring 未使用同目录临时文件原子替换"
echo "$reality_realm_service_body" | grep -q '_reality_install_realm_service_unit' \
    && pass "R5c: realm.service 安装走 service unit helper" \
    || fail "R5c: realm.service 安装未走 service unit helper"
if echo "$reality_realm_service_body" | grep -q 'cat > /etc/systemd/system/realm.service'; then
    fail "R5c: reality_relay_ensure_service 仍直写 realm.service"
else
    pass "R5c: reality_relay_ensure_service 不直写 realm.service"
fi
echo "$realm_service_helpers_body" | grep -q 'write_file_atomic "\$service_file" "\$content"' \
    && echo "$realm_service_helpers_body" | grep -q 'ExecStart=\$realm_bin -c \$realm_config' \
    && echo "$realm_service_helpers_body" | grep -q 'type -P realm' \
    && pass "R5c: realm.service unit 原子写入并使用解析后的 realm 路径" \
    || fail "R5c: realm.service unit 缺少原子写入或动态 ExecStart"
if echo "$reality_delete_body" | grep -q 'rm -f /etc/systemd/system/realm.service'; then
    fail "R5c: 删除 Reality 节点仍硬编码删除 realm.service"
else
    pass "R5c: 删除 Reality 节点通过路径 helper 删除 realm.service"
fi
printf '%s\n%s\n' "$docker_compose_body" "$docker_compose_standalone_body" | grep -q 'sha256sum -c' \
    && pass "R5: Docker Compose standalone 下载后执行 sha256 校验" \
    || fail "R5: Docker Compose standalone 下载缺少 sha256 校验"
echo "$reality_diag_body" | grep -q 'validate_port "\$REALITY_PORT"' \
    && pass "R6: Reality 诊断检查 REALITY_PORT 有效后才匹配监听/UFW" \
    || fail "R6: Reality 诊断未校验 REALITY_PORT，空端口可能假阳性"
echo "$docker_containers_body" | grep -q 'trap - INT' \
    && echo "$docker_containers_body" | grep -q "trap 'handle_interrupt' INT" \
    && pass "R7: Docker logs 临时接管 Ctrl+C，返回菜单而非杀脚本" \
    || fail "R7: Docker logs Ctrl+C 仍可能触发全局退出"
echo "$docker_uninstall_body" | grep -q 'rm -f "\$DOCKER_PROXY_CONF"' \
    && echo "$docker_uninstall_body" | grep -q 'rm -rf "\$DOCKER_PROXY_DIR"' \
    && echo "$docker_uninstall_body" | grep -q 'rm -rf /etc/docker' \
    && echo "$docker_uninstall_body" | grep -q 'hash -r' \
    && pass "R8: Docker 卸载清理代理 drop-in 与 /etc/docker" \
    || fail "R8: Docker 卸载未清理代理 drop-in 或 /etc/docker"
if echo "$docker_proxy_helper_body" | grep -q '^_docker_apply_proxy_conf()' \
   && echo "$docker_proxy_helper_body" | grep -q '^_docker_clear_proxy_conf()' \
   && echo "$docker_proxy_helper_body" | grep -Fq '_docker_restore_proxy_conf "$backup" "$had_old"' \
   && echo "$docker_proxy_config_body" | grep -Fq '_docker_apply_proxy_conf "$proxy_conf"' \
   && echo "$docker_proxy_config_body" | grep -Fq '_docker_clear_proxy_conf' \
   && ! echo "$docker_proxy_config_body" | grep -q 'systemctl restart docker || true'; then
    pass "R8: Docker 代理配置/清除失败会走 helper 回滚且不吞 restart 失败"
else
    fail "R8: Docker 代理配置/清除仍可能吞掉 restart 失败或缺少回滚 helper"
fi
if echo "$docker_images_body" | grep -Fq 'if docker image prune -a -f; then' \
   && echo "$docker_images_body" | grep -Fq 'if docker rmi -f $all_images; then' \
   && echo "$docker_images_body" | grep -Fq '镜像清理失败。' \
   && echo "$docker_images_body" | grep -Fq '镜像删除失败。' \
   && echo "$docker_images_body" | grep -Fq 'pause; return 1'; then
    pass "R8: Docker 镜像 prune/rmi 失败会返回非 0"
else
    fail "R8: Docker 镜像 prune/rmi 失败仍可能被当作成功"
fi
coexist_reality_port_body=$(awk '/^reality_coexist_reality_port\(\)/,/^reality_coexist_web_port\(\)/' "$BUILT")
coexist_web_port_body=$(awk '/^reality_coexist_web_port\(\)/,/^reality_coexist_collect_web_domains\(\)/' "$BUILT")
if echo "$coexist_reality_port_body" | grep -q 'validate_conf_file "\$REALITY_COEXIST_STATE_FILE"' \
   && echo "$coexist_reality_port_body" | grep -q 'validate_port "\${REALITY_COEXIST_REALITY_PORT:-}"' \
   && echo "$coexist_web_port_body" | grep -q 'validate_conf_file "\$REALITY_COEXIST_STATE_FILE"' \
   && echo "$coexist_web_port_body" | grep -q 'validate_port "\${REALITY_COEXIST_WEB_PORT:-}"'; then
    pass "R9: Reality 共存端口 accessor 读取 state 前重新校验"
else
    fail "R9: Reality 共存端口 accessor 仍可能裸 source state"
fi
coexist_inject_body=$(awk '/^reality_coexist_inject_nginx_include\(\)/,/^reality_coexist_remove_nginx_include\(\)/' "$BUILT")
if echo "$coexist_inject_body" | grep -q '.tmp.server-manage.nginx-stream-include' \
   && echo "$coexist_inject_body" | grep -q 'cat "\$main_conf" > "\$tmp"' \
   && echo "$coexist_inject_body" | grep -q 'mv "\$tmp" "\$main_conf"' \
   && ! echo "$coexist_inject_body" | grep -q 'cat >> "\$main_conf"'; then
    pass "R10: Reality 共存 nginx include 注入通过同目录候选文件原子替换"
else
    fail "R10: Reality 共存 nginx include 注入仍可能直接追加 nginx.conf"
fi
web_add_domain_body=$(awk '/^web_add_domain\(\)/,/^web_domain_menu\(\)/' "$BUILT")
web_home_body=$(awk '/^web_home_expose\(\)/,/^docker_install\(\)/' "$BUILT")
web_proxy_body=$(awk '/^web_add_reverse_proxy\(\)/,/^web_edit_reverse_proxy\(\)/' "$BUILT")
reality_cdn_install_body=$(awk '/^reality_cdn_install\(\)/,/^reality_cdn_status\(\)/' "$BUILT")
if echo "$reality_cdn_install_body" | grep -Fq 'firewall_allow_tcp_port "$origin_port" "CDN-origin"' \
   && echo "$reality_cdn_install_body" | grep -Fq 'fw_rc=$?' \
   && echo "$reality_cdn_install_body" | grep -Fq 'pause; return 1' \
   && ! echo "$reality_cdn_install_body" | grep -q 'ufw allow "\${origin_port}/tcp".*|| true'; then
    pass "R12: Reality CDN 回源端口放行失败会返回非 0"
else
    fail "R12: Reality CDN 回源端口仍可能吞掉 UFW 放行失败"
fi
if grep -q '^reality_cdn_install_rollback()' "$BUILT" \
   && echo "$reality_cdn_install_body" | grep -Fq 'if ! reality_cdn_sync_dns_orange "$cdn_domain" "$cf_token"; then' \
   && echo "$reality_cdn_install_body" | grep -Fq 'if ! reality_cdn_apply_origin_rule "$cdn_domain" "$cf_token" "$origin_port"; then' \
   && echo "$reality_cdn_install_body" | grep -Fq 'if ! reality_cdn_write_client_artifacts; then' \
   && echo "$reality_cdn_install_body" | grep -Fq 'reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state"' \
   && ! echo "$reality_cdn_install_body" | grep -Fq 'reality_cdn_sync_dns_orange "$cdn_domain" "$cf_token" || print_warn' \
   && ! echo "$reality_cdn_install_body" | grep -Fq 'reality_cdn_apply_origin_rule "$cdn_domain" "$cf_token" "$origin_port" ||' \
   && ! echo "$reality_cdn_install_body" | grep -Fq 'reality_cdn_write_client_artifacts || true'; then
    pass "R12b: Reality CDN DNS/Origin/产物失败会 fail-closed 并回滚"
else
    fail "R12b: Reality CDN 关键失败仍可能 warn-only 或保留半成品"
fi
reality_cdn_rollback_body=$(awk '/^reality_cdn_install_rollback\(\)/,/^reality_cdn_render_nginx_conf\(\)/' "$BUILT")
reality_cdn_cert_cleanup_body=$(awk '/^reality_cdn_cleanup_cert_resources\(\)/,/^reality_cdn_remove_nginx_conf\(\)/' "$BUILT")
if grep -q '^reality_cdn_cleanup_cert_resources()' "$BUILT" \
   && grep -q '^reality_cdn_cf_cred_path()' "$BUILT" \
   && grep -q '^reality_cdn_le_live_dir()' "$BUILT" \
   && echo "$reality_cdn_rollback_body" | grep -Fq 'reality_cdn_cleanup_cert_resources "$cdn_domain"' \
   && echo "$reality_cdn_install_body" | grep -Fq 'cert_snapshot_dir=$(mktemp -d "${REALITY_CONFIG_DIR%/}/.cdn-cert-rollback.XXXXXX")' \
   && echo "$reality_cdn_install_body" | grep -Fq 'reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"' \
   && echo "$reality_cdn_cert_cleanup_body" | grep -Fq 'cron_remove_job "CertRenew_${domain}"' \
   && echo "$reality_cdn_cert_cleanup_body" | grep -Fq 'rm -f "$cred_path"' \
   && echo "$reality_cdn_cert_cleanup_body" | grep -Fq 'rm -f "$hook_path"' \
   && echo "$reality_cdn_cert_cleanup_body" | grep -Fq 'rm -rf "$cert_dir"' \
   && echo "$reality_cdn_cert_cleanup_body" | grep -Fq 'certbot delete --cert-name "$domain" --non-interactive'; then
    pass "R12d: Reality CDN 安装失败会清理/恢复证书凭据 hook cron 半成品"
else
    fail "R12d: Reality CDN 安装失败仍可能残留证书凭据或续签任务"
fi
reality_cdn_origin_body=$(awk '/^reality_cdn_apply_origin_rule\(\)/,/^reality_build_vless_link\(\)/' "$BUILT")
if echo "$reality_cdn_origin_body" | grep -Fq 'if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then' \
   && echo "$reality_cdn_origin_body" | grep -q '读取现有规则失败' \
   && ! echo "$reality_cdn_origin_body" | grep -q '_cf_get_origin_ruleset "\$token" "\$zone_id").*|| true' \
   && ! echo "$reality_cdn_origin_body" | grep -q '|| echo "\[\]"'; then
    pass "R12c: Reality CDN Origin Rules 读取失败会 fail-closed"
else
    fail "R12c: Reality CDN Origin Rules 读取失败仍可能按空规则覆盖"
fi
reality_cdn_dns_body=$(awk '/^reality_cdn_sync_dns_orange\(\)/,/^reality_cdn_apply_origin_rule\(\)/' "$BUILT")
if echo "$reality_cdn_dns_body" | grep -Fq 'reality_cf_delete_dns_type "$domain" "$token" "A" "$zone_id"' \
   && echo "$reality_cdn_dns_body" | grep -Fq 'reality_cf_delete_dns_type "$domain" "$token" "AAAA" "$zone_id"'; then
    pass "R12c: Reality CDN DNS 会清理未检测到的旧地址族"
else
    fail "R12c: Reality CDN DNS 仍可能保留旧 A/AAAA 地址族"
fi
reality_cf_list_zones_body=$(awk '/^reality_cf_list_zones\(\)/,/^reality_join_subdomain\(\)/' "$BUILT")
if echo "$reality_cf_list_zones_body" | grep -Fq '_cf_list_zones "$token"' \
   || { echo "$reality_cf_list_zones_body" | grep -q 'page=1' && echo "$reality_cf_list_zones_body" | grep -q 'page=\$page'; }; then
    pass "R12c: Reality zone 列表支持分页"
else
    fail "R12c: Reality zone 列表仍只读第一页"
fi
cert_pair_body="$web_add_domain_body
$web_home_body
$web_proxy_body
$reality_cdn_install_body"
if grep -q '^copy_cert_pair_atomic()' "$BUILT" \
   && grep -q '^render_cert_pair_hook_helper()' "$BUILT" \
	   && echo "$cert_pair_body" | grep -Fq 'copy_cert_pair_atomic "$custom_cert" "$custom_key" "$cert_dir"' \
	   && echo "$cert_pair_body" | grep -Fq 'copy_cert_pair_atomic "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "/etc/letsencrypt/live/${DOMAIN}/privkey.pem" "$cert_dir"' \
	   && echo "$cert_pair_body" | grep -Fq 'copy_cert_pair_atomic "/etc/letsencrypt/live/${full_domain}/fullchain.pem" "/etc/letsencrypt/live/${full_domain}/privkey.pem" "$cert_dir"' \
	   && echo "$cert_pair_body" | grep -Fq 'copy_cert_pair_atomic "${le_live_dir}/fullchain.pem" "${le_live_dir}/privkey.pem" "$cert_dir"' \
   && echo "$cert_pair_body" | grep -Fq '$(render_cert_pair_hook_helper)' \
   && grep -Fq 'copy_cert_pair_restore "$dest_full" "$dest_key" "$bak_full" "$bak_key" "" "$key_tmp"' "$BUILT" \
   && grep -Fq 'bak_full=$(mktemp "${dest_dir}/.bak.server-manage.fullchain.XXXXXX")' "$BUILT" \
   && grep -Fq 'bak_key=$(mktemp "${dest_dir}/.bak.server-manage.privkey.XXXXXX")' "$BUILT" \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L "$custom_cert" "$cert_dir/fullchain.pem"' \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" "$cert_dir/fullchain.pem"' \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L "/etc/letsencrypt/live/${full_domain}/fullchain.pem" "$cert_dir/fullchain.pem"' \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L "/etc/letsencrypt/live/${cdn_domain}/fullchain.pem" "$cert_dir/fullchain.pem"' \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L \"\${LETSENCRYPT_LIVE}/fullchain.pem\" \"\${CERT_DIR}/fullchain.pem\"' \
   && ! echo "$cert_pair_body" | grep -Fq 'cp -L \"\$LIVE/fullchain.pem\" \"${cert_dir}/fullchain.pem\"'; then
    pass "R11: Web/Reality 证书对复制通过同目录临时文件原子落地"
else
    fail "R11: Web/Reality 证书对仍可能直接复制到最终 fullchain/privkey"
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
if printf '%s\n%s\n' "$docker_install_body" "$docker_install_helpers_body" | grep -q 'docker_repo_os' \
   && printf '%s\n%s\n' "$docker_install_body" "$docker_install_helpers_body" | grep -q 'download.docker.com/linux/${docker_repo_os}'; then
    pass "Docker: GPG URL 与 apt source 使用同一官方 repo OS"
else
    fail "Docker: 非 Debian/Ubuntu fallback 仍可能 GPG/source OS 不一致"
fi
if echo "$docker_install_body" | grep -q '> "\$docker_list"' \
   || echo "$docker_install_body" | grep -q 'echo "deb .*docker_list'; then
    fail "Docker: apt source 仍可能直写最终 docker.list"
else
    pass "Docker: apt source 通过 helper 原子写入"
fi
if echo "$docker_install_helpers_body" | grep -q 'write_file_atomic "\$docker_list" "\$content"' \
   && echo "$docker_install_helpers_body" | grep -q 'mktemp "\${dir}/.tmp.server-manage.docker-gpg' \
   && ! echo "$docker_install_helpers_body" | grep -q 'gpg --dearmor -o "\$docker_gpg"'; then
    pass "Docker: GPG keyring/source helper 使用同目录候选文件"
else
    fail "Docker: GPG keyring/source helper 缺少同目录候选文件或原子写入"
fi
if echo "$docker_compose_standalone_body" | grep -q 'mktemp "\${target_dir}/.tmp.server-manage.docker-compose' \
   && echo "$docker_compose_standalone_body" | grep -q 'mv "\$tmp_bin" "\$target_bin"' \
   && ! echo "$docker_compose_standalone_body" | grep -q 'mktemp /tmp/docker-compose' \
   && ! echo "$docker_compose_body" | grep -q 'install -m 0755 "\$tmp_bin" /usr/local/bin/docker-compose'; then
    pass "Docker: Compose standalone 使用同目录校验后原子替换"
else
    fail "Docker: Compose standalone 仍可能使用公共 /tmp 或非原子安装"
fi
if echo "$docker_body" | grep -q '\[\[ -n "\$rq" \]\] && docker stop \$rq && print_success "已停止" || print_warn "无运行中容器"' \
   || echo "$docker_body" | grep -q '\[\[ -n "\$aq" \]\] && docker rm -f \$aq && print_success "已删除" || print_warn "无容器"'; then
    fail "Docker: 停止/删除所有仍用 A&&B||C 链，失败提示可能失真"
else
    pass "Docker: 停止/删除所有使用显式分支区分无容器与操作失败"
fi
docker_stop_success_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "print_success \"已停止\"") {print NR; exit}')
docker_stop_log_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "log_action \"Docker all containers stopped\"") {print NR; exit}')
docker_stop_error_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "print_error \"停止失败\"") {print NR; exit}')
docker_remove_success_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "print_success \"已删除\"") {print NR; exit}')
docker_remove_log_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "log_action \"Docker all containers removed\"") {print NR; exit}')
docker_remove_error_line=$(printf '%s\n' "$docker_containers_body" | awk 'index($0, "print_error \"删除失败\"") {print NR; exit}')
if [[ -n "$docker_stop_success_line" && -n "$docker_stop_log_line" && -n "$docker_stop_error_line" \
      && -n "$docker_remove_success_line" && -n "$docker_remove_log_line" && -n "$docker_remove_error_line" \
      && "$docker_stop_success_line" -lt "$docker_stop_log_line" && "$docker_stop_log_line" -lt "$docker_stop_error_line" \
      && "$docker_remove_success_line" -lt "$docker_remove_log_line" && "$docker_remove_log_line" -lt "$docker_remove_error_line" ]]; then
    pass "Docker: 批量容器操作只在成功分支写成功日志"
else
    fail "Docker: 批量容器操作失败时仍可能写成功日志"
fi
docker_menu_body=$(awk '/^menu_docker\(\)/,0' "$BUILT")
if echo "$docker_menu_body" | grep -Fq 'if docker system prune -a -f --volumes; then' \
   && echo "$docker_menu_body" | grep -Fq 'print_error "清理失败。"' \
   && echo "$docker_menu_body" | grep -Fq 'log_action "Docker system pruned"'; then
    pass "Docker: system prune 失败不会无条件提示成功"
else
    fail "Docker: system prune 失败仍可能被当作成功"
fi

echo ""
echo "== review #34 剩余安全/稳定性回归 =="
menu_update_body=$(awk '/^menu_update\(\)/,/^}/' "$BUILT")
ufw_setup_body=$(awk '/^ufw_setup\(\)/,/^}/' "$BUILT")
ufw_reset_body=$(awk '/^ufw_safe_reset\(\)/,/^}/' "$BUILT")
ufw_apply_ssh_body=$(awk '/^_ufw_apply_default_ssh_rules\(\)/,/^}/' "$BUILT")
geoip_update_body=$(awk '/^geoip_update\(\)/,/^}/' "$BUILT")
wg_rebuild_conf_body=$(awk '/^wg_rebuild_conf\(\)/,/^}/' "$BUILT")
wg_deb_rebuild_conf_body=$(awk '/^wg_deb_rebuild_conf\(\)/,/^}/' "$BUILT")
wg_deb_apply_conf_body=$(awk '/^wg_deb_apply_conf\(\)/,/^}/' "$BUILT")
wg_deb_add_full_body=$(awk '/^wg_deb_add_peer\(\)/,/^_wg_deb_update_peer_routes\(\)/' "$BUILT")
wg_deb_toggle_body=$(awk '/^wg_deb_toggle_peer\(\)/,/^wg_deb_delete_peer\(\)/' "$BUILT")
wg_deb_delete_body=$(awk '/^wg_deb_delete_peer\(\)/,/^wg_deb_show_peer_conf\(\)/' "$BUILT")
sysinfo_body=$(awk '/^show_dual_column_sysinfo\(\)/,/^}/' "$BUILT")
net_iperf_body=$(awk '/^net_iperf3\(\)/,/^}/' "$BUILT")
net_dns_body=$(awk '/^net_dns\(\)/,/^}/' "$BUILT")

# S5: geoip_update 必须检查 _geoip_apply 返回值，否则下载成功但规则加载失败仍会误报完成。
echo "$geoip_update_body" | grep -q 'if ! _geoip_apply "\$GEOIP_MODE" "\$GEOIP_COUNTRIES"' \
    && pass "S5: geoip_update 检查 _geoip_apply 返回值" \
    || fail "S5: geoip_update 未检查 _geoip_apply 返回值"

# S6: 手动依赖修复也要记录本次是否新装 fail2ban，避免引用未赋值变量且无法停掉默认 jail。
echo "$menu_update_body" | grep -q 'local f2b_newly_installed=0' \
    && echo "$menu_update_body" | grep -q '\[\[ "\$pkg" == "fail2ban" \]\] && f2b_newly_installed=1' \
    && pass "S6: menu_update 正确跟踪本次新装 fail2ban" \
    || fail "S6: menu_update 未跟踪 f2b_newly_installed"

# S7: 多 Port sshd 要保留全部 SSH 监听端口，UFW setup/reset 不能只放行第一个。
ssh_multi_tmp=$(mktemp)
cat > "$ssh_multi_tmp" <<'EOF_SSH_MULTI'
Port 22
Port 22222
EOF_SSH_MULTI
_old_sshd_config="$SSHD_CONFIG"
SSHD_CONFIG="$ssh_multi_tmp"
CURRENT_SSH_PORT=""
CURRENT_SSH_PORTS=""
# 本机可能装有 sshd → refresh_ssh_port 会优先用 sshd -T 读真实系统配置；
# 此处要验证“从 SSHD_CONFIG 解析多端口”的回退路径，故临时 stub sshd 使其无输出以强制回退。
sshd() { return 1; }
refresh_ssh_port
unset -f sshd
SSHD_CONFIG="$_old_sshd_config"
if [[ "$CURRENT_SSH_PORT" == "22" && "$CURRENT_SSH_PORTS" == *"22"* && "$CURRENT_SSH_PORTS" == *"22222"* ]]; then
    pass "S7: refresh_ssh_port fallback 保留多个 Port"
else
    fail "S7: refresh_ssh_port 未保留多个 Port (CURRENT_SSH_PORT=${CURRENT_SSH_PORT:-空}, CURRENT_SSH_PORTS=${CURRENT_SSH_PORTS:-空})"
fi
rm -f "$ssh_multi_tmp"
echo "$ufw_apply_ssh_body" | grep -q 'for _ssh_port in \$CURRENT_SSH_PORTS' \
    && echo "$ufw_setup_body" | grep -q '_ufw_apply_default_ssh_rules ||' \
    && echo "$ufw_reset_body" | grep -q '_ufw_apply_default_ssh_rules ||' \
    && pass "S7: UFW setup/reset 通过 helper 放行全部 SSH 端口" \
    || fail "S7: UFW setup/reset 仍可能只放行单个 SSH 端口"

# S1 补漏：没有 [sshd] jail 时不能静默返回成功。
f2b_no_sshd_tmp=$(mktemp)
cat > "$f2b_no_sshd_tmp" <<'EOF_F2B_NO_SSHD'
[nginx-http-auth]
enabled = true
port = http,https
EOF_F2B_NO_SSHD
if _fail2ban_set_sshd_port "$f2b_no_sshd_tmp" "22222" >/dev/null 2>&1; then
    fail "S1: _fail2ban_set_sshd_port 未命中 [sshd] 时仍返回成功"
else
    pass "S1: _fail2ban_set_sshd_port 未命中 [sshd] 时返回失败"
fi
rm -f "$f2b_no_sshd_tmp"

# P5: WireGuard 服务端私钥配置必须通过私有临时文件原子替换，不能直接重定向到最终文件再 chmod。
wg_private_write_body=$(awk '/^wg_write_private_file\(\)/,/^wg_shared_db_init\(\)/' "$BUILT")
echo "$wg_private_write_body" | grep -q 'umask 077' \
    && echo "$wg_private_write_body" | grep -q 'chmod 600 "\$tmp"' \
    && echo "$wg_private_write_body" | grep -q 'mv -f "\$tmp" "\$file"' \
    && pass "P5: WireGuard 私有文件写入 helper 收紧权限并原子替换" \
    || fail "P5: WireGuard 私有文件写入 helper 缺少权限保护"
echo "$wg_rebuild_conf_body" | grep -q 'wg_write_private_file "\$WG_CONF"' \
    && ! echo "$wg_rebuild_conf_body" | grep -q '> "\$WG_CONF"' \
    && pass "P5: OpenWrt wg0.conf 通过私有原子写入" \
    || fail "P5: OpenWrt wg0.conf 仍可能直接写最终文件"
echo "$wg_deb_rebuild_conf_body" | grep -q 'wg_write_private_file "\$WG_DEB_CONF"' \
    && ! echo "$wg_deb_rebuild_conf_body" | grep -q '> "\$WG_DEB_CONF"' \
    && pass "P5: Debian wg0.conf 通过私有原子写入" \
    || fail "P5: Debian wg0.conf 仍可能直接写最终文件"
echo "$wg_deb_apply_conf_body" | grep -q 'wg_deb_regenerate_client_confs || return 1' \
    && pass "P5: Debian WireGuard 热应用检查客户端配置重建失败" \
    || fail "P5: Debian WireGuard 热应用仍可能忽略客户端配置重建失败"
if grep -q '^_wg_deb_snapshot_db()' "$BUILT" \
   && grep -q '^_wg_deb_restore_peer_snapshot()' "$BUILT" \
   && grep -q '_wg_deb_restore_peer_snapshot "\$db_snapshot" "\$conf_file"' <<< "$wg_deb_add_full_body"; then
    pass "P5: Debian 添加 peer 具备 DB 快照和失败回滚"
else
    fail "P5: Debian 添加 peer 缺少 DB 快照或失败回滚"
fi
if grep -q '_wg_deb_restore_peer_snapshot "\$db_snapshot"' <<< "$wg_deb_toggle_body" \
   && grep -q 'if ! wg_deb_db_set --argjson idx "\$target_idx" .*enabled = false' <<< "$wg_deb_toggle_body" \
   && grep -q 'if ! wg_deb_db_set --argjson idx "\$target_idx" .*enabled = true' <<< "$wg_deb_toggle_body"; then
    pass "P5: Debian peer 启停检查 DB 写入并在热应用失败时回滚"
else
    fail "P5: Debian peer 启停缺少 DB 检查或失败回滚"
fi
if grep -q '_wg_deb_restore_peer_snapshot "\$db_snapshot"' <<< "$wg_deb_delete_body" \
   && grep -q 'if ! wg_deb_db_set --argjson idx "\$target_idx" .*del(.peers' <<< "$wg_deb_delete_body" \
   && awk '
       /wg_deb_apply_conf/ && !apply { apply=NR }
       /rm -f -- "\$conf_file"/ { rm=NR }
       END { exit (apply && rm && apply < rm) ? 0 : 1 }
   ' <<< "$wg_deb_delete_body"; then
    pass "P5: Debian 删除 peer 应用成功后才删除客户端配置，失败会回滚"
else
    fail "P5: Debian 删除 peer 仍可能运行态失败后丢 DB/配置"
fi

# 12d 自定义 AllowedIPs：合法裸 IP 应允许；非法输入应保守回退 VPN 内网，不能回退全局代理。
grep -q '^validate_wg_allowed_ips()' "$BUILT" \
    && pass "WG: AllowedIPs 校验 helper 已定义" \
    || fail "WG: 缺少 AllowedIPs 校验 helper"
if declare -F validate_wg_allowed_ips >/dev/null; then
    validate_wg_allowed_ips "10.0.0.5, 192.168.1.0/24, fd00::1" \
        && pass "WG: AllowedIPs helper 接受裸 IP 与 CIDR 混合" \
        || fail "WG: AllowedIPs helper 未接受合法裸 IP/CIDR"
    if validate_wg_allowed_ips "bad;reboot"; then
        fail "WG: AllowedIPs helper 错误接受注入字符"
    else
        pass "WG: AllowedIPs helper 拒绝注入字符"
    fi
fi
echo "$wg_deb_add_body" | grep -q 'validate_wg_allowed_ips "\$client_allowed_ips"' \
    && ! echo "$wg_deb_add_body" | grep -q '回退为全局代理' \
    && pass "12d: Debian 自定义路由校验裸 IP 且非法时不回退全局代理" \
    || fail "12d: Debian 自定义路由仍拒绝裸 IP或非法时回退全局代理"

# 12c: Debian 服务端 role 必须在数据库写入成功后标记，避免半初始化状态进入菜单。
role_line=$(awk '/^wg_deb_server_install\(\)/{infn=1} infn && /wg_deb_set_role "server"/{print NR; exit}' "$BUILT")
db_line=$(awk '/^wg_deb_server_install\(\)/{infn=1} infn && /if ! wg_deb_db_set/{print NR; exit}' "$BUILT")
if [[ -n "$role_line" && -n "$db_line" && "$role_line" -gt "$db_line" ]]; then
    pass "12c: Debian 服务端 role 在 DB 写入成功后设置"
else
    fail "12c: Debian 服务端 role 仍可能先于 DB 写入成功设置"
fi
echo "$wg_deb_install_body" | grep -Eq 'local .*wg_endpoint=""' \
    && pass "12c: Debian 服务端安装 set -u 下初始化 endpoint" \
    || fail "12c: Debian 服务端安装未初始化 wg_endpoint，set -u 下可能中断"
if grep -q '^firewall_allow_udp_port()' "$BUILT" \
   && echo "$wg_deb_install_full_body" | grep -Fq 'firewall_allow_udp_port "$wg_port" "WireGuard-Debian"' \
   && echo "$wg_deb_install_full_body" | grep -Fq 'firewall_prepare_non_ufw_udp_port "$wg_port" "WireGuard-Debian"' \
   && echo "$wg_deb_install_full_body" | grep -Fq 'wg_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"' \
   && echo "$wg_deb_install_full_body" | grep -Fq '放行 WireGuard UDP 端口失败' \
   && ! echo "$wg_deb_install_full_body" | grep -q 'ufw allow "\$wg_port"/udp'; then
    pass "12c: Debian 服务端安装使用 UDP/UFW+非UFW 防火墙 helper 并传播失败"
else
    fail "12c: Debian 服务端安装仍可能吞掉 UDP 端口放行失败或未处理非 UFW 本机防火墙"
fi
install_fw_line=$(printf '%s\n' "$wg_deb_install_full_body" | awk 'index($0, "firewall_allow_udp_port \"$wg_port\" \"WireGuard-Debian\"") {print NR; exit}')
install_db_line=$(printf '%s\n' "$wg_deb_install_full_body" | awk 'index($0, "if ! wg_deb_db_set") {print NR; exit}')
if [[ -n "$install_fw_line" && -n "$install_db_line" && "$install_fw_line" -lt "$install_db_line" ]] \
   && echo "$wg_deb_install_full_body" | grep -Fq '_wg_deb_rollback_new_udp_allow "$wg_port" "$wg_udp_rule_added" "$wg_non_ufw_open_backends"' \
   && echo "$wg_deb_install_full_body" | grep -Fq '_wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added" "$wg_install_snapshot_dir" "$wg_db_existed" "$wg_role_existed" "$wg_conf_existed" "$wg_non_ufw_open_backends"'; then
    pass "12c: Debian 服务端安装先预检 UDP 端口，DB/配置失败会回滚 UFW/非UFW 新规则"
else
    fail "12c: Debian 服务端安装可能在 DB 后才放行 UDP 或失败不回滚本机防火墙规则"
fi

# G11 补漏：Debian 修改/启停/删除/路由联动的 DB 写失败不能继续假成功。
echo "$wg_deb_modify_body" | grep -q 'if ! wg_deb_db_set --argjson p' \
    && echo "$wg_deb_modify_body" | grep -q 'if ! wg_deb_db_set --arg d' \
    && echo "$wg_deb_modify_body" | grep -q 'if ! wg_deb_db_set --arg e' \
    && echo "$wg_deb_modify_body" | grep -q 'if ! wg_deb_db_set --arg l' \
    && echo "$wg_deb_modify_body" | grep -q 'if ! wg_deb_db_set --arg i' \
    && pass "G11: Debian 服务端修改检查所有 DB 写入" \
    || fail "G11: Debian 服务端修改仍有未检查 DB 写入"
echo "$wg_deb_toggle_body" | grep -q 'if ! wg_deb_db_set --argjson idx "\$target_idx"' \
    && pass "G11: Debian peer 启停检查 DB 写入" \
    || fail "G11: Debian peer 启停未检查 DB 写入"
echo "$wg_deb_delete_body" | grep -q 'if ! wg_deb_db_set --argjson idx "\$target_idx"' \
    && pass "G11: Debian peer 删除检查 DB 写入" \
    || fail "G11: Debian peer 删除未检查 DB 写入"
echo "$wg_deb_update_routes_body" | grep -q 'if ! wg_deb_db_set --argjson idx "\$_pi"' \
    && pass "G11: Debian route 联动检查 DB 写入" \
    || fail "G11: Debian route 联动未检查 DB 写入"
if echo "$wg_deb_modify_full_body" | grep -Fq 'firewall_allow_udp_port "$new_port" "WireGuard-Debian"' \
   && echo "$wg_deb_modify_full_body" | grep -Fq 'firewall_prepare_non_ufw_udp_port "$new_port" "WireGuard-Debian"' \
   && echo "$wg_deb_modify_full_body" | grep -Fq 'new_non_ufw_open_backends="$FIREWALL_UDP_OPEN_BACKENDS"' \
   && echo "$wg_deb_modify_full_body" | grep -Fq '放行新 WireGuard UDP 端口失败' \
   && grep -q '^_wg_deb_rollback_server_modify()' "$BUILT" \
   && echo "$wg_deb_modify_full_body" | grep -Fq '_wg_deb_rollback_server_modify "$server_snapshot" "$cur_port" "$new_port" "$new_udp_rule_added"' \
   && awk '/^_wg_deb_rollback_server_modify\(\)/,/^_wg_deb_rollback_server_install\(\)/' "$BUILT" | grep -Fq '_wg_deb_rollback_new_udp_allow "$new_port" "$added" "$non_ufw_backends"' \
   && ! echo "$wg_deb_modify_full_body" | grep -q 'ufw allow "\$new_port"/udp'; then
    pass "12c: Debian 服务端改端口先放行 UDP，失败/后续异常会回滚 UFW/非UFW 规则"
else
    fail "12c: Debian 服务端改端口仍可能吞掉 UDP 放行失败或残留本机防火墙规则"
fi
echo "$wg_export_body" | grep -Fq 'if ! peer_count=$(wg_db_get' \
    && echo "$wg_export_body" | grep -Fq '[[ ! "$peer_count" =~ ^[0-9]+$ ]]' \
    && echo "$wg_deb_export_body" | grep -Fq 'if ! peer_count=$(wg_deb_db_get' \
    && echo "$wg_deb_export_body" | grep -Fq '[[ ! "$peer_count" =~ ^[0-9]+$ ]]' \
    && pass "WG: 导出读取设备数量失败会返回非 0" \
    || fail "WG: 导出读取设备数量失败仍可能误判为空列表"
wg_export_success_line=$(printf '%s\n' "$wg_export_body" | awk 'index($0, "log_action \"WireGuard peers exported:") {print NR; exit}')
wg_export_fail_line=$(printf '%s\n' "$wg_export_body" | awk 'index($0, "print_error \"导出失败\"") {print NR; exit}')
wg_export_cleanup_line=$(printf '%s\n' "$wg_export_body" | awk 'index($0, "print_error \"导出失败\"") {seen=1} seen && index($0, "rm -f \"$export_file\"") {print NR; exit}')
wg_export_return_line=$(printf '%s\n' "$wg_export_body" | awk 'index($0, "print_error \"导出失败\"") {seen=1} seen && index($0, "pause; return 1") {print NR; exit}')
wg_deb_export_success_line=$(printf '%s\n' "$wg_deb_export_body" | awk 'index($0, "log_action \"WireGuard(deb) peers exported:") {print NR; exit}')
wg_deb_export_fail_line=$(printf '%s\n' "$wg_deb_export_body" | awk 'index($0, "print_error \"导出失败\"") {print NR; exit}')
wg_deb_export_cleanup_line=$(printf '%s\n' "$wg_deb_export_body" | awk 'index($0, "print_error \"导出失败\"") {seen=1} seen && index($0, "rm -f \"$export_file\"") {print NR; exit}')
wg_deb_export_return_line=$(printf '%s\n' "$wg_deb_export_body" | awk 'index($0, "print_error \"导出失败\"") {seen=1} seen && index($0, "pause; return 1") {print NR; exit}')
if [[ -n "$wg_export_success_line" && -n "$wg_export_fail_line" && -n "$wg_export_return_line" \
      && -n "$wg_export_cleanup_line" && -n "$wg_deb_export_success_line" \
      && -n "$wg_deb_export_fail_line" && -n "$wg_deb_export_cleanup_line" && -n "$wg_deb_export_return_line" \
      && "$wg_export_success_line" -lt "$wg_export_fail_line" && "$wg_export_fail_line" -lt "$wg_export_cleanup_line" \
      && "$wg_export_cleanup_line" -lt "$wg_export_return_line" \
      && "$wg_deb_export_success_line" -lt "$wg_deb_export_fail_line" && "$wg_deb_export_fail_line" -lt "$wg_deb_export_cleanup_line" \
      && "$wg_deb_export_cleanup_line" -lt "$wg_deb_export_return_line" ]]; then
    pass "WG: 导出失败不会写成功日志或残留文件"
else
    fail "WG: 导出失败仍可能写成功日志、返回成功或残留文件"
fi

# 低危补扫：03-sysinfo SSH 端口、iperf3 清理、OpenWrt DNS 接口硬编码、Reality 随机端口。
echo "$sysinfo_body" | grep -q 'refresh_ssh_port' \
    && pass "03: 系统信息复用 refresh_ssh_port" \
    || fail "03: 系统信息仍重复 grep sshd_config 取端口"
grep -q 'local ip="$1" cache_file="$2" lock_file$' "$BUILT" \
    && grep -q 'lock_file="${cache_file}.lock"' "$BUILT" \
    && pass "03: IP 归属后台刷新锁文件路径在 cache_file 赋值后生成" \
    || fail "03: IP 归属后台刷新仍可能在同一 local 赋值中生成错误锁路径"
if echo "$net_iperf_body" | grep -q 'pkill -f "iperf3 -s -p \$port"'; then
    fail "08: iPerf3 清理仍使用子串 pkill"
else
    pass "08: iPerf3 清理不再使用子串 pkill"
fi
if echo "$net_iperf_body" | grep -q 'command_exists iperf3' \
   && echo "$net_iperf_body" | grep -Fq 'jobs -pr | grep -qx "$iperf_pid"' \
   && echo "$net_iperf_body" | grep -q 'iPerf3 服务启动失败。' \
   && echo "$net_iperf_body" | grep -Fq 'pause; return 1'; then
    pass "08: iPerf3 安装/启动失败会返回非 0"
else
    fail "08: iPerf3 安装或启动失败仍可能被当作完成"
fi
echo "$net_dns_body" | grep -q 'network_lan' \
    && echo "$net_dns_body" | grep -q 'network_wan' \
    && pass "08: OpenWrt DNS 设置不再硬编码 wan" \
    || fail "08: OpenWrt DNS 设置仍硬编码 network.wan"
if grep -q '^_net_openwrt_apply_dns()' "$BUILT" \
   && grep -q '^_net_openwrt_restore_dns_snapshot()' "$BUILT" \
   && echo "$net_dns_body" | grep -q '_net_openwrt_apply_dns "$dns_iface" "$dns"' \
   && awk '/^_net_openwrt_apply_dns\(\)/,/^net_dns\(\)/' "$BUILT" | grep -q 'if ! uci add_list' \
   && awk '/^_net_openwrt_apply_dns\(\)/,/^net_dns\(\)/' "$BUILT" | grep -q 'if ! uci set "network.${iface}.peerdns=0"' \
   && awk '/^_net_openwrt_apply_dns\(\)/,/^net_dns\(\)/' "$BUILT" | grep -q 'if ! uci commit network' \
   && grep -q '^_net_openwrt_reload_network()' "$BUILT" \
   && awk '/^_net_openwrt_apply_dns\(\)/,/^net_dns\(\)/' "$BUILT" | grep -q 'if ! _net_openwrt_reload_network' \
   && awk '/^_net_openwrt_restore_dns_snapshot\(\)/,/^_net_openwrt_apply_dns\(\)/' "$BUILT" | grep -q '_net_openwrt_reload_network' \
   && awk '/^_net_openwrt_apply_dns\(\)/,/^net_dns\(\)/' "$BUILT" | grep -q '_net_openwrt_restore_dns_snapshot'; then
    pass "08: OpenWrt DNS uci/reload 失败会回滚旧配置"
else
    fail "08: OpenWrt DNS uci/reload 失败仍可能留下半写配置"
fi
if grep -q '^_net_render_resolved_dns_conf()' "$BUILT" \
   && grep -q '^_net_apply_systemd_resolved_dns()' "$BUILT" \
   && echo "$net_dns_body" | grep -q '_net_apply_systemd_resolved_dns "$dns"' \
   && ! echo "$net_dns_body" | grep -q 'sed -i.*resolved.conf' \
   && ! echo "$net_dns_body" | grep -q '>> "$res_conf"' \
   && ! echo "$net_dns_body" | grep -q 'echo.*\\[Resolve\\].*res_conf'; then
    pass "08: systemd-resolved DNS 通过渲染候选和原子写入"
else
    fail "08: systemd-resolved DNS 仍可能直接改写 resolved.conf"
fi
if grep -q '^_net_render_gai_conf()' "$BUILT" \
   && grep -q '^_net_apply_gai_priority()' "$BUILT" \
   && echo "$net_body" | grep -q '_net_apply_gai_priority ipv4' \
   && echo "$net_body" | grep -q '_net_apply_gai_priority ipv6' \
   && ! echo "$net_body" | grep -q 'sed -i.*gai.conf' \
   && ! echo "$net_body" | grep -q '>> /etc/gai.conf'; then
    pass "08: gai.conf IP 优先级通过托管块原子写入"
else
    fail "08: gai.conf IP 优先级仍可能 sed/append 直接改写"
fi
if grep -q 'RANDOM % (max - min + 1)' "$BUILT"; then
    fail "Reality: 无 shuf fallback 仍受 RANDOM 32767 截断"
else
    pass "Reality: 无 shuf fallback 不受 RANDOM 截断"
fi

echo ""
echo "== review #35 剩余低/中危回归 =="
ufw_del_body=$(awk '/^ufw_del\(\)/,/^}/' "$BUILT")
ssh_keys_body=$(awk '/^ssh_keys\(\)/,/^}/' "$BUILT")
wg_rc_helper_body=$(awk '/^_wg_rc_local_insert_block\(\)/,/^}/' "$BUILT")
wg_openwrt_deploy_body=$(awk '/^_wg_show_openwrt_deploy\(\)/,/^wg_setup_watchdog\(\)/' "$BUILT")
geoip_update_template_body=$(awk '/cat > \/usr\/local\/bin\/geoip-update\.sh/,/UPDATE_EOF/' "$BUILT")
sshd_directive_body=$(awk '/^_sshd_set_directive\(\)/,/^}/' "$BUILT")
reality_apply_body=$(awk '/^reality_apply_singbox_config\(\)/,/^reality_load_state\(\)/' "$BUILT")
ddns_setup_body=$(awk '/^ddns_setup\(\)/,/^ddns_setup_noninteractive\(\)/' "$BUILT")
ddns_setup_noninteractive_body=$(awk '/^ddns_setup_noninteractive\(\)/,/^parse_ddns_conf\(\)/' "$BUILT")

# DDNS update_cf 的 POST/PUT 也必须设置超时，不能只有 GET 有超时。
echo "$update_cf_body" | grep -q -- '--connect-timeout 10 --max-time 30 -X "\$method"' \
    && pass "DDNS: update_cf POST/PUT curl 设置超时并引用 method" \
    || fail "DDNS: update_cf POST/PUT curl 缺少超时或未引用 method"
grep -q 'DDNS_DOMAIN=\\"${ddns_domain}\\"' "$BUILT" \
    && grep -q 'DDNS_INTERVAL=\\"${ddns_interval}\\"' "$BUILT" \
    && pass "DDNS: 家宽暴露生成的 DDNS 配置保留值引号" \
    || fail "DDNS: 家宽暴露生成的 DDNS 配置仍可能丢失值引号"
echo "$web_home_body" | grep -Fq 'write_file_atomic "${CONFIG_DIR}/${full_domain}.conf" "$domain_config_content"' \
    && ! echo "$web_home_body" | grep -q 'cat > "${CONFIG_DIR}/${full_domain}.conf"' \
    && pass "Web: 家宽暴露域名管理配置通过原子写入" \
    || fail "Web: 家宽暴露域名管理配置仍可能直写最终路径"
web_home_rollback_body=$(awk '/^_web_home_expose_rollback\(\)/,/^web_home_expose\(\)/' "$BUILT")
if echo "$web_home_body" | grep -Fq 'if ! write_file_atomic "$hook_script" "$hook_content"; then' \
   && echo "$web_home_body" | grep -Fq 'if ! chmod +x "$hook_script"; then' \
   && echo "$web_home_body" | grep -Fq 'if ! cron_add_job "$cron_tag"' \
   && echo "$web_home_body" | grep -Fq 'if ! write_file_atomic "${CONFIG_DIR}/${full_domain}.conf" "$domain_config_content"; then' \
   && grep -q '^_web_home_expose_rollback()' "$BUILT" \
   && echo "$web_home_rollback_body" | grep -Fq '_cf_dns_restore_records "$zone_id" "$token" "$domain" "$dns_snapshot" A AAAA CNAME' \
   && echo "$web_home_rollback_body" | grep -Fq '_cf_origin_rules_restore "$token" "$zone_id" "$origin_rules_snapshot"' \
   && echo "$web_home_rollback_body" | grep -Fq '_web_cleanup_domain "$domain" "quiet"' \
   && [[ $(grep -F -c '_web_home_expose_rollback "$full_domain" "$zone_id" "$token"' <<< "$web_home_body") -ge 4 ]] \
   && ! echo "$web_home_body" | grep -Fq '域名管理配置写入失败，请稍后在 Web 管理中检查'; then
    pass "Web: 家宽暴露尾段 hook/cron/config 失败会中止、恢复 CF 远端并清理"
else
    fail "Web: 家宽暴露尾段失败仍可能提示成功、残留半成品或不恢复 CF 远端"
fi
echo "$ddns_setup_body$ddns_setup_noninteractive_body" | grep -Fq 'ddns_create_script ||' \
    && echo "$ddns_setup_body$ddns_setup_noninteractive_body" | grep -Fq 'ddns_rebuild_cron ||' \
    && pass "DDNS: setup helper 检查脚本生成和 cron 更新失败" \
    || fail "DDNS: setup helper 仍可能忽略脚本生成或 cron 更新失败"
echo "$web_home_body" | grep -Fq 'ddns_create_script ||' \
    && echo "$web_home_body" | grep -Fq 'ddns_rebuild_cron ||' \
    && pass "Web: 家宽暴露 DDNS 阶段检查脚本生成和 cron 更新失败" \
    || fail "Web: 家宽暴露 DDNS 阶段仍可能失败后继续"
if echo "$web_home_body" | grep -Fq 'dns_snapshot=$(_cf_dns_snapshot_records "$zone_id" "$token" "$full_domain" A AAAA CNAME)' \
   && echo "$web_home_body" | grep -Fq 'dns_restore_needed=1' \
   && echo "$web_home_body" | grep -Fq 'origin_rules_snapshot="$existing_rules"' \
   && echo "$web_home_body" | grep -Fq 'origin_restore_needed=1' \
   && echo "$web_home_body" | grep -Fq 'dns_restore_needed=0' \
   && echo "$web_home_body" | grep -Fq 'origin_restore_needed=0'; then
    pass "Web: 家宽暴露 DNS/Origin 远端状态具备快照恢复边界"
else
    fail "Web: 家宽暴露缺少 DNS/Origin 远端快照恢复边界"
fi
web_add_body=$(awk '/^web_add_domain\(\)/,/^web_view_config\(\)/' "$BUILT")
echo "$web_add_body" | grep -Fq 'case $dns_mode in' \
    && echo "$web_add_body" | grep -Fq 'esac || {' \
    && echo "$web_add_body" | grep -Fq 'print_error "DNS 记录配置失败"' \
	&& echo "$web_add_body" | grep -Fq 'ddns_setup "$DOMAIN" "$CF_API_TOKEN" "$zone_id" "$ddns_ipv4" "$ddns_ipv6" "$dns_proxied" ||' \
	&& pass "Web: 添加域名检查 DNS/DDNS 配置失败" \
	|| fail "Web: 添加域名仍可能忽略 DNS 或 DDNS 配置失败"
web_add_rollback_body=$(awk '/^_web_add_domain_rollback\(\)/,/^web_add_domain\(\)/' "$BUILT")
grep -q '^_web_add_domain_rollback()' "$BUILT" \
	&& echo "$web_add_rollback_body" | grep -Fq '_web_cleanup_domain "$domain" "quiet"' \
	&& echo "$web_add_body" | grep -Fq '_web_add_domain_rollback "$DOMAIN" "$rollback_clean_start"' \
	&& pass "Web: 添加域名失败会清理本次本地半成品" \
	|| fail "Web: 添加域名失败路径缺少本地半成品回滚"
if grep -q '^_cf_dns_snapshot_records()' "$BUILT" \
   && grep -q '^_cf_dns_restore_records()' "$BUILT" \
   && echo "$web_add_body" | grep -Fq 'dns_snapshot=$(_cf_dns_snapshot_records "$zone_id" "$CF_API_TOKEN" "$DOMAIN" A AAAA CNAME)' \
   && echo "$web_add_body" | grep -Fq 'dns_restore_needed=1' \
   && echo "$web_add_rollback_body" | grep -Fq '_cf_dns_restore_records "$zone_id" "$token" "$domain" "$dns_snapshot" A AAAA CNAME'; then
    pass "Web: 添加域名失败会恢复 Cloudflare DNS 快照"
else
    fail "Web: 添加域名失败路径缺少 Cloudflare DNS 快照恢复"
fi
web_reverse_body=$(awk '/^web_reverse_proxy_site\(\)/,/^web_edit_reverse_proxy\(\)/' "$BUILT")
if grep -q '^_web_allow_public_tcp_port()' "$BUILT" \
   && echo "$web_add_body" | grep -q '_web_allow_public_tcp_port "\$NGINX_HTTP_PORT"' \
   && echo "$web_add_body" | grep -q '_web_allow_public_tcp_port "\$NGINX_HTTPS_PORT"' \
   && echo "$web_reverse_body" | grep -q '_web_allow_public_tcp_port "\$HTTP_PORT"' \
   && echo "$web_reverse_body" | grep -q '_web_allow_public_tcp_port "\$HTTPS_PORT"' \
   && echo "$web_home_body" | grep -q '_web_allow_public_tcp_port "\$https_port"' \
   && ! echo "$web_add_body$web_reverse_body$web_home_body" | grep -q 'ufw allow .*|| true'; then
    pass "Web: 公网端口放行统一走 helper，UFW active 失败不再被吞掉"
else
    fail "Web: 仍可能直接吞掉 ufw allow 失败并误报防火墙已更新"
fi

# UFW 删除菜单文案声称过滤 Fail2ban，就必须真实过滤；端口也要走 validate_port。
echo "$ufw_del_body" | grep -qiE 'grep -viE .*fail2ban|grep -viE .*f2b' \
    && pass "UFW: 删除列表真实过滤 Fail2ban 规则" \
    || fail "UFW: 删除列表仍未过滤 Fail2ban 规则"
echo "$ufw_del_body" | grep -q 'validate_port "\$port"' \
    && pass "UFW: 删除规则前校验端口范围" \
    || fail "UFW: 删除规则前缺 validate_port"

# SSH 公钥删除不能用 sed 分隔符拼接目标 key；应按整行固定字符串过滤。
if echo "$ssh_keys_body" | grep -q 'sed -i "\\|${escaped_key}|d"'; then
    fail "SSH: 公钥删除仍依赖 sed 分隔符，key/comment 含 | 时会误删/失败"
else
    pass "SSH: 公钥删除不再依赖 sed 分隔符"
fi
ssh_keys_remove_body=$(awk '/^_ssh_authorized_keys_remove\(\)/,/^_ssh_non_root_sudo_available\(\)/' "$BUILT")
echo "$ssh_keys_remove_body" | grep -q 'grep -Fvx -- "\$key" "\$ak"' \
    && pass "SSH: 公钥删除按整行固定字符串过滤" \
    || fail "SSH: 公钥删除未按整行固定字符串过滤"
grep -q '^_ssh_authorized_keys_remove()' "$BUILT" \
    && echo "$ssh_keys_body" | grep -q '_ssh_authorized_keys_remove "\$ak" "\$target_key" "\$user:\$user"' \
    && ! echo "$ssh_keys_body" | grep -q 'cat "\$tmp_ak" > "\$ak"' \
    && pass "SSH: 公钥删除通过同目录私有临时文件原子替换" \
    || fail "SSH: 公钥删除仍可能直接截断 authorized_keys"
grep -q '^_ssh_authorized_keys_append()' "$BUILT" \
    && echo "$ssh_keys_body" | grep -q '_ssh_authorized_keys_append "\$dir/authorized_keys" "\$key" "\$user:\$user"' \
    && echo "$ssh_keys_body" | grep -q '_ssh_authorized_keys_append "\$imp_dir/authorized_keys" "\$pub_key" "\$imp_user:\$imp_user"' \
    && ! echo "$ssh_keys_body" | grep -q '>> "\$dir/authorized_keys"' \
    && ! echo "$ssh_keys_body" | grep -q '>> "\$imp_dir/authorized_keys"' \
    && pass "SSH: 公钥导入通过同目录私有临时文件原子追加" \
    || fail "SSH: 公钥导入仍可能直接追加 authorized_keys"

# rc.local 插入应识别带空格/注释的 exit 0，而不是追加到 exit 0 后。
rc_anchor_tmp=$(mktemp)
printf '#!/bin/sh\necho boot\nexit 0   # done\n' > "$rc_anchor_tmp"
if _wg_rc_local_insert_block 'echo inserted' "$rc_anchor_tmp" >/dev/null 2>&1 \
   && awk '/echo inserted/{ins=NR} /exit 0/{ex=NR} END{exit !(ins && ex && ins < ex)}' "$rc_anchor_tmp"; then
    pass "G10: rc.local helper 支持带空格/注释的 exit 0 锚点"
else
    fail "G10: rc.local helper 未识别带空格/注释的 exit 0 锚点"
    sed 's/^/    /' "$rc_anchor_tmp"
fi
rm -f "$rc_anchor_tmp"
if echo "$wg_openwrt_deploy_body" | grep -q '/^exit 0\\$/'; then
    fail "G10: OpenWrt 部署命令仍只匹配严格 exit 0"
else
    pass "G10: OpenWrt 部署命令不再只匹配严格 exit 0"
fi
echo "$wg_openwrt_deploy_body" | grep -q '^wg_endpoint_host()' \
    && pass "WG/OpenWrt: watchdog 已定义 endpoint host 解析 helper" \
    || fail "WG/OpenWrt: watchdog 缺少 endpoint host 解析 helper"
echo "$wg_openwrt_deploy_body" | grep -q '^resolve_real()' \
    && ! echo "$wg_openwrt_deploy_body" | grep -Fq "awk '/^Address:/{a=" \
    && pass "WG/OpenWrt: watchdog 使用兼容 BusyBox/fake-ip 的 endpoint 解析逻辑" \
    || fail "WG/OpenWrt: watchdog 仍可能误解析 endpoint DNS 输出"
if echo "$wg_openwrt_deploy_body" | grep -q 'cut -d: -f1'; then
    fail "WG/OpenWrt: watchdog 仍用 cut -d: 截断 IPv6 endpoint"
else
    pass "WG/OpenWrt: watchdog 不再用 cut -d: 解析 endpoint"
fi
if echo "$wg_openwrt_deploy_body" | grep -q '&>/dev/null'; then
    fail "WG/OpenWrt: 部署命令生成的 sh 脚本仍含 Bash-only &> 重定向"
else
    pass "WG/OpenWrt: 部署命令生成的 sh 脚本使用 POSIX 重定向"
fi
wg_openwrt_clean_body=$(awk '/^wg_openwrt_clean_cmd\(\)/,/^wg_server_menu\(\)/' "$BUILT")
if grep -q 'ip -o link show type wireguard' "$BUILT"; then
    fail "WG/OpenWrt: 仍依赖 BusyBox 可能不支持的 ip -o 枚举 WireGuard 接口"
else
    pass "WG/OpenWrt: WireGuard 接口枚举不再依赖 ip -o"
fi
echo "$wg_openwrt_deploy_body$wg_openwrt_clean_body" | grep -q 'list_wg_ifaces()' \
    && echo "$wg_openwrt_deploy_body$wg_openwrt_clean_body" | grep -q 'ip link show type wireguard' \
    && pass "WG/OpenWrt: 生成脚本使用 BusyBox 兼容接口枚举函数" \
    || fail "WG/OpenWrt: 生成脚本缺少兼容接口枚举函数"
if grep -q 'grep -v wg-watchdog' "$BUILT" || grep -q 'cron_remove_job "wg-watchdog.sh"' "$BUILT"; then
    fail "WG: watchdog cron 清理仍使用宽泛 wg-watchdog 匹配"
else
    pass "WG: watchdog cron 清理按脚本命令路径匹配"
fi
echo "$wg_openwrt_deploy_body" | grep -Fq "awk '\\\$6 != \"/usr/bin/wg-watchdog.sh\"'" \
    && pass "WG/OpenWrt: 部署命令按 /usr/bin/wg-watchdog.sh 精确更新 cron" \
    || fail "WG/OpenWrt: 部署命令未精确更新 watchdog cron"
echo "$wg_openwrt_deploy_body" | grep -q '^wg_ensure_wireguard_proto()' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'ubus call network get_proto_handlers' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'die_restore "netifd 未注册 wireguard 协议"' \
    && echo "$wg_openwrt_deploy_body" | grep -q '/etc/init.d/network restart' \
    && pass "WG/OpenWrt: 部署命令会重启 netifd 以注册 wireguard 协议" \
    || fail "WG/OpenWrt: 部署命令未处理 netifd 缺少 wireguard 协议"
echo "$wg_openwrt_deploy_body" | grep -q 'ubus call network reload >/dev/null 2>&1 || true' \
    && pass "WG/OpenWrt: UCI 写入后会 reload network 配置" \
    || fail "WG/OpenWrt: UCI 写入后未 reload network 配置"
if echo "$wg_openwrt_deploy_body" | grep -Fq "ifstatus wg0 2>/dev/null | grep -q '\"up\": true'" \
   && echo "$wg_openwrt_deploy_body" | grep -Fq 'if ! wg_is_up; then' \
   && ! echo "$wg_openwrt_deploy_body" | grep -Fq 'if ! ifstatus wg0 >/dev/null 2>&1'; then
    pass "WG/OpenWrt: watchdog 按 up=true 判断接口状态"
else
    fail "WG/OpenWrt: watchdog 仍可能把 NO_DEVICE 误判为已启动"
fi
echo "$wg_openwrt_deploy_body" | grep -Fq 'cp "$WG_CRON_TMP" /etc/crontabs/root' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq 'chmod 600 /etc/crontabs/root' \
    && echo "$wg_openwrt_deploy_body" | grep -Fq '/etc/crontabs/root || die_restore "安装 wg-watchdog cron 失败"' \
    && pass "WG/OpenWrt: watchdog cron 直接持久化到 /etc/crontabs/root" \
    || fail "WG/OpenWrt: watchdog cron 仍可能依赖 crontab - 管道丢失"
echo "$wg_openwrt_deploy_body" | grep -q '^wg_format_endpoint()' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'endpoint "\$WG_ENDPOINT"' \
    && pass "WG/OpenWrt: watchdog IPv6 endpoint 会加方括号传给 wg set" \
    || fail "WG/OpenWrt: watchdog 未安全格式化 IPv6 endpoint"
echo "$wg_openwrt_deploy_body" | grep -q '^wg_nft_addr_family()' \
    && echo "$wg_openwrt_deploy_body" | grep -q '"\$NFT_FAMILY" daddr "\$RESOLVED"' \
    && pass "WG/OpenWrt: watchdog bypass 按 IPv4/IPv6 选择 nft 地址族" \
    || fail "WG/OpenWrt: watchdog bypass 仍可能把 IPv6 写入 ip daddr"
echo "$wg_openwrt_deploy_body" | grep -q '^wg_ip_rule_add()' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'ip -6 rule add to "\$1"' \
    && pass "WG/OpenWrt: watchdog IPv6 endpoint 使用 ip -6 rule" \
    || fail "WG/OpenWrt: watchdog IPv6 endpoint 未使用 ip -6 rule"
echo "$wg_openwrt_deploy_body" | grep -q 'elif echo "\$EP_HOST" | grep -q' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'RESOLVED="\$EP_HOST"' \
    && echo "$wg_openwrt_deploy_body" | grep -q '! echo "\$EP_HOST" | grep -q' \
    && pass "WG/OpenWrt: watchdog IPv6 literal endpoint 不再走 DNS re-resolve" \
    || fail "WG/OpenWrt: watchdog IPv6 literal endpoint 仍可能被当域名解析"
echo "$wg_openwrt_deploy_body" | grep -q 'ep_host=$(wg_shared_endpoint_host "\$sep")' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'uci set network.wg_server.endpoint_host=' \
    && pass "WG/OpenWrt: 部署命令会规范化 bracketed IPv6 endpoint_host" \
    || fail "WG/OpenWrt: 部署命令未规范化 endpoint_host"
echo "$wg_openwrt_deploy_body" | grep -q 'NFT_FAMILY="ip6"' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'ip -6 rule add to "\\${EP_IP}"' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'mangle_prerouting "\\${NFT_FAMILY}" daddr "\\${EP_IP}"' \
    && pass "WG/OpenWrt: 初次部署 bypass 支持 IPv6 endpoint" \
    || fail "WG/OpenWrt: 初次部署 bypass 仍可能 IPv4-only"
echo "$wg_openwrt_deploy_body" | grep -q 'WG_NFT_FAMILY=ip6' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'ip -6 rule add to "\\$WG_EP"' \
    && echo "$wg_openwrt_deploy_body" | grep -q 'mangle_prerouting "\\$WG_NFT_FAMILY" daddr "\\$WG_EP"' \
    && pass "WG/OpenWrt: rc.local bypass 支持 IPv6 endpoint" \
    || fail "WG/OpenWrt: rc.local bypass 仍可能 IPv4-only"
echo "$wg_openwrt_endpoint_migrate_body" | grep -q '^install_rc_local_bypass()' \
    && echo "$wg_openwrt_endpoint_migrate_body" | grep -q 'BEGIN server-manage wireguard bypass' \
    && echo "$wg_openwrt_endpoint_migrate_body" | grep -Fq 'WG_EP=\$(wg_resolve_real' \
    && echo "$wg_openwrt_endpoint_migrate_body" | grep -q 'WG_NFT_FAMILY=ip6' \
    && ! echo "$wg_openwrt_endpoint_migrate_body" | grep -Fq "awk '/^Address:/{a=" \
    && pass "WG/OpenWrt: endpoint 迁移命令会重建 fake-ip 安全 rc.local bypass" \
    || fail "WG/OpenWrt: endpoint 迁移命令仍只替换旧 rc.local 或解析不安全"
grep -q '^wg_shared_format_endpoint()' "$BUILT" \
    && grep -q 'Endpoint = ${endpoint}' "$BUILT" \
    && pass "WG: 客户端配置使用共享 endpoint formatter" \
    || fail "WG: 客户端配置仍可能生成裸 IPv6 Endpoint"

# GeoIP cron IPv4 失败路径必须同时清理 tmp6。
grep -q 'rm -f "\$tmp" "\$tmp6"' "$BUILT" \
    && pass "GeoIP: cron IPv4 失败路径清理 tmp6" \
    || fail "GeoIP: cron IPv4 失败路径仍泄漏 tmp6"

# 新增临时文件也要接入统一中断清理。
echo "$sshd_directive_body" | grep -q '.tmp.server-manage.sshd-directive' \
    && echo "$sshd_directive_body" | grep -q '_tmp_register "\$tmpfile"' \
    && echo "$sshd_directive_body" | grep -q '_tmp_unregister "\$tmpfile"' \
    && pass "C4: _sshd_set_directive 临时文件接入统一清理" \
    || fail "C4: _sshd_set_directive 临时文件未接入统一清理"
echo "$reality_apply_body" | grep -q '.tmp.server-manage.singbox' \
    && echo "$reality_apply_body" | grep -q '_tmp_register "\$tmp"' \
    && echo "$reality_apply_body" | grep -q '_tmp_unregister "\$tmp"' \
    && pass "C4: Reality apply 临时配置接入统一清理" \
    || fail "C4: Reality apply 临时配置未接入统一清理"

# Debian WireGuard unit 名应使用 WG_DEB_INTERFACE 常量，避免 wg0 硬编码漂移。
if grep -q 'wg-quick@wg0' "$BUILT"; then
    fail "12c/12d/12e: Debian WireGuard 仍硬编码 wg-quick@wg0"
else
    pass "12c/12d/12e: Debian WireGuard unit 使用 WG_DEB_INTERFACE"
fi

# Debian watchdog 脚本由单引号 heredoc 写入时，运行期不能依赖未定义的 WG_DEB_INTERFACE。
wg_deb_watchdog_body=$(awk '/^wg_deb_setup_watchdog\(\)/,/^wg_deb_export_peers\(\)/' "$BUILT")
if echo "$wg_deb_watchdog_body" | grep -q "<< 'WDEOF_DEB'" \
   && echo "$wg_deb_watchdog_body" | grep -q 'wg-quick@${WG_DEB_INTERFACE}' \
   && ! echo "$wg_deb_watchdog_body" | grep -q "printf 'WG_DEB_INTERFACE=%q"; then
    fail "12e: Debian watchdog 单引号 heredoc 会把 WG_DEB_INTERFACE 留到运行期未定义"
else
    pass "12e: Debian watchdog 生成脚本内固定 WG_DEB_INTERFACE"
fi
if echo "$wg_deb_watchdog_body" | grep -qE 'ip link show wg0|wg show wg0|wg0 down'; then
    fail "12e: Debian watchdog 接口检测仍硬编码 wg0"
else
    pass "12e: Debian watchdog 接口检测使用 WG_DEB_INTERFACE"
fi
echo "$wg_deb_watchdog_body" | grep -q '\[\[ -z "\$auto_mode" \]\] && pause' \
    && echo "$wg_deb_watchdog_body" | grep -q 'return 0' \
    && pass "12e: Debian watchdog auto_mode 成功返回 0" \
    || fail "12e: Debian watchdog auto_mode 可能因条件判断返回 1"
echo "$wg_deb_watchdog_body" | grep -Fq 'mktemp "$(dirname "$watchdog_script")/.tmp.server-manage.wg-watchdog.XXXXXX"' \
    && echo "$wg_deb_watchdog_body" | grep -Fq 'mv "$watchdog_tmp" "$watchdog_script"' \
    && ! echo "$wg_deb_watchdog_body" | grep -q '> "$watchdog_script"' \
    && pass "12e: Debian watchdog 脚本通过临时文件原子替换" \
    || fail "12e: Debian watchdog 脚本仍可能直写最终路径"

# OpenWrt 包检测不能把包名前缀当命令名（如 ca-bundle -> ca）。
install_package_body=$(awk '/^install_package\(\)/,/^auto_deps\(\)/' "$BUILT")
if echo "$install_package_body" | grep -q 'command -v "${pkg%%-\*}"'; then
    fail "07: OpenWrt install_package 仍用包名前缀当命令检测"
else
    pass "07: OpenWrt install_package 不再用包名前缀当命令检测"
fi
opt_sysctl_body=$(awk '/^opt_sysctl\(\)/,/^menu_opt\(\)/' "$BUILT")
if echo "$opt_sysctl_body" | grep -Fq "sed -i '/^# server-manage sysctl tuning/,/^$/d'"; then
    fail "07: sysctl 调优块仍按首个空行删除，重复执行会累积/误删"
elif echo "$opt_sysctl_body" | grep -q 'BEGIN server-manage sysctl tuning' \
     && echo "$opt_sysctl_body" | grep -q 'END server-manage sysctl tuning'; then
    pass "07: sysctl 调优块使用显式 begin/end 标记删除"
else
    fail "07: sysctl 调优块缺少显式 begin/end 标记"
fi
if echo "$opt_sysctl_body" | grep -q 'sysctl -p "$tmp_candidate"' \
   && echo "$opt_sysctl_body" | grep -q 'mv "$tmp_candidate" "$sysctl_conf"' \
   && ! echo "$opt_sysctl_body" | grep -q "sed -i .*sysctl_conf" \
   && ! echo "$opt_sysctl_body" | grep -q '>> "$sysctl_conf"'; then
    pass "07: sysctl 调优先验证临时配置再提交"
else
    fail "07: sysctl 调优仍可能失败后污染正式配置"
fi
opt_bbr_body=$(awk '/^opt_bbr\(\)/,/^select_timezone\(\)/' "$BUILT")
if echo "$opt_bbr_body" | grep -Fq 'sysctl -p "$tmp_candidate"' \
   && echo "$opt_bbr_body" | grep -Fq 'mv "$tmp_candidate" "$sysctl_conf"' \
   && grep -q '^_sysctl_render_bbr_conf()' "$BUILT" \
   && ! echo "$opt_bbr_body" | grep -q 'sed -i .*sysctl.conf' \
   && ! echo "$opt_bbr_body" | grep -q '>> /etc/sysctl.conf' \
   && ! echo "$opt_bbr_body" | grep -q 'sysctl -p >/dev/null'; then
    pass "07: BBR 先验证临时配置再提交正式 sysctl.conf"
else
    fail "07: BBR 仍可能失败后污染正式 sysctl.conf"
fi
wg_deb_server_install_body=$(awk '/^wg_deb_server_install\(\)/,/^wg_deb_modify_server\(\)/' "$BUILT")
wg_deb_uninstall_body=$(awk '/^wg_deb_uninstall\(\)/,/^wg_deb_main_menu\(\)/' "$BUILT")
wg_openwrt_server_install_body=$(awk '/^wg_server_install\(\)/,/^wg_modify_server\(\)/' "$BUILT")
wg_openwrt_uninstall_body=$(awk '/^wg_uninstall\(\)/,/^wg_openwrt_clean_cmd\(\)/' "$BUILT")
if grep -q '^_sysctl_enable_wireguard_forward()' "$BUILT" \
   && grep -q '^_sysctl_disable_wireguard_forward()' "$BUILT" \
   && echo "$wg_deb_server_install_body" | grep -q '_sysctl_enable_wireguard_forward' \
   && echo "$wg_openwrt_server_install_body" | grep -q '_sysctl_enable_wireguard_forward' \
   && echo "$wg_deb_uninstall_body" | grep -q '_sysctl_disable_wireguard_forward' \
   && echo "$wg_openwrt_uninstall_body" | grep -q '_sysctl_disable_wireguard_forward' \
   && ! echo "$wg_deb_server_install_body$wg_openwrt_server_install_body$wg_deb_uninstall_body$wg_openwrt_uninstall_body" | grep -q 'sed -i .*net.ipv4.ip_forward.*sysctl.conf' \
   && ! echo "$wg_deb_server_install_body$wg_openwrt_server_install_body" | grep -q 'net.ipv4.ip_forward=1.*>> /etc/sysctl.conf'; then
    pass "WG: IP 转发 sysctl 通过托管块候选验证提交"
else
    fail "WG: IP 转发仍可能直接改写 /etc/sysctl.conf 或误删外部配置"
fi
if grep -q '^_wg_deb_rollback_server_install()' "$BUILT" \
   && echo "$wg_deb_server_install_body" | grep -q 'if ! systemctl enable "wg-quick@${WG_DEB_INTERFACE}"' \
   && echo "$wg_deb_server_install_body" | grep -q 'if ! systemctl start "wg-quick@${WG_DEB_INTERFACE}"' \
   && echo "$wg_deb_server_install_body" | grep -q 'if ! wg_deb_is_running; then' \
   && echo "$wg_deb_server_install_body" | grep -q '_wg_deb_rollback_server_install "$wg_port" "$wg_udp_rule_added"' \
   && echo "$wg_deb_server_install_body" | grep -q 'wg_deb_setup_watchdog "true" || print_warn' \
   && ! echo "$wg_deb_server_install_body" | grep -q 'WireGuard 已安装，但启动可能失败'; then
    pass "WG: Debian 服务端启动/运行失败会回滚并返回非 0"
else
    fail "WG: Debian 服务端启动失败仍可能被当作安装成功"
fi
if grep -q '^_wg_openwrt_rollback_server_install()' "$BUILT" \
   && grep -q '^_wg_openwrt_snapshot_server_install()' "$BUILT" \
   && grep -q '^_wg_openwrt_restore_uci_package()' "$BUILT" \
   && echo "$wg_openwrt_server_install_body" | grep -q '_wg_openwrt_snapshot_server_install "$wg_install_snapshot_dir"' \
   && echo "$wg_openwrt_server_install_body" | grep -q '_wg_openwrt_rollback_server_install "$wg_install_snapshot_dir" "$wg_forward_changed"' \
   && echo "$wg_openwrt_server_install_body" | grep -q 'if ! ifup wg0' \
   && echo "$wg_openwrt_server_install_body" | grep -q 'if ! wg_is_running; then'; then
    pass "WG: OpenWrt 服务端安装失败会恢复 UCI/本地文件/运行态"
else
    fail "WG: OpenWrt 服务端安装失败仍可能留下半配置"
fi
wg_openwrt_netcheck_body=$(awk '/^wg_check_openwrt_compat\(\)/,/^wg_check_public_ip\(\)/' "$BUILT")
if echo "$wg_openwrt_server_install_body$wg_openwrt_netcheck_body" | grep -q 'grep -oP.*inet .*\\\\K'; then
    fail "WG/OpenWrt: br-lan 网段检测仍依赖 BusyBox 不支持的 grep -P"
elif echo "$wg_openwrt_server_install_body$wg_openwrt_netcheck_body" | grep -Fq 'awk '\''/^[[:space:]]*inet[[:space:]]/ { print $2; exit }'\'''; then
    pass "WG/OpenWrt: br-lan 网段检测使用 BusyBox 兼容 awk"
else
    fail "WG/OpenWrt: br-lan 网段检测缺少 BusyBox 兼容 awk"
fi
if echo "$wg_openwrt_uninstall_body" | grep -q 'if ! uci commit network' \
   && echo "$wg_openwrt_uninstall_body" | grep -q 'if ! uci commit firewall' \
   && echo "$wg_openwrt_uninstall_body" | grep -q 'pause; return 1' \
   && ! echo "$wg_openwrt_uninstall_body" | grep -q 'uci commit network.*|| true' \
   && ! echo "$wg_openwrt_uninstall_body" | grep -q 'uci commit firewall.*|| true'; then
    pass "WG: OpenWrt 卸载 UCI commit 失败会中止成功路径"
else
    fail "WG: OpenWrt 卸载仍可能吞掉 UCI commit 失败"
fi
constants_head=$(sed -n '1,90p' "$BUILT")
if echo "$constants_head" | awk '
    /^detect_platform$/ { seen_detect=1 }
    /readonly LOG_FILE="\/var\/log/ && !seen_detect { bad=1 }
    END { exit bad ? 0 : 1 }
'; then
    fail "00: LOG_FILE 在平台检测前固定到 /var/log，OpenWrt tmpfs 重启丢日志"
elif echo "$constants_head" | grep -q 'PLATFORM.*openwrt' \
     && echo "$constants_head" | grep -q '/root/.server-manage/log'; then
    pass "00: OpenWrt LOG_FILE 使用持久化路径"
else
    fail "00: LOG_FILE 缺少 OpenWrt 持久化路径分支"
fi
if grep -qE 'while ip rule del prio 100|ip rule del lookup main prio 100' "$BUILT"; then
    fail "11: WireGuard 清理仍粗暴删除全部 prio 100 ip rule"
else
    pass "11: WireGuard 清理不再删除第三方 prio 100 ip rule"
fi
if grep -q 'ip rule.*prio 100/d' "$BUILT"; then
    fail "11: WireGuard rc.local 清理仍粗暴删除第三方 prio 100 行"
else
    pass "11: WireGuard rc.local 清理不再删除第三方 prio 100 行"
fi
wg_deb_db_get() {
    case "$1" in
        ".server.subnet") echo "10.8.0.0/24" ;;
        '[.server.ip] + [.peers[].ip] | join(" ")') echo "10x8x0x2 10.8.0.3" ;;
        *) echo "" ;;
    esac
}
if [[ "$(wg_deb_next_ip 2>/dev/null)" == "10.8.0.2" ]]; then
    pass "12b: Debian 下一可用 IP 查重按固定字符串精确匹配"
else
    fail "12b: Debian 下一可用 IP 查重仍受 grep 正则影响"
fi
wg_db_get() {
    case "$1" in
        ".server.subnet") echo "10.9.0.0/24" ;;
        '[.server.ip] + [.peers[].ip] | join(" ")') echo "10x9x0x2 10.9.0.3" ;;
        *) echo "" ;;
    esac
}
if [[ "$(wg_next_ip 2>/dev/null)" == "10.9.0.2" ]]; then
    pass "11: OpenWrt 下一可用 IP 查重按固定字符串精确匹配"
else
    fail "11: OpenWrt 下一可用 IP 查重仍受 grep 正则影响"
fi
wg_deb_add_peer_body=$(awk '/^wg_deb_add_peer\(\)/,/^wg_deb_toggle_peer\(\)/' "$BUILT")
if echo "$wg_deb_add_peer_body" | awk '
    /write_file_atomic "\$conf_file" "\$client_conf"/ { prewrite=NR }
    /wg_deb_db_set/ && !dbset { dbset=NR }
    END { exit (prewrite && dbset && prewrite < dbset) ? 0 : 1 }
'; then
    fail "12d: Debian 添加 peer 仍在 DB 写入前冗余初写客户端配置"
else
    pass "12d: Debian 添加 peer 不再 DB 前冗余初写客户端配置"
fi
if grep -q 'rm -f /etc/wireguard/\*.key' "$BUILT"; then
    fail "12c: Debian 卸载仍删除 /etc/wireguard/*.key，可能误删外部密钥"
else
    pass "12c: Debian 卸载不再误删外部 .key 文件"
fi
dead_defs=()
for fn in _cf_dns_upsert wg_db_migrate wg_deb_db_migrate wg_list_peers wg_deb_list_peers; do
    grep -q "^${fn}()" "$BUILT" && dead_defs+=("$fn")
done
if [[ ${#dead_defs[@]} -eq 0 ]]; then
    pass "P7: 已清理未调用死函数"
else
    fail "P7: 仍保留未调用死函数: ${dead_defs[*]}"
fi
wg_rebuild_uci_body=$(awk '/^wg_rebuild_uci_conf\(\)/,/^wg_sync_peer_routes\(\)/' "$BUILT")
if echo "$wg_rebuild_uci_body" | grep -q 'no_reload' \
   && echo "$wg_deb_add_peer_body" | grep -q 'wg_deb_apply_conf' \
   && grep -q '^wg_deb_apply_conf()' "$BUILT" \
   && grep -q '^wg_apply_runtime_conf()' "$BUILT"; then
    pass "G1: WireGuard peer 操作具备热应用 helper"
else
    fail "G1: WireGuard peer 操作仍缺少热应用 helper"
fi
wg_restore_network_uci_body=$(awk '/^_wg_openwrt_restore_network_uci_snapshot\(\)/,/^}/' "$BUILT")
if grep -q '^_wg_openwrt_restore_network_uci_snapshot()' "$BUILT" \
   && echo "$wg_restore_network_uci_body" | grep -q 'uci revert network' \
   && echo "$wg_restore_network_uci_body" | grep -q 'uci import network < "\$snapshot"' \
   && echo "$wg_restore_network_uci_body" | grep -q 'uci commit network' \
   && echo "$wg_rebuild_uci_body" | grep -q 'uci export network > "\$uci_snapshot"' \
   && echo "$wg_rebuild_uci_body" | grep -q '_wg_openwrt_restore_network_uci_snapshot "\$uci_snapshot"'; then
    pass "G1: OpenWrt wg_rebuild_uci_conf 失败时恢复 network UCI 快照"
else
    fail "G1: OpenWrt wg_rebuild_uci_conf 缺少 network UCI 快照恢复"
fi
if echo "$wg_deb_add_peer_body" | grep -q 'systemctl restart wg-quick@${WG_DEB_INTERFACE}' \
   || awk '/^wg_deb_toggle_peer\(\)/,/^wg_deb_show_peer_conf\(\)/' "$BUILT" | grep -q 'systemctl restart wg-quick@${WG_DEB_INTERFACE}' \
   || awk '/^wg_deb_import_peers\(\)/,/^wg_deb_server_menu\(\)/' "$BUILT" | grep -q 'systemctl restart wg-quick@${WG_DEB_INTERFACE}'; then
    fail "G1: Debian peer 增删启停/导入仍整隧道 restart"
else
    pass "G1: Debian peer 增删启停/导入不再整隧道 restart"
fi
if grep -q '^wg_deb_generate_clash_config()' "$BUILT" \
   && awk '/^wg_deb_add_peer\(\)/,/^wg_deb_show_peer_conf\(\)/' "$BUILT" | grep -q 'wg_deb_generate_clash_config' \
   && awk '/^wg_deb_server_menu\(\)/,/^wg_deb_main_menu\(\)/' "$BUILT" | grep -q 'wg_deb_generate_clash_config' \
   && ! awk '/^wg_deb_add_peer\(\)/,/^wg_deb_show_peer_conf\(\)/' "$BUILT" | grep -q 'wg_generate_clash_config'; then
    pass "H9: Debian WireGuard 不再直接调用 OpenWrt Clash 生成函数"
else
    fail "H9: Debian WireGuard 仍隐式调用 OpenWrt Clash 生成函数"
fi
if grep -q '^_wg_generate_clash_config_impl()' "$BUILT" \
   && awk '/^wg_generate_clash_config\(\)/,/^wg_deb_generate_clash_config\(\)/' "$BUILT" | grep -q '_wg_generate_clash_config_impl "openwrt"' \
   && awk '/^wg_deb_generate_clash_config\(\)/,/^wg_deb_setup_watchdog\(\)/' "$BUILT" | grep -q '_wg_generate_clash_config_impl "debian"'; then
    pass "H9: Clash 配置生成共用实现，平台差异由 wrapper 注入"
else
    fail "H9: Clash 配置生成仍未收敛到共享实现"
fi
if grep -q 'WG_SHARED_DB_FILE' "$BUILT" \
   && grep -q 'WG_DB_FILE="${WG_SHARED_DB_FILE}"' "$BUILT" \
   && grep -q 'WG_DEB_DB_FILE="${WG_SHARED_DB_FILE}"' "$BUILT" \
   && grep -q 'WG_DEB_ROLE_FILE="${WG_SHARED_ROLE_FILE}"' "$BUILT"; then
    pass "H9: 11/12 共用 WireGuard DB/role 路径改为显式共享常量"
else
    fail "H9: 11/12 WireGuard DB/role 仍是隐式同路径假隔离"
fi
if grep -q '^wg_shared_db_set()' "$BUILT" \
   && awk '/^wg_deb_db_set\(\)/,/^wg_deb_get_role\(\)/' "$BUILT" | grep -q 'wg_shared_db_set "$@"' \
   && awk '/^wg_db_set\(\)/,/^wg_get_role\(\)/' "$BUILT" | grep -q 'wg_shared_db_set "$@"' \
   && awk '/^wg_deb_get_role\(\)/,/^wg_deb_set_role\(\)/' "$BUILT" | grep -q 'wg_shared_get_role'; then
    pass "H9: 11/12 WireGuard DB/role 工具函数收敛到共享实现"
else
    fail "H9: 11/12 WireGuard DB/role 工具函数仍重复实现"
fi
wg_apply_runtime_body=$(awk '/^wg_apply_runtime_conf\(\)/,/^wg_rebuild_conf\(\)/' "$BUILT")
wg_deb_apply_runtime_body=$(awk '/^wg_deb_apply_conf\(\)/,/^wg_deb_server_menu\(\)/' "$BUILT")
wg_shared_db_init_body=$(awk '/^wg_shared_db_init\(\)/,/^wg_shared_db_get\(\)/' "$BUILT")
wg_regenerate_client_body=$(awk '/^wg_regenerate_client_confs\(\)/,/^wg_apply_runtime_conf\(\)/' "$BUILT")
wg_deb_regenerate_client_body=$(awk '/^wg_deb_regenerate_client_confs\(\)/,/^wg_deb_apply_conf\(\)/' "$BUILT")
if echo "$wg_shared_db_init_body" | grep -q 'wg_write_private_file "\$WG_SHARED_DB_FILE"' \
   && echo "$wg_private_write_body" | grep -q 'umask 077'; then
    pass "WG: 共享 DB 初始化走私有原子写入"
else
    fail "WG: 共享 DB 初始化仍可能按宽 umask 创建"
fi
if echo "$wg_regenerate_client_body" | grep -q 'wg_write_private_file "/etc/wireguard/clients/\${name}.conf"' \
   && ! echo "$wg_regenerate_client_body" | grep -q 'write_file_atomic "/etc/wireguard/clients/\${name}.conf"'; then
    pass "WG/OpenWrt: 客户端配置批量重建走私有原子写入"
else
    fail "WG/OpenWrt: 客户端配置批量重建仍可能继承旧宽权限"
fi
if echo "$wg_deb_regenerate_client_body" | grep -q 'wg_write_private_file "\${WG_DEB_CLIENT_DIR}/\${name}.conf"' \
   && ! echo "$wg_deb_regenerate_client_body" | grep -q 'write_file_atomic "\${WG_DEB_CLIENT_DIR}/\${name}.conf"'; then
    pass "WG/Debian: 客户端配置批量重建走私有原子写入"
else
    fail "WG/Debian: 客户端配置批量重建仍可能继承旧宽权限"
fi
if echo "$wg_apply_runtime_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/\${SCRIPT_NAME}-wg-sync.XXXXXX"' \
   && echo "$wg_apply_runtime_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$wg_apply_runtime_body" | grep -q 'chmod 600 "\$tmp"' \
   && echo "$wg_apply_runtime_body" | grep -q 'rm -rf "\$tmp_dir"' \
   && ! echo "$wg_apply_runtime_body" | grep -q 'mktemp "/tmp/\${SCRIPT_NAME}-wg-sync.XXXXXX"'; then
    pass "WG/OpenWrt: syncconf 敏感临时文件使用私有目录"
else
    fail "WG/OpenWrt: syncconf 临时文件仍可能散落公共 /tmp"
fi
if echo "$wg_deb_apply_runtime_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/\${SCRIPT_NAME}-wg-deb-sync.XXXXXX"' \
   && echo "$wg_deb_apply_runtime_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$wg_deb_apply_runtime_body" | grep -q 'chmod 600 "\$tmp"' \
   && echo "$wg_deb_apply_runtime_body" | grep -q 'rm -rf "\$tmp_dir"' \
   && ! echo "$wg_deb_apply_runtime_body" | grep -q 'mktemp "/tmp/\${SCRIPT_NAME}-wg-deb-sync.XXXXXX"'; then
    pass "WG/Debian: syncconf 敏感临时文件使用私有目录"
else
    fail "WG/Debian: syncconf 临时文件仍可能散落公共 /tmp"
fi
if grep -q '^wg_shared_sync_gateway_routes()' "$BUILT" \
   && grep -q 'WG_SHARED_ROUTE_STATE_FILE' "$BUILT" \
   && echo "$wg_apply_runtime_body" | grep -q 'wg_sync_peer_routes || return 1' \
   && echo "$wg_deb_apply_runtime_body" | grep -q 'wg_deb_sync_peer_routes || return 1' \
   && awk '/^wg_shared_sync_gateway_routes\(\)/,/^wg_apply_runtime_conf\(\)/' "$BUILT" | grep -q 'ip route del "\$old" dev "\$iface"' \
   && awk '/^wg_shared_sync_gateway_routes\(\)/,/^wg_apply_runtime_conf\(\)/' "$BUILT" | grep -q 'ip route replace "\$old" dev "\$iface"' \
   && awk '/^wg_shared_sync_gateway_routes\(\)/,/^wg_apply_runtime_conf\(\)/' "$BUILT" | grep -q 'ip -6 route del "\$old" dev "\$iface"' \
   && awk '/^wg_shared_sync_gateway_routes\(\)/,/^wg_apply_runtime_conf\(\)/' "$BUILT" | grep -q 'ip -6 route replace "\$old" dev "\$iface"'; then
    pass "WG: syncconf 后同步受管 gateway LAN 路由并清理 stale route"
else
    fail "WG: syncconf 后缺少受管 gateway LAN 路由同步/清理"
fi
wg_import_body=$(awk '/^wg_import_peers\(\)/,/^wg_server_menu\(\)/' "$BUILT")
wg_deb_import_body=$(awk '/^wg_deb_import_peers\(\)/,/^wg_deb_server_menu\(\)/' "$BUILT")
wg_watchdog_body=$(awk '/^wg_setup_watchdog\(\)/,/^wg_export_peers\(\)/' "$BUILT")
wg_deb_watchdog_body=$(awk '/^wg_deb_setup_watchdog\(\)/,/^wg_deb_export_peers\(\)/' "$BUILT")
if grep -q '^_wg_openwrt_import_restore_snapshot()' "$BUILT" \
   && echo "$wg_import_body" | grep -q '_wg_openwrt_import_restore_snapshot "\$db_snapshot" "\$client_backup/clients"' \
   && echo "$wg_import_body" | grep -q 'if ! wg_rebuild_uci_conf "no_reload" || ! wg_apply_runtime_conf || ! wg_regenerate_client_confs'; then
    pass "WG/OpenWrt: 导入 peer 失败会恢复 DB/客户端配置快照"
else
    fail "WG/OpenWrt: 导入 peer 失败缺少事务恢复"
fi
if grep -q '^_wg_deb_import_restore_snapshot()' "$BUILT" \
   && echo "$wg_deb_import_body" | grep -q '_wg_deb_import_restore_snapshot "\$db_snapshot" "\$client_backup/clients"' \
   && echo "$wg_deb_import_body" | grep -q 'if ! wg_deb_apply_conf'; then
    pass "WG/Debian: 导入 peer 失败会恢复 DB/客户端配置快照"
else
    fail "WG/Debian: 导入 peer 失败缺少事务恢复"
fi
if echo "$wg_watchdog_body" | grep -q 'if ! cron_add_job_command "\$watchdog_script"' \
   && echo "$wg_watchdog_body" | grep -q 'rm -f "\$watchdog_script"' \
   && echo "$wg_watchdog_body" | grep -q 'sh "\$watchdog_script"' \
   && echo "$wg_deb_watchdog_body" | grep -q 'if ! cron_add_job_command "\$watchdog_script"' \
   && echo "$wg_deb_watchdog_body" | grep -q 'rm -f "\$watchdog_script"'; then
    pass "WG: watchdog cron 安装失败会返回错误并清理脚本"
else
    fail "WG: watchdog cron 安装失败仍可能误报成功或残留脚本"
fi
if grep -qE '/tmp/reality-sni-check(\.|/)|/tmp/reality-selftest-curl\.log|/tmp/reality-client-test\.|/tmp/certbot-renew\.log' "$BUILT"; then
    fail "LOW: Reality/Web 仍使用固定 /tmp 日志文件"
else
    pass "LOW: Reality/Web 不再使用固定 /tmp 日志文件"
fi
reality_self_test_body=$(awk '/^reality_local_client_self_test\(\)/,/^reality_require_supported_os\(\)/' "$BUILT")
if echo "$reality_self_test_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/reality-client-test.XXXXXX"' \
   && echo "$reality_self_test_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$reality_self_test_body" | grep -q 'umask 077' \
   && echo "$reality_self_test_body" | grep -q 'rm -rf "\$tmp_dir"'; then
    pass "LOW: Reality 本机自测敏感日志使用私有临时目录并清理"
else
    fail "LOW: Reality 本机自测仍可能散落敏感临时文件"
fi
reality_one_artifact_body=$(awk '/^reality_write_one_client_artifact\(\)/,/^reality_write_client_artifacts\(\)/' "$BUILT")
reality_client_artifacts_body=$(awk '/^reality_write_client_artifacts\(\)/,/^reality_has_local_public_ipv4\(\)/' "$BUILT")
reality_cdn_artifact_body=$(awk '/^reality_cdn_write_client_artifacts\(\)/,/^reality_cdn_nginx_site_name\(\)/' "$BUILT")
reality_relay_artifact_body=$(awk '/^reality_relay_write_client_artifacts\(\)/,/^reality_render_realm_config_multi\(\)/' "$BUILT")
if echo "$reality_one_artifact_body" | grep -q 'reality_write_secure_file "\$link_path"' \
   && echo "$reality_one_artifact_body" | grep -q 'reality_write_secure_file "\$json_path"' \
   && echo "$reality_client_artifacts_body" | grep -q 'reality_write_secure_file "\$REALITY_LINK_FILE"' \
   && echo "$reality_client_artifacts_body" | grep -q 'reality_write_secure_file "\$REALITY_CLIENT_JSON"' \
   && echo "$reality_cdn_artifact_body" | grep -q 'reality_write_secure_file "\$REALITY_CDN_LINK_FILE"' \
   && echo "$reality_cdn_artifact_body" | grep -q 'reality_write_secure_file "\$REALITY_CDN_CLIENT_JSON"' \
   && echo "$reality_relay_artifact_body" | grep -q 'reality_write_secure_file "\$link_path"' \
   && echo "$reality_relay_artifact_body" | grep -q 'reality_write_secure_file "\$json_path"' \
   && ! echo "$reality_one_artifact_body$reality_client_artifacts_body$reality_cdn_artifact_body$reality_relay_artifact_body" | grep -Eq '> "\$REALITY_.*(LINK|JSON)|cat > "\$.*(link|json|JSON)'; then
    pass "LOW: Reality 客户端产物走私有原子写入"
else
    fail "LOW: Reality 客户端产物仍可能先宽权限写入再 chmod"
fi
reality_prompt_sni_body=$(awk '/^reality_prompt_sni_legacy\(\)/,/^if ! declare -F reality_prompt_sni/' "$BUILT")
if grep -q '^reality_cleanup_sni_check_log()' "$BUILT" \
   && echo "$reality_prompt_sni_body" | grep -q 'reality_cleanup_sni_check_log' \
   && echo "$reality_diag_body" | grep -q 'reality_cleanup_sni_check_log' \
   && grep -q 'rm -rf -- "\$REALITY_SNI_CHECK_DIR"' "$BUILT"; then
    pass "LOW: Reality SNI 校验临时日志会在诊断输出后清理"
else
    fail "LOW: Reality SNI 校验临时日志缺少清理路径"
fi
if grep -qE '/tmp/v2ray-agent-install\.sh|/tmp/reality-fallback-pool\.txt|/tmp/bulianglin-sni-pool\.txt' "$BUILT" \
   || grep -qE '/tmp/v2ray-agent-install\.sh|/tmp/reality-fallback-pool\.txt|/tmp/bulianglin-sni-pool\.txt' modules/enhancements/*.sh; then
    fail "LOW: Reality SNI 增强仍使用固定 /tmp 候选池/下载文件"
else
    pass "LOW: Reality SNI 增强不再使用固定 /tmp 候选池/下载文件"
fi
web_snap_purge_body=$(awk '/^_purge_snap_certbot\(\)/,/^_install_certbot_apt\(\)/' "$BUILT")
if echo "$web_snap_purge_body" | grep -Eq 'rm -rf .*(/snap|/var/snap|/var/lib/snapd|~/snap)'; then
    fail "LOW: Web certbot 清理仍可能删除整个 snap 数据目录"
else
    pass "LOW: Web certbot 清理不再删除整个 snap 数据目录"
fi
web_cleanup_domain_body=$(awk '/^_web_cleanup_domain\(\)/,/^}/' "$BUILT")
if echo "$web_cleanup_domain_body" | grep -q 'validate_domain "\$domain"' \
   && echo "$web_cleanup_domain_body" | grep -q 'grep -Fq -- "\$domain"' \
   && echo "$web_cleanup_domain_body" | grep -q 'cert_prefix='; then
    pass "LOW: Web 域名清理先校验域名并按固定字符串匹配证书"
else
    fail "LOW: Web 域名清理缺少域名校验或固定字符串匹配"
fi
if echo "$web_cleanup_domain_body" | grep -Fq 'for hook in "${CERT_HOOKS_DIR}/renew-${domain}.sh" "/root/cert-renew-hook-${domain}.sh"; do' \
   && echo "$web_cleanup_domain_body" | grep -Fq 'hook_cleaned=true'; then
    pass "LOW: Web 域名清理覆盖新旧续签 hook 路径"
else
    fail "LOW: Web 域名清理未同时覆盖新旧续签 hook 路径"
fi
if grep -q '_CACHED_IPV[46]' "$BUILT"; then
    fail "P6: Web 公网 IP 缓存仍使用独立 _CACHED_IPV4/_CACHED_IPV6"
else
    pass "P6: Web 公网 IP 缓存复用全局 CACHED_IPV4/CACHED_IPV6"
fi
reality_status_body=$(awk '/^reality_status\(\)/,/^reality_diagnose\(\)/' "$BUILT")
if echo "$reality_status_body" | grep -q 'status sing-box .*| sed .*|| print_warn'; then
    fail "Reality: status 不可达失败分支仍由 sed 管道退出码遮蔽"
else
    pass "Reality: status 先检查 systemctl 返回码再输出摘要"
fi

echo ""
echo "== 结果 =="
echo "  PASS=$PASS  FAIL=$FAIL"
rm -rf "$TMP_SMOKE_ROOT"
exit $FAIL
