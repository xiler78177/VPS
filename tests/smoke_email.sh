#!/bin/bash
# 远程冒烟测试：email 模块（不触发任何 CF API 调用，不实际部署）
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILT="${BUILT:-$ROOT/dist/v4-built.sh}"
TMP_EMAIL_ROOT=$(mktemp -d)
EMAIL_TEST_OUT_DIR="$TMP_EMAIL_ROOT/out"
LIB="$TMP_EMAIL_ROOT/v4-lib.sh"
PASS=0; FAIL=0
mkdir -p "$EMAIL_TEST_OUT_DIR"
export EMAIL_TEST_OUT_DIR
trap 'rm -rf "$TMP_EMAIL_ROOT"' EXIT

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

head -n -1 "$BUILT" > "$LIB"
cat >> "$LIB" <<'STUB'
install_package() { return 0; }
auto_deps() { return 0; }
STUB
sed -i \
    -e "s|^readonly EMAIL_STATE_DIR=.*|readonly EMAIL_STATE_DIR=\"$TMP_EMAIL_ROOT/state\"|" \
    -e "s|^readonly EMAIL_ADMIN_FILE=.*|readonly EMAIL_ADMIN_FILE=\"$TMP_EMAIL_ROOT/email-admin.txt\"|" \
    -e "s|^readonly EMAIL_LOG_FILE=.*|readonly EMAIL_LOG_FILE=\"$TMP_EMAIL_ROOT/email.log\"|" \
    -e "s|^readonly EMAIL_INSTALL_DIR=.*|readonly EMAIL_INSTALL_DIR=\"$TMP_EMAIL_ROOT/install\"|" \
    "$LIB"

# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || { echo "source 失败"; exit 1; }
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    # 本地 Git Bash/非 root 环境没有 root owner；只在本地跳过 owner 检查，远端 root 冒烟仍走严格校验。
    PLATFORM="openwrt"
    chown() { return 0; }
fi

echo "== Test 1: state quote / write / load roundtrip =="
# 给一组刁钻字段
EMAIL_INSTALLED=1
EMAIL_INSTALL_VERSION='v1.2.3-rc"with"quote'
EMAIL_DOMAIN='example.com'
EMAIL_ZONE_ID='abc"$(rm -rf /)def'
EMAIL_API_DOMAIN='mail-api.example.com'
EMAIL_FRONTEND_DOMAIN='mail.example.com'
EMAIL_API_PREFIX='mail-api'
EMAIL_FRONTEND_PREFIX='mail'
EMAIL_ADDRESS_PREFIX=''
EMAIL_WORKER_NAME='cloudflare_temp_email'
EMAIL_PAGES_PROJECT='temp-email-pages'
EMAIL_PAGES_DOMAIN='temp-email-pages.pages.dev'
EMAIL_D1_NAME='temp-email-a1b2c3'
EMAIL_D1_ID='aaaa-bbbb'
EMAIL_RESEND_ENABLED=1
EMAIL_RESEND_SEND_DOMAIN='send.example.com'
EMAIL_DNS_FRONTEND_ID='r1'
EMAIL_DNS_MX1_ID='r2'
EMAIL_DNS_MX2_ID='r3'
EMAIL_DNS_MX3_ID='r4'
EMAIL_DNS_DKIM_ID='r5'
EMAIL_DNS_SPF_ID='r6'
EMAIL_DNS_SEND_MX_ID='r7'
EMAIL_DNS_DMARC_ID='r8'
EMAIL_CATCH_ALL_ENABLED=1
EMAIL_INSTALL_DATE='2026-05-24 10:00:00'
EMAIL_PATCHES_APPLIED='schema.sql 2024-01-13-patch.sql'

email_state_write && pass "state 写入成功" || fail "state 写入失败"

# 校验写出的文件不会触发命令替换（用新 validate_conf_file）
validate_conf_file "$EMAIL_STATE_FILE" 2>/dev/null && pass "写出文件通过 validate_conf_file" || fail "写出文件未通过校验"

# 测危险字符是否被触发（如果 quote 失败，marker 会被删除）
EMAIL_TEST_MARKER="$TMP_EMAIL_ROOT/email_test_marker_$$"
touch "$EMAIL_TEST_MARKER"
ZONE_BEFORE="$EMAIL_ZONE_ID"
unset EMAIL_INSTALLED EMAIL_ZONE_ID
email_state_load && pass "state 重新加载成功" || fail "state 重新加载失败"
if [[ -f "$EMAIL_TEST_MARKER" ]]; then
    pass "危险字符未触发命令执行 (marker 仍在)"
    rm -f "$EMAIL_TEST_MARKER"
else
    fail "marker 消失 — 危险字符可能触发了命令"
fi
if [[ "$EMAIL_ZONE_ID" == "$ZONE_BEFORE" ]]; then
    pass "ZONE_ID round-trip 一致"
else
    fail "ZONE_ID 不一致: got='$EMAIL_ZONE_ID' want='$ZONE_BEFORE'"
fi

echo ""
echo "== Test 2: email_mask_token =="
m=$(email_mask_token "")
[[ "$m" == "****" ]] && pass "空 token → ****" || fail "空 token 应 ****, got '$m'"
m=$(email_mask_token "abc")
[[ "$m" == "****" ]] && pass "短 token → ****" || fail "短 token 应 ****, got '$m'"
m=$(email_mask_token "abcdefghijkl1234")
[[ "$m" == "abcd****1234" ]] && pass "长 token mask 正确" || fail "长 token mask 错误: $m"

echo ""
echo "== Test 3: _email_cf_api 缺 Token 应安全返回 =="
unset CF_API_TOKEN
out=$(_email_cf_api GET "user/tokens/verify" 2>&1)
rc=$?
[[ $rc -ne 0 ]] && pass "缺 Token 返回非零 (rc=$rc)" || fail "缺 Token 应返回错误"

echo ""
echo "== Test 3b: email_run 保留失败命令退出码 =="
email_run "预期失败命令" bash -c 'exit 7' >/dev/null 2>&1
rc=$?
[[ $rc -eq 7 ]] && pass "email_run 返回真实失败码 7" || fail "email_run 返回码错误: $rc (应为 7)"

echo ""
echo "== Test 4: 主菜单 11. 项已变 =="
grep -q '10. 临时邮箱 (Cloudflare)' "$BUILT" && pass "主菜单仍含临时邮箱入口" || fail "主菜单丢失邮箱入口"

echo ""
echo "== Test 5: 旧版痕迹清零 =="
grep -nE 'python3 -c .import sys,json' "$BUILT" >/dev/null \
    && fail "仍有 python3 JSON 解析（应全部替换为 jq）" \
    || pass "python3 JSON 解析已清零"

grep -nE 'eval \$cmd' "$BUILT" >/dev/null \
    && fail "仍有 eval \$cmd" \
    || pass "ssh eval 已无残留"

grep -nE 'menu_backup|backup_create' "$BUILT" >/dev/null \
    && fail "仍有 backup 残留" \
    || pass "backup 模块清零"

echo ""
echo "== Test 6: 关键函数齐备 =="
required=(email_deploy email_status email_view_log email_uninstall menu_email
          email_manage_change_admin_password email_manage_domains
          email_manage_resend email_manage_upgrade email_manage_redeploy
          email_state_write email_state_load email_state_clear email_mask_token
          email_save_admin_password email_read_secret email_run
          _email_cf_api _email_cf_token_verify _email_cf_zone_id_by_name
          _email_cf_dns_create _email_cf_dns_delete _email_cf_dns_purge
          _email_cf_pages_project_create _email_cf_pages_project_delete
          _email_cf_pages_get_subdomain _email_cf_pages_attach_domain
          _email_cf_worker_delete _email_cf_worker_secret_put _email_cf_worker_exists
          _email_cf_pages_project_exists _email_cf_d1_delete
          _email_cf_email_routing_enable _email_cf_catch_all_to_worker _email_cf_catch_all_disable
          _email_cf_account_first_id _email_cf_accounts_list
          _email_deploy_pick_account _email_deploy_pick_worker_name
          _email_validate_dns_label)
for fn in "${required[@]}"; do
    if declare -F "$fn" >/dev/null; then
        :
    else
        fail "缺函数: $fn"
    fi
done
[[ $FAIL -eq 0 ]] && pass "全部 ${#required[@]} 个函数已定义" || true

echo ""
echo "== Test 7: review #31 邮箱高优先回归 =="
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_E1_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
pause() { :; }
confirm() { return 0; }
_email_cf_token_verify() { return 0; }
_email_export_wrangler_env() { :; }
_email_uninstall_delete_dns() { return 0; }
_email_cf_catch_all_disable() { return 0; }
_email_cf_worker_delete() { return 0; }
_email_cf_pages_project_delete() { return 0; }
_email_cf_d1_delete() { return 23; }

mkdir -p "$EMAIL_INSTALL_DIR"
printf 'admin_password=old\n' > "$EMAIL_ADMIN_FILE"
EMAIL_INSTALLED=1
EMAIL_DOMAIN='e1.example.com'
EMAIL_ZONE_ID='zone-e1'
EMAIL_CF_ACCOUNT_ID='acct-e1'
EMAIL_WORKER_NAME='worker-e1'
EMAIL_PAGES_PROJECT='pages-e1'
EMAIL_D1_NAME='d1-e1'
EMAIL_D1_ID='d1-id-e1'
EMAIL_CATCH_ALL_ENABLED=0
email_state_write || exit 11
CF_API_TOKEN='token-e1'
CF_ACCOUNT_ID='acct-e1'
printf '%s\n' "$EMAIL_DOMAIN" | email_uninstall >"$EMAIL_TEST_OUT_DIR/email-e1.out" 2>&1 || true
[[ -f "$EMAIL_STATE_FILE" ]] || exit 1
[[ -d "$EMAIL_INSTALL_DIR" ]] || exit 2
[[ -f "$EMAIL_ADMIN_FILE" ]] || exit 3
exit 0
EMAIL_E1_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "E1: D1 远端删除失败时保留 state/本地目录/管理员文件"
else
    fail "E1: D1 远端删除失败仍清理了 state 或本地资源"
fi
rm -f "$tmp_email_script"

tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_E6_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
pause() { :; }
confirm() { return 0; }
_email_cf_token_verify() { return 0; }
_email_export_wrangler_env() { :; }
_email_patch_pages_service_binding() { return 0; }
_email_wrangler() {
    local file="" arg base
    for arg in "$@"; do
        case "$arg" in --file=*) file="${arg#--file=}" ;; esac
    done
    base=$(basename "$file")
    case "$base" in
        001-patch.sql) return 0 ;;
        002-patch.sql) return 44 ;;
    esac
    return 0
}

mock_bin=$(mktemp -d)
cat > "$mock_bin/git" <<'GITMOCK'
#!/bin/bash
args="$*"
case "$args" in
  *"rev-list --tags --max-count=1"*) echo "abc123"; exit 0 ;;
  *"describe --tags"*) echo "v9.9.9"; exit 0 ;;
  *) exit 0 ;;
esac
GITMOCK
cat > "$mock_bin/pnpm" <<'PNPMMOCK'
#!/bin/bash
exit 0
PNPMMOCK
chmod +x "$mock_bin/git" "$mock_bin/pnpm"
export PATH="$mock_bin:$PATH"

mkdir -p "$EMAIL_INSTALL_DIR/worker" "$EMAIL_INSTALL_DIR/db" "$EMAIL_INSTALL_DIR/frontend" "$EMAIL_INSTALL_DIR/pages"
printf 'alter table a add column b;\n' > "$EMAIL_INSTALL_DIR/db/001-patch.sql"
printf 'alter table a add column c;\n' > "$EMAIL_INSTALL_DIR/db/002-patch.sql"
EMAIL_INSTALLED=1
EMAIL_INSTALL_VERSION='v1.0.0'
EMAIL_DOMAIN='e6.example.com'
EMAIL_CF_ACCOUNT_ID='acct-e6'
EMAIL_WORKER_NAME='worker-e6'
EMAIL_D1_NAME='d1-e6'
EMAIL_PATCHES_APPLIED=''
email_state_write || exit 11
CF_API_TOKEN='token-e6'
CF_ACCOUNT_ID='acct-e6'
email_manage_upgrade >"$EMAIL_TEST_OUT_DIR/email-e6.out" 2>&1 || true
grep -q 'EMAIL_PATCHES_APPLIED="001-patch.sql"' "$EMAIL_STATE_FILE" || exit 1
rm -rf "$mock_bin"
exit 0
EMAIL_E6_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "E6: D1 patch 成功后立即持久化进度，后续 patch 失败可安全重跑"
else
    fail "E6: D1 patch 成功后未持久化进度"
fi
rm -f "$tmp_email_script"

worker_exists_body=$(awk '/^_email_cf_worker_exists\(\)/,/^}/' "$BUILT")
echo "$worker_exists_body" | grep -q '%{http_code}' \
    && echo "$worker_exists_body" | grep -q 'return 2' \
    && pass "P1-Email: worker_exists 使用 HTTP 状态区分存在/不存在/未知" \
    || fail "P1-Email: worker_exists 仍未实现三态"

tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_P1_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
_email_cf_worker_exists() { return 2; }
EMAIL_WORKER_NAME=""
if _email_deploy_pick_worker_name </dev/null >"$EMAIL_TEST_OUT_DIR/email-p1.out" 2>&1; then
    exit 1
fi
[[ -z "$EMAIL_WORKER_NAME" ]] || exit 2
exit 0
EMAIL_P1_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "P1-Email: Worker 存在性未知时部署命名 fail-closed"
else
    fail "P1-Email: Worker 存在性未知时仍可能使用默认名覆盖"
fi
rm -f "$tmp_email_script"

echo ""
echo "== Test 8: review #32 邮箱剩余高优先回归 =="
# E2: CF/Wrangler 环境变量必须有统一清理 helper，且公开入口设置 RETURN 清理，避免后续子进程继承凭据。
grep -q '^_email_clear_sensitive_env()' "$BUILT" \
    && pass "E2: 已定义敏感环境变量清理 helper" \
    || fail "E2: 缺少敏感环境变量清理 helper"
for _fn in email_deploy email_uninstall email_manage_change_admin_password email_manage_domains email_manage_resend email_manage_upgrade email_manage_redeploy; do
    _body=$(awk "/^${_fn}\\(\\)/,/^}/" "$BUILT")
    echo "$_body" | grep -q "trap '_email_clear_sensitive_env' RETURN" \
        && pass "E2: ${_fn} 设置 RETURN 清理敏感环境变量" \
        || fail "E2: ${_fn} 未设置 RETURN 清理敏感环境变量"
done
clear_body=$(awk '/^_email_clear_sensitive_env\(\)/,/^}/' "$BUILT")
echo "$clear_body" | grep -q 'CLOUDFLARE_API_TOKEN' \
    && echo "$clear_body" | grep -q 'CLOUDFLARE_ACCOUNT_ID' \
    && pass "E2: 清理 helper 覆盖 Wrangler CLOUDFLARE_* 环境变量" \
    || fail "E2: 清理 helper 未覆盖 CLOUDFLARE_* 环境变量"

# E3: NodeSource 安装链路必须检查 curl|bash 管道失败，不能只取 apt-get 退出码。
env_body=$(awk '/^_email_deploy_check_env\(\)/,/^}/' "$BUILT")
if echo "$env_body" | grep -q 'curl -fsSL https://deb.nodesource.com/setup_lts.x | bash'; then
    fail "E3: NodeSource 仍用未开启 pipefail 的 curl|bash"
else
    pass "E3: NodeSource 不再使用裸 curl|bash 管道"
fi
echo "$env_body" | grep -q 'bash -o pipefail' \
    && pass "E3: NodeSource 安装开启 pipefail" \
    || fail "E3: NodeSource 安装未开启 pipefail"
if echo "$env_body" | grep -q 'mktemp -d "\${TMPDIR:-/tmp}/server-manage-email-node.XXXXXX"' \
   && echo "$env_body" | grep -q 'chmod 700 "\$tmp_dir"' \
   && echo "$env_body" | grep -q 'chmod 600 "\$tmp"' \
   && echo "$env_body" | grep -q 'rm -rf "\$tmp_dir"' \
   && ! echo "$env_body" | grep -q 'tmp=$(mktemp)'; then
    pass "E3: NodeSource 安装脚本使用私有临时目录并清理"
else
    fail "E3: NodeSource 安装脚本仍可能落公共临时文件"
fi

# E4: 首次 Worker deploy 前 wrangler.toml 已包含 ADMIN_PASSWORDS 普通变量兜底，secret 写入失败也不会出现无密码窗口。
render_body=$(awk '/^_email_deploy_render_toml\(\)/,/^}/' "$BUILT")
min_render_body=$(awk '/^_email_render_min_toml\(\)/,/^}/' "$BUILT")
echo "$render_body" | grep -q 'ADMIN_PASSWORDS = ' \
    && pass "E4: Worker 首次部署配置含 ADMIN_PASSWORDS 兜底变量" \
    || fail "E4: Worker 首次部署前未配置 ADMIN_PASSWORDS"
if declare -F _email_write_private_file >/dev/null \
   && echo "$min_render_body" | grep -q '_email_write_private_file "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"' \
   && echo "$render_body" | grep -q '_email_write_private_file "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"' \
   && ! echo "$min_render_body$render_body" | grep -q 'cat > "\$EMAIL_INSTALL_DIR/worker/wrangler.toml"'; then
    pass "E4: wrangler.toml 渲染走私有原子写入"
else
    fail "E4: wrangler.toml 渲染仍可能先宽权限写入再 chmod"
fi
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_E4_PERM_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
jq() { printf '%s\n' '["admin-pass"]'; }
mode_is_600() {
    local file="$1" mode
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
    esac
    mode="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)"
    [[ "$mode" == "600" ]]
}
mkdir -p "$EMAIL_INSTALL_DIR/worker"
umask 022
EMAIL_WORKER_NAME="worker-e4"
EMAIL_D1_NAME="d1-e4"
EMAIL_D1_ID="d1-id-e4"
_email_render_min_toml || exit 11
mode_is_600 "$EMAIL_INSTALL_DIR/worker/wrangler.toml" || exit 12
EMAIL_DOMAIN="example.com"
EMAIL_API_DOMAIN="api.example.com"
EMAIL_ADDRESS_PREFIX="prefix"
EMAIL_ADMIN_PASSWORD="admin-pass"
EMAIL_JWT_SECRET="jwt-e4"
_email_deploy_render_toml >/dev/null || exit 13
mode_is_600 "$EMAIL_INSTALL_DIR/worker/wrangler.toml" || exit 14
grep -Fxq 'JWT_SECRET = "jwt-e4"' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" || exit 15
grep -Fxq 'ADMIN_PASSWORDS = ["admin-pass"]' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" || exit 16
EMAIL_E4_PERM_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "E4: wrangler.toml 在宽 umask 下仍以 0600 写出"
else
    fail "E4: wrangler.toml 私有权限写入实测失败"
fi
rm -f "$tmp_email_script"

# E5: pages service binding 不能长期 dirty git tracked wrangler.toml；patch 后必须恢复，且 helper 不应再用 sed -i 原地改。
patch_body=$(awk '/^_email_patch_pages_service_binding\(\)/,/^}/' "$BUILT")
restore_body=$(awk '/^_email_restore_pages_service_binding\(\)/,/^}/' "$BUILT")
if echo "$patch_body" | grep -q 'sed -i'; then
    fail "E5: pages service binding 仍用 sed -i 原地修改 tracked wrangler.toml"
else
    pass "E5: pages service binding 不再用 sed -i 原地修改"
fi
if echo "$patch_body" | grep -q '/tmp/server-manage-pages-wrangler'; then
    fail "E5: pages/wrangler.toml 备份仍落公共 /tmp"
elif echo "$patch_body" | grep -q 'mktemp "\${pages_dir}/.wrangler.toml.bak.XXXXXX"'; then
    pass "E5: pages/wrangler.toml 备份落 pages 同目录"
else
    fail "E5: pages/wrangler.toml 备份缺少同目录 mktemp"
fi
grep -q '^_email_restore_pages_service_binding()' "$BUILT" \
    && echo "$restore_body" | grep -q 'mv .*wrangler.toml' \
    && pass "E5: 已定义 pages/wrangler.toml 恢复 helper" \
    || fail "E5: 缺少 pages/wrangler.toml 恢复 helper"
pages_body=$(awk '/^_email_deploy_pages\(\)/,/^}/' "$BUILT")
upgrade_body=$(awk '/^email_manage_upgrade\(\)/,/^email_manage_redeploy\(\)/' "$BUILT")
redeploy_body=$(awk '/^email_manage_redeploy\(\)/,/^}/' "$BUILT")
echo "$pages_body" | grep -q '_email_restore_pages_service_binding' \
    && echo "$upgrade_body" | grep -q '_email_restore_pages_service_binding' \
    && echo "$redeploy_body" | grep -q '_email_restore_pages_service_binding' \
    && pass "E5: 部署/升级/重部署后恢复 pages/wrangler.toml" \
    || fail "E5: 存在部署路径未恢复 pages/wrangler.toml"
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_E5_PATCH_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
chown() { return 0; }
EMAIL_WORKER_NAME="custom-worker"
mkdir -p "$EMAIL_INSTALL_DIR/pages"
cat > "$EMAIL_INSTALL_DIR/pages/wrangler.toml" <<'EOF'
name = "pages-app"
[[services]]
binding = "TEMP_EMAIL"
service = "cloudflare_temp_email"
EOF
_email_patch_pages_service_binding "$EMAIL_INSTALL_DIR/pages" || exit 11
backup="${EMAIL_PAGES_TOML_BACKUP:-}"
target="${EMAIL_PAGES_TOML_BACKUP_TARGET:-}"
[[ "$backup" == "$EMAIL_INSTALL_DIR/pages"/.wrangler.toml.bak.* ]] || exit 12
[[ "$target" == "$EMAIL_INSTALL_DIR/pages/wrangler.toml" ]] || exit 13
grep -Fxq 'service = "custom-worker"' "$target" || exit 14
_email_restore_pages_service_binding || exit 15
grep -Fxq 'service = "cloudflare_temp_email"' "$target" || exit 16
find "$EMAIL_INSTALL_DIR/pages" -maxdepth 1 -name '.wrangler.toml.bak.*' -print -quit | grep -q . && exit 17
exit 0
EMAIL_E5_PATCH_TEST
if bash "$tmp_email_script" "$LIB" "$TMP_EMAIL_ROOT"; then
    pass "E5: pages/wrangler.toml patch/restore 使用同目录备份且无残留"
else
    fail "E5: pages/wrangler.toml patch/restore 同目录备份实测失败"
fi
rm -f "$tmp_email_script"

# E7: 已安装状态再次进入部署必须 fail-closed，不能生成新随机 D1/Pages 丢弃旧资源 ID。
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_E7_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
pause() { :; }
confirm() { return 0; }
_email_deploy_check_env() { touch "$EMAIL_STATE_DIR/should-not-run"; return 0; }
EMAIL_INSTALLED=1
EMAIL_DOMAIN='e7.example.com'
EMAIL_FRONTEND_DOMAIN='mail.e7.example.com'
EMAIL_API_DOMAIN='mail-api.e7.example.com'
EMAIL_D1_NAME='old-d1'
EMAIL_D1_ID='old-d1-id'
EMAIL_PAGES_PROJECT='old-pages'
EMAIL_WORKER_NAME='old-worker'
email_state_write || exit 11
email_deploy >"$EMAIL_TEST_OUT_DIR/email-e7.out" 2>&1 || true
[[ ! -f "$EMAIL_STATE_DIR/should-not-run" ]] || exit 1
grep -q 'EMAIL_D1_NAME="old-d1"' "$EMAIL_STATE_FILE" || exit 2
grep -q 'EMAIL_PAGES_PROJECT="old-pages"' "$EMAIL_STATE_FILE" || exit 3
exit 0
EMAIL_E7_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "E7: 已安装状态部署入口不覆盖旧 D1/Pages state"
else
    fail "E7: 已安装状态部署仍可能覆盖旧资源 state"
fi
rm -f "$tmp_email_script"

echo ""
echo "== Test 9: 邮箱低危/质量回归 =="
# L1: ADMIN_PASSWORDS 普通变量回退不能通过 awk -v 吃掉反斜杠。
mkdir -p "$EMAIL_INSTALL_DIR/worker"
cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'TOML'
name = "worker-test"
[vars]
ADMIN_PASSWORDS = ["old"]
JWT_SECRET = "keep"
TOML
email_run() { return 0; }
_email_export_wrangler_env() { :; }
admin_json='["pa\\ss"]'
if _email_manage_update_admin_passwords_var "$admin_json" >/dev/null 2>&1 \
   && grep -Fxq 'ADMIN_PASSWORDS = ["pa\\ss"]' "$EMAIL_INSTALL_DIR/worker/wrangler.toml"; then
    pass "L1: ADMIN_PASSWORDS 普通变量保留反斜杠字面量"
else
    fail "L1: ADMIN_PASSWORDS 普通变量写入会破坏反斜杠"
    sed 's/^/    /' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null || true
fi
if find "$EMAIL_INSTALL_DIR/worker" -maxdepth 1 -name 'wrangler.toml.tmp' -print -quit | grep -q .; then
    fail "L1b: ADMIN_PASSWORDS fallback 留下可预测 wrangler.toml.tmp"
else
    pass "L1b: ADMIN_PASSWORDS fallback 不留下可预测临时文件"
fi

# L6: 首次部署 Resend/Email DNS 失败必须 fail-closed，不能把半成品标成已启用/已成功。
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_L6_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
jq() { printf '["admin-pass"]\n'; }
print_info() { :; }
print_success() { :; }
print_warn() { :; }
print_error() { :; }
email_log() { :; }
log_action() { :; }
email_save_admin_password() { :; }

log="$2"
_email_state_reset_vars
EMAIL_DOMAIN="example.com"
EMAIL_ZONE_ID="zone-test"
EMAIL_WORKER_NAME="worker-test"
EMAIL_ADMIN_PASSWORD="admin-pass"
EMAIL_RESEND_ENABLED=1
EMAIL_RESEND_SEND_DOMAIN="send.example.com"
EMAIL_RESEND_TOKEN="resend-token"
_email_cf_worker_secret_put() {
    printf 'secret|%s|%s|%s\n' "$1" "$2" "$3" >> "$log"
    [[ "$2" != "RESEND_TOKEN" ]]
}
if _email_deploy_secrets >/dev/null 2>&1; then exit 1; fi
grep -Fxq 'EMAIL_RESEND_ENABLED=0' "$EMAIL_STATE_FILE" || exit 2
grep -Fxq 'EMAIL_RESEND_SEND_DOMAIN=""' "$EMAIL_STATE_FILE" || exit 3
grep -Fxq 'secret|worker-test|RESEND_TOKEN|resend-token' "$log" || exit 4

: > "$log"
_email_state_reset_vars
EMAIL_DOMAIN="example.com"
EMAIL_ZONE_ID="zone-test"
EMAIL_FRONTEND_PREFIX="mail"
EMAIL_FRONTEND_DOMAIN="mail.example.com"
EMAIL_PAGES_DOMAIN="pages.example.dev"
EMAIL_RESEND_ENABLED=0
_email_cf_dns_purge() {
    printf 'purge|%s|%s\n' "$2" "$3" >> "$log"
    [[ "$2|$3" != "MX|example.com" ]]
}
_email_cf_dns_create_record_into() {
    printf 'create|%s|%s|%s\n' "$1" "$3" "$4" >> "$log"
    printf -v "$1" '%s-id' "$3"
    return 0
}
if _email_deploy_dns >/dev/null 2>&1; then exit 5; fi
grep -Fxq 'purge|MX|example.com' "$log" || exit 6
if grep -Fq 'create|EMAIL_DNS_MX' "$log"; then exit 7; fi

: > "$log"
_email_state_reset_vars
EMAIL_DOMAIN="example.com"
EMAIL_ZONE_ID="zone-test"
EMAIL_FRONTEND_PREFIX="mail"
EMAIL_FRONTEND_DOMAIN="mail.example.com"
EMAIL_PAGES_DOMAIN="pages.example.dev"
EMAIL_RESEND_ENABLED=1
EMAIL_RESEND_SEND_DOMAIN="send.example.com"
EMAIL_RESEND_DKIM="dkim-value"
_email_cf_dns_purge() {
    printf 'purge|%s|%s\n' "$2" "$3" >> "$log"
    return 0
}
_email_cf_dns_create_record_into() {
    printf 'create|%s|%s|%s\n' "$1" "$3" "$4" >> "$log"
    printf -v "$1" '%s-id' "$3"
    [[ "$1" != "EMAIL_DNS_SPF_ID" ]]
}
if _email_deploy_dns >/dev/null 2>&1; then exit 8; fi
grep -Fxq 'EMAIL_RESEND_ENABLED=0' "$EMAIL_STATE_FILE" || exit 9
grep -Fxq 'EMAIL_RESEND_SEND_DOMAIN=""' "$EMAIL_STATE_FILE" || exit 11
grep -Fq 'EMAIL_DNS_DKIM_ID=' "$EMAIL_STATE_FILE" || exit 12
grep -Fxq 'create|EMAIL_DNS_SPF_ID|TXT|send.example.com' "$log" || exit 13
exit 0
EMAIL_L6_TEST
email_l6_log="$TMP_EMAIL_ROOT/email-l6.log"
if bash "$tmp_email_script" "$LIB" "$email_l6_log"; then
    pass "L6: 首次部署 Resend/DNS 失败 fail-closed 并落 partial state"
else
    fail "L6: 首次部署 Resend/DNS 失败仍可能标记成功"
    sed 's/^/    /' "$email_l6_log" 2>/dev/null || true
fi
rm -f "$tmp_email_script" "$email_l6_log"

# L7: Pages 自定义域名绑定失败必须 fail-closed，不能继续把部署标记为完成。
tmp_email_script=$(mktemp)
cat > "$tmp_email_script" <<'EMAIL_L7_TEST'
#!/bin/bash
set -u
source "$1" >/dev/null 2>&1 || exit 10
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    PLATFORM="openwrt"
    chown() { return 0; }
fi
print_success() { :; }
print_warn() { :; }
print_error() { :; }
print_info() { :; }
email_run() { return 0; }
_email_patch_pages_service_binding() { return 0; }
_email_restore_pages_service_binding() { :; }
_email_cf_pages_project_create() { return 0; }
_email_wrangler() { return 0; }
_email_cf_pages_get_subdomain() { printf 'pages-mock.pages.dev\n'; }
_email_cf_pages_attach_domain() { return 1; }
mkdir -p "$EMAIL_INSTALL_DIR/pages"
_email_state_reset_vars
EMAIL_DOMAIN="example.com"
EMAIL_FRONTEND_DOMAIN="mail.example.com"
EMAIL_PAGES_PROJECT="pages-mock"
EMAIL_WORKER_NAME="worker-mock"
if _email_deploy_pages >/dev/null 2>&1; then exit 1; fi
grep -Fxq 'EMAIL_INSTALLED=0' "$EMAIL_STATE_FILE" || exit 2
grep -Fxq 'EMAIL_PAGES_PROJECT="pages-mock"' "$EMAIL_STATE_FILE" || exit 3
grep -Fxq 'EMAIL_PAGES_DOMAIN="pages-mock.pages.dev"' "$EMAIL_STATE_FILE" || exit 4
exit 0
EMAIL_L7_TEST
if bash "$tmp_email_script" "$LIB"; then
    pass "L7: Pages 自定义域名绑定失败 fail-closed 并落 partial state"
else
    fail "L7: Pages 自定义域名绑定失败仍可能继续部署"
fi
rm -f "$tmp_email_script"

# L2: DOMAINS 解析失败不能 fallback 成仅主域名后继续覆盖部署。
cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'TOML'
[vars]
DOMAINS = ["broken"
DEFAULT_DOMAINS = ["broken"
TOML
EMAIL_DOMAIN='primary.example.com'
EMAIL_API_DOMAIN='api.primary.example.com'
_email_manage_prepare() { return 0; }
pause() { :; }
before_domains=$(cat "$EMAIL_INSTALL_DIR/worker/wrangler.toml")
printf '1\nnew.example.com\n' | email_manage_domains >"$EMAIL_TEST_OUT_DIR/email-domains-invalid.out" 2>&1 || true
after_domains=$(cat "$EMAIL_INSTALL_DIR/worker/wrangler.toml")
if [[ "$after_domains" == "$before_domains" ]] \
   && grep -qi 'DOMAINS' "$EMAIL_TEST_OUT_DIR/email-domains-invalid.out"; then
    pass "L2: DOMAINS 解析失败时拒绝覆盖而非静默重置"
else
    fail "L2: DOMAINS 解析失败仍可能静默重置/覆盖"
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "  [SKIP] L4: 缺少 jq，跳过 DOMAINS 部署失败回滚实测"
else
cat > "$EMAIL_INSTALL_DIR/worker/wrangler.toml" <<'TOML'
[vars]
DOMAINS = ["primary.example.com"]
DEFAULT_DOMAINS = ["primary.example.com"]
TOML
    before_domains=$(cat "$EMAIL_INSTALL_DIR/worker/wrangler.toml")
    email_run() {
        case "$1" in
            "重新部署 Worker") return 31 ;;
            *) return 0 ;;
        esac
    }
    printf '1\nnew.example.com\n' | email_manage_domains >"$EMAIL_TEST_OUT_DIR/email-domains-deploy-fail.out" 2>&1 || true
    after_domains=$(cat "$EMAIL_INSTALL_DIR/worker/wrangler.toml")
    if [[ "$after_domains" == "$before_domains" ]] \
       && grep -q 'wrangler.toml 已恢复' "$EMAIL_TEST_OUT_DIR/email-domains-deploy-fail.out"; then
        pass "L4: DOMAINS Worker 部署失败时恢复 wrangler.toml"
    else
        fail "L4: DOMAINS 部署失败后未恢复 wrangler.toml"
        sed 's/^/    /' "$EMAIL_INSTALL_DIR/worker/wrangler.toml" 2>/dev/null || true
    fi
fi

manage_body=$(awk '/^email_manage_resend\(\)/,/^email_manage_upgrade\(\)/' "$BUILT")
echo "$manage_body" | grep -q 'echo -e "当前状态:' \
    && pass "L3: Resend 当前状态输出使用 echo -e 解析颜色" \
    || fail "L3: Resend 当前状态输出仍可能显示原始颜色转义"
upgrade_body=$(awk '/^email_manage_upgrade\(\)/,/^email_manage_redeploy\(\)/' "$BUILT")
echo "$upgrade_body" | grep -q 'old_version=' \
    && echo "$upgrade_body" | grep -q 'Email upgraded ${old_version} → $latest' \
    && pass "L5: 升级日志记录旧版本到新版本" \
    || fail "L5: 升级日志仍可能记录 X → X"

echo ""
echo "== 结果 =="
echo "  PASS=$PASS  FAIL=$FAIL"
rm -f "$LIB" "$EMAIL_STATE_FILE"
rm -rf "$TMP_EMAIL_ROOT"
exit $FAIL
