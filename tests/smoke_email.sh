#!/bin/bash
# 远程冒烟测试：email 模块（不触发任何 CF API 调用，不实际部署）
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

# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || { echo "source 失败"; exit 1; }

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

# 测危险字符是否被触发（如果 quote 失败，rm -rf / 会被执行；用 -d /test_marker_dir 检查）
touch /tmp/email_test_marker_$$
ZONE_BEFORE="$EMAIL_ZONE_ID"
unset EMAIL_INSTALLED EMAIL_ZONE_ID
email_state_load && pass "state 重新加载成功" || fail "state 重新加载失败"
if [[ -f /tmp/email_test_marker_$$ ]]; then
    pass "危险字符未触发命令执行 (marker 仍在)"
    rm -f /tmp/email_test_marker_$$
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
echo "== 结果 =="
echo "  PASS=$PASS  FAIL=$FAIL"
rm -f "$LIB" "$EMAIL_STATE_FILE"
exit $FAIL
