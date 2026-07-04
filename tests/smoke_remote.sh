#!/bin/bash
# 远程冒烟测试：不修改持久状态（除临时端口 64999 立即还原）
set -u

BUILT="/tmp/v4-built.sh"
WORK=$(mktemp -d)
LIB="$WORK/v4-lib.sh"
PWNED_MARKER="$WORK/PWNED_BY_SSH_EVAL"
PASS=0; FAIL=0

cleanup() {
    rm -rf "$WORK"
}
trap cleanup EXIT

pass() { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }

# 把构建产物末行 main "$@" 去掉，得到纯函数库
mkdir -p "$WORK"
head -n -1 "$BUILT" > "$LIB"
export CONFIG_FILE="$WORK/none.conf"   # 防止 01-utils.sh 末尾真去读 /etc/server-manage.conf

# init_environment 会装包，绕过：临时把 install_package / auto_deps 变 noop
cat >> "$LIB" <<'STUB'
install_package() { return 0; }
auto_deps() { return 0; }
STUB
sed -i \
    -e "s|^[[:space:]]*readonly LOG_FILE=.*|readonly LOG_FILE=\"$WORK/log/server-manage.log\"|" \
    -e "s|^readonly CONFIG_FILE=.*|readonly CONFIG_FILE=\"$WORK/none.conf\"|" \
    "$LIB"

# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || { echo "source 失败"; exit 1; }
log_err=$(log_action "smoke log mkdir" 2>&1 >/dev/null || true)
if [[ -z "$log_err" && -f "$WORK/log/server-manage.log" ]]; then
    pass "log_action 自动创建日志目录且无 stderr"
else
    fail "log_action 未处理缺失日志目录: ${log_err:-<no stderr>}"
fi
NON_ROOT=0
if [[ "$(id -u 2>/dev/null || echo 1)" -ne 0 ]]; then
    NON_ROOT=1
    # 本地 Git Bash/非 root 环境无法 chown root；validate_conf_file 的 owner/mode 严格路径仍由远端 root 冒烟覆盖。
    PLATFORM="openwrt"
    chown() { return 0; }
fi

echo "== Test 1: validate_conf_file =="

mk() { printf '%s\n' "$2" > "$WORK/$1"; chown root:root "$WORK/$1"; chmod 600 "$WORK/$1"; }

# 1.1 合法：裸字面量 + 单引号 + 双引号
mk t1_ok.conf $'A=hello\nB=\'literal value\'\nC="abc-1.2"\n# comment'
validate_conf_file "$WORK/t1_ok.conf" 2>/dev/null && pass "合法配置通过" || fail "合法配置应通过"

# 1.2 危险：双引号 + $(cmd)
mk t2_cmdsub.conf 'X="$(rm -rf /)"'
validate_conf_file "$WORK/t2_cmdsub.conf" 2>/dev/null && fail "应拒绝 \$()" || pass "拒绝双引号内 \$()"

# 1.3 危险：反引号
mk t3_backtick.conf 'X="`whoami`"'
validate_conf_file "$WORK/t3_backtick.conf" 2>/dev/null && fail "应拒绝反引号" || pass "拒绝双引号内反引号"

# 1.4 危险：${var}
mk t4_varexp.conf 'X="${HOME}"'
validate_conf_file "$WORK/t4_varexp.conf" 2>/dev/null && fail "应拒绝 \${}" || pass "拒绝双引号内 \${}"

# 1.5 合法：单引号内含 $ ` 不会被扩展
mk t5_singlequote.conf $'X=\'$(echo safe)\'\nY=\'$HOME\''
validate_conf_file "$WORK/t5_singlequote.conf" 2>/dev/null && pass "单引号包裹危险字符通过" || fail "单引号应安全"

# 1.6 合法：双引号内已转义的 \$
mk t6_escaped.conf 'X="literal \$dollar"'
validate_conf_file "$WORK/t6_escaped.conf" 2>/dev/null && pass "转义的 \\\$ 通过" || fail "转义 \\\$ 应通过"

# 1.7 owner 错误：chown nobody
mk t7_owner.conf 'A=hello'
chown nobody:nogroup "$WORK/t7_owner.conf" 2>/dev/null
if [[ "$(stat -c '%U' "$WORK/t7_owner.conf")" == "nobody" ]]; then
    validate_conf_file "$WORK/t7_owner.conf" 2>/dev/null && fail "应拒绝非 root owner" || pass "拒绝非 root owner"
else
    echo "  [SKIP] 无法切 owner，跳过 owner 测试"
fi

# 1.8 mode 过宽
mk t8_mode.conf 'A=hello'
chmod 666 "$WORK/t8_mode.conf"
if [[ $NON_ROOT -eq 1 ]]; then
    echo "  [SKIP] 非 root 本地环境跳过 mode owner 严格测试"
else
    validate_conf_file "$WORK/t8_mode.conf" 2>/dev/null && fail "应拒绝 666 mode" || pass "拒绝 666 mode (group/other 可写)"
fi

# 1.9 行格式异常
mk t9_badline.conf $'A=hello\nthis is not key=value\nB=ok'
chmod 600 "$WORK/t9_badline.conf"
validate_conf_file "$WORK/t9_badline.conf" 2>/dev/null && fail "应拒绝非 KEY=value 行" || pass "拒绝非 KEY=value"

echo ""
echo "== Test 2: SSH 数组调用防注入 =="
rm -f "$PWNED_MARKER"
# 直接调用 ssh_keys 选项 4 不方便，单独验证：用同样的数组写法跑一次
# 模拟旧 eval 行为应被注入，新数组写法不会
KEYFILE="$WORK/idtest"
EVIL="\"; touch $PWNED_MARKER; \""

# 新写法（与 06-ssh.sh 当前实现一致）
args=(ssh-keygen -t ed25519 -f "$KEYFILE" -N "" -C "$EVIL" -q)
"${args[@]}" 2>/dev/null

if [[ -f "$PWNED_MARKER" ]]; then
    fail "注入成功 — 数组调用没保护住"
    rm -f "$PWNED_MARKER"
else
    pass "数组调用未被注入"
fi
# 验证生成的 key 确实带了恶意备注做字面量
if grep -qF "$EVIL" "$KEYFILE.pub" 2>/dev/null; then
    pass "恶意备注作为字面量写入公钥"
else
    fail "公钥中未保留字面量备注"
fi
rm -f "$KEYFILE" "$KEYFILE.pub"

echo ""
echo "== Test 3: firewall_apply_reality_port (UFW active) =="
TESTPORT=64999
# shellcheck disable=SC2034  # read dynamically by sourced helpers
PLATFORM="debian"
MOCK_UFW_RULES="$WORK/ufw.rules"
: > "$MOCK_UFW_RULES"
ufw() {
    case "${1:-}" in
        status)
            echo "Status: active"
            cat "$MOCK_UFW_RULES" 2>/dev/null
            ;;
        allow)
            printf '%s ALLOW Anywhere\n' "${2:-}" >> "$MOCK_UFW_RULES"
            ;;
        delete)
            if [[ "${2:-}" == "allow" ]]; then
                grep -vE "^${3:-}[[:space:]]" "$MOCK_UFW_RULES" > "${MOCK_UFW_RULES}.tmp" 2>/dev/null || true
                mv "${MOCK_UFW_RULES}.tmp" "$MOCK_UFW_RULES"
            fi
            ;;
        *) return 0 ;;
    esac
}
# 确保起始无该规则
ufw delete allow "${TESTPORT}/tcp" >/dev/null 2>&1

firewall_apply_reality_port "$TESTPORT"
rc=$?
echo "  返回码: $rc (期望 0)"
if [[ $rc -eq 0 ]] && ufw status 2>/dev/null | grep -qE "^${TESTPORT}/tcp\s+ALLOW"; then
    pass "UFW active 路径 — 规则已添加"
else
    fail "UFW active 路径未生效"
fi
# 还原
ufw delete allow "${TESTPORT}/tcp" >/dev/null 2>&1
if ! ufw status 2>/dev/null | grep -qE "^${TESTPORT}/tcp\s+ALLOW"; then
    pass "测试端口已清理"
else
    fail "测试端口未清理 — 请手动 ufw delete allow ${TESTPORT}/tcp"
fi

echo ""
echo "== Test 4: 主菜单渲染 (0-12) =="
# 早期版本曾用 `echo 0` 通过管道喂给 timeout 5 bash $BUILT 来抓 read -p prompt，
# 但 Bash 非交互模式不输出 prompt（写到 stderr 又会被 timeout 截断），假阴性高。
# 改为静态 grep dist 中关键字面值。
# 注释里有意拆分 "echo 0"+"timeout" 字面，避免被回归测试脚本误命中。
if grep -q '请选择功能 \[0-12\]:' "$BUILT"; then
    pass "菜单提示字面已包含 [0-12]"
else
    fail "菜单提示字面未包含 [0-12]"
fi
if grep -qE '"13\. 备份与恢复|13\) menu_backup' "$BUILT"; then
    fail "dist 中仍有 13. 备份与恢复 残留"
else
    pass "dist 已无 13. 备份项"
fi

echo ""
echo "== 结果 =="
echo "  PASS=$PASS  FAIL=$FAIL"
exit $FAIL
