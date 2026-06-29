#!/usr/bin/env bash
# tests/cdn_preferip_test.sh
# 离线验证 scripts/cdn-preferip 的关键策略：
#   1) 优选无结果时不覆盖旧 result
#   2) 多轮 + pick_mode=latency 生效
#   3) 某地区缺结果时 keep 原 server，且不隐式回退 global
#   4) IPv6 优选 IP 回写时自动加 []
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CDN_DIR="$ROOT/scripts/cdn-preferip"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0
pass(){ echo "  PASS: $1"; PASS=$((PASS+1)); }
fail(){ echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
ck(){ if eval "$2"; then pass "$1"; else fail "$1"; fi; }

write_base_conf() {
    local conf="$1" cfst_bin="${2:-$TMP/cfst}"
    cat > "$conf" <<EOF
SUBSTORE_BASE="http://sub.example.test/secret"
SUBSTORE_SUB_NAME="cdn-preferip"
CFST_BIN="$cfst_bin"
CFST_TOP_N="1"
CFST_COLO_MODE="auto"
CFST_EXTRA_ARGS="-dn 2 -tl 200"
CFST_ROUNDS="1"
CFST_PICK_MODE="cfst"
KEEP_ON_EMPTY="true"
MISSING_COLO_POLICY="keep"
EOF
}

write_nodes() {
    local file="$1"
    cat > "$file" <<'EOF'
HK-CDN|HKG|vless://00000000-0000-0000-0000-000000000001@old-hk.example:443?encryption=none&security=tls&sni=hk.example&fp=chrome&type=ws&host=hk.example&path=%2Fhk#old
KR-CDN|ICN|vless://00000000-0000-0000-0000-000000000002@old-kr.example:443?encryption=none&security=tls&sni=kr.example&fp=chrome&type=ws&host=kr.example&path=%2Fkr#old
EOF
}

write_fake_curl() {
    local dir="$1" payload_file="$2"
    cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -u
method="GET"
data=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -X) method="$2"; shift 2 ;;
        --data|-d) data="$2"; shift 2 ;;
        -H|--max-time) shift 2 ;;
        -f|-s|-S|-fsS) shift ;;
        http://*|https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
case "$method" in
    GET)
        printf '{"status":"success","data":{"name":"cdn-preferip","displayName":"cdn-preferip","source":"local","content":""}}\n'
        ;;
    PATCH|POST)
        printf '%s' "$data" > "${PATCH_PAYLOAD:?}"
        printf '{"status":"success"}\n'
        ;;
    *)
        printf '{"status":"failed","message":"unexpected method"}\n'
        ;;
esac
SH
    chmod +x "$dir/curl"
    export PATCH_PAYLOAD="$payload_file"
}

echo "== cdn-preferip: collect 空结果不覆盖旧文件 =="
cat > "$TMP/cfst-empty" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
: > "${out:?missing -o}"
SH
chmod +x "$TMP/cfst-empty"
conf="$TMP/empty.conf"; nodes="$TMP/nodes.txt"; result="$TMP/result.txt"
write_base_conf "$conf" "$TMP/cfst-empty"
write_nodes "$nodes"
printf 'OLD_RESULT_SHOULD_STAY\n' > "$result"
if CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-collect.sh" >/tmp/cdn-pref-empty.out 2>/tmp/cdn-pref-empty.err; then
    fail "空 CSV 时 collect 应失败"
else
    pass "空 CSV 时 collect 返回失败"
fi
ck "空结果保留旧 preferip.result" "grep -qx 'OLD_RESULT_SHOULD_STAY' '$result'"

echo ""
echo "== cdn-preferip: 多轮 latency 选择 =="
cat > "$TMP/cfst-rounds" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
n=$(($(cat "$TMPDIR/cfst-count" 2>/dev/null || echo 0)+1))
echo "$n" > "$TMPDIR/cfst-count"
if [[ "$n" -eq 1 ]]; then
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
104.20.0.1,4,4,0.00,120.00,80.00,HKG
104.20.0.2,4,4,0.00,80.00,10.00,HKG
CSV
else
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
104.20.0.3,4,4,0.00,70.00,20.00,HKG
104.20.0.4,4,4,0.00,110.00,90.00,HKG
CSV
fi
SH
chmod +x "$TMP/cfst-rounds"
conf="$TMP/rounds.conf"; nodes="$TMP/nodes-hkg.txt"; result="$TMP/rounds.result"
write_base_conf "$conf" "$TMP/cfst-rounds"
cat >> "$conf" <<'EOF'
CFST_ROUNDS="2"
CFST_PICK_MODE="latency"
EOF
cat > "$nodes" <<'EOF'
HK-CDN|HKG|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=hk.example&path=%2Fhk&sni=hk.example#old
EOF
TMPDIR="$TMP" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-collect.sh" >/tmp/cdn-pref-rounds.out 2>/tmp/cdn-pref-rounds.err \
    && pass "多轮 collect 成功" || fail "多轮 collect 失败"
ck "latency 模式选最低延迟 IP" "grep -qx 'HKG|104.20.0.3' '$result'"

echo ""
echo "== cdn-preferip: 缺地区结果 keep 原 server，且不隐式回退 GLOBAL =="
fakebin="$TMP/fakebin"; mkdir -p "$fakebin"
payload="$TMP/patch-payload.json"
write_fake_curl "$fakebin" "$payload"
conf="$TMP/push.conf"; nodes="$TMP/push.nodes"; result="$TMP/push.result"
write_base_conf "$conf" "/bin/false"
write_nodes "$nodes"
cat > "$result" <<'EOF'
# cdn-preferip result v2: colo|ip
GLOBAL|8.8.8.8
HKG|1.1.1.1
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-push.out 2>/tmp/cdn-pref-push.err \
    && pass "push keep 策略成功" || fail "push keep 策略失败"
content="$(jq -r '.content' "$payload")"
ck "HKG 节点更新为地区优选 IP" "grep -q '@1.1.1.1:443' <<< \"\$content\""
ck "ICN 缺结果时保留原 server" "grep -q '@old-kr.example:443' <<< \"\$content\""
ck "ICN 缺结果时没有隐式回退 GLOBAL" "! grep -q '@8.8.8.8:443' <<< \"\$content\""

echo ""
echo "== cdn-preferip: 混合 IPv4/IPv6 池按节点分组 =="
cat > "$TMP/cfst-mixed" <<'SH'
#!/usr/bin/env bash
out=""
ipfile=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -f) ipfile="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ "$ipfile" == *"ipv6.txt" ]]; then
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
2606:4700::abcd,4,4,0.00,88.00,12.00,HKG
CSV
else
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
1.1.1.1,4,4,0.00,80.00,20.00,HKG
CSV
fi
SH
chmod +x "$TMP/cfst-mixed"
printf 'dummy\n' > "$TMP/ip.txt"
printf 'dummy\n' > "$TMP/ipv6.txt"
conf="$TMP/mixed.conf"; nodes="$TMP/mixed.nodes"; result="$TMP/mixed.result"
write_base_conf "$conf" "$TMP/cfst-mixed"
cat >> "$conf" <<EOF
CFST_IP_FILE="$TMP/ip.txt"
CFST_IPV6_FILE="$TMP/ipv6.txt"
EOF
cat > "$nodes" <<'EOF'
HK-v4|HKG|vless://00000000-0000-0000-0000-000000000001@old-v4.example:443?type=ws&security=tls&host=hk.example&path=%2Fhk&sni=hk.example#old
HK-v6|HKG|ipv6|vless://00000000-0000-0000-0000-000000000002@old-v6.example:443?type=ws&security=tls&host=hk6.example&path=%2Fhk6&sni=hk6.example#old
EOF
CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-collect.sh" >/tmp/cdn-pref-mixed.out 2>/tmp/cdn-pref-mixed.err \
    && pass "混合池 collect 成功" || fail "混合池 collect 失败"
ck "IPv4 分组写入 HKG" "grep -qx 'HKG|1.1.1.1' '$result'"
ck "IPv6 分组写入 HKG@IPV6" "grep -qx 'HKG@IPV6|2606:4700::abcd' '$result'"

payload_mixed="$TMP/patch-payload-mixed.json"
write_fake_curl "$fakebin" "$payload_mixed"
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-mixed-push.out 2>/tmp/cdn-pref-mixed-push.err \
    && pass "混合池 push 成功" || fail "混合池 push 失败"
content_mixed="$(jq -r '.content' "$payload_mixed")"
ck "IPv4 节点使用 IPv4 优选 IP" "grep -q '@1.1.1.1:443' <<< \"\$content_mixed\""
ck "IPv6 节点使用 IPv6 优选 IP 并加 []" "grep -q '@\\[2606:4700::abcd\\]:443' <<< \"\$content_mixed\""

echo ""
echo "== cdn-preferip: 多分组部分失败时 keep 可继续 =="
cat > "$TMP/cfst-partial" <<'SH'
#!/usr/bin/env bash
out=""
ipfile=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -f) ipfile="$2"; shift 2 ;;
        *) shift ;;
    esac
done
if [[ "$ipfile" == *"ipv6.txt" ]]; then
    : > "$out"
else
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
1.0.0.1,4,4,0.00,90.00,18.00,HKG
CSV
fi
SH
chmod +x "$TMP/cfst-partial"
conf="$TMP/partial.conf"; nodes="$TMP/mixed.nodes"; result="$TMP/partial.result"
write_base_conf "$conf" "$TMP/cfst-partial"
cat >> "$conf" <<EOF
CFST_IP_FILE="$TMP/ip.txt"
CFST_IPV6_FILE="$TMP/ipv6.txt"
MISSING_COLO_POLICY="keep"
EOF
CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-collect.sh" >/tmp/cdn-pref-partial.out 2>/tmp/cdn-pref-partial.err \
    && pass "部分分组失败时 collect 仍成功" || fail "部分分组失败时 collect 不应失败"
ck "部分失败时仍写入成功分组" "grep -qx 'HKG|1.0.0.1' '$result'"
ck "部分失败时不写空 IPv6 分组" "! grep -q 'HKG@IPV6' '$result'"

echo ""
echo "== cdn-preferip: IPv6 server 自动加 [] =="
payload6="$TMP/patch-payload-v6.json"
write_fake_curl "$fakebin" "$payload6"
conf="$TMP/push-v6.conf"; nodes="$TMP/push-v6.nodes"; result="$TMP/push-v6.result"
write_base_conf "$conf" "/bin/false"
cat > "$nodes" <<'EOF'
HK-CDN|HKG|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=hk.example&path=%2Fhk&sni=hk.example#old
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v2: colo|ip
HKG|2606:4700::1234
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-v6.out 2>/tmp/cdn-pref-v6.err \
    && pass "push IPv6 成功" || fail "push IPv6 失败"
content6="$(jq -r '.content' "$payload6")"
ck "IPv6 server 写入 vless 时带方括号" "grep -q '@\\[2606:4700::1234\\]:443' <<< \"\$content6\""

echo ""
echo "== 汇总 =="
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
