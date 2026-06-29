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
CFST_BIN="$cfst_bin"
CFST_TOP_N="1"
CFST_COLO_MODE="auto"
CFST_EXTRA_ARGS="-dn 2 -tl 200"
CFST_ROUNDS="1"
CFST_PICK_MODE="cfst"
KEEP_ON_EMPTY="true"
MISSING_COLO_POLICY="keep"
PREFERIP_OUTPUT_FILE="$TMP/rendered.txt"
PREFERIP_STATE_FILE="$TMP/state.tsv"
PREFERIP_HISTORY_FILE="$TMP/history.csv"
PREFERIP_BAD_FILE="$TMP/bad-ip.txt"
PREFERIP_LOCK_FILE="$TMP/preferip.lock"
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
    local dir="$1"
    cat > "$dir/curl" <<'SH'
#!/usr/bin/env bash
set -u
method="GET"
data=""
url=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -X) method="$2"; shift 2 ;;
        --data|-d) data="$2"; shift 2 ;;
        -H|--max-time|--connect-timeout|-o|-w|--resolve) shift 2 ;;
        -f|-s|-S|-fsS|-k) shift ;;
        http://*|https://*) url="$1"; shift ;;
        *) shift ;;
    esac
done
if [[ -n "${CF_CALL_LOG:-}" && "$url" == *"/client/v4/"* ]]; then
    {
        printf '%s %s\n' "$method" "$url"
        [[ -n "$data" ]] && printf '%s\n' "$data"
    } >> "$CF_CALL_LOG"
fi
case "$method" in
    GET)
        if [[ "$url" == *"/client/v4/zones?name="* ]]; then
            printf '{"success":true,"errors":[],"messages":[],"result":[{"id":"zone-123","name":"example.com"}]}\n'
        elif [[ "$url" == *"/client/v4/zones/"*"/dns_records?type=A&name="* ]]; then
            printf '{"success":true,"errors":[],"messages":[],"result":[{"id":"rec-a-1","type":"A","name":"prefer.example.com","content":"172.67.1.1"}]}\n'
        elif [[ "$url" == *"/client/v4/zones/"*"/dns_records?type=AAAA&name="* ]]; then
            printf '{"success":true,"errors":[],"messages":[],"result":[{"id":"rec-aaaa-1","type":"AAAA","name":"prefer6.example.com","content":"2606:4700::1"}]}\n'
        else
            printf '{"success":true,"errors":[],"messages":[],"result":[]}\n'
        fi
        ;;
    PATCH|POST|PUT)
        if [[ "$url" == *"/client/v4/zones/"*"/dns_records"* ]]; then
            printf '{"success":true,"errors":[],"messages":[],"result":{"id":"rec-new"}}\n'
        else
            printf '{"success":true,"errors":[],"messages":[],"result":{"id":"zone-123"}}\n'
        fi
        ;;
    DELETE)
        if [[ "$url" == *"/client/v4/zones/"*"/dns_records/"* ]]; then
            printf '{"success":true,"errors":[],"messages":[],"result":{"id":"deleted"}}\n'
        else
            printf '{"success":true,"errors":[],"messages":[],"result":{"id":"deleted"}}\n'
        fi
        ;;
    *)
        printf '{"status":"failed","message":"unexpected method"}\n'
        ;;
esac
SH
    chmod +x "$dir/curl"
}

extract_rendered() {
    sed '/^# generated:/d' "$TMP/rendered.txt"
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
ck "latency 模式选最低延迟 IP" "grep -Eq '^HKG\\|104\\.20\\.0\\.3\\|' '$result'"

echo ""
echo "== cdn-preferip: DNS 模式保持 entry 域名并同步 Cloudflare A 记录 =="
fakebin="$TMP/fakebin"; mkdir -p "$fakebin"
CF_CALL_LOG="$TMP/cf-calls.log"
write_fake_curl "$fakebin"
conf="$TMP/dns.conf"; nodes="$TMP/dns.nodes"; result="$TMP/dns.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
PREFERIP_DNS_PROXIED="false"
PREFERIP_DNS_DELETE_STALE="true"
EOF
cat > "$nodes" <<'EOF'
HK-DNS|HKG|entry=prefer.example.com|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=hk.example&path=%2Fhk&sni=hk.example#old
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v3: colo|ip|avg_latency_ms|avg_speed_mbps|rounds_hit
HKG|172.67.66.8|80.00|10.00|1
EOF
CF_CALL_LOG="$CF_CALL_LOG" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns.out 2>/tmp/cdn-pref-dns.err \
    && pass "DNS 模式 push 成功" || fail "DNS 模式 push 失败"
content_dns="$(extract_rendered)"
ck "DNS 模式输出里 server 保持为入口域名" "grep -q '@prefer.example.com:443' <<< \"\$content_dns\""
ck "DNS 模式仍保留真实 host/sni" "grep -q 'sni=hk.example' <<< \"\$content_dns\""
ck "DNS 模式同步到 Cloudflare 记录" "grep -q 'prefer.example.com' '$CF_CALL_LOG'"
ck "DNS 模式写入优选 IP" "grep -q '172.67.66.8' '$CF_CALL_LOG'"

echo ""
echo "== cdn-preferip: DNS 模式禁止隐式使用原 CDN 域名 =="
CF_CALL_LOG_GUARD="$TMP/cf-calls-guard.log"
write_fake_curl "$fakebin"
conf="$TMP/dns-guard.conf"; nodes="$TMP/dns-guard.nodes"; result="$TMP/dns-guard.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
EOF
cat > "$nodes" <<'EOF'
HK-NO-ENTRY|HKG|vless://00000000-0000-0000-0000-000000000001@origin.example:443?type=ws&security=tls&host=origin.example&path=%2Fhk&sni=origin.example#old
EOF
cat > "$result" <<'EOF'
HKG|172.67.66.9|80.00|10.00|1
EOF
if CF_CALL_LOG="$CF_CALL_LOG_GUARD" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns-guard.out 2>/tmp/cdn-pref-dns-guard.err; then
    fail "DNS 模式缺 entry 应拒绝执行"
else
    pass "DNS 模式缺 entry 会拒绝执行"
fi
ck "缺 entry 时不会调用 Cloudflare 改 DNS" "! grep -q 'origin.example' '$CF_CALL_LOG_GUARD' 2>/dev/null"
ck "缺 entry 错误提示明确" "grep -q '必须显式配置 entry' /tmp/cdn-pref-dns-guard.err"

echo ""
echo "== cdn-preferip: entry 不能等于原 Host/SNI =="
CF_CALL_LOG_BADENTRY="$TMP/cf-calls-badentry.log"
write_fake_curl "$fakebin"
conf="$TMP/dns-badentry.conf"; nodes="$TMP/dns-badentry.nodes"; result="$TMP/dns-badentry.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
EOF
cat > "$nodes" <<'EOF'
HK-BAD-ENTRY|HKG|entry=origin.example|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=origin.example&path=%2Fhk&sni=origin.example#old
EOF
cat > "$result" <<'EOF'
HKG|172.67.66.10|80.00|10.00|1
EOF
if CF_CALL_LOG="$CF_CALL_LOG_BADENTRY" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns-badentry.out 2>/tmp/cdn-pref-dns-badentry.err; then
    fail "entry 等于 Host/SNI 应拒绝执行"
else
    pass "entry 等于 Host/SNI 会拒绝执行"
fi
ck "bad entry 时不会调用 Cloudflare 改 DNS" "! grep -q 'origin.example' '$CF_CALL_LOG_BADENTRY' 2>/dev/null"
ck "bad entry 错误提示明确" "grep -q '与原 CDN 域名/Host/SNI 相同' /tmp/cdn-pref-dns-badentry.err"

echo ""
echo "== cdn-preferip: ip 模式忽略残留 entry 撞名，不误杀整批生成 =="
write_fake_curl "$fakebin"
conf="$TMP/ip-entry-collision.conf"; nodes="$TMP/ip-entry-collision.nodes"; result="$TMP/ip-entry-collision.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="ip"
EOF
cat > "$nodes" <<'EOF'
HK-IP|HKG|entry=origin.example|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=origin.example&path=%2Fhk&sni=origin.example#old
EOF
cat > "$result" <<'EOF'
HKG|172.67.66.11|80.00|10.00|1
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-ip-entry-collision.out 2>/tmp/cdn-pref-ip-entry-collision.err \
    && pass "ip 模式残留 entry 撞名仍可生成" || fail "ip 模式不应因 entry 撞名失败"
content_ip_entry_collision="$(extract_rendered)"
ck "ip 模式残留 entry 被忽略，server 使用优选 IP" "grep -q '@172.67.66.11:443' <<< \"\$content_ip_entry_collision\""

echo ""
echo "== cdn-preferip: DNS 模式同步 IPv6 AAAA 记录 =="
CF_CALL_LOG6="$TMP/cf-calls6.log"
write_fake_curl "$fakebin"
conf="$TMP/dns6.conf"; nodes="$TMP/dns6.nodes"; result="$TMP/dns6.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
PREFERIP_DNS_PROXIED="false"
PREFERIP_DNS_DELETE_STALE="true"
EOF
cat > "$nodes" <<'EOF'
HK-DNS6|HKG|ipv6|entry=prefer6.example.com|vless://00000000-0000-0000-0000-000000000002@old6.example.com:443?type=ws&security=tls&host=hk6.example.com&path=%2Fhk6&sni=hk6.example.com#old
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v3: colo|ip|avg_latency_ms|avg_speed_mbps|rounds_hit
HKG@IPV6|2606:4700::1234|70.00|8.00|1
EOF
CF_CALL_LOG="$CF_CALL_LOG6" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns6.out 2>/tmp/cdn-pref-dns6.err \
    && pass "IPv6 DNS 模式 push 成功" || fail "IPv6 DNS 模式 push 失败"
content_dns6="$(extract_rendered)"
ck "IPv6 DNS 模式输出里 server 保持为入口域名" "grep -q '@prefer6.example.com:443' <<< \"\$content_dns6\""
ck "IPv6 DNS 模式同步 AAAA 记录内容" "grep -q 'prefer6.example.com' '$CF_CALL_LOG6'"
ck "IPv6 DNS 模式写入 IPv6 优选 IP" "grep -q '2606:4700::1234' '$CF_CALL_LOG6'"

echo ""
echo "== cdn-preferip: 同一 entry 双栈 A+AAAA 不互删 =="
CF_CALL_LOG_DUAL="$TMP/cf-calls-dual.log"
write_fake_curl "$fakebin"
conf="$TMP/dns-dual.conf"; nodes="$TMP/dns-dual.nodes"; result="$TMP/dns-dual.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
PREFERIP_DNS_DELETE_STALE="true"
EOF
cat > "$nodes" <<'EOF'
Dual-v4|HKG|entry=prefer-dual.example.com|vless://00000000-0000-0000-0000-000000000001@old4.example:443?type=ws&security=tls&host=dual4.example.com&path=%2Fhk&sni=dual4.example.com#old
Dual-v6|HKG|ipv6|entry=prefer-dual.example.com|vless://00000000-0000-0000-0000-000000000002@old6.example:443?type=ws&security=tls&host=dual6.example.com&path=%2Fhk6&sni=dual6.example.com#old
EOF
cat > "$result" <<'EOF'
HKG|172.67.66.12|80.00|10.00|1
HKG@IPV6|2606:4700::5678|70.00|8.00|1
EOF
CF_CALL_LOG="$CF_CALL_LOG_DUAL" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns-dual.out 2>/tmp/cdn-pref-dns-dual.err \
    && pass "同 entry 双栈 push 成功" || fail "同 entry 双栈 push 失败"
content_dns_dual="$(extract_rendered)"
ck "同 entry 双栈两个节点均使用入口域名" "[[ \$(grep -c '@prefer-dual.example.com:443' <<< \"\$content_dns_dual\") -eq 2 ]]"
ck "同 entry 双栈写入 A 记录" "grep -Eq '\"type\"[[:space:]]*:[[:space:]]*\"A\"' '$CF_CALL_LOG_DUAL'"
ck "同 entry 双栈写入 AAAA 记录" "grep -Eq '\"type\"[[:space:]]*:[[:space:]]*\"AAAA\"' '$CF_CALL_LOG_DUAL'"
ck "同 entry 双栈未触发 stale family 删除" "! grep -q '^DELETE ' '$CF_CALL_LOG_DUAL'"

echo ""
echo "== cdn-preferip: 同一 entry 冷启动缺 IPv6 候选时仍按显式 ipv6 计划保留 AAAA =="
CF_CALL_LOG_DUAL_COLD="$TMP/cf-calls-dual-cold.log"
write_fake_curl "$fakebin"
conf="$TMP/dns-dual-cold.conf"; nodes="$TMP/dns-dual-cold.nodes"; result="$TMP/dns-dual-cold.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<'EOF'
PREFERIP_SERVER_MODE="dns"
PREFERIP_CF_API_TOKEN="fake-token"
PREFERIP_CF_ZONE_ID="zone-123"
PREFERIP_DNS_DELETE_STALE="true"
EOF
cat > "$nodes" <<'EOF'
DualCold-v4|HKG|entry=prefer-dual-cold.example.com|vless://00000000-0000-0000-0000-000000000001@origin4.example.com:443?type=ws&security=tls&host=dual4.example.com&path=%2Fhk&sni=dual4.example.com#old
DualCold-v6|HKG|ipv6|entry=prefer-dual-cold.example.com|vless://00000000-0000-0000-0000-000000000002@origin6.example.com:443?type=ws&security=tls&host=dual6.example.com&path=%2Fhk6&sni=dual6.example.com#old
EOF
cat > "$result" <<'EOF'
HKG|172.67.66.13|80.00|10.00|1
EOF
CF_CALL_LOG="$CF_CALL_LOG_DUAL_COLD" PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-dns-dual-cold.out 2>/tmp/cdn-pref-dns-dual-cold.err \
    && pass "同 entry 冷启动缺 IPv6 候选 push 成功" || fail "同 entry 冷启动缺 IPv6 候选 push 失败"
content_dns_dual_cold="$(extract_rendered)"
ck "冷启动缺 IPv6 候选时两个节点仍使用同一入口域名" "[[ \$(grep -c '@prefer-dual-cold.example.com:443' <<< \"\$content_dns_dual_cold\") -eq 2 ]]"
ck "冷启动缺 IPv6 候选时写入 IPv4 A 记录" "grep -Eq '\"type\"[[:space:]]*:[[:space:]]*\"A\"' '$CF_CALL_LOG_DUAL_COLD'"
ck "冷启动缺 IPv6 候选时未删除现有 AAAA" "! grep -q '^DELETE ' '$CF_CALL_LOG_DUAL_COLD'"
ck "冷启动缺 IPv6 候选时识别 A+AAAA 计划" "grep -q '计划同时维护 A+AAAA' /tmp/cdn-pref-dns-dual-cold.err"

echo ""
echo "== cdn-preferip: 缺地区结果 keep 原 server，且不隐式回退 GLOBAL =="
fakebin="$TMP/fakebin"; mkdir -p "$fakebin"
write_fake_curl "$fakebin"
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
content="$(extract_rendered)"
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
ck "IPv4 分组写入 HKG" "grep -Eq '^HKG\\|1\\.1\\.1\\.1\\|' '$result'"
ck "IPv6 分组写入 HKG@IPV6" "grep -Eq '^HKG@IPV6\\|2606:4700::abcd\\|' '$result'"

write_fake_curl "$fakebin"
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-mixed-push.out 2>/tmp/cdn-pref-mixed-push.err \
    && pass "混合池 push 成功" || fail "混合池 push 失败"
content_mixed="$(extract_rendered)"
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
ck "部分失败时仍写入成功分组" "grep -Eq '^HKG\\|1\\.0\\.0\\.1\\|' '$result'"
ck "部分失败时不写空 IPv6 分组" "! grep -q 'HKG@IPV6' '$result'"

echo ""
echo "== cdn-preferip: IPv6 server 自动加 [] =="
write_fake_curl "$fakebin"
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
content6="$(extract_rendered)"
ck "IPv6 server 写入 vless 时带方括号" "grep -q '@\\[2606:4700::1234\\]:443' <<< \"\$content6\""

echo ""
echo "== cdn-preferip: TopN 多 IP 池按同地区节点轮询分配 =="
write_fake_curl "$fakebin"
conf="$TMP/pool.conf"; nodes="$TMP/pool.nodes"; result="$TMP/pool.result"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<EOF
PREFERIP_STATE_FILE="$TMP/pool-state.tsv"
PREFERIP_ASSIGN_MODE="round_robin"
PREFERIP_STICKY="false"
EOF
cat > "$nodes" <<'EOF'
HK-1|HKG|vless://00000000-0000-0000-0000-000000000001@old1.example:443?type=ws&security=tls&host=hk1.example&path=%2Fhk&sni=hk1.example#old
HK-2|HKG|vless://00000000-0000-0000-0000-000000000002@old2.example:443?type=ws&security=tls&host=hk2.example&path=%2Fhk&sni=hk2.example#old
HK-3|HKG|vless://00000000-0000-0000-0000-000000000003@old3.example:443?type=ws&security=tls&host=hk3.example&path=%2Fhk&sni=hk3.example#old
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v3: colo|ip|avg_latency_ms|avg_speed_mbps|rounds_hit
HKG|1.1.1.1|80.00|10.00|1
HKG|1.1.1.2|82.00|11.00|1
HKG|1.1.1.3|84.00|12.00|1
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-pool.out 2>/tmp/cdn-pref-pool.err \
    && pass "TopN 池化 push 成功" || fail "TopN 池化 push 失败"
content_pool="$(extract_rendered)"
ck "HK-1 使用候选池第 1 个 IP" "grep -q '@1.1.1.1:443' <<< \"\$content_pool\""
ck "HK-2 使用候选池第 2 个 IP" "grep -q '@1.1.1.2:443' <<< \"\$content_pool\""
ck "HK-3 使用候选池第 3 个 IP" "grep -q '@1.1.1.3:443' <<< \"\$content_pool\""

echo ""
echo "== cdn-preferip: TopN 轮询分配优先于 sticky，避免全部节点粘在一个 IP =="
write_fake_curl "$fakebin"
conf="$TMP/pool-sticky.conf"; nodes="$TMP/pool-sticky.nodes"; result="$TMP/pool-sticky.result"; state="$TMP/pool-sticky-state.tsv"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<EOF
PREFERIP_STATE_FILE="$state"
PREFERIP_ASSIGN_MODE="round_robin"
PREFERIP_STICKY="true"
EOF
cat > "$nodes" <<'EOF'
HK-S1|HKG|vless://00000000-0000-0000-0000-000000000001@old1.example:443?type=ws&security=tls&host=hk1.example&path=%2Fhk&sni=hk1.example#old
HK-S2|HKG|vless://00000000-0000-0000-0000-000000000002@old2.example:443?type=ws&security=tls&host=hk2.example&path=%2Fhk&sni=hk2.example#old
HK-S3|HKG|vless://00000000-0000-0000-0000-000000000003@old3.example:443?type=ws&security=tls&host=hk3.example&path=%2Fhk&sni=hk3.example#old
EOF
cat > "$state" <<'EOF'
# note	key	server	avg_latency_ms	avg_speed_mbps	rounds_hit	updated_at_epoch
HK-S1	HKG	1.1.1.1	80.00	10.00	1	100
HK-S2	HKG	1.1.1.1	80.00	10.00	1	100
HK-S3	HKG	1.1.1.1	80.00	10.00	1	100
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v3: colo|ip|avg_latency_ms|avg_speed_mbps|rounds_hit
HKG|1.1.1.1|80.00|10.00|1
HKG|1.1.1.2|82.00|11.00|1
HKG|1.1.1.3|84.00|12.00|1
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-pool-sticky.out 2>/tmp/cdn-pref-pool-sticky.err \
    && pass "TopN + sticky 池化 push 成功" || fail "TopN + sticky 池化 push 失败"
content_pool_sticky="$(extract_rendered)"
ck "sticky=true 时 HK-S1 使用候选池第 1 个 IP" "grep -q '@1.1.1.1:443' <<< \"\$content_pool_sticky\""
ck "sticky=true 时 HK-S2 使用候选池第 2 个 IP" "grep -q '@1.1.1.2:443' <<< \"\$content_pool_sticky\""
ck "sticky=true 时 HK-S3 使用候选池第 3 个 IP" "grep -q '@1.1.1.3:443' <<< \"\$content_pool_sticky\""

echo ""
echo "== cdn-preferip: sticky 稳态切换避免无明显收益时频繁换 IP =="
write_fake_curl "$fakebin"
conf="$TMP/sticky.conf"; nodes="$TMP/sticky.nodes"; result="$TMP/sticky.result"; state="$TMP/sticky-state.tsv"
write_base_conf "$conf" "/bin/false"
cat >> "$conf" <<EOF
PREFERIP_STATE_FILE="$state"
PREFERIP_ASSIGN_MODE="first"
PREFERIP_STICKY="true"
PREFERIP_SWITCH_MIN_SPEED_GAIN_PERCENT="20"
PREFERIP_SWITCH_MIN_LATENCY_GAIN_MS="20"
EOF
cat > "$nodes" <<'EOF'
HK-1|HKG|vless://00000000-0000-0000-0000-000000000001@old1.example:443?type=ws&security=tls&host=hk1.example&path=%2Fhk&sni=hk1.example#old
EOF
cat > "$state" <<'EOF'
# note	key	server	avg_latency_ms	avg_speed_mbps	rounds_hit	updated_at_epoch
HK-1	HKG	1.1.1.2	90.00	10.00	1	100
EOF
cat > "$result" <<'EOF'
# cdn-preferip result v3: colo|ip|avg_latency_ms|avg_speed_mbps|rounds_hit
HKG|1.1.1.1|85.00|11.00|1
HKG|1.1.1.2|90.00|10.00|1
EOF
PATH="$fakebin:$PATH" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-push.sh" >/tmp/cdn-pref-sticky.out 2>/tmp/cdn-pref-sticky.err \
    && pass "sticky push 成功" || fail "sticky push 失败"
content_sticky="$(extract_rendered)"
ck "新候选收益不足时保持当前 state IP" "grep -q '@1.1.1.2:443' <<< \"\$content_sticky\""

echo ""
echo "== cdn-preferip: 二阶段复测用候选池重新排序 =="
cat > "$TMP/cfst-stage2" <<'SH'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
n=$(($(cat "$TMPDIR/cfst-stage2-count" 2>/dev/null || echo 0)+1))
echo "$n" > "$TMPDIR/cfst-stage2-count"
if [[ "$n" -eq 1 ]]; then
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
104.20.0.1,4,4,0.00,100.00,100.00,HKG
104.20.0.2,4,4,0.00,70.00,10.00,HKG
CSV
else
    cat > "$out" <<CSV
IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码
104.20.0.1,4,4,0.00,120.00,1.00,HKG
104.20.0.2,4,4,0.00,60.00,50.00,HKG
CSV
fi
SH
chmod +x "$TMP/cfst-stage2"
conf="$TMP/stage2.conf"; nodes="$TMP/stage2.nodes"; result="$TMP/stage2.result"
write_base_conf "$conf" "$TMP/cfst-stage2"
cat >> "$conf" <<'EOF'
CFST_PICK_MODE="speed"
CFST_STAGE2_ENABLE="true"
CFST_STAGE2_TOP_N="2"
CFST_STAGE2_ROUNDS="1"
EOF
cat > "$nodes" <<'EOF'
HK-CDN|HKG|vless://00000000-0000-0000-0000-000000000001@old.example:443?type=ws&security=tls&host=hk.example&path=%2Fhk&sni=hk.example#old
EOF
TMPDIR="$TMP" CDN_PREFERIP_CONF="$conf" RESULT_FILE="$result" NODES_FILE="$nodes" "$CDN_DIR/preferip-collect.sh" >/tmp/cdn-pref-stage2.out 2>/tmp/cdn-pref-stage2.err \
    && pass "二阶段 collect 成功" || fail "二阶段 collect 失败"
ck "二阶段复测后按二阶段速度选择 IP" "grep -Eq '^HKG\\|104\\.20\\.0\\.2\\|60\\.00\\|50\\.00\\|1' '$result'"

echo ""
echo "== 汇总 =="
echo "PASS=$PASS FAIL=$FAIL"
[[ "$FAIL" -eq 0 ]]
