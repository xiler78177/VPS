#!/usr/bin/env bash
# Mock Cloudflare API coverage for web and email helpers. No real CF calls.
set -u

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUILT="${BUILT:-$ROOT/dist/v4-built.sh}"
TMP_ROOT=$(mktemp -d)
LIB="$TMP_ROOT/v4-lib.sh"
PASS=0
FAIL=0

cleanup() {
    rm -rf "$TMP_ROOT"
}
trap cleanup EXIT

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

if [[ ! -f "$BUILT" ]]; then
    echo "missing built script: $BUILT"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "SKIP: jq is required for Cloudflare/email API mock coverage"
    exit 0
fi

head -n -1 "$BUILT" > "$LIB"
cat >> "$LIB" <<'STUB'
install_package() { return 0; }
auto_deps() { return 0; }
STUB
sed -i \
    -e "s|^readonly EMAIL_STATE_DIR=.*|readonly EMAIL_STATE_DIR=\"$TMP_ROOT/state\"|" \
    -e "s|^readonly EMAIL_ADMIN_FILE=.*|readonly EMAIL_ADMIN_FILE=\"$TMP_ROOT/email-admin.txt\"|" \
    -e "s|^readonly EMAIL_LOG_FILE=.*|readonly EMAIL_LOG_FILE=\"$TMP_ROOT/email.log\"|" \
    -e "s|^readonly EMAIL_INSTALL_DIR=.*|readonly EMAIL_INSTALL_DIR=\"$TMP_ROOT/install\"|" \
    "$LIB"

# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || { echo "source failed: $LIB"; exit 1; }

pause() { :; }
draw_line() { :; }
log_action() { :; }
sleep() { :; }
print_info() { :; }
print_success() { :; }
print_warn() { :; }
print_error() { :; }
print_title() { :; }

export CF_API_TOKEN="token-mock"
export CF_ACCOUNT_ID="acct-mock"
: > "$EMAIL_LOG_FILE"

capture_data_arg() {
    local data=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --data|-d)
                data="${2:-}"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    printf '%s' "$data"
}

test_cf_list_zones_pagination() {
    _cf_api() {
        local method="$1" endpoint="$2" token="$3"
        [[ "$method" == "GET" && "$token" == "token-mock" ]] || {
            printf '{"success":false,"errors":[{"message":"bad call"}]}'
            return 1
        }
        case "$endpoint" in
            "/zones?per_page=2&page=1&status=active")
                printf '{"success":true,"result":[{"id":"z1","name":"a.example"},{"id":"z2","name":"b.example"}],"result_info":{"total_pages":2}}'
                ;;
            "/zones?per_page=2&page=2&status=active")
                printf '{"success":true,"result":[{"id":"z3","name":"c.example"}],"result_info":{"total_pages":2}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    local out count names
    out=$(_cf_list_zones "token-mock" "status=active" 2) || {
        fail "_cf_list_zones should aggregate paged zone responses"
        return
    }
    count=$(jq -r '.result | length' <<< "$out")
    names=$(jq -r '[.result[].name] | join(",")' <<< "$out")
    [[ "$count" == "3" && "$names" == "a.example,b.example,c.example" ]] \
        && pass "_cf_list_zones aggregates all pages" \
        || fail "_cf_list_zones returned count=$count names=$names"
}

test_cf_get_zone_id_fallback() {
    _cf_api() {
        local method="$1" endpoint="$2"
        [[ "$method" == "GET" ]] || return 1
        case "$endpoint" in
            /zones?name=*)
                printf '{"success":true,"result":[]}'
                ;;
            "/zones?per_page=50&page=1")
                printf '{"success":true,"result":[{"id":"zone-root","name":"example.com"}],"result_info":{"total_pages":1}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    local zid
    zid=$(_cf_get_zone_id "app.sub.example.com" "token-mock")
    [[ "$zid" == "zone-root" ]] \
        && pass "_cf_get_zone_id falls back to visible zone list" \
        || fail "_cf_get_zone_id fallback got '$zid'"
}

test_cf_update_dns_record_put_post_failure() {
    local calls="$TMP_ROOT/cf-dns-calls.jsonl"
    : > "$calls"
    _cf_api() {
        local method="$1" endpoint="$2" token="$3"
        shift 3
        [[ "$token" == "token-mock" ]] || return 1
        case "${method}:${endpoint}" in
            "GET:/zones/zid/dns_records?type=A&name=host.example.com")
                printf '{"success":true,"result":[{"id":"old-a"},{"id":"extra-a"}]}'
                ;;
            "PUT:/zones/zid/dns_records/old-a"|"POST:/zones/zid/dns_records")
                local data
                data=$(capture_data_arg "$@")
                jq -nc --arg method "$method" --arg endpoint "$endpoint" --argjson body "$data" \
                    '{method:$method, endpoint:$endpoint, body:$body}' >> "$calls"
                printf '{"success":true,"result":{"id":"ok"}}'
                ;;
            "DELETE:/zones/zid/dns_records/extra-a")
                jq -nc --arg method "$method" --arg endpoint "$endpoint" \
                    '{method:$method, endpoint:$endpoint}' >> "$calls"
                printf '{"success":true,"result":{"id":"extra-a"}}'
                ;;
            "GET:/zones/zid/dns_records?type=AAAA&name=host.example.com")
                printf '{"success":true,"result":[]}'
                ;;
            "GET:/zones/zid/dns_records?type=A&name=fail.example.com")
                printf '{"success":false,"errors":[{"message":"read failed"}]}'
                ;;
            "GET:/zones/zid/dns_records?type=A&name=delete-fail.example.com")
                printf '{"success":true,"result":[{"id":"keep-a"},{"id":"stale-a"}]}'
                ;;
            "PUT:/zones/zid/dns_records/keep-a")
                printf '{"success":true,"result":{"id":"keep-a"}}'
                ;;
            "DELETE:/zones/zid/dns_records/stale-a")
                printf '{"success":false,"errors":[{"message":"delete failed"}]}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    _cf_update_dns_record "zid" "token-mock" "host.example.com" "A" "198.51.100.7" "true" >/dev/null
    _cf_update_dns_record "zid" "token-mock" "host.example.com" "AAAA" "2001:db8::7" "false" >/dev/null

    local put_ok post_ok delete_ok rc
    put_ok=$(jq -r 'select(.method=="PUT") | [.endpoint, .body.content, (.body.ttl|tostring), (.body.proxied|tostring)] | @tsv' "$calls")
    post_ok=$(jq -r 'select(.method=="POST") | [.body.type, .body.content, (.body.proxied|tostring)] | @tsv' "$calls")
    delete_ok=$(jq -r 'select(.method=="DELETE") | .endpoint' "$calls")
    [[ "$put_ok" == $'/zones/zid/dns_records/old-a\t198.51.100.7\t1\ttrue' ]] \
        && pass "_cf_update_dns_record PUT keeps ttl=1 and proxied=true" \
        || fail "_cf_update_dns_record PUT payload mismatch: $put_ok"
    [[ "$delete_ok" == "/zones/zid/dns_records/extra-a" ]] \
        && pass "_cf_update_dns_record deletes stale duplicate records after update" \
        || fail "_cf_update_dns_record did not delete stale duplicate records: $delete_ok"
    [[ "$post_ok" == $'AAAA\t2001:db8::7\tfalse' ]] \
        && pass "_cf_update_dns_record POST creates missing record" \
        || fail "_cf_update_dns_record POST payload mismatch: $post_ok"

    _cf_update_dns_record "zid" "token-mock" "fail.example.com" "A" "198.51.100.8" "false" >/dev/null
    rc=$?
    [[ $rc -ne 0 ]] \
        && pass "_cf_update_dns_record fails closed when record read fails" \
        || fail "_cf_update_dns_record should fail when record read fails"

    _cf_update_dns_record "zid" "token-mock" "delete-fail.example.com" "A" "198.51.100.9" "false" >/dev/null
    rc=$?
    [[ $rc -ne 0 ]] \
        && pass "_cf_update_dns_record fails closed when stale duplicate delete fails" \
        || fail "_cf_update_dns_record swallowed stale duplicate delete failure"

    : > "$calls"
    _cf_update_dns_record "zid" "token-mock" "empty.example.com" "A" "" "false" >/dev/null
    rc=$?
    [[ $rc -ne 0 && ! -s "$calls" ]] \
        && pass "_cf_update_dns_record rejects empty target IP before API calls" \
        || fail "_cf_update_dns_record accepted empty target IP or called API"
}

test_cf_dns_snapshot_restore_records() {
    local calls="$TMP_ROOT/cf-dns-restore-calls.jsonl"
    : > "$calls"
    _cf_api() {
        local method="$1" endpoint="$2" token="$3"
        shift 3
        [[ "$token" == "token-mock" ]] || return 1
        jq -nc --arg method "$method" --arg endpoint "$endpoint" \
            '{method:$method, endpoint:$endpoint}' >> "$calls"
        case "${method}:${endpoint}" in
            "GET:/zones/zid/dns_records?type=A&name=app.example.com")
                printf '{"success":true,"result":[{"id":"old-a","type":"A","name":"app.example.com","content":"198.51.100.10","ttl":1,"proxied":true}]}'
                ;;
            "GET:/zones/zid/dns_records?type=AAAA&name=app.example.com")
                printf '{"success":true,"result":[{"id":"old-aaaa","type":"AAAA","name":"app.example.com","content":"2001:db8::10","ttl":1,"proxied":false}]}'
                ;;
            "GET:/zones/zid/dns_records?type=CNAME&name=app.example.com")
                printf '{"success":true,"result":[]}'
                ;;
            "DELETE:/zones/zid/dns_records/old-a"|"DELETE:/zones/zid/dns_records/old-aaaa")
                printf '{"success":true,"result":{}}'
                ;;
            "POST:/zones/zid/dns_records")
                local data
                data=$(capture_data_arg "$@")
                jq -nc --argjson body "$data" '{method:"POST_BODY", body:$body}' >> "$calls"
                printf '{"success":true,"result":{"id":"restored"}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    local snapshot posts deletes
    snapshot=$(_cf_dns_snapshot_records "zid" "token-mock" "app.example.com" A AAAA CNAME) || {
        fail "_cf_dns_snapshot_records failed on mock records"
        return
    }
    if jq -e 'length == 2 and .[0].content == "198.51.100.10" and .[1].content == "2001:db8::10"' >/dev/null <<< "$snapshot"; then
        pass "_cf_dns_snapshot_records captures A/AAAA/CNAME state"
    else
        fail "_cf_dns_snapshot_records snapshot mismatch: $snapshot"
    fi

    _cf_dns_restore_records "zid" "token-mock" "app.example.com" "$snapshot" A AAAA CNAME >/dev/null
    local rc=$?
    deletes=$(jq -r 'select(.method=="DELETE") | .endpoint' "$calls" | paste -sd ',')
    posts=$(jq -r 'select(.method=="POST_BODY") | [.body.type, .body.content, (.body.proxied|tostring)] | @tsv' "$calls" | paste -sd '|')
    if [[ $rc -eq 0 ]] \
       && [[ "$deletes" == "/zones/zid/dns_records/old-a,/zones/zid/dns_records/old-aaaa" ]] \
       && [[ "$posts" == $'A\t198.51.100.10\ttrue|AAAA\t2001:db8::10\tfalse' ]]; then
        pass "_cf_dns_restore_records deletes current records and recreates snapshot"
    else
        fail "_cf_dns_restore_records restore mismatch rc=$rc deletes=$deletes posts=$posts"
        sed 's/^/    /' "$calls"
    fi
}

test_web_cf_dns_update_fail_closed() {
    local log="$TMP_ROOT/web-cf-dns-update.log"
    : > "$log"
    command_exists() { [[ "${1:-}" == "jq" ]]; }
    get_public_ipv4() { printf '198.51.100.12\n'; }
    get_public_ipv6() { printf '2001:db8::12\n'; }
    _cf_read_token() {
        printf -v "$1" '%s' "token-mock"
        return 0
    }
    _cf_get_zone_id() {
        printf 'zone-mock\n'
        return 0
    }
    ddns_setup() {
        printf 'ddns|%s|%s|%s|%s|%s|%s\n' "$@" >> "$log"
        [[ "${WEB_CF_DDNS_OK:-1}" == "1" ]]
    }
    _cf_update_dns_record() {
        printf 'update|%s|%s|%s|%s|%s|%s\n' "$@" >> "$log"
        [[ "${WEB_CF_FAIL_TYPE:-}" != "${4:-}" ]]
    }

    local rc
    WEB_CF_FAIL_TYPE=A WEB_CF_DDNS_OK=1
    _CF_RESULT_DOMAIN="old.example.com"
    _CF_RESULT_TOKEN="old-token"
    CACHED_IPV4=""
    CACHED_IPV6=""
    web_cf_dns_update >/dev/null 2>&1 <<< $'3\nexample.com\nn\n'
    rc=$?
    if [[ $rc -ne 0 ]] \
       && grep -q '^update|zone-mock|token-mock|example.com|A|198.51.100.12|false$' "$log" \
       && ! grep -q '^update|.*|AAAA|' "$log" \
       && ! grep -q '^ddns|' "$log" \
       && [[ -z "$_CF_RESULT_DOMAIN" && -z "$_CF_RESULT_TOKEN" ]]; then
        pass "web_cf_dns_update fails closed when A/AAAA update fails"
    else
        fail "web_cf_dns_update DNS failure path mismatch rc=$rc result=${_CF_RESULT_DOMAIN:-unset}/${_CF_RESULT_TOKEN:-unset}"
        sed 's/^/    /' "$log"
    fi

    : > "$log"
    WEB_CF_FAIL_TYPE="" WEB_CF_DDNS_OK=0
    _CF_RESULT_DOMAIN="old.example.com"
    _CF_RESULT_TOKEN="old-token"
    CACHED_IPV4=""
    CACHED_IPV6=""
    web_cf_dns_update >/dev/null 2>&1 <<< $'1\nexample.com\nn\n'
    rc=$?
    if [[ $rc -ne 0 ]] \
       && grep -q '^update|zone-mock|token-mock|example.com|A|198.51.100.12|false$' "$log" \
       && grep -q '^ddns|example.com|token-mock|zone-mock|true|false|false$' "$log" \
       && [[ -z "$_CF_RESULT_DOMAIN" && -z "$_CF_RESULT_TOKEN" ]]; then
        pass "web_cf_dns_update fails closed when DDNS setup fails"
    else
        fail "web_cf_dns_update DDNS failure path mismatch rc=$rc result=${_CF_RESULT_DOMAIN:-unset}/${_CF_RESULT_TOKEN:-unset}"
        sed 's/^/    /' "$log"
    fi

    : > "$log"
    get_public_ipv4() { :; }
    get_public_ipv6() { printf '2001:db8::12\n'; }
    _CF_RESULT_DOMAIN="old.example.com"
    _CF_RESULT_TOKEN="old-token"
    CACHED_IPV4=""
    CACHED_IPV6=""
    web_cf_dns_update >/dev/null 2>&1 <<< $'1\n'
    rc=$?
    if [[ $rc -ne 0 ]] \
       && [[ ! -s "$log" ]] \
       && [[ -z "$_CF_RESULT_DOMAIN" && -z "$_CF_RESULT_TOKEN" ]]; then
        pass "web_cf_dns_update refuses selected IPv4 mode when IPv4 is missing"
    else
        fail "web_cf_dns_update allowed selected IPv4 mode without IPv4 rc=$rc result=${_CF_RESULT_DOMAIN:-unset}/${_CF_RESULT_TOKEN:-unset}"
        sed 's/^/    /' "$log"
    fi
    unset WEB_CF_FAIL_TYPE WEB_CF_DDNS_OK
}

test_cf_dns_delete_checks_delete_success() {
    local calls="$TMP_ROOT/cf-dns-delete-calls.txt"
    : > "$calls"
    _cf_api() {
        local method="$1" endpoint="$2"
        printf '%s %s\n' "$method" "$endpoint" >> "$calls"
        case "${method}:${endpoint}" in
            "GET:/zones/zid/dns_records?type=CNAME&name=ok.example.com")
                printf '{"success":true,"result":[{"id":"rec-ok"}]}'
                ;;
            "DELETE:/zones/zid/dns_records/rec-ok")
                printf '{"success":true,"result":{"id":"rec-ok"}}'
                ;;
            "GET:/zones/zid/dns_records?type=CNAME&name=fail.example.com")
                printf '{"success":true,"result":[{"id":"rec-fail"}]}'
                ;;
            "DELETE:/zones/zid/dns_records/rec-fail")
                printf '{"success":false,"errors":[{"message":"delete denied"}]}'
                ;;
            "GET:/zones/zid/dns_records?type=CNAME&name=missing.example.com")
                printf '{"success":true,"result":[]}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected call"}]}'
                return 1
                ;;
        esac
    }

    local rc
    _cf_dns_delete "zid" "token-mock" "CNAME" "ok.example.com" >/dev/null
    rc=$?
    [[ $rc -eq 0 ]] \
        && pass "_cf_dns_delete succeeds only when DELETE response is success=true" \
        || fail "_cf_dns_delete unexpectedly failed on success path"

    _cf_dns_delete "zid" "token-mock" "CNAME" "fail.example.com" >/dev/null
    rc=$?
    [[ $rc -ne 0 ]] \
        && pass "_cf_dns_delete fails closed when DELETE response is success=false" \
        || fail "_cf_dns_delete swallowed DELETE success=false"

    local delete_count_before delete_count_after
    delete_count_before=$(grep -c '^DELETE ' "$calls" 2>/dev/null || echo 0)
    _cf_dns_delete "zid" "token-mock" "CNAME" "missing.example.com" >/dev/null
    rc=$?
    delete_count_after=$(grep -c '^DELETE ' "$calls" 2>/dev/null || echo 0)
    [[ $rc -eq 0 && "$delete_count_after" -eq "$delete_count_before" ]] \
        && pass "_cf_dns_delete treats absent records as already clean" \
        || fail "_cf_dns_delete absent-record behavior mismatch"
}

test_reality_cf_dns_delete_paginates_and_checks_delete_success() {
    local calls="$TMP_ROOT/reality-dns-delete-calls.txt"
    : > "$calls"
    _cf_get_zone_id() { printf 'zid\n'; }
    _cf_api() {
        local method="$1" endpoint="$2"
        printf '%s %s\n' "$method" "$endpoint" >> "$calls"
        case "${method}:${endpoint}" in
            "GET:/zones/zid/dns_records?type=AAAA&name=cdn.example.com&per_page=100&page=1")
                printf '{"success":true,"result":[{"id":"aaaa-1"}],"result_info":{"total_pages":2}}'
                ;;
            "GET:/zones/zid/dns_records?type=AAAA&name=cdn.example.com&per_page=100&page=2")
                printf '{"success":true,"result":[{"id":"aaaa-2"}],"result_info":{"total_pages":2}}'
                ;;
            "DELETE:/zones/zid/dns_records/aaaa-1"|"DELETE:/zones/zid/dns_records/aaaa-2")
                printf '{"success":true,"result":{}}'
                ;;
            "GET:/zones/zid/dns_records?type=A&name=fail.example.com&per_page=100&page=1")
                printf '{"success":true,"result":[{"id":"a-fail"}],"result_info":{"total_pages":1}}'
                ;;
            "DELETE:/zones/zid/dns_records/a-fail")
                printf '{"success":false,"errors":[{"message":"delete denied"}]}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    if reality_cf_delete_dns_type "cdn.example.com" "token-mock" "AAAA" >/dev/null \
       && grep -Fq 'GET /zones/zid/dns_records?type=AAAA&name=cdn.example.com&per_page=100&page=2' "$calls" \
       && grep -Fq 'DELETE /zones/zid/dns_records/aaaa-1' "$calls" \
       && grep -Fq 'DELETE /zones/zid/dns_records/aaaa-2' "$calls"; then
        pass "reality_cf_delete_dns_type paginates matching DNS records"
    else
        fail "reality_cf_delete_dns_type did not delete all paged records"
        sed 's/^/    /' "$calls"
    fi

    if reality_cf_delete_dns_type "fail.example.com" "token-mock" "A" >/dev/null; then
        fail "reality_cf_delete_dns_type swallowed DELETE success=false"
    else
        pass "reality_cf_delete_dns_type fails closed on DELETE success=false"
    fi
}

test_reality_cdn_sync_dns_orange_cleans_stale_family() {
    local calls="$TMP_ROOT/reality-cdn-dns-calls.txt"
    : > "$calls"
    command_exists() { [[ "${1:-}" == "jq" ]]; }
    install_package() { return 0; }
    _cf_verify_token() { return 0; }
    _cf_get_zone_id() { printf 'zid\n'; }
    reality_detect_ips() { REALITY_IPV4="198.51.100.44"; REALITY_IPV6=""; }
    _cf_update_dns_record() {
        printf 'upsert|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$calls"
    }
    _cf_api() {
        local method="$1" endpoint="$2"
        printf 'api|%s|%s\n' "$method" "$endpoint" >> "$calls"
        case "${method}:${endpoint}" in
            "GET:/zones/zid/dns_records?type=AAAA&name=cdn.example.com&per_page=100&page=1")
                printf '{"success":true,"result":[{"id":"old-aaaa"}],"result_info":{"total_pages":1}}'
                ;;
            "DELETE:/zones/zid/dns_records/old-aaaa")
                printf '{"success":true,"result":{}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }

    if reality_cdn_sync_dns_orange "cdn.example.com" "token-mock" >/dev/null \
       && grep -Fq 'upsert|zid|token-mock|cdn.example.com|A|198.51.100.44|true' "$calls" \
       && grep -Fq 'api|DELETE|/zones/zid/dns_records/old-aaaa' "$calls"; then
        pass "reality_cdn_sync_dns_orange deletes stale AAAA when only IPv4 is detected"
    else
        fail "reality_cdn_sync_dns_orange did not clean stale address family"
        sed 's/^/    /' "$calls"
    fi
}

test_reality_cf_list_zones_uses_pagination() {
    _cf_api() {
        local method="$1" endpoint="$2"
        [[ "$method" == "GET" ]] || return 1
        case "$endpoint" in
            "/zones?per_page=50&page=1")
                printf '{"success":true,"result":[{"name":"a.example"}],"result_info":{"total_pages":2}}'
                ;;
            "/zones?per_page=50&page=2")
                printf '{"success":true,"result":[{"name":"b.example"}],"result_info":{"total_pages":2}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }
    local names
    names=$(reality_cf_list_zones "token-mock" | paste -sd ',')
    [[ "$names" == "a.example,b.example" ]] \
        && pass "reality_cf_list_zones aggregates paged zone results" \
        || fail "reality_cf_list_zones pagination mismatch: $names"
}

test_cf_origin_ruleset_get() {
    curl() {
        case "${ORIGIN_MODE:-}" in
            ok)
                printf '%s\n200' '{"success":true,"result":{"rules":[{"id":"rule-1"}]}}'
                ;;
            missing)
                printf '%s\n404' '{"success":false,"errors":[{"message":"not found"}]}'
                ;;
            fail)
                return 28
                ;;
            *)
                return 2
                ;;
        esac
    }

    local out rc
    ORIGIN_MODE=ok
    out=$(_cf_get_origin_ruleset "token-mock" "zid")
    rc=$?
    [[ $rc -eq 0 && "$(jq -r '.result.rules[0].id' <<< "$out")" == "rule-1" ]] \
        && pass "_cf_get_origin_ruleset returns 200 body" \
        || fail "_cf_get_origin_ruleset 200 handling failed"

    ORIGIN_MODE=missing
    out=$(_cf_get_origin_ruleset "token-mock" "zid")
    rc=$?
    [[ $rc -eq 0 && -z "$out" ]] \
        && pass "_cf_get_origin_ruleset treats 404 as empty ruleset" \
        || fail "_cf_get_origin_ruleset 404 handling failed rc=$rc out=$out"

    ORIGIN_MODE=fail
    out=$(_cf_get_origin_ruleset "token-mock" "zid")
    rc=$?
    [[ $rc -ne 0 && "$(jq -r '.errors[0].message' <<< "$out")" == "Origin Rules 读取失败或超时" ]] \
        && pass "_cf_get_origin_ruleset reports network timeout" \
        || fail "_cf_get_origin_ruleset network failure handling failed"
}

test_reality_cdn_origin_rule_get_failure_does_not_put() {
    local put_calls="$TMP_ROOT/reality-origin-put-calls.txt"
    local real_cf_get_zone_id real_validate_domain real_validate_port real_command_exists real_cf_get_origin_ruleset real_cf_put_origin_ruleset
    real_cf_get_zone_id="$(declare -f _cf_get_zone_id 2>/dev/null || true)"
    real_validate_domain="$(declare -f validate_domain 2>/dev/null || true)"
    real_validate_port="$(declare -f validate_port 2>/dev/null || true)"
    real_command_exists="$(declare -f command_exists 2>/dev/null || true)"
    real_cf_get_origin_ruleset="$(declare -f _cf_get_origin_ruleset 2>/dev/null || true)"
    real_cf_put_origin_ruleset="$(declare -f _cf_put_origin_ruleset 2>/dev/null || true)"
    : > "$put_calls"
    _cf_get_zone_id() { printf 'zid\n'; }
    validate_domain() { return 0; }
    validate_port() { return 0; }
    command_exists() { return 0; }
    _cf_get_origin_ruleset() { printf '{"success":false,"errors":[{"message":"timeout"}]}'; return 1; }
    _cf_put_origin_ruleset() { printf '%s\n' "$3" >> "$put_calls"; return 0; }

    local rc
    reality_cdn_apply_origin_rule "cdn.example.com" "token-mock" "8443" >/dev/null 2>&1
    rc=$?
    [[ $rc -ne 0 && ! -s "$put_calls" ]] \
        && pass "reality_cdn_apply_origin_rule fails closed when Origin Rules GET fails" \
        || fail "reality_cdn_apply_origin_rule wrote rules after GET failure"
    eval "$real_cf_get_zone_id"
    eval "$real_validate_domain"
    eval "$real_validate_port"
    eval "$real_command_exists"
    eval "$real_cf_get_origin_ruleset"
    eval "$real_cf_put_origin_ruleset"
}

test_cf_origin_ruleset_put() {
    local payload_file="$TMP_ROOT/origin-payload.json"
    local args_file="$TMP_ROOT/origin-put-args.txt"
    curl() {
        local data
        printf '%s\n' "$*" > "$args_file"
        data=$(capture_data_arg "$@")
        printf '%s' "$data" > "$payload_file"
        printf '{"success":true}'
    }

    _cf_put_origin_ruleset "token-mock" "zid" '[{"expression":"http.host eq \"x.example.com\"","action":"route"}]' >/dev/null
    jq -e '.rules[0].expression == "http.host eq \"x.example.com\"" and .rules[0].action == "route"' "$payload_file" >/dev/null \
        && pass "_cf_put_origin_ruleset wraps rules in payload" \
        || fail "_cf_put_origin_ruleset payload mismatch"
    grep -Fq -- '--connect-timeout 10 --max-time 30 -X PUT' "$args_file" \
        && pass "_cf_put_origin_ruleset sets connect and total timeouts" \
        || fail "_cf_put_origin_ruleset curl args missing timeout: $(<"$args_file")"

    curl() {
        printf '{"success":false,"errors":[{"message":"bad rules"}]}'
    }
    local out rc
    out=$(_cf_put_origin_ruleset "token-mock" "zid" '[]')
    rc=$?
    [[ $rc -ne 0 && "$out" == "bad rules" ]] \
        && pass "_cf_put_origin_ruleset returns CF error message" \
        || fail "_cf_put_origin_ruleset error handling failed rc=$rc out=$out"
}

test_cf_origin_rules_snapshot_restore() {
    local real_get real_put calls="$TMP_ROOT/origin-snapshot-restore.txt"
    real_get="$(declare -f _cf_get_origin_ruleset 2>/dev/null || true)"
    real_put="$(declare -f _cf_put_origin_ruleset 2>/dev/null || true)"
    : > "$calls"

    _cf_get_origin_ruleset() {
        case "${ORIGIN_SNAPSHOT_MODE:-ok}" in
            ok) jq -nc '{success:true,result:{rules:[{id:"old",expression:"http.host eq \"old.example.com\""}]}}' ;;
            missing) return 0 ;;
            fail) printf '{"success":false,"errors":[{"message":"timeout"}]}'; return 1 ;;
        esac
    }
    _cf_put_origin_ruleset() {
        printf 'put|%s|%s|%s\n' "$1" "$2" "$3" >> "$calls"
        [[ "${ORIGIN_RESTORE_OK:-1}" == "1" ]]
    }

    local snapshot rc
    ORIGIN_SNAPSHOT_MODE=ok
    snapshot=$(_cf_origin_rules_snapshot "token-mock" "zid")
    rc=$?
    [[ $rc -eq 0 && "$(jq -r '.[0].id' <<< "$snapshot")" == "old" ]] \
        && pass "_cf_origin_rules_snapshot captures existing rules array" \
        || fail "_cf_origin_rules_snapshot existing mismatch rc=$rc snapshot=$snapshot"

    ORIGIN_SNAPSHOT_MODE=missing
    snapshot=$(_cf_origin_rules_snapshot "token-mock" "zid")
    rc=$?
    [[ $rc -eq 0 && "$snapshot" == "[]" ]] \
        && pass "_cf_origin_rules_snapshot treats absent ruleset as empty array" \
        || fail "_cf_origin_rules_snapshot missing mismatch rc=$rc snapshot=$snapshot"

    _cf_origin_rules_restore "token-mock" "zid" '[{"id":"old"}]' >/dev/null
    rc=$?
    [[ $rc -eq 0 && "$(tail -n 1 "$calls")" == 'put|token-mock|zid|[{"id":"old"}]' ]] \
        && pass "_cf_origin_rules_restore writes snapshot rules array" \
        || fail "_cf_origin_rules_restore did not PUT snapshot rc=$rc"

    ORIGIN_RESTORE_OK=0
    _cf_origin_rules_restore "token-mock" "zid" '[{"id":"old"}]' >/dev/null
    rc=$?
    [[ $rc -ne 0 ]] \
        && pass "_cf_origin_rules_restore propagates PUT failure" \
        || fail "_cf_origin_rules_restore swallowed PUT failure"

    eval "$real_get"
    eval "$real_put"
    unset ORIGIN_SNAPSHOT_MODE ORIGIN_RESTORE_OK
}

test_email_cf_api_redaction_and_rcs() {
    : > "$EMAIL_LOG_FILE"
    curl() {
        printf '{"success":false,"errors":[{"code":9100,"message":"bad secret"}]}'
    }

    local body='{"name":"ADMIN_PASSWORDS","text":"super-secret"}'
    local rc
    _email_cf_api PUT "accounts/acct-mock/workers/scripts/w/secrets" "$body" >/dev/null
    rc=$?
    if [[ $rc -eq 1 ]] && grep -q '<redacted: secret payload>' "$EMAIL_LOG_FILE" && ! grep -q 'super-secret' "$EMAIL_LOG_FILE"; then
        pass "_email_cf_api redacts secret payloads in logs"
    else
        fail "_email_cf_api did not redact secret payload correctly"
    fi

    curl() {
        printf '{"success":true,"result":{"id":"ok"}}'
    }
    local out
    out=$(_email_cf_api GET "user/tokens/verify")
    [[ "$(jq -r '.result.id' <<< "$out")" == "ok" ]] \
        && pass "_email_cf_api returns successful response body" \
        || fail "_email_cf_api success body mismatch"

    curl() {
        return 7
    }
    _email_cf_api GET "user/tokens/verify" >/dev/null
    rc=$?
    [[ $rc -eq 2 ]] \
        && pass "_email_cf_api maps curl failure to rc=2" \
        || fail "_email_cf_api network rc mismatch: $rc"
}

test_email_cf_delete_idempotency() {
    curl() {
        printf '%s\n404' '{"success":false,"errors":[{"code":1003,"message":"not found"}]}'
    }
    local rc
    _email_cf_api_delete "zones/zid/dns_records/rid" >/dev/null
    rc=$?
    [[ $rc -eq 0 ]] \
        && pass "_email_cf_api_delete treats 404 as success" \
        || fail "_email_cf_api_delete 404 rc mismatch: $rc"

    curl() {
        printf '%s\n500' '{"success":false,"errors":[{"code":999,"message":"boom"}]}'
    }
    _email_cf_api_delete "zones/zid/dns_records/rid" >/dev/null
    rc=$?
    [[ $rc -eq 1 ]] \
        && pass "_email_cf_api_delete keeps non-404 API failures" \
        || fail "_email_cf_api_delete 500 rc mismatch: $rc"

    curl() {
        return 28
    }
    _email_cf_api_delete "zones/zid/dns_records/rid" >/dev/null
    rc=$?
    [[ $rc -eq 2 ]] \
        && pass "_email_cf_api_delete maps network failure to rc=2" \
        || fail "_email_cf_api_delete network rc mismatch: $rc"

    local calls="$TMP_ROOT/email-catchall-disable.log"
    : > "$calls"
    _email_cf_api() {
        printf 'email-cf-api|%s|%s|%s\n' "$1" "$2" "${3:-}" >> "$calls"
        return 7
    }
    if _email_cf_catch_all_disable "zone-catch" >/dev/null 2>&1; then
        fail "_email_cf_catch_all_disable swallowed API failure"
    elif grep -Fq 'email-cf-api|PUT|zones/zone-catch/email/routing/rules/catch_all|' "$calls"; then
        pass "_email_cf_catch_all_disable propagates API failure"
    else
        fail "_email_cf_catch_all_disable did not call expected API endpoint"
    fi
}

test_email_cf_dns_helpers() {
    local enc id capture="$TMP_ROOT/email-dns-body.json"
    enc=$(_email_cf_urlencode "a b@c.com")
    [[ "$enc" == "a%20b%40c.com" ]] \
        && pass "_email_cf_urlencode encodes query components" \
        || fail "_email_cf_urlencode mismatch: $enc"

    _email_cf_api() {
        local method="$1" path="$2" body="${3:-}"
        [[ "$method" == "POST" && "$path" == "zones/zid/dns_records" ]] || return 1
        printf '%s' "$body" > "$capture"
        printf '{"success":true,"result":{"id":"rid-1"}}'
    }
    id=$(_email_cf_dns_create "zid" "MX" "mail.example.com" "route1.mx.cloudflare.net" "10" "false")
    if [[ "$id" == "rid-1" ]] && jq -e '.type=="MX" and .priority==10 and .proxied==false' "$capture" >/dev/null; then
        pass "_email_cf_dns_create builds MX priority/proxied payload"
    else
        fail "_email_cf_dns_create payload/id mismatch"
    fi

    _email_cf_api() {
        local method="$1" path="$2"
        [[ "$method" == "GET" ]] || return 1
        case "$path" in
            "zones/zid/dns_records?type=TXT&name=_dmarc.example.com&per_page=50&page=1")
                printf '{"success":true,"result":[{"id":"rid-page-1"}],"result_info":{"total_pages":2}}'
                ;;
            "zones/zid/dns_records?type=TXT&name=_dmarc.example.com&per_page=50&page=2")
                printf '{"success":true,"result":[{"id":"rid-page-2"}],"result_info":{"total_pages":2}}'
                ;;
            *)
                printf '{"success":false,"errors":[{"message":"unexpected endpoint"}]}'
                return 1
                ;;
        esac
    }
    local paged_ids
    paged_ids=$(_email_cf_dns_find_ids "zid" "TXT" "_dmarc.example.com" | paste -sd ',')
    [[ "$paged_ids" == "rid-page-1,rid-page-2" ]] \
        && pass "_email_cf_dns_find_ids paginates all matching records" \
        || fail "_email_cf_dns_find_ids pagination mismatch: $paged_ids"

    local deleted="$TMP_ROOT/deleted-records.txt"
    : > "$deleted"
    _email_cf_dns_find_ids() {
        printf 'rid-a\n\nrid-b\n'
    }
    _email_cf_dns_delete() {
        printf '%s\n' "$2" >> "$deleted"
    }
    _email_cf_dns_purge "zid" "TXT" "_dmarc.example.com"
    [[ "$(paste -sd ',' "$deleted")" == "rid-a,rid-b" ]] \
        && pass "_email_cf_dns_purge deletes all non-empty matched ids" \
        || fail "_email_cf_dns_purge deleted ids: $(paste -sd ',' "$deleted")"

    : > "$deleted"
    _email_cf_dns_find_ids() {
        printf 'rid-ok\nrid-fail\n'
    }
    _email_cf_dns_delete() {
        printf '%s\n' "$2" >> "$deleted"
        [[ "$2" != "rid-fail" ]]
    }
    if _email_cf_dns_purge "zid" "TXT" "_dmarc.example.com"; then
        fail "_email_cf_dns_purge swallowed delete failure"
    elif [[ "$(paste -sd ',' "$deleted")" == "rid-ok,rid-fail" ]]; then
        pass "_email_cf_dns_purge reports delete failure after best-effort deletes"
    else
        fail "_email_cf_dns_purge failure path deleted ids: $(paste -sd ',' "$deleted")"
    fi

    _email_cf_dns_find_ids() {
        return 9
    }
    if _email_cf_dns_purge "zid" "TXT" "_dmarc.example.com"; then
        fail "_email_cf_dns_purge swallowed find failure"
    else
        pass "_email_cf_dns_purge reports find failure"
    fi
}

test_email_cf_worker_exists_tristate() {
    local url_file="$TMP_ROOT/worker-url.txt"
    curl() {
        local arg
        for arg in "$@"; do
            [[ "$arg" == https://* ]] && printf '%s' "$arg" > "$url_file"
        done
        case "${WORKER_MODE:-}" in
            ok)
                printf '%s\n200' '{"success":true,"result":{"id":"worker"}}'
                ;;
            missing)
                printf '%s\n404' '{"success":false,"errors":[{"code":10007,"message":"not found"}]}'
                ;;
            error)
                printf '%s\n500' '{"success":false,"errors":[{"code":9000,"message":"boom"}]}'
                ;;
            network)
                return 7
                ;;
            *)
                return 2
                ;;
        esac
    }

    local rc
    WORKER_MODE=ok
    : > "$url_file"
    _email_cf_worker_exists "worker name" >/dev/null
    rc=$?
    local worker_url
    worker_url=$(<"$url_file")
    [[ $rc -eq 0 && "$worker_url" == *"worker%20name" ]] \
        && pass "_email_cf_worker_exists returns rc=0 and encodes script name" \
        || fail "_email_cf_worker_exists ok rc/url mismatch rc=$rc url=$worker_url"

    WORKER_MODE=missing
    _email_cf_worker_exists "worker name" >/dev/null
    rc=$?
    [[ $rc -eq 1 ]] \
        && pass "_email_cf_worker_exists returns rc=1 for 404 missing" \
        || fail "_email_cf_worker_exists missing rc mismatch: $rc"

    WORKER_MODE=error
    _email_cf_worker_exists "worker name" >/dev/null
    rc=$?
    [[ $rc -eq 2 ]] \
        && pass "_email_cf_worker_exists returns rc=2 for indeterminate API error" \
        || fail "_email_cf_worker_exists API error rc mismatch: $rc"

    WORKER_MODE=network
    _email_cf_worker_exists "worker name" >/dev/null
    rc=$?
    [[ $rc -eq 2 ]] \
        && pass "_email_cf_worker_exists returns rc=2 for network failure" \
        || fail "_email_cf_worker_exists network rc mismatch: $rc"
}

echo "== Cloudflare web API mocks =="
test_cf_list_zones_pagination
test_cf_get_zone_id_fallback
test_cf_update_dns_record_put_post_failure
test_cf_dns_snapshot_restore_records
test_web_cf_dns_update_fail_closed
test_cf_dns_delete_checks_delete_success
test_reality_cf_dns_delete_paginates_and_checks_delete_success
test_reality_cdn_sync_dns_orange_cleans_stale_family
test_reality_cf_list_zones_uses_pagination
test_cf_origin_ruleset_get
test_reality_cdn_origin_rule_get_failure_does_not_put
test_cf_origin_ruleset_put
test_cf_origin_rules_snapshot_restore

echo ""
echo "== Email Cloudflare API mocks =="
test_email_cf_api_redaction_and_rcs
test_email_cf_delete_idempotency
test_email_cf_dns_helpers
test_email_cf_worker_exists_tristate

echo ""
echo "SUMMARY PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
