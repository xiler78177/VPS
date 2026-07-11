#!/usr/bin/env bash
# Low-side-effect coverage for system/network/firewall/fail2ban helpers.
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

count_lines_equal() {
    local file="${1:-}" value="${2:-}"
    awk -v value="$value" '$0 == value { c++ } END { print c + 0 }' "$file" 2>/dev/null || echo 0
}

if [[ ! -f "$BUILT" ]]; then
    echo "missing built script: $BUILT"
    exit 1
fi

head -n -1 "$BUILT" > "$LIB"
sed -i \
    -e "s|^readonly WG_SHARED_DB_DIR=.*|readonly WG_SHARED_DB_DIR=\"$TMP_ROOT/wireguard/db\"|" \
    -e "s|^readonly WG_SHARED_DB_FILE=.*|readonly WG_SHARED_DB_FILE=\"$TMP_ROOT/wireguard/db/wg-data.json\"|" \
    -e "s|^readonly WG_SHARED_ROLE_FILE=.*|readonly WG_SHARED_ROLE_FILE=\"$TMP_ROOT/wireguard/.role\"|" \
    -e "s|^readonly WG_SHARED_ROUTE_STATE_FILE=.*|readonly WG_SHARED_ROUTE_STATE_FILE=\"$TMP_ROOT/wireguard/db/managed-routes.state\"|" \
    -e "s|^readonly WG_DEB_CONF=.*|readonly WG_DEB_CONF=\"$TMP_ROOT/wireguard/wg0.conf\"|" \
    -e "s|^readonly WG_DEB_CLIENT_DIR=.*|readonly WG_DEB_CLIENT_DIR=\"$TMP_ROOT/wireguard/clients\"|" \
    -e "s|^readonly FAIL2BAN_JAIL_LOCAL=.*|readonly FAIL2BAN_JAIL_LOCAL=\"$TMP_ROOT/jail.local\"|" \
    -e "s|^CERT_PATH_PREFIX=.*|CERT_PATH_PREFIX=\"$TMP_ROOT/cert\"|" \
    -e "s|^CONFIG_DIR=.*|CONFIG_DIR=\"$TMP_ROOT/cert/.managed_domains\"|" \
    -e "s|^DDNS_CONFIG_DIR=.*|DDNS_CONFIG_DIR=\"$TMP_ROOT/ddns\"|" \
    "$LIB"

# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || { echo "source failed: $LIB"; exit 1; }
ORIG_WG_RESTORE_NETWORK_UCI_SNAPSHOT_DEF=$(declare -f _wg_openwrt_restore_network_uci_snapshot)
ORIG_WG_WRITE_NETWORK_UCI_FROM_DB_DEF=$(declare -f _wg_openwrt_write_network_uci_from_db)
ORIG_WG_REBUILD_UCI_CONF_DEF=$(declare -f wg_rebuild_uci_conf)

pause() { :; }
draw_line() { :; }
log_action() { :; }
print_info() { :; }
print_success() { :; }
print_warn() { :; }
print_error() { :; }
print_title() { :; }
fix_terminal() { :; }
confirm() { return 0; }
install_package() { return 0; }
is_systemd() { return 0; }

test_f2b_ipv6_banned_ip_parsing() {
    fail2ban-client() {
        case "$*" in
            "status sshd")
                cat <<'EOF'
Status for the jail: sshd
|- Filter
`- Actions
   |- Currently banned: 2
   |- Total banned: 2
   `- Banned IP list: 192.0.2.10 2001:db8::10
EOF
                ;;
            "status")
                printf 'Status\n|- Number of jail: 1\n`- Jail list: sshd\n'
                ;;
            *)
                return 1
                ;;
        esac
    }

    local ips
    ips=$(_f2b_banned_ips_for_jail "sshd")
    [[ "$ips" == "192.0.2.10 2001:db8::10" ]] \
        && pass "_f2b_banned_ips_for_jail preserves IPv6 addresses" \
        || fail "_f2b_banned_ips_for_jail parsed '$ips'"
}

test_f2b_unban_ipv6_exact_match() {
    local calls="$TMP_ROOT/f2b-unban-calls.txt"
    : > "$calls"
    fail2ban-client() {
        case "$*" in
            "status")
                printf 'Status\n|- Number of jail: 2\n`- Jail list: sshd, nginx-http-auth\n'
                ;;
            "status sshd")
                cat <<'EOF'
Status for the jail: sshd
`- Actions
   `- Banned IP list: 192.0.2.10 2001:db8::10
EOF
                ;;
            "status nginx-http-auth")
                cat <<'EOF'
Status for the jail: nginx-http-auth
`- Actions
   `- Banned IP list: 198.51.100.50
EOF
                ;;
            set\ *\ unbanip\ *)
                printf '%s\n' "$*" >> "$calls"
                ;;
            *)
                return 1
                ;;
        esac
    }

    printf '2001:db8::10\n' | f2b_unban >/dev/null 2>&1
    local called
    called=$(<"$calls")
    [[ "$called" == "set sshd unbanip 2001:db8::10" ]] \
        && pass "f2b_unban unbans the exact IPv6 address from matching jail" \
        || fail "f2b_unban call mismatch: $called"
}

test_fail2ban_status_ipv6_display_static() {
    local body
    body=$(awk '/^f2b_status\(\)/,/^f2b_unban\(\)/' "$BUILT")
    if echo "$body" | grep -q 'Banned IP.*cut -d:' || echo "$body" | grep -q 'cut -d: -f2 | xargs'; then
        fail "f2b_status still truncates Banned IP list with colon splitting"
    else
        pass "f2b_status no longer truncates IPv6 banned IPs with cut -d:"
    fi
}

test_f2b_apply_jail_local_is_transactional() {
    local dir="$TMP_ROOT/f2b-apply"
    local conf="$dir/jail.local"
    local validate_rc=0 restart_rc=0 restart_calls="$dir/restart-calls"
    mkdir -p "$dir"
    printf '[sshd]\nport = 22\n' > "$conf"
    chmod 640 "$conf" 2>/dev/null || true
    FAIL2BAN_JAIL_LOCAL="$conf"
    fail2ban-client() {
        [[ "${1:-}" == "-d" ]] && return "$validate_rc"
        return 1
    }
    systemctl() {
        case "${1:-} ${2:-}" in
            "enable fail2ban") return 0 ;;
            "restart fail2ban") printf 'restart\n' >> "$restart_calls"; return "$restart_rc" ;;
            *) return 0 ;;
        esac
    }

    if _f2b_apply_jail_local $'[sshd]\nport = 2222' 'mock-action' >/dev/null 2>&1 \
       && grep -q '^port = 2222$' "$conf" \
       && [[ "$(count_lines_equal "$restart_calls" "restart")" -eq 1 ]] \
       && ! find "$dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
        pass "_f2b_apply_jail_local applies validated config and restarts service"
    else
        fail "_f2b_apply_jail_local success path failed"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf" 2>/dev/null || true
    fi

    printf '[sshd]\nport = 22\n' > "$conf"
    : > "$restart_calls"
    validate_rc=1
    restart_rc=0
    if ! _f2b_apply_jail_local $'[sshd]\nport = 2223' 'mock-action' >/dev/null 2>&1 \
       && grep -q '^port = 22$' "$conf" \
       && ! grep -q '^port = 2223$' "$conf" \
       && [[ ! -s "$restart_calls" ]] \
       && ! find "$dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
        pass "_f2b_apply_jail_local rolls back when fail2ban config validation fails"
    else
        fail "_f2b_apply_jail_local validation failure did not roll back cleanly"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf" 2>/dev/null || true
    fi

    printf '[sshd]\nport = 22\n' > "$conf"
    : > "$restart_calls"
    validate_rc=0
    restart_rc=1
    if ! _f2b_apply_jail_local $'[sshd]\nport = 2224' 'mock-action' >/dev/null 2>&1 \
       && grep -q '^port = 22$' "$conf" \
       && ! grep -q '^port = 2224$' "$conf" \
       && [[ "$(count_lines_equal "$restart_calls" "restart")" -eq 1 ]] \
       && ! find "$dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
        pass "_f2b_apply_jail_local rolls back when fail2ban restart fails"
    else
        fail "_f2b_apply_jail_local restart failure did not roll back cleanly"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf" 2>/dev/null || true
    fi
}

test_f2b_setup_returns_failure_when_apply_fails() {
    local dir="$TMP_ROOT/f2b-setup"
    local conf="$dir/jail.local"
    mkdir -p "$dir"
    printf '[sshd]\nport = 22\n' > "$conf"
    FAIL2BAN_JAIL_LOCAL="$conf"
    CURRENT_SSH_PORT=22
    command_exists() {
        case "${1:-}" in
            nft|fail2ban-client) return 0 ;;
            nginx|iptables|ipset) return 1 ;;
            *) return 0 ;;
        esac
    }
    nft() {
        [[ "${1:-} ${2:-}" == "list ruleset" ]] && return 0
        return 1
    }
    fail2ban-client() {
        [[ "${1:-}" == "-d" ]] && return 1
        return 1
    }
    systemctl() { return 0; }
    install_package() { return 0; }
    ufw_is_active() { return 1; }
    confirm() { return 0; }

    if ! printf '\n\n\n\n\n' | f2b_setup >/dev/null 2>&1 \
       && grep -q '^port = 22$' "$conf" \
       && ! grep -q '^enabled = true$' "$conf" \
       && ! find "$dir" -maxdepth 1 -name '.bak.server-manage.fail2ban.*' -print -quit | grep -q .; then
        pass "f2b_setup returns failure and rolls back when apply helper fails"
    else
        fail "f2b_setup did not propagate fail2ban apply failure"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf" 2>/dev/null || true
    fi
}

test_ssh_authorized_keys_append_is_atomic_private() {
    local dir="$TMP_ROOT/ssh-ak/.ssh"
    local ak="$dir/authorized_keys"
    local key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA appended@example'
    mkdir -p "$dir"
    printf '%s' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB old@example' > "$ak"
    chmod 666 "$ak" 2>/dev/null || true
    if ! _ssh_authorized_keys_append "$ak" "$key"; then
        fail "_ssh_authorized_keys_append failed"
        return
    fi
    if ! _ssh_authorized_keys_append "$ak" "$key"; then
        fail "_ssh_authorized_keys_append duplicate call failed"
        return
    fi
    local mode mode_ok=0 nonempty_count
    mode=$(stat -c '%a' "$ak" 2>/dev/null || stat -f '%Lp' "$ak" 2>/dev/null || echo "")
    nonempty_count=$(grep -cve '^[[:space:]]*$' "$ak" 2>/dev/null || echo 0)
    if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
        [[ "$mode" == "600" ]] && mode_ok=1
    else
        [[ -n "$mode" ]] && mode_ok=1
    fi
    if [[ "$mode_ok" -eq 1 ]] \
       && grep -Fxq "$key" "$ak" \
       && [[ "$(grep -Fxc "$key" "$ak")" -eq 1 ]] \
       && [[ "$nonempty_count" -eq 2 ]] \
       && ! find "$dir" -maxdepth 1 -name '.tmp.server-manage.authorized-keys.*' -print -quit | grep -q .; then
        pass "_ssh_authorized_keys_append atomically appends and tightens permissions"
    else
        fail "_ssh_authorized_keys_append content/mode/temp mismatch mode=$mode"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$ak"
    fi
}

test_ssh_authorized_keys_remove_is_atomic_private() {
    local dir="$TMP_ROOT/ssh-ak-remove/.ssh"
    local ak="$dir/authorized_keys"
    local keep_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEKEEPKEEPKEEPKEEPKEEPKEEPKEEPKEEP keep@example'
    local remove_key='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEREMOVEREMOVEREMOVEREMOVEREMOVE remove@example'
    mkdir -p "$dir"
    printf '%s\n%s\n' "$keep_key" "$remove_key" > "$ak"
    chmod 666 "$ak" 2>/dev/null || true

    if ! _ssh_authorized_keys_remove "$ak" "$remove_key"; then
        fail "_ssh_authorized_keys_remove failed"
        return
    fi

    local mode mode_ok=0
    mode=$(stat -c '%a' "$ak" 2>/dev/null || stat -f '%Lp' "$ak" 2>/dev/null || echo "")
    if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
        [[ "$mode" == "600" ]] && mode_ok=1
    else
        [[ -n "$mode" ]] && mode_ok=1
    fi
    if [[ "$mode_ok" -eq 1 ]] \
       && grep -Fxq "$keep_key" "$ak" \
       && ! grep -Fxq "$remove_key" "$ak" \
       && [[ "$(grep -cve '^[[:space:]]*$' "$ak")" -eq 1 ]] \
       && ! find "$dir" -maxdepth 1 -name '.tmp.server-manage.authorized-keys.*' -print -quit | grep -q .; then
        pass "_ssh_authorized_keys_remove atomically removes exact key and tightens permissions"
    else
        fail "_ssh_authorized_keys_remove content/mode/temp mismatch mode=$mode"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$ak"
    fi
}

test_copy_cert_pair_atomic_modes_and_rollback() {
    local src="$TMP_ROOT/cert-src" dst="$TMP_ROOT/cert-dst"
    mkdir -p "$src" "$dst"
    printf 'old-full\n' > "$dst/fullchain.pem"
    printf 'old-key\n' > "$dst/privkey.pem"
    printf 'new-full\n' > "$src/fullchain.pem"
    printf 'new-key\n' > "$src/privkey.pem"
    chmod 666 "$dst/fullchain.pem" "$dst/privkey.pem" 2>/dev/null || true
    if copy_cert_pair_atomic "$src/fullchain.pem" "$src/privkey.pem" "$dst" \
       && grep -Fxq 'new-full' "$dst/fullchain.pem" \
       && grep -Fxq 'new-key' "$dst/privkey.pem" \
       && { [[ "$(uname -s 2>/dev/null)" != "Linux" ]] || [[ "$(stat -c '%a' "$dst/fullchain.pem" 2>/dev/null)" == "644" ]]; } \
       && { [[ "$(uname -s 2>/dev/null)" != "Linux" ]] || [[ "$(stat -c '%a' "$dst/privkey.pem" 2>/dev/null)" == "600" ]]; } \
       && ! find "$dst" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.bak.server-manage.*' \) -print -quit | grep -q .; then
        pass "copy_cert_pair_atomic installs cert/key with final permissions and no temp residue"
    else
        fail "copy_cert_pair_atomic success path content/mode/temp mismatch"
        ls -la "$dst" | sed 's/^/    /'
        sed 's/^/    full: /' "$dst/fullchain.pem" 2>/dev/null || true
        sed 's/^/    key: /' "$dst/privkey.pem" 2>/dev/null || true
        return
    fi

    printf 'v2-full\n' > "$src/fullchain.pem"
    printf 'v2-key\n' > "$src/privkey.pem"
    mv() {
        if [[ "${1:-}" == "$dst/.tmp.server-manage.privkey."* && "${2:-}" == "$dst/privkey.pem" ]]; then
            return 97
        fi
        command mv "$@"
    }
    if copy_cert_pair_atomic "$src/fullchain.pem" "$src/privkey.pem" "$dst" >/dev/null 2>&1; then
        unset -f mv
        fail "copy_cert_pair_atomic succeeded despite injected privkey commit failure"
        return
    fi
    unset -f mv
    if grep -Fxq 'new-full' "$dst/fullchain.pem" \
       && grep -Fxq 'new-key' "$dst/privkey.pem" \
       && ! find "$dst" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.bak.server-manage.*' \) -print -quit | grep -q .; then
        pass "copy_cert_pair_atomic rolls back both files when pair commit fails"
    else
        fail "copy_cert_pair_atomic rollback left mismatched cert pair or residue"
        ls -la "$dst" | sed 's/^/    /'
        sed 's/^/    full: /' "$dst/fullchain.pem" 2>/dev/null || true
        sed 's/^/    key: /' "$dst/privkey.pem" 2>/dev/null || true
    fi
}

test_render_cert_pair_hook_helper_rolls_back() {
    local src="$TMP_ROOT/hook-cert-src" dst="$TMP_ROOT/hook-cert-dst" script="$TMP_ROOT/hook-cert-rollback.sh"
    mkdir -p "$src" "$dst"
    printf 'old-hook-full\n' > "$dst/fullchain.pem"
    printf 'old-hook-key\n' > "$dst/privkey.pem"
    printf 'new-hook-full\n' > "$src/fullchain.pem"
    printf 'new-hook-key\n' > "$src/privkey.pem"
    {
        printf '#!/usr/bin/env bash\nset -u\n'
        printf 'SRC=%q\nDST=%q\n' "$src" "$dst"
        render_cert_pair_hook_helper
        cat <<'EOF'
mv() {
    if [[ "${1:-}" == "$DST/.tmp.server-manage.privkey."* && "${2:-}" == "$DST/privkey.pem" ]]; then
        return 91
    fi
    command mv "$@"
}
copy_cert_pair_atomic "$SRC/fullchain.pem" "$SRC/privkey.pem" "$DST"
EOF
    } > "$script"
    chmod +x "$script"
    if bash -n "$script" && bash "$script" >/dev/null 2>&1; then
        fail "rendered cert renewal hook helper succeeded despite injected privkey commit failure"
        return
    fi
    if grep -Fxq 'old-hook-full' "$dst/fullchain.pem" \
       && grep -Fxq 'old-hook-key' "$dst/privkey.pem" \
       && ! find "$dst" -maxdepth 1 \( -name '.tmp.server-manage.*' -o -name '.bak.server-manage.*' \) -print -quit | grep -q .; then
        pass "rendered cert renewal hook helper rolls back both files on pair commit failure"
    else
        fail "rendered cert renewal hook helper left mismatched cert pair or residue"
        ls -la "$dst" | sed 's/^/    /'
        sed 's/^/    full: /' "$dst/fullchain.pem" 2>/dev/null || true
        sed 's/^/    key: /' "$dst/privkey.pem" 2>/dev/null || true
    fi
}

test_net_dns_validation_before_write() {
    local writes="$TMP_ROOT/resolv-writes.txt"
    local real_write_file_atomic
    real_write_file_atomic="$(declare -f write_file_atomic)"
    : > "$writes"
    PLATFORM="debian"
    is_systemd() { return 1; }
    systemctl() { return 1; }
    confirm() { return 0; }
    write_file_atomic() {
        printf '%s\n' "$2" >> "$writes"
    }

    printf '13\n999.1.1.1 1.1.1.1\n' | net_dns >/dev/null 2>&1
    [[ ! -s "$writes" ]] \
        && pass "net_dns rejects invalid custom DNS before writing resolv.conf" \
        || fail "net_dns wrote resolv.conf for invalid DNS"

    printf '13\n1.1.1.1 2606:4700:4700::1111\n' | net_dns >/dev/null 2>&1
    if grep -q 'nameserver 1.1.1.1' "$writes" && grep -q 'nameserver 2606:4700:4700::1111' "$writes"; then
        pass "net_dns writes validated dual-stack custom DNS"
    else
        fail "net_dns did not write expected valid DNS content"
    fi
    eval "$real_write_file_atomic"
}

test_net_systemd_dns_rollback_and_render() {
    local resolved_conf="$TMP_ROOT/resolved.conf"
    local systemctl_log="$TMP_ROOT/resolved-systemctl-calls.txt"
    cat > "$resolved_conf" <<'EOF'
# keep global
[Resolve]
# keep comment
DNS=9.9.9.9
FallbackDNS=1.0.0.1
[DHCP]
UseDNS=yes
EOF
    TEST_RESOLVED_CONF="$resolved_conf"
    _net_resolved_conf_path() { printf '%s' "$TEST_RESOLVED_CONF"; }
    systemctl() {
        printf '%s\n' "$*" >> "$systemctl_log"
        [[ "${SYSTEMCTL_RESTART_OK:-0}" == "1" ]]
    }

    SYSTEMCTL_RESTART_OK=0
    if _net_apply_systemd_resolved_dns "1.1.1.1 2606:4700:4700::1111" >/dev/null 2>&1; then
        fail "_net_apply_systemd_resolved_dns succeeded despite restart failure"
    elif grep -q '^DNS=9.9.9.9$' "$resolved_conf" \
       && ! grep -q '^DNS=1.1.1.1 2606:4700:4700::1111$' "$resolved_conf"; then
        pass "_net_apply_systemd_resolved_dns rolls back when restart fails"
    else
        fail "_net_apply_systemd_resolved_dns left failed DNS change in resolved.conf"
        sed 's/^/    /' "$resolved_conf"
    fi

    SYSTEMCTL_RESTART_OK=1
    if _net_apply_systemd_resolved_dns "1.1.1.1 2606:4700:4700::1111" >/dev/null 2>&1 \
       && grep -q '^# keep global$' "$resolved_conf" \
       && grep -q '^# keep comment$' "$resolved_conf" \
       && grep -q '^FallbackDNS=1.0.0.1$' "$resolved_conf" \
       && grep -q '^UseDNS=yes$' "$resolved_conf" \
       && grep -q '^DNS=1.1.1.1 2606:4700:4700::1111$' "$resolved_conf" \
       && ! grep -q '^DNS=9.9.9.9$' "$resolved_conf"; then
        pass "_net_apply_systemd_resolved_dns atomically replaces only Resolve DNS"
    else
        fail "_net_apply_systemd_resolved_dns did not preserve resolved.conf structure"
        sed 's/^/    /' "$resolved_conf"
    fi
    unset TEST_RESOLVED_CONF
}

test_openwrt_net_dns_rolls_back_on_failure() {
    local log="$TMP_ROOT/openwrt-dns.log"
    local state="$TMP_ROOT/openwrt-dns-state"
    local fake_root="$TMP_ROOT/openwrt-dns-bin"
    local old_path="$PATH"
    : > "$log"
    mkdir -p "$state" "$fake_root/etc/init.d"
    printf '9.9.9.9\n149.112.112.112\n' > "$state/lan.dns"
    printf '1\n' > "$state/lan.peerdns"
    cat > "$fake_root/etc/init.d/network" <<'EOF'
#!/bin/sh
printf 'reload\n' >> "$OPENWRT_DNS_LOG"
exit "${OPENWRT_DNS_RELOAD_RC:-0}"
EOF
    chmod +x "$fake_root/etc/init.d/network"

    uci() {
        local args="$*"
        printf 'uci|%s\n' "$*" >> "$log"
        case "$args" in
            "-q get network.wan") return 1 ;;
            "-q get network.lan") return 0 ;;
            "-q get network.lan.dns") cat "$state/lan.dns"; return 0 ;;
            "-q get network.lan.peerdns") cat "$state/lan.peerdns"; return 0 ;;
            "-q delete network.lan.dns") : > "$state/lan.dns"; return 0 ;;
            "-q delete network.lan.peerdns") rm -f "$state/lan.peerdns"; return 0 ;;
            "add_list network.lan.dns="*)
                printf '%s\n' "${args#add_list network.lan.dns=}" >> "$state/lan.dns"
                return 0
                ;;
            "set network.lan.peerdns="*)
                printf '%s\n' "${args#set network.lan.peerdns=}" > "$state/lan.peerdns"
                return 0
                ;;
            "commit network")
                if [[ "${OPENWRT_DNS_COMMIT_OK:-0}" == "1" ]]; then
                    return 0
                fi
                OPENWRT_DNS_COMMIT_OK=1
                return 1
                ;;
            *) return 1 ;;
        esac
    }

    local old_platform="$PLATFORM"
    PLATFORM="openwrt"
    PATH="$fake_root:$PATH"
    OPENWRT_DNS_LOG="$log"
    export OPENWRT_DNS_LOG
    _net_openwrt_reload_network() {
        printf 'reload\n' >> "$OPENWRT_DNS_LOG"
        return "${OPENWRT_DNS_RELOAD_RC:-0}"
    }
    OPENWRT_DNS_RELOAD_RC=0
    export OPENWRT_DNS_RELOAD_RC
    OPENWRT_DNS_COMMIT_OK=0
    if printf '13\n1.1.1.1 2606:4700:4700::1111\n' | net_dns >/dev/null 2>&1; then
        fail "OpenWrt net_dns succeeded despite commit failure"
    elif grep -Fxq '9.9.9.9' "$state/lan.dns" \
       && grep -Fxq '149.112.112.112' "$state/lan.dns" \
       && [[ "$(cat "$state/lan.peerdns" 2>/dev/null)" == "1" ]] \
       && [[ "$(grep -c '^uci|commit network$' "$log")" -ge 2 ]] \
       && grep -Fxq 'reload' "$log"; then
        pass "OpenWrt net_dns restores previous DNS/peerdns when commit fails"
    else
        fail "OpenWrt net_dns did not restore previous DNS/peerdns on commit failure"
        sed 's/^/    log: /' "$log"
        sed 's/^/    dns: /' "$state/lan.dns" 2>/dev/null || true
        sed 's/^/    peerdns: /' "$state/lan.peerdns" 2>/dev/null || true
    fi

    : > "$log"
    printf '9.9.9.9\n' > "$state/lan.dns"
    printf '1\n' > "$state/lan.peerdns"
    OPENWRT_DNS_COMMIT_OK=1
    OPENWRT_DNS_RELOAD_RC=1
    if printf '13\n1.0.0.1\n' | net_dns >/dev/null 2>&1; then
        fail "OpenWrt net_dns succeeded despite network reload failure"
    elif grep -Fxq '9.9.9.9' "$state/lan.dns" \
       && [[ "$(cat "$state/lan.peerdns" 2>/dev/null)" == "1" ]] \
       && [[ "$(grep -c '^reload$' "$log")" -ge 2 ]]; then
        pass "OpenWrt net_dns restores previous DNS when reload fails"
    else
        fail "OpenWrt net_dns did not restore previous DNS on reload failure"
        sed 's/^/    log: /' "$log"
        sed 's/^/    dns: /' "$state/lan.dns" 2>/dev/null || true
        sed 's/^/    peerdns: /' "$state/lan.peerdns" 2>/dev/null || true
    fi

    PLATFORM="$old_platform"
    PATH="$old_path"
    unset OPENWRT_DNS_COMMIT_OK OPENWRT_DNS_RELOAD_RC OPENWRT_DNS_LOG
    unset -f uci _net_openwrt_reload_network
}

test_net_gai_priority_managed_block() {
    local gai_conf="$TMP_ROOT/gai.conf"
    cat > "$gai_conf" <<'EOF'
# keep gai header
#precedence ::ffff:0:0/96  100
precedence 2002::/16  30
precedence ::ffff:0:0/96  100
EOF
    TEST_GAI_CONF="$gai_conf"
    _net_gai_conf_path() { printf '%s' "$TEST_GAI_CONF"; }

    if _net_apply_gai_priority ipv4 \
       && grep -q '^# keep gai header$' "$gai_conf" \
       && grep -q '^#precedence ::ffff:0:0/96  100$' "$gai_conf" \
       && grep -q '^precedence 2002::/16  30$' "$gai_conf" \
       && grep -q '^# BEGIN server-manage ip-priority$' "$gai_conf" \
       && grep -q '^precedence ::ffff:0:0/96  100$' "$gai_conf"; then
        pass "_net_apply_gai_priority ipv4 preserves comments and adds managed block"
    else
        fail "_net_apply_gai_priority ipv4 removed unrelated gai.conf lines"
        sed 's/^/    /' "$gai_conf"
    fi

    if _net_apply_gai_priority ipv6 \
       && grep -q '^# keep gai header$' "$gai_conf" \
       && grep -q '^#precedence ::ffff:0:0/96  100$' "$gai_conf" \
       && grep -q '^precedence 2002::/16  30$' "$gai_conf" \
       && ! grep -q '^# BEGIN server-manage ip-priority$' "$gai_conf" \
       && ! grep -q '^precedence ::ffff:0:0/96  100$' "$gai_conf"; then
        pass "_net_apply_gai_priority ipv6 removes only active IPv4 preference"
    else
        fail "_net_apply_gai_priority ipv6 removed comments/unrelated precedence or left managed line"
        sed 's/^/    /' "$gai_conf"
    fi
    unset TEST_GAI_CONF
}

test_hostname_hosts_rendering_is_precise() {
    local hosts_file="$TMP_ROOT/hosts"
    cat > "$hosts_file" <<'EOF'
# oldbox should stay in comment
127.0.0.1 localhost oldbox oldbox
127.0.1.1 oldbox.example.com oldbox-other oldbox
::1 localhost ip6-localhost
EOF
    TEST_HOSTS_FILE="$hosts_file"
    _hosts_file_path() { printf '%s' "$TEST_HOSTS_FILE"; }

    if _hostname_update_hosts oldbox newbox \
       && grep -qF '# oldbox should stay in comment' "$hosts_file" \
       && grep -q '^127\.0\.0\.1 localhost newbox$' "$hosts_file" \
       && grep -q '^127\.0\.1\.1 oldbox.example.com oldbox-other newbox$' "$hosts_file" \
       && ! awk 'NF && $1 !~ /^#/ { for (i=2; i<=NF; i++) if ($i == "oldbox") found=1 } END { exit found ? 0 : 1 }' "$hosts_file"; then
        pass "_hostname_update_hosts replaces only hostname tokens and keeps comments/substrings"
    else
        fail "_hostname_update_hosts replaced comments/substrings or missed host tokens"
        sed 's/^/    /' "$hosts_file"
    fi

    : > "$hosts_file"
    if _hostname_update_hosts "" freshbox \
       && grep -q '^127\.0\.0\.1 localhost freshbox$' "$hosts_file"; then
        pass "_hostname_update_hosts creates localhost row when hosts file is empty"
    else
        fail "_hostname_update_hosts did not create localhost row for empty hosts"
        sed 's/^/    /' "$hosts_file"
    fi
    unset TEST_HOSTS_FILE
}

test_hostname_fallback_rolls_back_file_on_hostname_failure() {
    local hostname_file="$TMP_ROOT/hostname"
    local hosts_file="$TMP_ROOT/hosts-fallback"
    cat > "$hostname_file" <<'EOF'
oldbox
EOF
    cat > "$hosts_file" <<'EOF'
127.0.0.1 localhost oldbox
EOF
    PLATFORM="debian"
    TEST_HOSTNAME_FILE="$hostname_file"
    TEST_HOSTS_FILE="$hosts_file"
    _hostname_file_path() { printf '%s' "$TEST_HOSTNAME_FILE"; }
    _hosts_file_path() { printf '%s' "$TEST_HOSTS_FILE"; }
    command_exists() { [[ "${1:-}" != "hostnamectl" ]]; }
    hostname() {
        if [[ "$#" -eq 0 ]]; then
            printf 'oldbox\n'
            return 0
        fi
        return 1
    }

    if printf 'newbox\n' | opt_hostname >/dev/null 2>&1; then
        fail "opt_hostname fallback succeeded despite hostname command failure"
    elif grep -qx 'oldbox' "$hostname_file" \
       && grep -q '^127\.0\.0\.1 localhost oldbox$' "$hosts_file"; then
        pass "opt_hostname fallback rolls back /etc/hostname and does not touch hosts when hostname fails"
    else
        fail "opt_hostname fallback did not roll back hostname file cleanly"
        sed 's/^/    hostname: /' "$hostname_file"
        sed 's/^/    hosts: /' "$hosts_file"
    fi
    unset TEST_HOSTNAME_FILE TEST_HOSTS_FILE
}

test_net_diag_port_input_validation() {
    local nc_calls="$TMP_ROOT/nc-calls.txt"
    : > "$nc_calls"
    command_exists() {
        [[ "$1" == "nc" ]]
    }
    nc() {
        printf '%s\n' "$*" >> "$nc_calls"
        return 0
    }

    printf '3\nbad_host!\n443\n' | net_diag >/dev/null 2>&1
    printf '3\nexample.com\n70000\n' | net_diag >/dev/null 2>&1
    [[ ! -s "$nc_calls" ]] \
        && pass "net_diag rejects invalid host/port before nc" \
        || fail "net_diag called nc for invalid input: $(<"$nc_calls")"

    printf '3\nexample.com\n443\n' | net_diag >/dev/null 2>&1
    [[ "$(cat "$nc_calls")" == "-zv -w 5 example.com 443" ]] \
        && pass "net_diag calls nc only for validated host/port" \
        || fail "net_diag nc call mismatch: $(<"$nc_calls")"
}

test_firewall_allow_tcp_port_modes() {
    # shellcheck disable=SC2034  # read dynamically by sourced helpers
    PLATFORM="debian"
    local ufw_calls="$TMP_ROOT/ufw-calls.txt"
    : > "$ufw_calls"

    command_exists() {
        [[ "$1" != "ufw" ]] && return 0
        [[ "${UFW_PRESENT:-0}" == "1" ]]
    }
    ufw_is_active() {
        [[ "${UFW_ACTIVE:-0}" == "1" ]]
    }
    ufw() {
        printf '%s\n' "$*" >> "$ufw_calls"
        [[ "${UFW_OK:-1}" == "1" ]]
    }

    local rc_absent rc_inactive rc_active rc_udp_absent rc_udp_inactive rc_udp_active rc_udp_fail
    UFW_PRESENT=0 UFW_ACTIVE=0 UFW_OK=1
    firewall_allow_tcp_port 9443 "Mock" >/dev/null 2>&1
    rc_absent=$?
    firewall_allow_udp_port 51820 "WGMock" >/dev/null 2>&1
    rc_udp_absent=$?
    UFW_PRESENT=1 UFW_ACTIVE=0 UFW_OK=1
    firewall_allow_tcp_port 9443 "Mock" >/dev/null 2>&1
    rc_inactive=$?
    firewall_allow_udp_port 51820 "WGMock" >/dev/null 2>&1
    rc_udp_inactive=$?
    UFW_PRESENT=1 UFW_ACTIVE=1 UFW_OK=1
    firewall_allow_tcp_port 9443 "Mock" >/dev/null 2>&1
    rc_active=$?
    firewall_allow_udp_port 51820 "WGMock" >/dev/null 2>&1
    rc_udp_active=$?
    UFW_PRESENT=1 UFW_ACTIVE=1 UFW_OK=0
    firewall_allow_udp_port 51821 "WGFail" >/dev/null 2>&1
    rc_udp_fail=$?

    if [[ $rc_absent -eq 2 && $rc_inactive -eq 2 && $rc_active -eq 0 \
          && $rc_udp_absent -eq 2 && $rc_udp_inactive -eq 2 && $rc_udp_active -eq 0 && $rc_udp_fail -eq 1 ]] \
       && grep -q 'allow 9443/tcp comment Mock' "$ufw_calls" \
       && grep -q 'allow 51820/udp comment WGMock' "$ufw_calls" \
       && grep -q 'allow 51821/udp comment WGFail' "$ufw_calls"; then
        pass "firewall_allow tcp/udp helpers return soft rc=2 unless active UFW can add rule"
    else
        fail "firewall_allow tcp/udp rc/call mismatch tcp=($rc_absent,$rc_inactive,$rc_active) udp=($rc_udp_absent,$rc_udp_inactive,$rc_udp_active,$rc_udp_fail) calls=$(<"$ufw_calls")"
    fi
}

test_firewall_prepare_non_ufw_udp_port_restrictive_iptables() {
    local insert_log="$TMP_ROOT/fw-udp-insert.log"
    local delete_log="$TMP_ROOT/fw-udp-delete.log"
    local backend_log="$TMP_ROOT/fw-udp-backends.log"
    : > "$insert_log"
    : > "$delete_log"
    : > "$backend_log"

    if (
        PLATFORM=debian
        is_systemd() { return 1; }
        command_exists() { [[ "${1:-}" == "iptables" ]]; }
        confirm() { return 0; }
        iptables() {
            if [[ "${1:-}" == "-S" && "${2:-}" == "INPUT" ]]; then
                cat <<'EOF_FW'
-P INPUT ACCEPT
-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
-A INPUT -j REJECT --reject-with icmp-host-prohibited
EOF_FW
                return 0
            fi
            if [[ "${1:-}" == "-I" && "${2:-}" == "INPUT" ]]; then
                printf '%s\n' "$*" > "$insert_log"
                return 0
            fi
            if [[ "${1:-}" == "-D" && "${2:-}" == "INPUT" ]]; then
                printf '%s\n' "$*" > "$delete_log"
                return 0
            fi
            return 1
        }

        firewall_prepare_non_ufw_udp_port 51820 "WireGuard-Debian" >/dev/null 2>&1 || exit 1
        printf '%s\n' "$FIREWALL_UDP_OPEN_BACKENDS" > "$backend_log"
        firewall_rollback_udp_port 51820 "$FIREWALL_UDP_OPEN_BACKENDS" "WireGuard-Debian" >/dev/null 2>&1 || exit 1
    ); then
        if grep -q 'iptables' "$backend_log" \
           && grep -q -- '-p udp' "$insert_log" \
           && grep -q -- '--dport 51820' "$insert_log" \
           && grep -q -- '--comment WireGuard-Debian' "$insert_log" \
           && grep -q -- '-D INPUT -p udp' "$delete_log" \
           && grep -q -- '--dport 51820' "$delete_log"; then
            pass "firewall_prepare_non_ufw_udp_port inserts and rolls back UDP accept on restrictive iptables"
        else
            fail "UDP non-UFW firewall helper command mismatch"
            sed 's/^/    backends: /' "$backend_log"
            sed 's/^/    insert: /' "$insert_log"
            sed 's/^/    delete: /' "$delete_log"
        fi
    else
        fail "firewall_prepare_non_ufw_udp_port failed in restrictive iptables mock"
    fi
}

test_wg_deb_modify_server_udp_firewall_failure_stops_safely() {
    local log="$TMP_ROOT/wg-deb-modify-ufw-fail.log"
    : > "$log"

    if (
        wg_deb_check_server() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.server.port') echo 51820 ;;
                '.server.dns') echo "1.1.1.1" ;;
                '.server.endpoint') echo "vpn.example.com" ;;
                '.server.server_lan_subnet // empty') echo "" ;;
                '.server.default_iface // empty') echo "eth0" ;;
                '.server.subnet') echo "10.66.66.0/24" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() { printf 'dbset|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$log"
            case "$*" in
                "show added") return 0 ;;
                "allow 51821/udp comment WireGuard-Debian") return 1 ;;
                *) return 0 ;;
            esac
        }
        printf '51821\n' | wg_deb_modify_server
    ) >/dev/null 2>&1; then
        fail "wg_deb_modify_server succeeded despite UFW UDP allow failure"
    elif grep -q '^ufw|allow 51821/udp comment WireGuard-Debian$' "$log" \
         && ! grep -q '^dbset|' "$log"; then
        pass "wg_deb_modify_server stops before DB write when new UDP port cannot be allowed"
    else
        fail "wg_deb_modify_server UFW failure path mismatch: $(paste -sd ',' "$log")"
    fi
}

test_wg_deb_modify_server_non_ufw_udp_prepare_failure_stops_safely() {
    local log="$TMP_ROOT/wg-deb-modify-non-ufw-fail.log"
    : > "$log"
    rm -f "$WG_DEB_DB_FILE" 2>/dev/null || true

    if (
        wg_deb_check_server() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.server.port') echo 51820 ;;
                '.server.dns') echo "1.1.1.1" ;;
                '.server.endpoint') echo "vpn.example.com" ;;
                '.server.server_lan_subnet // empty') echo "" ;;
                '.server.default_iface // empty') echo "eth0" ;;
                '.server.subnet') echo "10.66.66.0/24" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() { printf 'dbset|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        command_exists() { return 1; }
        firewall_allow_udp_port() { printf 'allowudp|%s|%s\n' "$1" "$2" >> "$log"; return 2; }
        firewall_prepare_non_ufw_udp_port() { printf 'prepareudp|%s|%s\n' "$1" "$2" >> "$log"; return 1; }
        printf '51821\n' | wg_deb_modify_server
    ) >/dev/null 2>&1; then
        fail "wg_deb_modify_server succeeded despite non-UFW UDP prepare failure"
    elif grep -q '^allowudp|51821|WireGuard-Debian$' "$log" \
         && grep -q '^prepareudp|51821|WireGuard-Debian$' "$log" \
         && ! grep -q '^dbset|' "$log"; then
        pass "wg_deb_modify_server stops before DB write when non-UFW UDP prepare fails"
    else
        fail "wg_deb_modify_server non-UFW failure path mismatch: $(paste -sd ',' "$log")"
    fi
}

test_wg_deb_server_install_udp_firewall_precheck_stops_before_db() {
    local log="$TMP_ROOT/wg-deb-install-ufw-fail.log"
    : > "$log"

    if (
        wg_deb_is_installed() { return 1; }
        wg_deb_check_compat() { return 0; }
        wg_deb_install_packages() { return 0; }
        _sysctl_enable_wireguard_forward() { return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        get_public_ipv4() { echo "198.51.100.10"; }
        wg_shared_normalize_endpoint_host() { printf '%s\n' "${1:-}"; }
        wg_deb_db_init() { printf 'dbinit\n' >> "$log"; return 0; }
        wg_deb_db_set() { printf 'dbset|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_set_role() { printf 'role|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_is_running() { return 1; }
        wg_deb_setup_watchdog() { :; }
        hostname() { echo "mockhost"; }
        ip() { return 1; }
        wg() {
            case "${1:-}" in
                genkey) echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ;;
                pubkey) cat >/dev/null; echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ;;
                *) return 1 ;;
            esac
        }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$log"; return 0; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$log"
            case "$*" in
                "show added") return 0 ;;
                "allow 51820/udp comment WireGuard-Debian") return 1 ;;
                *) return 0 ;;
            esac
        }
        printf '51820\n\n\n\n\nmockserver\n' | wg_deb_server_install
    ) >/dev/null 2>&1; then
        fail "wg_deb_server_install succeeded despite UFW UDP allow failure"
    elif grep -q '^ufw|allow 51820/udp comment WireGuard-Debian$' "$log" \
         && ! grep -q '^dbset|' "$log" \
         && ! grep -q '^role|' "$log" \
         && ! grep -q '^systemctl|' "$log"; then
        pass "wg_deb_server_install stops before DB/role/service when UDP port cannot be allowed"
    else
        fail "wg_deb_server_install UFW failure path mismatch: $(paste -sd ',' "$log")"
    fi
}

test_wg_deb_server_install_rolls_back_non_ufw_udp_on_db_init_failure() {
    local log="$TMP_ROOT/wg-deb-install-non-ufw-rollback.log"
    : > "$log"
    rm -f "$WG_DEB_DB_FILE" "$WG_DEB_ROLE_FILE" "$WG_DEB_CONF" 2>/dev/null || true

    if (
        wg_deb_is_installed() { return 1; }
        wg_deb_check_compat() { return 0; }
        wg_deb_install_packages() { return 0; }
        _sysctl_enable_wireguard_forward() { return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        get_public_ipv4() { echo "198.51.100.10"; }
        wg_shared_normalize_endpoint_host() { printf '%s\n' "${1:-}"; }
        wg_deb_db_init() { printf 'dbinit\n' >> "$log"; return 1; }
        wg_deb_db_set() { printf 'dbset|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_set_role() { printf 'role|%s\n' "$*" >> "$log"; return 0; }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_is_running() { return 1; }
        wg_deb_setup_watchdog() { :; }
        hostname() { echo "mockhost"; }
        ip() { return 1; }
        wg() {
            case "${1:-}" in
                genkey) echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ;;
                pubkey) cat >/dev/null; echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ;;
                *) return 1 ;;
            esac
        }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$log"; return 0; }
        command_exists() { return 1; }
        firewall_allow_udp_port() { printf 'allowudp|%s|%s\n' "$1" "$2" >> "$log"; return 2; }
        firewall_prepare_non_ufw_udp_port() {
            printf 'prepareudp|%s|%s\n' "$1" "$2" >> "$log"
            FIREWALL_UDP_OPEN_BACKENDS="iptables"
            return 0
        }
        firewall_rollback_udp_port() { printf 'rollbackudp|%s|%s|%s\n' "$1" "$2" "$3" >> "$log"; return 0; }
        printf '51820\n\n\n\n\nnew-server\n' | wg_deb_server_install
    ) >/dev/null 2>&1; then
        fail "wg_deb_server_install succeeded despite DB init failure"
    elif grep -q '^allowudp|51820|WireGuard-Debian$' "$log" \
         && grep -q '^prepareudp|51820|WireGuard-Debian$' "$log" \
         && grep -q '^dbinit$' "$log" \
         && grep -q '^rollbackudp|51820|iptables|WireGuard-Debian$' "$log" \
         && ! grep -q '^dbset|' "$log" \
         && ! grep -q '^role|' "$log" \
         && ! grep -q '^rebuild$' "$log"; then
        pass "wg_deb_server_install rolls back non-UFW UDP rule when later install step fails"
    else
        fail "wg_deb_server_install non-UFW rollback mismatch: $(paste -sd ',' "$log")"
    fi
}

test_wg_deb_server_install_rolls_back_when_service_not_running() {
    local log="$TMP_ROOT/wg-deb-install-service-fail.log"
    local ufw_state="$TMP_ROOT/wg-deb-install-ufw-state"
    local old_db="$TMP_ROOT/wg-deb-install-old-db.json"
    local old_role="$TMP_ROOT/wg-deb-install-old-role"
    local old_conf="$TMP_ROOT/wg-deb-install-old-conf"
    : > "$log"
    : > "$ufw_state"
    mkdir -p "$(dirname "$WG_DEB_DB_FILE")" "$(dirname "$WG_DEB_ROLE_FILE")" "$(dirname "$WG_DEB_CONF")"
    printf '{"server":{"name":"old-server","port":51819},"peers":[]}\n' > "$old_db"
    printf 'client\n' > "$old_role"
    printf '[Interface]\nListenPort = 51819\n' > "$old_conf"
    cp "$old_db" "$WG_DEB_DB_FILE"
    cp "$old_role" "$WG_DEB_ROLE_FILE"
    cp "$old_conf" "$WG_DEB_CONF"

    if (
        wg_deb_is_installed() { return 1; }
        wg_deb_check_compat() { return 0; }
        wg_deb_install_packages() { return 0; }
        _sysctl_enable_wireguard_forward() { return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        get_public_ipv4() { echo "198.51.100.10"; }
        wg_shared_normalize_endpoint_host() { printf '%s\n' "${1:-}"; }
        wg_deb_db_init() { printf 'dbinit\n' >> "$log"; return 0; }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"server":{"name":"new-server","port":51820},"peers":[]}\n' > "$WG_DEB_DB_FILE"
            return 0
        }
        wg_deb_set_role() {
            printf 'role|%s\n' "$*" >> "$log"
            printf '%s\n' "${1:-}" > "$WG_DEB_ROLE_FILE"
            return 0
        }
        wg_deb_rebuild_conf() {
            printf 'rebuild\n' >> "$log"
            printf '[Interface]\nListenPort = 51820\n' > "$WG_DEB_CONF"
            return 0
        }
        wg_deb_is_running() { return 1; }
        wg_deb_setup_watchdog() { printf 'watchdog\n' >> "$log"; return 0; }
        log_action() { printf 'log|%s\n' "$*" >> "$log"; }
        hostname() { echo "mockhost"; }
        ip() { return 1; }
        sleep() { :; }
        wg() {
            case "${1:-}" in
                genkey) echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ;;
                pubkey) cat >/dev/null; echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ;;
                *) return 1 ;;
            esac
        }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$log"; return 0; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$log"
            case "$*" in
                "show added")
                    grep -q '^51820$' "$ufw_state" && echo "ufw allow 51820/udp comment 'WireGuard-Debian'"
                    return 0
                    ;;
                "allow 51820/udp comment WireGuard-Debian")
                    printf '51820\n' > "$ufw_state"
                    return 0
                    ;;
                "delete allow 51820/udp")
                    : > "$ufw_state"
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        printf '51820\n\n\n\n\nnew-server\n' | wg_deb_server_install
    ) >/dev/null 2>&1; then
        fail "wg_deb_server_install succeeded despite service not running"
    elif cmp -s "$WG_DEB_DB_FILE" "$old_db" \
         && cmp -s "$WG_DEB_ROLE_FILE" "$old_role" \
         && cmp -s "$WG_DEB_CONF" "$old_conf" \
         && grep -q '^systemctl|enable wg-quick@wg0$' "$log" \
         && grep -q '^systemctl|start wg-quick@wg0$' "$log" \
         && grep -q '^systemctl|stop wg-quick@wg0$' "$log" \
         && grep -q '^systemctl|disable wg-quick@wg0$' "$log" \
         && grep -q '^ufw|delete allow 51820/udp$' "$log" \
         && ! grep -q '^watchdog$' "$log" \
         && ! grep -q '^log|WireGuard(deb) server installed' "$log" \
         && [[ ! -s "$ufw_state" ]]; then
        pass "wg_deb_server_install rolls back DB/role/conf/UFW when service is not running"
    else
        fail "wg_deb_server_install service failure rollback mismatch"
        sed 's/^/    log: /' "$log"
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    role: /' "$WG_DEB_ROLE_FILE" 2>/dev/null || true
        sed 's/^/    conf: /' "$WG_DEB_CONF" 2>/dev/null || true
        printf '    ufw_state: %s\n' "$(cat "$ufw_state" 2>/dev/null || true)"
    fi
}

test_wg_deb_modify_server_rolls_back_new_udp_allow_on_later_failure() {
    local log="$TMP_ROOT/wg-deb-modify-rollback.log"
    local ufw_state="$TMP_ROOT/wg-deb-modify-ufw-state"
    local old_db="$TMP_ROOT/wg-deb-modify-rollback-old.json"
    : > "$log"
    : > "$ufw_state"
    mkdir -p "$(dirname "$WG_DEB_DB_FILE")"
    printf '{"server":{"port":51820,"dns":"1.1.1.1","endpoint":"vpn.example.com","server_lan_subnet":"","default_iface":"eth0"},"peers":[]}\n' > "$old_db"
    cp "$old_db" "$WG_DEB_DB_FILE"

    if (
        wg_deb_check_server() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.server.port') echo 51820 ;;
                '.server.dns') echo "1.1.1.1" ;;
                '.server.endpoint') echo "vpn.example.com" ;;
                '.server.server_lan_subnet // empty') echo "" ;;
                '.server.default_iface // empty') echo "eth0" ;;
                '.server.subnet') echo "10.66.66.0/24" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"server":{"port":51821,"dns":"partial"},"peers":[]}\n' > "$WG_DEB_DB_FILE"
            [[ "$*" == *'.server.dns = $d'* ]] && return 1
            return 0
        }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_regenerate_client_confs() { printf 'regen\n' >> "$log"; return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$log"
            case "$*" in
                "show added")
                    grep -q '^51821$' "$ufw_state" && echo "ufw allow 51821/udp comment 'WireGuard-Debian'"
                    return 0
                    ;;
                "allow 51821/udp comment WireGuard-Debian")
                    printf '51821\n' > "$ufw_state"
                    return 0
                    ;;
                "delete allow 51821/udp")
                    : > "$ufw_state"
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        printf '51821\n9.9.9.9\n' | wg_deb_modify_server
    ) >/dev/null 2>&1; then
        fail "wg_deb_modify_server succeeded despite later DB failure"
    elif grep -q '^ufw|allow 51821/udp comment WireGuard-Debian$' "$log" \
         && grep -q '^ufw|delete allow 51821/udp$' "$log" \
         && grep -q '^dbset|--argjson p ' "$log" \
         && ! grep -q '^rebuild$' "$log" \
         && cmp -s "$WG_DEB_DB_FILE" "$old_db" \
         && [[ ! -s "$ufw_state" ]]; then
        pass "wg_deb_modify_server rolls back newly-added UDP rule and DB snapshot when later update fails"
    else
        fail "wg_deb_modify_server rollback path mismatch: $(paste -sd ',' "$log") state=$(<"$ufw_state")"
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    old: /' "$old_db" 2>/dev/null || true
    fi
}

test_wg_deb_modify_server_restores_full_snapshot_on_restart_failure() {
    local log="$TMP_ROOT/wg-deb-modify-full-rollback.log"
    local ufw_state="$TMP_ROOT/wg-deb-modify-full-ufw-state"
    local old_db="$TMP_ROOT/wg-deb-modify-full-old.json"
    : > "$log"
    : > "$ufw_state"
    mkdir -p "$(dirname "$WG_DEB_DB_FILE")"
    cat > "$old_db" <<'EOF'
{"server":{"port":51820,"dns":"1.1.1.1","endpoint":"vpn.example.com","server_lan_subnet":"","default_iface":"eth0","subnet":"10.66.66.0/24"},"peers":[{"name":"peer1","client_allowed_ips":"10.66.66.0/24","route_mode":"managed"}]}
EOF
    cp "$old_db" "$WG_DEB_DB_FILE"

    if (
        wg_deb_check_server() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.server.port') echo 51820 ;;
                '.server.dns') echo "1.1.1.1" ;;
                '.server.endpoint') echo "vpn.example.com" ;;
                '.server.server_lan_subnet // empty') echo "" ;;
                '.server.default_iface // empty') echo "eth0" ;;
                '.server.subnet') echo "10.66.66.0/24" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"server":{"port":51821,"dns":"9.9.9.9","endpoint":"new.example.com","server_lan_subnet":"192.168.2.0/24","default_iface":"eth1","subnet":"10.66.66.0/24"},"peers":[{"name":"peer1","client_allowed_ips":"10.66.66.0/24, 192.168.2.0/24","route_mode":"managed"}]}\n' > "$WG_DEB_DB_FILE"
            return 0
        }
        _wg_deb_update_peer_routes() { printf 'routes\n' >> "$log"; return 0; }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_regenerate_client_confs() { printf 'regen\n' >> "$log"; return 0; }
        wg_deb_detect_default_iface() { echo "eth0"; }
        wg_deb_is_running() { return 0; }
        systemctl() { printf 'systemctl|%s\n' "$*" >> "$log"; return 1; }
        sleep() { :; }
        command_exists() { [[ "${1:-}" == "ufw" ]]; }
        ufw_is_active() { return 0; }
        ufw() {
            printf 'ufw|%s\n' "$*" >> "$log"
            case "$*" in
                "show added")
                    grep -q '^51821$' "$ufw_state" && echo "ufw allow 51821/udp comment 'WireGuard-Debian'"
                    return 0
                    ;;
                "allow 51821/udp comment WireGuard-Debian")
                    printf '51821\n' > "$ufw_state"
                    return 0
                    ;;
                "delete allow 51821/udp")
                    : > "$ufw_state"
                    return 0
                    ;;
                *) return 0 ;;
            esac
        }
        printf '51821\n9.9.9.9\nnew.example.com\n192.168.2.0/24\neth1\n' | wg_deb_modify_server
    ) >/dev/null 2>&1; then
        fail "wg_deb_modify_server succeeded despite restart failure"
    elif cmp -s "$WG_DEB_DB_FILE" "$old_db" \
         && grep -q '^dbset|--argjson p 51821' "$log" \
         && grep -q '^dbset|--arg d 9.9.9.9' "$log" \
         && grep -q '^dbset|--arg e new.example.com' "$log" \
         && grep -q '^dbset|--arg l 192.168.2.0/24' "$log" \
         && grep -q '^dbset|--arg i eth1' "$log" \
         && grep -q '^routes$' "$log" \
         && grep -q '^systemctl|restart wg-quick@wg0$' "$log" \
         && grep -q '^ufw|delete allow 51821/udp$' "$log" \
         && [[ ! -s "$ufw_state" ]]; then
        pass "wg_deb_modify_server restores full DB snapshot when restart fails"
    else
        fail "wg_deb_modify_server did not restore full snapshot after restart failure"
        sed 's/^/    log: /' "$log"
        sed 's/^/    db: /' "$WG_DEB_DB_FILE" 2>/dev/null || true
        sed 's/^/    old: /' "$old_db" 2>/dev/null || true
        printf '    ufw_state: %s\n' "$(cat "$ufw_state" 2>/dev/null || true)"
    fi
}

test_wg_deb_update_peer_routes_refreshes_managed_vpn_only_peer() {
    local log="$TMP_ROOT/wg-deb-update-managed-routes.log"
    : > "$log"

    wg_deb_db_get() {
        case "${1:-}" in
            '.server.subnet') printf '10.66.66.0/24\n' ;;
            '.server.server_lan_subnet // empty') printf '192.168.1.0/24\n' ;;
            '.peers | length') printf '2\n' ;;
            '.peers[0].lan_subnets // empty') printf '\n' ;;
            '.peers[1].lan_subnets // empty') printf '192.168.88.0/24\n' ;;
            '.peers[0].client_allowed_ips') printf '10.66.66.0/24\n' ;;
            '.peers[1].client_allowed_ips') printf '10.66.66.0/24, 192.168.88.0/24\n' ;;
            '.peers[0].is_gateway // false') printf 'false\n' ;;
            '.peers[1].is_gateway // false') printf 'true\n' ;;
            '.peers[0].peer_type // "standard"') printf 'standard\n' ;;
            '.peers[1].peer_type // "standard"') printf 'gateway\n' ;;
            '.peers[0].route_mode // empty') printf 'managed\n' ;;
            '.peers[1].route_mode // empty') printf 'managed\n' ;;
            *) printf '\n' ;;
        esac
    }
    wg_deb_db_set() {
        printf 'dbset|%s\n' "$*" >> "$log"
        return 0
    }

    if _wg_deb_update_peer_routes \
       && grep -Fq 'dbset|--argjson idx 0 --arg a 10.66.66.0/24, 192.168.1.0/24, 192.168.88.0/24' "$log"; then
        pass "_wg_deb_update_peer_routes refreshes managed peer even when current route is VPN-only"
    else
        fail "_wg_deb_update_peer_routes skipped managed VPN-only peer"
        sed 's/^/    log: /' "$log"
    fi
    unset -f wg_deb_db_get wg_deb_db_set
}

test_wg_deb_peer_ops_roll_back_on_apply_failure() {
    local db="$WG_DEB_DB_FILE"
    local clients="$WG_DEB_CLIENT_DIR"
    local original="$TMP_ROOT/wg-deb-peer-original.json"
    local log="$TMP_ROOT/wg-deb-peer-rollback.log"
    mkdir -p "$(dirname "$db")" "$clients"
    : > "$log"

    cat > "$original" <<'EOF'
{
  "server": {
    "subnet": "10.66.66.0/24",
    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "endpoint": "vpn.example.com",
    "port": 51820,
    "dns": "1.1.1.1"
  },
  "peers": [
    {
      "name": "debpeer",
      "ip": "10.66.66.2",
      "enabled": true,
      "is_gateway": false,
      "public_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
      "preshared_key": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
      "client_allowed_ips": "10.66.66.0/24"
    }
  ]
}
EOF

    cp "$original" "$db"
    printf 'old client\n' > "$clients/debpeer.conf"
    if (
        wg_deb_check_server() { return 0; }
        wg_deb_select_peer() { REPLY=0; return 0; }
        confirm() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.peers[0].name') echo "debpeer" ;;
                '.peers[0].public_key') echo "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" ;;
                '.peers[0].enabled') echo "true" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"peers":[{"name":"debpeer","enabled":false}]}\n' > "$WG_DEB_DB_FILE"
            return 0
        }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_regenerate_client_confs() { printf 'regen\n' >> "$log"; return 0; }
        wg_deb_is_running() { return 0; }
        wg_deb_apply_conf() { printf 'apply-fail\n' >> "$log"; return 1; }
        wg_deb_toggle_peer
    ) >/dev/null 2>&1; then
        fail "wg_deb_toggle_peer succeeded despite failed runtime apply"
    elif cmp -s "$db" "$original" && [[ -f "$clients/debpeer.conf" ]]; then
        pass "wg_deb_toggle_peer rolls DB/client state back when runtime apply fails"
    else
        fail "wg_deb_toggle_peer failed to roll back DB/client state"
        sed 's/^/    db: /' "$db"
        sed 's/^/    log: /' "$log"
    fi

    cp "$original" "$db"
    printf 'old client\n' > "$clients/debpeer.conf"
    if (
        wg_deb_check_server() { return 0; }
        wg_deb_select_peer() { REPLY=0; return 0; }
        confirm() { return 0; }
        wg_deb_db_get() {
            case "${1:-}" in
                '.peers[0].name') echo "debpeer" ;;
                '.peers[0].is_gateway // false') echo "false" ;;
                '.peers[0].lan_subnets // empty') echo "" ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"peers":[]}\n' > "$WG_DEB_DB_FILE"
            return 0
        }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_regenerate_client_confs() { printf 'regen\n' >> "$log"; return 0; }
        wg_deb_is_running() { return 0; }
        wg_deb_apply_conf() { printf 'apply-fail\n' >> "$log"; return 1; }
        wg_deb_delete_peer
    ) >/dev/null 2>&1; then
        fail "wg_deb_delete_peer succeeded despite failed runtime apply"
    elif cmp -s "$db" "$original" && [[ -f "$clients/debpeer.conf" ]]; then
        pass "wg_deb_delete_peer keeps DB/client config when runtime apply fails"
    else
        fail "wg_deb_delete_peer failed to preserve DB/client config"
        sed 's/^/    db: /' "$db"
        sed 's/^/    log: /' "$log"
        ls -la "$clients" | sed 's/^/    /'
    fi

    cat > "$original" <<'EOF'
{
  "server": {
    "subnet": "10.66.66.0/24",
    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "endpoint": "vpn.example.com",
    "port": 51820,
    "dns": "1.1.1.1"
  },
  "peers": []
}
EOF
    cp "$original" "$db"
    rm -f "$clients/failpeer.conf"
    if (
        wg_deb_check_server() { return 0; }
        wg_deb_next_ip() { echo "10.66.66.2"; }
        wg_deb_db_get() {
            local query="${!#}"
            case "$query" in
                '.server.subnet') echo "10.66.66.0/24" ;;
                '.server.server_lan_subnet // empty') echo "" ;;
                '.peers | length') echo 0 ;;
                *) echo "" ;;
            esac
        }
        wg_deb_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"peers":[{"name":"failpeer","enabled":true}]}\n' > "$WG_DEB_DB_FILE"
            return 0
        }
        wg_deb_rebuild_conf() { printf 'rebuild\n' >> "$log"; return 0; }
        wg_deb_regenerate_client_confs() { printf 'regen\n' >> "$log"; return 0; }
        wg_deb_is_running() { return 0; }
        wg_deb_apply_conf() {
            printf 'new client\n' > "$WG_DEB_CLIENT_DIR/failpeer.conf"
            printf 'apply-fail\n' >> "$log"
            return 1
        }
        wg() {
            case "${1:-}" in
                genkey) printf 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=\n' ;;
                genpsk) printf 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=\n' ;;
                pubkey) cat >/dev/null; printf 'GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG=\n' ;;
                *) return 1 ;;
            esac
        }
        printf 'failpeer\n3\n2\n' | wg_deb_add_peer
    ) >/dev/null 2>&1; then
        fail "wg_deb_add_peer succeeded despite failed runtime apply"
    elif cmp -s "$db" "$original" && [[ ! -e "$clients/failpeer.conf" ]]; then
        pass "wg_deb_add_peer rolls DB/client config back when runtime apply fails"
    else
        fail "wg_deb_add_peer failed to roll back DB/client config"
        sed 's/^/    db: /' "$db"
        sed 's/^/    log: /' "$log"
        ls -la "$clients" | sed 's/^/    /'
    fi
}

test_wg_deb_import_rolls_back_on_apply_failure() {
    local db="$WG_DEB_DB_FILE"
    local clients="$WG_DEB_CLIENT_DIR"
    local original="$TMP_ROOT/wg-deb-import-original.json"
    local import_file="$TMP_ROOT/wg-deb-import.json"
    mkdir -p "$(dirname "$db")" "$clients"

    cat > "$original" <<'EOF'
{
  "server": {
    "subnet": "10.66.66.0/24",
    "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    "endpoint": "vpn.example.com",
    "port": 51820,
    "dns": "1.1.1.1"
  },
  "peers": [
    {
      "name": "oldpeer",
      "ip": "10.66.66.2",
      "enabled": true,
      "is_gateway": false,
      "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "public_key": "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
      "preshared_key": "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=",
      "client_allowed_ips": "10.66.66.0/24",
      "peer_type": "standard",
      "route_mode": "managed"
    }
  ]
}
EOF
    cat > "$import_file" <<'EOF'
{
  "peers": [
    {
      "name": "newpeer",
      "ip": "10.66.66.3",
      "enabled": true,
      "is_gateway": false,
      "private_key": "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=",
      "public_key": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=",
      "preshared_key": "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=",
      "client_allowed_ips": "10.66.66.0/24",
      "peer_type": "standard",
      "route_mode": "managed"
    }
  ]
}
EOF
    cp "$original" "$db"
    printf 'old client\n' > "$clients/oldpeer.conf"

    if (
        wg_deb_check_server() { return 0; }
        confirm() { return 0; }
        jq() {
            local raw=0 query file name=""
            [[ "${1:-}" == "-r" ]] && { raw=1; shift; }
            if [[ "${1:-}" == "empty" ]]; then
                [[ -f "${2:-}" ]]
                return
            fi
            if [[ "${1:-}" == "--arg" ]]; then
                local arg_name="${2:-}" arg_value="${3:-}"
                shift 3
                query="${1:-}"; file="${2:-}"
                [[ "$arg_name" == "n" || "$arg_name" == "ip" ]] && name="$arg_value"
            else
                query="${1:-}"; file="${2:-}"
            fi
            if [[ "$file" == "$import_file" ]]; then
                case "$query" in
                    ".peers | length") echo 1 ;;
                    ".peers[] | \"  - \\(.name) (\\(.ip))\"") echo "  - newpeer (10.66.66.3)" ;;
                    ".peers[0].name") echo "newpeer" ;;
                    ".peers[0].ip") echo "10.66.66.3" ;;
                    ".peers[0].private_key") echo "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE=" ;;
                    ".peers[0].public_key") echo "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF=" ;;
                    ".peers[0].preshared_key") echo "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH=" ;;
                    ".peers[0].client_allowed_ips") echo "10.66.66.0/24" ;;
                    ".peers[0].enabled // true") echo "true" ;;
                    ".peers[0].is_gateway // false") echo "false" ;;
                    ".peers[0].lan_subnets // empty") echo "" ;;
                    ".peers[0].created // empty") echo "" ;;
                    ".peers[0].peer_type // empty") echo "standard" ;;
                    ".peers[0].route_mode // empty") echo "managed" ;;
                    *) return 1 ;;
                esac
                return
            fi
            if [[ "$file" == "$WG_DEB_DB_FILE" ]]; then
                case "$query" in
                    ".peers | length")
                        if grep -q '"name"[[:space:]]*:[[:space:]]*"oldpeer"' "$WG_DEB_DB_FILE" \
                           || grep -q '"name":"newpeer"' "$WG_DEB_DB_FILE"; then
                            echo 1
                        else
                            echo 0
                        fi
                        ;;
                    ".peers[] | select(.name == \$n) | .name")
                        [[ "$name" == "newpeer" ]] && grep -q '"name":"newpeer"' "$WG_DEB_DB_FILE" && echo "newpeer"
                        ;;
                    ".peers[] | select(.ip == \$ip) | .ip")
                        [[ "$name" == "10.66.66.3" ]] && grep -q '"ip":"10.66.66.3"' "$WG_DEB_DB_FILE" && echo "10.66.66.3"
                        ;;
                    *) return 1 ;;
                esac
                return
            fi
            return 1
        }
        wg_deb_db_get() { jq -r "$@" "$WG_DEB_DB_FILE"; }
        wg_deb_db_set() {
            if [[ "$*" == ".peers = []" ]]; then
                printf '{"server":{"subnet":"10.66.66.0/24","public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","endpoint":"vpn.example.com","port":51820,"dns":"1.1.1.1"},"peers":[]}\n' > "$WG_DEB_DB_FILE"
                return 0
            fi
            printf '{"server":{"subnet":"10.66.66.0/24","public_key":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=","endpoint":"vpn.example.com","port":51820,"dns":"1.1.1.1"},"peers":[{"name":"newpeer","ip":"10.66.66.3","enabled":true}]}\n' > "$WG_DEB_DB_FILE"
        }
        wg_deb_apply_conf() {
            if [[ ! -e "$TMP_ROOT/wg-deb-import-apply-called" ]]; then
                : > "$TMP_ROOT/wg-deb-import-apply-called"
                printf 'new client\n' > "$WG_DEB_CLIENT_DIR/newpeer.conf"
                return 1
            fi
            return 0
        }
        wg_deb_rebuild_conf() { return 0; }
        wg_deb_regenerate_client_confs() { return 0; }
        wg_deb_is_running() { return 0; }
        printf '%s\n1\n2\ny\n' "$import_file" | wg_deb_import_peers
    ) >/dev/null 2>&1; then
        fail "wg_deb_import_peers succeeded despite failed apply"
    elif cmp -s "$db" "$original" \
         && [[ -f "$clients/oldpeer.conf" ]] \
         && [[ ! -e "$clients/newpeer.conf" ]]; then
        pass "wg_deb_import_peers restores DB/client configs when apply fails"
    else
        fail "wg_deb_import_peers failed to restore DB/client configs"
        sed 's/^/    db: /' "$db"
        find "$clients" -maxdepth 1 -type f -print -exec sed 's/^/    client: /' {} \;
    fi
}

test_wg_deb_watchdog_cron_failure_returns_error() {
    local script="/usr/local/bin/wg-watchdog.sh"
    rm -f "$script" 2>/dev/null || true
    if (
        wg_deb_check_installed() { return 0; }
        cron_has_job_command() { return 1; }
        cron_add_job_command() { return 1; }
        wg_deb_setup_watchdog auto
    ) >/dev/null 2>&1; then
        fail "wg_deb_setup_watchdog succeeded despite cron failure"
    elif [[ ! -e "$script" ]]; then
        pass "wg_deb_setup_watchdog returns failure and removes script when cron install fails"
    else
        fail "wg_deb_setup_watchdog left script after cron failure"
        ls -l "$script" 2>/dev/null || true
        rm -f "$script" 2>/dev/null || true
    fi
}

test_ufw_setup_reset_stop_when_ssh_allow_fails() {
    local calls="$TMP_ROOT/ufw-setup-reset-calls.txt"
    : > "$calls"
    PLATFORM="debian"
    CURRENT_SSH_PORTS=""
    install_package() { return 0; }
    command_exists() { [[ "${1:-}" == "ufw" ]]; }
    is_systemd() { return 0; }
    systemctl() { return 3; }
    refresh_ssh_port() {
        CURRENT_SSH_PORT="22"
        CURRENT_SSH_PORTS="${MOCK_SSH_PORTS-22 2222}"
    }
    confirm() { return 0; }
    ufw() {
        printf '%s\n' "$*" >> "$calls"
        case "$*" in
            "allow 2222/tcp comment SSH-Access") return 1 ;;
            *) return 0 ;;
        esac
    }

    local rc_setup rc_reset
    MOCK_SSH_PORTS="22 2222"
    ufw_setup >/dev/null 2>&1
    rc_setup=$?
    ufw_safe_reset >/dev/null 2>&1
    rc_reset=$?

    if [[ "$rc_setup" -ne 0 && "$rc_reset" -ne 0 ]] \
       && grep -q '^allow 2222/tcp comment SSH-Access$' "$calls" \
       && ! grep -q '^enable$' "$calls"; then
        pass "ufw_setup/reset stop before enabling when any SSH port allow fails"
    else
        fail "ufw_setup/reset did not stop safely rc_setup=$rc_setup rc_reset=$rc_reset calls=$(paste -sd ',' "$calls")"
    fi

    : > "$calls"
    MOCK_SSH_PORTS=""
    if ufw_setup >/dev/null 2>&1; then
        fail "ufw_setup succeeded with empty CURRENT_SSH_PORTS"
    elif ! grep -q '^allow ' "$calls" && ! grep -q '^enable$' "$calls"; then
        pass "ufw_setup refuses to continue when SSH ports cannot be confirmed"
    else
        fail "ufw_setup touched UFW despite empty SSH port set: $(paste -sd ',' "$calls")"
    fi
}

test_ufw_manual_add_delete_validate_inputs() {
    local calls="$TMP_ROOT/ufw-manual-calls.txt"
    : > "$calls"
    command_exists() { [[ "${1:-}" == "ufw" ]]; }
    ufw() {
        printf '%s\n' "$*" >> "$calls"
        case "$*" in
            status)
                cat <<'EOF'
Status: active
80/tcp ALLOW Anywhere
53/udp ALLOW Anywhere
2222/tcp ALLOW Anywhere # fail2ban
EOF
                ;;
        esac
        return 0
    }

    printf '80 bad 65536 53/udp 443/tcp\n' | ufw_add >/dev/null 2>&1
    if grep -q '^allow 80/tcp comment Manual-Add$' "$calls" \
       && grep -q '^allow 80/udp comment Manual-Add$' "$calls" \
       && grep -q '^allow 53/udp comment Manual-Add$' "$calls" \
       && grep -q '^allow 443/tcp comment Manual-Add$' "$calls" \
       && ! grep -q '65536' "$calls" \
       && ! grep -q 'bad' "$calls"; then
        pass "ufw_add validates manual ports and applies only valid rules"
    else
        fail "ufw_add manual validation mismatch: $(paste -sd ',' "$calls")"
    fi

    : > "$calls"
    printf '80 53/udp bad 70000/tcp\n' | ufw_del >/dev/null 2>&1
    if grep -q '^status$' "$calls" \
       && grep -q '^delete allow 80/tcp$' "$calls" \
       && grep -q '^delete allow 80/udp$' "$calls" \
       && grep -q '^delete allow 53/udp$' "$calls" \
       && ! grep -q '70000' "$calls" \
       && ! grep -q 'bad' "$calls"; then
        pass "ufw_del validates manual ports and deletes only valid rules"
    else
        fail "ufw_del manual validation mismatch: $(paste -sd ',' "$calls")"
    fi
}

test_web_firewall_allow_helper_modes() {
    local calls="$TMP_ROOT/web-firewall-calls.txt"
    : > "$calls"
    PLATFORM="debian"
    command_exists() {
        [[ "${1:-}" == "ufw" ]]
    }
    ufw_is_active() {
        [[ "${WEB_UFW_ACTIVE:-0}" == "1" ]]
    }
    ufw() {
        printf '%s\n' "$*" >> "$calls"
        [[ "${WEB_UFW_OK:-1}" == "1" ]]
    }

    local rc_inactive rc_active_ok rc_active_fail
    WEB_UFW_ACTIVE=0 WEB_UFW_OK=1
    _web_allow_public_tcp_port 9444 "WebMock" "9444/tcp" >/dev/null 2>&1
    rc_inactive=$?
    WEB_UFW_ACTIVE=1 WEB_UFW_OK=1
    _web_allow_public_tcp_port 9444 "WebMock" "9444/tcp" >/dev/null 2>&1
    rc_active_ok=$?
    WEB_UFW_ACTIVE=1 WEB_UFW_OK=0
    _web_allow_public_tcp_port 9445 "WebMockFail" "9445/tcp" >/dev/null 2>&1
    rc_active_fail=$?

    if [[ "$rc_inactive" -eq 0 && "$rc_active_ok" -eq 0 && "$rc_active_fail" -eq 1 ]] \
       && grep -q 'allow 9444/tcp comment WebMock' "$calls" \
       && grep -q 'allow 9445/tcp comment WebMockFail' "$calls"; then
        pass "_web_allow_public_tcp_port treats inactive UFW as soft warning but propagates active UFW failures"
    else
        fail "_web_allow_public_tcp_port rc/call mismatch inactive=$rc_inactive active_ok=$rc_active_ok active_fail=$rc_active_fail calls=$(<"$calls")"
    fi
}





test_swap_fstab_helpers_are_precise() {
    local swap_file="$TMP_ROOT/swapfile" fstab="$TMP_ROOT/fstab" count mode_before="" mode_after=""
    _swap_file_path() { printf '%s' "$swap_file"; }
    _swap_fstab_path() { printf '%s' "$fstab"; }

    cat > "$fstab" <<EOF
# keep /swapfile mention in a comment
/dev/sda2 none swap sw 0 0
/swapfile2 none swap sw 0 0
$swap_file none ext4 defaults 0 0
$swap_file none swap sw 0 0
EOF
    chmod 640 "$fstab" 2>/dev/null || true

    if _swap_fstab_remove_swapfile \
       && grep -qF '# keep /swapfile mention in a comment' "$fstab" \
       && grep -qF '/dev/sda2 none swap sw 0 0' "$fstab" \
       && grep -qF '/swapfile2 none swap sw 0 0' "$fstab" \
       && grep -qF "$swap_file none ext4 defaults 0 0" "$fstab" \
       && ! awk -v sf="$swap_file" '$1 == sf && $3 == "swap" { found=1 } END { exit(found ? 0 : 1) }' "$fstab"; then
        pass "_swap_fstab_remove_swapfile removes only the managed swapfile row"
    else
        fail "_swap_fstab_remove_swapfile removed too much or missed the managed row"
        sed 's/^/    /' "$fstab"
    fi

    mode_before=$(stat -c '%a' "$fstab" 2>/dev/null || stat -f '%Lp' "$fstab" 2>/dev/null || echo "")
    _swap_fstab_add_swapfile >/dev/null 2>&1 || {
        fail "_swap_fstab_add_swapfile failed to append managed row"
        _swap_file_path() { printf '%s' "/swapfile"; }
        _swap_fstab_path() { printf '%s' "/etc/fstab"; }
        return
    }
    _swap_fstab_add_swapfile >/dev/null 2>&1 || {
        fail "_swap_fstab_add_swapfile failed on idempotent second call"
        _swap_file_path() { printf '%s' "/swapfile"; }
        _swap_fstab_path() { printf '%s' "/etc/fstab"; }
        return
    }
    count=$(awk -v sf="$swap_file" '$1 == sf && $3 == "swap" { c++ } END { print c + 0 }' "$fstab")
    mode_after=$(stat -c '%a' "$fstab" 2>/dev/null || stat -f '%Lp' "$fstab" 2>/dev/null || echo "")
    if [[ "$count" == "1" ]] \
       && [[ -z "$mode_before" || "$mode_before" == "$mode_after" ]] \
       && ! find "$(dirname "$fstab")" -maxdepth 1 -name '.tmp.server-manage.fstab.*' -print -quit | grep -q .; then
        pass "_swap_fstab_add_swapfile atomically appends exactly one managed row"
    else
        fail "_swap_fstab_add_swapfile count/mode/temp mismatch count=$count mode=${mode_before}->${mode_after}"
        ls -la "$(dirname "$fstab")" | sed 's/^/    /'
        sed 's/^/    /' "$fstab"
    fi

    _swap_file_path() { printf '%s' "/swapfile"; }
    _swap_fstab_path() { printf '%s' "/etc/fstab"; }
}

test_opt_swap_delete_only_managed_swapfile() {
    local swap_file="$TMP_ROOT/managed-swapfile" fstab="$TMP_ROOT/opt-swap-fstab" calls="$TMP_ROOT/swapoff-calls.txt"
    _swap_file_path() { printf '%s' "$swap_file"; }
    _swap_fstab_path() { printf '%s' "$fstab"; }
    free() {
        printf '              total        used        free\n'
        printf 'Swap:          2048           0        2048\n'
    }
    swapoff() {
        printf '%s\n' "$*" >> "$calls"
        return 0
    }

    : > "$calls"
    : > "$swap_file"
    cat > "$fstab" <<EOF
/dev/sda2 none swap sw 0 0
$swap_file none swap sw 0 0
EOF

    printf '2\n' | opt_swap >/dev/null 2>&1
    if [[ "$(cat "$calls")" == "$swap_file" ]] \
       && [[ ! -e "$swap_file" ]] \
       && grep -qF '/dev/sda2 none swap sw 0 0' "$fstab" \
       && ! grep -qF "$swap_file none swap sw 0 0" "$fstab"; then
        pass "opt_swap delete only swapoffs/removes the managed swapfile"
    else
        fail "opt_swap delete path touched the wrong swap state"
        {
            echo "swapoff calls:"
            sed 's/^/  /' "$calls"
            echo "fstab:"
            sed 's/^/  /' "$fstab"
        } | sed 's/^/    /'
    fi

    unset -f free swapoff
    _swap_file_path() { printf '%s' "/swapfile"; }
    _swap_fstab_path() { printf '%s' "/etc/fstab"; }
}

test_auto_deps_new_fail2ban_not_left_active() {
    local systemctl_calls="$TMP_ROOT/systemctl-calls.txt"
    : > "$systemctl_calls"
    local installed="$TMP_ROOT/installed.txt"
    : > "$installed"
    local state_dir="$TMP_ROOT/state"
    mkdir -p "$state_dir"

    ufw_is_active() { return 1; }
    systemctl() {
        printf '%s\n' "$*" >> "$systemctl_calls"
        case "$*" in
            "is-active fail2ban") return 3 ;;
            *) return 0 ;;
        esac
    }
    apt-get() { return 0; }
    dpkg() {
        local pkg="${3:-}"
        grep -qx "$pkg" "$installed"
    }
    _deps_save_state() {
        printf 'checked=mock\n' > "$state_dir/.deps-ok"
    }

    # Mark everything installed except fail2ban, so the test only checks the
    # newly-installed fail2ban service policy without touching apt.
    printf '%s\n' curl wget jq unzip openssl ca-certificates ufw ipset iproute2 net-tools procps > "$installed"
    auto_deps >/dev/null 2>&1

    if grep -q '^disable --now fail2ban$' "$systemctl_calls"; then
        pass "auto_deps disables a newly-installed fail2ban instead of silently enabling jails"
    else
        fail "auto_deps did not disable newly-installed fail2ban; calls=$(paste -sd ',' "$systemctl_calls")"
    fi
}

test_openwrt_wg_watchdog_ipv6_helpers() {
    local helper_lib="$TMP_ROOT/wg-watchdog-helpers.sh"
    awk '
        /^resolve_real\(\)/ {capture=1}
        capture {print}
        /^if ! wg_is_up/ {exit}
    ' "$ROOT/modules/11d-wireguard-peers.sh" | sed '$d' > "$helper_lib"

    # shellcheck disable=SC1090
    source "$helper_lib" || {
        fail "failed to source extracted OpenWrt WireGuard watchdog helpers"
        return
    }

    local h4 h6 ep4 ep6 fam4 fam6 ip_calls="$TMP_ROOT/ip-rule-calls.txt"
    h4=$(wg_endpoint_host "198.51.100.8:51820")
    h6=$(wg_endpoint_host "[2001:db8::8]:51820")
    ep4=$(wg_format_endpoint "198.51.100.8" "51820")
    ep6=$(wg_format_endpoint "2001:db8::8" "51820")
    fam4=$(wg_nft_addr_family "198.51.100.8")
    fam6=$(wg_nft_addr_family "2001:db8::8")
    if [[ "$h4" == "198.51.100.8" && "$h6" == "2001:db8::8" && "$ep4" == "198.51.100.8:51820" && "$ep6" == "[2001:db8::8]:51820" && "$fam4" == "ip" && "$fam6" == "ip6" ]]; then
        pass "OpenWrt WG watchdog helpers parse and format IPv4/IPv6 endpoints"
    else
        fail "OpenWrt WG watchdog helper mismatch h4=$h4 h6=$h6 ep4=$ep4 ep6=$ep6 fam4=$fam4 fam6=$fam6"
    fi

    nslookup() {
        case "${2:-}" in
            223.5.5.5)
                cat <<'EOF'
Server: 223.5.5.5
Address: 223.5.5.5#53

Name: vpn.example.com
Address: 198.18.0.42
EOF
                ;;
            119.29.29.29)
                cat <<'EOF'
Server: 119.29.29.29
Address 1: 119.29.29.29

Name: vpn.example.com
Address 1: 203.0.113.44
EOF
                ;;
            *)
                return 1
                ;;
        esac
    }
    local resolved
    resolved=$(resolve_real "vpn.example.com")
    if [[ "$resolved" == "203.0.113.44" ]]; then
        pass "OpenWrt WG watchdog resolver skips fake-ip and parses BusyBox Address N output"
    else
        fail "OpenWrt WG watchdog resolver returned '$resolved' instead of real BusyBox answer"
    fi
    unset -f nslookup

    ip() {
        printf '%s\n' "$*" >> "$ip_calls"
    }
    : > "$ip_calls"
    wg_ip_rule_add "2001:db8::8"
    wg_ip_rule_del "2001:db8::8"
    wg_ip_rule_add "198.51.100.8"
    if grep -q '^-6 rule add to 2001:db8::8 lookup main prio 100$' "$ip_calls" \
       && grep -q '^-6 rule del to 2001:db8::8 lookup main prio 100$' "$ip_calls" \
       && grep -q '^rule add to 198.51.100.8 lookup main prio 100$' "$ip_calls"; then
        pass "OpenWrt WG watchdog uses ip -6 rule for IPv6 endpoints"
    else
        fail "OpenWrt WG watchdog ip rule calls mismatch: $(paste -sd ',' "$ip_calls")"
    fi
}

test_wg_shared_endpoint_formatting() {
    local ep4 ep6 ep6_bracketed host4 host6 norm_domain norm6
    ep4=$(wg_shared_format_endpoint "198.51.100.8" "51820")
    ep6=$(wg_shared_format_endpoint "2001:db8::8" "51820")
    ep6_bracketed=$(wg_shared_format_endpoint "[2001:db8::9]" "51820")
    host4=$(wg_shared_endpoint_host "198.51.100.8:51820")
    host6=$(wg_shared_endpoint_host "[2001:db8::8]:51820")
    norm_domain=$(wg_shared_normalize_endpoint_host "vpn.example.com:51820")
    norm6=$(wg_shared_normalize_endpoint_host "[2001:db8::10]:51820")
    if [[ "$ep4" == "198.51.100.8:51820" \
       && "$ep6" == "[2001:db8::8]:51820" \
       && "$ep6_bracketed" == "[2001:db8::9]:51820" \
       && "$host4" == "198.51.100.8" \
       && "$host6" == "2001:db8::8" \
       && "$norm_domain" == "vpn.example.com" \
       && "$norm6" == "2001:db8::10" ]]; then
        pass "WireGuard shared endpoint formatter handles IPv4 and IPv6"
    else
        fail "WireGuard endpoint formatter mismatch ep4=$ep4 ep6=$ep6 ep6b=$ep6_bracketed host4=$host4 host6=$host6 norm_domain=$norm_domain norm6=$norm6"
    fi
    if wg_shared_normalize_endpoint_host "vpn.example.com'; touch /tmp/pwn #" >/dev/null 2>&1; then
        fail "WireGuard endpoint normalizer accepted shell metacharacters"
    else
        pass "WireGuard endpoint normalizer rejects shell metacharacters"
    fi
}

test_wg_rc_local_cleanup_preserves_third_party_prio100() {
    local rc_file="$TMP_ROOT/rc.local"
    cat > "$rc_file" <<'EOF'
#!/bin/sh
ip rule add to 203.0.113.7 lookup main prio 100 # third-party keep
# BEGIN server-manage wireguard bypass
# WireGuard bypass Mihomo
ip rule add to 198.51.100.9 lookup main prio 100 # wg_bypass
nft insert rule inet fw4 mangle_prerouting ip daddr "198.51.100.9" udp dport 51820 counter return comment "wg_bypass" 2>/dev/null || true # wg_bypass
# END server-manage wireguard bypass
nft insert rule inet fw4 input_wan udp dport 51820 counter accept comment "wg_allow_port" 2>/dev/null || true # wg_allow_port
exit 0
EOF

    if _wg_rc_local_cleanup_managed_entries all "$rc_file" \
       && grep -qF 'ip rule add to 203.0.113.7 lookup main prio 100 # third-party keep' "$rc_file" \
       && ! grep -q 'wg_bypass\|wg_allow_port\|server-manage wireguard' "$rc_file"; then
        pass "_wg_rc_local_cleanup_managed_entries preserves third-party prio 100 rc.local lines"
    else
        fail "_wg_rc_local_cleanup_managed_entries removed third-party rc.local lines or left managed entries"
        sed 's/^/    /' "$rc_file"
    fi
}

test_openwrt_apply_allow_port_rolls_back_new_rule_on_uci_failure() {
    local rules="$TMP_ROOT/openwrt-allow-rules.txt"
    local deleted="$TMP_ROOT/openwrt-allow-deleted.txt"
    cat > "$rules" <<'EOF'
udp dport 51820 counter accept comment "wg_allow_port" # handle 11
EOF
    : > "$deleted"

    nft() {
        case "$*" in
            "list chain inet fw4 input_wan"|"-a list chain inet fw4 input_wan")
                cat "$rules"
                return 0
                ;;
            "insert rule inet fw4 input_wan udp dport 51820 counter accept comment wg_allow_port")
                printf '%s\n' 'udp dport 51820 counter accept comment "wg_allow_port" # handle 22' >> "$rules"
                return 0
                ;;
            "delete rule inet fw4 input_wan handle 22")
                printf '%s\n' 22 >> "$deleted"
                sed -i '/handle 22$/d' "$rules"
                return 0
                ;;
            "delete rule inet fw4 input_wan handle 11")
                printf '%s\n' 11 >> "$deleted"
                sed -i '/handle 11$/d' "$rules"
                return 0
                ;;
            *)
                return 1
                ;;
        esac
    }
    uci() {
        [[ "$*" == "commit firewall" ]] && return 1
        return 0
    }
    _wg_rc_local_cleanup_managed_entries() { return 0; }
    _wg_rc_local_insert_block() { return 0; }

    if ! _wg_openwrt_apply_allow_port 51820 >/dev/null 2>&1 \
       && grep -q 'handle 11$' "$rules" \
       && ! grep -q 'handle 22$' "$rules" \
       && grep -Fxq '22' "$deleted" \
       && ! grep -Fxq '11' "$deleted"; then
        pass "_wg_openwrt_apply_allow_port rolls back only the newly inserted nft rule on uci failure"
    else
        fail "_wg_openwrt_apply_allow_port did not preserve old nft rule and remove new failed rule"
        sed 's/^/    rules: /' "$rules"
        sed 's/^/    deleted: /' "$deleted"
    fi
    unset -f nft uci _wg_rc_local_cleanup_managed_entries _wg_rc_local_insert_block
}

test_openwrt_persist_allow_port_restores_firewall_on_uci_failure() {
    local dir="$TMP_ROOT/openwrt-persist-fw-uci"
    local state="$dir/firewall.uci"
    local old_state="$dir/firewall.old"
    local log="$dir/uci.log"
    local marker="$dir/failure-point"
    local tmpdir="$dir/tmp"
    rm -rf "$dir"
    mkdir -p "$tmpdir"
    cat > "$old_state" <<'EOF'
config rule 'existing'
        option name 'old'
EOF
    cp "$old_state" "$state"
    : > "$log"

    uci() {
        [[ "${1:-}" == "-q" ]] && shift
        printf 'uci|%s\n' "$*" >> "$log"
        case "${1:-}" in
            export)
                [[ "${2:-}" == "firewall" ]] || return 1
                cat "$state"
                return 0
                ;;
            import)
                [[ "${2:-}" == "firewall" ]] || return 1
                cat > "$state"
                return 0
                ;;
            revert)
                return 0
                ;;
            set)
                printf 'mutated-set|%s\n' "$*" >> "$state"
                if [[ "${2:-}" == "firewall.wg_allow_port.dest_port=51820" ]]; then
                    : > "$marker"
                    return 77
                fi
                return 0
                ;;
            commit)
                [[ "${2:-}" == "firewall" ]] || return 1
                return 0
                ;;
        esac
        return 1
    }

    if ! TMPDIR="$tmpdir" _wg_openwrt_persist_allow_port 51820 >/dev/null 2>&1 \
       && cmp -s "$state" "$old_state" \
       && [[ -f "$marker" ]] \
       && grep -Fxq 'uci|revert firewall' "$log" \
       && grep -Fxq 'uci|import firewall' "$log" \
       && grep -Fxq 'uci|commit firewall' "$log" \
       && ! find "$tmpdir" -maxdepth 1 -name "${SCRIPT_NAME}-wg-fw.*" -print -quit | grep -q .; then
        pass "_wg_openwrt_persist_allow_port restores firewall UCI snapshot when a set fails"
    else
        fail "_wg_openwrt_persist_allow_port did not restore firewall UCI snapshot on set failure"
        sed 's/^/    log: /' "$log" 2>/dev/null || true
        sed 's/^/    state: /' "$state" 2>/dev/null || true
        find "$tmpdir" -maxdepth 2 -ls 2>/dev/null | sed 's/^/    tmp: /' || true
    fi
    unset -f uci
}

test_openwrt_configure_server_uci_restores_packages_on_uci_failure() {
    local dir="$TMP_ROOT/openwrt-server-uci"
    local network_state="$dir/network.uci"
    local firewall_state="$dir/firewall.uci"
    local old_network="$dir/network.old"
    local old_firewall="$dir/firewall.old"
    local log="$dir/uci.log"
    local marker="$dir/failure-point"
    local tmpdir="$dir/tmp"
    rm -rf "$dir"
    mkdir -p "$tmpdir"
    cat > "$old_network" <<'EOF'
config interface 'lan'
        option proto 'static'
EOF
    cat > "$old_firewall" <<'EOF'
config defaults
        option input 'REJECT'
EOF
    cp "$old_network" "$network_state"
    cp "$old_firewall" "$firewall_state"
    : > "$log"

    uci() {
        [[ "${1:-}" == "-q" ]] && shift
        printf 'uci|%s\n' "$*" >> "$log"
        case "${1:-}" in
            export)
                case "${2:-}" in
                    network) cat "$network_state"; return 0 ;;
                    firewall) cat "$firewall_state"; return 0 ;;
                esac
                return 1
                ;;
            import)
                case "${2:-}" in
                    network) cat > "$network_state"; return 0 ;;
                    firewall) cat > "$firewall_state"; return 0 ;;
                esac
                return 1
                ;;
            revert|delete)
                return 0
                ;;
            set|add_list)
                case "${2:-}" in
                    network.*) printf 'mutated-%s|%s\n' "${1:-}" "$*" >> "$network_state" ;;
                    firewall.*) printf 'mutated-%s|%s\n' "${1:-}" "$*" >> "$firewall_state" ;;
                esac
                if [[ "${2:-}" == "firewall.wg_zone.output=ACCEPT" ]]; then
                    : > "$marker"
                    return 77
                fi
                return 0
                ;;
            commit)
                case "${2:-}" in
                    network|firewall) return 0 ;;
                esac
                return 1
                ;;
        esac
        return 1
    }

    if ! TMPDIR="$tmpdir" _wg_openwrt_configure_server_uci \
            "server-private" "10.66.66.1" "24" "51820" "1420" >/dev/null 2>&1 \
       && cmp -s "$network_state" "$old_network" \
       && cmp -s "$firewall_state" "$old_firewall" \
       && [[ -f "$marker" ]] \
       && grep -Fxq 'uci|revert network' "$log" \
       && grep -Fxq 'uci|import network' "$log" \
       && grep -Fxq 'uci|commit network' "$log" \
       && grep -Fxq 'uci|revert firewall' "$log" \
       && grep -Fxq 'uci|import firewall' "$log" \
       && grep -Fxq 'uci|commit firewall' "$log" \
       && ! find "$tmpdir" -maxdepth 1 -name "${SCRIPT_NAME}-wg-server-uci.*" -print -quit | grep -q .; then
        pass "_wg_openwrt_configure_server_uci restores network/firewall UCI snapshots when a set fails"
    else
        fail "_wg_openwrt_configure_server_uci did not restore UCI snapshots on set failure"
        sed 's/^/    log: /' "$log" 2>/dev/null || true
        sed 's/^/    network: /' "$network_state" 2>/dev/null || true
        sed 's/^/    firewall: /' "$firewall_state" 2>/dev/null || true
        find "$tmpdir" -maxdepth 2 -ls 2>/dev/null | sed 's/^/    tmp: /' || true
    fi
    unset -f uci
}

test_openwrt_wg_modify_server_firewall_failure_stops_before_db() {
    local db_calls="$TMP_ROOT/openwrt-modify-fw-db.txt"
    local rebuild_calls="$TMP_ROOT/openwrt-modify-fw-rebuild.txt"
    : > "$db_calls"
    : > "$rebuild_calls"

    wg_check_server() { return 0; }
    wg_db_get() {
        case "$1" in
            '.server.port') printf '51820\n' ;;
            '.server.dns') printf '1.1.1.1\n' ;;
            '.server.endpoint') printf 'vpn.example.com\n' ;;
            '.server.server_lan_subnet // empty') printf '192.168.1.0/24\n' ;;
            *) printf '\n' ;;
        esac
    }
    _wg_openwrt_apply_allow_port() { return 1; }
    wg_db_set() { printf '%s\n' "$*" >> "$db_calls"; return 0; }
    _wg_update_peer_routes() { printf 'routes\n' >> "$rebuild_calls"; return 0; }
    wg_rebuild_uci_conf() { printf 'uci\n' >> "$rebuild_calls"; return 0; }
    wg_rebuild_conf() { printf 'conf\n' >> "$rebuild_calls"; return 0; }
    wg_regenerate_client_confs() { printf 'clients\n' >> "$rebuild_calls"; return 0; }
    wg_mihomo_bypass_rebuild() { printf 'bypass\n' >> "$rebuild_calls"; return 0; }

    if ! printf '51821\n1.1.1.1\nvpn.example.com\n192.168.1.0/24\n' | wg_modify_server >/dev/null 2>&1 \
       && [[ ! -s "$db_calls" ]] \
       && [[ ! -s "$rebuild_calls" ]]; then
        pass "wg_modify_server stops before DB/config writes when OpenWrt UDP allow fails"
    else
        fail "wg_modify_server wrote DB/config despite OpenWrt UDP allow failure"
        sed 's/^/    db: /' "$db_calls"
        sed 's/^/    rebuild: /' "$rebuild_calls"
    fi
    unset -f wg_check_server wg_db_get _wg_openwrt_apply_allow_port wg_db_set _wg_update_peer_routes wg_rebuild_uci_conf wg_rebuild_conf wg_regenerate_client_confs wg_mihomo_bypass_rebuild
}

test_openwrt_wg_modify_server_rolls_back_on_rebuild_failure() {
    local db_calls="$TMP_ROOT/openwrt-modify-rollback-db.txt"
    local ports="$TMP_ROOT/openwrt-modify-rollback-ports.txt"
    : > "$db_calls"
    : > "$ports"

    wg_check_server() { return 0; }
    wg_db_get() {
        case "$1" in
            '.server.port') printf '51820\n' ;;
            '.server.dns') printf '1.1.1.1\n' ;;
            '.server.endpoint') printf 'vpn.example.com\n' ;;
            '.server.server_lan_subnet // empty') printf '192.168.1.0/24\n' ;;
            *) printf '\n' ;;
        esac
    }
    _wg_openwrt_apply_allow_port() { printf '%s\n' "$1" >> "$ports"; return 0; }
    wg_db_set() { printf '%s\n' "$*" >> "$db_calls"; return 0; }
    _wg_update_peer_routes() { return 0; }
    wg_rebuild_uci_conf() { return 1; }
    wg_rebuild_conf() { return 0; }
    wg_regenerate_client_confs() { return 0; }
    wg_mihomo_bypass_rebuild() { return 0; }

    if ! printf '51821\n1.1.1.1\nvpn.example.com\n192.168.1.0/24\n' | wg_modify_server >/dev/null 2>&1 \
       && grep -Fxq '51821' "$ports" \
       && grep -Fxq '51820' "$ports" \
       && grep -q -- '--argjson p 51821' "$db_calls" \
       && grep -q -- '--argjson p 51820' "$db_calls"; then
        pass "wg_modify_server rolls back OpenWrt firewall and DB when rebuild fails"
    else
        fail "wg_modify_server did not roll back OpenWrt firewall/DB after rebuild failure"
        sed 's/^/    ports: /' "$ports"
        sed 's/^/    db: /' "$db_calls"
    fi
    unset -f wg_check_server wg_db_get _wg_openwrt_apply_allow_port wg_db_set _wg_update_peer_routes wg_rebuild_uci_conf wg_rebuild_conf wg_regenerate_client_confs wg_mihomo_bypass_rebuild
}

test_openwrt_wg_server_install_rolls_back_on_ifup_failure() {
    local log="$TMP_ROOT/openwrt-install-rollback.log"
    local rc_file="$TMP_ROOT/openwrt-install-rc.local"
    local mock_forward_conf="$TMP_ROOT/openwrt-install-sysctl.conf"
    local old_db="$TMP_ROOT/openwrt-install-old-db.json"
    local old_role="$TMP_ROOT/openwrt-install-old-role"
    local old_conf="$TMP_ROOT/openwrt-install-old-conf"
    local old_routes="$TMP_ROOT/openwrt-install-old-routes"
    : > "$log"
    mkdir -p "$(dirname "$WG_DB_FILE")" "$(dirname "$WG_ROLE_FILE")" "$(dirname "$WG_CONF")" "$(dirname "$WG_SHARED_ROUTE_STATE_FILE")"
    printf '{"role":"client","server":{"name":"old"},"peers":[],"client":{}}\n' > "$old_db"
    printf 'client\n' > "$old_role"
    printf '[Interface]\n# old\n' > "$old_conf"
    printf '192.168.50.0/24\n' > "$old_routes"
    cp "$old_db" "$WG_DB_FILE"
    cp "$old_role" "$WG_ROLE_FILE"
    cp "$old_conf" "$WG_CONF"
    cp "$old_routes" "$WG_SHARED_ROUTE_STATE_FILE"
    rm -rf "$DDNS_CONFIG_DIR"
    printf '#!/bin/sh\n# third party\nexit 0\n' > "$rc_file"
    printf '# keep sysctl\nnet.ipv4.ip_forward = 0\n' > "$mock_forward_conf"

    if (
        WG_OPENWRT_RC_LOCAL_FILE="$rc_file"
        read() {
            local OPTIND opt
            while getopts ":erp:" opt; do :; done
            shift $((OPTIND - 1))
            command read -r "$@"
        }
        _sysctl_conf_path() { printf '%s' "$mock_forward_conf"; }
        sysctl() {
            printf 'sysctl|%s\n' "$*" >> "$log"
            case "$*" in
                "-n net.ipv4.ip_forward") printf '0\n'; return 0 ;;
                "-w net.ipv4.ip_forward="*) return 0 ;;
                *) return 0 ;;
            esac
        }
        _sysctl_enable_wireguard_forward() { printf 'forward-enable\n' >> "$log"; return 0; }
        wg_is_installed() { return 1; }
        wg_check_openwrt_compat() { return 0; }
        wg_install_packages() { return 0; }
        get_public_ipv4() { echo "198.51.100.10"; }
        wg_shared_normalize_endpoint_host() { printf '%s\n' "${1:-}"; }
        hostname() { echo "openwrt-mock"; }
        ip() { return 1; }
        wg() {
            case "${1:-}" in
                genkey) echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ;;
                pubkey) cat >/dev/null; echo "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=" ;;
                *) return 1 ;;
            esac
        }
        uci() {
            printf 'uci|%s\n' "$*" >> "$log"
            case "$*" in
                "export network") printf 'config interface loopback\n'; return 0 ;;
                "export firewall") printf 'config defaults\n'; return 0 ;;
                "import network") cat >/dev/null; return 0 ;;
                "import firewall") cat >/dev/null; return 0 ;;
                "commit network"|"commit firewall") return 0 ;;
                *) return 0 ;;
            esac
        }
        nft() {
            printf 'nft|%s\n' "$*" >> "$log"
            case "$*" in
                "list chain inet fw4 input_wan"|"-a list chain inet fw4 input_wan"|"list chain inet fw4 mangle_prerouting"|"-a list chain inet fw4 mangle_prerouting") return 0 ;;
                *) return 0 ;;
            esac
        }
        _wg_rc_local_cleanup_managed_entries() {
            printf 'rc-clean|%s|%s\n' "${1:-}" "${2:-}" >> "$log"
            return 0
        }
        _wg_rc_local_insert_block() {
            printf 'rc-insert|%s\n' "${2:-}" >> "$log"
            printf '# managed\n' >> "${2:-$rc_file}"
            return 0
        }
        wg_db_init() { printf 'dbinit\n' >> "$log"; return 0; }
        wg_db_set() {
            printf 'dbset|%s\n' "$*" >> "$log"
            printf '{"role":"","server":{"name":"new"},"peers":[],"client":{}}\n' > "$WG_DB_FILE"
            return 0
        }
        wg_set_role() {
            printf 'role|%s\n' "$*" >> "$log"
            printf '%s\n' "$1" > "$WG_ROLE_FILE"
            return 0
        }
        wg_rebuild_conf() {
            printf 'rebuild-conf\n' >> "$log"
            printf '[Interface]\n# new\n' > "$WG_CONF"
            return 0
        }
        wg_setup_mihomo_bypass() { printf 'bypass|%s\n' "$*" >> "$log"; return 0; }
        ifup() { printf 'ifup|%s\n' "$*" >> "$log"; return 1; }
        ifdown() { printf 'ifdown|%s\n' "$*" >> "$log"; return 0; }
        wg_mihomo_bypass_clean() { printf 'bypass-clean\n' >> "$log"; return 0; }
        sleep() { :; }
        log_action() { printf 'log|%s\n' "$*" >> "$log"; }
        printf '51820\n\n\n\nnew-openwrt\n' | wg_server_install
    ) >/dev/null 2>&1; then
        fail "wg_server_install succeeded despite ifup failure"
    elif cmp -s "$WG_DB_FILE" "$old_db" \
         && cmp -s "$WG_ROLE_FILE" "$old_role" \
         && cmp -s "$WG_CONF" "$old_conf" \
         && cmp -s "$WG_SHARED_ROUTE_STATE_FILE" "$old_routes" \
         && grep -q '^uci|import network$' "$log" \
         && grep -q '^uci|import firewall$' "$log" \
         && grep -q '^ifdown|wg0$' "$log" \
         && grep -q '^bypass-clean$' "$log" \
         && grep -q '^sysctl|-w net.ipv4.ip_forward=0$' "$log" \
         && grep -qF '# third party' "$rc_file" \
         && ! grep -q '^log|WireGuard server installed' "$log"; then
        pass "wg_server_install rolls back OpenWrt UCI/files/rc/sysctl when ifup fails"
    else
        fail "wg_server_install did not fully roll back after ifup failure"
        sed 's/^/    log: /' "$log"
        sed 's/^/    db: /' "$WG_DB_FILE" 2>/dev/null || true
        sed 's/^/    role: /' "$WG_ROLE_FILE" 2>/dev/null || true
        sed 's/^/    conf: /' "$WG_CONF" 2>/dev/null || true
        sed 's/^/    routes: /' "$WG_SHARED_ROUTE_STATE_FILE" 2>/dev/null || true
        sed 's/^/    rc: /' "$rc_file" 2>/dev/null || true
    fi
}

test_openwrt_wg_add_peer_db_failure_leaves_no_client_conf() {
    local conf_file="/etc/wireguard/clients/peer1.conf"
    local calls="$TMP_ROOT/openwrt-add-peer-calls.txt"
    mkdir -p "$(dirname "$WG_DB_FILE")"
    printf '{"role":"server","server":{},"peers":[],"client":{}}\n' > "$WG_DB_FILE"
    : > "$calls"

    wg_check_server() { return 0; }
    wg_db_get() {
        case "$*" in
            *'.peers[] | select(.name == $n) | .name'*) printf '\n' ;;
            '.server.subnet') printf '10.66.66.0/24\n' ;;
            '.server.server_lan_subnet // empty') printf '\n' ;;
            '.peers | length') printf '0\n' ;;
            '.server.public_key') printf 'server-public\n' ;;
            '.server.endpoint') printf 'vpn.example.com\n' ;;
            '.server.port') printf '51820\n' ;;
            '.server.dns') printf '1.1.1.1\n' ;;
            *) printf '\n' ;;
        esac
    }
    wg_next_ip() { printf '10.66.66.2\n'; }
    wg() {
        case "$1" in
            genkey) printf 'peer-private\n' ;;
            pubkey) printf 'peer-public\n' ;;
            genpsk) printf 'peer-psk\n' ;;
            *) return 1 ;;
        esac
    }
    wg_db_set() { printf '%s\n' "$*" >> "$calls"; return 1; }
    wg_rebuild_uci_conf() { printf 'uci\n' >> "$calls"; return 0; }
    wg_apply_runtime_conf() { printf 'apply\n' >> "$calls"; return 0; }
    wg_regenerate_client_confs() { printf 'clients\n' >> "$calls"; return 0; }
    wg_mihomo_bypass_rebuild() { printf 'bypass\n' >> "$calls"; return 0; }

    rm -f "$conf_file" 2>/dev/null || true
    if ! printf 'peer1\n3\n2\n' | wg_add_peer >/dev/null 2>&1 \
       && [[ ! -e "$conf_file" ]] \
       && ! grep -q '^uci\|^apply\|^clients\|^bypass' "$calls"; then
        pass "wg_add_peer stops on DB failure before writing/applying client config"
    else
        fail "wg_add_peer left client config or continued after DB failure"
        sed 's/^/    calls: /' "$calls"
        ls -l "$conf_file" 2>/dev/null || true
    fi
    unset -f wg_check_server wg_db_get wg_next_ip wg wg_db_set wg_rebuild_uci_conf wg_apply_runtime_conf wg_regenerate_client_confs wg_mihomo_bypass_rebuild
}

test_openwrt_wg_toggle_peer_rolls_back_db_on_apply_failure() {
    local restore_log="$TMP_ROOT/openwrt-toggle-restore.txt"
    mkdir -p "$(dirname "$WG_DB_FILE")"
    printf 'OLD_DB\n' > "$WG_DB_FILE"
    : > "$restore_log"

    wg_check_server() { return 0; }
    wg_select_peer() { REPLY=0; return 0; }
    wg_db_get() {
        case "$1" in
            '.peers[0].name') printf 'peer1\n' ;;
            '.peers[0].enabled') printf 'true\n' ;;
            *) printf '\n' ;;
        esac
    }
    wg_db_set() { printf 'NEW_DB\n' > "$WG_DB_FILE"; return 0; }
    wg_rebuild_uci_conf() { return 0; }
    wg_apply_runtime_conf() { return 1; }
    wg_regenerate_client_confs() { return 0; }
    wg_mihomo_bypass_rebuild() { return 0; }
    wg_write_private_file() { printf '%s\n' "$2" > "$1"; printf 'restore\n' >> "$restore_log"; }

    if ! wg_toggle_peer >/dev/null 2>&1 \
       && grep -Fxq 'OLD_DB' "$WG_DB_FILE" \
       && grep -q 'restore' "$restore_log"; then
        pass "wg_toggle_peer rolls DB back when runtime apply fails"
    else
        fail "wg_toggle_peer did not restore DB after runtime apply failure"
        sed 's/^/    db: /' "$WG_DB_FILE"
        sed 's/^/    restore: /' "$restore_log"
    fi
    unset -f wg_check_server wg_select_peer wg_db_get wg_db_set wg_rebuild_uci_conf wg_apply_runtime_conf wg_regenerate_client_confs wg_mihomo_bypass_rebuild wg_write_private_file
}

test_openwrt_wg_delete_peer_rolls_back_before_removing_conf_on_apply_failure() {
    local conf_file="/etc/wireguard/clients/peer1.conf"
    mkdir -p "$(dirname "$WG_DB_FILE")"
    printf 'OLD_DB\n' > "$WG_DB_FILE"
    mkdir -p "$(dirname "$conf_file")"
    printf 'client-conf\n' > "$conf_file"

    wg_check_server() { return 0; }
    wg_select_peer() { REPLY=0; return 0; }
    wg_db_get() {
        case "$1" in
            '.peers[0].name') printf 'peer1\n' ;;
            '.peers[0].is_gateway // false') printf 'false\n' ;;
            '.peers[0].lan_subnets // empty') printf '\n' ;;
            *) printf '\n' ;;
        esac
    }
    wg_db_set() { printf 'DELETED_DB\n' > "$WG_DB_FILE"; return 0; }
    wg_rebuild_uci_conf() { return 0; }
    wg_apply_runtime_conf() { return 1; }
    wg_regenerate_client_confs() { return 0; }
    wg_mihomo_bypass_rebuild() { return 0; }
    wg_write_private_file() { printf '%s\n' "$2" > "$1"; }

    if ! wg_delete_peer >/dev/null 2>&1 \
       && grep -Fxq 'OLD_DB' "$WG_DB_FILE" \
       && [[ -f "$conf_file" ]]; then
        pass "wg_delete_peer rolls DB back and preserves client config when apply fails"
    else
        fail "wg_delete_peer did not restore DB/preserve config after apply failure"
        sed 's/^/    db: /' "$WG_DB_FILE"
        ls -l "$conf_file" 2>/dev/null || true
    fi
    rm -f "$conf_file" 2>/dev/null || true
    unset -f wg_check_server wg_select_peer wg_db_get wg_db_set wg_rebuild_uci_conf wg_apply_runtime_conf wg_regenerate_client_confs wg_mihomo_bypass_rebuild wg_write_private_file
}

test_openwrt_wg_rebuild_uci_conf_restores_network_on_uci_failure() {
    local probe="$TMP_ROOT/openwrt-wg-uci-probe.sh"
    local probe_out="$TMP_ROOT/openwrt-wg-uci-probe.out"
    cat > "$probe" <<'EOF_PROBE'
#!/usr/bin/env bash
set -u
LIB="${1:?}"
ROOT="${2:?}/openwrt-wg-uci-probe"
rm -rf "$ROOT"
mkdir -p "$ROOT/tmp"
# shellcheck disable=SC1090
source "$LIB" >/dev/null 2>&1 || exit 90
print_error() { :; }
print_warn() { :; }
uci_state="$ROOT/network.uci"
old_state="$ROOT/network.old"
uci_log="$ROOT/uci.log"
peer_count="$ROOT/peer-count"
mutation_marker="$ROOT/mutated"
cat > "$old_state" <<'EOF_OLD'
config interface 'wg0'
        option proto 'wireguard'
        option listen_port '51820'
config wireguard_wg0
        option description 'old-peer'
EOF_OLD
cp "$old_state" "$uci_state"
printf '1\n' > "$peer_count"
: > "$uci_log"
uci() {
    [[ "${1:-}" == "-q" ]] && shift
    printf 'uci|%s\n' "$*" >> "$uci_log"
    case "${1:-}" in
        export)
            [[ "${2:-}" == "network" ]] || return 1
            cat "$uci_state"
            return 0
            ;;
        import)
            [[ "${2:-}" == "network" ]] || return 1
            cat > "$uci_state"
            return 0
            ;;
        revert) return 0 ;;
        get)
            [[ "${2:-}" == "network.@wireguard_wg0[0]" && "$(cat "$peer_count" 2>/dev/null || echo 0)" -gt 0 ]]
            return $?
            ;;
        delete)
            [[ "${2:-}" == "network.@wireguard_wg0[0]" ]] && {
                printf '0\n' > "$peer_count"
                printf 'mutated-delete-old-peer\n' > "$uci_state"
            }
            return 0
            ;;
        add)
            [[ "${2:-}" == "network" && "${3:-}" == "wireguard_wg0" ]] && printf '1\n' > "$peer_count"
            printf 'mutated-add|%s\n' "$*" >> "$uci_state"
            return 0
            ;;
        set)
            printf 'mutated-set|%s\n' "$*" >> "$uci_state"
            return 0
            ;;
        add_list)
            printf 'mutated-add-list|%s\n' "$*" >> "$uci_state"
            if [[ "$*" == *'network.@wireguard_wg0[-1].allowed_ips=10.66.66.2/32'* ]]; then
                : > "$mutation_marker"
                return 77
            fi
            return 0
            ;;
        commit) return 0 ;;
    esac
    return 1
}
wg_get_role() { printf 'server\n'; }
wg_db_get() {
    case "${1:-}" in
        '.server.private_key') printf 'server-private\n' ;;
        '.server.port') printf '51820\n' ;;
        '.server.subnet') printf '10.66.66.0/24\n' ;;
        '.server.ip') printf '10.66.66.1\n' ;;
        '.server.mtu // empty') printf '1420\n' ;;
        '.peers | length') printf '1\n' ;;
        '.peers[0].enabled') printf 'true\n' ;;
        '.peers[0].name') printf 'peer1\n' ;;
        '.peers[0].public_key') printf 'peer-public\n' ;;
        '.peers[0].preshared_key') printf 'peer-psk\n' ;;
        '.peers[0].ip') printf '10.66.66.2\n' ;;
        '.peers[0].is_gateway // false') printf 'false\n' ;;
        '.peers[0].lan_subnets // empty') printf '\n' ;;
        *) printf '\n' ;;
    esac
}
wg_is_running() { return 1; }
if TMPDIR="$ROOT/tmp" wg_rebuild_uci_conf "no_reload" >/dev/null 2>&1; then
    echo "wg_rebuild_uci_conf unexpectedly succeeded"
    cat "$uci_log"
    exit 1
fi
cmp -s "$uci_state" "$old_state" || { echo "network state was not restored"; cat "$uci_state"; cat "$uci_log"; exit 2; }
[[ -f "$mutation_marker" ]] || { echo "failure point was not reached"; cat "$uci_log"; exit 3; }
if find "$ROOT/tmp" -maxdepth 1 -name "${SCRIPT_NAME}-wg-uci.*" -print -quit | grep -q .; then
    echo "snapshot temp dir was not cleaned"
    find "$ROOT/tmp" -maxdepth 2 -ls
    exit 4
fi
grep -Fxq 'uci|revert network' "$uci_log" || { echo "missing revert"; cat "$uci_log"; exit 5; }
grep -Fxq 'uci|import network' "$uci_log" || { echo "missing import"; cat "$uci_log"; exit 6; }
grep -Fxq 'uci|commit network' "$uci_log" || { echo "missing restore commit"; cat "$uci_log"; exit 7; }
EOF_PROBE
    if bash "$probe" "$LIB" "$TMP_ROOT" > "$probe_out" 2>&1; then
        pass "wg_rebuild_uci_conf restores OpenWrt network UCI snapshot when peer write fails"
    else
        fail "wg_rebuild_uci_conf did not restore OpenWrt network UCI snapshot on write failure"
        sed 's/^/    /' "$probe_out" 2>/dev/null || true
    fi
}

test_wg_shared_gateway_routes_syncs_and_cleans_stale_routes() {
    local db="$WG_DB_FILE"
    local routes="$TMP_ROOT/wg-route-sync.log"
    mkdir -p "$(dirname "$db")" "$(dirname "$WG_SHARED_ROUTE_STATE_FILE")"
    cat > "$db" <<'EOF'
{
  "server": {"subnet": "10.66.66.0/24"},
  "peers": [
    {
      "name": "gw1",
      "enabled": true,
      "is_gateway": true,
      "lan_subnets": "192.168.50.0/24, 192.168.60.0/24, 2001:db8:50::/64"
    },
    {
      "name": "gw2",
      "enabled": false,
      "is_gateway": true,
      "lan_subnets": "192.168.70.0/24"
    },
    {
      "name": "plain",
      "enabled": true,
      "is_gateway": false,
      "lan_subnets": "192.168.80.0/24"
    }
  ]
}
EOF
    printf '192.168.60.0/24\n192.168.99.0/24\n2001:db8:99::/64\n' > "$WG_SHARED_ROUTE_STATE_FILE"
    : > "$routes"
    # 自包含：重置 command_exists 为真实语义，避免前置测试泄漏的 mock 污染
    # （wg_shared_sync_gateway_routes 内 `command_exists ip || return 1`）
    command_exists() { command -v "$1" >/dev/null 2>&1; }
    wg_is_running() { return 0; }
    wg_db_get() {
        case "$1" in
            '.peers | length') printf '3\n' ;;
            '.peers[0].enabled') printf 'true\n' ;;
            '.peers[0].is_gateway // false') printf 'true\n' ;;
            '.peers[0].lan_subnets // empty') printf '192.168.50.0/24, 192.168.60.0/24, 2001:db8:50::/64\n' ;;
            '.peers[1].enabled') printf 'false\n' ;;
            '.peers[1].is_gateway // false') printf 'true\n' ;;
            '.peers[1].lan_subnets // empty') printf '192.168.70.0/24\n' ;;
            '.peers[2].enabled') printf 'true\n' ;;
            '.peers[2].is_gateway // false') printf 'false\n' ;;
            '.peers[2].lan_subnets // empty') printf '192.168.80.0/24\n' ;;
            *) printf '\n' ;;
        esac
    }
    ip() {
        if [[ "${1:-}" == "-6" ]]; then
            [[ "${2:-}" == "route" ]] || return 1
        else
            [[ "${1:-}" == "route" ]] || return 1
        fi
        printf '%s\n' "$*" >> "$routes"
        return 0
    }
    wg_write_private_file() { printf '%s\n' "$2" > "$1"; }

    if wg_sync_peer_routes \
       && grep -Fxq 'route del 192.168.99.0/24 dev wg0' "$routes" \
       && grep -Fxq -- '-6 route del 2001:db8:99::/64 dev wg0' "$routes" \
       && grep -Fxq 'route replace 192.168.50.0/24 dev wg0' "$routes" \
       && grep -Fxq 'route replace 192.168.60.0/24 dev wg0' "$routes" \
       && grep -Fxq -- '-6 route replace 2001:db8:50::/64 dev wg0' "$routes" \
       && ! grep -q '192.168.70.0/24' "$routes" \
       && ! grep -q '192.168.80.0/24' "$routes" \
       && grep -Fxq '192.168.50.0/24' "$WG_SHARED_ROUTE_STATE_FILE" \
       && grep -Fxq '192.168.60.0/24' "$WG_SHARED_ROUTE_STATE_FILE" \
       && grep -Fxq '2001:db8:50::/64' "$WG_SHARED_ROUTE_STATE_FILE" \
       && ! grep -q '192.168.99.0/24' "$WG_SHARED_ROUTE_STATE_FILE"; then
        pass "wg_sync_peer_routes syncs current gateway LAN routes and cleans stale managed routes"
    else
        fail "wg_sync_peer_routes did not reconcile managed gateway routes"
        sed 's/^/    routes: /' "$routes"
        sed 's/^/    state: /' "$WG_SHARED_ROUTE_STATE_FILE" 2>/dev/null || true
    fi
    unset -f wg_is_running wg_db_get ip wg_write_private_file
}

test_wg_shared_gateway_routes_removes_state_when_no_gateways() {
    local db="$WG_DB_FILE"
    local routes="$TMP_ROOT/wg-route-empty.log"
    mkdir -p "$(dirname "$db")" "$(dirname "$WG_SHARED_ROUTE_STATE_FILE")"
    cat > "$db" <<'EOF'
{
  "server": {"subnet": "10.66.66.0/24"},
  "peers": [
    {
      "name": "gw1",
      "enabled": false,
      "is_gateway": true,
      "lan_subnets": "192.168.50.0/24, 2001:db8:50::/64"
    }
  ]
}
EOF
    printf '192.168.50.0/24\n2001:db8:50::/64\n' > "$WG_SHARED_ROUTE_STATE_FILE"
    : > "$routes"
    # 自包含：重置 command_exists 为真实语义，避免前置测试泄漏的 mock 污染
    # （wg_shared_sync_gateway_routes 内 `command_exists ip || return 1`）
    command_exists() { command -v "$1" >/dev/null 2>&1; }
    wg_is_running() { return 0; }
    wg_db_get() {
        case "$1" in
            '.peers | length') printf '1\n' ;;
            '.peers[0].enabled') printf 'false\n' ;;
            '.peers[0].is_gateway // false') printf 'true\n' ;;
            '.peers[0].lan_subnets // empty') printf '192.168.50.0/24, 2001:db8:50::/64\n' ;;
            *) printf '\n' ;;
        esac
    }
    ip() {
        if [[ "${1:-}" == "-6" ]]; then
            [[ "${2:-}" == "route" ]] || return 1
        else
            [[ "${1:-}" == "route" ]] || return 1
        fi
        printf '%s\n' "$*" >> "$routes"
        return 0
    }

    if wg_sync_peer_routes \
       && grep -Fxq 'route del 192.168.50.0/24 dev wg0' "$routes" \
       && grep -Fxq -- '-6 route del 2001:db8:50::/64 dev wg0' "$routes" \
       && [[ ! -e "$WG_SHARED_ROUTE_STATE_FILE" ]]; then
        pass "wg_sync_peer_routes removes stale managed state when no gateway LAN remains"
    else
        fail "wg_sync_peer_routes did not clear stale state for empty gateway set"
        sed 's/^/    routes: /' "$routes"
        sed 's/^/    state: /' "$WG_SHARED_ROUTE_STATE_FILE" 2>/dev/null || true
    fi
    unset -f wg_is_running wg_db_get ip
}

test_openwrt_wg_uninstall_fails_on_uci_commit_failure() {
    local log="$TMP_ROOT/openwrt-wg-uninstall-commit.log"
    local db="$WG_DB_FILE"
    local role="$WG_ROLE_FILE"
    local conf="$WG_CONF"
    local real_wg_is_installed real_wg_get_role real_confirm real_ifdown real_ip real_uci
    local real_wg_mihomo_bypass_clean real_cron_remove_job_command real_opkg real_sysctl_disable real_log_action
    real_wg_is_installed="$(declare -f wg_is_installed 2>/dev/null || true)"
    real_wg_get_role="$(declare -f wg_get_role 2>/dev/null || true)"
    real_confirm="$(declare -f confirm 2>/dev/null || true)"
    real_ifdown="$(declare -f ifdown 2>/dev/null || true)"
    real_ip="$(declare -f ip 2>/dev/null || true)"
    real_uci="$(declare -f uci 2>/dev/null || true)"
    real_wg_mihomo_bypass_clean="$(declare -f wg_mihomo_bypass_clean 2>/dev/null || true)"
    real_cron_remove_job_command="$(declare -f cron_remove_job_command 2>/dev/null || true)"
    real_opkg="$(declare -f opkg 2>/dev/null || true)"
    real_sysctl_disable="$(declare -f _sysctl_disable_wireguard_forward 2>/dev/null || true)"
    real_log_action="$(declare -f log_action 2>/dev/null || true)"
    : > "$log"
    mkdir -p "$(dirname "$db")" "$(dirname "$role")" "$(dirname "$conf")"
    printf '{"server":{"port":51820},"peers":[]}\n' > "$db"
    printf 'server\n' > "$role"
    printf 'old wg conf\n' > "$conf"

    wg_is_installed() { return 0; }
    wg_get_role() { printf 'server\n'; }
    confirm() { return 0; }
    ifdown() { printf 'ifdown|%s\n' "$*" >> "$log"; return 0; }
    ip() { return 1; }
    uci() {
        printf 'uci|%s\n' "$*" >> "$log"
        case "$*" in
            "commit network") return 1 ;;
            "commit firewall") return 0 ;;
            "get firewall.@zone["*) return 1 ;;
            "-q get network.@wireguard_wg0[0]"|"-q get network.@wireguard_wg_mesh[0]") return 1 ;;
            *) return 0 ;;
        esac
    }
    wg_mihomo_bypass_clean() { printf 'bypass-clean\n' >> "$log"; return 0; }
    cron_remove_job_command() { printf 'cron-remove|%s\n' "$*" >> "$log"; return 0; }
    opkg() { printf 'opkg|%s\n' "$*" >> "$log"; return 0; }
    _sysctl_disable_wireguard_forward() { printf 'sysctl-disable\n' >> "$log"; return 0; }
    log_action() { printf 'log|%s\n' "$*" >> "$log"; }

    if wg_uninstall >/dev/null 2>&1; then
        fail "wg_uninstall succeeded despite OpenWrt network commit failure"
    elif [[ -f "$db" && -f "$role" && -f "$conf" ]] \
       && grep -q '^uci|commit network$' "$log" \
       && ! grep -q '^bypass-clean$' "$log" \
       && ! grep -q '^cron-remove|' "$log" \
       && ! grep -q '^opkg|' "$log" \
       && ! grep -q '^log|WireGuard uninstalled' "$log"; then
        pass "wg_uninstall stops before local state deletion when OpenWrt network commit fails"
    else
        fail "wg_uninstall did not fail closed on OpenWrt network commit failure"
        sed 's/^/    log: /' "$log"
        ls -l "$db" "$role" "$conf" 2>&1 | sed 's/^/    /'
    fi

    : > "$log"
    printf '{"server":{"port":51820},"peers":[]}\n' > "$db"
    printf 'server\n' > "$role"
    printf 'old wg conf\n' > "$conf"
    uci() {
        printf 'uci|%s\n' "$*" >> "$log"
        case "$*" in
            "commit network") return 0 ;;
            "commit firewall") return 1 ;;
            "get firewall.@zone["*) return 1 ;;
            "-q get network.@wireguard_wg0[0]"|"-q get network.@wireguard_wg_mesh[0]") return 1 ;;
            *) return 0 ;;
        esac
    }

    if wg_uninstall >/dev/null 2>&1; then
        fail "wg_uninstall succeeded despite OpenWrt firewall commit failure"
    elif [[ -f "$db" && -f "$role" && -f "$conf" ]] \
       && grep -q '^uci|commit firewall$' "$log" \
       && ! grep -q '^bypass-clean$' "$log" \
       && ! grep -q '^cron-remove|' "$log" \
       && ! grep -q '^opkg|' "$log" \
       && ! grep -q '^log|WireGuard uninstalled' "$log"; then
        pass "wg_uninstall stops before local state deletion when OpenWrt firewall commit fails"
    else
        fail "wg_uninstall did not fail closed on OpenWrt firewall commit failure"
        sed 's/^/    log: /' "$log"
        ls -l "$db" "$role" "$conf" 2>&1 | sed 's/^/    /'
    fi

    unset -f wg_is_installed wg_get_role confirm ifdown ip uci wg_mihomo_bypass_clean cron_remove_job_command opkg _sysctl_disable_wireguard_forward log_action
    [[ -n "$real_wg_is_installed" ]] && eval "$real_wg_is_installed"
    [[ -n "$real_wg_get_role" ]] && eval "$real_wg_get_role"
    [[ -n "$real_confirm" ]] && eval "$real_confirm"
    [[ -n "$real_ifdown" ]] && eval "$real_ifdown"
    [[ -n "$real_ip" ]] && eval "$real_ip"
    [[ -n "$real_uci" ]] && eval "$real_uci"
    [[ -n "$real_wg_mihomo_bypass_clean" ]] && eval "$real_wg_mihomo_bypass_clean"
    [[ -n "$real_cron_remove_job_command" ]] && eval "$real_cron_remove_job_command"
    [[ -n "$real_opkg" ]] && eval "$real_opkg"
    [[ -n "$real_sysctl_disable" ]] && eval "$real_sysctl_disable"
    [[ -n "$real_log_action" ]] && eval "$real_log_action"
}

test_web_cleanup_domain_rejects_path_traversal() {
    local keep_dir="$TMP_ROOT/keep"
    mkdir -p "$keep_dir" "$CERT_PATH_PREFIX" "$CONFIG_DIR" "$DDNS_CONFIG_DIR"
    printf 'keep\n' > "$keep_dir/marker"

    certbot() { return 1; }
    nginx() { return 1; }
    _nginx_reload() { :; }
    cron_remove_job() { :; }
    ddns_rebuild_cron() { :; }

    if _web_cleanup_domain "../keep" quiet >/dev/null 2>&1; then
        fail "_web_cleanup_domain accepted path traversal domain"
    elif [[ -f "$keep_dir/marker" ]]; then
        pass "_web_cleanup_domain rejects path traversal before deleting files"
    else
        fail "_web_cleanup_domain removed files outside certificate prefix"
    fi
}

test_web_reverse_proxy_backend_update_is_atomic() {
    local dir="$TMP_ROOT/web-proxy"
    local conf="$dir/site.conf" nginx_rc=0 reload_rc=0 mode_before mode_after
    mkdir -p "$dir"
    cat > "$conf" <<'EOF'
server {
    location / {
        proxy_pass http://127.0.0.1:8080/base;
    }
}
EOF
    chmod 640 "$conf" 2>/dev/null || true
    nginx() { return "$nginx_rc"; }
    _nginx_reload() { return "$reload_rc"; }

    mode_before=$(stat -c '%a' "$conf" 2>/dev/null || stat -f '%Lp' "$conf" 2>/dev/null || echo "")
    if _web_update_reverse_proxy_backend "$conf" 'http://127.0.0.1:9090/a&b|c' \
       && grep -Fq 'proxy_pass http://127.0.0.1:9090/a&b|c;' "$conf" \
       && ! grep -Fq 'proxy_pass http://127.0.0.1:8080/base;' "$conf" \
       && { mode_after=$(stat -c '%a' "$conf" 2>/dev/null || stat -f '%Lp' "$conf" 2>/dev/null || echo ""); [[ -z "$mode_before" || "$mode_before" == "$mode_after" ]]; } \
       && ! find "$dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
        pass "_web_update_reverse_proxy_backend atomically updates backend and preserves file mode"
    else
        fail "_web_update_reverse_proxy_backend success path content/mode/temp mismatch"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf"
    fi

    cat > "$conf" <<'EOF'
server {
    location / {
        proxy_pass http://127.0.0.1:8080/base;
    }
}
EOF
    chmod 640 "$conf" 2>/dev/null || true
    nginx_rc=1
    reload_rc=0
    if ! _web_update_reverse_proxy_backend "$conf" 'http://127.0.0.1:9091' >/dev/null 2>&1 \
       && grep -Fq 'proxy_pass http://127.0.0.1:8080/base;' "$conf" \
       && ! grep -Fq 'proxy_pass http://127.0.0.1:9091;' "$conf" \
       && ! find "$dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
        pass "_web_update_reverse_proxy_backend rolls back when nginx -t fails"
    else
        fail "_web_update_reverse_proxy_backend failed to roll back nginx -t failure"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf"
    fi

    nginx_rc=0
    reload_rc=1
    if ! _web_update_reverse_proxy_backend "$conf" 'http://127.0.0.1:9092' >/dev/null 2>&1 \
       && grep -Fq 'proxy_pass http://127.0.0.1:8080/base;' "$conf" \
       && ! grep -Fq 'proxy_pass http://127.0.0.1:9092;' "$conf" \
       && ! find "$dir" -maxdepth 1 \( -name '.site.conf.tmp.*' -o -name '.site.conf.bak.*' -o -name 'site.conf.bak' \) -print -quit | grep -q .; then
        pass "_web_update_reverse_proxy_backend rolls back when nginx reload fails"
    else
        fail "_web_update_reverse_proxy_backend failed to roll back reload failure"
        ls -la "$dir" | sed 's/^/    /'
        sed 's/^/    /' "$conf"
    fi
    unset -f nginx _nginx_reload
}

test_nginx_official_source_and_stream_conf_are_atomic() {
    local keyring="$TMP_ROOT/nginx/keyrings/nginx.gpg"
    local source_file="$TMP_ROOT/nginx/sources/nginx.list"
    local pin_file="$TMP_ROOT/nginx/preferences/99nginx"
    local stream_conf="$TMP_ROOT/nginx/modules-enabled/50-mod-stream.conf"
    local module_so="$TMP_ROOT/nginx/modules/ngx_stream_module.so"
    local NGINX_KEYRING_FILE="$keyring"
    local NGINX_SOURCE_LIST_FILE="$source_file"
    local NGINX_APT_PIN_FILE="$pin_file"
    local NGINX_STREAM_MODULE_CONF="$stream_conf"
    mkdir -p "$(dirname "$module_so")"
    : > "$module_so"

    if _nginx_write_official_apt_files debian bookworm \
       && grep -Fxq "deb [signed-by=$keyring] http://nginx.org/packages/debian bookworm nginx" "$source_file" \
       && grep -Fxq 'Pin: origin nginx.org' "$pin_file" \
       && grep -Fxq 'Pin-Priority: 900' "$pin_file" \
       && { [[ "$(uname -s 2>/dev/null)" != "Linux" ]] || [[ "$(stat -c '%a' "$source_file" 2>/dev/null || echo "")" == "644" ]]; } \
       && { [[ "$(uname -s 2>/dev/null)" != "Linux" ]] || [[ "$(stat -c '%a' "$pin_file" 2>/dev/null || echo "")" == "644" ]]; }; then
        pass "_nginx_write_official_apt_files writes source/pin atomically"
    else
        fail "_nginx_write_official_apt_files did not write expected apt files"
        sed 's/^/    source: /' "$source_file" 2>/dev/null || true
        sed 's/^/    pin: /' "$pin_file" 2>/dev/null || true
    fi

    if _nginx_write_stream_module_conf "$module_so" \
       && grep -Fxq "load_module $module_so;" "$stream_conf" \
       && { [[ "$(uname -s 2>/dev/null)" != "Linux" ]] || [[ "$(stat -c '%a' "$stream_conf" 2>/dev/null || echo "")" == "644" ]]; }; then
        pass "_nginx_write_stream_module_conf writes stream load_module atomically"
    else
        fail "_nginx_write_stream_module_conf did not write expected stream module config"
        sed 's/^/    /' "$stream_conf" 2>/dev/null || true
    fi

    if _nginx_write_official_apt_files 'bad;distro' bookworm >/dev/null 2>&1; then
        fail "_nginx_write_official_apt_files accepted invalid distro"
    else
        pass "_nginx_write_official_apt_files rejects invalid distro"
    fi
    if _nginx_write_stream_module_conf "../relative.so" >/dev/null 2>&1; then
        fail "_nginx_write_stream_module_conf accepted unsafe module path"
    else
        pass "_nginx_write_stream_module_conf rejects unsafe module path"
    fi
}

test_nginx_deploy_conf_rolls_back_on_symlink_failure() {
    local avail_dir="$TMP_ROOT/nginx-sites/available"
    local enabled_dir="$TMP_ROOT/nginx-sites/enabled"
    local domain="rollback.invalid"
    local avail="$avail_dir/${domain}.conf"
    local enabled="$enabled_dir/${domain}.conf"
    local old_enabled="$enabled_dir/${domain}.old"
    mkdir -p "$avail_dir" "$enabled_dir"
    printf 'old available\n' > "$avail"
    printf 'old enabled file\n' > "$old_enabled"
    ln -s "$old_enabled" "$enabled" 2>/dev/null || {
        pass "_nginx_deploy_conf symlink rollback skipped on filesystem without symlink support"
        return
    }
    if [[ ! -L "$enabled" ]]; then
        pass "_nginx_deploy_conf symlink rollback skipped on filesystem without real symlink support"
        return
    fi

    nginx() { return 0; }
    _nginx_reload() { return 0; }
    ln() {
        if [[ "${1:-}" == "-sfn" && "${2:-}" == "$avail" && "${3:-}" == "$enabled" ]]; then
            return 91
        fi
        command ln "$@"
    }

    local deploy_rc=0
    NGINX_SITES_AVAILABLE_DIR="$avail_dir" NGINX_SITES_ENABLED_DIR="$enabled_dir" \
        _nginx_deploy_conf "$domain" "new available" >/dev/null 2>&1 || deploy_rc=$?
    if [[ "$deploy_rc" -ne 0 ]] \
       && grep -Fxq 'old available' "$avail" \
       && [[ -L "$enabled" ]] \
       && [[ "$(readlink "$enabled" 2>/dev/null)" == "$old_enabled" ]] \
       && ! grep -Fxq 'new available' "$avail" \
       && ! find "$avail_dir" "$enabled_dir" -maxdepth 1 -name ".${domain}.conf.bak.*" -print -quit | grep -q .; then
        pass "_nginx_deploy_conf restores old site when enabling symlink fails"
    else
        fail "_nginx_deploy_conf left half-written site after symlink failure"
        ls -la "$avail_dir" "$enabled_dir" | sed 's/^/    /'
        sed 's/^/    avail: /' "$avail" 2>/dev/null || true
        readlink "$enabled" 2>/dev/null | sed 's/^/    enabled -> /' || true
    fi
    unset -f nginx _nginx_reload ln
}

test_wg_clash_output_uses_private_random_dir() {
    local tmpout="$TMP_ROOT/clash-output"
    local out="$TMP_ROOT/clash-generate.out"
    mkdir -p "$tmpout"

    wg_check_server() { return 0; }
    wg_get_server_name() { printf 'server-a\n'; }
    wg_db_get() {
        case "$1" in
            '.peers | length') printf '1\n' ;;
            '.peers[0].name') printf 'peer name with spaces\n' ;;
            '.peers[0].ip') printf '10.66.66.2\n' ;;
            '.peers[0].is_gateway // false') printf 'false\n' ;;
            '.peers[0].private_key') printf 'peer-private-key\n' ;;
            '.peers[0].preshared_key') printf 'peer-psk\n' ;;
            '.server.public_key') printf 'server-public-key\n' ;;
            '.server.endpoint') printf '198.51.100.8\n' ;;
            '.server.port') printf '51820\n' ;;
            '.server.subnet') printf '10.66.66.0/24\n' ;;
            '.server.dns') printf '1.1.1.1\n' ;;
            '.server.server_lan_subnet // empty') printf '\n' ;;
            '.peers[0].lan_subnets // empty') printf '\n' ;;
            *) printf '\n' ;;
        esac
    }

    if ! printf '1\n2\nproxy-providers:\n  sub:\n    url: "https://subscribe.example.net/path.yaml"\ndns:\n  enable: true\nproxies:\n  - name: existing\n    type: direct\nrules:\n  - MATCH,DIRECT\n' \
        | TMPDIR="$tmpout" _wg_generate_clash_config_impl openwrt > "$out" 2>&1; then
        fail "_wg_generate_clash_config_impl failed in mock output test"
        sed 's/^/    /' "$out"
        return
    fi

    local generated
    generated=$(find "$tmpout" -type f -name 'clash-config.yaml' -print | head -1)
    if [[ -z "$generated" ]]; then
        fail "_wg_generate_clash_config_impl did not create clash-config.yaml"
        find "$tmpout" -maxdepth 2 -ls | sed 's/^/    /'
        return
    fi

    local dir mode file_mode
    dir=$(dirname "$generated")
    mode=$(stat -c '%a' "$dir" 2>/dev/null || stat -f '%Lp' "$dir" 2>/dev/null || echo "")
    file_mode=$(stat -c '%a' "$generated" 2>/dev/null || stat -f '%Lp' "$generated" 2>/dev/null || echo "")
    local perms_ok=0
    if [[ "$(uname -s 2>/dev/null)" == "Linux" ]]; then
        [[ "$mode" == "700" && "$file_mode" == "600" ]] && perms_ok=1
    else
        # Git Bash on Windows reports NTFS-derived modes; Linux CI/real host enforces the strict bits.
        [[ -n "$mode" && -n "$file_mode" ]] && perms_ok=1
    fi
    if [[ "$generated" == "$tmpout"/clash-wg.*/clash-config.yaml \
       && "$generated" != *"peer name with spaces"* \
       && "$perms_ok" -eq 1 ]] \
       && grep -qF 'peer-private-key' "$generated" \
       && grep -qF 'allowed-ips:' "$generated" \
       && grep -qF 'WireGuard VPN 路由规则' "$generated" \
       && grep -qF 'nameserver-policy:' "$generated" \
       && grep -qF '+.example.net' "$generated" \
       && ! find "$dir" -maxdepth 1 -name '.clash-config.yaml.policy.*' -print -quit | grep -q .; then
        pass "_wg_generate_clash_config_impl writes sensitive YAML in a private random directory"
    else
        fail "_wg_generate_clash_config_impl output path/permissions/content mismatch path=$generated dir_mode=$mode file_mode=$file_mode"
        sed 's/^/    /' "$generated" 2>/dev/null || true
    fi
}

test_wg_clash_rules_handle_ipv6_literals() {
    local ep4 ep6 domain cidr4 cidr6
    ep4=$(_wg_clash_endpoint_direct_rule "198.51.100.8")
    ep6=$(_wg_clash_endpoint_direct_rule "[2001:db8::8]")
    domain=$(_wg_clash_endpoint_direct_rule "vpn.example.com")
    cidr4=$(_wg_clash_cidr_rule "10.66.66.0/24" "WireGuard-VPN")
    cidr6=$(_wg_clash_cidr_rule "fd00:66::/64" "WireGuard-VPN")

    if [[ "$ep4" == "  - IP-CIDR,198.51.100.8/32,DIRECT" ]] \
       && [[ "$ep6" == "  - IP-CIDR6,2001:db8::8/128,DIRECT" ]] \
       && [[ "$domain" == "  - DOMAIN,vpn.example.com,DIRECT" ]] \
       && [[ "$cidr4" == "  - IP-CIDR,10.66.66.0/24,WireGuard-VPN" ]] \
       && [[ "$cidr6" == "  - IP-CIDR6,fd00:66::/64,WireGuard-VPN" ]]; then
        pass "WireGuard Clash rules distinguish IPv4 IPv6 and domain endpoints"
    else
        fail "WireGuard Clash rules mishandle IPv6/domain endpoint routing"
        printf '    ep4=%s\n    ep6=%s\n    domain=%s\n    cidr4=%s\n    cidr6=%s\n' "$ep4" "$ep6" "$domain" "$cidr4" "$cidr6"
    fi
}

test_openwrt_wg_deploy_generated_script_is_posix_sh() {
    local endpoint="$1" label="$2" expected_host="$3" expect_watchdog="$4" expect_ip6="${5:-0}"
    local out="$TMP_ROOT/openwrt-deploy-${label}.out"
    local script="$TMP_ROOT/openwrt-deploy-${label}.sh"
    wg_db_get() {
        case "$1" in
            ".peers[0].private_key") printf 'peer-private-key\n' ;;
            ".peers[0].ip") printf '10.66.66.2\n' ;;
            ".peers[0].preshared_key") printf 'peer-psk\n' ;;
            ".peers[0].client_allowed_ips") printf '10.66.66.0/24, 192.168.77.0/24\n' ;;
            ".server.public_key") printf 'server-public-key\n' ;;
            ".server.endpoint") printf '%s\n' "$endpoint" ;;
            ".server.port") printf '51820\n' ;;
            ".server.subnet") printf '10.66.66.0/24\n' ;;
            ".server.ip") printf '10.66.66.1\n' ;;
            *) printf '\n' ;;
        esac
    }

    _wg_show_openwrt_deploy 0 > "$out"
    awk '/^# === 清理旧配置 ===/{cap=1} /复制以上全部命令/{cap=0} cap{print}' "$out" > "$script"

    if ! /bin/sh -n "$script"; then
        fail "Generated OpenWrt WG deploy script for $label is not POSIX sh"
        sed -n '1,180p' "$script" | sed 's/^/    /'
        return
    fi
    if grep -q "endpoint_host='${expected_host}'" "$script" \
       && [[ "$expect_watchdog" != "1" || $(grep -c 'WG_WATCHDOG_TMP="$(mktemp /usr/bin/.wg-watchdog.XXXXXX' "$script") -eq 1 ]] \
       && [[ "$expect_watchdog" != "1" || $(grep -c 'mv "$WG_WATCHDOG_TMP" /usr/bin/wg-watchdog.sh' "$script") -eq 1 ]] \
       && [[ "$expect_watchdog" != "1" || $(grep -c 'LOG_DIR="/var/run/server-manage"' "$script") -eq 1 ]] \
       && [[ "$expect_watchdog" != "1" || $(grep -F -c 'mktemp "$LOG_DIR/.wg-watchdog-log.XXXXXX"' "$script") -eq 1 ]] \
       && [[ "$expect_watchdog" != "1" || $(grep -c 'LOG_FILE="/tmp/wg-watchdog.log"' "$script") -eq 0 ]] \
       && [[ "$expect_watchdog" != "1" || $(grep -F -c '${LOG_FILE}.tmp' "$script") -eq 0 ]] \
       && [[ "$expect_watchdog" == "1" || $(grep -c 'WG_WATCHDOG_TMP=' "$script") -eq 0 ]] \
	       && grep -qF 'awk '\''$6 != "/usr/bin/wg-watchdog.sh"'\''' "$script" \
	       && ! grep -qF 'awk '\''\$6 != "/usr/bin/wg-watchdog.sh"'\''' "$script" \
	       && ! grep -q 'ip rule.*prio 100/d' "$script" \
	       && grep -q '^wg_rc_local_cleanup_managed()' "$script" \
	       && grep -q 'BEGIN server-manage wireguard bypass' "$script" \
		       && grep -q 'WG_RC_BLOCK="$(mktemp /etc/.wg-rc-block.XXXXXX' "$script" \
		       && grep -q 'WG_RC_TMP="$(mktemp /etc/.rc.local.XXXXXX' "$script" \
		       && grep -q 'mv "$WG_RC_TMP" /etc/rc.local' "$script" \
		       && grep -q 'WG_CLIENT_TMP="$(mktemp /etc/init.d/.wg-client.XXXXXX' "$script" \
		       && grep -q 'mv "$WG_CLIENT_TMP" /etc/init.d/wg-client' "$script" \
		       && grep -q 'WG_UCI_SNAPSHOT_DIR="$(mktemp -d /tmp/server-manage-wg-deploy-uci.XXXXXX' "$script" \
		       && grep -q 'uci export network > "$WG_UCI_SNAPSHOT_DIR/network.uci"' "$script" \
		       && grep -q 'uci export firewall > "$WG_UCI_SNAPSHOT_DIR/firewall.uci"' "$script" \
		       && grep -q 'uci import network < "$WG_UCI_SNAPSHOT_DIR/network.uci"' "$script" \
		       && grep -q 'uci import firewall < "$WG_UCI_SNAPSHOT_DIR/firewall.uci"' "$script" \
		       && awk '/WG_UCI_SNAPSHOT_DIR="\$\(mktemp -d \/tmp\/server-manage-wg-deploy-uci\.XXXXXX/ { snap=NR } /while uci -q get network\.@wireguard_wg0\[0\]/ { clean=NR } END { exit !(snap > 0 && clean > 0 && snap < clean) }' "$script" \
		       && grep -q '^write_wg_uci()' "$script" \
		       && grep -q '^[[:space:]]*restore_wg_uci()' "$script" \
		       && ! grep -q 'set -e' "$script" \
			       && grep -Fq 'die() { echo "[!] $*" >&2; exit 1; }' "$script" \
		       && grep -q '|| die_restore "写入 WireGuard UCI 配置失败"' "$script" \
		       && grep -Fq 'die_restore "安装 wg-client init 失败"' "$script" \
		       && grep -q 'ifup wg0 || die_restore "启动 wg0 失败"' "$script" \
	       && grep -q '^wg_resolve_real()' "$script" \
	       && grep -Fq 'EP_IP=$(wg_resolve_real' "$script" \
	       && grep -Fq 'WG_EP=$(wg_resolve_real' "$script" \
	       && ! grep -Fq "awk '/^Address:/{a=" "$script" \
		       && [[ "$expect_watchdog" != "1" || $(grep -c 'die_restore "安装 wg-watchdog 失败"' "$script") -eq 1 ]] \
		       && [[ "$expect_watchdog" != "1" || $(grep -c '|| die_restore "安装 wg-watchdog cron 失败"' "$script") -eq 1 ]] \
	       && ! grep -Eq '\|\| echo [^[:space:]]*\$\$' "$script" \
		       && [[ "$expect_ip6" != "1" || $(grep -c 'NFT_FAMILY="ip6"' "$script") -gt 0 && $(grep -c 'WG_NFT_FAMILY=ip6' "$script") -gt 0 && $(grep -c 'ip -6 rule add' "$script") -gt 0 ]]; then
        pass "Generated OpenWrt WG deploy script is POSIX sh for $label endpoint"
    else
        fail "Generated OpenWrt WG deploy script failed endpoint checks for $label"
        sed -n '1,180p' "$script" | sed 's/^/    /'
    fi
}

test_openwrt_wg_clean_generated_script_is_posix_sh() {
    local out="$TMP_ROOT/openwrt-clean.out"
    local script="$TMP_ROOT/openwrt-clean.sh"

    wg_openwrt_clean_cmd > "$out"
    awk '/^# === 停止所有 WireGuard 接口 ===/{cap=1} /执行后可在 LuCI/{cap=0} cap{print}' "$out" > "$script"

    if ! /bin/sh -n "$script"; then
        fail "Generated OpenWrt WG clean script is not POSIX sh"
        sed -n '1,180p' "$script" | sed 's/^/    /'
        return
    fi
    if grep -qF 'awk '\''$6 != "/usr/bin/wg-watchdog.sh"'\''' "$script" \
       && ! grep -qF 'awk '\''\$6 != "/usr/bin/wg-watchdog.sh"'\''' "$script" \
       && grep -q 'WG_RC_TMP="$(mktemp /etc/.rc.local.clean.XXXXXX' "$script" \
       && grep -q '^die()' "$script" \
       && grep -q 'uci commit network || die "提交 network 清理失败"' "$script" \
       && grep -q 'uci commit firewall || die "提交 firewall 清理失败"' "$script" \
       && ! grep -Eq '\|\| echo [^[:space:]]*\$\$' "$script"; then
        pass "Generated OpenWrt WG clean script has valid watchdog cron awk"
    else
        fail "Generated OpenWrt WG clean script has invalid watchdog cron awk quoting"
        grep -n 'wg-watchdog.sh' "$script" | sed 's/^/    /'
    fi
}

test_ssh_change_port_inserts_global_port_before_match() {
    local conf="$TMP_ROOT/sshd-port-match.conf"
    cat > "$conf" <<'EOF'
# no global Port here
Match User alice
    AllowTcpForwarding no
EOF

    SSHD_CONFIG="$conf"
    FAIL2BAN_JAIL_LOCAL="$TMP_ROOT/no-fail2ban-jail"
    CURRENT_SSH_PORT=22
    CURRENT_SSH_PORTS=22
    refresh_ssh_port() { CURRENT_SSH_PORT=22; CURRENT_SSH_PORTS=22; }
    _ssh_socket_activation_active() { return 1; }
    command_exists() { [[ "${1:-}" != "ss" ]]; }
    ufw_is_active() { return 1; }
    firewall_prepare_non_ufw_ssh_port() { FIREWALL_SSH_OPEN_BACKENDS="mock"; return 0; }
    firewall_rollback_ssh_port() { return 0; }
    _restart_sshd() { return 0; }
    _ssh_port_is_listening() { [[ "${1:-}" == "65022" ]]; }
    sshd() {
        case "${1:-}" in
            -t) return 0 ;;
            -T) printf 'port 65022\n'; return 0 ;;
            *) return 1 ;;
        esac
    }
    sleep() { :; }

    if printf '65022\n2\n' | ssh_change_port >/dev/null 2>&1 \
       && awk 'BEGIN{ok=0} /^Port 65022$/{port=NR} /^Match /{matchline=NR} END{exit !(port && matchline && port < matchline)}' "$conf" \
       && ! awk 'seen_match && /^Port /{bad=1} /^Match /{seen_match=1} END{exit bad ? 0 : 1}' "$conf"; then
        pass "ssh_change_port inserts Port before Match blocks instead of appending inside Match scope"
    else
        fail "ssh_change_port did not keep Port in global sshd_config scope"
        sed 's/^/    /' "$conf"
    fi
}

test_ssh_change_port_rolls_back_socket_dropin_when_firewall_fails() {
    local conf="$TMP_ROOT/sshd-socket-firewall.conf"
    local socket_dir="$TMP_ROOT/systemd/ssh.socket.d"
    local test_socket_dropin="$socket_dir/server-manage-port.conf"
    local systemctl_log="$TMP_ROOT/ssh-socket-systemctl.log"
    mkdir -p "$socket_dir"
    cat > "$conf" <<'EOF'
Port 22
AuthorizedKeysFile .ssh/authorized_keys
EOF

    SSHD_CONFIG="$conf"
    FAIL2BAN_JAIL_LOCAL="$TMP_ROOT/no-fail2ban-jail"
    CURRENT_SSH_PORT=22
    CURRENT_SSH_PORTS=22
    refresh_ssh_port() { CURRENT_SSH_PORT=22; CURRENT_SSH_PORTS=22; }
    _ssh_socket_activation_active() { return 0; }
    _ssh_socket_unit() { printf 'ssh.socket\n'; }
    _ssh_socket_dropin_path() { printf '%s' "$test_socket_dropin"; }
    command_exists() { [[ "${1:-}" != "ss" ]]; }
    ufw_is_active() { return 1; }
    firewall_prepare_non_ufw_ssh_port() { FIREWALL_SSH_OPEN_BACKENDS=""; return 1; }
    systemctl() { printf '%s\n' "$*" >> "$systemctl_log"; return 0; }

    : > "$systemctl_log"
    if printf '65023\n2\n' | ssh_change_port >/dev/null 2>&1; then
        fail "ssh_change_port succeeded despite firewall failure after socket drop-in write"
        return
    fi
    if grep -q '^Port 22$' "$conf" \
       && ! grep -q '^Port 65023$' "$conf" \
       && [[ ! -e "$test_socket_dropin" ]] \
       && ! find "$(dirname "$conf")" -maxdepth 1 -name 'sshd-socket-firewall.conf.bak.*' -print -quit | grep -q . \
       && [[ "$(grep -c '^daemon-reload$' "$systemctl_log" 2>/dev/null || echo 0)" -ge 2 ]]; then
        pass "ssh_change_port removes newly-created socket drop-in when firewall precheck fails"
    else
        fail "ssh_change_port left new socket drop-in or config residue after firewall failure"
        sed 's/^/    conf: /' "$conf"
        ls -la "$socket_dir" | sed 's/^/    socket-dir: /'
        sed 's/^/    systemctl: /' "$systemctl_log"
    fi

    printf '[Socket]\nListenStream=0.0.0.0:22\n' > "$test_socket_dropin"
    : > "$systemctl_log"
    if printf '65024\n2\n' | ssh_change_port >/dev/null 2>&1; then
        fail "ssh_change_port succeeded despite firewall failure with existing socket drop-in"
        return
    fi
    if grep -Fxq 'ListenStream=0.0.0.0:22' "$test_socket_dropin" \
       && ! grep -q '65024' "$test_socket_dropin" \
       && ! find "$socket_dir" -maxdepth 1 -name 'server-manage-port.conf.bak.*' -print -quit | grep -q . \
       && grep -q '^Port 22$' "$conf" \
       && ! grep -q '^Port 65024$' "$conf"; then
        pass "ssh_change_port restores existing socket drop-in when firewall precheck fails"
    else
        fail "ssh_change_port did not restore existing socket drop-in after firewall failure"
        sed 's/^/    conf: /' "$conf"
        sed 's/^/    socket: /' "$test_socket_dropin" 2>/dev/null || true
        ls -la "$socket_dir" | sed 's/^/    socket-dir: /'
    fi
}

test_opt_sysctl_validates_before_commit() {
    local mock_sysctl_conf="$TMP_ROOT/sysctl.conf"
    local sysctl_log="$TMP_ROOT/sysctl-calls.txt"
    local tuning_conf="$TMP_ROOT/sysctl.d/99zz-server-manage-tuning.conf"
    local profile_file="$TMP_ROOT/sysctl.d/99zz-server-manage-tuning.profile.md"
    local rollback_file="$TMP_ROOT/server-manage-sysctl.rollback.conf"
    local latest_file="$TMP_ROOT/server-manage-sysctl.latest-snapshot"
    local params params_second first_rollback first_latest
    cat > "$mock_sysctl_conf" <<'EOF'
# keep this line
net.ipv4.tcp_syncookies = 1
EOF
    _sysctl_conf_path() { printf '%s' "$mock_sysctl_conf"; }
    params="$(_sysctl_build_role_params conservative 1)"
    declare -A SYSCTL_VALUES=(
        ["fs.file-max"]="100000"
        ["net.core.somaxconn"]="128"
        ["net.ipv4.tcp_max_syn_backlog"]="128"
        ["net.ipv4.tcp_tw_reuse"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_fin_timeout"]="60"
        ["net.ipv4.tcp_available_congestion_control"]="reno cubic"
    )
    sysctl() {
        if [[ "${1:-}" == "-n" ]]; then
            if [[ "${SYSCTL_BAD_AFTER_SYSTEM:-0}" == "1" \
               && "${SYSCTL_AFTER_SYSTEM:-0}" == "1" \
               && "${2:-}" == "fs.file-max" ]]; then
                printf '999999\n'
                return 0
            fi
            printf '%s\n' "${SYSCTL_VALUES[${2:-}]:-0}"
            return 0
        fi
        if [[ "${1:-}" == "-p" ]]; then
            printf '%s\n' "${2:-}" >> "$sysctl_log"
            [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]] || return 1
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
                SYSCTL_VALUES["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            done < "${2:-/dev/null}"
            return 0
        fi
        if [[ "${1:-}" == "--system" ]]; then
            printf '%s\n' "--system" >> "$sysctl_log"
            SYSCTL_AFTER_SYSTEM=1
            [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]]
            return
        fi
        return 0
    }

    SYSCTL_APPLY_OK=0
    _sysctl_commit_tuning "$params" "conservative" "100M/small-memory" "test failure" >/dev/null 2>&1
    if grep -qF '# keep this line' "$mock_sysctl_conf" \
       && grep -q '^net.ipv4.tcp_syncookies = 1$' "$mock_sysctl_conf" \
       && [[ ! -f "$tuning_conf" ]] \
       && [[ ! -f "$rollback_file" ]]; then
        pass "opt_sysctl does not commit failed sysctl -p candidate"
    else
        fail "opt_sysctl modified persistent config despite failed validation"
        sed 's/^/    /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
    fi

    SYSCTL_APPLY_OK=1
    _sysctl_commit_tuning "$params" "conservative" "100M/small-memory" "test success" >/dev/null 2>&1
    local block_count
    block_count=$(grep -c '^# BEGIN server-manage sysctl tuning' "$tuning_conf" 2>/dev/null || echo 0)
    if [[ "$block_count" == "1" ]] \
       && grep -qF '# keep this line' "$mock_sysctl_conf" \
       && grep -q '^# server-manage moved to sysctl.d: net.ipv4.tcp_syncookies = 1$' "$mock_sysctl_conf" \
       && grep -q '^fs.file-max = 262144$' "$tuning_conf" \
       && [[ -f "$rollback_file" ]] \
       && [[ -f "$latest_file" ]] \
       && [[ -f "$profile_file" ]] \
       && find "$TMP_ROOT/sysctl-backups" -mindepth 1 -maxdepth 1 -type d -print -quit | grep -q .; then
        pass "opt_sysctl commits validated sysctl.d candidate with rollback/profile/backup"
    else
        fail "opt_sysctl successful commit/backup mismatch"
        sed 's/^/    conf: /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
        [[ -f "$rollback_file" ]] && sed 's/^/    rollback: /' "$rollback_file"
        [[ -f "$profile_file" ]] && sed 's/^/    profile: /' "$profile_file"
    fi

    first_rollback=$(cat "$rollback_file" 2>/dev/null || true)
    first_latest=$(cat "$latest_file" 2>/dev/null || true)
    params_second="$(_sysctl_build_role_params landing 1)"
    SYSCTL_BAD_AFTER_SYSTEM=1 SYSCTL_AFTER_SYSTEM=0
    if _sysctl_commit_tuning "$params_second" "landing" "100M/small-memory" "test failed second apply" >/dev/null 2>&1; then
        fail "opt_sysctl second commit unexpectedly succeeded despite bad readback"
    elif grep -q '^fs.file-max = 262144$' "$tuning_conf" \
       && ! grep -q '^fs.file-max = 1048576$' "$tuning_conf" \
       && [[ "$(cat "$rollback_file" 2>/dev/null || true)" == "$first_rollback" ]] \
       && [[ "$(cat "$latest_file" 2>/dev/null || true)" == "$first_latest" ]]; then
        pass "opt_sysctl failed second commit preserves previous rollback metadata"
    else
        fail "opt_sysctl failed second commit left rollback metadata inconsistent"
        sed 's/^/    tuning: /' "$tuning_conf" 2>/dev/null || true
        sed 's/^/    rollback: /' "$rollback_file" 2>/dev/null || true
        sed 's/^/    latest: /' "$latest_file" 2>/dev/null || true
    fi
    SYSCTL_BAD_AFTER_SYSTEM=0 SYSCTL_AFTER_SYSTEM=0

    _sysctl_rollback_tuning >/dev/null 2>&1
    if grep -qF '# keep this line' "$mock_sysctl_conf" \
       && grep -q '^net.ipv4.tcp_syncookies = 1$' "$mock_sysctl_conf" \
       && ! grep -q '^# server-manage moved to sysctl.d:' "$mock_sysctl_conf" \
       && [[ ! -f "$tuning_conf" ]] \
       && [[ ! -f "$latest_file" ]] \
       && [[ "${SYSCTL_VALUES[fs.file-max]:-}" == "100000" ]]; then
        pass "opt_sysctl rollback restores persistent snapshot"
    else
        fail "opt_sysctl rollback did not restore persistent snapshot"
        sed 's/^/    conf: /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
        [[ -f "$latest_file" ]] && sed 's/^/    latest: /' "$latest_file"
    fi
    unset SYSCTL_VALUES
}

test_opt_sysctl_latest_pointer_failure_rolls_back() {
    local workdir="$TMP_ROOT/latest-failure"
    local mock_sysctl_conf="$workdir/sysctl.conf"
    local tuning_conf="$workdir/sysctl.d/99zz-server-manage-tuning.conf"
    local rollback_file="$workdir/server-manage-sysctl.rollback.conf"
    local latest_file="$workdir/server-manage-sysctl.latest-snapshot"
    local params rc
    mkdir -p "$workdir"
    cat > "$mock_sysctl_conf" <<'EOF'
# latest failure base
net.ipv4.tcp_syncookies = 1
EOF
    _sysctl_conf_path() { printf '%s' "$mock_sysctl_conf"; }
    params="$(_sysctl_build_role_params conservative 1)"
    declare -A SYSCTL_VALUES=(
        ["fs.file-max"]="100000"
        ["net.core.somaxconn"]="128"
        ["net.ipv4.tcp_max_syn_backlog"]="128"
        ["net.ipv4.tcp_tw_reuse"]="0"
        ["net.ipv4.tcp_syncookies"]="1"
        ["net.ipv4.tcp_fin_timeout"]="60"
        ["net.ipv4.tcp_available_congestion_control"]="reno cubic"
    )
    sysctl() {
        if [[ "${1:-}" == "-n" ]]; then
            printf '%s\n' "${SYSCTL_VALUES[${2:-}]:-0}"
            return 0
        fi
        if [[ "${1:-}" == "-p" ]]; then
            [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]] || return 1
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
                SYSCTL_VALUES["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            done < "${2:-/dev/null}"
            return 0
        fi
        if [[ "${1:-}" == "--system" ]]; then
            return 0
        fi
        return 0
    }
    mv() {
        if [[ "${2:-}" == "$latest_file" ]]; then
            return 1
        fi
        command mv "$@"
    }

    SYSCTL_APPLY_OK=1
    _sysctl_commit_tuning "$params" "conservative" "100M/small-memory" "latest pointer failure" >/dev/null 2>&1
    rc=$?
    unset -f mv
    if [[ "$rc" -ne 0 ]] \
       && grep -q '^net.ipv4.tcp_syncookies = 1$' "$mock_sysctl_conf" \
       && ! grep -q '^# server-manage moved to sysctl.d:' "$mock_sysctl_conf" \
       && [[ ! -f "$tuning_conf" ]] \
       && [[ ! -f "$rollback_file" ]] \
       && [[ ! -f "$latest_file" ]] \
       && [[ "${SYSCTL_VALUES[fs.file-max]:-}" == "100000" ]]; then
        pass "opt_sysctl latest snapshot write failure rolls back persistent/runtime state"
    else
        fail "opt_sysctl latest snapshot write failure left committed residue"
        sed 's/^/    conf: /' "$mock_sysctl_conf" 2>/dev/null || true
        sed 's/^/    tuning: /' "$tuning_conf" 2>/dev/null || true
        sed 's/^/    rollback: /' "$rollback_file" 2>/dev/null || true
        sed 's/^/    latest: /' "$latest_file" 2>/dev/null || true
    fi
    unset SYSCTL_VALUES
}

test_opt_bbr_validates_before_commit() {
    local mock_sysctl_conf="$TMP_ROOT/bbr-sysctl.conf"
    local sysctl_log="$TMP_ROOT/bbr-sysctl-calls.txt"
    local tuning_conf="$TMP_ROOT/sysctl.d/99zz-server-manage-tuning.conf"
    local profile_file="$TMP_ROOT/sysctl.d/99zz-server-manage-tuning.profile.md"
    local latest_file="$TMP_ROOT/server-manage-sysctl.latest-snapshot"
    cat > "$mock_sysctl_conf" <<'EOF'
# keep bbr base
net.core.default_qdisc = pfifo_fast
net.ipv4.tcp_congestion_control = cubic
EOF
    _sysctl_conf_path() { printf '%s' "$mock_sysctl_conf"; }
    SYSCTL_CURRENT_QDISC=pfifo_fast
    sysctl() {
        if [[ "${1:-}" == "-n" ]]; then
            case "${2:-}" in
                net.ipv4.tcp_congestion_control)
                    printf '%s\n' "${SYSCTL_CURRENT_CC:-cubic}"
                    ;;
                net.core.default_qdisc)
                    printf '%s\n' "${SYSCTL_CURRENT_QDISC:-pfifo_fast}"
                    ;;
                net.ipv4.tcp_available_congestion_control)
                    printf 'reno cubic bbr\n'
                    ;;
                *)
                    printf '0\n'
                    ;;
            esac
            return 0
        fi
        if [[ "${1:-}" == "-p" ]]; then
            printf '%s\n' "${2:-}" >> "$sysctl_log"
            if [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]]; then
                if [[ "${SYSCTL_APPLY_EFFECTIVE:-0}" == "1" ]] \
                   && [[ -f "${2:-/dev/null}" ]]; then
                    while IFS= read -r line; do
                        case "$line" in
                            "net.ipv4.tcp_congestion_control = "*)
                                SYSCTL_CURRENT_CC="${line#*= }"
                                ;;
                            "net.core.default_qdisc = "*)
                                SYSCTL_CURRENT_QDISC="${line#*= }"
                                ;;
                        esac
                    done < "${2:-/dev/null}"
                fi
                return 0
            fi
            return 1
            return
        fi
        if [[ "${1:-}" == "--system" ]]; then
            printf '%s\n' "--system" >> "$sysctl_log"
            return 0
        fi
        return 0
    }

    SYSCTL_APPLY_OK=0 SYSCTL_APPLY_EFFECTIVE=0 SYSCTL_CURRENT_CC=cubic SYSCTL_CURRENT_QDISC=pfifo_fast
    opt_bbr >/dev/null 2>&1
    if grep -qF '# keep bbr base' "$mock_sysctl_conf" \
       && grep -q '^net.core.default_qdisc = pfifo_fast$' "$mock_sysctl_conf" \
       && [[ ! -f "$tuning_conf" ]] \
       && [[ ! -f "$latest_file" ]]; then
        pass "opt_bbr does not commit failed sysctl -p candidate"
    else
        fail "opt_bbr modified persistent config despite failed validation"
        sed 's/^/    /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
    fi

    SYSCTL_APPLY_OK=1 SYSCTL_APPLY_EFFECTIVE=0 SYSCTL_CURRENT_CC=cubic SYSCTL_CURRENT_QDISC=pfifo_fast
    opt_bbr >/dev/null 2>&1
    if grep -qF '# keep bbr base' "$mock_sysctl_conf" \
       && [[ ! -f "$tuning_conf" ]] \
       && [[ ! -f "$latest_file" ]]; then
        pass "opt_bbr does not commit when bbr verification fails"
    else
        fail "opt_bbr committed even though verify_cc was not bbr"
        sed 's/^/    /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
    fi

    SYSCTL_APPLY_OK=1 SYSCTL_APPLY_EFFECTIVE=1 SYSCTL_CURRENT_CC=cubic SYSCTL_CURRENT_QDISC=pfifo_fast
    opt_bbr >/dev/null 2>&1
    if grep -qF '# keep bbr base' "$mock_sysctl_conf" \
       && grep -q '^# server-manage moved to sysctl.d: net.core.default_qdisc = pfifo_fast$' "$mock_sysctl_conf" \
       && grep -q '^# server-manage moved to sysctl.d: net.ipv4.tcp_congestion_control = cubic$' "$mock_sysctl_conf" \
       && grep -q '^# BEGIN server-manage bbr$' "$tuning_conf" \
       && grep -q '^net.core.default_qdisc = fq$' "$tuning_conf" \
       && grep -q '^net.ipv4.tcp_congestion_control = bbr$' "$tuning_conf" \
       && ! grep -q '^net.core.default_qdisc = pfifo_fast$' "$mock_sysctl_conf" \
       && ! grep -q '^net.ipv4.tcp_congestion_control = cubic$' "$mock_sysctl_conf" \
       && [[ -f "$profile_file" ]] \
       && [[ -f "$latest_file" ]]; then
        pass "opt_bbr commits only validated sysctl.d candidate and keeps rollback metadata"
    else
        fail "opt_bbr successful commit/backup mismatch"
        sed 's/^/    conf: /' "$mock_sysctl_conf"
        [[ -f "$tuning_conf" ]] && sed 's/^/    tuning: /' "$tuning_conf"
        [[ -f "$profile_file" ]] && sed 's/^/    profile: /' "$profile_file"
    fi
}

test_opt_bbr_preserves_existing_role_tuning() {
    local workdir="$TMP_ROOT/bbr-preserve"
    local mock_sysctl_conf="$workdir/sysctl.conf"
    local tuning_conf="$workdir/sysctl.d/99zz-server-manage-tuning.conf"
    mkdir -p "$(dirname "$tuning_conf")"
    cat > "$mock_sysctl_conf" <<'EOF'
# bbr preserve base
net.core.default_qdisc = pfifo_fast
net.ipv4.tcp_congestion_control = cubic
EOF
    cat > "$tuning_conf" <<'EOF'
# BEGIN server-manage sysctl tuning: landing
net.core.default_qdisc = fq_codel
net.ipv4.tcp_congestion_control = cubic
fs.file-max = 1048576
net.core.somaxconn = 8192
net.ipv4.tcp_max_syn_backlog = 8192
# END server-manage sysctl tuning
EOF
    _sysctl_conf_path() { printf '%s' "$mock_sysctl_conf"; }
    declare -A SYSCTL_VALUES=(
        ["net.ipv4.tcp_congestion_control"]="cubic"
        ["net.core.default_qdisc"]="pfifo_fast"
        ["net.ipv4.tcp_available_congestion_control"]="reno cubic bbr"
        ["fs.file-max"]="262144"
        ["net.core.somaxconn"]="2048"
        ["net.ipv4.tcp_max_syn_backlog"]="2048"
    )
    sysctl() {
        if [[ "${1:-}" == "-n" ]]; then
            printf '%s\n' "${SYSCTL_VALUES[${2:-}]:-0}"
            return 0
        fi
        if [[ "${1:-}" == "-p" ]]; then
            [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]] || return 1
            while IFS= read -r line; do
                [[ "$line" =~ ^[[:space:]]*([A-Za-z0-9_.-]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
                SYSCTL_VALUES["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            done < "${2:-/dev/null}"
            return 0
        fi
        if [[ "${1:-}" == "--system" ]]; then
            return 0
        fi
        return 0
    }

    SYSCTL_APPLY_OK=1
    opt_bbr >/dev/null 2>&1
    if grep -q '^fs.file-max = 1048576$' "$tuning_conf" \
       && grep -q '^net.core.somaxconn = 8192$' "$tuning_conf" \
       && grep -q '^net.ipv4.tcp_max_syn_backlog = 8192$' "$tuning_conf" \
       && grep -q '^# BEGIN server-manage bbr$' "$tuning_conf" \
       && grep -q '^net.core.default_qdisc = fq$' "$tuning_conf" \
       && grep -q '^net.ipv4.tcp_congestion_control = bbr$' "$tuning_conf" \
       && ! grep -q '^net.core.default_qdisc = fq_codel$' "$tuning_conf" \
       && ! grep -q '^net.ipv4.tcp_congestion_control = cubic$' "$tuning_conf"; then
        pass "opt_bbr preserves existing role tuning while replacing BBR keys"
    else
        fail "opt_bbr overwrote existing role tuning"
        sed 's/^/    tuning: /' "$tuning_conf" 2>/dev/null || true
    fi
    unset SYSCTL_VALUES
}

test_wireguard_ip_forward_sysctl_managed_block() {
    local mock_sysctl_conf="$TMP_ROOT/wg-forward-sysctl.conf"
    local sysctl_log="$TMP_ROOT/wg-forward-sysctl-calls.txt"
    cat > "$mock_sysctl_conf" <<'EOF'
# external forwarding owner
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 1
EOF
    _sysctl_conf_path() { printf '%s' "$mock_sysctl_conf"; }
    sysctl() {
        if [[ "${1:-}" == "-p" ]]; then
            printf '%s\n' "${2:-}" >> "$sysctl_log"
            [[ "${SYSCTL_APPLY_OK:-0}" == "1" ]]
            return
        fi
        if [[ "${1:-}" == "-w" ]]; then
            printf 'write %s\n' "${2:-}" >> "$sysctl_log"
            return 0
        fi
        return 0
    }

    SYSCTL_APPLY_OK=0
    if _sysctl_enable_wireguard_forward >/dev/null 2>&1; then
        fail "_sysctl_enable_wireguard_forward succeeded despite failed candidate validation"
    elif grep -qF '# external forwarding owner' "$mock_sysctl_conf" \
         && ! grep -qF '# BEGIN server-manage wireguard ip-forward' "$mock_sysctl_conf"; then
        pass "WireGuard IP forward failed candidate does not modify sysctl.conf"
    else
        fail "WireGuard IP forward modified sysctl.conf despite failed validation"
        sed 's/^/    /' "$mock_sysctl_conf"
    fi

    SYSCTL_APPLY_OK=1
    if _sysctl_enable_wireguard_forward >/dev/null 2>&1 \
       && grep -qF '# external forwarding owner' "$mock_sysctl_conf" \
       && grep -q '^net.ipv4.ip_forward = 0$' "$mock_sysctl_conf" \
       && grep -q '^# BEGIN server-manage wireguard ip-forward$' "$mock_sysctl_conf" \
       && grep -q '^net.ipv4.ip_forward = 1$' "$mock_sysctl_conf"; then
        pass "WireGuard IP forward commit adds managed block without deleting external line"
    else
        fail "WireGuard IP forward enable did not preserve external line and managed block"
        sed 's/^/    /' "$mock_sysctl_conf"
    fi

    if _sysctl_disable_wireguard_forward >/dev/null 2>&1 \
       && grep -qF '# external forwarding owner' "$mock_sysctl_conf" \
       && grep -q '^net.ipv4.ip_forward = 0$' "$mock_sysctl_conf" \
       && ! grep -qF '# BEGIN server-manage wireguard ip-forward' "$mock_sysctl_conf" \
       && ! grep -q '^write net.ipv4.ip_forward=0$' "$sysctl_log"; then
        pass "WireGuard IP forward disable removes only managed block when external line remains"
    else
        fail "WireGuard IP forward disable removed external line or wrote runtime 0 incorrectly"
        sed 's/^/    /' "$mock_sysctl_conf"
        sed 's/^/    log: /' "$sysctl_log"
    fi
}

echo "== Fail2ban mocks =="
test_f2b_ipv6_banned_ip_parsing
test_f2b_unban_ipv6_exact_match
test_fail2ban_status_ipv6_display_static
test_f2b_apply_jail_local_is_transactional
test_f2b_setup_returns_failure_when_apply_fails
test_ssh_authorized_keys_append_is_atomic_private
test_ssh_authorized_keys_remove_is_atomic_private
test_copy_cert_pair_atomic_modes_and_rollback
test_render_cert_pair_hook_helper_rolls_back

echo ""
echo "== Network/firewall/system mocks =="
test_net_dns_validation_before_write
test_net_systemd_dns_rollback_and_render
test_openwrt_net_dns_rolls_back_on_failure
test_net_gai_priority_managed_block
test_hostname_hosts_rendering_is_precise
test_hostname_fallback_rolls_back_file_on_hostname_failure
test_net_diag_port_input_validation
test_firewall_allow_tcp_port_modes
test_firewall_prepare_non_ufw_udp_port_restrictive_iptables
test_wg_deb_server_install_udp_firewall_precheck_stops_before_db
test_wg_deb_server_install_rolls_back_non_ufw_udp_on_db_init_failure
test_wg_deb_server_install_rolls_back_when_service_not_running
test_wg_deb_modify_server_udp_firewall_failure_stops_safely
test_wg_deb_modify_server_non_ufw_udp_prepare_failure_stops_safely
test_wg_deb_modify_server_rolls_back_new_udp_allow_on_later_failure
test_wg_deb_modify_server_restores_full_snapshot_on_restart_failure
test_wg_deb_update_peer_routes_refreshes_managed_vpn_only_peer
test_wg_deb_peer_ops_roll_back_on_apply_failure
test_wg_deb_import_rolls_back_on_apply_failure
test_wg_deb_watchdog_cron_failure_returns_error
test_ufw_setup_reset_stop_when_ssh_allow_fails
test_ufw_manual_add_delete_validate_inputs
test_web_firewall_allow_helper_modes
test_swap_fstab_helpers_are_precise
test_opt_swap_delete_only_managed_swapfile
test_auto_deps_new_fail2ban_not_left_active
test_wg_shared_endpoint_formatting
test_wg_rc_local_cleanup_preserves_third_party_prio100
test_openwrt_apply_allow_port_rolls_back_new_rule_on_uci_failure
test_openwrt_persist_allow_port_restores_firewall_on_uci_failure
test_openwrt_configure_server_uci_restores_packages_on_uci_failure
test_openwrt_wg_modify_server_firewall_failure_stops_before_db
test_openwrt_wg_modify_server_rolls_back_on_rebuild_failure
test_openwrt_wg_server_install_rolls_back_on_ifup_failure
test_openwrt_wg_add_peer_db_failure_leaves_no_client_conf
test_openwrt_wg_toggle_peer_rolls_back_db_on_apply_failure
test_openwrt_wg_delete_peer_rolls_back_before_removing_conf_on_apply_failure
test_openwrt_wg_rebuild_uci_conf_restores_network_on_uci_failure
test_wg_shared_gateway_routes_syncs_and_cleans_stale_routes
test_wg_shared_gateway_routes_removes_state_when_no_gateways
test_openwrt_wg_uninstall_fails_on_uci_commit_failure
test_web_cleanup_domain_rejects_path_traversal
test_web_reverse_proxy_backend_update_is_atomic
test_nginx_official_source_and_stream_conf_are_atomic
test_nginx_deploy_conf_rolls_back_on_symlink_failure
test_wg_clash_output_uses_private_random_dir
test_wg_clash_rules_handle_ipv6_literals
test_openwrt_wg_watchdog_ipv6_helpers
test_openwrt_wg_deploy_generated_script_is_posix_sh "198.51.100.8" "ipv4" "198.51.100.8" "0" "0"
test_openwrt_wg_deploy_generated_script_is_posix_sh "vpn.example.com" "domain" "vpn.example.com" "1" "0"
test_openwrt_wg_deploy_generated_script_is_posix_sh "[2001:db8::8]" "ipv6" "2001:db8::8" "1" "1"
test_openwrt_wg_clean_generated_script_is_posix_sh
test_ssh_change_port_inserts_global_port_before_match
test_ssh_change_port_rolls_back_socket_dropin_when_firewall_fails
test_opt_sysctl_validates_before_commit
test_opt_sysctl_latest_pointer_failure_rolls_back
test_opt_bbr_validates_before_commit
test_opt_bbr_preserves_existing_role_tuning
test_wireguard_ip_forward_sysctl_managed_block

echo ""
echo "SUMMARY PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]
