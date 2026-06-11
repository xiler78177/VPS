#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
    echo "TEST FAILED: $1" >&2
    exit 1
}

grep -q 'client_max_body_size 50M;' modules/09c-web-domain.sh || \
    fail "web_add_domain generated nginx config should set client_max_body_size 50M"

grep -q 'client_max_body_size 50M;' modules/09e-web-home-expose.sh || \
    fail "web_home_expose generated nginx config should set client_max_body_size 50M"

if grep -q 'client_max_body_size 128M;' modules/09e-web-home-expose.sh; then
    fail "web_home_expose should no longer hardcode client_max_body_size 128M"
fi

grep -q '_nginx_tls_http2_block' modules/09a-web-helpers.sh || \
    fail "web helpers should expose version-aware HTTP/2 listen helper"

if grep -RE 'listen .* ssl http2;' modules/09c-web-domain.sh modules/09d-web-proxy.sh modules/09e-web-home-expose.sh >/dev/null; then
    fail "generated nginx templates should not hardcode deprecated listen ... http2 syntax"
fi

grep -q '_nginx_tls_http2_block "$NGINX_HTTPS_PORT"' modules/09c-web-domain.sh || \
    fail "web_add_domain should use version-aware HTTP/2 listen helper"

grep -q '_nginx_tls_http2_block "$HTTPS_PORT"' modules/09d-web-proxy.sh || \
    fail "web_reverse_proxy_site should use version-aware HTTP/2 listen helper"

grep -q '_nginx_tls_http2_block "$https_port"' modules/09e-web-home-expose.sh || \
    fail "web_home_expose should use version-aware HTTP/2 listen helper"

echo "nginx_body_size_defaults_test: PASS"
