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

echo "nginx_body_size_defaults_test: PASS"
