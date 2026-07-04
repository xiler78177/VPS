#!/usr/bin/env bash
# Run the repository's local/remote-safe test matrix.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 99

export LC_ALL="${LC_ALL:-C.UTF-8}"

BUILT_TMP="${BUILT_TMP:-/tmp/v4-built.sh}"
PASS=0
FAIL=0

pass() {
    echo "  [PASS] $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  [FAIL] $1"
    FAIL=$((FAIL + 1))
}

run_cmd() {
    local label="$1"
    shift
    echo "==== $label ===="
    "$@"
    local rc=$?
    if [[ $rc -eq 0 ]]; then
        pass "$label"
    else
        fail "$label rc=$rc"
    fi
    echo
    return 0
}

echo "==== build ===="
if bash build.sh; then
    pass "build.sh"
else
    fail "build.sh"
fi
cp dist/v4-built.sh "$BUILT_TMP"
echo

mapfile -t shell_files < <(
    {
        [[ -f build.sh ]] && printf '%s\n' build.sh
        [[ -f dist/v4-built.sh ]] && printf '%s\n' dist/v4-built.sh
        find modules scripts tests docs -type f -name '*.sh' 2>/dev/null
    } | sort -u
)
run_cmd "bash syntax" bash -n "${shell_files[@]}"

while IFS= read -r test_file; do
    case "$test_file" in
        tests/run_all.sh) continue ;;
    esac
    run_cmd "$test_file" bash "$test_file"
done < <(find tests -maxdepth 1 -type f -name '*.sh' | sort)

echo "==== result ===="
echo "PASS=$PASS FAIL=$FAIL"
if [[ $FAIL -eq 0 ]]; then
    exit 0
fi
exit 1
