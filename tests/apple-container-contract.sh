#!/usr/bin/env bash
# Stock-runtime contract for the apple-container build (spec WP-0 / T-02).
#
# On an Apple Container runtime without the per-machine network and
# SSH-agent extension, `coop setup` must fail with APPLE_RUNTIME_UNQUALIFIED
# and leave no coop state or runtime objects behind. `coop update` must refuse
# to replace the build. Safe to run: it only probes the runtime and uses a
# throwaway config/data directory. The Apple Container service may be stopped.
#
# Usage: tests/apple-container-contract.sh   (macOS with `container` installed)
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "SKIP: apple-container is macOS-only" >&2
    exit 0
fi
RUNTIME=""
for candidate in /usr/local/bin/container /opt/homebrew/bin/container; do
    if [[ -x "$candidate" ]]; then
        RUNTIME="$candidate"
        break
    fi
done
if [[ -z "$RUNTIME" ]]; then
    echo "SKIP: no Apple container runtime installed" >&2
    exit 0
fi

cargo build --features apple-container --quiet
BIN="${CARGO_TARGET_DIR:-$PWD/target}/debug/coop"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
printf 'data_dir = "%s/data"\n' "$WORK" > "$WORK/config.toml"
export COOP_NO_UPDATE_CHECK=1

snapshot() {
    # Runtime objects, when the service answers; empty otherwise.
    { "$RUNTIME" machine list --quiet 2>/dev/null || true
      "$RUNTIME" network list --quiet 2>/dev/null || true; } | sort
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

before="$(snapshot)"

echo "=> coop setup on $("$RUNTIME" --version)"
if "$BIN" --config "$WORK/config.toml" setup --yes > "$WORK/setup.out" 2>&1; then
    if grep -q -- '--no-ssh-agent' < <("$RUNTIME" machine create --help); then
        echo "SKIP: runtime advertises the isolation extension; this contract covers stock runtimes" >&2
        exit 0
    fi
    fail "setup succeeded on a runtime without the isolation extension"
fi
grep -q "APPLE_RUNTIME_UNQUALIFIED" "$WORK/setup.out" \
    || fail "setup did not report APPLE_RUNTIME_UNQUALIFIED: $(cat "$WORK/setup.out")"
[[ ! -e "$WORK/data/backends/apple-container-v1/owner.json" ]] \
    || fail "setup wrote owner.json before qualification"
[[ ! -e "$WORK/data/backends/apple-container-v1/vm_key" ]] \
    || fail "setup generated a VM key before qualification"

echo "=> coop update"
if "$BIN" --config "$WORK/config.toml" update > "$WORK/update.out" 2>&1; then
    fail "update ran on an apple-container build"
fi
grep -q "APPLE_UPDATE_VARIANT_UNSUPPORTED" "$WORK/update.out" \
    || fail "update did not report APPLE_UPDATE_VARIANT_UNSUPPORTED"

after="$(snapshot)"
[[ "$before" == "$after" ]] || fail "runtime objects changed: before=[$before] after=[$after]"

echo "PASS: stock runtime refused before any side effect"
