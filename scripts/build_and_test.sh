#!/bin/bash
# build_and_test.sh — build OpenSSL (if needed), build composite provider, run tests.
#
# Environment variables:
#   OPENSSL_BRANCH   — branch/tag to clone; default "master"
#   MAKE_PARAMS      — extra flags passed to every make invocation (e.g. "-j$(nproc)")
#   CMAKE_PARAMS     — extra flags passed to cmake
#
# Arguments:
#   -f   soft-clean: remove _build before rebuilding (keeps openssl/)
#   -F   hard-clean: remove _build and openssl/ before rebuilding

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── argument parsing ──────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        -f) echo "[build] Soft-clean: removing _build/"; rm -rf "$ROOT/_build" ;;
        -F) echo "[build] Hard-clean: removing _build/ and openssl/";
            rm -rf "$ROOT/_build" "$ROOT/openssl" ;;
    esac
done

cd "$ROOT"

: "${OPENSSL_BRANCH:=master}"
: "${MAKE_PARAMS:=}"
: "${CMAKE_PARAMS:=}"
: "${OSSL_CONFIG:=}"

# ── OpenSSL ───────────────────────────────────────────────────────────────────
OSSL_DIR="$ROOT/openssl"
OSSL_BIN="$OSSL_DIR/apps/openssl"

if [[ ! -x "$OSSL_BIN" ]]; then
    if [[ ! -d "$OSSL_DIR" ]]; then
        echo "[build] Cloning OpenSSL (branch: $OPENSSL_BRANCH) …"
        git clone --depth 1 --branch "$OPENSSL_BRANCH" \
            https://github.com/openssl/openssl.git "$OSSL_DIR"
    fi

    echo "[build] Configuring OpenSSL …"
    cd "$OSSL_DIR"
    # Build in-tree (no install); shared libs end up in openssl/ directly.
    ./config shared $OSSL_CONFIG
    echo "[build] Building OpenSSL (this may take a while) …"
    make $MAKE_PARAMS
    cd "$ROOT"
else
    echo "[build] OpenSSL already built at $OSSL_BIN — skipping."
fi

# Resolve the actual shared-library path for LD_LIBRARY_PATH
OSSL_LIB_DIR="$OSSL_DIR"
if [[ -z "$(ls "$OSSL_LIB_DIR"/libcrypto.so* 2>/dev/null)" ]]; then
    echo "[error] Cannot find libcrypto.so* under $OSSL_LIB_DIR" >&2
    exit 1
fi

# ── Provider ──────────────────────────────────────────────────────────────────
BUILD_DIR="$ROOT/_build"

if [[ ! -f "$BUILD_DIR/composite.so" ]]; then
    echo "[build] Configuring composite provider …"
    cmake $CMAKE_PARAMS \
        -DOPENSSL_ROOT_DIR="$OSSL_DIR" \
        -DOPENSSL_INCLUDE_DIR="$OSSL_DIR/include" \
        -S "$ROOT" -B "$BUILD_DIR"

    echo "[build] Building composite provider …"
    make $MAKE_PARAMS -C "$BUILD_DIR"
else
    echo "[build] composite.so already built — skipping provider build."
    echo "        (Run with -f to force a rebuild.)"
fi

# ── Tests ─────────────────────────────────────────────────────────────────────
export OSSL_LIB_DIR="$OSSL_LIB_DIR"
export BUILD_DIR="$BUILD_DIR"
exec "$SCRIPT_DIR/run_tests.sh"
