#!/bin/bash
# run_tests.sh — run the composite provider test suite.
#
# Can be invoked directly or sourced from build_and_test.sh.
#
# Environment variables (all optional):
#   OSSL_LIB_DIR   — directory containing libcrypto.so (default: <root>/openssl)
#   BUILD_DIR      — provider build directory           (default: <root>/_build)
#   TESTS          — space-separated list of test names to run; default: all
#
# Example standalone usage:
#   ./scripts/run_tests.sh
#   TESTS="test_sign_verify test_oid_registration" ./scripts/run_tests.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

: "${OSSL_LIB_DIR:=$ROOT/openssl}"
: "${BUILD_DIR:=$ROOT/_build}"

if [[ "$(uname -s)" == "Darwin" ]]; then
    SHLIB_EXT="dylib"
    LIBCRYPTO_GLOB="libcrypto*.dylib"
    LIB_PATH_VAR="DYLD_LIBRARY_PATH"
else
    SHLIB_EXT="so"
    LIBCRYPTO_GLOB="libcrypto.so*"
    LIB_PATH_VAR="LD_LIBRARY_PATH"
fi

# Validate prerequisites
if [[ -z "$(find "$OSSL_LIB_DIR" -maxdepth 1 -name "$LIBCRYPTO_GLOB" -print -quit)" ]]; then
    echo "[error] $LIBCRYPTO_GLOB not found under $OSSL_LIB_DIR" >&2
    echo "        Set OSSL_LIB_DIR or run build_and_test.sh first." >&2
    exit 1
fi

if [[ ! -f "$BUILD_DIR/composite.$SHLIB_EXT" ]]; then
    echo "[error] composite.$SHLIB_EXT not found in $BUILD_DIR" >&2
    echo "        Run build_and_test.sh first." >&2
    exit 1
fi

export "$LIB_PATH_VAR=$OSSL_LIB_DIR"
export OPENSSL_MODULES="$BUILD_DIR"

# Default test list (all)
DEFAULT_TESTS=(
    "test_provider"
    "test_encoding"
    "test_keygen_sig"
    "test_evp_keygen"
    "test_sign_verify"
    "test_oid_registration"
    "test_keygen_kem"
    "test_evp_kem_keygen"
)

# Allow override via env var (space-separated names)
if [[ -n "${TESTS:-}" ]]; then
    read -r -a RUN_TESTS <<< "$TESTS"
else
    RUN_TESTS=("${DEFAULT_TESTS[@]}")
fi

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Composite Provider — Test Suite"
echo " BUILD_DIR    : $BUILD_DIR"
echo " OSSL_LIB_DIR : $OSSL_LIB_DIR"
echo "═══════════════════════════════════════════════════════"

PASS=0
FAIL=0
FAILED_TESTS=()

for t in "${RUN_TESTS[@]}"; do
    BIN="$BUILD_DIR/tests/$t"
    if [[ ! -x "$BIN" ]]; then
        echo ""
        echo "[FAIL] $t — binary not found at $BIN"
        FAIL=$(( FAIL + 1 ))
        FAILED_TESTS+=("$t")
        continue
    fi

    echo ""
    echo "── $t ──"
    if "$BIN"; then
        PASS=$(( PASS + 1 ))
    else
        FAIL=$(( FAIL + 1 ))
        FAILED_TESTS+=("$t")
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed"
if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
    echo " Failed:  ${FAILED_TESTS[*]}"
fi
echo "═══════════════════════════════════════════════════════"

[[ $FAIL -eq 0 ]]
