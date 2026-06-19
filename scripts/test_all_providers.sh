#!/usr/bin/env bash
# test_all_providers.sh
#
# Discovers artifacts_certs_r5.zip under:
#   .vscode/internal_scripts/providers/<name_of_provider>/
# Extracts only the leaf artifact files (flat, no subdirectory structure) into:
#   .vscode/internal_scripts/test/
# The test/ directory is wiped before each provider's extraction.
# Then runs check_composite_r5.sh for every provider, printing a section
# per provider in the output.
#
# Usage:
#   ./test_all_providers.sh
#
# Environment variables (all optional, passed through to check_composite_r5.sh):
#   OPENSSL_DIR   - OpenSSL source/build directory (default: workspace root)
#   OPENSSL_BIN   - Path to openssl binary (default: OPENSSL_DIR/apps/openssl)
#   OPENSSL_CONF  - Path to openssl.cnf

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── Argument parsing ────────────────────────────────────────────────────────
GEN_COMPAT=0
for arg in "$@"; do
    case "${arg}" in
        --compat) GEN_COMPAT=1 ;;
    esac
done

OUTPUT_FILE="${SCRIPT_DIR}/output.txt"
# Redirect all stdout and stderr to output.txt, while also printing to terminal
exec > "${OUTPUT_FILE}" 2>&1

PROVIDER_BASE="${SCRIPT_DIR}/providers"
TEST_BASE="${SCRIPT_DIR}/test"
CHECK_SCRIPT="${SCRIPT_DIR}/check_composite_r5.sh"

# ─── Validate check script exists ────────────────────────────────────────────
if [[ ! -x "${CHECK_SCRIPT}" ]]; then
    echo "ERROR: check_composite_r5.sh not found or not executable at:"
    echo "       ${CHECK_SCRIPT}"
    exit 1
fi

# ─── OpenSSL binary defaults ─────────────────────────────────────────────────
export OPENSSL_DIR="${OPENSSL_DIR:-${WORKSPACE_ROOT}/openssl}"
export OPENSSL_BIN="${OPENSSL_BIN:-${OPENSSL_DIR}/apps/openssl}"
export LD_LIBRARY_PATH="${OPENSSL_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export OPENSSL_MODULES="${OPENSSL_MODULES:-${WORKSPACE_ROOT}/_build}"
OPENSSL_CONF="${OPENSSL_CONF:-${WORKSPACE_ROOT}/tests/composite.cnf}"
export OPENSSL_CONF

# ─── Collect providers ───────────────────────────────────────────────────────
if [[ ! -d "${PROVIDER_BASE}" ]]; then
    echo "ERROR: provider directory not found: ${PROVIDER_BASE}"
    echo "       Create .vscode/internal_scripts/providers/<name>/ and place"
    echo "       artifacts_certs_r5.zip inside."
    exit 1
fi

mapfile -t ZIP_FILES < <(find "${PROVIDER_BASE}" -mindepth 2 -maxdepth 2 \
    -name "artifacts_certs_r5.zip" | sort)

if [[ ${#ZIP_FILES[@]} -eq 0 ]]; then
    echo "No artifacts_certs_r5.zip found under ${PROVIDER_BASE}/"
    echo "Expected layout: providers/<name_of_provider>/artifacts_certs_r5.zip"
    exit 1
fi

# ─── Compat matrix settings ─────────────────────────────────────────────────
OUR_NAME="composite-crypto"
COMPAT_MATRICES_DIR="${SCRIPT_DIR}/compatMatrices/artifacts_certs_r5"
if (( GEN_COMPAT )); then
    rm -rf "${SCRIPT_DIR}/compatMatrices/"
    mkdir -p "${COMPAT_MATRICES_DIR}"
fi

# 18 composite signature OIDs (draft-ietf-lamps-pq-composite-sigs)
COMPOSITE_OIDS=(
    "1.3.6.1.5.5.7.6.37"
    "1.3.6.1.5.5.7.6.38"
    "1.3.6.1.5.5.7.6.39"
    "1.3.6.1.5.5.7.6.40"
    "1.3.6.1.5.5.7.6.41"
    "1.3.6.1.5.5.7.6.42"
    "1.3.6.1.5.5.7.6.43"
    "1.3.6.1.5.5.7.6.44"
    "1.3.6.1.5.5.7.6.45"
    "1.3.6.1.5.5.7.6.46"
    "1.3.6.1.5.5.7.6.47"
    "1.3.6.1.5.5.7.6.48"
    "1.3.6.1.5.5.7.6.49"
    "1.3.6.1.5.5.7.6.50"
    "1.3.6.1.5.5.7.6.51"
    "1.3.6.1.5.5.7.6.52"
    "1.3.6.1.5.5.7.6.53"
    "1.3.6.1.5.5.7.6.54"
)

# ─── Global counters ─────────────────────────────────────────────────────────
TOTAL_PROVIDERS=0
TOTAL_WITH_COMPOSITE=0        # providers with at least 1 artifact found (PASS+FAIL > 0)
TOTAL_WITH_COMPOSITE_NO_FAIL=0 # of those, providers with zero FAILs
TOTAL_EXTRACT_ERRORS=0        # providers whose zip failed to extract

# ─── Banner ──────────────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║       Composite Signature R5 — Multi-Provider Verification              ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo "OpenSSL:  ${OPENSSL_BIN}"
echo "Date:     $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ─── Ensure test dir exists ─────────────────────────────────────────────────
mkdir -p "${TEST_BASE}"

# ─── Per-provider loop ───────────────────────────────────────────────────────
for zip_path in "${ZIP_FILES[@]}"; do
    provider_dir="$(dirname "${zip_path}")"
    provider_name="$(basename "${provider_dir}")"

    TOTAL_PROVIDERS=$((TOTAL_PROVIDERS + 1))

    echo "┌──────────────────────────────────────────────────────────────────────────"
    echo "│ Provider: ${provider_name}"
    echo "│ Zip:      ${zip_path}"
    echo "│ Extract:  ${TEST_BASE}/ (leaf files, flat)"
    echo "└──────────────────────────────────────────────────────────────────────────"

    # ── Wipe test dir, then extract leaf files only (no directory structure) ──
    rm -rf "${TEST_BASE:?}"/*

    unzip_out="$(unzip -j -q -o "${zip_path}" -d "${TEST_BASE}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        echo "  [ERROR] Failed to extract zip:"
        echo "${unzip_out}" | sed 's/^/    /'
        TOTAL_EXTRACT_ERRORS=$((TOTAL_EXTRACT_ERRORS + 1))
        echo ""
        continue
    fi

    # ── Run check script ─────────────────────────────────────────────────────
    provider_output="$("${CHECK_SCRIPT}" "${TEST_BASE}" 2>&1)"
    provider_exit=$?

    # Indent every line of the check output for readability
    echo "${provider_output}" | sed 's/^/  /'

    # Parse the "Results: X passed, Y failed, Z skipped" line from check output
    _pass=0; _fail=0
    if _rline="$(echo "${provider_output}" | grep -E '^Results: ')"; then
        _pass=$(echo "${_rline}" | sed -E 's/Results: ([0-9]+) passed.*/\1/')
        _fail=$(echo "${_rline}" | sed -E 's/Results: [0-9]+ passed, ([0-9]+) failed.*/\1/')
    fi

    # ── Generate compat matrix CSV (only when -compat is set) ─────────────────
    if (( GEN_COMPAT )); then
        csv_file="${COMPAT_MATRICES_DIR}/${provider_name}_${OUR_NAME}.csv"
        {
            echo "key_algorithm_oid,type,test_result"
            for oid in "${COMPOSITE_OIDS[@]}"; do
                if echo "${provider_output}" | grep -qE "\[CERT[[:space:]]*\].*${oid}.*(PASS|FAIL)"; then
                    if echo "${provider_output}" | grep -qE "\[CERT[[:space:]]*\].*${oid}.*PASS"; then
                        cert_val="Y"
                    else
                        cert_val="N"
                    fi
                    echo "${oid},cert,${cert_val}"
                fi
                if echo "${provider_output}" | grep -qE "\[PRIVKEY\].*${oid}.*(PASS|FAIL)"; then
                    if echo "${provider_output}" | grep -qE "\[PRIVKEY\].*${oid}.*PASS"; then
                        priv_val="Y"
                    else
                        priv_val="N"
                    fi
                    echo "${oid},priv,${priv_val}"
                fi
            done
        } > "${csv_file}"
    fi

    if (( _pass + _fail > 0 )); then
        TOTAL_WITH_COMPOSITE=$((TOTAL_WITH_COMPOSITE + 1))
        if (( _fail == 0 )); then
            TOTAL_WITH_COMPOSITE_NO_FAIL=$((TOTAL_WITH_COMPOSITE_NO_FAIL + 1))
        fi
    fi

    if [[ ${provider_exit} -eq 0 ]]; then
        echo ""
        echo "  ► Provider result: PASS"
    else
        echo ""
        echo "  ► Provider result: FAIL"
    fi
    echo ""
done

# ─── Clean up test dir after last provider ───────────────────────────────────
rm -rf "${TEST_BASE:?}"

# ─── Grand summary ───────────────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║ Grand Summary                                                            ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
printf "  Providers tested:                    %d\n"  "${TOTAL_PROVIDERS}"
printf "  Providers with composite artifacts:  %d\n"  "${TOTAL_WITH_COMPOSITE}"
printf "  Providers with composite, no FAIL:   %d\n"  "${TOTAL_WITH_COMPOSITE_NO_FAIL}"
echo ""

[[ ${TOTAL_WITH_COMPOSITE_NO_FAIL} -eq ${TOTAL_WITH_COMPOSITE} && ${TOTAL_EXTRACT_ERRORS} -eq 0 ]]
