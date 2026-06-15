#!/usr/bin/env bash
# check_composite_r5.sh
#
# Verifies R5 composite signature artifacts for all 18 combinations:
#   1. TA certificate: openssl verify -CAfile <name>_ta.der <name>_ta.der
#   2. Private key: sign test data with _priv.der, verify against _ta.der public key
#
# R5 naming convention (from readme + oid_mapping.md):
#   <friendly>-<oid>_ta.der   (e.g. id-MLDSA44-RSA2048-PSS-SHA256-1.3.6.1.5.5.7.6.37_ta.der)
#   <friendly>-<oid>_priv.der
#
# Usage:
#   ./check_composite_r5.sh [artifacts_certs_r5_dir]
#
# Environment variables:
#   OPENSSL_DIR   - OpenSSL source/build directory (default: workspace root)
#   OPENSSL_BIN   - Path to openssl binary (default: OPENSSL_DIR/apps/openssl)
#   OPENSSL_CONF  - Path to openssl.cnf (optional)

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# ─── OpenSSL binary configuration ────────────────────────────────────────────
OPENSSL_DIR="${OPENSSL_DIR:-${WORKSPACE_ROOT}/openssl}"
OPENSSL_BIN="${OPENSSL_BIN:-${OPENSSL_DIR}/apps/openssl}"
export LD_LIBRARY_PATH="${OPENSSL_DIR}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
export OPENSSL_MODULES="${OPENSSL_MODULES:-${WORKSPACE_ROOT}/_build}"
OPENSSL_CONF="${OPENSSL_CONF:-${WORKSPACE_ROOT}/tests/composite.cnf}"
export OPENSSL_CONF

# ─── Artifacts directory ─────────────────────────────────────────────────────
# The zip extracts into test/artifacts_certs_r5/
ARTIFACTS_DIR="${1:-${WORKSPACE_ROOT}/test/artifacts_certs_r5}"

# ─── All 18 composite signature algorithms ───────────────────────────────────
# Source: oid_mapping.md / draft-ietf-lamps-pq-composite-sigs-12
# Each entry: "friendly_name OID"
COMPOSITE_ALGOS=(
    "id-MLDSA44-RSA2048-PSS-SHA256            1.3.6.1.5.5.7.6.37"
    "id-MLDSA44-RSA2048-PKCS15-SHA256         1.3.6.1.5.5.7.6.38"
    "id-MLDSA44-Ed25519-SHA512                1.3.6.1.5.5.7.6.39"
    "id-MLDSA44-ECDSA-P256-SHA256             1.3.6.1.5.5.7.6.40"
    "id-MLDSA65-RSA3072-PSS-SHA512            1.3.6.1.5.5.7.6.41"
    "id-MLDSA65-RSA3072-PKCS15-SHA512         1.3.6.1.5.5.7.6.42"
    "id-MLDSA65-RSA4096-PSS-SHA512            1.3.6.1.5.5.7.6.43"
    "id-MLDSA65-RSA4096-PKCS15-SHA512         1.3.6.1.5.5.7.6.44"
    "id-MLDSA65-ECDSA-P256-SHA512             1.3.6.1.5.5.7.6.45"
    "id-MLDSA65-ECDSA-P384-SHA512             1.3.6.1.5.5.7.6.46"
    "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512  1.3.6.1.5.5.7.6.47"
    "id-MLDSA65-Ed25519-SHA512                1.3.6.1.5.5.7.6.48"
    "id-MLDSA87-ECDSA-P384-SHA512             1.3.6.1.5.5.7.6.49"
    "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512  1.3.6.1.5.5.7.6.50"
    "id-MLDSA87-Ed448-SHAKE256                1.3.6.1.5.5.7.6.51"
    "id-MLDSA87-RSA3072-PSS-SHA512            1.3.6.1.5.5.7.6.52"
    "id-MLDSA87-RSA4096-PSS-SHA512            1.3.6.1.5.5.7.6.53"
    "id-MLDSA87-ECDSA-P521-SHA512             1.3.6.1.5.5.7.6.54"
)

# ─── Counters ────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
SKIP=0
declare -a FAILURES=()

# ─── Temp dir, cleaned on exit ───────────────────────────────────────────────
WORK_DIR="$(mktemp -d /tmp/composite_check.XXXXXX)"
trap 'rm -rf "${WORK_DIR}"' EXIT

TEST_DATA="${WORK_DIR}/testdata.bin"
printf 'This is a test of signature data' > "${TEST_DATA}"

# ─── Helper: print padded result ─────────────────────────────────────────────
print_result() {
    local label="$1" name="$2" result="$3" detail="${4:-}"
    printf "  [%-7s] %-68s %s" "${label}" "${name}" "${result}"
    if [[ -n "${detail}" ]]; then
        printf " (%s)" "${detail}"
    fi
    printf "\n"
}

# ─── Verify TA cert (self-signed) ────────────────────────────────────────────
# -check_ss_sig forces OpenSSL to actually verify the signature on the
# self-signed cert rather than short-circuiting it as a trust anchor.
check_ta_cert() {
    local label="$1" ta_file="$2"

    local ta_pem="${WORK_DIR}/ta_$$.pem"
    local err

    # Convert DER to PEM (-CAfile requires PEM)
    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ta_file}" -out "${ta_pem}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "CERT" "${label}" "FAIL" "DER to PEM conversion failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("CERT: ${label}")
        return
    fi

    err="$("${OPENSSL_BIN}" verify -CAfile "${ta_pem}" -check_ss_sig "${ta_pem}" 2>&1)"
    if [[ $? -eq 0 ]]; then
        print_result "CERT" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "CERT" "${label}" "FAIL"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("CERT: ${label}")
    fi
}

# ─── Verify private key via sign + verify round-trip ─────────────────────────
check_priv_key() {
    local label="$1" ta_file="$2" priv_file="$3"

    local sig_file="${WORK_DIR}/sig_$$.bin"
    local pub_file="${WORK_DIR}/pub_$$.pem"
    local err

    # Extract public key from TA cert
    err="$("${OPENSSL_BIN}" x509 -inform DER -in "${ta_file}" \
            -pubkey -noout -out "${pub_file}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "PRIVKEY" "${label}" "FAIL" "pubkey extraction failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
        return
    fi

    # Sign test data with the private key (DER format)
    # Use -rawin so pkeyutl routes through digest_sign_* (required for composite).
    # No -digest flag: composite determines its own hash algorithm internally.
    err="$("${OPENSSL_BIN}" pkeyutl -sign \
            -inkey "${priv_file}" -keyform DER \
            -rawin \
            -in "${TEST_DATA}" \
            -out "${sig_file}" 2>&1)"
    if [[ $? -ne 0 ]]; then
        print_result "PRIVKEY" "${label}" "FAIL" "signing failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
        return
    fi

    # Verify signature against the TA public key
    err="$("${OPENSSL_BIN}" pkeyutl -verify \
            -pubin -inkey "${pub_file}" \
            -rawin \
            -in "${TEST_DATA}" \
            -sigfile "${sig_file}" 2>&1)"
    if [[ $? -eq 0 ]]; then
        print_result "PRIVKEY" "${label}" "PASS"
        PASS=$((PASS + 1))
    else
        print_result "PRIVKEY" "${label}" "FAIL" "signature verification failed"
        echo "${err}" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        FAILURES+=("PRIVKEY: ${label}")
    fi
}

# ─── Header ──────────────────────────────────────────────────────────────────
echo "Composite Signature R5 Artifact Verification"
echo "============================================="
echo "OpenSSL:    ${OPENSSL_BIN}"
echo "Artifacts:  ${ARTIFACTS_DIR}"
echo ""

if [[ ! -d "${ARTIFACTS_DIR}" ]]; then
    echo "ERROR: artifacts directory not found: ${ARTIFACTS_DIR}"
    echo "       Extract artifacts_certs_r5.zip into test/ at the workspace root."
    exit 1
fi

# ─── Main loop ───────────────────────────────────────────────────────────────
for entry in "${COMPOSITE_ALGOS[@]}"; do
    friendly="${entry%% *}"
    oid="${entry##* }"

    echo "${friendly} (${oid}):"

    # Locate files by OID only — the friendly-name prefix may vary per provider
    mapfile -t ta_matches  < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_ta.der"   2>/dev/null | sort)
    mapfile -t priv_matches < <(find "${ARTIFACTS_DIR}" -maxdepth 1 -name "*${oid}_priv.der" 2>/dev/null | sort)

    ta_file="${ta_matches[0]:-}"
    priv_file="${priv_matches[0]:-}"

    # Use the actual filename (minus directory) as the display label
    ta_label="${ta_file:+$(basename "${ta_file}" _ta.der)}"
    priv_label="${priv_file:+$(basename "${priv_file}" _priv.der)}"

    # --- TA cert verification ---
    if [[ -z "${ta_file}" ]]; then
        print_result "CERT" "${oid}" "SKIP" "no *${oid}_ta.der found"
        SKIP=$((SKIP + 1))
    else
        check_ta_cert "${ta_label}" "${ta_file}"
    fi

    # --- Private key round-trip test ---
    if [[ -z "${priv_file}" ]]; then
        print_result "PRIVKEY" "${oid}" "SKIP" "no *${oid}_priv.der found"
        SKIP=$((SKIP + 1))
    elif [[ -z "${ta_file}" ]]; then
        print_result "PRIVKEY" "${oid}" "SKIP" "TA not found, cannot extract public key"
        SKIP=$((SKIP + 1))
    else
        check_priv_key "${priv_label}" "${ta_file}" "${priv_file}"
    fi
done

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
printf "Results: %d passed, %d failed, %d skipped\n" "${PASS}" "${FAIL}" "${SKIP}"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "Failed checks:"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}"
    done
fi

echo ""
[[ ${FAIL} -eq 0 ]]
