#!/usr/bin/env bash
# gen_composite_r5.sh
#
# Generates artifacts_certs_r5.zip for all 18 composite signature algorithms
# following the IETF Hackathon R5 artifact naming convention:
#   <friendly>-<oid>_ta.der    — self-signed DER CA certificate (10-year)
#   <friendly>-<oid>_priv.der  — PKCS#8 DER private key
#
# Example output filenames:
#   mldsa44_rsa2048_pss_sha256-1.3.6.1.5.5.7.6.37_ta.der
#   mldsa44_rsa2048_pss_sha256-1.3.6.1.5.5.7.6.37_priv.der
#
# Usage:
#   ./gen_composite_r5.sh [output_dir]
#
# The zip is written to <output_dir>/artifacts_certs_r5.zip
# Default output_dir: the directory containing this script.
#
# Environment variables (all optional):
#   OPENSSL_DIR   — OpenSSL build directory (default: workspace root)
#   OPENSSL_BIN   — Path to openssl binary  (default: OPENSSL_DIR/apps/openssl)
#   OPENSSL_CONF  — Path to openssl.cnf

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

# ─── Output directory ────────────────────────────────────────────────────────
OUTPUT_DIR="${1:-${SCRIPT_DIR}}"
mkdir -p "${OUTPUT_DIR}"

# ─── All 18 composite algorithms ─────────────────────────────────────────────
# Format per entry: "OPENSSL_GENPKEY_NAME  r5_friendly_prefix  oid"
# OPENSSL_GENPKEY_NAME uses the LN (long name) format registered by the provider.
COMPOSITE_ALGOS=(
    "MLDSA44-RSA2048-PSS-SHA256            mldsa44_rsa2048_pss_sha256             1.3.6.1.5.5.7.6.37"
    "MLDSA44-RSA2048-PKCS15-SHA256         mldsa44_rsa2048_pkcs15_sha256          1.3.6.1.5.5.7.6.38"
    "MLDSA44-Ed25519-SHA512                mldsa44_ed25519_sha512                 1.3.6.1.5.5.7.6.39"
    "MLDSA44-ECDSA-P256-SHA256             mldsa44_ecdsa_p256_sha256              1.3.6.1.5.5.7.6.40"
    "MLDSA65-RSA3072-PSS-SHA512            mldsa65_rsa3072_pss_sha512             1.3.6.1.5.5.7.6.41"
    "MLDSA65-RSA3072-PKCS15-SHA512         mldsa65_rsa3072_pkcs15_sha512          1.3.6.1.5.5.7.6.42"
    "MLDSA65-RSA4096-PSS-SHA512            mldsa65_rsa4096_pss_sha512             1.3.6.1.5.5.7.6.43"
    "MLDSA65-RSA4096-PKCS15-SHA512         mldsa65_rsa4096_pkcs15_sha512          1.3.6.1.5.5.7.6.44"
    "MLDSA65-ECDSA-P256-SHA512             mldsa65_ecdsa_p256_sha512              1.3.6.1.5.5.7.6.45"
    "MLDSA65-ECDSA-P384-SHA512             mldsa65_ecdsa_p384_sha512              1.3.6.1.5.5.7.6.46"
    "MLDSA65-ECDSA-brainpoolP256r1-SHA512  mldsa65_ecdsa_brainpoolp256r1_sha512   1.3.6.1.5.5.7.6.47"
    "MLDSA65-Ed25519-SHA512                mldsa65_ed25519_sha512                 1.3.6.1.5.5.7.6.48"
    "MLDSA87-ECDSA-P384-SHA512             mldsa87_ecdsa_p384_sha512              1.3.6.1.5.5.7.6.49"
    "MLDSA87-ECDSA-brainpoolP384r1-SHA512  mldsa87_ecdsa_brainpoolp384r1_sha512   1.3.6.1.5.5.7.6.50"
    "MLDSA87-Ed448-SHAKE256                mldsa87_ed448_shake256                 1.3.6.1.5.5.7.6.51"
    "MLDSA87-RSA3072-PSS-SHA512            mldsa87_rsa3072_pss_sha512             1.3.6.1.5.5.7.6.52"
    "MLDSA87-RSA4096-PSS-SHA512            mldsa87_rsa4096_pss_sha512             1.3.6.1.5.5.7.6.53"
    "MLDSA87-ECDSA-P521-SHA512             mldsa87_ecdsa_p521_sha512              1.3.6.1.5.5.7.6.54"
)

# ─── Counters ────────────────────────────────────────────────────────────────
PASS=0
FAIL=0
declare -a FAILURES=()

# ─── Temp working dirs ───────────────────────────────────────────────────────
WORK_DIR="$(mktemp -d /tmp/gen_composite_r5.XXXXXX)"
STAGING_DIR="${WORK_DIR}/staging"
mkdir -p "${STAGING_DIR}"
trap 'rm -rf "${WORK_DIR}"' EXIT

# ─── Header ──────────────────────────────────────────────────────────────────
echo "Composite Signature R5 Artifact Generation"
echo "==========================================="
echo "OpenSSL:  ${OPENSSL_BIN}"
echo "Output:   ${OUTPUT_DIR}/artifacts_certs_r5.zip"
echo ""

# ─── Main generation loop ────────────────────────────────────────────────────
for entry in "${COMPOSITE_ALGOS[@]}"; do
    read -r ossl_name friendly oid <<< "${entry}"

    file_base="${friendly}-${oid}"
    ta_file="${STAGING_DIR}/${file_base}_ta.der"
    priv_file="${STAGING_DIR}/${file_base}_priv.der"
    temp_key="${WORK_DIR}/key_${ossl_name}.pem"

    printf "  %-50s " "${ossl_name}"

    # Step 1: Generate composite keypair as PKCS#8 PEM
    if ! keygen_err="$("${OPENSSL_BIN}" genpkey \
            -algorithm "${ossl_name}" \
            -out "${temp_key}" 2>&1)"; then
        echo "FAIL (keygen)"
        echo "${keygen_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: keygen failed")
        continue
    fi

    # Step 2: Self-signed TA certificate in DER format
    # basicConstraints and keyUsage make it a proper CA cert.
    if ! cert_err="$("${OPENSSL_BIN}" req -new -x509 \
            -key "${temp_key}" \
            -days 3650 \
            -subj "/CN=${file_base}" \
            -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            -outform DER \
            -out "${ta_file}" 2>&1)"; then
        echo "FAIL (cert)"
        echo "${cert_err}" | sed 's/^/    /'
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: certificate generation failed")
        continue
    fi

    # Step 3: Export private key as PKCS#8 DER
    # genpkey outputs PKCS#8 PEM already; strip the PEM headers and base64-
    # decode to get the identical DER.  `openssl pkey -outform DER` silently
    # fails for composite keys in OpenSSL 4.x, so we avoid it here.
    if ! grep -v '^-----' "${temp_key}" | base64 -d > "${priv_file}" 2>&1; then
        echo "FAIL (pkey export)"
        FAIL=$((FAIL + 1))
        FAILURES+=("${ossl_name}: PKCS#8 DER export failed")
        continue
    fi

    echo "OK"
    PASS=$((PASS + 1))
done

# ─── Pack zip ────────────────────────────────────────────────────────────────
echo ""

mapfile -t artifacts < <(find "${STAGING_DIR}" -maxdepth 1 \
    \( -name "*_ta.der" -o -name "*_priv.der" \) | sort)

ZIP_PATH="${OUTPUT_DIR}/artifacts_certs_r5.zip"
rm -f "${ZIP_PATH}"

if [[ ${#artifacts[@]} -eq 0 ]]; then
    echo "ERROR: no artifacts were generated — zip not created."
    exit 1
fi

if ! zip_err="$(zip -j -q "${ZIP_PATH}" "${artifacts[@]}" 2>&1)"; then
    echo "ERROR: zip failed:"
    echo "${zip_err}" | sed 's/^/  /'
    exit 1
fi

# ─── Summary ─────────────────────────────────────────────────────────────────
echo "==========================================="
printf "Generated: %d/%d algorithms\n" "${PASS}" "$((PASS + FAIL))"

if [[ ${#FAILURES[@]} -gt 0 ]]; then
    echo ""
    echo "Failed:"
    for f in "${FAILURES[@]}"; do
        echo "  - ${f}"
    done
fi

echo ""
echo "Zip:  ${ZIP_PATH}"
echo "Size: $(du -sh "${ZIP_PATH}" | cut -f1)"
echo ""

[[ ${FAIL} -eq 0 ]]
