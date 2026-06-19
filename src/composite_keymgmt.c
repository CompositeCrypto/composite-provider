/* composite_keymgmt.c — per-algorithm keymgmt dispatch tables */

#include "composite_keymgmt.h"
#include "composite_kem_keymgmt.h"
#include "composite_sig_key.h"

#define KEM_NAMES(ln, sn, oid) ln ":" sn ":" oid

/* -------------------------------------------------------------------------
 * Per-algorithm dispatch tables (18 algorithms)
 * KEYMGMT_DISPATCH_TABLE(ident, SN_MACRO) defined in composite_keymgmt.h
 * --------------------------------------------------------------------- */

/* ML-DSA-44 */
KEYMGMT_DISPATCH_TABLE(mldsa44_rsa2048_pss,     MLDSA44_RSA2048_PSS_SN);
KEYMGMT_DISPATCH_TABLE(mldsa44_rsa2048_pkcs15,  MLDSA44_RSA2048_PKCS15_SN);
KEYMGMT_DISPATCH_TABLE(mldsa44_ed25519,         MLDSA44_ED25519_SN);
KEYMGMT_DISPATCH_TABLE(mldsa44_p256,            MLDSA44_P256_SN);

/* ML-DSA-65 */
KEYMGMT_DISPATCH_TABLE(mldsa65_rsa3072_pss,     MLDSA65_RSA3072_PSS_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_rsa3072_pkcs15,  MLDSA65_RSA3072_PKCS15_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_rsa4096_pss,     MLDSA65_RSA4096_PSS_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_rsa4096_pkcs15,  MLDSA65_RSA4096_PKCS15_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_p256,            MLDSA65_P256_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_p384,            MLDSA65_P384_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_brainpoolp256,   MLDSA65_BRAINPOOLP256_SN);
KEYMGMT_DISPATCH_TABLE(mldsa65_ed25519,         MLDSA65_ED25519_SN);

/* ML-DSA-87 */
KEYMGMT_DISPATCH_TABLE(mldsa87_p384,            MLDSA87_P384_SN);
KEYMGMT_DISPATCH_TABLE(mldsa87_brainpoolp384,   MLDSA87_BRAINPOOLP384_SN);
KEYMGMT_DISPATCH_TABLE(mldsa87_ed448,           MLDSA87_ED448_SN);
KEYMGMT_DISPATCH_TABLE(mldsa87_rsa3072_pss,     MLDSA87_RSA3072_PSS_SN);
KEYMGMT_DISPATCH_TABLE(mldsa87_rsa4096_pss,     MLDSA87_RSA4096_PSS_SN);
KEYMGMT_DISPATCH_TABLE(mldsa87_p521,            MLDSA87_P521_SN);

/* -------------------------------------------------------------------------
 * Algorithm list for the provider
 * --------------------------------------------------------------------- */

const OSSL_ALGORITHM *composite_keymgmt(void *provctx)
{
    (void)provctx;

    static const OSSL_ALGORITHM algorithms[] = {

        /* ML-DSA-44 */
        { PROV_NAMES_MLDSA44_RSA2048_PSS,    "provider=composite",
          ossl_composite_mldsa44_rsa2048_pss_keymgmt_functions,
          "Composite ML-DSA-44 with RSA-PSS-2048-SHA256" },

        { PROV_NAMES_MLDSA44_RSA2048_PKCS15, "provider=composite",
          ossl_composite_mldsa44_rsa2048_pkcs15_keymgmt_functions,
          "Composite ML-DSA-44 with RSA-2048-PKCS15-SHA256" },

        { PROV_NAMES_MLDSA44_ED25519,        "provider=composite",
          ossl_composite_mldsa44_ed25519_keymgmt_functions,
          "Composite ML-DSA-44 with Ed25519-SHA512" },

        { PROV_NAMES_MLDSA44_P256,           "provider=composite",
          ossl_composite_mldsa44_p256_keymgmt_functions,
          "Composite ML-DSA-44 with ECDSA-P256-SHA256" },

        /* ML-DSA-65 */
        { PROV_NAMES_MLDSA65_RSA3072_PSS,    "provider=composite",
          ossl_composite_mldsa65_rsa3072_pss_keymgmt_functions,
          "Composite ML-DSA-65 with RSA-PSS-3072-SHA512" },

        { PROV_NAMES_MLDSA65_RSA3072_PKCS15, "provider=composite",
          ossl_composite_mldsa65_rsa3072_pkcs15_keymgmt_functions,
          "Composite ML-DSA-65 with RSA-3072-PKCS15-SHA512" },

        { PROV_NAMES_MLDSA65_RSA4096_PSS,    "provider=composite",
          ossl_composite_mldsa65_rsa4096_pss_keymgmt_functions,
          "Composite ML-DSA-65 with RSA-PSS-4096-SHA512" },

        { PROV_NAMES_MLDSA65_RSA4096_PKCS15, "provider=composite",
          ossl_composite_mldsa65_rsa4096_pkcs15_keymgmt_functions,
          "Composite ML-DSA-65 with RSA-4096-PKCS15-SHA512" },

        { PROV_NAMES_MLDSA65_P256,           "provider=composite",
          ossl_composite_mldsa65_p256_keymgmt_functions,
          "Composite ML-DSA-65 with ECDSA-P256-SHA512" },

        { PROV_NAMES_MLDSA65_P384,           "provider=composite",
          ossl_composite_mldsa65_p384_keymgmt_functions,
          "Composite ML-DSA-65 with ECDSA-P384-SHA512" },

        { PROV_NAMES_MLDSA65_BRAINPOOLP256,  "provider=composite",
          ossl_composite_mldsa65_brainpoolp256_keymgmt_functions,
          "Composite ML-DSA-65 with ECDSA-Brainpool256-SHA512" },

        { PROV_NAMES_MLDSA65_ED25519,        "provider=composite",
          ossl_composite_mldsa65_ed25519_keymgmt_functions,
          "Composite ML-DSA-65 with Ed25519-SHA512" },

        /* ML-DSA-87 */
        { PROV_NAMES_MLDSA87_P384,           "provider=composite",
          ossl_composite_mldsa87_p384_keymgmt_functions,
          "Composite ML-DSA-87 with ECDSA-P384-SHA512" },

        { PROV_NAMES_MLDSA87_BRAINPOOLP384,  "provider=composite",
          ossl_composite_mldsa87_brainpoolp384_keymgmt_functions,
          "Composite ML-DSA-87 with ECDSA-Brainpool384-SHA512" },

        { PROV_NAMES_MLDSA87_ED448,          "provider=composite",
          ossl_composite_mldsa87_ed448_keymgmt_functions,
          "Composite ML-DSA-87 with Ed448-SHAKE256" },

        { PROV_NAMES_MLDSA87_RSA3072_PSS,    "provider=composite",
          ossl_composite_mldsa87_rsa3072_pss_keymgmt_functions,
          "Composite ML-DSA-87 with RSA-PSS-3072-SHA512" },

        { PROV_NAMES_MLDSA87_RSA4096_PSS,    "provider=composite",
          ossl_composite_mldsa87_rsa4096_pss_keymgmt_functions,
          "Composite ML-DSA-87 with RSA-PSS-4096-SHA512" },

        { PROV_NAMES_MLDSA87_P521,           "provider=composite",
          ossl_composite_mldsa87_p521_keymgmt_functions,
          "Composite ML-DSA-87 with ECDSA-P521-SHA512" },

        /* ML-KEM */
        { KEM_NAMES(MLKEM768_RSA2048_LN, MLKEM768_RSA2048_SN, MLKEM768_RSA2048_OID),
          "provider=composite", mlkem768_rsa2048_functions, NULL },
        { KEM_NAMES(MLKEM768_RSA3072_LN, MLKEM768_RSA3072_SN, MLKEM768_RSA3072_OID),
          "provider=composite", mlkem768_rsa3072_functions, NULL },
        { KEM_NAMES(MLKEM768_RSA4096_LN, MLKEM768_RSA4096_SN, MLKEM768_RSA4096_OID),
          "provider=composite", mlkem768_rsa4096_functions, NULL },
        { KEM_NAMES(MLKEM768_X25519_LN, MLKEM768_X25519_SN, MLKEM768_X25519_OID),
          "provider=composite", mlkem768_x25519_functions, NULL },
        { KEM_NAMES(MLKEM768_P256_LN, MLKEM768_P256_SN, MLKEM768_P256_OID),
          "provider=composite", mlkem768_p256_functions, NULL },
        { KEM_NAMES(MLKEM768_P384_LN, MLKEM768_P384_SN, MLKEM768_P384_OID),
          "provider=composite", mlkem768_p384_functions, NULL },
        { KEM_NAMES(MLKEM768_BRAINPOOLP256_LN, MLKEM768_BRAINPOOLP256_SN, MLKEM768_BRAINPOOLP256_OID),
          "provider=composite", mlkem768_brainpoolp256_functions, NULL },
        { KEM_NAMES(MLKEM1024_RSA3072_LN, MLKEM1024_RSA3072_SN, MLKEM1024_RSA3072_OID),
          "provider=composite", mlkem1024_rsa3072_functions, NULL },
        { KEM_NAMES(MLKEM1024_P384_LN, MLKEM1024_P384_SN, MLKEM1024_P384_OID),
          "provider=composite", mlkem1024_p384_functions, NULL },
        { KEM_NAMES(MLKEM1024_BRAINPOOLP384_LN, MLKEM1024_BRAINPOOLP384_SN, MLKEM1024_BRAINPOOLP384_OID),
          "provider=composite", mlkem1024_brainpoolp384_functions, NULL },
        { KEM_NAMES(MLKEM1024_X448_LN, MLKEM1024_X448_SN, MLKEM1024_X448_OID),
          "provider=composite", mlkem1024_x448_functions, NULL },
        { KEM_NAMES(MLKEM1024_P521_LN, MLKEM1024_P521_SN, MLKEM1024_P521_OID),
          "provider=composite", mlkem1024_p521_functions, NULL },

        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
