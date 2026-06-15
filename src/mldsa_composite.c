#include "mldsa_composite.h"

/* Per-variant dispatch tables — one per algorithm */
SIG_DISPATCH_TABLE(mldsa44_rsa2048_pss,      MLDSA44_RSA2048_PSS_SN);
SIG_DISPATCH_TABLE(mldsa44_rsa2048_pkcs15,   MLDSA44_RSA2048_PKCS15_SN);
SIG_DISPATCH_TABLE(mldsa44_ed25519,          MLDSA44_ED25519_SN);
SIG_DISPATCH_TABLE(mldsa44_p256,             MLDSA44_P256_SN);
SIG_DISPATCH_TABLE(mldsa65_rsa3072_pss,      MLDSA65_RSA3072_PSS_SN);
SIG_DISPATCH_TABLE(mldsa65_rsa3072_pkcs15,   MLDSA65_RSA3072_PKCS15_SN);
SIG_DISPATCH_TABLE(mldsa65_rsa4096_pss,      MLDSA65_RSA4096_PSS_SN);
SIG_DISPATCH_TABLE(mldsa65_rsa4096_pkcs15,   MLDSA65_RSA4096_PKCS15_SN);
SIG_DISPATCH_TABLE(mldsa65_p256,             MLDSA65_P256_SN);
SIG_DISPATCH_TABLE(mldsa65_p384,             MLDSA65_P384_SN);
SIG_DISPATCH_TABLE(mldsa65_brainpoolp256,    MLDSA65_BRAINPOOLP256_SN);
SIG_DISPATCH_TABLE(mldsa65_ed25519,          MLDSA65_ED25519_SN);
SIG_DISPATCH_TABLE(mldsa87_p384,             MLDSA87_P384_SN);
SIG_DISPATCH_TABLE(mldsa87_brainpoolp384,    MLDSA87_BRAINPOOLP384_SN);
SIG_DISPATCH_TABLE(mldsa87_ed448,            MLDSA87_ED448_SN);
SIG_DISPATCH_TABLE(mldsa87_rsa3072_pss,      MLDSA87_RSA3072_PSS_SN);
SIG_DISPATCH_TABLE(mldsa87_rsa4096_pss,      MLDSA87_RSA4096_PSS_SN);
SIG_DISPATCH_TABLE(mldsa87_p521,             MLDSA87_P521_SN);

const OSSL_ALGORITHM *composite_signature_algorithms(void *provctx)
{
    (void)provctx; /* Unused */
    
    static const OSSL_ALGORITHM algorithms[] = {

        //
        // ML-DSA-44 Composite Signature Algorithms
        //

        /* ML-DSA-44 */
        { PROV_NAMES_MLDSA44_RSA2048_PSS, "provider=composite",
          composite_mldsa44_rsa2048_pss_signature_functions,
          "Composite ML-DSA-44 with RSA-PSS-2048-SHA256" },

        { PROV_NAMES_MLDSA44_RSA2048_PKCS15, "provider=composite",
          composite_mldsa44_rsa2048_pkcs15_signature_functions,
          "Composite ML-DSA-44 with RSA-PKCS15-2048-SHA256" },

        { PROV_NAMES_MLDSA44_ED25519, "provider=composite",
          composite_mldsa44_ed25519_signature_functions,
          "Composite ML-DSA-44 with Ed25519" },

        { PROV_NAMES_MLDSA44_P256, "provider=composite",
          composite_mldsa44_p256_signature_functions,
          "Composite ML-DSA-44 with ECDSA-P256-SHA256" },

        /* ML-DSA-65 */
        { PROV_NAMES_MLDSA65_RSA3072_PSS, "provider=composite",
          composite_mldsa65_rsa3072_pss_signature_functions,
          "Composite ML-DSA-65 with RSA-PSS-3072-SHA512" },

        { PROV_NAMES_MLDSA65_RSA3072_PKCS15, "provider=composite",
          composite_mldsa65_rsa3072_pkcs15_signature_functions,
          "Composite ML-DSA-65 with RSA-PKCS15-3072-SHA512" },

        { PROV_NAMES_MLDSA65_RSA4096_PSS, "provider=composite",
          composite_mldsa65_rsa4096_pss_signature_functions,
          "Composite ML-DSA-65 with RSA-PSS-4096-SHA512" },

        { PROV_NAMES_MLDSA65_RSA4096_PKCS15, "provider=composite",
          composite_mldsa65_rsa4096_pkcs15_signature_functions,
          "Composite ML-DSA-65 with RSA-PKCS15-4096-SHA512" },

        { PROV_NAMES_MLDSA65_P256, "provider=composite",
          composite_mldsa65_p256_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P256-SHA512" },

        { PROV_NAMES_MLDSA65_P384, "provider=composite",
          composite_mldsa65_p384_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P384-SHA512" },

        { PROV_NAMES_MLDSA65_BRAINPOOLP256, "provider=composite",
          composite_mldsa65_brainpoolp256_signature_functions,
          "Composite ML-DSA-65 with ECDSA-Brainpool256-SHA512" },

        { PROV_NAMES_MLDSA65_ED25519, "provider=composite",
          composite_mldsa65_ed25519_signature_functions,
          "Composite ML-DSA-65 with Ed25519" },

        /* ML-DSA-87 */
        { PROV_NAMES_MLDSA87_P384, "provider=composite",
          composite_mldsa87_p384_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P384-SHA512" },

        { PROV_NAMES_MLDSA87_BRAINPOOLP384, "provider=composite",
          composite_mldsa87_brainpoolp384_signature_functions,
          "Composite ML-DSA-87 with ECDSA-Brainpool384-SHA512" },

        { PROV_NAMES_MLDSA87_ED448, "provider=composite",
          composite_mldsa87_ed448_signature_functions,
          "Composite ML-DSA-87 with Ed448-SHAKE256" },

        { PROV_NAMES_MLDSA87_RSA3072_PSS, "provider=composite",
          composite_mldsa87_rsa3072_pss_signature_functions,
          "Composite ML-DSA-87 with RSA-PSS-3072-SHA512" },

        { PROV_NAMES_MLDSA87_RSA4096_PSS, "provider=composite",
          composite_mldsa87_rsa4096_pss_signature_functions,
          "Composite ML-DSA-87 with RSA-PSS-4096-SHA512" },

        { PROV_NAMES_MLDSA87_P521, "provider=composite",
          composite_mldsa87_p521_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P521-SHA512" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
