#include "mldsa_composite.h"

/*
 * Following the OpenSSL precedent of putting the slightly friendlier long name
 * (which is actually shorter) first, followed by (in an inconsistent order)
 * the short name and OID.
 */
#define PROV_NAMES_MLDSA44_RSA2048_PSS       MLDSA44_RSA2048_PSS_LN ":" MLDSA44_RSA2048_PSS_SN ":" MLDSA44_RSA2048_PSS_OID
#define PROV_NAMES_MLDSA44_RSA2048_PKCS15    MLDSA44_RSA2048_PKCS15_LN ":" MLDSA44_RSA2048_PKCS15_SN ":" MLDSA44_RSA2048_PKCS15_OID
#define PROV_NAMES_MLDSA44_ED25519           MLDSA44_ED25519_LN ":" MLDSA44_ED25519_SN ":" MLDSA44_ED25519_OID
#define PROV_NAMES_MLDSA44_P256              MLDSA44_P256_LN ":" MLDSA44_P256_SN ":" MLDSA44_P256_OID
#define PROV_NAMES_MLDSA65_RSA3072_PSS       MLDSA65_RSA3072_PSS_LN ":" MLDSA65_RSA3072_PSS_SN ":" MLDSA65_RSA3072_PSS_OID
#define PROV_NAMES_MLDSA65_RSA3072_PKCS15    MLDSA65_RSA3072_PKCS15_LN ":" MLDSA65_RSA3072_PKCS15_SN ":" MLDSA65_RSA3072_PKCS15_OID
#define PROV_NAMES_MLDSA65_RSA4096_PSS       MLDSA65_RSA4096_PSS_LN ":" MLDSA65_RSA4096_PSS_SN ":" MLDSA65_RSA4096_PSS_OID
#define PROV_NAMES_MLDSA65_RSA4096_PKCS15    MLDSA65_RSA4096_PKCS15_LN ":" MLDSA65_RSA4096_PKCS15_SN ":" MLDSA65_RSA4096_PKCS15_OID
#define PROV_NAMES_MLDSA65_P256              MLDSA65_P256_LN ":" MLDSA65_P256_SN ":" MLDSA65_P256_OID
#define PROV_NAMES_MLDSA65_P384              MLDSA65_P384_LN ":" MLDSA65_P384_SN ":" MLDSA65_P384_OID
#define PROV_NAMES_MLDSA65_BRAINPOOLP256     MLDSA65_BRAINPOOLP256_LN ":" MLDSA65_BRAINPOOLP256_SN ":" MLDSA65_BRAINPOOLP256_OID
#define PROV_NAMES_MLDSA65_ED25519           MLDSA65_ED25519_LN ":" MLDSA65_ED25519_SN ":" MLDSA65_ED25519_OID
#define PROV_NAMES_MLDSA87_P384              MLDSA87_P384_LN ":" MLDSA87_P384_SN ":" MLDSA87_P384_OID
#define PROV_NAMES_MLDSA87_BRAINPOOLP384     MLDSA87_BRAINPOOLP384_LN ":" MLDSA87_BRAINPOOLP384_SN ":" MLDSA87_BRAINPOOLP384_OID
#define PROV_NAMES_MLDSA87_ED448             MLDSA87_ED448_LN ":" MLDSA87_ED448_SN ":" MLDSA87_ED448_OID
#define PROV_NAMES_MLDSA87_RSA3072_PSS       MLDSA87_RSA3072_PSS_LN ":" MLDSA87_RSA3072_PSS_SN ":" MLDSA87_RSA3072_PSS_OID
#define PROV_NAMES_MLDSA87_RSA4096_PSS       MLDSA87_RSA4096_PSS_LN ":" MLDSA87_RSA4096_PSS_SN ":" MLDSA87_RSA4096_PSS_OID
#define PROV_NAMES_MLDSA87_P521              MLDSA87_P521_LN ":" MLDSA87_P521_SN ":" MLDSA87_P521_OID

// ========================
// Function implementations
// ========================

const OSSL_ALGORITHM *composite_signature_algorithms(void *provctx)
{
    (void)provctx; /* Unused */
    
    static const OSSL_ALGORITHM algorithms[] = {

        //
        // ML-DSA-44 Composite Signature Algorithms
        //

        { PROV_NAMES_MLDSA44_RSA2048_PSS, "provider=composite",
          composite_mldsa44_rsa_signature_functions, 
          "Composite ML-DSA-44 with RSAPSS-2048 with SHA-256" },

        { PROV_NAMES_MLDSA44_RSA2048_PKCS15, "provider=composite",
          composite_mldsa44_rsa_signature_functions, 
          "Composite ML-DSA-44 with RSA-2048 with SHA-256" },
        
        { PROV_NAMES_MLDSA44_ED25519, "provider=composite",
          composite_mldsa44_ed25519_signature_functions,
          "Composite ML-DSA-44 with ED25519 with SHA-512" },

        { PROV_NAMES_MLDSA44_P256, "provider=composite",
          composite_mldsa44_ecdsa_signature_functions,
          "Composite ML-DSA-44 with ECDSA-P256 with SHA-256" },

        //
        // ML-DSA-65 Composite Signature Algorithms
        //

        { PROV_NAMES_MLDSA65_RSA3072_PSS, "provider=composite",
          composite_mldsa65_rsa_signature_functions,
          "Composite ML-DSA-65 with RSAPSS-3072 with SHA-512" },

        { PROV_NAMES_MLDSA65_RSA3072_PKCS15, "provider=composite",
          composite_mldsa65_rsa_signature_functions,
          "Composite ML-DSA-65 with RSA-3072 with SHA-512" },

        { PROV_NAMES_MLDSA65_RSA4096_PSS, "provider=composite",
          composite_mldsa65_rsa_signature_functions,
          "Composite ML-DSA-65 with RSAPSS-4096 with SHA-512" },

        { PROV_NAMES_MLDSA65_RSA4096_PKCS15, "provider=composite",
          composite_mldsa65_rsa_signature_functions,
          "Composite ML-DSA-65 with RSA-4096 with SHA-512" },

        { PROV_NAMES_MLDSA65_P256, "provider=composite",
          composite_mldsa65_ecdsa_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P256 with SHA-512" },

        { PROV_NAMES_MLDSA65_P384, "provider=composite",
          composite_mldsa65_ecdsa_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P384 with SHA-512" },

        { PROV_NAMES_MLDSA65_BRAINPOOLP256, "provider=composite",
          composite_mldsa65_ecdsa_signature_functions,
          "Composite ML-DSA-65 with ECDSA-Brainpool256 with SHA-512" },

        //
        // ML-DSA-87 Composite Signature Algorithms
        //
        
        { PROV_NAMES_MLDSA87_RSA4096_PSS, "provider=composite",
          composite_mldsa87_rsa_signature_functions,
          "Composite ML-DSA-87 with RSA-4096-PSS with SHA-512" },

        { PROV_NAMES_MLDSA87_RSA3072_PSS, "provider=composite",
          composite_mldsa87_rsa_signature_functions,
          "Composite ML-DSA-87 with RSA-3072-PSS with SHA-512" },

        { PROV_NAMES_MLDSA87_P384, "provider=composite",
          composite_mldsa87_ecdsa_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P384 with SHA-512" },

        { PROV_NAMES_MLDSA87_BRAINPOOLP384, "provider=composite",
          composite_mldsa87_ecdsa_signature_functions,
          "Composite ML-DSA-87 with ECDSA-Brainpool384 with SHA-512" },

        { PROV_NAMES_MLDSA87_ED448, "provider=composite",
          composite_mldsa87_ed448_signature_functions,
          "Composite ML-DSA-87 with ECDSA-ED448 with SHAKE256" },

        { PROV_NAMES_MLDSA87_P521, "provider=composite",
          composite_mldsa87_ecdsa_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P521 with SHA-512" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
