#include "mldsa_composite.h"


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
