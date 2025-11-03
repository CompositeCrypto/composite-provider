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

        { COMPOSITE_MLDSA44_RSA2048_PSS_NAME, "provider=composite",
          composite_mldsa44_rsa2048_signature_functions, 
          "Composite ML-DSA-44 with RSAPSS-2048 with SHA-256" },

        { COMPOSITE_MLDSA44_RSA2048_NAME, "provider=composite",
          composite_mldsa44_rsa2048_signature_functions, 
          "Composite ML-DSA-44 with RSA-2048 with SHA-256" },
        
        { COMPOSITE_MLDSA44_ED25519_NAME, "provider=composite",
          composite_mldsa44_ed25519_signature_functions,
          "Composite ML-DSA-44 with ED25519 with SHA-512" },

        { COMPOSITE_MLDSA44_NISTP256_NAME, "provider=composite",
          composite_mldsa44_ecdsa_p256_signature_functions,
          "Composite ML-DSA-44 with ECDSA-P256 with SHA-256" },

        //
        // ML-DSA-65 Composite Signature Algorithms
        //

        { COMPOSITE_MLDSA65_RSA3072_PSS_NAME, "provider=composite",
          composite_mldsa65_rsa3072_signature_functions,
          "Composite ML-DSA-65 with RSAPSS-3072 with SHA-512" },

        { COMPOSITE_MLDSA65_RSA3072_NAME, "provider=composite",
          composite_mldsa65_rsa3072_signature_functions,
          "Composite ML-DSA-65 with RSA-3072 with SHA-512" },

        { COMPOSITE_MLDSA65_RSA4096_PSS_NAME, "provider=composite",
          composite_mldsa65_rsa4096_signature_functions,
          "Composite ML-DSA-65 with RSAPSS-4096 with SHA-512" },

        { COMPOSITE_MLDSA65_RSA4096_NAME, "provider=composite",
          composite_mldsa65_rsa4096_signature_functions,
          "Composite ML-DSA-65 with RSA-4096 with SHA-512" },

        { COMPOSITE_MLDSA65_NISTP256_NAME, "provider=composite",
          composite_mldsa65_ecdsa_p256_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P256 with SHA-512" },

        { COMPOSITE_MLDSA65_NISTP384_NAME, "provider=composite",
          composite_mldsa65_ecdsa_p384_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P384 with SHA-512" },

        { COMPOSITE_MLDSA65_BRAINPOOL256_NAME, "provider=composite",
          composite_mldsa65_ecdsa_brainpool256_signature_functions,
          "Composite ML-DSA-65 with ECDSA-Brainpool256 with SHA-512" },

        //
        // ML-DSA-87 Composite Signature Algorithms
        //
        
        { COMPOSITE_MLDSA87_RSA4096_PSS_NAME, "provider=composite",
          composite_mldsa87_rsa4096_signature_functions,
          "Composite ML-DSA-87 with RSA-4096-PSS with SHA-512" },

        { COMPOSITE_MLDSA87_RSA3072_PSS_NAME, "provider=composite",
          composite_mldsa87_rsa3072_signature_functions,
          "Composite ML-DSA-87 with RSA-3072-PSS with SHA-512" },

        { COMPOSITE_MLDSA87_NISTP384_NAME, "provider=composite",
          composite_mldsa87_ecdsa_p384_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P384 with SHA-512" },

        { COMPOSITE_MLDSA87_BRAINPOOL384_NAME, "provider=composite",
          composite_mldsa87_ecdsa_brainpool384_signature_functions,
          "Composite ML-DSA-87 with ECDSA-Brainpool384 with SHA-512" },

        { COMPOSITE_MLDSA87_ED448_NAME, "provider=composite",
          composite_mldsa87_ed448_signature_functions,
          "Composite ML-DSA-87 with ECDSA-ED448 with SHAKE256" },

        { COMPOSITE_MLDSA87_NISTP521_NAME, "provider=composite",
          composite_mldsa87_ecdsa_p521_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P521 with SHA-512" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
