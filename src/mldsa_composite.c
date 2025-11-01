#include "composite_provider.h"
#include <openssl/core_names.h>

/*
 * ML-DSA Composite Signature Algorithms
 * 
 * This file implements the algorithm dispatch for ML-DSA composite signatures.
 * Each composite algorithm combines ML-DSA (Dilithium) with a traditional algorithm.
 *
 * Supported combinations:
 * - ML-DSA-44 + RSA-2048
 * - ML-DSA-44 + ECDSA-P256
 * - ML-DSA-65 + RSA-3072
 * - ML-DSA-65 + ECDSA-P384
 * - ML-DSA-87 + RSA-4096
 * - ML-DSA-87 + ECDSA-P521
 */

const OSSL_ALGORITHM *composite_signature_algorithms(void *provctx)
{
    (void)provctx; /* Unused */
    static const OSSL_ALGORITHM algorithms[] = {
        { COMPOSITE_MLDSA44_RSA2048_NAME, "provider=composite",
          composite_mldsa44_rsa2048_signature_functions, 
          "Composite ML-DSA-44 with RSA-2048" },
        
        { COMPOSITE_MLDSA44_ECDSA_P256_NAME, "provider=composite",
          composite_mldsa44_ecdsa_p256_signature_functions,
          "Composite ML-DSA-44 with ECDSA-P256" },
        
        { COMPOSITE_MLDSA65_RSA3072_NAME, "provider=composite",
          composite_mldsa65_rsa3072_signature_functions,
          "Composite ML-DSA-65 with RSA-3072" },
        
        { COMPOSITE_MLDSA65_ECDSA_P384_NAME, "provider=composite",
          composite_mldsa65_ecdsa_p384_signature_functions,
          "Composite ML-DSA-65 with ECDSA-P384" },
        
        { COMPOSITE_MLDSA87_RSA4096_NAME, "provider=composite",
          composite_mldsa87_rsa4096_signature_functions,
          "Composite ML-DSA-87 with RSA-4096" },
        
        { COMPOSITE_MLDSA87_ECDSA_P521_NAME, "provider=composite",
          composite_mldsa87_ecdsa_p521_signature_functions,
          "Composite ML-DSA-87 with ECDSA-P521" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
