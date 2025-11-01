#include "mlkem_composite.h"

/*
 * ML-KEM Composite Key Encapsulation Mechanisms
 * 
 * This file implements the algorithm dispatch for ML-KEM composite KEMs.
 * Each composite algorithm combines ML-KEM (Kyber) with ECDH.
 *
 * Supported combinations:
 * - ML-KEM-512 + ECDH-P256
 * - ML-KEM-768 + ECDH-P384
 * - ML-KEM-1024 + ECDH-P521
 */

const OSSL_ALGORITHM *composite_kem_algorithms(void *provctx)
{
    (void)provctx; /* Unused */
    static const OSSL_ALGORITHM algorithms[] = {
        { COMPOSITE_MLKEM512_ECDH_P256_NAME, "provider=composite",
          composite_mlkem512_ecdh_p256_kem_functions,
          "Composite ML-KEM-512 with ECDH-P256" },
        
        { COMPOSITE_MLKEM768_ECDH_P384_NAME, "provider=composite",
          composite_mlkem768_ecdh_p384_kem_functions,
          "Composite ML-KEM-768 with ECDH-P384" },
        
        { COMPOSITE_MLKEM1024_ECDH_P521_NAME, "provider=composite",
          composite_mlkem1024_ecdh_p521_kem_functions,
          "Composite ML-KEM-1024 with ECDH-P521" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
