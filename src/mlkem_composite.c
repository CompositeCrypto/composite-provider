#include "mlkem_composite.h"

/*
 * Following the OpenSSL precedent of putting the slightly friendlier long name
 * (which is actually shorter) first, followed by (in an inconsistent order)
 * the short name and OID.
 */
#define PROV_NAMES_MLKEM768_RSA2048      MLKEM768_RSA2048_LN ":" MLKEM768_RSA2048_SN ":" MLKEM768_RSA2048_OID
#define PROV_NAMES_MLKEM768_RSA3072      MLKEM768_RSA3072_LN ":" MLKEM768_RSA3072_SN ":" MLKEM768_RSA3072_OID
#define PROV_NAMES_MLKEM768_RSA4096      MLKEM768_RSA4096_LN ":" MLKEM768_RSA4096_SN ":" MLKEM768_RSA4096_OID
#define PROV_NAMES_MLKEM768_X25519       MLKEM768_X25519_LN ":" MLKEM768_X25519_SN ":" MLKEM768_X25519_OID
#define PROV_NAMES_MLKEM768_P256         MLKEM768_P256_LN ":" MLKEM768_P256_SN ":" MLKEM768_P256_OID
#define PROV_NAMES_MLKEM768_P384         MLKEM768_P384_LN ":" MLKEM768_P384_SN ":" MLKEM768_P384_OID
#define PROV_NAMES_MLKEM768_BRAINPOOLP256 MLKEM768_BRAINPOOLP256_LN ":" MLKEM768_BRAINPOOLP256_SN ":" MLKEM768_BRAINPOOLP256_OID
#define PROV_NAMES_MLKEM1024_RSA3072     MLKEM1024_RSA3072_LN ":" MLKEM1024_RSA3072_SN ":" MLKEM1024_RSA3072_OID
#define PROV_NAMES_MLKEM1024_P384        MLKEM1024_P384_LN ":" MLKEM1024_P384_SN ":" MLKEM1024_P384_OID
#define PROV_NAMES_MLKEM1024_BRAINPOOLP384 MLKEM1024_BRAINPOOLP384_LN ":" MLKEM1024_BRAINPOOLP384_SN ":" MLKEM1024_BRAINPOOLP384_OID
#define PROV_NAMES_MLKEM1024_X448        MLKEM1024_X448_LN ":" MLKEM1024_X448_SN ":" MLKEM1024_X448_OID
#define PROV_NAMES_MLKEM1024_P521        MLKEM1024_P521_LN ":" MLKEM1024_P521_SN ":" MLKEM1024_P521_OID

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
        { PROV_NAMES_MLKEM768_P384, "provider=composite",
          composite_mlkem768_ecdh_p384_kem_functions,
          "Composite ML-KEM-768 with ECDH-P384" },
        
        { PROV_NAMES_MLKEM1024_P521, "provider=composite",
          composite_mlkem1024_ecdh_p521_kem_functions,
          "Composite ML-KEM-1024 with ECDH-P521" },
        
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
