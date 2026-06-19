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

const OSSL_ALGORITHM *composite_kem_algorithms(void *provctx)
{
    (void)provctx; /* Unused */
    static const OSSL_ALGORITHM algorithms[] = {
        { PROV_NAMES_MLKEM768_RSA2048, "provider=composite",
          composite_mlkem768_rsa2048_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_RSA3072, "provider=composite",
          composite_mlkem768_rsa3072_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_RSA4096, "provider=composite",
          composite_mlkem768_rsa4096_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_X25519, "provider=composite",
          composite_mlkem768_x25519_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_P256, "provider=composite",
          composite_mlkem768_ecdh_p256_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_P384, "provider=composite",
          composite_mlkem768_ecdh_p384_kem_functions, NULL },
        { PROV_NAMES_MLKEM768_BRAINPOOLP256, "provider=composite",
          composite_mlkem768_ecdh_brainpool256r1_kem_functions, NULL },
        { PROV_NAMES_MLKEM1024_RSA3072, "provider=composite",
          composite_mlkem1024_rsa3072_kem_functions, NULL },
        { PROV_NAMES_MLKEM1024_P384, "provider=composite",
          composite_mlkem1024_ecdh_p384_kem_functions, NULL },
        { PROV_NAMES_MLKEM1024_BRAINPOOLP384, "provider=composite",
          composite_mlkem1024_ecdh_brainpool384r1_kem_functions, NULL },
        { PROV_NAMES_MLKEM1024_X448, "provider=composite",
          composite_mlkem1024_x448_kem_functions, NULL },
        { PROV_NAMES_MLKEM1024_P521, "provider=composite",
          composite_mlkem1024_ecdh_p521_kem_functions, NULL },
        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
