#ifndef COMPOSITE_PROVIDER_H
#define COMPOSITE_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* Provider name and version */
#define COMPOSITE_PROVIDER_NAME "composite"
#define COMPOSITE_PROVIDER_VERSION "0.0.1"

/* Default algorithm names - signatures and kems */
#define DEFAULT_MLDSA44_NAME   "ML-DSA-44"
#define DEFAULT_MLDSA65_NAME   "ML-DSA-65"
#define DEFAULT_MLDSA87_NAME   "ML-DSA-87"

#define DEFAULT_MLKEM512_NAME  "ML-KEM-512"
#define DEFAULT_MLKEM768_NAME  "ML-KEM-768"
#define DEFAULT_MLKEM1024_NAME "ML-KEM-1024"

#define DEFAULT_RSAPSS_NAME    "RSA-PSS"
#define DEFAULT_RSA_NAME       "RSA"

#define DEFAULT_ED25519_NAME   "ED25519"
#define DEFAULT_ED448_NAME     "ED448"

#define DEFAULT_ECDSA_NISTP256_NAME "P-256"
#define DEFAULT_ECDSA_NISTP384_NAME "P-384"
#define DEFAULT_ECDSA_NISTP521_NAME "P-521"

#define DEFAULT_ECDSA_BRAINPOOL256_NAME "BRAINPOOL-256"
#define DEFAULT_ECDSA_BRAINPOOL384_NAME "BRAINPOOL-384"

/*
 * For the names below, the short name is longer than the long name.
 * This is what OpenSSL does with other algorithms, e.g. ML-DSA-44
 * where the short name is the OID name (id-ml-dsa-44) and the long
 * name is a friendlier name, effectively remove the "id-" and do
 * capitalization (ML-DSA-44).
 * Do the same here based on this precedent and this comment:
 * https://github.com/openssl/openssl/pull/29163#issuecomment-3544966509
 */

/* Algorithm names and OIDs - signatures - rfc */

#define MLDSA44_RSA2048_PSS_SN          "id-MLDSA44-RSA2048-PSS-SHA256"
#define MLDSA44_RSA2048_PSS_LN          "MLDSA44-RSA2048-PSS-SHA256"
#define MLDSA44_RSA2048_PSS_OID         "1.3.6.1.5.5.7.6.37"

#define MLDSA44_RSA2048_PKCS15_SN       "id-MLDSA44-RSA2048-PKCS15-SHA256"
#define MLDSA44_RSA2048_PKCS15_LN       "MLDSA44-RSA2048-PKCS15-SHA256"
#define MLDSA44_RSA2048_PKCS15_OID      "1.3.6.1.5.5.7.6.38"

#define MLDSA44_ED25519_SN              "id-MLDSA44-Ed25519-SHA512"
#define MLDSA44_ED25519_LN              "MLDSA44-Ed25519-SHA512"
#define MLDSA44_ED25519_OID             "1.3.6.1.5.5.7.6.39"

#define MLDSA44_P256_SN                 "id-MLDSA44-ECDSA-P256-SHA256"
#define MLDSA44_P256_LN                 "MLDSA44-ECDSA-P256-SHA256"
#define MLDSA44_P256_OID                "1.3.6.1.5.5.7.6.40"

#define MLDSA65_RSA3072_PSS_SN          "id-MLDSA65-RSA3072-PSS-SHA512"
#define MLDSA65_RSA3072_PSS_LN          "MLDSA65-RSA3072-PSS-SHA512"
#define MLDSA65_RSA3072_PSS_OID         "1.3.6.1.5.5.7.6.41"

#define MLDSA65_RSA3072_PKCS15_SN       "id-MLDSA65-RSA3072-PKCS15-SHA512"
#define MLDSA65_RSA3072_PKCS15_LN       "MLDSA65-RSA3072-PKCS15-SHA512"
#define MLDSA65_RSA3072_PKCS15_OID      "1.3.6.1.5.5.7.6.42"

#define MLDSA65_RSA4096_PSS_SN          "id-MLDSA65-RSA4096-PSS-SHA512"
#define MLDSA65_RSA4096_PSS_LN          "MLDSA65-RSA4096-PSS-SHA512"
#define MLDSA65_RSA4096_PSS_OID         "1.3.6.1.5.5.7.6.43"

#define MLDSA65_RSA4096_PKCS15_SN       "id-MLDSA65-RSA4096-PKCS15-SHA512"
#define MLDSA65_RSA4096_PKCS15_LN       "MLDSA65-RSA4096-PKCS15-SHA512"
#define MLDSA65_RSA4096_PKCS15_OID      "1.3.6.1.5.5.7.6.44"

#define MLDSA65_P256_SN                 "id-MLDSA65-ECDSA-P256-SHA512"
#define MLDSA65_P256_LN                 "MLDSA65-ECDSA-P256-SHA512"
#define MLDSA65_P256_OID                "1.3.6.1.5.5.7.6.45"

#define MLDSA65_P384_SN                 "id-MLDSA65-ECDSA-P384-SHA512"
#define MLDSA65_P384_LN                 "MLDSA65-ECDSA-P384-SHA512"
#define MLDSA65_P384_OID                "1.3.6.1.5.5.7.6.46"

#define MLDSA65_BRAINPOOLP256_SN        "id-MLDSA65-ECDSA-brainpoolP256r1-SHA512"
#define MLDSA65_BRAINPOOLP256_LN        "MLDSA65-ECDSA-brainpoolP256r1-SHA512"
#define MLDSA65_BRAINPOOLP256_OID       "1.3.6.1.5.5.7.6.47"

#define MLDSA65_ED25519_SN              "id-MLDSA65-Ed25519-SHA512"
#define MLDSA65_ED25519_LN              "MLDSA65-Ed25519-SHA512"
#define MLDSA65_ED25519_OID             "1.3.6.1.5.5.7.6.48"

#define MLDSA87_P384_SN                 "id-MLDSA87-ECDSA-P384-SHA512"
#define MLDSA87_P384_LN                 "MLDSA87-ECDSA-P384-SHA512"
#define MLDSA87_P384_OID                "1.3.6.1.5.5.7.6.49"

#define MLDSA87_BRAINPOOLP384_SN        "id-MLDSA87-ECDSA-brainpoolP384r1-SHA512"
#define MLDSA87_BRAINPOOLP384_LN        "MLDSA87-ECDSA-brainpoolP384r1-SHA512"
#define MLDSA87_BRAINPOOLP384_OID       "1.3.6.1.5.5.7.6.50"

#define MLDSA87_ED448_SN                "id-MLDSA87-Ed448-SHAKE256"
#define MLDSA87_ED448_LN                "MLDSA87-Ed448-SHAKE256"
#define MLDSA87_ED448_OID               "1.3.6.1.5.5.7.6.51"

#define MLDSA87_RSA3072_PSS_SN          "id-MLDSA87-RSA3072-PSS-SHA512"
#define MLDSA87_RSA3072_PSS_LN          "MLDSA87-RSA3072-PSS-SHA512"
#define MLDSA87_RSA3072_PSS_OID         "1.3.6.1.5.5.7.6.52"

#define MLDSA87_RSA4096_PSS_SN          "id-MLDSA87-RSA4096-PSS-SHA512"
#define MLDSA87_RSA4096_PSS_LN          "MLDSA87-RSA4096-PSS-SHA512"
#define MLDSA87_RSA4096_PSS_OID         "1.3.6.1.5.5.7.6.53"

#define MLDSA87_P521_SN                 "id-MLDSA87-ECDSA-P521-SHA512"
#define MLDSA87_P521_LN                 "MLDSA87-ECDSA-P521-SHA512"
#define MLDSA87_P521_OID                "1.3.6.1.5.5.7.6.54"


/* Algorithm names and OIDs - KEMs - rfc */

#define MLKEM768_RSA2048_SN             "id-MLKEM768-RSA2048-SHA3-256"
#define MLKEM768_RSA2048_LN             "MLKEM768-RSA2048-SHA3-256"
#define MLKEM768_RSA2048_OID            "1.3.6.1.5.5.7.6.55"

#define MLKEM768_RSA3072_SN             "id-MLKEM768-RSA3072-SHA3-256"
#define MLKEM768_RSA3072_LN             "MLKEM768-RSA3072-SHA3-256"
#define MLKEM768_RSA3072_OID            "1.3.6.1.5.5.7.6.56"

#define MLKEM768_RSA4096_SN             "id-MLKEM768-RSA4096-SHA3-256"
#define MLKEM768_RSA4096_LN             "MLKEM768-RSA4096-SHA3-256"
#define MLKEM768_RSA4096_OID            "1.3.6.1.5.5.7.6.57"

#define MLKEM768_X25519_SN              "id-MLKEM768-X25519-SHA3-256"
#define MLKEM768_X25519_LN              "MLKEM768-X25519-SHA3-256"
#define MLKEM768_X25519_OID             "1.3.6.1.5.5.7.6.58"

#define MLKEM768_P256_SN                "id-MLKEM768-ECDH-P256-SHA3-256"
#define MLKEM768_P256_LN                "MLKEM768-ECDH-P256-SHA3-256"
#define MLKEM768_P256_OID               "1.3.6.1.5.5.7.6.59"

#define MLKEM768_P384_SN                "id-MLKEM768-ECDH-P384-SHA3-256"
#define MLKEM768_P384_LN                "MLKEM768-ECDH-P384-SHA3-256"
#define MLKEM768_P384_OID               "1.3.6.1.5.5.7.6.60"

#define MLKEM768_BRAINPOOLP256_SN       "id-MLKEM768-ECDH-brainpoolP256r1-SHA3-256"
#define MLKEM768_BRAINPOOLP256_LN       "MLKEM768-ECDH-brainpoolP256r1-SHA3-256"
#define MLKEM768_BRAINPOOLP256_OID      "1.3.6.1.5.5.7.6.61"

#define MLKEM1024_RSA3072_SN            "id-MLKEM1024-RSA3072-SHA3-256"
#define MLKEM1024_RSA3072_LN            "MLKEM1024-RSA3072-SHA3-256"
#define MLKEM1024_RSA3072_OID           "1.3.6.1.5.5.7.6.62"

#define MLKEM1024_P384_SN               "id-MLKEM1024-ECDH-P384-SHA3-256"
#define MLKEM1024_P384_LN               "MLKEM1024-ECDH-P384-SHA3-256"
#define MLKEM1024_P384_OID              "1.3.6.1.5.5.7.6.63"

#define MLKEM1024_BRAINPOOLP384_SN      "id-MLKEM1024-ECDH-brainpoolP384r1-SHA3-256"
#define MLKEM1024_BRAINPOOLP384_LN      "MLKEM1024-ECDH-brainpoolP384r1-SHA3-256"
#define MLKEM1024_BRAINPOOLP384_OID     "1.3.6.1.5.5.7.6.64"

#define MLKEM1024_X448_SN               "id-MLKEM1024-X448-SHA3-256"
#define MLKEM1024_X448_LN               "MLKEM1024-X448-SHA3-256"
#define MLKEM1024_X448_OID              "1.3.6.1.5.5.7.6.65"

#define MLKEM1024_P521_SN               "id-MLKEM1024-ECDH-P521-SHA3-256"
#define MLKEM1024_P521_LN               "MLKEM1024-ECDH-P521-SHA3-256"
#define MLKEM1024_P521_OID              "1.3.6.1.5.5.7.6.66"

/* Function declarations */
const OSSL_ALGORITHM *composite_signature_algorithms(void *provctx);
const OSSL_ALGORITHM *composite_kem_algorithms(void *provctx);

#define DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define EXTERN_DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define DECLARE_KEM_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_kem_functions[];

#define EXTERN_DECLARE_KEM_DISPATCH_TABLE(alg_name, alg2_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_kem_functions[];

// /* Signature operations */
// extern const OSSL_DISPATCH composite_mldsa44_rsa2048_signature_functions[];
// extern const OSSL_DISPATCH composite_mldsa44_ecdsa_p256_signature_functions[];
// extern const OSSL_DISPATCH composite_mldsa65_rsa3072_signature_functions[];
// extern const OSSL_DISPATCH composite_mldsa65_ecdsa_p384_signature_functions[];
// extern const OSSL_DISPATCH composite_mldsa87_rsa4096_signature_functions[];
// extern const OSSL_DISPATCH composite_mldsa87_ecdsa_p521_signature_functions[];

// /* KEM operations */
// extern const OSSL_DISPATCH composite_mlkem512_ecdh_p256_kem_functions[];
// extern const OSSL_DISPATCH composite_mlkem768_ecdh_p384_kem_functions[];
// extern const OSSL_DISPATCH composite_mlkem1024_ecdh_p521_kem_functions[];

#endif /* COMPOSITE_PROVIDER_H */
