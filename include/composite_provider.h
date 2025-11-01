#ifndef COMPOSITE_PROVIDER_H
#define COMPOSITE_PROVIDER_H

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/provider.h>

/* Provider name and version */
#define COMPOSITE_PROVIDER_NAME "composite"
#define COMPOSITE_PROVIDER_VERSION "0.0.1"

/* Algorithm identifiers - signatures - rfc */

#define COMPOSITE_MLDSA44_RSA2048_PSS_NAME  "ML-DSA-44-RSA2048-PSS"
#define COMPOSITE_MLDSA44_RSA2048_NAME      "ML-DSA-44-RSA2048"
#define COMPOSITE_MLDSA44_ED25519_NAME      "ML-DSA-44-ED25519"
#define COMPOSITE_MLDSA44_NISTP256_NAME     "ML-DSA-44-NISTP256"

#define COMPOSITE_MLDSA65_RSA3072_PSS_NAME  "ML-DSA-65-RSA3072-PSS"
#define COMPOSITE_MLDSA65_RSA3072_NAME      "ML-DSA-65-RSA3072"
#define COMPOSITE_MLDSA65_RSA4096_PSS_NAME  "ML-DSA-65-RSA4096-PSS"
#define COMPOSITE_MLDSA65_RSA4096_NAME      "ML-DSA-65-RSA4096"
#define COMPOSITE_MLDSA65_NISTP256_NAME     "ML-DSA-65-NISTP256"
#define COMPOSITE_MLDSA65_NISTP384_NAME     "ML-DSA-65-NISTP384"
#define COMPOSITE_MLDSA65_BPOOL256_NAME     "ML-DSA-65-BPOOL256"
#define COMPOSITE_MLDSA65_ED25519_NAME      "ML-DSA-65-ED25519"

#define COMPOSITE_MLDSA87_RSA3072_PSS_NAME  "ML-DSA-87-RSA3072-PSS"
#define COMPOSITE_MLDSA87_NISTP384_NAME     "ML-DSA-87-NISTP384"
#define COMPOSITE_MLDSA87_BPOOL384_NAME     "ML-DSA-87-BPOOL384"
#define COMPOSITE_MLDSA87_ED448_NAME        "ML-DSA-87-ED448"
#define COMPOSITE_MLDSA87_RSA4096_PSS_NAME  "ML-DSA-87-RSA4096-PSS"
#define COMPOSITE_MLDSA87_NISTP512_NAME     "ML-DSA-87-NISTP512"

#define COMPOSITE_MLDSA65_ECDSA_P384_NAME   "ML-DSA-65-ECDSA-P384"
#define COMPOSITE_MLDSA87_RSA4096_NAME      "ML-DSA-87-RSA4096"
#define COMPOSITE_MLDSA87_ECDSA_P521_NAME   "ML-DSA-87-ECDSA-P521"

/* Algorithm identifiers - KEMs - to be updated */

#define COMPOSITE_MLKEM512_ECDH_P256_NAME   "ML-KEM-512-ECDH-P256"
#define COMPOSITE_MLKEM768_ECDH_P384_NAME   "ML-KEM-768-ECDH-P384"
#define COMPOSITE_MLKEM1024_ECDH_P521_NAME  "ML-KEM-1024-ECDH-P521"

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
