#ifndef HEADER_COMPOSITE_SIG_FN_H
#define HEADER_COMPOSITE_SIG_FN_H

#include <string.h>
#include <stdlib.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

#include "composite_provider.h"
#include "provider.h"

/* Placeholder signature sizes (these would be calculated based on component algorithms) */
#define COMPOSITE_SIG_SIZE 4096  /* Placeholder: ML-DSA + traditional signature */

/* Signature context structure */
typedef struct composite_sig_ctx_st {
    COMPOSITE_CTX *provctx;
    const char *algorithm_name;
    /* Key material would go here */
    unsigned char *sig_buffer;
    size_t sig_buffer_len;
} COMPOSITE_SIG_CTX;

#define DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define EXTERN_DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[] = { \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx }, \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx }, \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init }, \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify }, \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params }, \
        {0, NULL} \
    }

//                     // ====================
//                     // Signature operations
//                     // ====================

// DECLARE_SIG_DISPATCH_TABLE(mldsa44, rsa2048)
// DECLARE_SIG_DISPATCH_TABLE(mldsa44, ecdsa_p256)
// DECLARE_SIG_DISPATCH_TABLE(mldsa65, rsa3072)
// DECLARE_SIG_DISPATCH_TABLE(mldsa65, ecdsa_p384)
// DECLARE_SIG_DISPATCH_TABLE(mldsa87, rsa4096)
// DECLARE_SIG_DISPATCH_TABLE(mldsa87, ecdsa_p521)

#endif /* HEADER_COMPOSITE_SIG_FN_H */
