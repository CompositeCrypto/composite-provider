#ifndef _COMPOSITE_KEM_H
#define _COMPOSITE_KEM_H

#include "compat.h"
#include "composite_provider.h"
#include "provider.h"

#include <openssl/core_names.h>
#include <openssl/params.h>

#include <string.h>
#include <stdlib.h>

/* Placeholder KEM sizes (these would be calculated based on component algorithms) */
#define COMPOSITE_KEM_CT_SIZE 2048  /* Placeholder: ML-KEM + ECDH ciphertext */
#define COMPOSITE_KEM_SS_SIZE 64    /* Placeholder: combined shared secret */

/* KEM context structure */
typedef struct composite_kem_ctx_st {
    COMPOSITE_CTX *provctx;
    const char *algorithm_name;
    /* Key material would go here */
    unsigned char *shared_secret;
    size_t shared_secret_len;
} COMPOSITE_KEM_CTX;

#define DECLARE_KEM_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_kem_functions[];

#define EXTERN_DECLARE_KEM_DISPATCH_TABLE(alg_name, alg2_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_kem_functions[];

#define KEM_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_kem_functions[] = { \
        { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))composite_kem_newctx }, \
        { OSSL_FUNC_KEM_FREECTX, (void (*)(void))composite_kem_freectx }, \
        { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))composite_kem_encapsulate_init }, \
        { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))composite_kem_encapsulate }, \
        { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))composite_kem_decapsulate_init }, \
        { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))composite_kem_decapsulate }, \
        { OSSL_FUNC_KEM_GET_CTX_PARAMS, (void (*)(void))composite_kem_get_ctx_params }, \
        { OSSL_FUNC_KEM_SET_CTX_PARAMS, (void (*)(void))composite_kem_set_ctx_params }, \
        { 0, NULL } \
    };

#endif /* _COMPOSITE_KEM_H */