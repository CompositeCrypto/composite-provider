#ifndef HEADER_COMPOSITE_SIG_FN_H
#define HEADER_COMPOSITE_SIG_FN_H

#include <string.h>
#include <stdlib.h>

#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bio.h>

#include "composite_provider.h"
#include "composite_sig_key.h"
#include "provider.h"

/* Signature context */
typedef struct composite_sig_ctx_st {
    COMPOSITE_CTX          *provctx;
    const char             *algorithm_name;  /* SN set in per-alg newctx */
    COMPOSITE_KEY          *key;             /* bound in sign/verify_init */
    const COMPOSITE_ALG_INFO *alg_info;      /* cached from algorithm_name */
    EVP_MD_CTX             *evp_ctx;
    BIO                    *msg_bio;        /* accumulates message for digest_sign/verify */
    unsigned char           alg_oid_der[12]; /* DER OID bytes cached at sign_init */
    size_t                  alg_oid_der_len;
    unsigned char           context_string[255]; /* application context (may be empty) */
    size_t                  context_string_len;
} COMPOSITE_SIG_CTX;

/* Base newctx — creates a context and stores the algorithm SN */
void *composite_sig_newctx_base(void *provctx, const char *alg_sn);

/* Shared signature operations declared in composite_sig.c */
void composite_sig_freectx(void *vctx);
int  composite_sig_sign_init(void *vctx, void *vkey, const OSSL_PARAM params[]);
int  composite_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                         size_t sigsize, const unsigned char *tbs, size_t tbslen);
int  composite_sig_verify_init(void *vctx, void *vkey, const OSSL_PARAM params[]);
int  composite_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                           const unsigned char *tbs, size_t tbslen);
int  composite_sig_get_ctx_params(void *vctx, OSSL_PARAM params[]);
const OSSL_PARAM *composite_sig_gettable_ctx_params(void *vctx, void *provctx);
int  composite_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[]);
const OSSL_PARAM *composite_sig_settable_ctx_params(void *vctx, void *provctx);

int  composite_sig_digest_sign_init(void *vctx, const char *mdname,
                                     void *vkey, const OSSL_PARAM params[]);
int  composite_sig_digest_sign_update(void *vctx,
                                       const unsigned char *data, size_t datalen);
int  composite_sig_digest_sign_final(void *vctx, unsigned char *sig,
                                      size_t *siglen, size_t sigsize);
int  composite_sig_digest_verify_init(void *vctx, const char *mdname,
                                       void *vkey, const OSSL_PARAM params[]);
int  composite_sig_digest_verify_update(void *vctx,
                                         const unsigned char *data, size_t datalen);
int  composite_sig_digest_verify_final(void *vctx,
                                        const unsigned char *sig, size_t siglen);

/* Per-algorithm dispatch table macro.
 * full_name — lowercase identifier, e.g. mldsa44_rsa2048_pss
 * sn_macro  — SN string constant, e.g. MLDSA44_RSA2048_PSS_SN
 */
#define SIG_DISPATCH_TABLE(full_name, sn_macro)                                \
    static void *composite_##full_name##_sig_newctx(void *provctx) {           \
        return composite_sig_newctx_base(provctx, sn_macro);                   \
    }                                                                          \
    const OSSL_DISPATCH composite_##full_name##_signature_functions[] = {      \
        { OSSL_FUNC_SIGNATURE_NEWCTX,                                          \
          (void(*)(void))composite_##full_name##_sig_newctx },                 \
        { OSSL_FUNC_SIGNATURE_FREECTX,                                         \
          (void(*)(void))composite_sig_freectx },                              \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT,                                       \
          (void(*)(void))composite_sig_sign_init },                            \
        { OSSL_FUNC_SIGNATURE_SIGN,                                            \
          (void(*)(void))composite_sig_sign },                                 \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT,                                     \
          (void(*)(void))composite_sig_verify_init },                          \
        { OSSL_FUNC_SIGNATURE_VERIFY,                                          \
          (void(*)(void))composite_sig_verify },                               \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,                                  \
          (void(*)(void))composite_sig_get_ctx_params },                       \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,                             \
          (void(*)(void))composite_sig_gettable_ctx_params },                  \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,                                  \
          (void(*)(void))composite_sig_set_ctx_params },                       \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,                             \
          (void(*)(void))composite_sig_settable_ctx_params },                  \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,                                \
          (void(*)(void))composite_sig_digest_sign_init },                     \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,                              \
          (void(*)(void))composite_sig_digest_sign_update },                   \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,                               \
          (void(*)(void))composite_sig_digest_sign_final },                    \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,                              \
          (void(*)(void))composite_sig_digest_verify_init },                   \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,                            \
          (void(*)(void))composite_sig_digest_verify_update },                 \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,                             \
          (void(*)(void))composite_sig_digest_verify_final },                  \
        OSSL_DISPATCH_END                                                      \
    }

#endif /* HEADER_COMPOSITE_SIG_FN_H */
