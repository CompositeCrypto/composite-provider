#include "composite_sig.h"

                    // ============================
                    // Static function declarations
                    // ============================

static OSSL_FUNC_signature_newctx_fn composite_sig_newctx;
static OSSL_FUNC_signature_freectx_fn composite_sig_freectx;
static OSSL_FUNC_signature_sign_init_fn composite_sig_sign_init;
static OSSL_FUNC_signature_sign_fn composite_sig_sign;
static OSSL_FUNC_signature_verify_init_fn composite_sig_verify_init;
static OSSL_FUNC_signature_verify_fn composite_sig_verify;
static OSSL_FUNC_signature_digest_sign_init_fn composite_sig_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_fn composite_sig_digest_sign;
static OSSL_FUNC_signature_digest_verify_init_fn composite_sig_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_fn composite_sig_digest_verify;
static OSSL_FUNC_signature_get_ctx_params_fn composite_sig_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn composite_sig_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn composite_sig_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn composite_sig_settable_ctx_params;

                    // ==================================
                    // Signature function implementations
                    // ==================================

static void *composite_sig_newctx(void *provctx, const char *propq)
{
    COMPOSITE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(COMPOSITE_SIG_CTX));
    (void)propq; /* Unused */
    
    if (ctx == NULL)
        return NULL;

    memset(ctx, 0, sizeof(COMPOSITE_SIG_CTX));
    ctx->provctx = (COMPOSITE_CTX *)provctx;
    
    return ctx;
}

static void composite_sig_freectx(void *ctx)
{
    COMPOSITE_SIG_CTX *sig_ctx = (COMPOSITE_SIG_CTX *)ctx;
    
    if (sig_ctx != NULL) {
        if (sig_ctx->sig_buffer != NULL) {
            memset(sig_ctx->sig_buffer, 0, sig_ctx->sig_buffer_len);
            free(sig_ctx->sig_buffer);
        }
        free(sig_ctx);
    }
}

static int composite_sig_sign_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *sig_ctx = (COMPOSITE_SIG_CTX *)ctx;
    (void)params; /* Unused */
    
    if (sig_ctx == NULL || provkey == NULL)
        return 0;
    
    /* Initialize signing operation */
    return 1;
}

static int composite_sig_sign(void *ctx, unsigned char *sig, size_t *siglen,
                              size_t sigsize, const unsigned char *tbs,
                              size_t tbslen)
{
    COMPOSITE_SIG_CTX *sig_ctx = (COMPOSITE_SIG_CTX *)ctx;
    (void)tbs; /* Unused */
    (void)tbslen; /* Unused */
    
    if (sig_ctx == NULL)
        return 0;

    /* 
     * Composite signature format:
     * For ML-DSA composite, combine ML-DSA and traditional signature
     * This is a placeholder that would perform actual signing
     */
    
    if (sig == NULL) {
        /* Return required signature size */

        *siglen = COMPOSITE_SIG_SIZE;
        return 1;
    }

    if (sigsize < COMPOSITE_SIG_SIZE)
        return 0;

    /* Placeholder: actual signing would happen here */
    memset(sig, 0, COMPOSITE_SIG_SIZE);
    *siglen = COMPOSITE_SIG_SIZE;
    


    return 1;
}

static int composite_sig_verify_init(void *ctx, void *provkey, const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *sig_ctx = (COMPOSITE_SIG_CTX *)ctx;
    (void)params; /* Unused */
    
    if (sig_ctx == NULL || provkey == NULL)
        return 0;
    
    /* Initialize verification operation */
    return 1;
}

static int composite_sig_verify(void *ctx, const unsigned char *sig, size_t siglen,
                                const unsigned char *tbs, size_t tbslen)
{
    COMPOSITE_SIG_CTX *sig_ctx = (COMPOSITE_SIG_CTX *)ctx;
    (void)siglen; /* Unused */
    (void)tbs; /* Unused */
    (void)tbslen; /* Unused */
    
    if (sig_ctx == NULL || sig == NULL)
        return 0;

    /* Placeholder: actual verification would happen here */
    return 1;
}

static int composite_sig_digest_sign_init(void *ctx, const char *mdname,
                                          void *provkey, const OSSL_PARAM params[])
{
    (void)mdname; /* Unused */
    return composite_sig_sign_init(ctx, provkey, params);
}

static int composite_sig_digest_sign(void *ctx, unsigned char *sig, size_t *siglen,
                                     size_t sigsize, const unsigned char *tbs,
                                     size_t tbslen)
{
    return composite_sig_sign(ctx, sig, siglen, sigsize, tbs, tbslen);
}

static int composite_sig_digest_verify_init(void *ctx, const char *mdname,
                                            void *provkey, const OSSL_PARAM params[])
{
    (void)mdname; /* Unused */
    return composite_sig_verify_init(ctx, provkey, params);
}

static int composite_sig_digest_verify(void *ctx, const unsigned char *sig,
                                       size_t siglen, const unsigned char *tbs,
                                       size_t tbslen)
{
    return composite_sig_verify(ctx, sig, siglen, tbs, tbslen);
}

static int composite_sig_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    (void)ctx; /* Unused */
    (void)params; /* Unused */
    /* Get context parameters */
    return 1;
}

static const OSSL_PARAM composite_get_ctx_params_list[] = {
    /*got this values from default provider*/
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *
composite_sig_gettable_ctx_params(ossl_unused void *vpoqs_sigctx,
                            ossl_unused void *vctx) {
    return composite_get_ctx_params_list;
}

static int composite_sig_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
    (void)ctx; /* Unused */
    (void)params; /* Unused */
    /* Set context parameters */
    return 1;
}

static const OSSL_PARAM composite_set_ctx_params_list[] = {
    /*got this values from default provider*/
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, NULL, 0),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, NULL),
    OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *
composite_sig_settable_ctx_params(ossl_unused void *vpsm2ctx,
                            ossl_unused void *provctx) {
    return composite_set_ctx_params_list;
}

                        // ===============
                        // Dispatch Tables
                        // ===============

// SIG_DISPATCH_TABLE(mldsa44, rsa2048);
// SIG_DISPATCH_TABLE(mldsa44, rsapss);
SIG_DISPATCH_TABLE(mldsa44, rsa);
// SIG_DISPATCH_TABLE(mldsa44, ecdsa_p256);
SIG_DISPATCH_TABLE(mldsa44, ecdsa);
SIG_DISPATCH_TABLE(mldsa44, ed25519);

// SIG_DISPATCH_TABLE(mldsa65, rsa3072);
SIG_DISPATCH_TABLE(mldsa65, rsa);
// SIG_DISPATCH_TABLE(mldsa65, ecdsa_p384);
SIG_DISPATCH_TABLE(mldsa65, ecdsa);
SIG_DISPATCH_TABLE(mldsa65, ed25519);


// SIG_DISPATCH_TABLE(mldsa87, rsa4096);
SIG_DISPATCH_TABLE(mldsa87, rsa);
SIG_DISPATCH_TABLE(mldsa87, ecdsa);
SIG_DISPATCH_TABLE(mldsa87, ed448);

// Use a custom dispatch table if special functions are needed
// const OSSL_DISPATCH composite_mldsa44_rsa2048_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };

// const OSSL_DISPATCH composite_mldsa44_ecdsa_p256_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };

// const OSSL_DISPATCH composite_mldsa65_rsa3072_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };

// const OSSL_DISPATCH composite_mldsa65_ecdsa_p384_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };

// const OSSL_DISPATCH composite_mldsa87_rsa4096_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };

// const OSSL_DISPATCH composite_mldsa87_ecdsa_p521_signature_functions[] = {
//     { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx },
//     { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx },
//     { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init },
//     { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign },
//     { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init },
//     { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init },
//     { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify },
//     { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params },
//     { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params },
//     { 0, NULL }
// };
