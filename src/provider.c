#include "provider.h"

/* Provider initialization */
static OSSL_FUNC_provider_gettable_params_fn composite_gettable_params;
static OSSL_FUNC_provider_get_params_fn composite_get_params;
static OSSL_FUNC_provider_query_operation_fn composite_query_operation;

static const OSSL_PARAM composite_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *composite_gettable_params(void *provctx)
{
    (void)provctx; /* Unused */
    return composite_param_types;
}

static int composite_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx; /* Unused */

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, COMPOSITE_PROVIDER_NAME))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, COMPOSITE_PROVIDER_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Composite ML-DSA/ML-KEM Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

const OSSL_ALGORITHM *composite_query_operation(void *provctx, int operation_id,
                                                 int *no_cache)
{
    (void)provctx; /* Unused */
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return composite_signature_algorithms(provctx);
    case OSSL_OP_KEM:
        return composite_kem_algorithms(provctx);
    }

    return NULL;
}

static void composite_teardown(void *provctx)
{
    COMPOSITE_CTX *ctx = (COMPOSITE_CTX *)provctx;
    
    if (ctx != NULL) {
        OSSL_LIB_CTX_free(ctx->libctx);
        free(ctx);
    }
}

/* Provider entry point */
static const OSSL_DISPATCH composite_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))composite_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))composite_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))composite_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))composite_query_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx)
{
    COMPOSITE_CTX *ctx;
    (void)in; /* Unused */

    ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->core_handle = core;
    ctx->libctx = OSSL_LIB_CTX_new();
    if (ctx->libctx == NULL) {
        free(ctx);
        return 0;
    }

    *provctx = ctx;
    *out = composite_dispatch_table;

    return 1;
}
