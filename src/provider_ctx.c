#include "provider_ctx.h"

COMPOSITE_CTX *COMPOSITE_PROVIDER_CTX_new(const OSSL_CORE_HANDLE *core_handle, OSSL_LIB_CTX *libctx) {

    COMPOSITE_CTX *provctx = (COMPOSITE_CTX *)malloc(sizeof(COMPOSITE_CTX));

    if (!provctx) {
        return 0;
    }

    memset(provctx, 0, sizeof(*provctx));
    provctx->libctx = OSSL_LIB_CTX_new();

    if (!provctx->libctx) {
        free(provctx);
        return 0;
    }
    return provctx;
}

void COMPOSITE_PROVIDER_CTX_free(COMPOSITE_CTX *ctx) {
    if (ctx) {
        OSSL_LIB_CTX_free(ctx->libctx);
        free(ctx);
    }
}