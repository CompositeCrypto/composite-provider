#ifndef _COMPOSITE_PROVIDER_CTX_H
#define _COMPOSITE_PROVIDER_CTX_H

#include "compat.h"

#include <openssl/core_names.h>
#include <openssl/err.h>

BEGIN_C_DECLS

                    // ==========================
                    // Composite Provider Context
                    // ==========================

typedef struct composite_prov_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    OSSL_LIB_CTX *libctx;

    int keytype;

} COMPOSITE_CTX;

                    // ===================
                    // Function Prototypes
                    // ===================

/*! \brief Create a new composite provider context.
 *
 * \param core_handle The core handle to use.
 * \param libctx The library context to use.
 * \return A pointer to the new composite provider context, or NULL on error.
 */
COMPOSITE_CTX *composite_provider_ctx_new(const OSSL_CORE_HANDLE *core_handle, OSSL_LIB_CTX *libctx);

/*!
 * \brief Free a composite provider context.
 *
 * \param ctx The composite provider context to free.
 */
void composite_provider_ctx_free(COMPOSITE_CTX *ctx);

END_C_DECLS

#endif /* _COMPOSITE_PROVIDER_CTX_H */
