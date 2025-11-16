#ifndef _COMPOSITE_PROVIDER_H
#define _COMPOSITE_PROVIDER_H

#include "compat.h"

#include "composite_provider.h"
#include "provider_ctx.h"

BEGIN_C_DECLS

#define COMPOSITE_DEBUG(fmt, ...) \
    if (getenv("COMPOSITE_DEBUG")) { \
        printf("[COMPOSITE:DEBUG][%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__); \
    }

#define COMPOSITE_DEBUG0(text) \
    COMPOSITE_DEBUG("%s", text)

#define COMPOSITE_ERROR(fmt, ...) \
    printf("[COMPOSITE:ERROR][%s:%d] " fmt, __func__, __LINE__, ##__VA_ARGS__);



    /*! \brief Initialize a provider.
 *
 * \param core The core handle to use.
 * \param in The input dispatch table.
 * \param out The output dispatch table.
 * \param provctx The provider context.
 * \return 1 on success, 0 on error.
 */
int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx);

END_C_DECLS

#endif /* _COMPOSITE_PROVIDER_H */