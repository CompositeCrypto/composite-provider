#ifndef _PROVIDER_H
#define _PROVIDER_H

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

typedef struct composite_prov_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    OSSL_LIB_CTX *libctx;
} COMPOSITE_CTX;

#include "composite_provider.h"

#endif /* _PROVIDER_H */