//
// Created by jake maynard on 5/4/26.
//

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/types.h>

#include "compat.h"
#include "test_helpers.h"


int composite_kem_algorithm_fetchable(OSSL_LIB_CTX *ctx, const char *name,
                                      const char *property_query)
{
    EVP_PKEY_CTX *keygen_ctx = EVP_PKEY_CTX_new_from_name(ctx, name,
                                                          property_query);

    if (keygen_ctx == NULL) {
        printf("FAILED: Could not fetch: %s\n", name);
        return 0;
    }
    EVP_PKEY_CTX_free(keygen_ctx);
    return 1;
}
