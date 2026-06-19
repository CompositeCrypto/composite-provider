//
// Created by jake maynard on 5/4/26.
//

#ifndef COMPOSITE_PROVIDER_TEST_HELPERS_H
#define COMPOSITE_PROVIDER_TEST_HELPERS_H
#include <openssl/types.h>

int composite_kem_algorithm_fetchable(OSSL_LIB_CTX *ctx, const char *name,
                                      const char *property_query);
#endif //COMPOSITE_PROVIDER_TEST_HELPERS_H
