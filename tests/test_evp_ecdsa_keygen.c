#include <stdio.h>

#include "composite_test.h"

/* Run under LeakSanitizer to catch contexts retained after successful keygen. */
int main(void)
{
    const char *algorithms[] = {
        MLDSA44_P256_SN, MLDSA65_P256_SN, MLDSA65_P384_SN,
        MLDSA65_BRAINPOOLP256_SN, MLDSA87_P384_SN,
        MLDSA87_BRAINPOOLP384_SN, MLDSA87_P521_SN
    };
    COMPOSITE_TEST_PROVIDERS providers = { NULL, NULL };
    size_t i;
    int iteration, ok = 1;

    if (!composite_test_providers_load(&providers)) {
        composite_test_providers_unload(&providers);
        return 1;
    }
    for (i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); i++) {
        int passed = 1;

        for (iteration = 0; iteration < 3; iteration++) {
            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, algorithms[i],
                                                          "provider=composite");
            EVP_PKEY *key = NULL;
            int generated = ctx != NULL && EVP_PKEY_keygen_init(ctx) > 0
                            && EVP_PKEY_generate(ctx, &key) > 0;

            if (generated)
                generated = key != NULL && EVP_PKEY_is_a(key, algorithms[i]);
            if (!generated)
                ERR_print_errors_fp(stderr);
            passed &= generated;
            EVP_PKEY_free(key);
            EVP_PKEY_CTX_free(ctx);
        }
        printf("%s: %s\n", algorithms[i], passed ? "PASS" : "FAIL");
        ok &= passed;
    }
    composite_test_providers_unload(&providers);
    return ok ? 0 : 1;
}
