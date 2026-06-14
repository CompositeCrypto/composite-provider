#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <stdio.h>

#include "composite_provider.h"

typedef struct {
    const char *name;
    int security_bits;
} KEM_TEST_CASE;

static const KEM_TEST_CASE test_cases[] = {
    { MLKEM768_RSA2048_SN, 112 },
    { MLKEM768_RSA3072_SN, 128 },
    { MLKEM768_RSA4096_SN, 152 },
    { MLKEM768_X25519_SN, 128 },
    { MLKEM768_P256_SN, 128 },
    { MLKEM768_P384_SN, 192 },
    { MLKEM768_BRAINPOOLP256_SN, 128 },
    { MLKEM1024_RSA3072_SN, 128 },
    { MLKEM1024_P384_SN, 192 },
    { MLKEM1024_BRAINPOOLP384_SN, 192 },
    { MLKEM1024_X448_SN, 224 },
    { MLKEM1024_P521_SN, 256 },
};

static int test_algorithm(const KEM_TEST_CASE *test_case)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, test_case->name, "provider=composite");
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0
            || EVP_PKEY_generate(ctx, &pkey) <= 0)
        goto done;

    ok = pkey != NULL
        && EVP_PKEY_is_a(pkey, test_case->name)
        && EVP_PKEY_get_security_bits(pkey) == test_case->security_bits;

done:
    printf("%s: %s\n", test_case->name, ok ? "PASS" : "FAIL");
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int test_kem_operations_not_advertised(void)
{
    EVP_KEM *kem = EVP_KEM_fetch(NULL, test_cases[0].name,
                                 "provider=composite");

    if (kem != NULL) {
        EVP_KEM_free(kem);
        return 0;
    }
    ERR_clear_error();
    return 1;
}

int main(void)
{
    OSSL_PROVIDER *provider = NULL;
    size_t i;
    int ok = 1;

    provider = OSSL_PROVIDER_load(NULL, "composite");
    if (provider == NULL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    ok &= test_kem_operations_not_advertised();
    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++)
        ok &= test_algorithm(&test_cases[i]);

    OSSL_PROVIDER_unload(provider);
    return ok ? 0 : 1;
}
