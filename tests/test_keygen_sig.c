#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/provider.h>

#include "../include/composite_provider.h"
#include "../src/composite_sig_key.h"
#include "../src/provider_ctx.h"

static int test_count = 0;
static int test_passed = 0;

#define TEST_START(name) \
    do { \
        test_count++; \
        printf("Test %d: %s ... ", test_count, name); \
    } while(0)

#define TEST_PASS() \
    do { \
        test_passed++; \
        printf("PASSED\n"); \
    } while(0)

#define TEST_FAIL(msg) \
    do { \
        printf("FAILED: %s\n", msg); \
        return 0; \
    } while(0)

#define TEST_LOG0(msg) \
    printf("LOG: %s\n", msg);

    #define TEST_LOG(fmt, ...) \
        printf("LOG: " fmt "\n", ##__VA_ARGS__);

/*
 * Helper: detect at runtime if ML-DSA is supported in the current OpenSSL libctx.
 * If not present, composite_signkey_generate is expected to fail (return 0),
 * otherwise it should succeed for supported composite algorithm names.
 */
static int is_mldsa_supported(OSSL_LIB_CTX *libctx) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, DEFAULT_MLDSA44_NAME, NULL);
    if (pctx == NULL) {
        return 0; /* Not available */
    }
    EVP_PKEY_CTX_free(pctx);
    return 1; /* Available */
}

static int test_composite_signkey_generate_null_args(void) {
    TEST_START("composite_signkey_generate with NULL arguments");

    int ret;
    COMPOSITE_KEY *key = composite_signkey_new();

    /* NULL ctx */
    ret = composite_signkey_generate(NULL, key, COMPOSITE_MLDSA44_NISTP256_NAME);
    if (ret) {
        TEST_FAIL("Expected failure with NULL ctx");
    }

    /* NULL key */
    COMPOSITE_CTX dummy_ctx = {0};
    ret = composite_signkey_generate(&dummy_ctx, NULL, COMPOSITE_MLDSA44_NISTP256_NAME);
    if (ret) {
        TEST_FAIL("Expected failure with NULL key");
    }

    /* NULL algorithm */
    ret = composite_signkey_generate(&dummy_ctx, key, NULL);
    if (ret) {
        TEST_FAIL("Expected failure with NULL algorithm");
    }

    composite_signkey_free(key);
    TEST_PASS();
    return 1;
}

static int test_composite_signkey_generate_invalid_algorithm(void) {
    TEST_START("composite_signkey_generate with invalid algorithm name");

    int ret;
    COMPOSITE_KEY *key = composite_signkey_new();

    /* Create a minimal provider ctx with a libctx */
    COMPOSITE_CTX *provctx = (COMPOSITE_CTX *)malloc(sizeof(COMPOSITE_CTX));
    if (!provctx) {
        TEST_FAIL("Memory allocation failed");
    }
    memset(provctx, 0, sizeof(*provctx));
    provctx->libctx = OSSL_LIB_CTX_new();

    ret = composite_signkey_generate(provctx, key, "UNKNOWN-COMPOSITE-ALGO");
    if (ret) {
        OSSL_LIB_CTX_free(provctx->libctx);
        free(provctx);
        composite_signkey_free(key);
        TEST_FAIL("Expected failure with invalid algorithm name");
    }

    OSSL_LIB_CTX_free(provctx->libctx);
    free(provctx);
    composite_signkey_free(key);
    TEST_PASS();
    return 1;
}

static int test_composite_signkey_generate(void) {

    TEST_START("composite_signkey_generate (all algorithms)");

    int ret;
    int expect_success;

    const char *algorithms[] = {
        COMPOSITE_MLDSA44_RSA2048_PSS_NAME,
        COMPOSITE_MLDSA44_RSA2048_NAME,
        COMPOSITE_MLDSA44_ED25519_NAME,
        COMPOSITE_MLDSA44_NISTP256_NAME,
        COMPOSITE_MLDSA65_RSA3072_PSS_NAME,
        COMPOSITE_MLDSA65_RSA3072_NAME,
        COMPOSITE_MLDSA65_RSA4096_PSS_NAME,
        COMPOSITE_MLDSA65_RSA4096_NAME,
        COMPOSITE_MLDSA65_NISTP256_NAME,
        COMPOSITE_MLDSA65_NISTP384_NAME,
        COMPOSITE_MLDSA65_BRAINPOOL256_NAME,
        COMPOSITE_MLDSA65_ED25519_NAME,
        COMPOSITE_MLDSA87_RSA3072_PSS_NAME,
        COMPOSITE_MLDSA87_RSA4096_PSS_NAME,
        COMPOSITE_MLDSA87_NISTP384_NAME,
        COMPOSITE_MLDSA87_BRAINPOOL384_NAME,
        COMPOSITE_MLDSA87_ED448_NAME,
        COMPOSITE_MLDSA87_NISTP521_NAME
    };

    const size_t algorithms_size = sizeof(algorithms) / sizeof(algorithms[0]); // remember to remove commented values */;

    /* Setup composite provider context with a fresh OpenSSL libctx */
    COMPOSITE_CTX *provctx = (COMPOSITE_CTX *)malloc(sizeof(COMPOSITE_CTX));
    if (!provctx) {
        TEST_FAIL("Memory allocation failed (provctx)");
    }
    memset(provctx, 0, sizeof(*provctx));
    provctx->libctx = OSSL_LIB_CTX_new();
    if (!provctx->libctx) {
        free(provctx);
        TEST_FAIL("OSSL_LIB_CTX_new failed");
    }

    /* Runtime capability detection */
    expect_success = is_mldsa_supported(provctx->libctx);

    for (size_t i = 0; i < algorithms_size; i++) {

        // TEST_LOG1("Testing algorithm: %s", algorithms[i]);
        
        COMPOSITE_KEY *key = composite_signkey_new();
        if (!key) {
            OSSL_LIB_CTX_free(provctx->libctx);
            free(provctx);
            TEST_FAIL("composite_signkey_new failed");
        }

        ret = composite_signkey_generate(provctx, key, algorithms[i]);
        if (ret != expect_success) {
            composite_signkey_free(key);
            OSSL_LIB_CTX_free(provctx->libctx);
            free(provctx);
            TEST_FAIL(expect_success ? "Generation should have succeeded" : "Generation should have failed (no ML-DSA support)");
        }

        if (ret) {
            /* On success, ensure components are present */
            EVP_PKEY *ml = NULL, *trad = NULL;
            if (!composite_signkey_get0_components(key, &ml, &trad)) {
                composite_signkey_free(key);
                OSSL_LIB_CTX_free(provctx->libctx);
                free(provctx);
                TEST_FAIL("get0_components failed");
            }
            if (ml == NULL || trad == NULL) {
                composite_signkey_free(key);
                OSSL_LIB_CTX_free(provctx->libctx);
                free(provctx);
                TEST_FAIL("Generated components should be non-NULL");
            }
        }

        composite_signkey_free(key);
    }

    OSSL_LIB_CTX_free(provctx->libctx);
    free(provctx);

    TEST_PASS();
    return 1;
}

int main(void) {
    printf("=== Composite SIG Key Generation Tests ===\n\n");

    test_composite_signkey_generate_null_args();
    test_composite_signkey_generate_invalid_algorithm();
    test_composite_signkey_generate();

    printf("\n=== Test Results ===\n");
    printf("Total: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_count - test_passed);

    if (test_passed == test_count) {
        printf("\n\u2713 All tests passed!\n");
        return 0;
    } else {
        printf("\n\u2717 Some tests failed!\n");
        return 1;
    }
}
