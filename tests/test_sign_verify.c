/* test_sign_verify.c — unit tests for composite_sig sign / verify */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

#include "../include/composite_provider.h"
#include "../src/composite_sig.h"
#include "../src/composite_sig_key.h"
#include "../src/provider_ctx.h"

static int test_count  = 0;
static int test_passed = 0;

#define TEST_START(name) \
    do { test_count++; printf("Test %d: %s ... ", test_count, (name)); } while(0)

#define TEST_PASS() \
    do { test_passed++; printf("PASSED\n"); } while(0)

#define TEST_FAIL(msg) \
    do { printf("FAILED: %s\n", (msg)); return 0; } while(0)

#define TEST_SKIP(reason) \
    do { test_passed++; printf("SKIPPED (%s)\n", (reason)); return 1; } while(0)

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

static int is_mldsa_supported(OSSL_LIB_CTX *libctx)
{
    EVP_PKEY_CTX *p = EVP_PKEY_CTX_new_from_name(libctx, DEFAULT_MLDSA44_NAME, NULL);
    if (!p) return 0;
    EVP_PKEY_CTX_free(p);
    return 1;
}

static COMPOSITE_KEY *make_key(COMPOSITE_CTX *provctx, const char *alg)
{
    COMPOSITE_KEY *k = composite_signkey_new();
    if (!k) return NULL;
    if (!composite_signkey_generate(provctx, k, alg)) {
        composite_signkey_free(k);
        return NULL;
    }
    return k;
}

/*
 * Core sign + verify helper.
 *
 * ctx_sign / ctx_sign_len  — context string to use when signing   (NULL = empty)
 * ctx_vfy  / ctx_vfy_len   — context string to use when verifying (NULL = empty)
 * expect_ok                — 1 if verify should succeed, 0 if it should fail
 *
 * Returns 1 if the actual outcome matches expect_ok, 0 otherwise.
 */
static int do_sign_verify(COMPOSITE_CTX *provctx, const char *alg,
                           const unsigned char *ctx_sign, size_t ctx_sign_len,
                           const unsigned char *ctx_vfy,  size_t ctx_vfy_len,
                           int expect_ok)
{
    static const unsigned char msg[] = "composite test message 2025";
    const size_t msg_len = sizeof(msg) - 1;

    unsigned char *sig  = NULL;
    size_t         siglen  = 0;
    size_t         sigsize = 0;
    void          *sctx = NULL;
    void          *vctx = NULL;
    COMPOSITE_KEY *key  = NULL;
    int            ok   = 0;

    key = make_key(provctx, alg);
    if (!key) goto done;

    /* ---- sign ---- */
    sctx = composite_sig_newctx_base(provctx, alg);
    if (!sctx) goto done;
    if (!composite_sig_sign_init(sctx, key, NULL)) goto done;

    if (ctx_sign != NULL && ctx_sign_len > 0) {
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                              (void *)ctx_sign, ctx_sign_len),
            OSSL_PARAM_construct_end()
        };
        if (!composite_sig_set_ctx_params(sctx, p)) goto done;
    }

    /* size query */
    if (!composite_sig_sign(sctx, NULL, &sigsize, 0, msg, msg_len)) goto done;
    sig = OPENSSL_malloc(sigsize);
    if (!sig) goto done;
    if (!composite_sig_sign(sctx, sig, &siglen, sigsize, msg, msg_len)) goto done;

    composite_sig_freectx(sctx);
    sctx = NULL;

    /* ---- verify ---- */
    vctx = composite_sig_newctx_base(provctx, alg);
    if (!vctx) goto done;
    if (!composite_sig_verify_init(vctx, key, NULL)) goto done;

    if (ctx_vfy != NULL && ctx_vfy_len > 0) {
        OSSL_PARAM p[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                              (void *)ctx_vfy, ctx_vfy_len),
            OSSL_PARAM_construct_end()
        };
        if (!composite_sig_set_ctx_params(vctx, p)) goto done;
    }

    {
        int vret = composite_sig_verify(vctx, sig, siglen, msg, msg_len);
        ok = ((vret > 0) == (expect_ok > 0));
    }

done:
    if (sctx) composite_sig_freectx(sctx);
    if (vctx) composite_sig_freectx(vctx);
    OPENSSL_free(sig);
    composite_signkey_free(key);
    return ok;
}

/* -------------------------------------------------------------------------
 * Tests
 * ---------------------------------------------------------------------- */

/*
 * Calling composite_sig_sign with sig=NULL must return 1 and write a
 * nonzero value into *siglen (size query).
 */
static int test_sign_size_query(void)
{
    TEST_START("sign size query (sig=NULL returns nonzero length)");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    COMPOSITE_KEY *key = make_key(provctx, MLDSA44_P256_SN);
    if (!key) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_FAIL("keygen failed");
    }

    void *sctx = composite_sig_newctx_base(provctx, MLDSA44_P256_SN);
    if (!sctx || !composite_sig_sign_init(sctx, key, NULL)) {
        if (sctx) composite_sig_freectx(sctx);
        composite_signkey_free(key);
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_FAIL("sign_init failed");
    }

    size_t siglen = 0;
    static const unsigned char msg[] = "x";
    int ret = composite_sig_sign(sctx, NULL, &siglen, 0, msg, sizeof(msg) - 1);

    composite_sig_freectx(sctx);
    composite_signkey_free(key);
    COMPOSITE_PROVIDER_CTX_free(provctx);

    if (!ret || siglen == 0)
        TEST_FAIL("size query should return nonzero length");
    TEST_PASS();
    return 1;
}

/*
 * Sign + verify round-trip, one algorithm per classic component type:
 *   ECDSA     — MLDSA44_P256_SN
 *   RSA-PSS   — MLDSA44_RSA2048_PSS_SN
 *   RSA-PKCS1 — MLDSA65_RSA3072_PKCS15_SN
 *   Ed25519   — MLDSA44_ED25519_SN
 */
static int test_sign_verify_roundtrip(void)
{
    TEST_START("sign+verify round-trip (one per classic type)");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    static const char *algs[] = {
        MLDSA44_P256_SN,
        MLDSA44_RSA2048_PSS_SN,
        MLDSA65_RSA3072_PKCS15_SN,
        MLDSA44_ED25519_SN,
    };
    int n = (int)(sizeof(algs) / sizeof(algs[0]));

    for (int i = 0; i < n; i++) {
        if (!do_sign_verify(provctx, algs[i], NULL, 0, NULL, 0, 1)) {
            COMPOSITE_PROVIDER_CTX_free(provctx);
            printf("FAILED (algorithm: %s)\n", algs[i]);
            return 0;
        }
    }

    COMPOSITE_PROVIDER_CTX_free(provctx);
    TEST_PASS();
    return 1;
}

/*
 * Sign + verify with the same non-empty application context string — must
 * succeed (matching M' on both sides).
 */
static int test_sign_verify_with_context(void)
{
    TEST_START("sign+verify with non-empty matching context string");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    static const unsigned char ctx[] = "my-application-context";
    int ok = do_sign_verify(provctx, MLDSA44_P256_SN,
                            ctx, sizeof(ctx) - 1,
                            ctx, sizeof(ctx) - 1,
                            1 /* expect success */);
    COMPOSITE_PROVIDER_CTX_free(provctx);

    if (!ok) TEST_FAIL("verify should succeed when context strings match");
    TEST_PASS();
    return 1;
}

/*
 * Sign with context "a", verify with context "b" — must fail because M'
 * differs: M' = Prefix || Label || len(ctx) || ctx || PH(M).
 */
static int test_sign_verify_context_mismatch(void)
{
    TEST_START("context string mismatch causes verify failure");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    static const unsigned char ctx_a[] = "context-a";
    static const unsigned char ctx_b[] = "context-b";
    int ok = do_sign_verify(provctx, MLDSA44_P256_SN,
                            ctx_a, sizeof(ctx_a) - 1,
                            ctx_b, sizeof(ctx_b) - 1,
                            0 /* expect failure */);
    COMPOSITE_PROVIDER_CTX_free(provctx);

    if (!ok) TEST_FAIL("verify should fail when context strings differ");
    TEST_PASS();
    return 1;
}

/*
 * Sign with empty context, verify with non-empty context — must fail.
 * Empty context produces M' = ... || 0x00 || PH(M); non-empty produces
 * M' = ... || len || ctx || PH(M).
 */
static int test_sign_verify_empty_vs_nonempty_ctx(void)
{
    TEST_START("empty context vs non-empty context causes verify failure");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    static const unsigned char ctx[] = "nonempty";
    int ok = do_sign_verify(provctx, MLDSA44_P256_SN,
                            NULL, 0,
                            ctx, sizeof(ctx) - 1,
                            0 /* expect failure */);
    COMPOSITE_PROVIDER_CTX_free(provctx);

    if (!ok) TEST_FAIL("empty vs non-empty context should cause verify failure");
    TEST_PASS();
    return 1;
}

/*
 * Sign a message, flip one byte in the signature, then verify — must fail.
 */
static int test_sign_verify_tampered_sig(void)
{
    TEST_START("tampered signature is rejected by verify");

    COMPOSITE_CTX *provctx = COMPOSITE_PROVIDER_CTX_new(NULL, NULL);
    if (!provctx) TEST_FAIL("COMPOSITE_PROVIDER_CTX_new failed");

    if (!is_mldsa_supported(provctx->libctx)) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_SKIP("ML-DSA not available");
    }

    static const unsigned char msg[] = "tamper test message";
    const size_t msg_len = sizeof(msg) - 1;

    unsigned char *sig  = NULL;
    size_t         siglen  = 0;
    size_t         sigsize = 0;
    void          *sctx = NULL;
    int            ret  = 0;

    COMPOSITE_KEY *key = make_key(provctx, MLDSA44_P256_SN);
    if (!key) {
        COMPOSITE_PROVIDER_CTX_free(provctx);
        TEST_FAIL("keygen failed");
    }

    sctx = composite_sig_newctx_base(provctx, MLDSA44_P256_SN);
    if (!sctx || !composite_sig_sign_init(sctx, key, NULL)) goto cleanup;

    if (!composite_sig_sign(sctx, NULL, &sigsize, 0, msg, msg_len)) goto cleanup;
    sig = OPENSSL_malloc(sigsize);
    if (!sig) goto cleanup;
    if (!composite_sig_sign(sctx, sig, &siglen, sigsize, msg, msg_len)) goto cleanup;

    composite_sig_freectx(sctx);
    sctx = NULL;

    /* Flip a byte in the middle of the composite signature */
    sig[siglen / 2] ^= 0xFF;

    {
        void *vctx = composite_sig_newctx_base(provctx, MLDSA44_P256_SN);
        if (!vctx || !composite_sig_verify_init(vctx, key, NULL)) {
            if (vctx) composite_sig_freectx(vctx);
            goto cleanup;
        }
        int vret = composite_sig_verify(vctx, sig, siglen, msg, msg_len);
        composite_sig_freectx(vctx);
        ret = (vret == 0); /* tampered → must NOT verify */
    }

cleanup:
    if (sctx) composite_sig_freectx(sctx);
    OPENSSL_free(sig);
    composite_signkey_free(key);
    COMPOSITE_PROVIDER_CTX_free(provctx);

    if (!ret) TEST_FAIL("tampered signature should not verify");
    TEST_PASS();
    return 1;
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(void)
{
    printf("=== Composite Signature Sign/Verify Tests ===\n\n");

    test_sign_size_query();
    test_sign_verify_roundtrip();
    test_sign_verify_with_context();
    test_sign_verify_context_mismatch();
    test_sign_verify_empty_vs_nonempty_ctx();
    test_sign_verify_tampered_sig();

    printf("\n=== Test Results ===\n");
    printf("Total:  %d\n", test_count);
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
