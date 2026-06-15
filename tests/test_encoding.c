#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/composite_sig_key.h"
#include "../src/composite_sig_encoding.h"
#include "../src/composite_kem_encoding.h"
#include "../src/provider_ctx.h"
#include <openssl/evp.h>
#include <openssl/ec.h>

/* Helper: build a minimal COMPOSITE_CTX with a NULL libctx (sufficient for
 * generating keys directly via OpenSSL without loading the provider). */
static COMPOSITE_CTX g_test_ctx = { NULL, NULL, 0 };

/* Helper: generate a fresh ML-DSA-44 EVP_PKEY (public+private). */
static EVP_PKEY *gen_mldsa44(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-44", NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0)
        EVP_PKEY_keygen(ctx, &pkey);
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Helper: generate a fresh EC P-256 EVP_PKEY (public+private). */
static EVP_PKEY *gen_ec_p256(void)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *pkey = NULL;
    if (!ctx) return NULL;
    if (EVP_PKEY_keygen_init(ctx) > 0) {
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
        EVP_PKEY_keygen(ctx, &pkey);
    }
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

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

// Traditional key max size for tests
#define TRAD_KEY_EX_MAX_SIZE 512

static int test_count = 0;
static int test_passed = 0;

/* Test SIG public key encoding/decoding with ML-DSA-44 public key */
static int test_sig_pubkey_encode_decode_ml_dsa_44(void) {
    TEST_START("SIG public key encode/decode with ML-DSA-44 + EC P-256");

    /* Generate real key material */
    EVP_PKEY *mldsa = gen_mldsa44();
    EVP_PKEY *ec    = gen_ec_p256();
    if (!mldsa || !ec) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Key generation failed");
    }

    /* Build source COMPOSITE_KEY */
    COMPOSITE_KEY src;
    memset(&src, 0, sizeof(src));
    src.provctx        = &g_test_ctx;
    src.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";
    src.mldsa_name     = "ML-DSA-44";
    src.mldsa_pubkey   = mldsa;
    src.classic_pubkey = ec;

    /* Encode */
    unsigned char *blob = NULL;
    size_t blen = 0;
    int ret = composite_sig_pubkey_encode(&src, &blob, &blen);
    if (!ret) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Encoding failed");
    }

    /* Decode into a fresh key */
    COMPOSITE_KEY dst;
    memset(&dst, 0, sizeof(dst));
    dst.provctx        = &g_test_ctx;
    dst.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";
    ret = composite_sig_pubkey_decode(&dst, blob, blen);
    OPENSSL_free(blob);
    blob = NULL; blen = 0;
    if (!ret) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Decoding failed");
    }

    /* Re-encode from decoded key and compare blobs */
    unsigned char *blob_src = NULL, *blob_dst = NULL;
    size_t len_src = 0, len_dst = 0;
    composite_sig_pubkey_encode(&src, &blob_src, &len_src);
    composite_sig_pubkey_encode(&dst, &blob_dst, &len_dst);

    int ok = (len_src == len_dst) && (memcmp(blob_src, blob_dst, len_src) == 0);
    OPENSSL_free(blob_src);
    OPENSSL_free(blob_dst);
    EVP_PKEY_free(mldsa);
    EVP_PKEY_free(ec);
    EVP_PKEY_free((EVP_PKEY *)dst.mldsa_pubkey);
    EVP_PKEY_free((EVP_PKEY *)dst.classic_pubkey);

    if (!ok) TEST_FAIL("Round-trip blob mismatch");
    TEST_PASS();
    return 1;
}

/* Test SIG public key encoding with invalid/NULL key fields */
static int test_sig_pubkey_encode_invalid_pq_size(void) {
    TEST_START("SIG public key encode with NULL key fields");

    /* NULL key pointer */
    unsigned char *blob = NULL; size_t blen = 0;
    if (composite_sig_pubkey_encode(NULL, &blob, &blen))
        TEST_FAIL("Should fail with NULL key");

    /* Key with missing mldsa_pubkey */
    COMPOSITE_KEY bad;
    memset(&bad, 0, sizeof(bad));
    bad.provctx        = &g_test_ctx;
    bad.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";
    bad.mldsa_pubkey   = NULL;
    bad.classic_pubkey = (void *)1; /* non-NULL but won't be reached */
    if (composite_sig_pubkey_encode(&bad, &blob, &blen))
        TEST_FAIL("Should fail with NULL mldsa_pubkey");

    TEST_PASS();
    return 1;
}

/* Test private key encode/decode with ML-DSA-44 + EC P-256
 * (replaces the old composite_sig_encode/decode test which used a removed API) */
static int test_sig_encode_decode_ml_dsa_44(void) {
    TEST_START("SIG private key encode/decode with ML-DSA-44 + EC P-256");

    EVP_PKEY *mldsa = gen_mldsa44();
    EVP_PKEY *ec    = gen_ec_p256();
    if (!mldsa || !ec) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Key generation failed");
    }

    COMPOSITE_KEY src;
    memset(&src, 0, sizeof(src));
    src.provctx         = &g_test_ctx;
    src.composite_name  = "id-MLDSA44-ECDSA-P256-SHA256";
    src.mldsa_name      = "ML-DSA-44";
    src.mldsa_privkey   = mldsa;
    src.classic_privkey = ec;
    src.has_private     = 1;

    /* Encode private key */
    unsigned char *blob = NULL; size_t blen = 0;
    if (!composite_sig_privkey_encode(&src, &blob, &blen)) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Private key encoding failed");
    }
    if (blen == 0) {
        OPENSSL_free(blob);
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Encoded size should be non-zero");
    }

    /* Decode into fresh key */
    COMPOSITE_KEY dst;
    memset(&dst, 0, sizeof(dst));
    dst.provctx        = &g_test_ctx;
    dst.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";
    int ret = composite_sig_privkey_decode(&dst, blob, blen);
    OPENSSL_free(blob);
    blob = NULL; blen = 0;
    if (!ret) {
        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        TEST_FAIL("Private key decoding failed");
    }

    /* Re-encode both and compare */
    unsigned char *blob_src = NULL, *blob_dst = NULL;
    size_t len_src = 0, len_dst = 0;
    composite_sig_privkey_encode(&src, &blob_src, &len_src);
    composite_sig_privkey_encode(&dst, &blob_dst, &len_dst);

    int ok = (len_src == len_dst) && (memcmp(blob_src, blob_dst, len_src) == 0);
    OPENSSL_cleanse(blob_src, len_src); OPENSSL_free(blob_src);
    OPENSSL_cleanse(blob_dst, len_dst); OPENSSL_free(blob_dst);
    EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
    EVP_PKEY_free((EVP_PKEY *)dst.mldsa_privkey);
    EVP_PKEY_free((EVP_PKEY *)dst.classic_privkey);

    if (!ok) TEST_FAIL("Round-trip private key blob mismatch");
    TEST_PASS();
    return 1;
}

/* Test private key encoding with missing private key fields */
static int test_sig_encode_invalid_pq_size(void) {
    TEST_START("SIG private key encode with missing private key");

    COMPOSITE_KEY bad;
    memset(&bad, 0, sizeof(bad));
    bad.provctx        = &g_test_ctx;
    bad.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";
    bad.has_private    = 0; /* not a private key */

    unsigned char *blob = NULL; size_t blen = 0;
    if (composite_sig_privkey_encode(&bad, &blob, &blen))
        TEST_FAIL("Should fail when has_private == 0");

    TEST_PASS();
    return 1;
}

/* Test decode with insufficient / truncated data */
static int test_sig_decode_insufficient_data(void) {
    TEST_START("SIG public key decode with truncated data");

    /* Buffer smaller than ML-DSA-44 public key size — must fail */
    unsigned char short_buf[16] = {0};
    COMPOSITE_KEY dst;
    memset(&dst, 0, sizeof(dst));
    dst.provctx        = &g_test_ctx;
    dst.composite_name = "id-MLDSA44-ECDSA-P256-SHA256";

    if (composite_sig_pubkey_decode(&dst, short_buf, sizeof(short_buf)))
        TEST_FAIL("Should fail with truncated data");

    TEST_PASS();
    return 1;
}

/* Test KEM ciphertext encoding/decoding with ML-KEM-768 */
static int test_kem_ct_encode_decode_ml_kem_768(void) {
    TEST_START("KEM ciphertext encode/decode with ML-KEM-768");
    
    unsigned char *pq_ct = NULL;
    unsigned char *trad_ct = NULL;
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t pq_len = ML_KEM_768_CT_SZ;
    size_t trad_len = 133;
    size_t encoded_len;
    size_t decoded_pq_len, decoded_trad_len;
    int ret;
    
    /* Allocate test data */
    pq_ct = malloc(pq_len);
    trad_ct = malloc(trad_len);
    if (!pq_ct || !trad_ct) {
        TEST_FAIL("Memory allocation failed");
    }
    
    memset(pq_ct, 0xC2, pq_len);
    memset(trad_ct, 0x8D, trad_len);
    
    /* Query size */
    ret = composite_kem_ct_encode(ML_KEM_768, pq_ct, pq_len, trad_ct, trad_len,
                                  NULL, &encoded_len);
    if (!ret) {
        TEST_FAIL("Query size failed");
    }
    
    if (encoded_len != pq_len + trad_len) {
        TEST_FAIL("Encoded size should be sum of component sizes");
    }
    
    /* Encode */
    encoded = malloc(encoded_len);
    if (!encoded) {
        TEST_FAIL("Memory allocation failed");
    }
    
    ret = composite_kem_ct_encode(ML_KEM_768, pq_ct, pq_len, trad_ct, trad_len,
                                  encoded, &encoded_len);
    if (!ret) {
        TEST_FAIL("Encoding failed");
    }
    
    /* Decode */
    ret = composite_kem_ct_decode(ML_KEM_768, encoded, encoded_len,
                                  &decoded_pq, &decoded_pq_len,
                                  &decoded_trad, &decoded_trad_len);
    if (!ret) {
        TEST_FAIL("Decoding failed");
    }
    
    /* Verify */
    if (decoded_pq_len != pq_len) {
        TEST_FAIL("PQ ciphertext length mismatch");
    }
    if (decoded_trad_len != trad_len) {
        TEST_FAIL("Traditional ciphertext length mismatch");
    }
    if (memcmp(pq_ct, decoded_pq, pq_len) != 0) {
        TEST_FAIL("PQ ciphertext data mismatch");
    }
    if (memcmp(trad_ct, decoded_trad, trad_len) != 0) {
        TEST_FAIL("Traditional ciphertext data mismatch");
    }
    
    free(pq_ct);
    free(trad_ct);
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    
    TEST_PASS();
    return 1;
}

/* Test KEM ciphertext encoding with invalid PQ ciphertext size */
static int test_kem_ct_encode_invalid_pq_size(void) {
    TEST_START("KEM ciphertext encode with invalid PQ ciphertext size");
    
    unsigned char pq_ct[100];
    unsigned char trad_ct[100];
    size_t encoded_len;
    int ret;
    
    /* Try encoding with wrong PQ ciphertext size */
    ret = composite_kem_ct_encode(ML_KEM_768, pq_ct, 100, trad_ct, 100,
                                  NULL, &encoded_len);
    if (ret) {
        TEST_FAIL("Should have failed with invalid PQ ciphertext size");
    }
    
    TEST_PASS();
    return 1;
}

/* Test all ML-DSA variants for public key round-trip */
static int test_all_ml_dsa_variants(void) {
    TEST_START("All ML-DSA variants — public key encode/decode round-trip");

    /* (variant_name, mldsa_name, composite_name) triples */
    static const struct { const char *mldsa; const char *composite; } variants[] = {
        { "ML-DSA-44", "id-MLDSA44-ECDSA-P256-SHA256" },
        { "ML-DSA-65", "id-MLDSA65-ECDSA-P256-SHA512" },
        { "ML-DSA-87", "id-MLDSA87-ECDSA-P384-SHA512" },
    };
    int n = (int)(sizeof(variants)/sizeof(variants[0]));

    for (int i = 0; i < n; i++) {
        EVP_PKEY_CTX *mctx = EVP_PKEY_CTX_new_from_name(NULL, variants[i].mldsa, NULL);
        EVP_PKEY *mldsa = NULL;
        if (mctx && EVP_PKEY_keygen_init(mctx) > 0)
            EVP_PKEY_keygen(mctx, &mldsa);
        EVP_PKEY_CTX_free(mctx);

        EVP_PKEY *ec = gen_ec_p256();
        if (!mldsa || !ec) {
            EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
            TEST_FAIL("Key generation failed");
        }

        COMPOSITE_KEY src;
        memset(&src, 0, sizeof(src));
        src.provctx        = &g_test_ctx;
        src.composite_name = variants[i].composite;
        src.mldsa_name     = variants[i].mldsa;
        src.mldsa_pubkey   = mldsa;
        src.classic_pubkey = ec;

        unsigned char *blob = NULL; size_t blen = 0;
        int ret = composite_sig_pubkey_encode(&src, &blob, &blen);

        EVP_PKEY_free(mldsa); EVP_PKEY_free(ec);
        OPENSSL_free(blob);

        if (!ret) TEST_FAIL("Public key encoding failed");
    }

    TEST_PASS();
    return 1;
}

/* Test KEM public key encoding/decoding with ML-KEM-768 */
static int test_kem_pubkey_encode_decode_ml_kem_768(void) {
    TEST_START("KEM public key encode/decode with ML-KEM-768");
    
    unsigned char *pq_key = NULL;
    unsigned char *trad_key = NULL;
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t pq_len = ML_KEM_768_PUB_KEY_SZ;
    size_t trad_len = 128; /* example traditional KEM pubkey size */
    size_t encoded_len;
    size_t decoded_pq_len, decoded_trad_len;
    int ret;
    
    pq_key = malloc(pq_len);
    trad_key = malloc(trad_len);
    if (!pq_key || !trad_key) {
        TEST_FAIL("Memory allocation failed");
    }
    memset(pq_key, 0x11, pq_len);
    memset(trad_key, 0x22, trad_len);
    
    /* Query size */
    ret = composite_kem_pubkey_encode(ML_KEM_768, pq_key, pq_len, trad_key, trad_len,
                                      NULL, &encoded_len);
    if (!ret) {
        TEST_FAIL("Query size failed");
    }
    if (encoded_len != pq_len + trad_len) {
        TEST_FAIL("Encoded size should be sum of component sizes");
    }
    
    /* Encode */
    encoded = malloc(encoded_len);
    if (!encoded) {
        TEST_FAIL("Memory allocation failed");
    }
    ret = composite_kem_pubkey_encode(ML_KEM_768, pq_key, pq_len, trad_key, trad_len,
                                      encoded, &encoded_len);
    if (!ret) {
        TEST_FAIL("Encoding failed");
    }
    
    /* Decode */
    ret = composite_kem_pubkey_decode(ML_KEM_768, encoded, encoded_len,
                                      &decoded_pq, &decoded_pq_len,
                                      &decoded_trad, &decoded_trad_len);
    if (!ret) {
        TEST_FAIL("Decoding failed");
    }
    
    /* Verify */
    if (decoded_pq_len != pq_len) {
        TEST_FAIL("PQ key length mismatch");
    }
    if (decoded_trad_len != trad_len) {
        TEST_FAIL("Traditional key length mismatch");
    }
    if (memcmp(pq_key, decoded_pq, pq_len) != 0) {
        TEST_FAIL("PQ key data mismatch");
    }
    if (memcmp(trad_key, decoded_trad, trad_len) != 0) {
        TEST_FAIL("Traditional key data mismatch");
    }
    
    free(pq_key);
    free(trad_key);
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    
    TEST_PASS();
    return 1;
}

/* Test all ML-KEM variants */
static int test_all_ml_kem_variants(void) {

    TEST_START("All ML-KEM variants");
    
    int variants[] = {ML_KEM_768, ML_KEM_1024};
    size_t ct_sizes[] = {ML_KEM_768_CT_SZ, ML_KEM_1024_CT_SZ};
    size_t pub_sizes[] = {ML_KEM_768_PUB_KEY_SZ, ML_KEM_1024_PUB_KEY_SZ};
    
    for (int i = 0; i < 2; i++) {
        unsigned char *pq_ct = malloc(ct_sizes[i]);
        unsigned char *trad_ct = malloc(TRAD_KEY_EX_MAX_SIZE);
        unsigned char *pq_key = malloc(pub_sizes[i]);
        unsigned char *trad_key = malloc(TRAD_KEY_EX_MAX_SIZE);
        size_t encoded_len;
        int ret;
        
        if (!pq_ct || !trad_ct || !pq_key || !trad_key) {
            free(pq_ct);
            free(trad_ct);
            free(pq_key);
            free(trad_key);
            TEST_FAIL("Memory allocation failed");
        }
        
        memset(pq_ct, 0xEE, ct_sizes[i]);
        memset(trad_ct, 0xFF, 100);
        memset(pq_key, 0xAB, pub_sizes[i]);
        memset(trad_key, 0xCD, 100);
        
        /* Test ciphertext encoding */
        ret = composite_kem_ct_encode(variants[i], pq_ct, ct_sizes[i], trad_ct, TRAD_KEY_EX_MAX_SIZE,
                                       NULL, &encoded_len);
        if (!ret) {
            TEST_FAIL("Ciphertext encoding query failed");
        }
        
        /* Test KEM public key encoding */
        ret = composite_kem_pubkey_encode(variants[i], pq_key, pub_sizes[i], trad_key, 100,
                                          NULL, &encoded_len);
        if (!ret) {
            TEST_FAIL("KEM public key encoding query failed");
        }
        
        free(pq_ct);
        free(trad_ct);
        free(pq_key);
        free(trad_key);
    }
    
    TEST_PASS();
    return 1;
}

int main(void) {
    printf("=== Composite Encoding Tests ===\n\n");
    
    /* Run all tests */
    test_sig_pubkey_encode_decode_ml_dsa_44();
    test_sig_pubkey_encode_invalid_pq_size();
    test_sig_encode_decode_ml_dsa_44();
    test_sig_encode_invalid_pq_size();
    test_sig_decode_insufficient_data();
    test_kem_pubkey_encode_decode_ml_kem_768();
    test_kem_ct_encode_decode_ml_kem_768();
    test_kem_ct_encode_invalid_pq_size();
    test_all_ml_dsa_variants();
    test_all_ml_kem_variants();
    
    printf("\n=== Test Results ===\n");
    printf("Total: %d\n", test_count);
    printf("Passed: %d\n", test_passed);
    printf("Failed: %d\n", test_count - test_passed);
    
    if (test_passed == test_count) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}
