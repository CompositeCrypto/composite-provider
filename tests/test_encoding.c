#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/composite_encoding.h"

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

/* Test key encoding/decoding with ML-DSA-44 public key */
static int test_key_encode_decode_ml_dsa_44_pub(void) {
    TEST_START("Key encode/decode with ML-DSA-44 public key");
    
    unsigned char *pq_key = NULL;
    unsigned char *trad_key = NULL;
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t pq_len = ML_DSA_44_PUB_KEY_SZ;
    size_t trad_len = 294;
    size_t encoded_len;
    size_t decoded_pq_len, decoded_trad_len;
    int ret;
    
    /* Allocate test data */
    pq_key = malloc(pq_len);
    trad_key = malloc(trad_len);
    if (!pq_key || !trad_key) {
        TEST_FAIL("Memory allocation failed");
    }
    
    memset(pq_key, 0xA4, pq_len);
    memset(trad_key, 0x5A, trad_len);
    
    /* Query size */
    ret = composite_key_encode(ML_DSA_44, pq_key, pq_len, trad_key, trad_len,
                              NULL, &encoded_len);
    if (!ret) {
        TEST_FAIL("Query size failed");
    }
    
    /* Encode */
    encoded = malloc(encoded_len);
    if (!encoded) {
        TEST_FAIL("Memory allocation failed");
    }
    
    ret = composite_key_encode(ML_DSA_44, pq_key, pq_len, trad_key, trad_len,
                              encoded, &encoded_len);
    if (!ret) {
        TEST_FAIL("Encoding failed");
    }
    
    /* Decode */
    ret = composite_key_decode(ML_DSA_44, encoded, encoded_len,
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

/* Test key encoding with invalid PQ key size */
static int test_key_encode_invalid_pq_size(void) {
    TEST_START("Key encode with invalid PQ key size");
    
    unsigned char pq_key[100];
    unsigned char trad_key[100];
    size_t encoded_len;
    int ret;
    
    /* Try encoding with wrong PQ key size */
    ret = composite_key_encode(ML_DSA_44, pq_key, 100, trad_key, 100,
                              NULL, &encoded_len);
    if (ret) {
        TEST_FAIL("Should have failed with invalid PQ key size");
    }
    
    TEST_PASS();
    return 1;
}

/* Test signature encoding/decoding with ML-DSA-44 */
static int test_sig_encode_decode_ml_dsa_44(void) {
    TEST_START("Signature encode/decode with ML-DSA-44");
    
    unsigned char *pq_sig = NULL;
    unsigned char *trad_sig = NULL;
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t pq_len = ML_DSA_44_SIG_SZ;
    size_t trad_len = 256;
    size_t encoded_len;
    size_t decoded_pq_len, decoded_trad_len;
    int ret;
    
    /* Allocate test data */
    pq_sig = malloc(pq_len);
    trad_sig = malloc(trad_len);
    if (!pq_sig || !trad_sig) {
        TEST_FAIL("Memory allocation failed");
    }
    
    memset(pq_sig, 0xB3, pq_len);
    memset(trad_sig, 0x7C, trad_len);
    
    /* Query size */
    ret = composite_sig_encode(ML_DSA_44, pq_sig, pq_len, trad_sig, trad_len,
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
    
    ret = composite_sig_encode(ML_DSA_44, pq_sig, pq_len, trad_sig, trad_len,
                               encoded, &encoded_len);
    if (!ret) {
        TEST_FAIL("Encoding failed");
    }
    
    /* Decode */
    ret = composite_sig_decode(ML_DSA_44, encoded, encoded_len,
                               &decoded_pq, &decoded_pq_len,
                               &decoded_trad, &decoded_trad_len);
    if (!ret) {
        TEST_FAIL("Decoding failed");
    }
    
    /* Verify */
    if (decoded_pq_len != pq_len) {
        TEST_FAIL("PQ signature length mismatch");
    }
    if (decoded_trad_len != trad_len) {
        TEST_FAIL("Traditional signature length mismatch");
    }
    if (memcmp(pq_sig, decoded_pq, pq_len) != 0) {
        TEST_FAIL("PQ signature data mismatch");
    }
    if (memcmp(trad_sig, decoded_trad, trad_len) != 0) {
        TEST_FAIL("Traditional signature data mismatch");
    }
    
    free(pq_sig);
    free(trad_sig);
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    
    TEST_PASS();
    return 1;
}

/* Test signature encoding with invalid PQ signature size */
static int test_sig_encode_invalid_pq_size(void) {
    TEST_START("Signature encode with invalid PQ signature size");
    
    unsigned char pq_sig[100];
    unsigned char trad_sig[100];
    size_t encoded_len;
    int ret;
    
    /* Try encoding with wrong PQ signature size */
    ret = composite_sig_encode(ML_DSA_44, pq_sig, 100, trad_sig, 100,
                               NULL, &encoded_len);
    if (ret) {
        TEST_FAIL("Should have failed with invalid PQ signature size");
    }
    
    TEST_PASS();
    return 1;
}

/* Test signature decoding with insufficient data */
static int test_sig_decode_insufficient_data(void) {
    TEST_START("Signature decode with insufficient data");
    
    unsigned char encoded[100];
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    size_t decoded_pq_len, decoded_trad_len;
    int ret;
    
    /* Try decoding with buffer smaller than ML signature size */
    ret = composite_sig_decode(ML_DSA_44, encoded, 100,
                               &decoded_pq, &decoded_pq_len,
                               &decoded_trad, &decoded_trad_len);
    if (ret) {
        TEST_FAIL("Should have failed with insufficient data");
    }
    
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

/* Test all ML-DSA variants */
static int test_all_ml_dsa_variants(void) {
    TEST_START("All ML-DSA variants");
    
    int variants[] = {ML_DSA_44, ML_DSA_65, ML_DSA_87};
    size_t pub_sizes[] = {ML_DSA_44_PUB_KEY_SZ, ML_DSA_65_PUB_KEY_SZ, ML_DSA_87_PUB_KEY_SZ};
    size_t sig_sizes[] = {ML_DSA_44_SIG_SZ, ML_DSA_65_SIG_SZ, ML_DSA_87_SIG_SZ};
    
    for (int i = 0; i < 3; i++) {
        unsigned char *pq_key = malloc(pub_sizes[i]);
        unsigned char *trad_key = malloc(100);
        unsigned char *pq_sig = malloc(sig_sizes[i]);
        unsigned char *trad_sig = malloc(100);
        size_t encoded_len;
        int ret;
        
        if (!pq_key || !trad_key || !pq_sig || !trad_sig) {
            free(pq_key);
            free(trad_key);
            free(pq_sig);
            free(trad_sig);
            TEST_FAIL("Memory allocation failed");
        }
        
        memset(pq_key, 0xAA, pub_sizes[i]);
        memset(trad_key, 0xBB, 100);
        memset(pq_sig, 0xCC, sig_sizes[i]);
        memset(trad_sig, 0xDD, 100);
        
        /* Test key encoding */
        ret = composite_key_encode(variants[i], pq_key, pub_sizes[i], trad_key, 100,
                                  NULL, &encoded_len);
        if (!ret) {
            TEST_FAIL("Key encoding query failed");
        }
        
        /* Test signature encoding */
        ret = composite_sig_encode(variants[i], pq_sig, sig_sizes[i], trad_sig, 100,
                                   NULL, &encoded_len);
        if (!ret) {
            TEST_FAIL("Signature encoding query failed");
        }
        
        free(pq_key);
        free(trad_key);
        free(pq_sig);
        free(trad_sig);
    }
    
    TEST_PASS();
    return 1;
}

/* Test all ML-KEM variants */
static int test_all_ml_kem_variants(void) {
    TEST_START("All ML-KEM variants");
    
    int variants[] = {ML_KEM_768, ML_KEM_1024};
    size_t ct_sizes[] = {ML_KEM_768_CT_SZ, ML_KEM_1024_CT_SZ};
    
    for (int i = 0; i < 2; i++) {
        unsigned char *pq_ct = malloc(ct_sizes[i]);
        unsigned char *trad_ct = malloc(100);
        size_t encoded_len;
        int ret;
        
        if (!pq_ct || !trad_ct) {
            free(pq_ct);
            free(trad_ct);
            TEST_FAIL("Memory allocation failed");
        }
        
        memset(pq_ct, 0xEE, ct_sizes[i]);
        memset(trad_ct, 0xFF, 100);
        
        /* Test ciphertext encoding */
        ret = composite_kem_ct_encode(variants[i], pq_ct, ct_sizes[i], trad_ct, 100,
                                      NULL, &encoded_len);
        if (!ret) {
            TEST_FAIL("Ciphertext encoding query failed");
        }
        
        free(pq_ct);
        free(trad_ct);
    }
    
    TEST_PASS();
    return 1;
}

int main(void) {
    printf("=== Composite Encoding Tests ===\n\n");
    
    /* Run all tests */
    test_key_encode_decode_ml_dsa_44_pub();
    test_key_encode_invalid_pq_size();
    test_sig_encode_decode_ml_dsa_44();
    test_sig_encode_invalid_pq_size();
    test_sig_decode_insufficient_data();
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
