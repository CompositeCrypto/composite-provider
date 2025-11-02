#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/composite_encoding.h"

/* Test helper function to print test results */
static void print_test_result(const char *test_name, int passed)
{
    printf("  %s: %s\n", test_name, passed ? "PASSED" : "FAILED");
}

/* Test composite key encoding and decoding */
static int test_composite_key_encoding(void)
{
    unsigned char pq_key[] = "PQ_KEY_DATA_SAMPLE_12345";
    unsigned char trad_key[] = "TRAD_KEY_DATA_67890";
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    int result = 0;

    printf("\nTest 1: Composite Key Encoding/Decoding\n");

    /* Get required size */
    if (!composite_key_encode(pq_key, sizeof(pq_key) - 1, 
                              trad_key, sizeof(trad_key) - 1,
                              NULL, &encoded_len)) {
        print_test_result("Get encoding size", 0);
        return 0;
    }
    print_test_result("Get encoding size", 1);

    /* Allocate buffer and encode */
    encoded = (unsigned char *)malloc(encoded_len);
    if (encoded == NULL) {
        print_test_result("Allocate encoding buffer", 0);
        return 0;
    }

    if (!composite_key_encode(pq_key, sizeof(pq_key) - 1,
                              trad_key, sizeof(trad_key) - 1,
                              encoded, &encoded_len)) {
        print_test_result("Encode composite key", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Encode composite key", 1);

    /* Decode */
    if (!composite_key_decode(encoded, encoded_len,
                              &decoded_pq, &decoded_pq_len,
                              &decoded_trad, &decoded_trad_len)) {
        print_test_result("Decode composite key", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Decode composite key", 1);

    /* Verify decoded data matches original */
    if (decoded_pq_len == sizeof(pq_key) - 1 &&
        memcmp(decoded_pq, pq_key, decoded_pq_len) == 0) {
        print_test_result("Verify PQ key data", 1);
    } else {
        print_test_result("Verify PQ key data", 0);
        goto cleanup;
    }

    if (decoded_trad_len == sizeof(trad_key) - 1 &&
        memcmp(decoded_trad, trad_key, decoded_trad_len) == 0) {
        print_test_result("Verify traditional key data", 1);
    } else {
        print_test_result("Verify traditional key data", 0);
        goto cleanup;
    }

    result = 1;

cleanup:
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    return result;
}

/* Test composite signature encoding and decoding (ASN.1) */
static int test_composite_sig_encoding(void)
{
    unsigned char pq_sig[] = "PQ_SIGNATURE_SAMPLE_DATA_123456789";
    unsigned char trad_sig[] = "TRADITIONAL_SIGNATURE_SAMPLE_DATA";
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    int result = 0;

    printf("\nTest 2: Composite Signature Encoding/Decoding (ASN.1)\n");

    /* Get required size */
    if (!composite_sig_encode(pq_sig, sizeof(pq_sig) - 1,
                              trad_sig, sizeof(trad_sig) - 1,
                              NULL, &encoded_len)) {
        print_test_result("Get encoding size", 0);
        return 0;
    }
    print_test_result("Get encoding size", 1);

    /* Allocate buffer and encode */
    encoded = (unsigned char *)malloc(encoded_len);
    if (encoded == NULL) {
        print_test_result("Allocate encoding buffer", 0);
        return 0;
    }

    if (!composite_sig_encode(pq_sig, sizeof(pq_sig) - 1,
                              trad_sig, sizeof(trad_sig) - 1,
                              encoded, &encoded_len)) {
        print_test_result("Encode composite signature", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Encode composite signature", 1);

    /* Decode */
    if (!composite_sig_decode(encoded, encoded_len,
                              &decoded_pq, &decoded_pq_len,
                              &decoded_trad, &decoded_trad_len)) {
        print_test_result("Decode composite signature", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Decode composite signature", 1);

    /* Verify decoded data matches original */
    if (decoded_pq_len == sizeof(pq_sig) - 1 &&
        memcmp(decoded_pq, pq_sig, decoded_pq_len) == 0) {
        print_test_result("Verify PQ signature data", 1);
    } else {
        print_test_result("Verify PQ signature data", 0);
        goto cleanup;
    }

    if (decoded_trad_len == sizeof(trad_sig) - 1 &&
        memcmp(decoded_trad, trad_sig, decoded_trad_len) == 0) {
        print_test_result("Verify traditional signature data", 1);
    } else {
        print_test_result("Verify traditional signature data", 0);
        goto cleanup;
    }

    result = 1;

cleanup:
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    return result;
}

/* Test composite KEM ciphertext encoding and decoding */
static int test_composite_kem_ct_encoding(void)
{
    unsigned char pq_ct[] = "PQ_CIPHERTEXT_SAMPLE_DATA_ABCDEFGH";
    unsigned char trad_ct[] = "TRAD_CIPHERTEXT_SAMPLE_XYZ";
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    int result = 0;

    printf("\nTest 3: Composite KEM Ciphertext Encoding/Decoding\n");

    /* Get required size */
    if (!composite_kem_ct_encode(pq_ct, sizeof(pq_ct) - 1,
                                 trad_ct, sizeof(trad_ct) - 1,
                                 NULL, &encoded_len)) {
        print_test_result("Get encoding size", 0);
        return 0;
    }
    print_test_result("Get encoding size", 1);

    /* Allocate buffer and encode */
    encoded = (unsigned char *)malloc(encoded_len);
    if (encoded == NULL) {
        print_test_result("Allocate encoding buffer", 0);
        return 0;
    }

    if (!composite_kem_ct_encode(pq_ct, sizeof(pq_ct) - 1,
                                 trad_ct, sizeof(trad_ct) - 1,
                                 encoded, &encoded_len)) {
        print_test_result("Encode composite ciphertext", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Encode composite ciphertext", 1);

    /* Decode */
    if (!composite_kem_ct_decode(encoded, encoded_len,
                                 &decoded_pq, &decoded_pq_len,
                                 &decoded_trad, &decoded_trad_len)) {
        print_test_result("Decode composite ciphertext", 0);
        free(encoded);
        return 0;
    }
    print_test_result("Decode composite ciphertext", 1);

    /* Verify decoded data matches original */
    if (decoded_pq_len == sizeof(pq_ct) - 1 &&
        memcmp(decoded_pq, pq_ct, decoded_pq_len) == 0) {
        print_test_result("Verify PQ ciphertext data", 1);
    } else {
        print_test_result("Verify PQ ciphertext data", 0);
        goto cleanup;
    }

    if (decoded_trad_len == sizeof(trad_ct) - 1 &&
        memcmp(decoded_trad, trad_ct, decoded_trad_len) == 0) {
        print_test_result("Verify traditional ciphertext data", 1);
    } else {
        print_test_result("Verify traditional ciphertext data", 0);
        goto cleanup;
    }

    result = 1;

cleanup:
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    return result;
}

/* Test error handling */
static int test_error_handling(void)
{
    unsigned char data[] = "SAMPLE_DATA";
    unsigned char *out = NULL;
    size_t out_len = 0;
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    int all_passed = 1;

    printf("\nTest 4: Error Handling\n");

    /* Test NULL pointer handling */
    if (composite_key_encode(NULL, 10, data, 10, out, &out_len) == 0) {
        print_test_result("NULL pq_key pointer", 1);
    } else {
        print_test_result("NULL pq_key pointer", 0);
        all_passed = 0;
    }

    if (composite_key_encode(data, 10, NULL, 10, out, &out_len) == 0) {
        print_test_result("NULL trad_key pointer", 1);
    } else {
        print_test_result("NULL trad_key pointer", 0);
        all_passed = 0;
    }

    if (composite_key_decode(NULL, 10, &decoded_pq, &decoded_pq_len,
                             &decoded_trad, &decoded_trad_len) == 0) {
        print_test_result("NULL input pointer for decode", 1);
    } else {
        print_test_result("NULL input pointer for decode", 0);
        all_passed = 0;
    }

    /* Test invalid length handling */
    unsigned char short_buf[4] = {0, 0, 0, 10}; /* Says it has 10 bytes but buffer is too short */
    if (composite_key_decode(short_buf, 4, &decoded_pq, &decoded_pq_len,
                             &decoded_trad, &decoded_trad_len) == 0) {
        print_test_result("Invalid length handling", 1);
    } else {
        print_test_result("Invalid length handling", 0);
        all_passed = 0;
        /* Clean up if decode somehow succeeded */
        free(decoded_pq);
        free(decoded_trad);
    }

    return all_passed;
}

int main(void)
{
    int all_passed = 1;

    printf("===========================================\n");
    printf("Composite Encoding/Decoding Test Suite\n");
    printf("===========================================\n");

    if (!test_composite_key_encoding()) {
        all_passed = 0;
    }

    if (!test_composite_sig_encoding()) {
        all_passed = 0;
    }

    if (!test_composite_kem_ct_encoding()) {
        all_passed = 0;
    }

    if (!test_error_handling()) {
        all_passed = 0;
    }

    printf("\n===========================================\n");
    if (all_passed) {
        printf("All tests PASSED\n");
        printf("===========================================\n");
        return 0;
    } else {
        printf("Some tests FAILED\n");
        printf("===========================================\n");
        return 1;
    }
}
