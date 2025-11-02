#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/composite_encoding.h"

/* Helper function to print hex data */
static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
}

int main(void) {
    int ret;
    unsigned char *pq_key = NULL;
    unsigned char *trad_key = NULL;
    unsigned char *encoded = NULL;
    unsigned char *decoded_pq = NULL;
    unsigned char *decoded_trad = NULL;
    unsigned char *pq_sig = NULL;
    unsigned char *trad_sig = NULL;
    unsigned char *encoded_sig = NULL;
    unsigned char *decoded_pq_sig = NULL;
    unsigned char *decoded_trad_sig = NULL;
    unsigned char *pq_ct = NULL;
    unsigned char *trad_ct = NULL;
    unsigned char *encoded_ct = NULL;
    unsigned char *decoded_pq_ct = NULL;
    unsigned char *decoded_trad_ct = NULL;
    size_t pq_len, trad_len, encoded_len;
    size_t decoded_pq_len, decoded_trad_len;
    
    printf("=== Composite Encoding Example ===\n\n");
    
    /* ========================================
     * Example 1: Key Encoding/Decoding
     * ======================================== */
    printf("--- Example 1: Key Encoding/Decoding ---\n");
    
    /* Allocate and initialize test key data for ML-DSA-44 */
    pq_len = ML_DSA_44_PUB_KEY_SZ;
    trad_len = 294;  /* Example RSA-2048 public key size */
    
    pq_key = (unsigned char *)malloc(pq_len);
    trad_key = (unsigned char *)malloc(trad_len);
    
    if (pq_key == NULL || trad_key == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Fill with test data */
    memset(pq_key, 0xA4, pq_len);
    memset(trad_key, 0x5A, trad_len);
    
    print_hex("PQ Key", pq_key, pq_len);
    print_hex("Traditional Key", trad_key, trad_len);
    
    /* Query required encoding size */
    ret = composite_key_encode(ML_DSA_44, pq_key, pq_len, trad_key, trad_len,
                              NULL, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Failed to query encoding size\n");
        goto cleanup;
    }
    
    printf("Required encoding size: %zu bytes\n", encoded_len);
    
    /* Allocate buffer and encode */
    encoded = (unsigned char *)malloc(encoded_len);
    if (encoded == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    ret = composite_key_encode(ML_DSA_44, pq_key, pq_len, trad_key, trad_len,
                              encoded, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Key encoding failed\n");
        goto cleanup;
    }
    
    print_hex("Encoded Key", encoded, encoded_len);
    
    /* Decode the key */
    ret = composite_key_decode(ML_DSA_44, encoded, encoded_len,
                              &decoded_pq, &decoded_pq_len,
                              &decoded_trad, &decoded_trad_len);
    if (!ret) {
        fprintf(stderr, "Key decoding failed\n");
        goto cleanup;
    }
    
    printf("Decoded PQ key length: %zu bytes\n", decoded_pq_len);
    printf("Decoded traditional key length: %zu bytes\n", decoded_trad_len);
    
    /* Verify decoded data matches original */
    if (decoded_pq_len == pq_len && memcmp(pq_key, decoded_pq, pq_len) == 0 &&
        decoded_trad_len == trad_len && memcmp(trad_key, decoded_trad, trad_len) == 0) {
        printf("✓ Key encoding/decoding successful!\n\n");
    } else {
        fprintf(stderr, "✗ Key verification failed\n\n");
        goto cleanup;
    }
    
    /* ========================================
     * Example 2: Signature Encoding/Decoding
     * ======================================== */
    printf("--- Example 2: Signature Encoding/Decoding ---\n");
    
    /* Allocate and initialize test signature data for ML-DSA-44 */
    pq_len = ML_DSA_44_SIG_SZ;
    trad_len = 256;  /* Example RSA-2048 signature size */
    
    pq_sig = (unsigned char *)malloc(pq_len);
    trad_sig = (unsigned char *)malloc(trad_len);
    
    if (pq_sig == NULL || trad_sig == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Fill with test data */
    memset(pq_sig, 0xB3, pq_len);
    memset(trad_sig, 0x7C, trad_len);
    
    print_hex("PQ Signature", pq_sig, pq_len);
    print_hex("Traditional Signature", trad_sig, trad_len);
    
    /* Query required encoding size */
    ret = composite_sig_encode(ML_DSA_44, pq_sig, pq_len, trad_sig, trad_len,
                               NULL, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Failed to query signature encoding size\n");
        goto cleanup;
    }
    
    printf("Required signature encoding size: %zu bytes\n", encoded_len);
    
    /* Allocate buffer and encode */
    encoded_sig = (unsigned char *)malloc(encoded_len);
    if (encoded_sig == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    ret = composite_sig_encode(ML_DSA_44, pq_sig, pq_len, trad_sig, trad_len,
                               encoded_sig, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Signature encoding failed\n");
        goto cleanup;
    }
    
    print_hex("Encoded Signature", encoded_sig, encoded_len);
    
    /* Decode the signature */
    ret = composite_sig_decode(ML_DSA_44, encoded_sig, encoded_len,
                               &decoded_pq_sig, &decoded_pq_len,
                               &decoded_trad_sig, &decoded_trad_len);
    if (!ret) {
        fprintf(stderr, "Signature decoding failed\n");
        goto cleanup;
    }
    
    printf("Decoded PQ signature length: %zu bytes\n", decoded_pq_len);
    printf("Decoded traditional signature length: %zu bytes\n", decoded_trad_len);
    
    /* Verify decoded data matches original */
    if (decoded_pq_len == pq_len && memcmp(pq_sig, decoded_pq_sig, pq_len) == 0 &&
        decoded_trad_len == trad_len && memcmp(trad_sig, decoded_trad_sig, trad_len) == 0) {
        printf("✓ Signature encoding/decoding successful!\n\n");
    } else {
        fprintf(stderr, "✗ Signature verification failed\n\n");
        goto cleanup;
    }
    
    /* ========================================
     * Example 3: KEM Ciphertext Encoding/Decoding
     * ======================================== */
    printf("--- Example 3: KEM Ciphertext Encoding/Decoding ---\n");
    
    /* Allocate and initialize test ciphertext data for ML-KEM-768 */
    pq_len = ML_KEM_768_CT_SZ;
    trad_len = 133;  /* Example ECDH P-256 ciphertext size */
    
    pq_ct = (unsigned char *)malloc(pq_len);
    trad_ct = (unsigned char *)malloc(trad_len);
    
    if (pq_ct == NULL || trad_ct == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    /* Fill with test data */
    memset(pq_ct, 0xC2, pq_len);
    memset(trad_ct, 0x8D, trad_len);
    
    print_hex("PQ Ciphertext", pq_ct, pq_len);
    print_hex("Traditional Ciphertext", trad_ct, trad_len);
    
    /* Query required encoding size */
    ret = composite_kem_ct_encode(ML_KEM_768, pq_ct, pq_len, trad_ct, trad_len,
                                  NULL, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Failed to query ciphertext encoding size\n");
        goto cleanup;
    }
    
    printf("Required ciphertext encoding size: %zu bytes\n", encoded_len);
    
    /* Allocate buffer and encode */
    encoded_ct = (unsigned char *)malloc(encoded_len);
    if (encoded_ct == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    
    ret = composite_kem_ct_encode(ML_KEM_768, pq_ct, pq_len, trad_ct, trad_len,
                                  encoded_ct, &encoded_len);
    if (!ret) {
        fprintf(stderr, "Ciphertext encoding failed\n");
        goto cleanup;
    }
    
    print_hex("Encoded Ciphertext", encoded_ct, encoded_len);
    
    /* Decode the ciphertext */
    ret = composite_kem_ct_decode(ML_KEM_768, encoded_ct, encoded_len,
                                  &decoded_pq_ct, &decoded_pq_len,
                                  &decoded_trad_ct, &decoded_trad_len);
    if (!ret) {
        fprintf(stderr, "Ciphertext decoding failed\n");
        goto cleanup;
    }
    
    printf("Decoded PQ ciphertext length: %zu bytes\n", decoded_pq_len);
    printf("Decoded traditional ciphertext length: %zu bytes\n", decoded_trad_len);
    
    /* Verify decoded data matches original */
    if (decoded_pq_len == pq_len && memcmp(pq_ct, decoded_pq_ct, pq_len) == 0 &&
        decoded_trad_len == trad_len && memcmp(trad_ct, decoded_trad_ct, trad_len) == 0) {
        printf("✓ Ciphertext encoding/decoding successful!\n\n");
    } else {
        fprintf(stderr, "✗ Ciphertext verification failed\n\n");
        goto cleanup;
    }
    
    printf("=== All examples completed successfully! ===\n");
    
cleanup:
    free(pq_key);
    free(trad_key);
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    free(pq_sig);
    free(trad_sig);
    free(encoded_sig);
    free(decoded_pq_sig);
    free(decoded_trad_sig);
    free(pq_ct);
    free(trad_ct);
    free(encoded_ct);
    free(decoded_pq_ct);
    free(decoded_trad_ct);
    
    return 0;
}
