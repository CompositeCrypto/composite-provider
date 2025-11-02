#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/composite_encoding.h"

/*
 * Example: Using Composite Encoding/Decoding Functions
 * 
 * This example demonstrates how to use the composite encoding and
 * decoding functions for keys, signatures, and KEM ciphertexts.
 */

void example_key_encoding(void)
{
    printf("Example 1: Composite Key Encoding/Decoding\n");
    printf("===========================================\n\n");

    /* Simulated key data (in real use, these would be actual keys) */
    unsigned char pq_key[] = "ML-DSA-44-KEY-DATA-SAMPLE";
    unsigned char trad_key[] = "RSA-2048-KEY-DATA";
    
    /* Step 1: Determine required buffer size */
    size_t encoded_len = 0;
    if (!composite_key_encode(pq_key, sizeof(pq_key) - 1,
                              trad_key, sizeof(trad_key) - 1,
                              NULL, &encoded_len)) {
        printf("Error: Failed to get encoding size\n");
        return;
    }
    printf("Required buffer size: %zu bytes\n", encoded_len);
    
    /* Step 2: Allocate buffer and encode */
    unsigned char *encoded = malloc(encoded_len);
    if (!encoded) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    
    if (!composite_key_encode(pq_key, sizeof(pq_key) - 1,
                              trad_key, sizeof(trad_key) - 1,
                              encoded, &encoded_len)) {
        printf("Error: Encoding failed\n");
        free(encoded);
        return;
    }
    printf("Successfully encoded composite key (%zu bytes)\n", encoded_len);
    
    /* Step 3: Decode the key */
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    
    if (!composite_key_decode(encoded, encoded_len,
                              &decoded_pq, &decoded_pq_len,
                              &decoded_trad, &decoded_trad_len)) {
        printf("Error: Decoding failed\n");
        free(encoded);
        return;
    }
    
    printf("Successfully decoded:\n");
    printf("  PQ key: %zu bytes\n", decoded_pq_len);
    printf("  Traditional key: %zu bytes\n", decoded_trad_len);
    
    /* Verify the data */
    if (memcmp(decoded_pq, pq_key, decoded_pq_len) == 0 &&
        memcmp(decoded_trad, trad_key, decoded_trad_len) == 0) {
        printf("✓ Verification successful: decoded data matches original\n");
    }
    
    /* Cleanup */
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    printf("\n");
}

void example_signature_encoding(void)
{
    printf("Example 2: Composite Signature Encoding/Decoding (ASN.1)\n");
    printf("=========================================================\n\n");

    /* Simulated signature data */
    unsigned char pq_sig[] = "ML-DSA-SIGNATURE-DATA";
    unsigned char trad_sig[] = "ECDSA-SIGNATURE-DATA";
    
    /* Step 1: Get required size */
    size_t encoded_len = 0;
    if (!composite_sig_encode(pq_sig, sizeof(pq_sig) - 1,
                              trad_sig, sizeof(trad_sig) - 1,
                              NULL, &encoded_len)) {
        printf("Error: Failed to get encoding size\n");
        return;
    }
    printf("Required ASN.1 DER buffer size: %zu bytes\n", encoded_len);
    
    /* Step 2: Encode using ASN.1 */
    unsigned char *encoded = malloc(encoded_len);
    if (!encoded) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    
    if (!composite_sig_encode(pq_sig, sizeof(pq_sig) - 1,
                              trad_sig, sizeof(trad_sig) - 1,
                              encoded, &encoded_len)) {
        printf("Error: Encoding failed\n");
        free(encoded);
        return;
    }
    printf("Successfully encoded composite signature (%zu bytes ASN.1 DER)\n", encoded_len);
    
    /* Step 3: Decode from ASN.1 */
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    
    if (!composite_sig_decode(encoded, encoded_len,
                              &decoded_pq, &decoded_pq_len,
                              &decoded_trad, &decoded_trad_len)) {
        printf("Error: Decoding failed\n");
        free(encoded);
        return;
    }
    
    printf("Successfully decoded from ASN.1:\n");
    printf("  PQ signature: %zu bytes\n", decoded_pq_len);
    printf("  Traditional signature: %zu bytes\n", decoded_trad_len);
    
    /* Verify */
    if (memcmp(decoded_pq, pq_sig, decoded_pq_len) == 0 &&
        memcmp(decoded_trad, trad_sig, decoded_trad_len) == 0) {
        printf("✓ Verification successful: decoded signature matches original\n");
    }
    
    /* Cleanup */
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    printf("\n");
}

void example_kem_ct_encoding(void)
{
    printf("Example 3: Composite KEM Ciphertext Encoding/Decoding\n");
    printf("======================================================\n\n");

    /* Simulated ciphertext data */
    unsigned char pq_ct[] = "ML-KEM-512-CIPHERTEXT";
    unsigned char trad_ct[] = "ECDH-P256-CIPHERTEXT";
    
    /* Encode */
    size_t encoded_len = 0;
    composite_kem_ct_encode(pq_ct, sizeof(pq_ct) - 1,
                            trad_ct, sizeof(trad_ct) - 1,
                            NULL, &encoded_len);
    
    unsigned char *encoded = malloc(encoded_len);
    if (!encoded) {
        printf("Error: Memory allocation failed\n");
        return;
    }
    
    composite_kem_ct_encode(pq_ct, sizeof(pq_ct) - 1,
                            trad_ct, sizeof(trad_ct) - 1,
                            encoded, &encoded_len);
    printf("Encoded composite KEM ciphertext: %zu bytes\n", encoded_len);
    
    /* Decode */
    unsigned char *decoded_pq = NULL, *decoded_trad = NULL;
    size_t decoded_pq_len = 0, decoded_trad_len = 0;
    
    composite_kem_ct_decode(encoded, encoded_len,
                            &decoded_pq, &decoded_pq_len,
                            &decoded_trad, &decoded_trad_len);
    
    printf("Decoded:\n");
    printf("  PQ ciphertext: %zu bytes\n", decoded_pq_len);
    printf("  Traditional ciphertext: %zu bytes\n", decoded_trad_len);
    
    /* Verify */
    if (memcmp(decoded_pq, pq_ct, decoded_pq_len) == 0 &&
        memcmp(decoded_trad, trad_ct, decoded_trad_len) == 0) {
        printf("✓ Verification successful\n");
    }
    
    /* Cleanup */
    free(encoded);
    free(decoded_pq);
    free(decoded_trad);
    printf("\n");
}

int main(void)
{
    printf("\n");
    printf("╔════════════════════════════════════════════════════════╗\n");
    printf("║  Composite Encoding/Decoding Examples                 ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    example_key_encoding();
    example_signature_encoding();
    example_kem_ct_encoding();
    
    printf("All examples completed successfully!\n");
    printf("\n");
    
    return 0;
}
