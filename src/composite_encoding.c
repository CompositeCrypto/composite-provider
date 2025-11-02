#include "composite_encoding.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

/* ========================================
 * Helper functions for length encoding
 * ======================================== */

/**
 * Write a 4-byte length value in big-endian format
 */
static void write_length(unsigned char *buf, size_t len)
{
    buf[0] = (len >> 24) & 0xFF;
    buf[1] = (len >> 16) & 0xFF;
    buf[2] = (len >> 8) & 0xFF;
    buf[3] = len & 0xFF;
}

/**
 * Read a 4-byte length value in big-endian format
 */
static size_t read_length(const unsigned char *buf)
{
    return ((size_t)buf[0] << 24) |
           ((size_t)buf[1] << 16) |
           ((size_t)buf[2] << 8) |
           ((size_t)buf[3]);
}

/* ========================================
 * Composite Key Encoding/Decoding
 * ======================================== */

int composite_key_encode(const unsigned char *pq_key, size_t pq_key_len,
                         const unsigned char *trad_key, size_t trad_key_len,
                         unsigned char *out, size_t *out_len)
{
    size_t total_len;
    
    if (pq_key == NULL || trad_key == NULL || out_len == NULL) {
        return 0;
    }
    
    /* Calculate total length: 4 bytes (pq_len) + pq_key + 4 bytes (trad_len) + trad_key */
    total_len = 4 + pq_key_len + 4 + trad_key_len;
    
    if (out == NULL) {
        /* Query mode: return required size */
        *out_len = total_len;
        return 1;
    }
    
    if (*out_len < total_len) {
        /* Output buffer too small */
        return 0;
    }
    
    /* Encode: [pq_key_len][pq_key][trad_key_len][trad_key] */
    write_length(out, pq_key_len);
    memcpy(out + 4, pq_key, pq_key_len);
    write_length(out + 4 + pq_key_len, trad_key_len);
    memcpy(out + 4 + pq_key_len + 4, trad_key, trad_key_len);
    
    *out_len = total_len;
    return 1;
}

int composite_key_decode(const unsigned char *in, size_t in_len,
                         unsigned char **pq_key, size_t *pq_key_len,
                         unsigned char **trad_key, size_t *trad_key_len)
{
    size_t pq_len, trad_len, offset;
    
    if (in == NULL || pq_key == NULL || pq_key_len == NULL ||
        trad_key == NULL || trad_key_len == NULL) {
        return 0;
    }
    
    /* Need at least 8 bytes for the two length fields */
    if (in_len < 8) {
        return 0;
    }
    
    /* Read PQ key length */
    pq_len = read_length(in);
    offset = 4;
    
    /* Check if we have enough data for PQ key */
    if (offset + pq_len + 4 > in_len) {
        return 0;
    }
    
    /* Read traditional key length */
    trad_len = read_length(in + offset + pq_len);
    
    /* Check if we have enough data for traditional key */
    if (offset + pq_len + 4 + trad_len != in_len) {
        return 0;
    }
    
    /* Allocate and copy PQ key */
    *pq_key = (unsigned char *)malloc(pq_len);
    if (*pq_key == NULL) {
        return 0;
    }
    memcpy(*pq_key, in + offset, pq_len);
    *pq_key_len = pq_len;
    
    /* Allocate and copy traditional key */
    offset += pq_len + 4;
    *trad_key = (unsigned char *)malloc(trad_len);
    if (*trad_key == NULL) {
        free(*pq_key);
        *pq_key = NULL;
        return 0;
    }
    memcpy(*trad_key, in + offset, trad_len);
    *trad_key_len = trad_len;
    
    return 1;
}

/* ========================================
 * Composite Signature Encoding/Decoding (ASN.1)
 * ======================================== */

/* ASN.1 structure for composite signature */
typedef struct {
    ASN1_OCTET_STRING *pq_signature;
    ASN1_OCTET_STRING *trad_signature;
} COMPOSITE_SIGNATURE_ASN1;

/* ASN.1 template for COMPOSITE_SIGNATURE_ASN1 */
ASN1_SEQUENCE(COMPOSITE_SIGNATURE_ASN1) = {
    ASN1_SIMPLE(COMPOSITE_SIGNATURE_ASN1, pq_signature, ASN1_OCTET_STRING),
    ASN1_SIMPLE(COMPOSITE_SIGNATURE_ASN1, trad_signature, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(COMPOSITE_SIGNATURE_ASN1)

IMPLEMENT_ASN1_FUNCTIONS(COMPOSITE_SIGNATURE_ASN1)

int composite_sig_encode(const unsigned char *pq_sig, size_t pq_sig_len,
                         const unsigned char *trad_sig, size_t trad_sig_len,
                         unsigned char *out, size_t *out_len)
{
    COMPOSITE_SIGNATURE_ASN1 *comp_sig = NULL;
    unsigned char *der_buf = NULL;
    int der_len;
    
    if (pq_sig == NULL || trad_sig == NULL || out_len == NULL) {
        return 0;
    }
    
    /* Create ASN.1 structure */
    comp_sig = COMPOSITE_SIGNATURE_ASN1_new();
    if (comp_sig == NULL) {
        return 0;
    }
    
    /* Set PQ signature */
    if (!ASN1_OCTET_STRING_set(comp_sig->pq_signature, pq_sig, (int)pq_sig_len)) {
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    
    /* Set traditional signature */
    if (!ASN1_OCTET_STRING_set(comp_sig->trad_signature, trad_sig, (int)trad_sig_len)) {
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    
    /* Encode to DER */
    der_len = i2d_COMPOSITE_SIGNATURE_ASN1(comp_sig, NULL);
    if (der_len < 0) {
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    
    if (out == NULL) {
        /* Query mode: return required size */
        *out_len = (size_t)der_len;
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 1;
    }
    
    if (*out_len < (size_t)der_len) {
        /* Output buffer too small */
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    
    /* Encode to output buffer */
    der_buf = out;
    der_len = i2d_COMPOSITE_SIGNATURE_ASN1(comp_sig, &der_buf);
    if (der_len < 0) {
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    
    *out_len = (size_t)der_len;
    COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
    return 1;
}

int composite_sig_decode(const unsigned char *in, size_t in_len,
                         unsigned char **pq_sig, size_t *pq_sig_len,
                         unsigned char **trad_sig, size_t *trad_sig_len)
{
    COMPOSITE_SIGNATURE_ASN1 *comp_sig = NULL;
    const unsigned char *der_buf = in;
    
    if (in == NULL || pq_sig == NULL || pq_sig_len == NULL ||
        trad_sig == NULL || trad_sig_len == NULL) {
        return 0;
    }
    
    /* Decode from DER */
    comp_sig = d2i_COMPOSITE_SIGNATURE_ASN1(NULL, &der_buf, (long)in_len);
    if (comp_sig == NULL) {
        return 0;
    }
    
    /* Extract PQ signature */
    *pq_sig_len = (size_t)ASN1_STRING_length(comp_sig->pq_signature);
    *pq_sig = (unsigned char *)malloc(*pq_sig_len);
    if (*pq_sig == NULL) {
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    memcpy(*pq_sig, ASN1_STRING_get0_data(comp_sig->pq_signature), *pq_sig_len);
    
    /* Extract traditional signature */
    *trad_sig_len = (size_t)ASN1_STRING_length(comp_sig->trad_signature);
    *trad_sig = (unsigned char *)malloc(*trad_sig_len);
    if (*trad_sig == NULL) {
        free(*pq_sig);
        *pq_sig = NULL;
        COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
        return 0;
    }
    memcpy(*trad_sig, ASN1_STRING_get0_data(comp_sig->trad_signature), *trad_sig_len);
    
    COMPOSITE_SIGNATURE_ASN1_free(comp_sig);
    return 1;
}

/* ========================================
 * Composite KEM Ciphertext Encoding/Decoding
 * ======================================== */

int composite_kem_ct_encode(const unsigned char *pq_ct, size_t pq_ct_len,
                            const unsigned char *trad_ct, size_t trad_ct_len,
                            unsigned char *out, size_t *out_len)
{
    size_t total_len;
    
    if (pq_ct == NULL || trad_ct == NULL || out_len == NULL) {
        return 0;
    }
    
    /* Calculate total length: 4 bytes (pq_len) + pq_ct + 4 bytes (trad_len) + trad_ct */
    total_len = 4 + pq_ct_len + 4 + trad_ct_len;
    
    if (out == NULL) {
        /* Query mode: return required size */
        *out_len = total_len;
        return 1;
    }
    
    if (*out_len < total_len) {
        /* Output buffer too small */
        return 0;
    }
    
    /* Encode: [pq_ct_len][pq_ct][trad_ct_len][trad_ct] */
    write_length(out, pq_ct_len);
    memcpy(out + 4, pq_ct, pq_ct_len);
    write_length(out + 4 + pq_ct_len, trad_ct_len);
    memcpy(out + 4 + pq_ct_len + 4, trad_ct, trad_ct_len);
    
    *out_len = total_len;
    return 1;
}

int composite_kem_ct_decode(const unsigned char *in, size_t in_len,
                            unsigned char **pq_ct, size_t *pq_ct_len,
                            unsigned char **trad_ct, size_t *trad_ct_len)
{
    size_t pq_len, trad_len, offset;
    
    if (in == NULL || pq_ct == NULL || pq_ct_len == NULL ||
        trad_ct == NULL || trad_ct_len == NULL) {
        return 0;
    }
    
    /* Need at least 8 bytes for the two length fields */
    if (in_len < 8) {
        return 0;
    }
    
    /* Read PQ ciphertext length */
    pq_len = read_length(in);
    offset = 4;
    
    /* Check if we have enough data for PQ ciphertext */
    if (offset + pq_len + 4 > in_len) {
        return 0;
    }
    
    /* Read traditional ciphertext length */
    trad_len = read_length(in + offset + pq_len);
    
    /* Check if we have enough data for traditional ciphertext */
    if (offset + pq_len + 4 + trad_len != in_len) {
        return 0;
    }
    
    /* Allocate and copy PQ ciphertext */
    *pq_ct = (unsigned char *)malloc(pq_len);
    if (*pq_ct == NULL) {
        return 0;
    }
    memcpy(*pq_ct, in + offset, pq_len);
    *pq_ct_len = pq_len;
    
    /* Allocate and copy traditional ciphertext */
    offset += pq_len + 4;
    *trad_ct = (unsigned char *)malloc(trad_len);
    if (*trad_ct == NULL) {
        free(*pq_ct);
        *pq_ct = NULL;
        return 0;
    }
    memcpy(*trad_ct, in + offset, trad_len);
    *trad_ct_len = trad_len;
    
    return 1;
}
