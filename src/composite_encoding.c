#include "composite_encoding.h"
#include <stdlib.h>
#include <string.h>

/*
 * Helper function to get expected PQ public key size for ML-DSA algorithm
 */
static size_t get_ml_dsa_pub_key_size(int pq_alg) {
    switch (pq_alg) {
        case ML_DSA_44:
            return ML_DSA_44_PUB_KEY_SZ;
        case ML_DSA_65:
            return ML_DSA_65_PUB_KEY_SZ;
        case ML_DSA_87:
            return ML_DSA_87_PUB_KEY_SZ;
        default:
            return 0;
    }
}

/*
 * Helper function to get expected PQ private key size for ML-DSA algorithm
 */
static size_t get_ml_dsa_priv_key_size(int pq_alg) {
    switch (pq_alg) {
        case ML_DSA_44:
            return ML_DSA_44_PRIV_KEY_SZ;
        case ML_DSA_65:
            return ML_DSA_65_PRIV_KEY_SZ;
        case ML_DSA_87:
            return ML_DSA_87_PRIV_KEY_SZ;
        default:
            return 0;
    }
}

/*
 * Helper function to get expected PQ signature size for ML-DSA algorithm
 */
static size_t get_ml_dsa_sig_size(int pq_alg) {
    switch (pq_alg) {
        case ML_DSA_44:
            return ML_DSA_44_SIG_SZ;
        case ML_DSA_65:
            return ML_DSA_65_SIG_SZ;
        case ML_DSA_87:
            return ML_DSA_87_SIG_SZ;
        default:
            return 0;
    }
}

/*
 * Helper function to get expected PQ ciphertext size for ML-KEM algorithm
 */
static size_t get_ml_kem_ct_size(int pq_alg) {
    switch (pq_alg) {
        case ML_KEM_768:
            return ML_KEM_768_CT_SZ;
        case ML_KEM_1024:
            return ML_KEM_1024_CT_SZ;
        default:
            return 0;
    }
}


int composite_key_encode(int pq_alg, const unsigned char *pq_key, size_t pq_key_len,
                         const unsigned char *trad_key, size_t trad_key_len,
                         unsigned char *out, size_t *out_len) {
    size_t expected_pq_pub_size, expected_pq_priv_size;
    size_t required_size;
    
    /* Validate inputs */
    if (pq_key == NULL || trad_key == NULL || out_len == NULL) {
        return 0;
    }
    
    if (pq_key_len == 0 || trad_key_len == 0) {
        return 0;
    }
    
    /* Get expected sizes for this algorithm */
    expected_pq_pub_size = get_ml_dsa_pub_key_size(pq_alg);
    expected_pq_priv_size = get_ml_dsa_priv_key_size(pq_alg);
    
    if (expected_pq_pub_size == 0 || expected_pq_priv_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Validate PQ key length - must match either public or private key size */
    if (pq_key_len != expected_pq_pub_size && pq_key_len != expected_pq_priv_size) {
        return 0;
    }
    
    /* Calculate required size: raw concatenation */
    required_size = pq_key_len + trad_key_len;
    
    /* Query mode: return required size */
    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    
    /* Check if output buffer is large enough */
    if (*out_len < required_size) {
        return 0;
    }
    
    /* Encode: [pq_key][trad_key] */
    memcpy(out, pq_key, pq_key_len);
    memcpy(out + pq_key_len, trad_key, trad_key_len);
    
    *out_len = required_size;
    return 1;
}

int composite_key_decode(int pq_alg, const unsigned char *in, size_t in_len,
                         unsigned char **pq_key, size_t *pq_key_len,
                         unsigned char **trad_key, size_t *trad_key_len) {
    size_t expected_pq_pub_size, expected_pq_priv_size;
    size_t pq_len, trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;
    
    /* Validate inputs */
    if (in == NULL || pq_key == NULL || pq_key_len == NULL ||
        trad_key == NULL || trad_key_len == NULL) {
        return 0;
    }
    
    /* Get expected sizes for this algorithm */
    expected_pq_pub_size = get_ml_dsa_pub_key_size(pq_alg);
    expected_pq_priv_size = get_ml_dsa_priv_key_size(pq_alg);
    
    if (expected_pq_pub_size == 0 || expected_pq_priv_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Try to determine which key type we have based on input length.
     * We prioritize public key size as it's more common. */
    if (in_len >= expected_pq_pub_size + 1) {
        /* Likely a public key (has enough data) */
        pq_len = expected_pq_pub_size;
    } else if (in_len >= expected_pq_priv_size + 1) {
        /* Likely a private key */
        pq_len = expected_pq_priv_size;
    } else {
        /* Not enough data for either key type */
        return 0;
    }
    
    /* Calculate traditional key length */
    trad_len = in_len - pq_len;
    
    /* Traditional key must have positive length */
    if (trad_len == 0) {
        return 0;
    }
    
    /* Allocate memory for PQ key */
    pq_buf = (unsigned char *)malloc(pq_len);
    if (pq_buf == NULL) {
        return 0;
    }
    
    /* Allocate memory for traditional key */
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }
    
    /* Copy key data */
    memcpy(pq_buf, in, pq_len);
    memcpy(trad_buf, in + pq_len, trad_len);
    
    /* Set output parameters */
    *pq_key = pq_buf;
    *pq_key_len = pq_len;
    *trad_key = trad_buf;
    *trad_key_len = trad_len;
    
    return 1;
}

int composite_sig_encode(int pq_alg, const unsigned char *pq_sig, size_t pq_sig_len,
                         const unsigned char *trad_sig, size_t trad_sig_len,
                         unsigned char *out, size_t *out_len) {
    size_t expected_sig_size;
    size_t required_size;
    
    /* Validate inputs */
    if (pq_sig == NULL || trad_sig == NULL || out_len == NULL) {
        return 0;
    }
    
    if (pq_sig_len == 0 || trad_sig_len == 0) {
        return 0;
    }
    
    /* Get expected signature size for this algorithm */
    expected_sig_size = get_ml_dsa_sig_size(pq_alg);
    
    if (expected_sig_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Validate PQ signature length - must match exactly */
    if (pq_sig_len != expected_sig_size) {
        return 0;
    }
    
    /* Calculate required size: raw concatenation */
    required_size = pq_sig_len + trad_sig_len;
    
    /* Query mode: return required size */
    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    
    /* Check if output buffer is large enough */
    if (*out_len < required_size) {
        return 0;
    }
    
    /* Encode: [ML signature bytes][traditional signature bytes] */
    memcpy(out, pq_sig, pq_sig_len);
    memcpy(out + pq_sig_len, trad_sig, trad_sig_len);
    
    *out_len = required_size;
    return 1;
}

int composite_sig_decode(int pq_alg, const unsigned char *in, size_t in_len,
                         unsigned char **pq_sig, size_t *pq_sig_len,
                         unsigned char **trad_sig, size_t *trad_sig_len) {
    size_t expected_sig_size;
    size_t trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;
    
    /* Validate inputs */
    if (in == NULL || pq_sig == NULL || pq_sig_len == NULL ||
        trad_sig == NULL || trad_sig_len == NULL) {
        return 0;
    }
    
    /* Get expected signature size for this algorithm */
    expected_sig_size = get_ml_dsa_sig_size(pq_alg);
    
    if (expected_sig_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Input must be at least as large as the ML signature */
    if (in_len < expected_sig_size) {
        return 0;
    }
    
    /* Calculate traditional signature length */
    trad_len = in_len - expected_sig_size;
    
    /* Traditional signature must have positive length */
    if (trad_len == 0) {
        return 0;
    }
    
    /* Allocate memory for PQ signature */
    pq_buf = (unsigned char *)malloc(expected_sig_size);
    if (pq_buf == NULL) {
        return 0;
    }
    
    /* Allocate memory for traditional signature */
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }
    
    /* Copy signature data */
    memcpy(pq_buf, in, expected_sig_size);
    memcpy(trad_buf, in + expected_sig_size, trad_len);
    
    /* Set output parameters */
    *pq_sig = pq_buf;
    *pq_sig_len = expected_sig_size;
    *trad_sig = trad_buf;
    *trad_sig_len = trad_len;
    
    return 1;
}

int composite_kem_ct_encode(int pq_alg, const unsigned char *pq_ct, size_t pq_ct_len,
                            const unsigned char *trad_ct, size_t trad_ct_len,
                            unsigned char *out, size_t *out_len) {
    size_t expected_ct_size;
    size_t required_size;
    
    /* Validate inputs */
    if (pq_ct == NULL || trad_ct == NULL || out_len == NULL) {
        return 0;
    }
    
    if (pq_ct_len == 0 || trad_ct_len == 0) {
        return 0;
    }
    
    /* Get expected ciphertext size for this algorithm */
    expected_ct_size = get_ml_kem_ct_size(pq_alg);
    
    if (expected_ct_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Validate PQ ciphertext length - must match exactly */
    if (pq_ct_len != expected_ct_size) {
        return 0;
    }
    
    /* Calculate required size: raw concatenation */
    required_size = pq_ct_len + trad_ct_len;
    
    /* Query mode: return required size */
    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    
    /* Check if output buffer is large enough */
    if (*out_len < required_size) {
        return 0;
    }
    
    /* Encode: [ML ciphertext bytes][traditional ciphertext bytes] */
    memcpy(out, pq_ct, pq_ct_len);
    memcpy(out + pq_ct_len, trad_ct, trad_ct_len);
    
    *out_len = required_size;
    return 1;
}

int composite_kem_ct_decode(int pq_alg, const unsigned char *in, size_t in_len,
                            unsigned char **pq_ct, size_t *pq_ct_len,
                            unsigned char **trad_ct, size_t *trad_ct_len) {
    size_t expected_ct_size;
    size_t trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;
    
    /* Validate inputs */
    if (in == NULL || pq_ct == NULL || pq_ct_len == NULL ||
        trad_ct == NULL || trad_ct_len == NULL) {
        return 0;
    }
    
    /* Get expected ciphertext size for this algorithm */
    expected_ct_size = get_ml_kem_ct_size(pq_alg);
    
    if (expected_ct_size == 0) {
        /* Invalid algorithm identifier */
        return 0;
    }
    
    /* Input must be at least as large as the ML ciphertext */
    if (in_len < expected_ct_size) {
        return 0;
    }
    
    /* Calculate traditional ciphertext length */
    trad_len = in_len - expected_ct_size;
    
    /* Traditional ciphertext must have positive length */
    if (trad_len == 0) {
        return 0;
    }
    
    /* Allocate memory for PQ ciphertext */
    pq_buf = (unsigned char *)malloc(expected_ct_size);
    if (pq_buf == NULL) {
        return 0;
    }
    
    /* Allocate memory for traditional ciphertext */
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }
    
    /* Copy ciphertext data */
    memcpy(pq_buf, in, expected_ct_size);
    memcpy(trad_buf, in + expected_ct_size, trad_len);
    
    /* Set output parameters */
    *pq_ct = pq_buf;
    *pq_ct_len = expected_ct_size;
    *trad_ct = trad_buf;
    *trad_ct_len = trad_len;
    
    return 1;
}
