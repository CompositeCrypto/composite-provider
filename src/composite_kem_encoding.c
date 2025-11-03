#include "composite_kem_encoding.h"

/* Helper function to get expected PQ ciphertext size for ML-KEM algorithm */
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

/* Helper function to get expected ML-KEM public key size */
static size_t get_ml_kem_pub_key_size(int pq_alg) {
    switch (pq_alg) {
        case ML_KEM_768:
            return ML_KEM_768_PUB_KEY_SZ;
        case ML_KEM_1024:
            return ML_KEM_1024_PUB_KEY_SZ;
        default:
            return 0;
    }
}

/* Helper function to get expected ML-KEM private key size (compact representation) */
static size_t get_ml_kem_priv_key_size(int pq_alg) {
    switch (pq_alg) {
        case ML_KEM_768:
            return ML_KEM_768_PRIV_KEY_SZ;
        case ML_KEM_1024:
            return ML_KEM_1024_PRIV_KEY_SZ;
        default:
            return 0;
    }
}

int composite_kem_pubkey_encode(int pq_alg,
                                const unsigned char *pq_pub, size_t pq_pub_len,
                                const unsigned char *trad_pub, size_t trad_pub_len,
                                unsigned char *out, size_t *out_len) {
    size_t expected_pq_pub_size;
    size_t required_size;

    if (pq_pub == NULL || trad_pub == NULL || out_len == NULL) {
        return 0;
    }
    if (pq_pub_len == 0 || trad_pub_len == 0) {
        return 0;
    }

    expected_pq_pub_size = get_ml_kem_pub_key_size(pq_alg);
    if (expected_pq_pub_size == 0) {
        return 0;
    }
    if (pq_pub_len != expected_pq_pub_size) {
        return 0;
    }

    required_size = pq_pub_len + trad_pub_len;

    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    if (*out_len < required_size) {
        return 0;
    }

    memcpy(out, pq_pub, pq_pub_len);
    memcpy(out + pq_pub_len, trad_pub, trad_pub_len);

    *out_len = required_size;
    return 1;
}

int composite_kem_pubkey_decode(int pq_alg,
                                const unsigned char *in, size_t in_len,
                                unsigned char **pq_pub, size_t *pq_pub_len,
                                unsigned char **trad_pub, size_t *trad_pub_len) {
    size_t expected_pq_pub_size;
    size_t trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;

    if (in == NULL || pq_pub == NULL || pq_pub_len == NULL ||
        trad_pub == NULL || trad_pub_len == NULL) {
        return 0;
    }

    expected_pq_pub_size = get_ml_kem_pub_key_size(pq_alg);
    if (expected_pq_pub_size == 0) {
        return 0;
    }
    if (in_len < expected_pq_pub_size) {
        return 0;
    }

    trad_len = in_len - expected_pq_pub_size;
    if (trad_len == 0) {
        return 0;
    }

    pq_buf = (unsigned char *)malloc(expected_pq_pub_size);
    if (pq_buf == NULL) {
        return 0;
    }
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }

    memcpy(pq_buf, in, expected_pq_pub_size);
    memcpy(trad_buf, in + expected_pq_pub_size, trad_len);

    *pq_pub = pq_buf;
    *pq_pub_len = expected_pq_pub_size;
    *trad_pub = trad_buf;
    *trad_pub_len = trad_len;

    return 1;
}

int composite_kem_privkey_encode(int pq_alg,
                                 const unsigned char *pq_priv, size_t pq_priv_len,
                                 const unsigned char *trad_priv, size_t trad_priv_len,
                                 unsigned char *out, size_t *out_len) {
    size_t expected_pq_priv_size;
    size_t required_size;

    if (pq_priv == NULL || trad_priv == NULL || out_len == NULL) {
        return 0;
    }
    if (pq_priv_len == 0 || trad_priv_len == 0) {
        return 0;
    }

    expected_pq_priv_size = get_ml_kem_priv_key_size(pq_alg);
    if (expected_pq_priv_size == 0) {
        return 0;
    }
    if (pq_priv_len != expected_pq_priv_size) {
        return 0;
    }

    required_size = pq_priv_len + trad_priv_len;

    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    if (*out_len < required_size) {
        return 0;
    }

    memcpy(out, pq_priv, pq_priv_len);
    memcpy(out + pq_priv_len, trad_priv, trad_priv_len);

    *out_len = required_size;
    return 1;
}

int composite_kem_privkey_decode(int pq_alg,
                                 const unsigned char *in, size_t in_len,
                                 unsigned char **pq_priv, size_t *pq_priv_len,
                                 unsigned char **trad_priv, size_t *trad_priv_len) {
    size_t expected_pq_priv_size;
    size_t trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;

    if (in == NULL || pq_priv == NULL || pq_priv_len == NULL ||
        trad_priv == NULL || trad_priv_len == NULL) {
        return 0;
    }

    expected_pq_priv_size = get_ml_kem_priv_key_size(pq_alg);
    if (expected_pq_priv_size == 0) {
        return 0;
    }
    if (in_len < expected_pq_priv_size) {
        return 0;
    }

    trad_len = in_len - expected_pq_priv_size;
    if (trad_len == 0) {
        return 0;
    }

    pq_buf = (unsigned char *)malloc(expected_pq_priv_size);
    if (pq_buf == NULL) {
        return 0;
    }
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }

    memcpy(pq_buf, in, expected_pq_priv_size);
    memcpy(trad_buf, in + expected_pq_priv_size, trad_len);

    *pq_priv = pq_buf;
    *pq_priv_len = expected_pq_priv_size;
    *trad_priv = trad_buf;
    *trad_priv_len = trad_len;

    return 1;
}

int composite_kem_ct_encode(int pq_alg, const unsigned char *pq_ct, size_t pq_ct_len,
                            const unsigned char *trad_ct, size_t trad_ct_len,
                            unsigned char *out, size_t *out_len) {
    size_t expected_ct_size;
    size_t required_size;
    
    if (pq_ct == NULL || trad_ct == NULL || out_len == NULL) {
        return 0;
    }
    if (pq_ct_len == 0 || trad_ct_len == 0) {
        return 0;
    }

    expected_ct_size = get_ml_kem_ct_size(pq_alg);
    if (expected_ct_size == 0) {
        return 0;
    }
    if (pq_ct_len != expected_ct_size) {
        return 0;
    }

    required_size = pq_ct_len + trad_ct_len;

    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    if (*out_len < required_size) {
        return 0;
    }

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

    if (in == NULL || pq_ct == NULL || pq_ct_len == NULL ||
        trad_ct == NULL || trad_ct_len == NULL) {
        return 0;
    }

    expected_ct_size = get_ml_kem_ct_size(pq_alg);
    if (expected_ct_size == 0) {
        return 0;
    }
    if (in_len < expected_ct_size) {
        return 0;
    }

    trad_len = in_len - expected_ct_size;
    if (trad_len == 0) {
        return 0;
    }

    pq_buf = (unsigned char *)malloc(expected_ct_size);
    if (pq_buf == NULL) {
        return 0;
    }
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }

    memcpy(pq_buf, in, expected_ct_size);
    memcpy(trad_buf, in + expected_ct_size, trad_len);

    *pq_ct = pq_buf;
    *pq_ct_len = expected_ct_size;
    *trad_ct = trad_buf;
    *trad_ct_len = trad_len;

    return 1;
}
