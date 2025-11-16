#include "composite_sig_encoding.h"

/* Helper: expected ML-DSA public key size for algorithm */
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

/* Helper: expected ML-DSA private seed size for algorithm */
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

/* Helper function to get expected PQ signature size for ML-DSA algorithm */
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

int composite_sig_pubkey_encode(int pq_alg,
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

    expected_pq_pub_size = get_ml_dsa_pub_key_size(pq_alg);
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

int composite_sig_pubkey_decode(int pq_alg,
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

    expected_pq_pub_size = get_ml_dsa_pub_key_size(pq_alg);
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

int composite_sig_privkey_encode(int pq_alg,
                                 const unsigned char *pq_seed, size_t pq_seed_len,
                                 const unsigned char *trad_priv, size_t trad_priv_len,
                                 unsigned char *out, size_t *out_len) {
    size_t expected_pq_priv_size;
    size_t required_size;

    if (pq_seed == NULL || trad_priv == NULL || out_len == NULL) {
        return 0;
    }
    if (pq_seed_len == 0 || trad_priv_len == 0) {
        return 0;
    }

    expected_pq_priv_size = get_ml_dsa_priv_key_size(pq_alg);
    if (expected_pq_priv_size == 0) {
        return 0;
    }
    if (pq_seed_len != expected_pq_priv_size) {
        return 0;
    }

    required_size = pq_seed_len + trad_priv_len;

    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    if (*out_len < required_size) {
        return 0;
    }

    memcpy(out, pq_seed, pq_seed_len);
    memcpy(out + pq_seed_len, trad_priv, trad_priv_len);

    *out_len = required_size;
    return 1;
}

int composite_sig_privkey_decode(int pq_alg,
                                 const unsigned char *in, size_t in_len,
                                 unsigned char **pq_seed, size_t *pq_seed_len,
                                 unsigned char **trad_priv, size_t *trad_priv_len) {
    size_t expected_pq_priv_size;
    size_t trad_len;
    unsigned char *pq_buf = NULL;
    unsigned char *trad_buf = NULL;

    if (in == NULL || pq_seed == NULL || pq_seed_len == NULL ||
        trad_priv == NULL || trad_priv_len == NULL) {
        return 0;
    }

    expected_pq_priv_size = get_ml_dsa_priv_key_size(pq_alg);
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

    *pq_seed = pq_buf;
    *pq_seed_len = expected_pq_priv_size;
    *trad_priv = trad_buf;
    *trad_priv_len = trad_len;

    return 1;
}

int composite_sig_encode(int pq_alg, const unsigned char *pq_sig, size_t pq_sig_len,
                         const unsigned char *trad_sig, size_t trad_sig_len,
                         unsigned char *out, size_t *out_len) {
    size_t expected_sig_size;
    size_t required_size;
    
    if (pq_sig == NULL || trad_sig == NULL || out_len == NULL) {
        return 0;
    }
    if (pq_sig_len == 0 || trad_sig_len == 0) {
        return 0;
    }

    expected_sig_size = get_ml_dsa_sig_size(pq_alg);
    if (expected_sig_size == 0) {
        return 0;
    }
    if (pq_sig_len != expected_sig_size) {
        return 0;
    }

    required_size = pq_sig_len + trad_sig_len;

    if (out == NULL) {
        *out_len = required_size;
        return 1;
    }
    if (*out_len < required_size) {
        return 0;
    }

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

    if (in == NULL || pq_sig == NULL || pq_sig_len == NULL ||
        trad_sig == NULL || trad_sig_len == NULL) {
        return 0;
    }

    expected_sig_size = get_ml_dsa_sig_size(pq_alg);
    if (expected_sig_size == 0) {
        return 0;
    }
    if (in_len < expected_sig_size) {
        return 0;
    }

    trad_len = in_len - expected_sig_size;
    if (trad_len == 0) {
        return 0;
    }

    pq_buf = (unsigned char *)malloc(expected_sig_size);
    if (pq_buf == NULL) {
        return 0;
    }
    trad_buf = (unsigned char *)malloc(trad_len);
    if (trad_buf == NULL) {
        free(pq_buf);
        return 0;
    }

    memcpy(pq_buf, in, expected_sig_size);
    memcpy(trad_buf, in + expected_sig_size, trad_len);

    *pq_sig = pq_buf;
    *pq_sig_len = expected_sig_size;
    *trad_sig = trad_buf;
    *trad_sig_len = trad_len;

    return 1;
}
