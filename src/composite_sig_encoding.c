#include "composite_sig_encoding.h"
#include <openssl/evp.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/objects.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdlib.h>

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

/* composite_sig_pubkey_encode — extract raw key bytes from a COMPOSITE_KEY and
 * produce the wire-format public key blob: mldsa_pub || classic_pub.
 * Allocates *out with OPENSSL_malloc; caller must OPENSSL_free it. */
int composite_sig_pubkey_encode(COMPOSITE_KEY *key,
                                unsigned char **out, size_t *out_len)
{
    const COMPOSITE_ALG_INFO *alg;
    unsigned char *mpub = NULL; size_t mpub_len = 0;
    unsigned char *tpub = NULL; size_t tpub_len = 0;
    unsigned char *buf  = NULL; size_t blen = 0;
    int ret = 0;

    if (!key || !out || !out_len || !key->composite_name) return 0;
    if (!key->mldsa_pubkey || !key->classic_pubkey) return 0;

    alg = composite_alg_info_find(key->composite_name);
    if (!alg) return 0;

    if (!EVP_PKEY_get_raw_public_key((EVP_PKEY *)key->mldsa_pubkey,
                                      NULL, &mpub_len))
        return 0;
    mpub = OPENSSL_malloc(mpub_len);
    if (!mpub) return 0;
    if (!EVP_PKEY_get_raw_public_key((EVP_PKEY *)key->mldsa_pubkey,
                                      mpub, &mpub_len))
        goto done;
    if (!classic_pubkey_to_bytes((EVP_PKEY *)key->classic_pubkey,
                                 &tpub, &tpub_len))
        goto done;

    blen = mpub_len + tpub_len;
    buf  = OPENSSL_malloc(blen);
    if (!buf) goto done;
    memcpy(buf,            mpub, mpub_len);
    memcpy(buf + mpub_len, tpub, tpub_len);
    *out     = buf;
    *out_len = blen;
    ret = 1;
done:
    OPENSSL_free(mpub);
    OPENSSL_free(tpub);
    return ret;
}

/* composite_sig_pubkey_decode — split a wire-format public key blob into its
 * ML-DSA and classic components and install them into key->mldsa_pubkey and
 * key->classic_pubkey. */
int composite_sig_pubkey_decode(COMPOSITE_KEY *key,
                                const unsigned char *data, size_t data_len)
{
    const COMPOSITE_ALG_INFO *alg;
    size_t mldsa_pub_len;

    if (!key || !data || !data_len || !key->composite_name) return 0;

    alg = composite_alg_info_find(key->composite_name);
    if (!alg) return 0;

    mldsa_pub_len = get_ml_dsa_pub_key_size(alg->mldsa_id);
    if (mldsa_pub_len == 0 || data_len <= mldsa_pub_len) return 0;

    size_t trad_len = data_len - mldsa_pub_len;

    EVP_PKEY *mpk = EVP_PKEY_new_raw_public_key_ex(
            key->provctx->libctx, alg->mldsa_name, NULL,
            data, mldsa_pub_len);
    if (!mpk) return 0;

    EVP_PKEY *tpk = classic_pubkey_from_bytes(
            key->provctx->libctx, alg->classic_alg, alg->classic_param,
            data + mldsa_pub_len, trad_len);
    if (!tpk) { EVP_PKEY_free(mpk); return 0; }

    EVP_PKEY_free((EVP_PKEY *)key->mldsa_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    key->mldsa_pubkey   = mpk;
    key->classic_pubkey = tpk;
    return 1;
}

/* composite_sig_privkey_encode — extract raw key bytes from a COMPOSITE_KEY and
 * produce the wire-format private key blob: mldsa_seed || classic_priv.
 * Allocates *out with OPENSSL_malloc; caller must OPENSSL_free it. */
int composite_sig_privkey_encode(COMPOSITE_KEY *key,
                                 unsigned char **out, size_t *out_len)
{
    unsigned char *mpriv = NULL; size_t mpriv_len = 0;
    unsigned char *tpriv = NULL; size_t tpriv_len = 0;
    unsigned char *buf   = NULL; size_t blen = 0;
    int ret = 0;

    if (!key || !out || !out_len || !key->has_private) return 0;
    if (!key->composite_name) return 0;

    EVP_PKEY *mldsa_full = key->mldsa_privkey
                         ? (EVP_PKEY *)key->mldsa_privkey
                         : (EVP_PKEY *)key->mldsa_pubkey;
    EVP_PKEY *trad_full  = key->classic_privkey
                         ? (EVP_PKEY *)key->classic_privkey
                         : (EVP_PKEY *)key->classic_pubkey;
    if (!mldsa_full || !trad_full) return 0;

    /* Extract the 32-byte ML-DSA seed via OSSL_PKEY_PARAM_ML_DSA_SEED.
     * EVP_PKEY_get_raw_private_key returns the full expanded private key
     * (~2560 bytes) which must NOT be used in the wire format. */
    mpriv_len = 32; /* ML_DSA_SEED_BYTES — same for all ML-DSA variants */
    mpriv = OPENSSL_malloc(mpriv_len);
    if (!mpriv) return 0;
    {
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                              mpriv, mpriv_len),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_get_params(mldsa_full, params) <= 0)
            goto done;
    }
    if (!classic_privkey_to_bytes(trad_full, &tpriv, &tpriv_len))
        goto done;

    blen = mpriv_len + tpriv_len;
    buf  = OPENSSL_malloc(blen);
    if (!buf) goto done;
    memcpy(buf,             mpriv, mpriv_len);
    memcpy(buf + mpriv_len, tpriv, tpriv_len);
    *out     = buf;
    *out_len = blen;
    ret = 1;
done:
    OPENSSL_cleanse(mpriv, mpriv_len);
    OPENSSL_free(mpriv);
    OPENSSL_free(tpriv);
    return ret;
}

/* composite_sig_privkey_decode — split a wire-format private key blob into its
 * ML-DSA seed and classic components and install them into key->mldsa_privkey
 * and key->classic_privkey. */
int composite_sig_privkey_decode(COMPOSITE_KEY *key,
                                 const unsigned char *data, size_t data_len)
{
    const COMPOSITE_ALG_INFO *alg;
    size_t mldsa_seed_len;

    if (!key || !data || !data_len || !key->composite_name) return 0;

    alg = composite_alg_info_find(key->composite_name);
    if (!alg) return 0;

    mldsa_seed_len = get_ml_dsa_priv_key_size(alg->mldsa_id);
    if (mldsa_seed_len == 0 || data_len <= mldsa_seed_len) return 0;

    size_t trad_len = data_len - mldsa_seed_len;

    /* Load ML-DSA key from seed via EVP_PKEY_fromdata(OSSL_PKEY_PARAM_ML_DSA_SEED).
     * EVP_PKEY_new_raw_private_key_ex passes bytes as OSSL_PKEY_PARAM_PRIV_KEY
     * which expects the full expanded key, not a 32-byte seed. */
    EVP_PKEY *mpk = NULL;
    {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(
                key->provctx->libctx, alg->mldsa_name, NULL);
        if (!pctx) return 0;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED,
                                              (void *)data, mldsa_seed_len),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_fromdata_init(pctx) > 0)
            EVP_PKEY_fromdata(pctx, &mpk, EVP_PKEY_KEYPAIR, params);
        EVP_PKEY_CTX_free(pctx);
    }
    if (!mpk) return 0;

    EVP_PKEY *tpk = classic_privkey_from_bytes(
            key->provctx->libctx, alg->classic_alg,
            data + mldsa_seed_len, trad_len);
    if (!tpk) { EVP_PKEY_free(mpk); return 0; }

    EVP_PKEY_free((EVP_PKEY *)key->mldsa_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);
    key->mldsa_privkey   = mpk;
    key->classic_privkey = tpk;
    key->has_private     = 1;
    return 1;
}

/* =========================================================================
 * EVP_PKEY <-> raw bytes conversions for classic (traditional) keys.
 * Used by composite_keys.c import/export and by any code that needs to
 * serialise classic key material without going through the full PKCS#8 path.
 * ======================================================================= */

int classic_pubkey_to_bytes(EVP_PKEY *pkey,
                            unsigned char **out, size_t *out_len)
{
    int id = EVP_PKEY_get_id(pkey);

    if (id == EVP_PKEY_ED25519 || id == EVP_PKEY_ED448) {
        size_t len = 0;
        if (!EVP_PKEY_get_raw_public_key(pkey, NULL, &len)) return 0;
        unsigned char *buf = OPENSSL_malloc(len);
        if (!buf) return 0;
        if (!EVP_PKEY_get_raw_public_key(pkey, buf, &len))
            { OPENSSL_free(buf); return 0; }
        *out = buf; *out_len = len;
        return 1;
    }
    if (id == EVP_PKEY_EC) {
        size_t len = 0;
        if (!EVP_PKEY_get_octet_string_param(pkey,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0, &len)) return 0;
        unsigned char *buf = OPENSSL_malloc(len);
        if (!buf) return 0;
        if (!EVP_PKEY_get_octet_string_param(pkey,
                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, buf, len, &len))
            { OPENSSL_free(buf); return 0; }
        *out = buf; *out_len = len;
        return 1;
    }
    /* RSA: RSAPublicKey PKCS#1 DER */
    OSSL_ENCODER_CTX *ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey,
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY, "DER", "type-specific", NULL);
    if (!ectx) return 0;
    unsigned char *buf  = NULL;
    size_t         blen = 0;
    if (!OSSL_ENCODER_to_data(ectx, &buf, &blen))
        { OSSL_ENCODER_CTX_free(ectx); return 0; }
    OSSL_ENCODER_CTX_free(ectx);
    *out = buf; *out_len = blen;
    return 1;
}

int classic_privkey_to_bytes(EVP_PKEY *pkey,
                             unsigned char **out, size_t *out_len)
{
    int id = EVP_PKEY_get_id(pkey);
    if (id == EVP_PKEY_ED25519 || id == EVP_PKEY_ED448) {
        size_t len = 0;
        if (!EVP_PKEY_get_raw_private_key(pkey, NULL, &len)) return 0;
        unsigned char *buf = OPENSSL_malloc(len);
        if (!buf) return 0;
        if (!EVP_PKEY_get_raw_private_key(pkey, buf, &len))
            { OPENSSL_free(buf); return 0; }
        *out = buf; *out_len = len;
        return 1;
    }
    /*
     * RSA: RSAPrivateKey PKCS#1 DER (type-specific)
     * EC:  ECPrivateKey RFC5915 DER (type-specific), public key component
     *      stripped via OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC=0.
     */
    OSSL_ENCODER_CTX *ectx = NULL;
    EVP_PKEY *ec_copy = NULL;
    EVP_PKEY *key_to_enc = pkey;
    unsigned char *buf = NULL;
    size_t blen = 0;
    int ret = 0;

    if (id == EVP_PKEY_EC) {
        int include_pub = 0;
        OSSL_PARAM params[] = {
            OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                     &include_pub),
            OSSL_PARAM_construct_end()
        };
        ec_copy = EVP_PKEY_dup(pkey);
        if (!ec_copy) return 0;
        if (!EVP_PKEY_set_params(ec_copy, params)) {
            EVP_PKEY_free(ec_copy);
            return 0;
        }
        key_to_enc = ec_copy;
    }

    ectx = OSSL_ENCODER_CTX_new_for_pkey(key_to_enc,
            OSSL_KEYMGMT_SELECT_KEYPAIR, "DER", "type-specific", NULL);
    if (ectx != NULL && OSSL_ENCODER_to_data(ectx, &buf, &blen)) {
        *out = buf; *out_len = blen;
        ret = 1;
    }
    OSSL_ENCODER_CTX_free(ectx);
    EVP_PKEY_free(ec_copy);
    return ret;
}

EVP_PKEY *classic_pubkey_from_bytes(OSSL_LIB_CTX *libctx,
                                    const char   *alg_name,
                                    int           classic_param,
                                    const unsigned char *data,
                                    size_t        data_len)
{
    EVP_PKEY *pkey = NULL;

    if (strcmp(alg_name, DEFAULT_ED25519_NAME) == 0)
        return EVP_PKEY_new_raw_public_key_ex(libctx, "ED25519", NULL,
                                               data, data_len);
    if (strcmp(alg_name, DEFAULT_ED448_NAME) == 0)
        return EVP_PKEY_new_raw_public_key_ex(libctx, "ED448", NULL,
                                               data, data_len);

    /* EC curve — classic_param is the NID */
    if (classic_param != 0 && classic_param != 2048 &&
        classic_param != 3072 && classic_param != 4096) {
        const char *curve = OBJ_nid2sn(classic_param);
        if (curve == NULL) return NULL;
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(libctx, "EC", NULL);
        if (!pctx) return NULL;
        OSSL_PARAM params[3] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, (char *)curve, 0),
            OSSL_PARAM_construct_octet_string(
                OSSL_PKEY_PARAM_PUB_KEY,
                (unsigned char *)data, data_len),
            OSSL_PARAM_construct_end()
        };
        if (EVP_PKEY_fromdata_init(pctx) > 0)
            EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
        EVP_PKEY_CTX_free(pctx);
        return pkey;
    }

    /* RSA: RSAPublicKey PKCS#1 DER */
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", "type-specific", "RSA",
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY, libctx, NULL);
    if (!dctx) return NULL;
    OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

EVP_PKEY *classic_privkey_from_bytes(OSSL_LIB_CTX *libctx,
                                     const char   *alg_name,
                                     const unsigned char *data,
                                     size_t        data_len)
{
    EVP_PKEY *pkey = NULL;
    if (strcmp(alg_name, DEFAULT_ED25519_NAME) == 0)
        return EVP_PKEY_new_raw_private_key_ex(libctx, "ED25519", NULL,
                                                data, data_len);
    if (strcmp(alg_name, DEFAULT_ED448_NAME) == 0)
        return EVP_PKEY_new_raw_private_key_ex(libctx, "ED448", NULL,
                                                data, data_len);
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(
            &pkey, "DER", NULL, NULL,
            OSSL_KEYMGMT_SELECT_PRIVATE_KEY, libctx, NULL);
    if (!dctx) return NULL;
    OSSL_DECODER_from_data(dctx, &data, &data_len);
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

/* =========================================================================
 * composite_key_export — serialise a COMPOSITE_KEY into OSSL_PARAMs.
 *
 * Delegates all key-material extraction and wire-format encoding to
 * composite_sig_pubkey_encode / composite_sig_privkey_encode.
 * ======================================================================= */

int composite_key_export(void *keydata, int selection,
                         OSSL_CALLBACK *param_cb, void *cbarg)
{
    COMPOSITE_KEY *key = (COMPOSITE_KEY *)keydata;
    if (!key || !param_cb) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        unsigned char *buf = NULL; size_t blen = 0;
        if (!composite_sig_pubkey_encode(key, &buf, &blen)) return 0;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, buf, blen),
            OSSL_PARAM_construct_end()
        };
        int ret = param_cb(params, cbarg);
        OPENSSL_free(buf);
        return ret;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        unsigned char *buf = NULL; size_t blen = 0;
        if (!composite_sig_privkey_encode(key, &buf, &blen)) return 0;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, buf, blen),
            OSSL_PARAM_construct_end()
        };
        int ret = param_cb(params, cbarg);
        OPENSSL_cleanse(buf, blen);
        OPENSSL_free(buf);
        return ret;
    }
    return 1;
}

/* =========================================================================
 * composite_key_import — populate a COMPOSITE_KEY from OSSL_PARAMs.
 *
 * Delegates wire-format splitting and EVP_PKEY reconstruction to
 * composite_sig_pubkey_decode / composite_sig_privkey_decode.
 * ======================================================================= */

int composite_key_import(void *keydata, int selection,
                         const OSSL_PARAM params[])
{
    COMPOSITE_KEY    *key = (COMPOSITE_KEY *)keydata;
    const OSSL_PARAM *p;

    if (!key || !params) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        if (p) {
            const unsigned char *blob; size_t blen;
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&blob, &blen))
                return 0;
            if (!composite_sig_pubkey_decode(key, blob, blen))
                return 0;
        }
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        if (p) {
            const unsigned char *blob; size_t blen;
            if (!OSSL_PARAM_get_octet_string_ptr(p, (const void **)&blob, &blen))
                return 0;
            if (!composite_sig_privkey_decode(key, blob, blen))
                return 0;
        }
    }
    return 1;
}
