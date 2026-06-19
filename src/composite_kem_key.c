#include "composite_kem_key.h"

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <string.h>

typedef struct {
    const char *composite_name;
    const char *mlkem_name;
    const char *classic_name;
    int classic_param;
} COMPOSITE_KEM_ALG_INFO;

static const COMPOSITE_KEM_ALG_INFO kem_algorithms[] = {
    { MLKEM768_RSA2048_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 2048 },
    { MLKEM768_RSA3072_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 3072 },
    { MLKEM768_RSA4096_SN, DEFAULT_MLKEM768_NAME, DEFAULT_RSA_NAME, 4096 },
    { MLKEM768_X25519_SN, DEFAULT_MLKEM768_NAME, "X25519", 0 },
    { MLKEM768_P256_SN, DEFAULT_MLKEM768_NAME, "EC", NID_X9_62_prime256v1 },
    { MLKEM768_P384_SN, DEFAULT_MLKEM768_NAME, "EC", NID_secp384r1 },
    { MLKEM768_BRAINPOOLP256_SN, DEFAULT_MLKEM768_NAME, "EC", NID_brainpoolP256r1 },
    { MLKEM1024_RSA3072_SN, DEFAULT_MLKEM1024_NAME, DEFAULT_RSA_NAME, 3072 },
    { MLKEM1024_P384_SN, DEFAULT_MLKEM1024_NAME, "EC", NID_secp384r1 },
    { MLKEM1024_BRAINPOOLP384_SN, DEFAULT_MLKEM1024_NAME, "EC", NID_brainpoolP384r1 },
    { MLKEM1024_X448_SN, DEFAULT_MLKEM1024_NAME, "X448", 0 },
    { MLKEM1024_P521_SN, DEFAULT_MLKEM1024_NAME, "EC", NID_secp521r1 },
};

static const COMPOSITE_KEM_ALG_INFO *composite_kem_alg_info_find(
        const char *composite_name)
{
    size_t i;

    if (composite_name == NULL)
        return NULL;

    for (i = 0; i < sizeof(kem_algorithms) / sizeof(kem_algorithms[0]); i++) {
        if (strcmp(kem_algorithms[i].composite_name, composite_name) == 0)
            return &kem_algorithms[i];
    }
    return NULL;
}

static EVP_PKEY *generate_key(COMPOSITE_CTX *ctx, const char *algorithm,
                              int parameter)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;

    pctx = EVP_PKEY_CTX_new_from_name(ctx->libctx, algorithm, NULL);
    if (pctx == NULL || EVP_PKEY_keygen_init(pctx) <= 0)
        goto done;

    if (strcmp(algorithm, DEFAULT_RSA_NAME) == 0) {
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, parameter) <= 0)
            goto done;
    } else if (strcmp(algorithm, "EC") == 0) {
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, parameter) <= 0)
            goto done;
    }

    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

COMPOSITE_KEM_KEY *composite_kemkey_new(void)
{
    COMPOSITE_KEM_KEY *key = OPENSSL_malloc(sizeof(*key));

    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    memset(key, 0, sizeof(*key));
    return key;
}

int composite_kemkey_generate(COMPOSITE_KEM_KEY *key,
                              const char *algorithm,
                              COMPOSITE_CTX *ctx)
{
    const COMPOSITE_KEM_ALG_INFO *alg;
    EVP_PKEY *mlkem_key = NULL;
    EVP_PKEY *classic_key = NULL;

    if (key == NULL || algorithm == NULL || ctx == NULL || ctx->libctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    alg = composite_kem_alg_info_find(algorithm);
    if (alg == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return 0;
    }

    mlkem_key = generate_key(ctx, alg->mlkem_name, 0);
    if (mlkem_key == NULL)
        goto err;

    classic_key = generate_key(ctx, alg->classic_name, alg->classic_param);
    if (classic_key == NULL)
        goto err;

    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    key->provctx = ctx;
    key->composite_name = alg->composite_name;
    key->mlkem_name = alg->mlkem_name;
    key->classic_algorithm_name = alg->classic_name;
    key->mlkem_pubkey = mlkem_key;
    key->classic_pubkey = classic_key;
    key->has_private = 1;
    return 1;

err:
    EVP_PKEY_free(mlkem_key);
    EVP_PKEY_free(classic_key);
    return 0;
}

void composite_kemkey_free(COMPOSITE_KEM_KEY *key)
{
    if (key == NULL)
        return;

    EVP_PKEY_CTX_free(key->ml_kem_ctx);
    EVP_PKEY_CTX_free(key->classic_ctx);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_privkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    OPENSSL_free(key);
}

int composite_kemkey_get0_components(const COMPOSITE_KEM_KEY *key,
                                     EVP_PKEY **ml_kem_key,
                                     EVP_PKEY **trad_key)
{
    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    *ml_kem_key = (EVP_PKEY *)key->mlkem_pubkey;
    *trad_key = (EVP_PKEY *)key->classic_pubkey;
    return 1;
}

int composite_kemkey_set0_components(COMPOSITE_KEM_KEY *key,
                                     EVP_PKEY *ml_kem_key,
                                     EVP_PKEY *trad_key)
{
    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    EVP_PKEY_free((EVP_PKEY *)key->mlkem_pubkey);
    EVP_PKEY_free((EVP_PKEY *)key->classic_pubkey);
    key->mlkem_pubkey = ml_kem_key;
    key->classic_pubkey = trad_key;
    key->has_private = 1;
    return 1;
}
