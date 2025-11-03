#include "composite_kem_key.h"


                    // ===========================
                    // Static Functions Prototypes
                    // ===========================

int ml_kem_key_generate(EVP_PKEY_CTX *ctx, const char *algorithm, COMPOSITE_CTX *composite_ctx);
int classic_kex_key_generate(EVP_PKEY_CTX *ctx, const char *algorithm, COMPOSITE_CTX *composite_ctx);

                    // ================
                    // Public Functions
                    // ================

COMPOSITE_KEM_KEY * composite_kemkey_new(void) {

    COMPOSITE_KEM_KEY *key = NULL;

    key = (COMPOSITE_KEM_KEY *)OPENSSL_malloc(sizeof(COMPOSITE_KEM_KEY));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    key->provctx = NULL;

    // Composite key information
    key->nid = 0;
    key->composite_name = NULL;
    key->composite_tls_name = NULL;

    // ML-KEM component and context
    key->mlkem_name = NULL;
    key->ml_kem_ctx = NULL;
    key->mlkem_privkey = NULL;
    key->mlkem_pubkey = NULL;

    // Classic Algorithm component and context
    key->classic_algorithm_name = NULL;
    key->classic_ctx = NULL;
    key->classic_privkey = NULL;
    key->classic_pubkey = NULL;

    // Success
    return key;
}

int composite_kemkey_generate(COMPOSITE_KEM_KEY * key,
                              const char    * const algorithm,
                              COMPOSITE_CTX * ctx) {

        if (key == NULL || algorithm == NULL || ctx == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            return 0;
        }

        // Generate key material for ML-KEM component
        if (!ml_kem_key_generate(key->ml_kem_ctx, algorithm, ctx)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        // Generate key material for classic component
        if (!classic_kex_key_generate(key->classic_ctx, algorithm, ctx)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }

    return 1;
}


void composite_kemkey_free(COMPOSITE_KEM_KEY * key) {
    if (key == NULL) {
        return;
    }

    // Free ML-KEM component
    if (key->ml_kem_ctx != NULL) {
        EVP_PKEY_CTX_free(key->ml_kem_ctx);
    }
    if (key->mlkem_privkey != NULL) {
        EVP_PKEY_free(key->mlkem_privkey);
    }
    if (key->mlkem_pubkey != NULL) {
        EVP_PKEY_free(key->mlkem_pubkey);
    }

    // Free classic component
    if (key->classic_ctx != NULL) {
        EVP_PKEY_CTX_free(key->classic_ctx);
    }
    if (key->classic_privkey != NULL) {
        EVP_PKEY_free(key->classic_privkey);
    }
    if (key->classic_pubkey != NULL) {
        EVP_PKEY_free(key->classic_pubkey);
    }

    // Free the key structure itself
    OPENSSL_free(key);
}

int composite_kemkey_get0_components(const COMPOSITE_KEM_KEY  * const key, 
                                     EVP_PKEY                ** const ml_kem_key,
                                     EVP_PKEY                ** const trad_key) {
    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    *ml_kem_key = key->mlkem_pubkey;
    *trad_key = key->classic_pubkey;

    return 1;
}


int composite_kemkey_set0_components(COMPOSITE_KEM_KEY * key, 
                                     EVP_PKEY          * ml_kem_key,
                                     EVP_PKEY          * trad_key) {

    if (key == NULL || ml_kem_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    key->mlkem_pubkey = ml_kem_key;
    key->classic_pubkey = trad_key;

    return 1;
}

                    // ================================
                    // Static Functions Implementations
                    // ================================

int ml_kem_key_generate(EVP_PKEY_CTX  * ctx, 
                        const char    * algorithm, 
                        COMPOSITE_CTX * composite_ctx) {
    return 0;
}

int classic_kex_key_generate(EVP_PKEY_CTX  * ctx, 
                             const char    * algorithm, 
                             COMPOSITE_CTX * composite_ctx) {
    return 0;
}