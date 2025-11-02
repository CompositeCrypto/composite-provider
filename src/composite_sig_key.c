#include "composite_sig_key.h"

                    // ===========================
                    // Static Functions Prototypes
                    // ===========================

int ml_dsa_key_generate(EVP_PKEY_CTX *ctx, const char *algorithm, COMPOSITE_CTX *composite_ctx);
int classic_key_generate(EVP_PKEY_CTX *ctx, const char *algorithm, COMPOSITE_CTX *composite_ctx);

                    // ================
                    // Public Functions
                    // ================


COMPOSITE_KEY * composite_signkey_new(void) {

    COMPOSITE_KEY *key = NULL;
    
    key = (COMPOSITE_KEY *)OPENSSL_malloc(sizeof(COMPOSITE_KEY));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    key->provctx = NULL;

    // Composite key information
    key->nid = 0;
    key->composite_name = NULL;
    key->composite_tls_name = NULL;

    // ML-DSA component and context
    key->mldsa_name = NULL;
    key->ml_dsa_ctx = NULL;
    key->mldsa_privkey = NULL;
    key->mldsa_pubkey = NULL;

    // Classic Algorithm component and context
    key->classic_algorithm_name = NULL;
    key->classic_ctx = NULL;
    key->classic_privkey = NULL;
    key->classic_pubkey = NULL;

    // Success
    return key;
}

int composite_signkey_generate(COMPOSITE_KEY * key,
                           const char    * const algorithm,
                           COMPOSITE_CTX * ctx) {

        if (key == NULL || algorithm == NULL || ctx == NULL) {
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
            return 0;
        }

        // Generate key material for ML-DSA component
        if (!ml_dsa_key_generate(key->ml_dsa_ctx, algorithm, ctx)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }

        // Generate key material for classic component
        if (!classic_key_generate(key->classic_ctx, algorithm, ctx)) {
            ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
            return 0;
        }

    return 1;
}


void composite_signkey_free(COMPOSITE_KEY * key) {
    if (key == NULL) {
        return;
    }

    // Free ML-DSA component
    if (key->ml_dsa_ctx != NULL) {
        EVP_PKEY_CTX_free(key->ml_dsa_ctx);
    }
    if (key->mldsa_privkey != NULL) {
        EVP_PKEY_free(key->mldsa_privkey);
    }
    if (key->mldsa_pubkey != NULL) {
        EVP_PKEY_free(key->mldsa_pubkey);
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

int composite_signkey_get0_components(const COMPOSITE_KEY  * const key, 
                                 EVP_PKEY      ** const ml_dsa_key,
                                 EVP_PKEY      ** const trad_key) {
    if (key == NULL || ml_dsa_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    *ml_dsa_key = key->mldsa_pubkey;
    *trad_key = key->classic_pubkey;

    return 1;
}


int composite_signkey_set0_components(COMPOSITE_KEY * key, 
                                  EVP_PKEY      * ml_dsa_key,
                                  EVP_PKEY      * trad_key) {

    if (key == NULL || ml_dsa_key == NULL || trad_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    key->mldsa_pubkey = ml_dsa_key;
    key->classic_pubkey = trad_key;

    return 1;
}

                    // ================================
                    // Static Functions Implementations
                    // ================================

int ml_dsa_key_generate(EVP_PKEY_CTX  * ctx, 
                        const char    * algorithm, 
                        COMPOSITE_CTX * composite_ctx) {
    return 0;
}

int classic_key_generate(EVP_PKEY_CTX  * ctx, 
                         const char    * algorithm, 
                         COMPOSITE_CTX * composite_ctx) {
    return 0;
}