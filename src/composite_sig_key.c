#include "composite_sig_key.h"

                    // ===========================
                    // Static Functions Prototypes
                    // ===========================

int ml_dsa_id_from_algorithm(const char * algorithm);
int classic_id_from_algorithm(const char * algorithm);

int composite_algorithm_get_trad_param(const char * composite_algorithm);
const char * composite_algorithm_get_trad_name(const char * composite_algorithm);
const char * composite_algorithm_get_mldsa_name(const char * composite_algorithm);

EVP_PKEY * ml_dsa_key_generate(COMPOSITE_CTX *composite_ctx, const char *algorithm);
EVP_PKEY * classic_key_generate(COMPOSITE_CTX *composite_ctx, const char *algorithm, int param);

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

int composite_signkey_generate(COMPOSITE_CTX * ctx,
                               COMPOSITE_KEY * key,
                               const char    * const algorithm) {

    EVP_PKEY * ml_dsa_key = NULL;
        // ML-DSA component key

    EVP_PKEY * classic_key = NULL;
        // Classic component key
    
    int trad_param = 0;
        // Parameter for the classic algorithm (key size or curve NID)

    const char * trad_alg = NULL;
        // Name of the classic algorithm
    
    const char * mldsa_alg = NULL;
        // Name of the ML-DSA algorithm

    if (key == NULL || algorithm == NULL || ctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    // Retrieve the ml-dsa and trad algorithms names and param
    mldsa_alg = composite_algorithm_get_mldsa_name(algorithm);
    trad_alg = composite_algorithm_get_trad_name(algorithm);
    trad_param = composite_algorithm_get_trad_param(algorithm);
    if (mldsa_alg == NULL || trad_alg == NULL || trad_param == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    // Generate key material for ML-DSA component
    ml_dsa_key = ml_dsa_key_generate(ctx, mldsa_alg);
    if (ml_dsa_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    // Generate key material for classic component
    classic_key = classic_key_generate(ctx, trad_alg, trad_param);
    if (classic_key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_free(ml_dsa_key);
        return 0;
    }

    // Assign generated keys to composite key structure
    if (!composite_signkey_set0_components(key, ml_dsa_key, classic_key)) {
        EVP_PKEY_free(ml_dsa_key);
        EVP_PKEY_free(classic_key);
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


const char * composite_algorithm_get_mldsa_name(const char * composite_algorithm) {

    if (composite_algorithm == NULL) {
        return NULL;
    }

    if (strcmp(composite_algorithm, MLDSA44_RSA2048_PSS_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA44_RSA2048_PKCS15_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA44_ED25519_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA44_P256_SN) == 0) {
        return DEFAULT_MLDSA44_NAME;
    } else if (strcmp(composite_algorithm, MLDSA65_ED25519_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA3072_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA3072_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA4096_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA4096_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_P256_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_P384_SN) == 0) {
        return DEFAULT_MLDSA65_NAME;
    } else if (strcmp(composite_algorithm, MLDSA87_RSA3072_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_RSA4096_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_ED448_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_P384_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_P521_SN) == 0) {
        return DEFAULT_MLDSA87_NAME;
    }

    return NULL; // Unknown composite algorithm
}

const char * composite_algorithm_get_trad_name(const char * composite_algorithm) {

    if (composite_algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (strcmp(composite_algorithm, MLDSA44_RSA2048_PSS_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA65_RSA3072_PSS_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA65_RSA4096_PSS_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA87_RSA3072_PSS_SN) == 0 ||
        strcmp(composite_algorithm, MLDSA87_RSA4096_PSS_SN) == 0) {

        return DEFAULT_RSA_NAME;

    } else if (strcmp(composite_algorithm, MLDSA44_RSA2048_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA3072_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA4096_PKCS15_SN) == 0) {

        return DEFAULT_RSAPSS_NAME;

    } else if (strcmp(composite_algorithm, MLDSA44_ED25519_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_ED25519_SN) == 0) {

        return DEFAULT_ED25519_NAME;

    } else if (strcmp(composite_algorithm, MLDSA87_ED448_SN) == 0) {

        return DEFAULT_ED448_NAME;

    } else if (strcmp(composite_algorithm, MLDSA44_P256_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_P256_SN) == 0) {

        return DEFAULT_ECDSA_NISTP256_NAME;

    } else if (strcmp(composite_algorithm, MLDSA65_P384_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_P384_SN) == 0) {

        return DEFAULT_ECDSA_NISTP384_NAME;

    } else if (strcmp(composite_algorithm, MLDSA87_P521_SN) == 0) {

        return DEFAULT_ECDSA_NISTP521_NAME;
    
    } else if (strcmp(composite_algorithm, MLDSA65_BRAINPOOLP256_SN) == 0) {

        return DEFAULT_ECDSA_BRAINPOOL256_NAME;

    } else if (strcmp(composite_algorithm, MLDSA87_BRAINPOOLP384_SN) == 0) {

        return DEFAULT_ECDSA_BRAINPOOL384_NAME;

    } else {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
    }

    return NULL; // Unknown composite algorithm
}

int composite_algorithm_get_trad_param(const char * composite_algorithm) {

    if (composite_algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (strcmp(composite_algorithm, MLDSA44_RSA2048_PSS_SN) == 0) {
        return 2048;
    } else if (strcmp(composite_algorithm, MLDSA65_RSA3072_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA3072_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_RSA3072_PSS_SN) == 0) {
        return 3072;
    } else if (strcmp(composite_algorithm, MLDSA65_RSA4096_PSS_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_RSA4096_PKCS15_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_RSA4096_PSS_SN) == 0) {
        return 4096;
    } else if (strcmp(composite_algorithm, MLDSA44_P256_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_P256_SN) == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(composite_algorithm, MLDSA65_P384_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA87_P384_SN) == 0){
        return NID_secp384r1;
    } else if (strcmp(composite_algorithm, MLDSA87_P521_SN) == 0) {
        return NID_secp521r1;
    } else if (strcmp(composite_algorithm, MLDSA65_BRAINPOOLP256_SN) == 0) {
        return NID_brainpoolP256r1;
    } else if (strcmp(composite_algorithm, MLDSA87_BRAINPOOLP384_SN) == 0) {
        return NID_brainpoolP384r1;
    } else if (strcmp(composite_algorithm, MLDSA44_ED25519_SN) == 0 ||
               strcmp(composite_algorithm, MLDSA65_ED25519_SN) == 0) {
        return 0;
    } else if (strcmp(composite_algorithm, MLDSA87_ED448_SN) == 0) {
        return 0;
    }

    // Unknown composite algorithm
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);

    // Error
    return 0;
}

int ml_dsa_id_from_algorithm(const char * mldsa_algorithm) {

    if (mldsa_algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (strcmp(mldsa_algorithm, "ML-DSA-44") == 0) {
        return ML_DSA_44;
    } else if (strcmp(mldsa_algorithm, "ML-DSA-65") == 0) {
        return ML_DSA_65;
    } else if (strcmp(mldsa_algorithm, "ML-DSA-87") == 0) {
        return ML_DSA_87;
    } else {
        return 0; // Unknown algorithm
    }
}

int classic_id_from_algorithm(const char * trad_algorithm) {

    if (trad_algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (strcmp(trad_algorithm, DEFAULT_RSA_NAME) == 0) {
        return NID_rsaEncryption;
    } else if (strcmp(trad_algorithm, DEFAULT_RSAPSS_NAME) == 0) {
        return NID_rsassaPss;
    } else if (strcmp(trad_algorithm, DEFAULT_ED25519_NAME) == 0) {
        return NID_ED25519;
    } else if (strcmp(trad_algorithm, DEFAULT_ED448_NAME) == 0) {
        return NID_ED448;
    } else if (strcmp(trad_algorithm, DEFAULT_ECDSA_NISTP256_NAME) == 0) {
        return NID_X9_62_prime256v1;
    } else if (strcmp(trad_algorithm, DEFAULT_ECDSA_NISTP384_NAME) == 0) {
        return NID_secp384r1;
    } else if (strcmp(trad_algorithm, DEFAULT_ECDSA_NISTP521_NAME) == 0) {
        return NID_secp521r1;
    } else if (strcmp(trad_algorithm, DEFAULT_ECDSA_BRAINPOOL256_NAME) == 0) {
        return NID_brainpoolP256r1;
    } else if (strcmp(trad_algorithm, DEFAULT_ECDSA_BRAINPOOL384_NAME) == 0) {
        return NID_brainpoolP384r1;
    } else {
        return 0; // Unknown algorithm
    }
}

EVP_PKEY * ml_dsa_key_generate(COMPOSITE_CTX * composite_ctx,
                               const char    * algorithm) {    

    EVP_PKEY *pkey = NULL;
        // Pointer for the generated key

    EVP_PKEY_CTX * pctx = NULL;
        // Pointer for the key generation context

    int alg_id = 0;
        // Provider's specific identifier for the ML-DSA algorithm

    if (composite_ctx == NULL || algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    alg_id = ml_dsa_id_from_algorithm(algorithm);
    if (alg_id == 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    // Generate the ML-DSA key based on the algorithm
    switch (alg_id) {
        
        case ML_DSA_44: {
            // Generate ML-DSA-44 key
            pctx = EVP_PKEY_CTX_new_from_name(composite_ctx->libctx, "ML-DSA-44", NULL);
        } break;
        
        case ML_DSA_65: {
            // Generate ML-DSA-65 key
            pctx = EVP_PKEY_CTX_new_from_name(composite_ctx->libctx, "ML-DSA-65", NULL);
        } break;

        case ML_DSA_87: {
            // Generate ML-DSA-87 key
            pctx = EVP_PKEY_CTX_new_from_name(composite_ctx->libctx, "ML-DSA-87", NULL);
        } break;

        default:
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return NULL;
    }

    if (pctx == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if ((EVP_PKEY_keygen_init(pctx) <= 0) ||
                (EVP_PKEY_generate(pctx, &pkey) <= 0)) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    return pkey;
}

EVP_PKEY * classic_key_generate(COMPOSITE_CTX * composite_ctx, 
                                const char    * algorithm,
                                int             curve_or_keysize) {

    EVP_PKEY *pkey = NULL;
        // Pointer for the generated key
    
    EVP_PKEY_CTX * ctx = NULL;
        // Pointer for the key generation context

    int alg_id = 0;
        // Provider's specific identifier for the classic algorithm

    if (composite_ctx == NULL || algorithm == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    alg_id = classic_id_from_algorithm(algorithm);
    if (alg_id == 0 || curve_or_keysize <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
        return NULL;
    }


    // Generate the classic key based on the algorithm
    switch (alg_id) {

        case NID_rsassaPss:
        case NID_rsaEncryption: {
            // Checks the key size
            if (curve_or_keysize != 2048 && curve_or_keysize != 3072 && 
                                                    curve_or_keysize != 4096) {
                // We only allow for 2048, 3072, and 4096 bits RSA keys
                ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
                return NULL;
            }
            // Generate RSA or RSA-PSS key
            if (alg_id == NID_rsassaPss) {
                ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA_PSS, NULL);
            } else {
                ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            }
            if (!ctx) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, curve_or_keysize) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            /* Generate key */
            if (!EVP_PKEY_generate(ctx, &pkey)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_free(pkey);
                return NULL;
            }
        } break;

        case NID_X9_62_prime256v1:
        case NID_secp384r1:
        case NID_secp521r1:
        case NID_brainpoolP256r1:
        case NID_brainpoolP384r1: {
            // Generate ECDSA key
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
            if (!ctx) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }

            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, alg_id) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }

            if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, alg_id) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            
            if (!EVP_PKEY_generate(ctx, &pkey)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                if (pkey) EVP_PKEY_free(pkey);
                return NULL;
            }
        } break;

        case NID_ED25519: {
            // Generate Ed25519 key
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
            if (!ctx) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                return NULL;
            }
            if (!EVP_PKEY_generate(ctx, &pkey)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                if (pkey) EVP_PKEY_free(pkey);
                return NULL;
            }
        } break;

        case NID_ED448: {
            // Generate Ed448 key
            ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED448, NULL);
            if (!ctx) {
                ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
                return NULL;
            }
            if (EVP_PKEY_keygen_init(ctx) <= 0) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_CTX_free(ctx);
                return NULL;
            }
            if (!EVP_PKEY_generate(ctx, &pkey)) {
                ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
                EVP_PKEY_free(pkey);
                return NULL;
            }
        } break;

        default:
            ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_INVALID_ARGUMENT);
            return NULL;
    }

    return pkey;
}