#include "provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>
#include <stdlib.h>

/* Key context structure */
typedef struct composite_key_st {
    COMPOSITE_CTX *provctx;

    /*MLDSA*/
    const char *mldsa_name;
    EVP_PKEY_CTX *mldsa_ctx;
    EVP_PKEY *mldsa_key;
    void *mldsa_privkey;
    void *mldsa_pubkey;

    /*Classic Algorithm*/
    const char *classic_algorithm_name;
    EVP_PKEY_CTX *classic_ctx;
    EVP_PKEY *classic_key;
    void *classic_privkey;
    void *classic_pubkey;

} COMPOSITE_KEY;


COMPOSITE_KEY *composite_key_new(COMPOSITE_CTX *ctx, const char *propq, int composite_alg_id) {
    
    int ret = 0;
    
    COMPOSITE_KEY *key = NULL;

    // Missing implementation
    // key->mldsa_key = ossl_ml_dsa_key_new(ctx->libctx, propq, ml_dsa_evp_type);

    // key = (COMPOSITE_KEY *)OPENSSL_malloc(sizeof(COMPOSITE_KEY));
    // if (key == NULL) {
    //     ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    //     return NULL;
    // }

    // key->provctx = ctx;
    // key->mldsa_name = NULL;

    COMPOSITE_DEBUG("composite_key_new: Created new composite key context");
    return key;
}