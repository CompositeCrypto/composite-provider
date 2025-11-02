#include "composite_provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>
#include <stdlib.h>

/* Key context structure */
typedef struct composite_key_st {
    COMPOSITE_PROV_CTX *provctx;

    /*MLDSA*/
    const char *mldsa_name;
    ML_DSA_KEY *mldsa_key;
    void *mldsa_privkey;
    void *mldsa_pubkey;

    /*Classic Algorithm*/
    const char *classic_algorithm_name;
    EVP_PKEY_CTX *classic_ctx;
    void *classic_privkey;
    void *classic_pubkey;

} COMPOSITE_KEY;


COMPOSITE_KEY *composite_key_new(COMPOSITE_PROV_CTX ctx, const char *propq, int ml_dsa_evp_type){
    int ret = 0;
    COMPOSITE_KEY *key;

    key->mldsa_key = ossl_ml_dsa_key_new(ctx.libctx, propq, ml_dsa_evp_type);
    
    

    return key;
}