#ifndef HEADER_COMPOSITE_SIG_FN_H
#define HEADER_COMPOSITE_SIG_FN_H

#include <string.h>
#include <stdlib.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

#include "composite_provider.h"
#include "provider.h"

/* Placeholder signature sizes (these would be calculated based on component algorithms) */
#define COMPOSITE_SIG_SIZE 4096  /* Placeholder: ML-DSA + traditional signature */
#define COMPOSITE_PREFIX 0x436F6D706F73697465416C676F726974686D5369676E61747572657332303235 /* "CompositeAlgorithmSignatures2025" in hex */ 

/* Composite Labels */
static const unsigned char *composite_sig_label[] = {
	(const unsigned char*) "COMPSIG-MLDSA44-RSA2048-PSS-SHA256",
	(const unsigned char*) "COMPSIG-MLDSA44-RSA2048-PKCS15-SHA256",
	(const unsigned char*) "COMPSIG-MLDSA44-Ed25519-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
	(const unsigned char*) "COMPSIG-MLDSA65-RSA3072-PSS-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-RSA3072-PKCS15-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-RSA4096-PSS-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-RSA4096-PKCS15-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-ECDSA-P384-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-ECDSA-BP256-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA65-Ed25519-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA87-ECDSA-BP384-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA87-Ed448-SHAKE256",
	(const unsigned char*) "COMPSIG-MLDSA87-RSA3072-PSS-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA87-RSA4096-PSS-SHA512",
	(const unsigned char*) "COMPSIG-MLDSA87-ECDSA-P521-SHA512"
};

/* Signature context structure */
typedef struct composite_sig_ctx_st {
    COMPOSITE_CTX *provctx;
    const char *algorithm_name;
    const char *pre_hash_func;
    const char *label;
    const char *ml_dsa;
    EVP_MD_CTX *evp_ctx;
    /* Key material would go here */
    unsigned char *sig_buffer;
    size_t sig_buffer_len;
}COMPOSITE_SIG_CTX;


#define DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define EXTERN_DECLARE_SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    extern const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[];

#define SIG_DISPATCH_TABLE(alg_name, alg2_name) \
    const OSSL_DISPATCH composite_##alg_name##_##alg2_name##_signature_functions[] = { \
        { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))composite_sig_newctx }, \
        { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))composite_sig_freectx }, \
        { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))composite_sig_sign_init }, \
        { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))composite_sig_sign }, \
        { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))composite_sig_verify_init }, \
        { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))composite_sig_verify }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))composite_sig_digest_sign_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))composite_sig_digest_sign }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))composite_sig_digest_verify_init }, \
        { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))composite_sig_digest_verify }, \
        { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))composite_sig_get_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS, (void (*)(void))composite_sig_gettable_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))composite_sig_set_ctx_params }, \
        { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS, (void (*)(void))composite_sig_settable_ctx_params }, \
        {0, NULL} \
    }

//                     // ====================
//                     // Signature operations
//                     // ====================

// DECLARE_SIG_DISPATCH_TABLE(mldsa44, rsa2048)
// DECLARE_SIG_DISPATCH_TABLE(mldsa44, ecdsa_p256)
// DECLARE_SIG_DISPATCH_TABLE(mldsa65, rsa3072)
// DECLARE_SIG_DISPATCH_TABLE(mldsa65, ecdsa_p384)
// DECLARE_SIG_DISPATCH_TABLE(mldsa87, rsa4096)
// DECLARE_SIG_DISPATCH_TABLE(mldsa87, ecdsa_p521)

#endif /* HEADER_COMPOSITE_SIG_FN_H */
