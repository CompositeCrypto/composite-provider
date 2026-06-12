#ifndef COMPOSITE_SIG_ENCODING_H
#define COMPOSITE_SIG_ENCODING_H

#include <stddef.h>
#include <string.h>

// #include "composite_encoding.h" /* for algorithm IDs and ML-DSA sizes */

#include "composite_sig_key.h"

/*
 * Encode a COMPOSITE_KEY's public material to wire format: mldsa_pub || classic_pub.
 * Allocates *out with OPENSSL_malloc; caller must OPENSSL_free it.
 * @return 1 on success, 0 on failure
 */
int composite_sig_pubkey_encode(COMPOSITE_KEY *key,
                                unsigned char **out, size_t *out_len);

/*
 * Decode a wire-format public key blob and install the ML-DSA and classic
 * public keys into key->mldsa_pubkey and key->classic_pubkey.
 * @return 1 on success, 0 on failure
 */
int composite_sig_pubkey_decode(COMPOSITE_KEY *key,
                                const unsigned char *data, size_t data_len);

/*
 * Encode a COMPOSITE_KEY's private material to wire format: mldsa_seed || classic_priv.
 * Allocates *out with OPENSSL_malloc; caller must OPENSSL_free it.
 * @return 1 on success, 0 on failure
 */
int composite_sig_privkey_encode(COMPOSITE_KEY *key,
                                 unsigned char **out, size_t *out_len);

/*
 * Decode a wire-format private key blob and install the ML-DSA and classic
 * private keys into key->mldsa_privkey and key->classic_privkey.
 * @return 1 on success, 0 on failure
 */
int composite_sig_privkey_decode(COMPOSITE_KEY *key,
                                 const unsigned char *data, size_t data_len);

/* EVP_PKEY <-> raw bytes helpers (implemented in composite_sig_encoding.c) */
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/params.h>

int      classic_pubkey_to_bytes(EVP_PKEY *pkey,
                                 unsigned char **out, size_t *out_len);
int      classic_privkey_to_bytes(EVP_PKEY *pkey,
                                  unsigned char **out, size_t *out_len);
EVP_PKEY *classic_pubkey_from_bytes(OSSL_LIB_CTX *libctx,
                                    const char *alg_name, int classic_param,
                                    const unsigned char *data, size_t data_len);
EVP_PKEY *classic_privkey_from_bytes(OSSL_LIB_CTX *libctx,
                                     const char *alg_name,
                                     const unsigned char *data, size_t data_len);

/* Export a COMPOSITE_KEY to OSSL_PARAMs via composite_sig_pubkey/privkey_encode. */
int composite_key_export(void *keydata, int selection,
                         OSSL_CALLBACK *param_cb, void *cbarg);

/* Import a COMPOSITE_KEY from OSSL_PARAMs via composite_sig_pubkey/privkey_decode. */
int composite_key_import(void *keydata, int selection,
                         const OSSL_PARAM params[]);

#endif /* COMPOSITE_SIG_ENCODING_H */
