/*
 * composite_decoder.c — DER decoder for composite key types
 *
 * Implements OSSL_OP_DECODER for:
 *   - SubjectPublicKeyInfo / DER  (public keys embedded in X.509 certificates)
 *   - PrivateKeyInfo / DER        (unencrypted PKCS#8 private keys)
 *
 * When OpenSSL parses an X.509 certificate whose SubjectPublicKeyInfo carries
 * a composite OID it invokes this decoder to reconstruct the EVP_PKEY.
 * Without a registered decoder X509_PUBKEY_get0() fails with
 * "decode error" (crypto/x509/x_pubkey.c).
 *
 * Wire formats (identical to what composite_encoder.c produces):
 *   Public  key: mldsa_pub  || classic_pub   (raw concatenation, no ASN.1 wrap)
 *   Private key: mldsa_seed || classic_priv  (raw concatenation, no ASN.1 wrap)
 */

#include "composite_decoder.h"
#include "composite_sig_key.h"
#include "composite_sig_encoding.h"
#include "composite_keymgmt.h"
#include "provider_ctx.h"
#include "../include/composite_provider.h"

#include <string.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* =========================================================================
 * Decoder context
 * ========================================================================= */

typedef struct {
    COMPOSITE_CTX *provctx;
    const char    *composite_name; /* static SN string, e.g. MLDSA44_ED25519_SN */
} COMPOSITE_DEC_CTX;

static void composite_dec_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/* =========================================================================
 * SubjectPublicKeyInfo / DER decoder
 * ========================================================================= */

static int composite_spki_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

static int composite_spki_decode(void *vctx, OSSL_CORE_BIO *cin,
                                  int selection,
                                  OSSL_CALLBACK *object_cb, void *object_cbarg,
                                  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_DEC_CTX   *ctx    = (COMPOSITE_DEC_CTX *)vctx;
    BIO                 *in     = NULL;
    unsigned char       *derbuf = NULL;
    long                 derlen = 0;
    const unsigned char *p      = NULL;
    long                 seqlen = 0;
    int                  tag, xclass;
    X509_ALGOR          *alg    = NULL;
    ASN1_BIT_STRING     *bs     = NULL;
    COMPOSITE_KEY       *key    = NULL;
    int                  ret    = 0;

    (void)pw_cb; (void)pw_cbarg;

    if (selection != 0 && !(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 1; /* not our selection — not an error, let others try */

    in = BIO_new_from_core_bio(ctx->provctx->libctx, cin);
    if (in == NULL)
        return 0;

    /*
     * Read the full SPKI DER.
     *
     * We MUST NOT call ASN1_item_d2i_bio(X509_PUBKEY, ...) here.  That
     * function's d2i callback (x509_pubkey_ex_d2i_ex) calls back into the
     * OSSL_DECODER framework with the same SPKI data to decode pubkey->pkey,
     * which dispatches to this very decoder again → infinite recursion →
     * stack overflow → segfault.
     *
     * Instead, read the raw DER bytes and parse the SPKI structure manually
     * using only d2i_X509_ALGOR + d2i_ASN1_BIT_STRING, which have no
     * decoder-framework callbacks.
     *
     * Use a looped BIO_read so that partial reads (possible with non-memory
     * core BIOs) don't silently truncate the buffer.
     */
    {
        unsigned char  chunk[4096];
        int            n;
        unsigned char *tmp;

        while ((n = BIO_read(in, chunk, (int)sizeof(chunk))) > 0) {
            tmp = OPENSSL_realloc(derbuf, (size_t)(derlen + n));
            if (tmp == NULL)
                goto done;
            derbuf = tmp;
            memcpy(derbuf + derlen, chunk, (size_t)n);
            derlen += (long)n;
        }
        if (derlen == 0)
            goto done;
    }

    /* Skip the outer SEQUENCE tag + length */
    p = derbuf;
    if (ASN1_get_object(&p, &seqlen, &tag, &xclass, derlen) & 0x80
            || tag != V_ASN1_SEQUENCE)
        goto done;

    /* Skip AlgorithmIdentifier (OID already verified by the dispatch table) */
    alg = d2i_X509_ALGOR(NULL, &p, seqlen);
    if (alg == NULL)
        goto done;

    /* BIT STRING content = raw mldsa_pub || classic_pub bytes */
    bs = d2i_ASN1_BIT_STRING(NULL, &p, derbuf + derlen - p);
    if (bs == NULL || ASN1_STRING_get0_data(bs) == NULL || ASN1_STRING_length(bs) <= 0)
        goto done;

    key = composite_key_new(ctx->provctx, ctx->composite_name);
    if (key == NULL)
        goto done;

    if (!composite_sig_pubkey_decode(key, ASN1_STRING_get0_data(bs), (size_t)ASN1_STRING_length(bs)))
        goto done;

    /* Pass the key back to the framework via KEYMGMT_LOAD reference */
    {
        int        obj_type = OSSL_OBJECT_PKEY;
        OSSL_PARAM params[4];
        int        i = 0;

        params[i++] = OSSL_PARAM_construct_int(
                OSSL_OBJECT_PARAM_TYPE, &obj_type);
        params[i++] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[i++] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE,
                (char *)ctx->composite_name, 0);
        params[i]   = OSSL_PARAM_construct_end();

        ret = object_cb(params, object_cbarg);
        if (ret)
            key = NULL; /* ownership transferred via KEYMGMT_LOAD */
    }

done:
    BIO_free(in);
    X509_ALGOR_free(alg);
    ASN1_BIT_STRING_free(bs);
    OPENSSL_free(derbuf);
    if (key != NULL)
        composite_signkey_free(key);
    return ret;
}

/* =========================================================================
 * PrivateKeyInfo / DER decoder
 * ========================================================================= */

static int composite_pki_does_selection(void *provctx, int selection)
{
    (void)provctx;
    if (selection == 0)
        return 1;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

static int composite_pki_decode(void *vctx, OSSL_CORE_BIO *cin,
                                 int selection,
                                 OSSL_CALLBACK *object_cb, void *object_cbarg,
                                 OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    COMPOSITE_DEC_CTX    *ctx     = (COMPOSITE_DEC_CTX *)vctx;
    BIO                  *in      = NULL;
    PKCS8_PRIV_KEY_INFO  *p8      = NULL;
    const ASN1_OBJECT    *palg    = NULL;
    const unsigned char  *pkey    = NULL;
    int                   pkeylen = 0;
    const X509_ALGOR     *alg     = NULL;
    COMPOSITE_KEY        *key     = NULL;
    int                   ret     = 0;

    (void)pw_cb; (void)pw_cbarg;

    if (selection != 0 && !(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 1;

    in = BIO_new_from_core_bio(ctx->provctx->libctx, cin);
    if (in == NULL)
        return 0;

    p8 = (PKCS8_PRIV_KEY_INFO *)ASN1_item_d2i_bio(
            ASN1_ITEM_rptr(PKCS8_PRIV_KEY_INFO), in, NULL);
    BIO_free(in);
    if (p8 == NULL)
        return 0;

    if (!PKCS8_pkey_get0(&palg, &pkey, &pkeylen, &alg, p8))
        goto done;

    /* Verify the OID matches this decoder's composite algorithm */
    {
        int nid_got      = OBJ_obj2nid(palg);
        int nid_expected = OBJ_sn2nid(ctx->composite_name);
        if (nid_got == NID_undef || nid_got != nid_expected)
            goto done;
    }

    key = composite_key_new(ctx->provctx, ctx->composite_name);
    if (key == NULL)
        goto done;

    if (!composite_sig_privkey_decode(key, pkey, (size_t)pkeylen))
        goto done;

    /*
     * Derive the public-key components from the private-key material so that
     * composite_has(key, PUBLIC_KEY) returns true.
     *
     * - mldsa_privkey was loaded with EVP_PKEY_fromdata(KEYPAIR) from the
     *   32-byte seed, so it already contains the full ML-DSA public key.
     * - classic_privkey was decoded from its wire-format private bytes; for
     *   RSA and EC, OpenSSL derives the public key automatically; for
     *   Ed25519/Ed448 the public key is always part of the key object.
     *
     * Duplicating the private EVP_PKEYs gives us EVP_PKEYs that expose the
     * public component for signature verification.
     */
    key->mldsa_pubkey   = EVP_PKEY_dup((EVP_PKEY *)key->mldsa_privkey);
    key->classic_pubkey = EVP_PKEY_dup((EVP_PKEY *)key->classic_privkey);
    if (key->mldsa_pubkey == NULL || key->classic_pubkey == NULL)
        goto done;

    /* Pass the key back to the framework via KEYMGMT_LOAD reference */
    {
        int        obj_type = OSSL_OBJECT_PKEY;
        OSSL_PARAM params[4];
        int        i = 0;

        params[i++] = OSSL_PARAM_construct_int(
                OSSL_OBJECT_PARAM_TYPE, &obj_type);
        params[i++] = OSSL_PARAM_construct_octet_string(
                OSSL_OBJECT_PARAM_REFERENCE, &key, sizeof(key));
        params[i++] = OSSL_PARAM_construct_utf8_string(
                OSSL_OBJECT_PARAM_DATA_TYPE,
                (char *)ctx->composite_name, 0);
        params[i]   = OSSL_PARAM_construct_end();

        ret = object_cb(params, object_cbarg);
        if (ret)
            key = NULL; /* ownership transferred via KEYMGMT_LOAD */
    }

done:
    PKCS8_PRIV_KEY_INFO_free(p8);
    if (key != NULL)
        composite_signkey_free(key);
    return ret;
}

/* =========================================================================
 * Per-algorithm dispatch tables
 *
 * Each composite algorithm needs its own newctx so the decoder context
 * carries the correct composite_name (SN).  The decode logic is shared.
 * ========================================================================= */

#define MAKE_SPKI_DECODER(id, SN)                                              \
static void *composite_##id##_spki_newctx(void *provctx)                       \
{                                                                               \
    COMPOSITE_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                     \
    if (ctx != NULL) {                                                          \
        ctx->provctx        = (COMPOSITE_CTX *)provctx;                        \
        ctx->composite_name = (SN);                                            \
    }                                                                           \
    return ctx;                                                                 \
}                                                                               \
static const OSSL_DISPATCH composite_##id##_spki_dec_funcs[] = {               \
    { OSSL_FUNC_DECODER_NEWCTX,         (void(*)(void))composite_##id##_spki_newctx      }, \
    { OSSL_FUNC_DECODER_FREECTX,        (void(*)(void))composite_dec_freectx             }, \
    { OSSL_FUNC_DECODER_DOES_SELECTION, (void(*)(void))composite_spki_does_selection     }, \
    { OSSL_FUNC_DECODER_DECODE,         (void(*)(void))composite_spki_decode             }, \
    OSSL_DISPATCH_END                                                           \
}

#define MAKE_PKI_DECODER(id, SN)                                               \
static void *composite_##id##_pki_newctx(void *provctx)                        \
{                                                                               \
    COMPOSITE_DEC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));                     \
    if (ctx != NULL) {                                                          \
        ctx->provctx        = (COMPOSITE_CTX *)provctx;                        \
        ctx->composite_name = (SN);                                            \
    }                                                                           \
    return ctx;                                                                 \
}                                                                               \
static const OSSL_DISPATCH composite_##id##_pki_dec_funcs[] = {                \
    { OSSL_FUNC_DECODER_NEWCTX,         (void(*)(void))composite_##id##_pki_newctx       }, \
    { OSSL_FUNC_DECODER_FREECTX,        (void(*)(void))composite_dec_freectx             }, \
    { OSSL_FUNC_DECODER_DOES_SELECTION, (void(*)(void))composite_pki_does_selection      }, \
    { OSSL_FUNC_DECODER_DECODE,         (void(*)(void))composite_pki_decode              }, \
    OSSL_DISPATCH_END                                                           \
}

/* ML-DSA-44 */
MAKE_SPKI_DECODER(mldsa44_rsa2048_pss,    MLDSA44_RSA2048_PSS_SN);
MAKE_PKI_DECODER( mldsa44_rsa2048_pss,    MLDSA44_RSA2048_PSS_SN);
MAKE_SPKI_DECODER(mldsa44_rsa2048_pkcs15, MLDSA44_RSA2048_PKCS15_SN);
MAKE_PKI_DECODER( mldsa44_rsa2048_pkcs15, MLDSA44_RSA2048_PKCS15_SN);
MAKE_SPKI_DECODER(mldsa44_ed25519,        MLDSA44_ED25519_SN);
MAKE_PKI_DECODER( mldsa44_ed25519,        MLDSA44_ED25519_SN);
MAKE_SPKI_DECODER(mldsa44_p256,           MLDSA44_P256_SN);
MAKE_PKI_DECODER( mldsa44_p256,           MLDSA44_P256_SN);

/* ML-DSA-65 */
MAKE_SPKI_DECODER(mldsa65_rsa3072_pss,    MLDSA65_RSA3072_PSS_SN);
MAKE_PKI_DECODER( mldsa65_rsa3072_pss,    MLDSA65_RSA3072_PSS_SN);
MAKE_SPKI_DECODER(mldsa65_rsa3072_pkcs15, MLDSA65_RSA3072_PKCS15_SN);
MAKE_PKI_DECODER( mldsa65_rsa3072_pkcs15, MLDSA65_RSA3072_PKCS15_SN);
MAKE_SPKI_DECODER(mldsa65_rsa4096_pss,    MLDSA65_RSA4096_PSS_SN);
MAKE_PKI_DECODER( mldsa65_rsa4096_pss,    MLDSA65_RSA4096_PSS_SN);
MAKE_SPKI_DECODER(mldsa65_rsa4096_pkcs15, MLDSA65_RSA4096_PKCS15_SN);
MAKE_PKI_DECODER( mldsa65_rsa4096_pkcs15, MLDSA65_RSA4096_PKCS15_SN);
MAKE_SPKI_DECODER(mldsa65_p256,           MLDSA65_P256_SN);
MAKE_PKI_DECODER( mldsa65_p256,           MLDSA65_P256_SN);
MAKE_SPKI_DECODER(mldsa65_p384,           MLDSA65_P384_SN);
MAKE_PKI_DECODER( mldsa65_p384,           MLDSA65_P384_SN);
MAKE_SPKI_DECODER(mldsa65_brainpoolp256,  MLDSA65_BRAINPOOLP256_SN);
MAKE_PKI_DECODER( mldsa65_brainpoolp256,  MLDSA65_BRAINPOOLP256_SN);
MAKE_SPKI_DECODER(mldsa65_ed25519,        MLDSA65_ED25519_SN);
MAKE_PKI_DECODER( mldsa65_ed25519,        MLDSA65_ED25519_SN);

/* ML-DSA-87 */
MAKE_SPKI_DECODER(mldsa87_p384,           MLDSA87_P384_SN);
MAKE_PKI_DECODER( mldsa87_p384,           MLDSA87_P384_SN);
MAKE_SPKI_DECODER(mldsa87_brainpoolp384,  MLDSA87_BRAINPOOLP384_SN);
MAKE_PKI_DECODER( mldsa87_brainpoolp384,  MLDSA87_BRAINPOOLP384_SN);
MAKE_SPKI_DECODER(mldsa87_ed448,          MLDSA87_ED448_SN);
MAKE_PKI_DECODER( mldsa87_ed448,          MLDSA87_ED448_SN);
MAKE_SPKI_DECODER(mldsa87_rsa3072_pss,    MLDSA87_RSA3072_PSS_SN);
MAKE_PKI_DECODER( mldsa87_rsa3072_pss,    MLDSA87_RSA3072_PSS_SN);
MAKE_SPKI_DECODER(mldsa87_rsa4096_pss,    MLDSA87_RSA4096_PSS_SN);
MAKE_PKI_DECODER( mldsa87_rsa4096_pss,    MLDSA87_RSA4096_PSS_SN);
MAKE_SPKI_DECODER(mldsa87_p521,           MLDSA87_P521_SN);
MAKE_PKI_DECODER( mldsa87_p521,           MLDSA87_P521_SN);

/* =========================================================================
 * OSSL_ALGORITHM table
 * ========================================================================= */

#define SPKI_DEC(names, id)                                                    \
    { names,                                                                   \
      "provider=composite,input=der,structure=SubjectPublicKeyInfo",           \
      composite_##id##_spki_dec_funcs, NULL }

#define PKI_DEC(names, id)                                                     \
    { names,                                                                   \
      "provider=composite,input=der,structure=PrivateKeyInfo",                 \
      composite_##id##_pki_dec_funcs, NULL }

const OSSL_ALGORITHM *composite_decoders(void *provctx)
{
    (void)provctx;

    static const OSSL_ALGORITHM algorithms[] = {
        /* ML-DSA-44 */
        SPKI_DEC(PROV_NAMES_MLDSA44_RSA2048_PSS,    mldsa44_rsa2048_pss),
        PKI_DEC( PROV_NAMES_MLDSA44_RSA2048_PSS,    mldsa44_rsa2048_pss),
        SPKI_DEC(PROV_NAMES_MLDSA44_RSA2048_PKCS15, mldsa44_rsa2048_pkcs15),
        PKI_DEC( PROV_NAMES_MLDSA44_RSA2048_PKCS15, mldsa44_rsa2048_pkcs15),
        SPKI_DEC(PROV_NAMES_MLDSA44_ED25519,        mldsa44_ed25519),
        PKI_DEC( PROV_NAMES_MLDSA44_ED25519,        mldsa44_ed25519),
        SPKI_DEC(PROV_NAMES_MLDSA44_P256,           mldsa44_p256),
        PKI_DEC( PROV_NAMES_MLDSA44_P256,           mldsa44_p256),

        /* ML-DSA-65 */
        SPKI_DEC(PROV_NAMES_MLDSA65_RSA3072_PSS,    mldsa65_rsa3072_pss),
        PKI_DEC( PROV_NAMES_MLDSA65_RSA3072_PSS,    mldsa65_rsa3072_pss),
        SPKI_DEC(PROV_NAMES_MLDSA65_RSA3072_PKCS15, mldsa65_rsa3072_pkcs15),
        PKI_DEC( PROV_NAMES_MLDSA65_RSA3072_PKCS15, mldsa65_rsa3072_pkcs15),
        SPKI_DEC(PROV_NAMES_MLDSA65_RSA4096_PSS,    mldsa65_rsa4096_pss),
        PKI_DEC( PROV_NAMES_MLDSA65_RSA4096_PSS,    mldsa65_rsa4096_pss),
        SPKI_DEC(PROV_NAMES_MLDSA65_RSA4096_PKCS15, mldsa65_rsa4096_pkcs15),
        PKI_DEC( PROV_NAMES_MLDSA65_RSA4096_PKCS15, mldsa65_rsa4096_pkcs15),
        SPKI_DEC(PROV_NAMES_MLDSA65_P256,           mldsa65_p256),
        PKI_DEC( PROV_NAMES_MLDSA65_P256,           mldsa65_p256),
        SPKI_DEC(PROV_NAMES_MLDSA65_P384,           mldsa65_p384),
        PKI_DEC( PROV_NAMES_MLDSA65_P384,           mldsa65_p384),
        SPKI_DEC(PROV_NAMES_MLDSA65_BRAINPOOLP256,  mldsa65_brainpoolp256),
        PKI_DEC( PROV_NAMES_MLDSA65_BRAINPOOLP256,  mldsa65_brainpoolp256),
        SPKI_DEC(PROV_NAMES_MLDSA65_ED25519,        mldsa65_ed25519),
        PKI_DEC( PROV_NAMES_MLDSA65_ED25519,        mldsa65_ed25519),

        /* ML-DSA-87 */
        SPKI_DEC(PROV_NAMES_MLDSA87_P384,           mldsa87_p384),
        PKI_DEC( PROV_NAMES_MLDSA87_P384,           mldsa87_p384),
        SPKI_DEC(PROV_NAMES_MLDSA87_BRAINPOOLP384,  mldsa87_brainpoolp384),
        PKI_DEC( PROV_NAMES_MLDSA87_BRAINPOOLP384,  mldsa87_brainpoolp384),
        SPKI_DEC(PROV_NAMES_MLDSA87_ED448,          mldsa87_ed448),
        PKI_DEC( PROV_NAMES_MLDSA87_ED448,          mldsa87_ed448),
        SPKI_DEC(PROV_NAMES_MLDSA87_RSA3072_PSS,    mldsa87_rsa3072_pss),
        PKI_DEC( PROV_NAMES_MLDSA87_RSA3072_PSS,    mldsa87_rsa3072_pss),
        SPKI_DEC(PROV_NAMES_MLDSA87_RSA4096_PSS,    mldsa87_rsa4096_pss),
        PKI_DEC( PROV_NAMES_MLDSA87_RSA4096_PSS,    mldsa87_rsa4096_pss),
        SPKI_DEC(PROV_NAMES_MLDSA87_P521,           mldsa87_p521),
        PKI_DEC( PROV_NAMES_MLDSA87_P521,           mldsa87_p521),

        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
