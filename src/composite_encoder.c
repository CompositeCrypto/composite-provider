/*
 * composite_encoder.c — PEM/DER encoder for composite key types
 *
 * Implements OSSL_OP_ENCODER for:
 *   - PrivateKeyInfo / PEM   (unencrypted PKCS#8)
 *   - SubjectPublicKeyInfo / PEM
 *
 * All composite SIG algorithms share the same two dispatch tables; the
 * per-algorithm OID is resolved at encode-time via OBJ_sn2nid() using the
 * key's composite_name field (which holds the algorithm SN).
 */

#include "composite_encoder.h"
#include "composite_sig_encoding.h"
#include "composite_sig_key.h"
#include "provider_ctx.h"
#include "../include/composite_provider.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/bio.h>

/* =========================================================================
 * OID registration
 * ========================================================================= */

/*
 * Register all composite SIG algorithm OIDs in the global OBJ database so
 * that OBJ_sn2nid() / OBJ_txt2nid() resolve them.  Idempotent — safe to
 * call multiple times.
 */
void composite_register_oids(void)
{
#define REGISTER(oid, sn, ln) do { \
        int _nid = OBJ_create((oid), (sn), (ln)); \
        if (_nid != NID_undef) \
            OBJ_add_sigid(_nid, NID_undef, _nid); \
    } while (0)

    /* ML-DSA-44 */
    REGISTER(MLDSA44_RSA2048_PSS_OID,    MLDSA44_RSA2048_PSS_SN,    MLDSA44_RSA2048_PSS_LN);
    REGISTER(MLDSA44_RSA2048_PKCS15_OID, MLDSA44_RSA2048_PKCS15_SN, MLDSA44_RSA2048_PKCS15_LN);
    REGISTER(MLDSA44_ED25519_OID,        MLDSA44_ED25519_SN,        MLDSA44_ED25519_LN);
    REGISTER(MLDSA44_P256_OID,           MLDSA44_P256_SN,           MLDSA44_P256_LN);

    /* ML-DSA-65 */
    REGISTER(MLDSA65_RSA3072_PSS_OID,    MLDSA65_RSA3072_PSS_SN,    MLDSA65_RSA3072_PSS_LN);
    REGISTER(MLDSA65_RSA3072_PKCS15_OID, MLDSA65_RSA3072_PKCS15_SN, MLDSA65_RSA3072_PKCS15_LN);
    REGISTER(MLDSA65_RSA4096_PSS_OID,    MLDSA65_RSA4096_PSS_SN,    MLDSA65_RSA4096_PSS_LN);
    REGISTER(MLDSA65_RSA4096_PKCS15_OID, MLDSA65_RSA4096_PKCS15_SN, MLDSA65_RSA4096_PKCS15_LN);
    REGISTER(MLDSA65_P256_OID,           MLDSA65_P256_SN,           MLDSA65_P256_LN);
    REGISTER(MLDSA65_P384_OID,           MLDSA65_P384_SN,           MLDSA65_P384_LN);
    REGISTER(MLDSA65_BRAINPOOLP256_OID,  MLDSA65_BRAINPOOLP256_SN,  MLDSA65_BRAINPOOLP256_LN);
    REGISTER(MLDSA65_ED25519_OID,        MLDSA65_ED25519_SN,        MLDSA65_ED25519_LN);

    /* ML-DSA-87 */
    REGISTER(MLDSA87_P384_OID,           MLDSA87_P384_SN,           MLDSA87_P384_LN);
    REGISTER(MLDSA87_BRAINPOOLP384_OID,  MLDSA87_BRAINPOOLP384_SN,  MLDSA87_BRAINPOOLP384_LN);
    REGISTER(MLDSA87_ED448_OID,          MLDSA87_ED448_SN,          MLDSA87_ED448_LN);
    REGISTER(MLDSA87_RSA3072_PSS_OID,    MLDSA87_RSA3072_PSS_SN,    MLDSA87_RSA3072_PSS_LN);
    REGISTER(MLDSA87_RSA4096_PSS_OID,    MLDSA87_RSA4096_PSS_SN,    MLDSA87_RSA4096_PSS_LN);
    REGISTER(MLDSA87_P521_OID,           MLDSA87_P521_SN,           MLDSA87_P521_LN);

#undef REGISTER
}

/* =========================================================================
 * Encoder context
 * ========================================================================= */

typedef struct {
    COMPOSITE_CTX *provctx;
} COMPOSITE_ENC_CTX;

static void *composite_enc_newctx(void *provctx)
{
    COMPOSITE_ENC_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = (COMPOSITE_CTX *)provctx;
    return ctx;
}

static void composite_enc_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

/* =========================================================================
 * Import / free object — cross-provider key passing not supported
 * ========================================================================= */

static void *composite_enc_import_object(void *vctx, int selection,
                                         const OSSL_PARAM params[])
{
    (void)vctx; (void)selection; (void)params;
    return NULL;
}

static void composite_enc_free_object(void *key)
{
    composite_signkey_free((COMPOSITE_KEY *)key);
}

/* =========================================================================
 * Shared helpers
 * ========================================================================= */

/*
 * Return a fresh (owned) copy of the ASN1_OBJECT for the algorithm OID.
 * The caller must free it with ASN1_OBJECT_free() if set0 fails, or
 * transfer ownership to the PKCS8/X509_PUBKEY structure on success.
 */
static ASN1_OBJECT *alg_obj_for_key(const COMPOSITE_KEY *key)
{
    int nid = OBJ_sn2nid(key->composite_name);

    if (nid == NID_undef) {
        ERR_raise(ERR_LIB_PROV, ERR_R_UNSUPPORTED);
        return NULL;
    }
    return OBJ_dup(OBJ_nid2obj(nid));
}

/* =========================================================================
 * PrivateKeyInfo / PEM encoder
 * ========================================================================= */

static int composite_pki_does_selection(void *vctx, int selection)
{
    (void)vctx;
    return (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;
}

/*
 * Encode the composite private key as an ASN.1 OCTET STRING containing
 * the raw concatenated private bytes.  Returns the DER length on success,
 * 0 on failure.  *pder is allocated with OPENSSL_malloc; PKCS8_pkey_set0
 * takes ownership on success.
 */
static int composite_privkey_to_der(const COMPOSITE_KEY *key,
                                    unsigned char **pder)
{
    unsigned char *raw = NULL;
    size_t raw_len = 0;

    if (!composite_sig_privkey_encode((COMPOSITE_KEY *)key, &raw, &raw_len))
        return 0;

    /* Pass raw bytes directly; PKCS8_pkey_set0 stores them as the content of
     * the privateKey OCTET STRING — no extra wrapping needed. */
    *pder = raw;
    return (int)raw_len;
}

static int composite_pki_pem_encode(void *vctx, OSSL_CORE_BIO *cout,
                                    const void *key_in,
                                    const OSSL_PARAM key_abstract[],
                                    int selection,
                                    OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_ENC_CTX      *ctx    = (COMPOSITE_ENC_CTX *)vctx;
    const COMPOSITE_KEY    *key    = (const COMPOSITE_KEY *)key_in;
    ASN1_OBJECT            *aobj   = NULL;
    unsigned char          *der    = NULL;
    int                     derlen = 0;
    PKCS8_PRIV_KEY_INFO    *p8info = NULL;
    BIO                    *out    = NULL;
    int                     ret    = 0;

    (void)cb; (void)cbarg;

    /* Only accept a directly-passed key object, not abstract params */
    if (key_abstract != NULL || key == NULL)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
        return 0;

    aobj = alg_obj_for_key(key);
    if (aobj == NULL)
        return 0;

    derlen = composite_privkey_to_der(key, &der);
    if (derlen <= 0) {
        ASN1_OBJECT_free(aobj);
        return 0;
    }

    /* Build PrivateKeyInfo; set0 takes ownership of aobj and der */
    p8info = PKCS8_PRIV_KEY_INFO_new();
    if (p8info == NULL ||
        !PKCS8_pkey_set0(p8info, aobj, 0, V_ASN1_UNDEF, NULL, der, derlen)) {
        PKCS8_PRIV_KEY_INFO_free(p8info);
        ASN1_OBJECT_free(aobj);
        OPENSSL_free(der);
        return 0;
    }
    /* aobj and der now owned by p8info */

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out != NULL) {
        ret = PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8info);
        BIO_free(out);
    }
    PKCS8_PRIV_KEY_INFO_free(p8info);
    return ret;
}

static const OSSL_DISPATCH composite_pki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void(*)(void))composite_enc_newctx         },
    { OSSL_FUNC_ENCODER_FREECTX,        (void(*)(void))composite_enc_freectx        },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))composite_pki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void(*)(void))composite_pki_pem_encode     },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (void(*)(void))composite_enc_import_object  },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (void(*)(void))composite_enc_free_object    },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * SubjectPublicKeyInfo / PEM encoder
 * ========================================================================= */

static int composite_spki_does_selection(void *vctx, int selection)
{
    (void)vctx;
    return (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0;
}

/*
 * Encode the composite public key as raw bytes (no extra wrapping).
 * X509_PUBKEY_set0_param stores them as the BIT STRING content in the SPKI.
 * Returns the byte count on success, 0 on failure.
 */
static int composite_pubkey_to_der(const COMPOSITE_KEY *key,
                                   unsigned char **pder)
{
    unsigned char *raw = NULL;
    size_t raw_len = 0;

    if (!composite_sig_pubkey_encode((COMPOSITE_KEY *)key, &raw, &raw_len))
        return 0;

    *pder = raw;
    return (int)raw_len;
}

static int composite_spki_pem_encode(void *vctx, OSSL_CORE_BIO *cout,
                                     const void *key_in,
                                     const OSSL_PARAM key_abstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_ENC_CTX   *ctx    = (COMPOSITE_ENC_CTX *)vctx;
    const COMPOSITE_KEY *key    = (const COMPOSITE_KEY *)key_in;
    ASN1_OBJECT         *aobj   = NULL;
    unsigned char       *der    = NULL;
    int                  derlen = 0;
    X509_PUBKEY         *xpk    = NULL;
    BIO                 *out    = NULL;
    int                  ret    = 0;

    (void)cb; (void)cbarg;

    if (key_abstract != NULL || key == NULL)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 0;

    aobj = alg_obj_for_key(key);
    if (aobj == NULL)
        return 0;

    derlen = composite_pubkey_to_der(key, &der);
    if (derlen <= 0) {
        ASN1_OBJECT_free(aobj);
        return 0;
    }

    /* Build SubjectPublicKeyInfo; set0_param takes ownership of aobj and der */
    xpk = X509_PUBKEY_new();
    if (xpk == NULL ||
        !X509_PUBKEY_set0_param(xpk, aobj, V_ASN1_UNDEF, NULL, der, derlen)) {
        X509_PUBKEY_free(xpk);
        ASN1_OBJECT_free(aobj);
        OPENSSL_free(der);
        return 0;
    }
    /* aobj and der now owned by xpk */

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out != NULL) {
        ret = PEM_write_bio_X509_PUBKEY(out, xpk);
        BIO_free(out);
    }
    X509_PUBKEY_free(xpk);
    return ret;
}

static const OSSL_DISPATCH composite_spki_pem_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void(*)(void))composite_enc_newctx          },
    { OSSL_FUNC_ENCODER_FREECTX,        (void(*)(void))composite_enc_freectx         },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))composite_spki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void(*)(void))composite_spki_pem_encode     },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (void(*)(void))composite_enc_import_object   },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (void(*)(void))composite_enc_free_object     },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * SubjectPublicKeyInfo / DER encoder
 * (required by X509_PUBKEY_set which requests output=der,structure=SubjectPublicKeyInfo)
 * ========================================================================= */

static int composite_spki_der_encode(void *vctx, OSSL_CORE_BIO *cout,
                                     const void *key_in,
                                     const OSSL_PARAM key_abstract[],
                                     int selection,
                                     OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    COMPOSITE_ENC_CTX   *ctx    = (COMPOSITE_ENC_CTX *)vctx;
    const COMPOSITE_KEY *key    = (const COMPOSITE_KEY *)key_in;
    ASN1_OBJECT         *aobj   = NULL;
    unsigned char       *pubder = NULL;
    int                  pubderlen = 0;
    X509_PUBKEY         *xpk    = NULL;
    unsigned char       *spkider = NULL;
    int                  spkilen = 0;
    BIO                 *out    = NULL;
    int                  ret    = 0;

    (void)cb; (void)cbarg;

    if (key_abstract != NULL || key == NULL)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY))
        return 0;

    aobj = alg_obj_for_key(key);
    if (aobj == NULL)
        return 0;

    pubderlen = composite_pubkey_to_der(key, &pubder);
    if (pubderlen <= 0) {
        ASN1_OBJECT_free(aobj);
        return 0;
    }

    /* Build SubjectPublicKeyInfo; set0_param takes ownership of aobj and pubder */
    xpk = X509_PUBKEY_new();
    if (xpk == NULL ||
        !X509_PUBKEY_set0_param(xpk, aobj, V_ASN1_UNDEF, NULL, pubder, pubderlen)) {
        X509_PUBKEY_free(xpk);
        ASN1_OBJECT_free(aobj);
        OPENSSL_free(pubder);
        return 0;
    }
    /* aobj and pubder now owned by xpk */

    /* Encode the SubjectPublicKeyInfo to DER */
    spkilen = i2d_X509_PUBKEY(xpk, &spkider);
    X509_PUBKEY_free(xpk);
    if (spkilen <= 0)
        return 0;

    out = BIO_new_from_core_bio(ctx->provctx->libctx, cout);
    if (out != NULL) {
        ret = (BIO_write(out, spkider, spkilen) == spkilen);
        BIO_free(out);
    }
    OPENSSL_free(spkider);
    return ret;
}

static const OSSL_DISPATCH composite_spki_der_encoder_functions[] = {
    { OSSL_FUNC_ENCODER_NEWCTX,         (void(*)(void))composite_enc_newctx          },
    { OSSL_FUNC_ENCODER_FREECTX,        (void(*)(void))composite_enc_freectx         },
    { OSSL_FUNC_ENCODER_DOES_SELECTION, (void(*)(void))composite_spki_does_selection },
    { OSSL_FUNC_ENCODER_ENCODE,         (void(*)(void))composite_spki_der_encode     },
    { OSSL_FUNC_ENCODER_IMPORT_OBJECT,  (void(*)(void))composite_enc_import_object   },
    { OSSL_FUNC_ENCODER_FREE_OBJECT,    (void(*)(void))composite_enc_free_object     },
    OSSL_DISPATCH_END
};

/* =========================================================================
 * OSSL_ALGORITHM table
 * ========================================================================= */

#define PKI_ENC(names) \
    { names, \
      "provider=composite,output=pem,structure=PrivateKeyInfo", \
      composite_pki_pem_encoder_functions, NULL }

#define SPKI_ENC(names) \
    { names, \
      "provider=composite,output=pem,structure=SubjectPublicKeyInfo", \
      composite_spki_pem_encoder_functions, NULL }

#define SPKI_DER_ENC(names) \
    { names, \
      "provider=composite,output=der,structure=SubjectPublicKeyInfo", \
      composite_spki_der_encoder_functions, NULL }

const OSSL_ALGORITHM *composite_encoders(void *provctx)
{
    (void)provctx;

    static const OSSL_ALGORITHM algorithms[] = {
        /* ML-DSA-44 */
        PKI_ENC(PROV_NAMES_MLDSA44_RSA2048_PSS),
        SPKI_ENC(PROV_NAMES_MLDSA44_RSA2048_PSS),
        SPKI_DER_ENC(PROV_NAMES_MLDSA44_RSA2048_PSS),
        PKI_ENC(PROV_NAMES_MLDSA44_RSA2048_PKCS15),
        SPKI_ENC(PROV_NAMES_MLDSA44_RSA2048_PKCS15),
        SPKI_DER_ENC(PROV_NAMES_MLDSA44_RSA2048_PKCS15),
        PKI_ENC(PROV_NAMES_MLDSA44_ED25519),
        SPKI_ENC(PROV_NAMES_MLDSA44_ED25519),
        SPKI_DER_ENC(PROV_NAMES_MLDSA44_ED25519),
        PKI_ENC(PROV_NAMES_MLDSA44_P256),
        SPKI_ENC(PROV_NAMES_MLDSA44_P256),
        SPKI_DER_ENC(PROV_NAMES_MLDSA44_P256),

        /* ML-DSA-65 */
        PKI_ENC(PROV_NAMES_MLDSA65_RSA3072_PSS),
        SPKI_ENC(PROV_NAMES_MLDSA65_RSA3072_PSS),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_RSA3072_PSS),
        PKI_ENC(PROV_NAMES_MLDSA65_RSA3072_PKCS15),
        SPKI_ENC(PROV_NAMES_MLDSA65_RSA3072_PKCS15),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_RSA3072_PKCS15),
        PKI_ENC(PROV_NAMES_MLDSA65_RSA4096_PSS),
        SPKI_ENC(PROV_NAMES_MLDSA65_RSA4096_PSS),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_RSA4096_PSS),
        PKI_ENC(PROV_NAMES_MLDSA65_RSA4096_PKCS15),
        SPKI_ENC(PROV_NAMES_MLDSA65_RSA4096_PKCS15),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_RSA4096_PKCS15),
        PKI_ENC(PROV_NAMES_MLDSA65_P256),
        SPKI_ENC(PROV_NAMES_MLDSA65_P256),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_P256),
        PKI_ENC(PROV_NAMES_MLDSA65_P384),
        SPKI_ENC(PROV_NAMES_MLDSA65_P384),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_P384),
        PKI_ENC(PROV_NAMES_MLDSA65_BRAINPOOLP256),
        SPKI_ENC(PROV_NAMES_MLDSA65_BRAINPOOLP256),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_BRAINPOOLP256),
        PKI_ENC(PROV_NAMES_MLDSA65_ED25519),
        SPKI_ENC(PROV_NAMES_MLDSA65_ED25519),
        SPKI_DER_ENC(PROV_NAMES_MLDSA65_ED25519),

        /* ML-DSA-87 */
        PKI_ENC(PROV_NAMES_MLDSA87_P384),
        SPKI_ENC(PROV_NAMES_MLDSA87_P384),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_P384),
        PKI_ENC(PROV_NAMES_MLDSA87_BRAINPOOLP384),
        SPKI_ENC(PROV_NAMES_MLDSA87_BRAINPOOLP384),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_BRAINPOOLP384),
        PKI_ENC(PROV_NAMES_MLDSA87_ED448),
        SPKI_ENC(PROV_NAMES_MLDSA87_ED448),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_ED448),
        PKI_ENC(PROV_NAMES_MLDSA87_RSA3072_PSS),
        SPKI_ENC(PROV_NAMES_MLDSA87_RSA3072_PSS),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_RSA3072_PSS),
        PKI_ENC(PROV_NAMES_MLDSA87_RSA4096_PSS),
        SPKI_ENC(PROV_NAMES_MLDSA87_RSA4096_PSS),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_RSA4096_PSS),
        PKI_ENC(PROV_NAMES_MLDSA87_P521),
        SPKI_ENC(PROV_NAMES_MLDSA87_P521),
        SPKI_DER_ENC(PROV_NAMES_MLDSA87_P521),

        { NULL, NULL, NULL, NULL }
    };

    return algorithms;
}
