/* composite_sig.c — composite signature operations */

#include "composite_sig.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include <string.h>

/* =========================================================================
 * Context lifecycle
 * ======================================================================= */

void *composite_sig_newctx_base(void *provctx, const char *alg_sn)
{
    COMPOSITE_SIG_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->provctx        = (COMPOSITE_CTX *)provctx;
    ctx->algorithm_name = alg_sn;
    return ctx;
}

void composite_sig_freectx(void *vctx)
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    if (!ctx) return;
    if (ctx->evp_ctx) EVP_MD_CTX_free(ctx->evp_ctx);
    if (ctx->msg_bio) BIO_free(ctx->msg_bio);
    OPENSSL_free(ctx);
}

/* =========================================================================
 * Sign / Verify init
 * ======================================================================= */

int composite_sig_sign_init(void *vctx, void *vkey,
                             const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    COMPOSITE_KEY     *key = (COMPOSITE_KEY *)vkey;
    const char        *alg;

    (void)params;
    if (!ctx || !key) return 0;

    ctx->key = key;
    alg = ctx->algorithm_name ? ctx->algorithm_name : key->composite_name;
    if (!alg) return 0;
    ctx->alg_info = composite_alg_info_find(alg);
    if (ctx->alg_info == NULL) return 0;

    /* Cache DER-encoded composite OID for get_ctx_params */
    {
        int nid = OBJ_sn2nid(alg);
        if (nid != NID_undef) {
            unsigned char *p = ctx->alg_oid_der;
            int oidlen = i2d_ASN1_OBJECT(OBJ_nid2obj(nid), &p);
            ctx->alg_oid_der_len = (oidlen > 0 && oidlen <= 10)
                                   ? (size_t)oidlen : 0;
        }
    }
    return 1;
}

int composite_sig_verify_init(void *vctx, void *vkey,
                               const OSSL_PARAM params[])
{
    return composite_sig_sign_init(vctx, vkey, params);
}

/* =========================================================================
 * Helpers
 * ======================================================================= */

/* Compute M' = Hash(msg) using prehash_alg from alg_info */
static int composite_prehash(OSSL_LIB_CTX *libctx,
                              const char   *hash_alg,
                              const unsigned char *msg, size_t msg_len,
                              unsigned char *out, size_t *out_len)
{
    EVP_MD     *md  = EVP_MD_fetch(libctx, hash_alg, NULL);
    EVP_MD_CTX *mctx;
    int         ret = 0;

    if (!md) return 0;
    mctx = EVP_MD_CTX_new();
    if (!mctx) { EVP_MD_free(md); return 0; }

    if (EVP_DigestInit_ex2(mctx, md, NULL) &&
        EVP_DigestUpdate(mctx, msg, msg_len)) {
        if (strcmp(hash_alg, "SHAKE-256") == 0) {
            *out_len = 64;
            ret = EVP_DigestFinalXOF(mctx, out, 64);
        } else {
            unsigned int len = 0;
            ret = EVP_DigestFinal_ex(mctx, out, &len);
            if (ret) *out_len = len;
        }
    }
    EVP_MD_CTX_free(mctx);
    EVP_MD_free(md);
    return ret;
}

/* 32-byte domain separation prefix (draft section 2.1) */
static const unsigned char composite_msg_prefix[32] = "CompositeAlgorithmSignatures2025";

/*
 * Build M' = Prefix || Label || len(ctx) || ctx || PH(M)
 * Label is the per-algorithm ASCII string from the draft §6 table.
 * ctx / ctx_len are the application context (may be zero-length).
 * Caller must OPENSSL_free the returned buffer.
 */
static unsigned char *composite_build_M_prime(const COMPOSITE_ALG_INFO *alg,
                                               const unsigned char *prehash,
                                               size_t prehash_len,
                                               const unsigned char *ctx,
                                               size_t ctx_len,
                                               size_t *mprime_len)
{
    size_t label_len = strlen(alg->label);
    size_t total = sizeof(composite_msg_prefix) + label_len + 1 + ctx_len + prehash_len;
    unsigned char *mprime = OPENSSL_malloc(total);
    size_t off = 0;

    if (!mprime) return NULL;
    memcpy(mprime + off, composite_msg_prefix, sizeof(composite_msg_prefix));
    off += sizeof(composite_msg_prefix);
    memcpy(mprime + off, alg->label, label_len);
    off += label_len;
    mprime[off++] = (unsigned char)ctx_len;
    if (ctx_len > 0) {
        memcpy(mprime + off, ctx, ctx_len);
        off += ctx_len;
    }
    memcpy(mprime + off, prehash, prehash_len);
    *mprime_len = total;
    return mprime;
}

/* Sign with classic algorithm. Receives M' and signs it using EVP_DigestSign,
 * letting the algorithm apply its own hash to M' internally. */
static int composite_classic_sign(OSSL_LIB_CTX        *libctx,
                                   const COMPOSITE_ALG_INFO *alg,
                                   EVP_PKEY            *pkey,
                                   const unsigned char *mprime, size_t mprime_len,
                                   unsigned char       *sig, size_t *sig_len)
{
    EVP_MD_CTX   *dctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    /* Ed25519/Ed448 hash M' internally; RSA/ECDSA use trad_hash_alg */
    const char   *mdname = (alg->classic_type == COMP_CLASSIC_ED25519 ||
                            alg->classic_type == COMP_CLASSIC_ED448)
                           ? NULL : alg->trad_hash_alg;
    int ret = 0;

    if (!dctx) return 0;
    if (EVP_DigestSignInit_ex(dctx, &pctx, mdname, libctx, NULL, pkey, NULL) <= 0)
        goto done;
    if (alg->classic_type == COMP_CLASSIC_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            goto done;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
            goto done;
    }
    ret = EVP_DigestSign(dctx, sig, sig_len, mprime, mprime_len) > 0;
done:
    EVP_MD_CTX_free(dctx);
    return ret;
}

/* Verify with classic algorithm. Receives M' and verifies using EVP_DigestVerify. */
static int composite_classic_verify(OSSL_LIB_CTX        *libctx,
                                     const COMPOSITE_ALG_INFO *alg,
                                     EVP_PKEY            *pkey,
                                     const unsigned char *mprime, size_t mprime_len,
                                     const unsigned char *sig, size_t sig_len)
{
    EVP_MD_CTX   *dctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    const char   *mdname = (alg->classic_type == COMP_CLASSIC_ED25519 ||
                            alg->classic_type == COMP_CLASSIC_ED448)
                           ? NULL : alg->trad_hash_alg;
    int ret = 0;

    if (!dctx) return 0;
    if (EVP_DigestVerifyInit_ex(dctx, &pctx, mdname, libctx, NULL, pkey, NULL) <= 0)
        goto done;
    if (alg->classic_type == COMP_CLASSIC_RSA_PSS) {
        if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0)
            goto done;
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, RSA_PSS_SALTLEN_DIGEST) <= 0)
            goto done;
    }
    ret = EVP_DigestVerify(dctx, sig, sig_len, mprime, mprime_len) > 0;
done:
    EVP_MD_CTX_free(dctx);
    return ret;
}

/* Sign with ML-DSA. Both signers receive M'. ML-DSA additionally receives the
 * per-algorithm label as its context string (FIPS 204 §5.2). */
static int composite_mldsa_sign(OSSL_LIB_CTX             *libctx,
                                 const COMPOSITE_ALG_INFO *alg,
                                 EVP_PKEY                 *mldsa_pkey,
                                 const unsigned char      *mprime, size_t mprime_len,
                                 unsigned char            *out_sig, size_t *out_sig_len)
{
    EVP_MD_CTX   *dctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM    params[2];
    int ret = 0;

    if (!dctx) return 0;
    if (EVP_DigestSignInit_ex(dctx, &pctx, NULL, libctx, NULL, mldsa_pkey, NULL) <= 0)
        goto done;
    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                    (void *)alg->label, strlen(alg->label));
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0)
        goto done;
    ret = EVP_DigestSign(dctx, out_sig, out_sig_len, mprime, mprime_len) > 0;
done:
    EVP_MD_CTX_free(dctx);
    return ret;
}

/* Verify with ML-DSA. Both signers verify over M'. Label is the context string. */
static int composite_mldsa_verify(OSSL_LIB_CTX             *libctx,
                                   const COMPOSITE_ALG_INFO *alg,
                                   EVP_PKEY                 *mldsa_pkey,
                                   const unsigned char      *mprime, size_t mprime_len,
                                   const unsigned char      *mldsa_sig, size_t mldsa_sig_len)
{
    EVP_MD_CTX   *dctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM    params[2];
    int ret = 0;

    if (!dctx) return 0;
    if (EVP_DigestVerifyInit_ex(dctx, &pctx, NULL, libctx, NULL, mldsa_pkey, NULL) <= 0)
        goto done;
    params[0] = OSSL_PARAM_construct_octet_string(
                    OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                    (void *)alg->label, strlen(alg->label));
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_CTX_set_params(pctx, params) <= 0)
        goto done;
    ret = EVP_DigestVerify(dctx, mldsa_sig, mldsa_sig_len, mprime, mprime_len) > 0;
done:
    EVP_MD_CTX_free(dctx);
    return ret;
}

/* =========================================================================
 * Sign
 *  sig format: mldsa_sig || trad_sig
 * ======================================================================= */

int composite_sig_sign(void *vctx, unsigned char *sig, size_t *siglen,
                        size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    COMPOSITE_SIG_CTX        *ctx = (COMPOSITE_SIG_CTX *)vctx;
    const COMPOSITE_ALG_INFO *alg;
    OSSL_LIB_CTX             *libctx;
    EVP_PKEY *mldsa_pkey, *trad_pkey;
    unsigned char  prehash[EVP_MAX_MD_SIZE + 64]; /* +64 for SHAKE-256 output */
    size_t         prehash_len = 0;
    unsigned char *mprime = NULL;
    size_t         mprime_len = 0;
    unsigned char  trad_sig_buf[8192];
    size_t         trad_sig_len = sizeof(trad_sig_buf);
    unsigned char  mldsa_sig_buf[ML_DSA_87_SIG_SZ];
    size_t         mldsa_sig_len;
    size_t         total;
    int            ret = 0;

    if (!ctx || !ctx->key || !ctx->alg_info)
        return 0;

    alg    = ctx->alg_info;
    libctx = ctx->provctx->libctx;

    mldsa_pkey = ctx->key->mldsa_privkey
               ? (EVP_PKEY *)ctx->key->mldsa_privkey
               : (EVP_PKEY *)ctx->key->mldsa_pubkey;
    trad_pkey  = ctx->key->classic_privkey
               ? (EVP_PKEY *)ctx->key->classic_privkey
               : (EVP_PKEY *)ctx->key->classic_pubkey;

    if (!mldsa_pkey || !trad_pkey) return 0;

    /* Size query */
    if (sig == NULL) {
        *siglen = alg->mldsa_sig_len + 8192;
        return 1;
    }

    /* Step 1: PH(M) = Hash(M) */
    if (!composite_prehash(libctx, alg->prehash_alg, tbs, tbslen,
                            prehash, &prehash_len))
        return 0;

    /* Step 2: M' = Prefix || Label || len(ctx) || ctx || PH(M) */
    mprime = composite_build_M_prime(alg, prehash, prehash_len,
                                     ctx->context_string, ctx->context_string_len,
                                     &mprime_len);
    if (!mprime) return 0;

    /* Step 3: trad_sig = ClassicSign(sk_trad, M') */
    if (!composite_classic_sign(libctx, alg, trad_pkey,
                                 mprime, mprime_len,
                                 trad_sig_buf, &trad_sig_len))
        goto done;

    /* Step 4: mldsa_sig = MLDSASign(sk_mldsa, M', ctx=label) */
    mldsa_sig_len = alg->mldsa_sig_len;
    if (!composite_mldsa_sign(libctx, alg, mldsa_pkey,
                               mprime, mprime_len,
                               mldsa_sig_buf, &mldsa_sig_len))
        goto done;

    /* Step 5: output = mldsa_sig || trad_sig */
    total = mldsa_sig_len + trad_sig_len;
    if (sigsize < total) goto done;

    memcpy(sig,                 mldsa_sig_buf, mldsa_sig_len);
    memcpy(sig + mldsa_sig_len, trad_sig_buf,  trad_sig_len);
    *siglen = total;
    ret = 1;
done:
    OPENSSL_free(mprime);
    return ret;
}

/* =========================================================================
 * Verify
 * ======================================================================= */

int composite_sig_verify(void *vctx, const unsigned char *sig, size_t siglen,
                          const unsigned char *tbs, size_t tbslen)
{
    COMPOSITE_SIG_CTX        *ctx = (COMPOSITE_SIG_CTX *)vctx;
    const COMPOSITE_ALG_INFO *alg;
    OSSL_LIB_CTX             *libctx;
    EVP_PKEY *mldsa_pkey, *trad_pkey;

    if (!ctx || !ctx->key || !ctx->alg_info || !sig)
        return 0;

    alg    = ctx->alg_info;
    libctx = ctx->provctx->libctx;

    mldsa_pkey = (EVP_PKEY *)ctx->key->mldsa_pubkey;
    trad_pkey  = (EVP_PKEY *)ctx->key->classic_pubkey;
    if (!mldsa_pkey || !trad_pkey) return 0;

    if (siglen < alg->mldsa_sig_len) return 0;

    {
        const unsigned char *mldsa_sig = sig;
        size_t               mldsa_len = alg->mldsa_sig_len;
        const unsigned char *trad_sig  = sig + alg->mldsa_sig_len;
        size_t               trad_len  = siglen - alg->mldsa_sig_len;
        unsigned char  prehash[EVP_MAX_MD_SIZE + 64];
        size_t         prehash_len = 0;
        unsigned char *mprime = NULL;
        size_t         mprime_len = 0;
        int            ret = 0;

        /* Step 1: PH(M) = Hash(M) */
        if (!composite_prehash(libctx, alg->prehash_alg, tbs, tbslen,
                                prehash, &prehash_len))
            return 0;

        /* Step 2: M' = Prefix || Label || len(ctx) || ctx || PH(M) */
        mprime = composite_build_M_prime(alg, prehash, prehash_len,
                                         ctx->context_string, ctx->context_string_len,
                                         &mprime_len);
        if (!mprime) return 0;

        /* Step 3: verify classic signature */
        if (!composite_classic_verify(libctx, alg, trad_pkey,
                                       mprime, mprime_len,
                                       trad_sig, trad_len))
            goto verify_done;

        /* Step 4: verify ML-DSA signature (M' + label as context) */
        ret = composite_mldsa_verify(libctx, alg, mldsa_pkey,
                                      mprime, mprime_len,
                                      mldsa_sig, mldsa_len);
verify_done:
        OPENSSL_free(mprime);
        return ret;
    }
}

/* =========================================================================
 * Streaming (digest_sign / digest_verify) — accumulate message in a BIO,
 * then delegate to the one-shot sign/verify at _final time.
 * The mdname argument is intentionally ignored: each composite algorithm
 * defines its own pre-hash internally.
 * ======================================================================= */

int composite_sig_digest_sign_init(void *vctx, const char *mdname,
                                    void *vkey, const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    (void)mdname;
    if (!composite_sig_sign_init(vctx, vkey, params))
        return 0;
    BIO_free(ctx->msg_bio);
    ctx->msg_bio = BIO_new(BIO_s_mem());
    return ctx->msg_bio != NULL ? 1 : 0;
}

int composite_sig_digest_sign_update(void *vctx,
                                      const unsigned char *data, size_t datalen)
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    if (!ctx || !ctx->msg_bio) return 0;
    return BIO_write(ctx->msg_bio, data, (int)datalen) == (int)datalen ? 1 : 0;
}

int composite_sig_digest_sign_final(void *vctx,
                                     unsigned char *sig, size_t *siglen,
                                     size_t sigsize)
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    const unsigned char *msg;
    long msg_len;

    if (!ctx || !ctx->msg_bio) return 0;
    msg_len = BIO_get_mem_data(ctx->msg_bio, (char **)&msg);
    if (msg_len < 0) return 0;
    return composite_sig_sign(vctx, sig, siglen, sigsize,
                               msg, (size_t)msg_len);
}

int composite_sig_digest_verify_init(void *vctx, const char *mdname,
                                      void *vkey, const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    (void)mdname;
    if (!composite_sig_verify_init(vctx, vkey, params))
        return 0;
    BIO_free(ctx->msg_bio);
    ctx->msg_bio = BIO_new(BIO_s_mem());
    return ctx->msg_bio != NULL ? 1 : 0;
}

int composite_sig_digest_verify_update(void *vctx,
                                        const unsigned char *data, size_t datalen)
{
    return composite_sig_digest_sign_update(vctx, data, datalen);
}

int composite_sig_digest_verify_final(void *vctx,
                                       const unsigned char *sig, size_t siglen)
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    const unsigned char *msg;
    long msg_len;

    if (!ctx || !ctx->msg_bio) return 0;
    msg_len = BIO_get_mem_data(ctx->msg_bio, (char **)&msg);
    if (msg_len < 0) return 0;
    return composite_sig_verify(vctx, sig, siglen,
                                 msg, (size_t)msg_len);
}

/* =========================================================================
 * Context parameters
 * ======================================================================= */

int composite_sig_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL) {
        unsigned char aid[12]; /* SEQUENCE(2) + OID(<=10) */
        size_t aid_len;

        if (!ctx || ctx->alg_oid_der_len == 0 ||
            ctx->alg_oid_der_len > sizeof(aid) - 2)
            return 0;

        aid[0] = 0x30; /* SEQUENCE tag */
        aid[1] = (unsigned char)ctx->alg_oid_der_len;
        memcpy(aid + 2, ctx->alg_oid_der, ctx->alg_oid_der_len);
        aid_len = 2 + ctx->alg_oid_der_len;

        return OSSL_PARAM_set_octet_string(p, aid, aid_len);
    }
    return 1;
}

static const OSSL_PARAM composite_get_ctx_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *composite_sig_gettable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx; (void)provctx;
    return composite_get_ctx_params_list;
}

int composite_sig_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    COMPOSITE_SIG_CTX *ctx = (COMPOSITE_SIG_CTX *)vctx;
    const OSSL_PARAM  *p;

    if (ctx == NULL || params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_CONTEXT_STRING);
    if (p != NULL) {
        void *vp = ctx->context_string;
        if (!OSSL_PARAM_get_octet_string(p, &vp, sizeof(ctx->context_string),
                                         &ctx->context_string_len)) {
            ctx->context_string_len = 0;
            return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM composite_set_ctx_params_list[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, NULL, 0),
    OSSL_PARAM_END
};

const OSSL_PARAM *composite_sig_settable_ctx_params(void *vctx, void *provctx)
{
    (void)vctx; (void)provctx;
    return composite_set_ctx_params_list;
}

