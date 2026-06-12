/* composite_keys.c — keymgmt helper functions for composite provider */

#include "composite_sig_key.h"
#include "composite_sig_encoding.h"
#include "provider.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

/* =========================================================================
 * Generation context
 * ======================================================================= */

typedef struct {
    COMPOSITE_CTX *provctx;
    int selection;
} COMPOSITE_GEN_CTX;

/* =========================================================================
 * Key lifecycle
 * ======================================================================= */

COMPOSITE_KEY *composite_key_new(COMPOSITE_CTX *provctx,
                                 const char    *composite_name)
{
    COMPOSITE_KEY *key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    key->provctx        = provctx;
    key->composite_name = composite_name; /* static string, no copy */
    key->has_private    = 0;
    return key;
}

void composite_free_key(void *keydata)
{
    composite_signkey_free((COMPOSITE_KEY *)keydata);
}

/* =========================================================================
 * Generation
 * ======================================================================= */

static void *composite_gen_init(void *provctx, int selection,
                                const OSSL_PARAM params[])
{
    COMPOSITE_GEN_CTX *gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;
    gctx->provctx   = (COMPOSITE_CTX *)provctx;
    gctx->selection = selection;
    (void)params;
    return gctx;
}

static void composite_gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static int composite_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    (void)genctx; (void)params;
    return 1;
}

static const OSSL_PARAM *composite_gen_settable_params(
        ossl_unused void *genctx, ossl_unused void *provctx)
{
    static const OSSL_PARAM settable[] = { OSSL_PARAM_END };
    return settable;
}

/*
 * Core generation helper — generate a keypair for the named composite
 * algorithm and return a filled-in COMPOSITE_KEY.
 */
void *composite_gen_with_alg(void *genctx, const char *composite_sn)
{
    COMPOSITE_GEN_CTX *gctx = (COMPOSITE_GEN_CTX *)genctx;
    COMPOSITE_KEY     *key;

    if (gctx == NULL || composite_sn == NULL)
        return NULL;

    key = composite_key_new(gctx->provctx, composite_sn);
    if (key == NULL)
        return NULL;

    if (!composite_signkey_generate(gctx->provctx, key, composite_sn)) {
        composite_signkey_free(key);
        return NULL;
    }

    key->composite_name = composite_sn;
    key->has_private    = 1;
    return key;
}

/* =========================================================================
 * Key introspection
 * ======================================================================= */

static int composite_has(const void *keydata, int selection)
{
    const COMPOSITE_KEY *key = (const COMPOSITE_KEY *)keydata;
    if (key == NULL)
        return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        if (key->mldsa_pubkey == NULL || key->classic_pubkey == NULL)
            return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        if (!key->has_private)
            return 0;
    return 1;
}

static int composite_match(const void *keydata1, const void *keydata2,
                           int selection)
{
    const COMPOSITE_KEY *k1 = (const COMPOSITE_KEY *)keydata1;
    const COMPOSITE_KEY *k2 = (const COMPOSITE_KEY *)keydata2;

    if (k1 == NULL || k2 == NULL)
        return 0;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (k1->mldsa_pubkey == NULL || k2->mldsa_pubkey == NULL ||
            k1->classic_pubkey == NULL || k2->classic_pubkey == NULL)
            return 0;
        if (!EVP_PKEY_eq((EVP_PKEY *)k1->mldsa_pubkey,
                         (EVP_PKEY *)k2->mldsa_pubkey))
            return 0;
        if (!EVP_PKEY_eq((EVP_PKEY *)k1->classic_pubkey,
                         (EVP_PKEY *)k2->classic_pubkey))
            return 0;
    }
    return 1;
}

static int composite_validate(const void *keydata, int selection, int checktype)
{
    const COMPOSITE_KEY *key = (const COMPOSITE_KEY *)keydata;
    (void)checktype;
    if (key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) &&
        (key->mldsa_pubkey == NULL || key->classic_pubkey == NULL))
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_private)
        return 0;
    return 1;
}



static const OSSL_PARAM composite_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *composite_imexport_types(int selection)
{
    (void)selection;
    return composite_key_types;
}

/* =========================================================================
 * Key parameters
 * ======================================================================= */

static const OSSL_PARAM composite_gettable_param_list[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS,          NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE,       NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *composite_gettable_params(void *provctx)
{
    (void)provctx;
    return composite_gettable_param_list;
}

static int composite_get_params(void *keydata, OSSL_PARAM params[])
{
    COMPOSITE_KEY            *key = (COMPOSITE_KEY *)keydata;
    const COMPOSITE_ALG_INFO *alg;
    OSSL_PARAM               *p;
    int bits, sec_bits, max_size;

    if (key == NULL) return 0;
    alg = key->composite_name
        ? composite_alg_info_find(key->composite_name) : NULL;

    if (alg == NULL || alg->mldsa_id == ML_DSA_44) {
        bits = 2048; sec_bits = 128;
        max_size = (int)(ML_DSA_44_SIG_SZ + 512);
    } else if (alg->mldsa_id == ML_DSA_65) {
        bits = 3072; sec_bits = 192;
        max_size = (int)(ML_DSA_65_SIG_SZ + 1024);
    } else {
        bits = 4096; sec_bits = 256;
        max_size = (int)(ML_DSA_87_SIG_SZ + 1024);
    }

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL)
        if (!OSSL_PARAM_set_int(p, bits)) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL)
        if (!OSSL_PARAM_set_int(p, sec_bits)) return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL)
        if (!OSSL_PARAM_set_int(p, max_size)) return 0;
    return 1;
}

static int composite_set_params(void *keydata, const OSSL_PARAM params[])
{
    (void)keydata; (void)params;
    return 1;
}

static const OSSL_PARAM *composite_settable_params(void *provctx)
{
    static const OSSL_PARAM settable[] = { OSSL_PARAM_END };
    (void)provctx;
    return settable;
}

/* =========================================================================
 * Key duplication and loading
 * ======================================================================= */

static void *composite_dup_key(const void *keydata, int selection)
{
    const COMPOSITE_KEY *src = (const COMPOSITE_KEY *)keydata;
    COMPOSITE_KEY       *dst;

    if (!src) return NULL;
    dst = composite_key_new(src->provctx, src->composite_name);
    if (!dst) return NULL;
    dst->has_private = src->has_private;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        if (src->mldsa_pubkey) {
            dst->mldsa_pubkey = EVP_PKEY_dup((EVP_PKEY *)src->mldsa_pubkey);
            if (!dst->mldsa_pubkey) goto err;
        }
        if (src->classic_pubkey) {
            dst->classic_pubkey =
                EVP_PKEY_dup((EVP_PKEY *)src->classic_pubkey);
            if (!dst->classic_pubkey) goto err;
        }
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && src->has_private) {
        if (src->mldsa_privkey) {
            dst->mldsa_privkey =
                EVP_PKEY_dup((EVP_PKEY *)src->mldsa_privkey);
            if (!dst->mldsa_privkey) goto err;
        }
        if (src->classic_privkey) {
            dst->classic_privkey =
                EVP_PKEY_dup((EVP_PKEY *)src->classic_privkey);
            if (!dst->classic_privkey) goto err;
        }
    }
    return dst;
err:
    composite_signkey_free(dst);
    return NULL;
}

static void *composite_load(const void *reference, size_t reference_sz)
{
    if (reference == NULL || reference_sz != sizeof(COMPOSITE_KEY *))
        return NULL;
    return *(COMPOSITE_KEY * const *)reference;
}

/* =========================================================================
 * Expose shared functions used by per-algorithm dispatch tables in
 * composite_keymgmt.c (declared in composite_keymgmt.h).
 * ======================================================================= */

void *composite_gen_init_fn(void *provctx, int selection,
                            const OSSL_PARAM params[])
{ return composite_gen_init(provctx, selection, params); }

void composite_gen_cleanup_fn(void *genctx)
{ composite_gen_cleanup(genctx); }

int composite_gen_set_params_fn(void *gc, const OSSL_PARAM p[])
{ return composite_gen_set_params(gc, p); }

const OSSL_PARAM *composite_gen_settable_params_fn(void *gc, void *pc)
{ return composite_gen_settable_params(gc, pc); }

int composite_has_fn(const void *kd, int sel)
{ return composite_has(kd, sel); }

int composite_match_fn(const void *k1, const void *k2, int sel)
{ return composite_match(k1, k2, sel); }

int composite_validate_fn(const void *kd, int sel, int ct)
{ return composite_validate(kd, sel, ct); }

int composite_import_fn(void *kd, int sel, const OSSL_PARAM p[])
{ return composite_key_import(kd, sel, p); }

int composite_export_fn(void *kd, int sel, OSSL_CALLBACK *cb, void *cbarg)
{ return composite_key_export(kd, sel, cb, cbarg); }

const OSSL_PARAM *composite_imexport_types_fn(int sel)
{ return composite_imexport_types(sel); }

int composite_get_params_fn(void *kd, OSSL_PARAM p[])
{ return composite_get_params(kd, p); }

const OSSL_PARAM *composite_gettable_params_fn(void *pc)
{ return composite_gettable_params(pc); }

int composite_set_params_fn(void *kd, const OSSL_PARAM p[])
{ return composite_set_params(kd, p); }

const OSSL_PARAM *composite_settable_params_fn(void *pc)
{ return composite_settable_params(pc); }

void *composite_dup_key_fn(const void *kd, int sel)
{ return composite_dup_key(kd, sel); }

void *composite_load_fn(const void *ref, size_t ref_sz)
{ return composite_load(ref, ref_sz); }

