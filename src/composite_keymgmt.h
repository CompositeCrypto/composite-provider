#ifndef _COMPOSITE_KEYMGMT_H
#define _COMPOSITE_KEYMGMT_H

#include "compat.h"
#include "composite_provider.h"
#include "composite_sig_key.h"

BEGIN_C_DECLS

/* -----------------------------------------------------------------------
 * Shared keymgmt functions declared in composite_keys.c
 * --------------------------------------------------------------------- */

COMPOSITE_KEY *composite_key_new(COMPOSITE_CTX *provctx,
                                 const char    *composite_name);
void           composite_free_key(void *keydata);
void          *composite_gen_with_alg(void *genctx, const char *composite_sn);

/* Shared wrapper functions exposed from composite_keys.c */
void          *composite_gen_init_fn(void *, int, const OSSL_PARAM []);
void           composite_gen_cleanup_fn(void *);
int            composite_gen_set_params_fn(void *, const OSSL_PARAM []);
const OSSL_PARAM *composite_gen_settable_params_fn(void *, void *);
int            composite_has_fn(const void *, int);
int            composite_match_fn(const void *, const void *, int);
int            composite_validate_fn(const void *, int, int);
int            composite_import_fn(void *, int, const OSSL_PARAM []);
int            composite_export_fn(void *, int, OSSL_CALLBACK *, void *);
const OSSL_PARAM *composite_imexport_types_fn(int);
int            composite_get_params_fn(void *, OSSL_PARAM []);
const OSSL_PARAM *composite_gettable_params_fn(void *);
int            composite_set_params_fn(void *, const OSSL_PARAM []);
const OSSL_PARAM *composite_settable_params_fn(void *);
void          *composite_dup_key_fn(const void *, int);
void          *composite_load_fn(const void *, size_t);

/* -----------------------------------------------------------------------
 * Per-algorithm dispatch table macro.
 * full_name  — lowercase identifier, e.g. mldsa44_rsa2048_pss
 * sn_macro   — string constant SN, e.g. MLDSA44_RSA2048_PSS_SN
 * --------------------------------------------------------------------- */

#define KEYMGMT_DISPATCH_TABLE(full_name, sn_macro)                            \
    static void *composite_##full_name##_new_key(void *provctx) {              \
        return composite_key_new((COMPOSITE_CTX *)provctx, sn_macro);          \
    }                                                                          \
    static void *composite_##full_name##_gen(void *genctx,                     \
                                             OSSL_CALLBACK *cb,                \
                                             void *cbarg) {                    \
        (void)cb; (void)cbarg;                                                 \
        return composite_gen_with_alg(genctx, sn_macro);                       \
    }                                                                          \
    const OSSL_DISPATCH ossl_composite_##full_name##_keymgmt_functions[] = {   \
        { OSSL_FUNC_KEYMGMT_NEW,                                               \
          (void(*)(void))composite_##full_name##_new_key },                    \
        { OSSL_FUNC_KEYMGMT_FREE,                                              \
          (void(*)(void))composite_free_key },                                 \
        { OSSL_FUNC_KEYMGMT_HAS,                                               \
          (void(*)(void))composite_has_fn },                                   \
        { OSSL_FUNC_KEYMGMT_MATCH,                                             \
          (void(*)(void))composite_match_fn },                                 \
        { OSSL_FUNC_KEYMGMT_VALIDATE,                                          \
          (void(*)(void))composite_validate_fn },                              \
        { OSSL_FUNC_KEYMGMT_IMPORT,                                            \
          (void(*)(void))composite_import_fn },                                \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,                                      \
          (void(*)(void))composite_imexport_types_fn },                        \
        { OSSL_FUNC_KEYMGMT_EXPORT,                                            \
          (void(*)(void))composite_export_fn },                                \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,                                      \
          (void(*)(void))composite_imexport_types_fn },                        \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS,                                        \
          (void(*)(void))composite_get_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,                                   \
          (void(*)(void))composite_gettable_params_fn },                       \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS,                                        \
          (void(*)(void))composite_set_params_fn },                            \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,                                   \
          (void(*)(void))composite_settable_params_fn },                       \
        { OSSL_FUNC_KEYMGMT_DUP,                                               \
          (void(*)(void))composite_dup_key_fn },                               \
        { OSSL_FUNC_KEYMGMT_LOAD,                                              \
          (void(*)(void))composite_load_fn },                                  \
        { OSSL_FUNC_KEYMGMT_GEN_INIT,                                          \
          (void(*)(void))composite_gen_init_fn },                              \
        { OSSL_FUNC_KEYMGMT_GEN,                                               \
          (void(*)(void))composite_##full_name##_gen },                        \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,                                       \
          (void(*)(void))composite_gen_cleanup_fn },                           \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                    \
          (void(*)(void))composite_gen_set_params_fn },                        \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                               \
          (void(*)(void))composite_gen_settable_params_fn },                   \
        OSSL_DISPATCH_END                                                      \
    }

/* -----------------------------------------------------------------------
 * Per-algorithm extern declarations (18 algorithms)
 * --------------------------------------------------------------------- */

/* ML-DSA-44 */
extern const OSSL_DISPATCH ossl_composite_mldsa44_rsa2048_pss_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa44_rsa2048_pkcs15_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa44_ed25519_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa44_p256_keymgmt_functions[];

/* ML-DSA-65 */
extern const OSSL_DISPATCH ossl_composite_mldsa65_rsa3072_pss_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_rsa3072_pkcs15_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_rsa4096_pss_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_rsa4096_pkcs15_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_p256_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_p384_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_brainpoolp256_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa65_ed25519_keymgmt_functions[];

/* ML-DSA-87 */
extern const OSSL_DISPATCH ossl_composite_mldsa87_p384_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa87_brainpoolp384_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa87_ed448_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa87_rsa3072_pss_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa87_rsa4096_pss_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_composite_mldsa87_p521_keymgmt_functions[];

END_C_DECLS

#endif /* _COMPOSITE_KEYMGMT_H */