#include "provider.h"
#include "composite_encoder.h"
#include "composite_decoder.h"
#include "composite_kem_info.h"
#include "composite_kem_decoder.h"
#include "composite_kem_encoder.h"

#include <openssl/crypto.h>

/*
 * The signature and KEM modules each publish their own codec algorithm
 * lists, but OSSL_PROVIDER_QUERY_OPERATION returns exactly one array per
 * operation.  Merge the two lists once, on first query; both sources are
 * static const arrays that ignore provctx, so the merge does not depend on
 * which provider instance triggers it.
 *
 * Capacity: 24 KEM + 36 signature decoders, 48 KEM + 72 signature encoders,
 * plus a terminator.  merge_algorithm_lists() stops early (leaving the list
 * terminated) rather than overrun if an addition outgrows this — bump the
 * size when adding algorithms.
 */
#define COMPOSITE_MAX_CODEC_ALGS 128

static OSSL_ALGORITHM merged_decoders[COMPOSITE_MAX_CODEC_ALGS];
static OSSL_ALGORITHM merged_encoders[COMPOSITE_MAX_CODEC_ALGS];
static CRYPTO_ONCE codec_merge_once = CRYPTO_ONCE_STATIC_INIT;

static size_t merge_algorithm_lists(OSSL_ALGORITHM *dst, size_t used,
                                    const OSSL_ALGORITHM *src)
{
    for (; src != NULL && src->algorithm_names != NULL; src++) {
        if (used >= COMPOSITE_MAX_CODEC_ALGS - 1)
            break;
        dst[used++] = *src;
    }
    dst[used].algorithm_names = NULL;
    return used;
}

static void codec_merge_do(void)
{
    size_t n;

    n = merge_algorithm_lists(merged_decoders, 0, composite_decoders(NULL));
    (void)merge_algorithm_lists(merged_decoders, n, composite_kem_decoders(NULL));

    n = merge_algorithm_lists(merged_encoders, 0, composite_encoders(NULL));
    (void)merge_algorithm_lists(merged_encoders, n, composite_kem_encoders(NULL));
}

static const OSSL_ALGORITHM *composite_all_decoders(void)
{
    if (!CRYPTO_THREAD_run_once(&codec_merge_once, codec_merge_do))
        return NULL;
    return merged_decoders;
}

static const OSSL_ALGORITHM *composite_all_encoders(void)
{
    if (!CRYPTO_THREAD_run_once(&codec_merge_once, codec_merge_do))
        return NULL;
    return merged_encoders;
}

/* Provider initialization */
static OSSL_FUNC_provider_gettable_params_fn composite_gettable_params;
static OSSL_FUNC_provider_get_params_fn composite_get_params;
static OSSL_FUNC_provider_query_operation_fn composite_query_operation;

static const OSSL_PARAM composite_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *composite_gettable_params(void *provctx)
{
    (void)provctx; /* Unused */
    return composite_param_types;
}

static int composite_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;
    (void)provctx; /* Unused */

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, COMPOSITE_PROVIDER_NAME))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, COMPOSITE_PROVIDER_VERSION))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "Composite ML-DSA/ML-KEM Provider"))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1))
        return 0;

    return 1;
}

const OSSL_ALGORITHM *composite_query_operation(void *provctx, int operation_id,
                                                 int *no_cache)
{
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_SIGNATURE:
        return composite_signature_algorithms(provctx);
    case OSSL_OP_KEYMGMT:
        return composite_keymgmt(provctx);
    case OSSL_OP_ENCODER:
        return composite_all_encoders();
    case OSSL_OP_DECODER:
        return composite_all_decoders();
    /*
     * The composite KEMs are advertised unconditionally. Probing for ML-KEM
     * here (or caching a probe from OSSL_provider_init) would make availability
     * depend on provider load order and, because no_cache is 0, OpenSSL would
     * cache the empty result forever. Key generation reports a specific error if
     * the ML-KEM component is missing, which is where the caller can act on it.
     */
    case OSSL_OP_KEM:
        return composite_kem_algorithms(provctx);
    }

    return NULL;
}

static void composite_teardown(void *provctx)
{
    COMPOSITE_CTX *ctx = (COMPOSITE_CTX *)provctx;
    
    if (ctx != NULL) {
        OSSL_LIB_CTX_free(ctx->libctx);
        OPENSSL_free(ctx);
    }
}

/* Provider entry point */
static const OSSL_DISPATCH composite_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))composite_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))composite_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))composite_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))composite_query_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {

    COMPOSITE_CTX *ctx;
        // Composite provider context

    /*
     * Register composite algorithm OIDs in the global OBJ database.
     *
     * Both registrations must run before any codec does OBJ_sn2nid() on a
     * composite name: the PKCS#8 and SPKI paths match an incoming
     * AlgorithmIdentifier against the NID that these calls create, so an
     * unregistered OID makes every composite key look like an unknown
     * algorithm.  The KEM half is deliberately a separate function that calls
     * OBJ_create() only -- composite_register_oids() also calls
     * OBJ_add_sigid(), which declares a signature algorithm ID and is
     * meaningless for a KEM.
     */
    composite_register_oids();
    composite_kem_register_oids();

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx == NULL)
        return 0;

    ctx->core_handle = core;
    ctx->libctx = OSSL_LIB_CTX_new_from_dispatch(core, in);
    if (ctx->libctx == NULL) {
        OPENSSL_free(ctx);
        return 0;
    }

    *provctx = ctx;
    *out = composite_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(ctx->libctx, "default") &&
        !OSSL_PROVIDER_available(ctx->libctx, "fips")) {
        COMPOSITE_DEBUG0(
            "OQS PROV: Default and FIPS provider not available. Errors "
            "may result.\n");
    } else {
        COMPOSITE_DEBUG0("OQS PROV: Default or FIPS provider available.\n");
    }

    return 1;
}
