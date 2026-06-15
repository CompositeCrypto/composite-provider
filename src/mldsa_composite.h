#ifndef _COMPOSITE_MLDSA_H
#define _COMPOSITE_MLDSA_H

#include "compat.h"
#include "composite_provider.h"
#include "composite_sig.h"

#include <openssl/core_names.h>

BEGIN_C_DECLS

/* Per-variant signature dispatch tables (defined in mldsa_composite.c) */
/* ML-DSA-44 */
extern const OSSL_DISPATCH composite_mldsa44_rsa2048_pss_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa44_rsa2048_pkcs15_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa44_ed25519_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa44_p256_signature_functions[];
/* ML-DSA-65 */
extern const OSSL_DISPATCH composite_mldsa65_rsa3072_pss_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_rsa3072_pkcs15_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_rsa4096_pss_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_rsa4096_pkcs15_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_p256_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_p384_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_brainpoolp256_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa65_ed25519_signature_functions[];
/* ML-DSA-87 */
extern const OSSL_DISPATCH composite_mldsa87_p384_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa87_brainpoolp384_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa87_ed448_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa87_rsa3072_pss_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa87_rsa4096_pss_signature_functions[];
extern const OSSL_DISPATCH composite_mldsa87_p521_signature_functions[];

END_C_DECLS

#endif /* _COMPOSITE_MLDSA_H */
