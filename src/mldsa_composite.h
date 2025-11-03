#ifndef _COMPOSITE_MLDSA_H
#define _COMPOSITE_MLDSA_H

#include "compat.h"
#include "composite_provider.h"

#include <openssl/core_names.h>

/*
 * ML-DSA Composite Signature Algorithms
 * 
 * This file implements the algorithm dispatch for ML-DSA composite signatures.
 * Each composite algorithm combines ML-DSA (Dilithium) with a traditional algorithm.
 *
 * Supported combinations:
 * - ML-DSA-44 + RSA-2048
 * - ML-DSA-44 + ECDSA-P256
 * - ML-DSA-65 + RSA-3072
 * - ML-DSA-65 + ECDSA-P384
 * - ML-DSA-87 + RSA-4096
 * - ML-DSA-87 + ECDSA-P521
 */

BEGIN_C_DECLS

                    // ====================
                    // Signature operations
                    // ====================

EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa44, rsa2048)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa44, ed25519)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa44, ecdsa_p256)

EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa65, rsa3072)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa65, rsa4096)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa65, ecdsa_p256)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa65, ecdsa_p384)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa65, ecdsa_brainpool256)

EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, ecdsa_p384)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, ecdsa_brainpool384)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, ed448)

EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, rsa4096)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, rsa3072)
EXTERN_DECLARE_SIG_DISPATCH_TABLE(mldsa87, ecdsa_p521)

END_C_DECLS

#endif /* _COMPOSITE_MLDSA_H */