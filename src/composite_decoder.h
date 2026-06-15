/*
 * composite_decoder.h — DER decoder for composite key types
 *
 * Declares the OSSL_OP_DECODER algorithm table for SubjectPublicKeyInfo
 * and PrivateKeyInfo structures covering all composite SIG algorithms.
 */
#ifndef COMPOSITE_DECODER_H
#define COMPOSITE_DECODER_H

#include "compat.h"
#include "../include/composite_provider.h"

#include <openssl/core.h>

BEGIN_C_DECLS

/*
 * Return the OSSL_ALGORITHM table for OSSL_OP_DECODER.
 * Covers SubjectPublicKeyInfo/DER and PrivateKeyInfo/DER for every
 * composite SIG algorithm.
 */
const OSSL_ALGORITHM *composite_decoders(void *provctx);

END_C_DECLS

#endif /* COMPOSITE_DECODER_H */
