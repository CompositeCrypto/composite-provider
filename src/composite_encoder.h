/*
 * composite_encoder.h — PEM encoder for composite key types
 *
 * Declares the OSSL_OP_ENCODER algorithm table (PrivateKeyInfo/PEM and
 * SubjectPublicKeyInfo/PEM) and the OID registration helper used by
 * OSSL_provider_init.
 */
#ifndef COMPOSITE_ENCODER_H
#define COMPOSITE_ENCODER_H

#include "compat.h"
#include "../include/composite_provider.h"

#include <openssl/core.h>

BEGIN_C_DECLS

/*
 * Register all composite SIG algorithm OIDs in the global OBJ database.
 * Must be called once from OSSL_provider_init before any encoder or
 * keymgmt operation that resolves an OID by SN.
 */
void composite_register_oids(void);

/*
 * Return the OSSL_ALGORITHM table for OSSL_OP_ENCODER.
 * Covers PrivateKeyInfo/PEM and SubjectPublicKeyInfo/PEM for every
 * composite SIG algorithm.
 */
const OSSL_ALGORITHM *composite_encoders(void *provctx);

END_C_DECLS

#endif /* COMPOSITE_ENCODER_H */
