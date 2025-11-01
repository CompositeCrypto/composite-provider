#ifndef _MLDSA_COMPOSITE_H
#define _MLDSA_COMPOSITE_H

#include "compat.h"
#include "composite_provider.h"

#include <openssl/core_names.h>

BEGIN_C_DECLS

                    // ==============
                    // KEM operations
                    // ==============

EXTERN_DECLARE_KEM_DISPATCH_TABLE(mlkem512, ecdh_p256)
EXTERN_DECLARE_KEM_DISPATCH_TABLE(mlkem768, ecdh_p384)
EXTERN_DECLARE_KEM_DISPATCH_TABLE(mlkem1024, ecdh_p521)

END_C_DECLS

#endif /* _MLDSA_COMPOSITE_H */