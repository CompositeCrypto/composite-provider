#ifndef _COMPOSITE_KEM_KEYMGMT_H
#define _COMPOSITE_KEM_KEYMGMT_H

#include "composite_kem_key.h"

BEGIN_C_DECLS

extern const OSSL_DISPATCH mlkem768_rsa2048_functions[];
extern const OSSL_DISPATCH mlkem768_rsa3072_functions[];
extern const OSSL_DISPATCH mlkem768_rsa4096_functions[];
extern const OSSL_DISPATCH mlkem768_x25519_functions[];
extern const OSSL_DISPATCH mlkem768_p256_functions[];
extern const OSSL_DISPATCH mlkem768_p384_functions[];
extern const OSSL_DISPATCH mlkem768_brainpoolp256_functions[];
extern const OSSL_DISPATCH mlkem1024_rsa3072_functions[];
extern const OSSL_DISPATCH mlkem1024_p384_functions[];
extern const OSSL_DISPATCH mlkem1024_brainpoolp384_functions[];
extern const OSSL_DISPATCH mlkem1024_x448_functions[];
extern const OSSL_DISPATCH mlkem1024_p521_functions[];

const OSSL_ALGORITHM *composite_kem_keymgmt_algorithms(void *provctx);

END_C_DECLS

#endif
