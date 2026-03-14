#ifndef _COMPOSITE_SIG_KEY_H
#define _COMPOSITE_SIG_KEY_H

#include "compat.h"
#include "provider_ctx.h"
#include "composite_provider.h"

#include <string.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>

BEGIN_C_DECLS

// ========================
// Composite Crypto Support
// ========================

// // Basic CTRL values for COMPOSITE support
// # define EVP_PKEY_CTRL_COMPOSITE_PUSH    0x201
// # define EVP_PKEY_CTRL_COMPOSITE_POP     0x202
// # define EVP_PKEY_CTRL_COMPOSITE_ADD     0x203
// # define EVP_PKEY_CTRL_COMPOSITE_DEL     0x204
// # define EVP_PKEY_CTRL_COMPOSITE_CLEAR   0x205

// ==============================
// Declarations & Data Structures
// ==============================

// typedef struct _composite_key_st {
//   int algorithm;
//   const EVP_MD * md;
//   EVP_PKEY * ml_dsa_key;
//   EVP_PKEY * trad_key;
// } COMPOSITE_KEY;

/*
 * Algorithm Identifiers for ML-DSA (FIPS 204)
 */
#define ML_DSA_44  1
#define ML_DSA_65  2
#define ML_DSA_87  3

/*
 * ML-DSA-44 Size Definitions (FIPS 204)
 * Note: PRIV_KEY_SZ represents the seed size (ξ), not the full expanded private key.
 * Full private key would be 2560 bytes. This matches common usage where only the
 * seed is stored and the full key is expanded when needed.
 */
#define ML_DSA_44_PUB_KEY_SZ  1312
#define ML_DSA_44_PRIV_KEY_SZ 32
#define ML_DSA_44_SIG_SZ      2420

/*
 * ML-DSA-65 Size Definitions (FIPS 204)
 * Note: PRIV_KEY_SZ represents the seed size (ξ), not the full expanded private key.
 * Full private key would be 4032 bytes.
 */
#define ML_DSA_65_PUB_KEY_SZ  1952
#define ML_DSA_65_PRIV_KEY_SZ 32
#define ML_DSA_65_SIG_SZ      3309

/*
 * ML-DSA-87 Size Definitions (FIPS 204)
 * Note: PRIV_KEY_SZ represents the seed size (ξ), not the full expanded private key.
 * Full private key would be 4896 bytes.
 */
#define ML_DSA_87_PUB_KEY_SZ  2420
#define ML_DSA_87_PRIV_KEY_SZ 32
#define ML_DSA_87_SIG_SZ      4627


/* Key context structure */
typedef struct composite_key_st {

    // Composite context
    COMPOSITE_CTX *provctx;

    // Identifier for the algorithm used
    int nid;

    // Identifier for the name of the algorithm
    const char *composite_name;

    // Identifier for the TLS name of the algorithm
    const char *composite_tls_name;

    // ML-DSA component and context
    const char *mldsa_name;
    EVP_PKEY_CTX *ml_dsa_ctx;
    EVP_PKEY *mldsa_key;

    // ML-DSA public and private keys
    void *mldsa_privkey;
    void *mldsa_pubkey;

    // Classic Algorithm name and context
    const char *classic_algorithm_name;
    EVP_PKEY_CTX *classic_ctx;
    EVP_PKEY *classic_key;

    // Classic Algorithm public and private keys
    void *classic_privkey;
    void *classic_pubkey;

} COMPOSITE_KEY;

// ====================
// Functions Prototypes
// ====================


/*! \brief Allocates the memory for a new Composite Key
*
* \return A pointer to the new Composite Key, or NULL on error.
*/
COMPOSITE_KEY * composite_signkey_new(void);

/*!
 * \brief Generates the cryptographic key material for a Composite Key
 *
 * This function generates the key material for both the ML-DSA and
 * traditional components of the Composite Key based on the specified
 * algorithm.
 * 
 * \param[in out] key The Composite Key to generate key material for.
 * \param[in] algorithm The name of the composite algorithm to use.
 * \param[in] ctx The Composite context to use for key generation.
 *
 * \return 1 on success, 0 on failure.
 */
int composite_signkey_generate(COMPOSITE_CTX * ctx,
                               COMPOSITE_KEY * key,
                               const char    * const algorithm);

/*!
 * \brief Frees the memory associated with a Composite Key
 *
 * \param key The Composite Key to free.
 */
void composite_signkey_free(COMPOSITE_KEY * key);

/*!
 * \brief Retrieves the components of a Composite Key
 *
 * This function retrieves the ML-DSA key and traditional key components of
 * a Composite Key. The returned pointers are only valid as long as the
 * Composite Key is not modified or freed (i.e., they are still owned by)
 * the Composite Key and the caller SHALL NOT free them.
 * 
 * \param[in] key The Composite Key to retrieve components from.
 * \param[out] ml_dsa_key Pointer to store the ML-DSA key.
 * \param[out] trad_key Pointer to store the traditional key.
 * 
 * \return 1 on success, 0 on failure.
 */
int composite_signkey_get0_components(const COMPOSITE_KEY  * const key, 
                                      EVP_PKEY            ** const ml_dsa_key,
                                      EVP_PKEY            ** const trad_key);

/*!
 * \brief Sets the components of a Composite Key
 *
 * This function sets the ML-DSA key and traditional key components of
 * a Composite Key. The components are transferred (moved) to the new
 * Composite Key and the caller SHALL NOT free them.
 *
 * \param[in] key The Composite Key to set components for.
 * \param[in] ml_dsa_key The ML-DSA key to set.
 * \param[in] trad_key The traditional key to set.
 * 
 * \return 1 on success, 0 on failure.
 */
int composite_signkey_set0_components(COMPOSITE_KEY * key, 
                                      EVP_PKEY      * ml_dsa_key,
                                      EVP_PKEY      * trad_key);


END_C_DECLS

#endif /* _COMPOSITE_SIG_KEY_H */
