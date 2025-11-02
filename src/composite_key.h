#ifndef _COMPOSITE_KEY_H
#define _COMPOSITE_KEY_H

#include "compat.h"
#include "provider_ctx.h"

#include <openssl/evp.h>

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

typedef struct _composite_key_st {
  int algorithm;
  const EVP_MD * md;
  EVP_PKEY * ml_dsa_key;
  EVP_PKEY * trad_key;
} COMPOSITE_KEY;

// ====================
// Functions Prototypes
// ====================


/*! \brief Allocates the memory for a new Composite Key
*
* \return A pointer to the new Composite Key, or NULL on error.
*/
COMPOSITE_KEY * COMPOSITE_KEY_new(void);

/*!
 * \brief Generates a new Composite Key
 *
 * \param algorithm The algorithm to use for key generation.
 * 
 * \return 1 on success, 0 on failure.
 */
int COMPOSITE_KEY_keygen(COMPOSITE_KEY *key, const char * const algorithm);

/*!
 * \brief Frees the memory associated with a Composite Key
 *
 * \param key The Composite Key to free.
 */
void COMPOSITE_KEY_free(COMPOSITE_KEY * key);

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
int COMPOSITE_KEY_get0_components(const COMPOSITE_KEY  * const key, 
                                  EVP_PKEY      ** const ml_dsa_key,
                                  EVP_PKEY      ** const trad_key);

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
int COMPOSITE_KEY_set0_components(COMPOSITE_KEY * key, 
                                  EVP_PKEY      * ml_dsa_key,
                                  EVP_PKEY      * trad_key);


END_C_DECLS

#endif /* _COMPOSITE_KEY_H */