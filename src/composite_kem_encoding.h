#ifndef COMPOSITE_KEM_ENCODING_H
#define COMPOSITE_KEM_ENCODING_H

#include <stddef.h>
#include <string.h>

#include "composite_kem_key.h" /* for algorithm IDs and ML-KEM sizes */

/*
 * Encode a composite KEM public key using raw concatenation.
 * Format: [ML-KEM public key bytes][traditional public key bytes]
 *
 * The ML-KEM public key length must match the expected size for pq_alg.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param pq_pub Pointer to ML-KEM public key data
 * @param pq_pub_len Length of ML-KEM public key (must match ML_KEM_*_PUB_KEY_SZ)
 * @param trad_pub Pointer to traditional public key data
 * @param trad_pub_len Length of traditional public key
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_kem_pubkey_encode(int pq_alg,
                                const unsigned char *pq_pub, size_t pq_pub_len,
                                const unsigned char *trad_pub, size_t trad_pub_len,
                                unsigned char *out, size_t *out_len);

/*
 * Decode a composite KEM public key from raw concatenation.
 *
 * The ML-KEM public key is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_pub and trad_pub; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param in Input buffer containing encoded public key
 * @param in_len Length of input buffer
 * @param pq_pub Output: pointer to allocated ML-KEM public key data
 * @param pq_pub_len Output: length of ML-KEM public key
 * @param trad_pub Output: pointer to allocated traditional public key data
 * @param trad_pub_len Output: length of traditional public key
 * @return 1 on success, 0 on failure
 */
int composite_kem_pubkey_decode(int pq_alg,
                                const unsigned char *in, size_t in_len,
                                unsigned char **pq_pub, size_t *pq_pub_len,
                                unsigned char **trad_pub, size_t *trad_pub_len);

/*
 * Encode a composite KEM private key using raw concatenation.
 * Format: [ML-KEM private key bytes][traditional private key bytes]
 *
 * The ML-KEM private key length must match the expected size for pq_alg.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param pq_priv Pointer to ML-KEM private key data (compact representation)
 * @param pq_priv_len Length of ML-KEM private key (must match ML_KEM_*_PRIV_KEY_SZ)
 * @param trad_priv Pointer to traditional private key data
 * @param trad_priv_len Length of traditional private key
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_kem_privkey_encode(int pq_alg,
                                 const unsigned char *pq_priv, size_t pq_priv_len,
                                 const unsigned char *trad_priv, size_t trad_priv_len,
                                 unsigned char *out, size_t *out_len);

/*
 * Decode a composite KEM private key from raw concatenation.
 *
 * The ML-KEM private key is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_priv and trad_priv; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param in Input buffer containing encoded private key
 * @param in_len Length of input buffer
 * @param pq_priv Output: pointer to allocated ML-KEM private key data
 * @param pq_priv_len Output: length of ML-KEM private key
 * @param trad_priv Output: pointer to allocated traditional private key data
 * @param trad_priv_len Output: length of traditional private key
 * @return 1 on success, 0 on failure
 */
int composite_kem_privkey_decode(int pq_alg,
                                 const unsigned char *in, size_t in_len,
                                 unsigned char **pq_priv, size_t *pq_priv_len,
                                 unsigned char **trad_priv, size_t *trad_priv_len);

/*
 * Encode a composite KEM ciphertext using raw concatenation.
 * Format: [ML ciphertext bytes][traditional ciphertext bytes]
 *
 * The ML ciphertext length must exactly match the expected size for pq_alg.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param pq_ct Pointer to PQ ciphertext data
 * @param pq_ct_len Length of PQ ciphertext (must match ML_KEM_*_CT_SZ)
 * @param trad_ct Pointer to traditional ciphertext data
 * @param trad_ct_len Length of traditional ciphertext
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_kem_ct_encode(int pq_alg, const unsigned char *pq_ct, size_t pq_ct_len,
                            const unsigned char *trad_ct, size_t trad_ct_len,
                            unsigned char *out, size_t *out_len);

/*
 * Decode a composite KEM ciphertext from raw concatenation format.
 *
 * The ML ciphertext is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_ct and trad_ct; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_KEM_768 or ML_KEM_1024)
 * @param in Input buffer containing encoded ciphertext
 * @param in_len Length of input buffer
 * @param pq_ct Output: pointer to allocated PQ ciphertext data
 * @param pq_ct_len Output: length of PQ ciphertext
 * @param trad_ct Output: pointer to allocated traditional ciphertext data
 * @param trad_ct_len Output: length of traditional ciphertext
 * @return 1 on success, 0 on failure
 */
int composite_kem_ct_decode(int pq_alg, const unsigned char *in, size_t in_len,
                            unsigned char **pq_ct, size_t *pq_ct_len,
                            unsigned char **trad_ct, size_t *trad_ct_len);

#endif /* COMPOSITE_KEM_ENCODING_H */
