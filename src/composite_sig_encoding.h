#ifndef COMPOSITE_SIG_ENCODING_H
#define COMPOSITE_SIG_ENCODING_H

#include <stddef.h>
#include <string.h>

// #include "composite_encoding.h" /* for algorithm IDs and ML-DSA sizes */

#include "composite_sig_key.h"

/*
 * Encode a composite SIG public key using raw concatenation.
 * Format: [ML-DSA public key bytes][traditional public key bytes]
 *
 * The ML-DSA public key length must match the expected size for pq_alg.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param pq_pub Pointer to ML-DSA public key data
 * @param pq_pub_len Length of ML-DSA public key (must match ML_DSA_*_PUB_KEY_SZ)
 * @param trad_pub Pointer to traditional public key data
 * @param trad_pub_len Length of traditional public key
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_sig_pubkey_encode(int pq_alg,
                                const unsigned char *pq_pub, size_t pq_pub_len,
                                const unsigned char *trad_pub, size_t trad_pub_len,
                                unsigned char *out, size_t *out_len);

/*
 * Decode a composite SIG public key from raw concatenation.
 *
 * The ML-DSA public key is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_pub and trad_pub; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param in Input buffer containing encoded public key
 * @param in_len Length of input buffer
 * @param pq_pub Output: pointer to allocated ML-DSA public key data
 * @param pq_pub_len Output: length of ML-DSA public key
 * @param trad_pub Output: pointer to allocated traditional public key data
 * @param trad_pub_len Output: length of traditional public key
 * @return 1 on success, 0 on failure
 */
int composite_sig_pubkey_decode(int pq_alg,
                                const unsigned char *in, size_t in_len,
                                unsigned char **pq_pub, size_t *pq_pub_len,
                                unsigned char **trad_pub, size_t *trad_pub_len);

/*
 * Encode a composite SIG private key using raw concatenation.
 * Format: [ML-DSA private seed bytes][traditional private key bytes]
 *
 * The ML-DSA private seed length must match the expected size for pq_alg.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param pq_seed Pointer to ML-DSA private seed data
 * @param pq_seed_len Length of ML-DSA private seed (must match ML_DSA_*_PRIV_KEY_SZ)
 * @param trad_priv Pointer to traditional private key data
 * @param trad_priv_len Length of traditional private key
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_sig_privkey_encode(int pq_alg,
                                 const unsigned char *pq_seed, size_t pq_seed_len,
                                 const unsigned char *trad_priv, size_t trad_priv_len,
                                 unsigned char *out, size_t *out_len);

/*
 * Decode a composite SIG private key from raw concatenation.
 *
 * The ML-DSA private seed is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_seed and trad_priv; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param in Input buffer containing encoded private key
 * @param in_len Length of input buffer
 * @param pq_seed Output: pointer to allocated ML-DSA private seed data
 * @param pq_seed_len Output: length of ML-DSA private seed
 * @param trad_priv Output: pointer to allocated traditional private key data
 * @param trad_priv_len Output: length of traditional private key
 * @return 1 on success, 0 on failure
 */
int composite_sig_privkey_decode(int pq_alg,
                                 const unsigned char *in, size_t in_len,
                                 unsigned char **pq_seed, size_t *pq_seed_len,
                                 unsigned char **trad_priv, size_t *trad_priv_len);

/*
 * Encode a composite signature using raw concatenation.
 * Format: [ML signature bytes][traditional signature bytes]
 *
 * The ML signature length must exactly match the expected size for pq_alg.
 * No length prefixes or ASN.1 encoding is used.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param pq_sig Pointer to PQ signature data
 * @param pq_sig_len Length of PQ signature (must match ML_DSA_*_SIG_SZ)
 * @param trad_sig Pointer to traditional signature data
 * @param trad_sig_len Length of traditional signature
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_sig_encode(int pq_alg, const unsigned char *pq_sig, size_t pq_sig_len,
                         const unsigned char *trad_sig, size_t trad_sig_len,
                         unsigned char *out, size_t *out_len);

/*
 * Decode a composite signature from raw concatenation format.
 *
 * The ML signature is extracted based on the expected size for pq_alg.
 * Memory is allocated for pq_sig and trad_sig; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param in Input buffer containing encoded signature
 * @param in_len Length of input buffer
 * @param pq_sig Output: pointer to allocated PQ signature data
 * @param pq_sig_len Output: length of PQ signature
 * @param trad_sig Output: pointer to allocated traditional signature data
 * @param trad_sig_len Output: length of traditional signature
 * @return 1 on success, 0 on failure
 */
int composite_sig_decode(int pq_alg, const unsigned char *in, size_t in_len,
                         unsigned char **pq_sig, size_t *pq_sig_len,
                         unsigned char **trad_sig, size_t *trad_sig_len);

#endif /* COMPOSITE_SIG_ENCODING_H */
