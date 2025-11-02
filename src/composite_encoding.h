#ifndef COMPOSITE_ENCODING_H
#define COMPOSITE_ENCODING_H

#include <stddef.h>

/*
 * Algorithm Identifiers for ML-DSA (FIPS 204)
 * These identifiers are used to specify which ML-DSA variant is being used
 */
#define ML_DSA_44  1
#define ML_DSA_65  2
#define ML_DSA_87  3

/*
 * Algorithm Identifiers for ML-KEM (FIPS 203)
 * These identifiers are used to specify which ML-KEM variant is being used
 */
#define ML_KEM_768  4
#define ML_KEM_1024 5

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

/*
 * ML-KEM-768 Size Definitions (FIPS 203)
 * Note: PRIV_KEY_SZ represents a compact representation (seed or hash), not the full
 * expanded private key. Full private key would be 2400 bytes.
 */
#define ML_KEM_768_PUB_KEY_SZ  1184
#define ML_KEM_768_PRIV_KEY_SZ 64
#define ML_KEM_768_CT_SZ       1088

/*
 * ML-KEM-1024 Size Definitions (FIPS 203)
 * Note: PRIV_KEY_SZ represents a compact representation (seed or hash), not the full
 * expanded private key. Full private key would be 3168 bytes.
 */
#define ML_KEM_1024_PUB_KEY_SZ  1568
#define ML_KEM_1024_PRIV_KEY_SZ 64
#define ML_KEM_1024_CT_SZ       1568

/*
 * Encode a composite key using raw concatenation.
 * Format: [pq_key][trad_key]
 *
 * The pq_key length must exactly match the expected size for the given pq_alg.
 * For public keys, pq_key_len must match ML_DSA_*_PUB_KEY_SZ.
 * For private keys, pq_key_len must match ML_DSA_*_PRIV_KEY_SZ.
 * No length prefixes are used.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param pq_key Pointer to PQ key data
 * @param pq_key_len Length of PQ key (must match expected size)
 * @param trad_key Pointer to traditional key data
 * @param trad_key_len Length of traditional key
 * @param out Output buffer (NULL to query required size)
 * @param out_len Input: buffer size, Output: required/written size
 * @return 1 on success, 0 on failure
 */
int composite_key_encode(int pq_alg, const unsigned char *pq_key, size_t pq_key_len,
                         const unsigned char *trad_key, size_t trad_key_len,
                         unsigned char *out, size_t *out_len);

/*
 * Decode a composite key from raw concatenation format.
 *
 * The pq_key is extracted based on the expected size for the given pq_alg.
 * The traditional key is the remaining data.
 * Memory is allocated for pq_key and trad_key; caller must free them.
 *
 * @param pq_alg Algorithm identifier (ML_DSA_44, ML_DSA_65, or ML_DSA_87)
 * @param in Input buffer containing encoded key
 * @param in_len Length of input buffer
 * @param pq_key Output: pointer to allocated PQ key data
 * @param pq_key_len Output: length of PQ key
 * @param trad_key Output: pointer to allocated traditional key data
 * @param trad_key_len Output: length of traditional key
 * @return 1 on success, 0 on failure
 */
int composite_key_decode(int pq_alg, const unsigned char *in, size_t in_len,
                         unsigned char **pq_key, size_t *pq_key_len,
                         unsigned char **trad_key, size_t *trad_key_len);

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

#endif /* COMPOSITE_ENCODING_H */
