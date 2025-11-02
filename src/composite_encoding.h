#ifndef COMPOSITE_ENCODING_H
#define COMPOSITE_ENCODING_H

#include "compat.h"
#include <openssl/evp.h>
#include <openssl/asn1.h>
#include <stddef.h>

BEGIN_C_DECLS

/* ========================================
 * Composite Key Encoding/Decoding
 * ========================================
 * Keys are encoded as concatenated raw bytes:
 * [PQ_key_length (4 bytes)][PQ_key_data][Trad_key_length (4 bytes)][Trad_key_data]
 */

/**
 * Encode a composite key (signature or KEM) into a byte array
 * 
 * @param pq_key Pointer to the post-quantum key data
 * @param pq_key_len Length of the post-quantum key
 * @param trad_key Pointer to the traditional key data
 * @param trad_key_len Length of the traditional key
 * @param out Output buffer for encoded key (can be NULL to query size)
 * @param out_len Pointer to store the output length
 * @return 1 on success, 0 on failure
 */
int composite_key_encode(const unsigned char *pq_key, size_t pq_key_len,
                         const unsigned char *trad_key, size_t trad_key_len,
                         unsigned char *out, size_t *out_len);

/**
 * Decode a composite key from a byte array
 * 
 * @param in Input buffer containing encoded key
 * @param in_len Length of the input buffer
 * @param pq_key Output buffer for post-quantum key (allocated by this function)
 * @param pq_key_len Pointer to store the post-quantum key length
 * @param trad_key Output buffer for traditional key (allocated by this function)
 * @param trad_key_len Pointer to store the traditional key length
 * @return 1 on success, 0 on failure
 */
int composite_key_decode(const unsigned char *in, size_t in_len,
                         unsigned char **pq_key, size_t *pq_key_len,
                         unsigned char **trad_key, size_t *trad_key_len);

/* ========================================
 * Composite Signature Encoding/Decoding
 * ========================================
 * Signatures use ASN.1 SEQUENCE encoding:
 * CompositeSignature ::= SEQUENCE {
 *     pqSignature       OCTET STRING,
 *     traditionalSignature OCTET STRING
 * }
 */

/**
 * Encode a composite signature using ASN.1
 * 
 * @param pq_sig Pointer to the post-quantum signature
 * @param pq_sig_len Length of the post-quantum signature
 * @param trad_sig Pointer to the traditional signature
 * @param trad_sig_len Length of the traditional signature
 * @param out Output buffer for encoded signature (can be NULL to query size)
 * @param out_len Pointer to store the output length
 * @return 1 on success, 0 on failure
 */
int composite_sig_encode(const unsigned char *pq_sig, size_t pq_sig_len,
                         const unsigned char *trad_sig, size_t trad_sig_len,
                         unsigned char *out, size_t *out_len);

/**
 * Decode a composite signature from ASN.1
 * 
 * @param in Input buffer containing ASN.1 encoded signature
 * @param in_len Length of the input buffer
 * @param pq_sig Output buffer for post-quantum signature (allocated by this function)
 * @param pq_sig_len Pointer to store the post-quantum signature length
 * @param trad_sig Output buffer for traditional signature (allocated by this function)
 * @param trad_sig_len Pointer to store the traditional signature length
 * @return 1 on success, 0 on failure
 */
int composite_sig_decode(const unsigned char *in, size_t in_len,
                         unsigned char **pq_sig, size_t *pq_sig_len,
                         unsigned char **trad_sig, size_t *trad_sig_len);

/* ========================================
 * Composite KEM Ciphertext Encoding/Decoding
 * ========================================
 * KEM ciphertexts are encoded as concatenated raw bytes:
 * [PQ_ct_length (4 bytes)][PQ_ciphertext][Trad_ct_length (4 bytes)][Trad_ciphertext]
 */

/**
 * Encode a composite KEM ciphertext into a byte array
 * 
 * @param pq_ct Pointer to the post-quantum ciphertext
 * @param pq_ct_len Length of the post-quantum ciphertext
 * @param trad_ct Pointer to the traditional ciphertext
 * @param trad_ct_len Length of the traditional ciphertext
 * @param out Output buffer for encoded ciphertext (can be NULL to query size)
 * @param out_len Pointer to store the output length
 * @return 1 on success, 0 on failure
 */
int composite_kem_ct_encode(const unsigned char *pq_ct, size_t pq_ct_len,
                            const unsigned char *trad_ct, size_t trad_ct_len,
                            unsigned char *out, size_t *out_len);

/**
 * Decode a composite KEM ciphertext from a byte array
 * 
 * @param in Input buffer containing encoded ciphertext
 * @param in_len Length of the input buffer
 * @param pq_ct Output buffer for post-quantum ciphertext (allocated by this function)
 * @param pq_ct_len Pointer to store the post-quantum ciphertext length
 * @param trad_ct Output buffer for traditional ciphertext (allocated by this function)
 * @param trad_ct_len Pointer to store the traditional ciphertext length
 * @return 1 on success, 0 on failure
 */
int composite_kem_ct_decode(const unsigned char *in, size_t in_len,
                            unsigned char **pq_ct, size_t *pq_ct_len,
                            unsigned char **trad_ct, size_t *trad_ct_len);

END_C_DECLS

#endif /* COMPOSITE_ENCODING_H */
