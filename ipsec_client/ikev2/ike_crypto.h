/**
 * ike_crypto.h - IKEv2 Key Material Derivation (RFC 7296)
 *
 * Provides functions to derive SKEYSEED, SK_d, SK_ei, SK_er, etc.
 * and to compute PSK authentication values.
 */

#ifndef IKE_CRYPTO_H
#define IKE_CRYPTO_H

#include "ike_types.h"
#include <stdint.h>

/**
 * Derive all IKE SA keys from the DH shared secret.
 *
 * SKEYSEED = prf(Ni | Nr, g^ir)
 * {SK_d|SK_ai|SK_ar|SK_ei|SK_er|SK_pi|SK_pr} = prf+(SKEYSEED, Ni|Nr|SPIi|SPIr)
 *
 * @param ctx   IKE SA context (contains nonces, SPIs, algorithms, will be filled)
 * @return      0 on success, -1 on failure
 */
int ike_derive_keys(ike_sa_ctx_t *ctx);

/**
 * Derive Child SA keys.
 *
 * KEYMAT = prf+(SK_d, Ni' | Nr')
 *
 * @param ctx     IKE SA context (contains SK_d, child nonces, algorithms)
 * @param nonce_i Child SA nonce from initiator
 * @param ni_len  Length of nonce_i
 * @param nonce_r Child SA nonce from responder
 * @param nr_len  Length of nonce_r
 * @return        0 on success, -1 on failure
 */
int ike_derive_child_keys(ike_sa_ctx_t *ctx,
                          const uint8_t *nonce_i, int ni_len,
                          const uint8_t *nonce_r, int nr_len);

/**
 * Compute PSK AUTH value for the initiator.
 *
 * AUTH_i = prf(prf(PSK, "Key Pad for IKEv2"),
 *              msg1_octets | Nr | prf(SK_pi, IDi_payload_data))
 *
 * @param ctx       IKE SA context
 * @param idi_data  IDi payload data (after generic payload header, starting from id_type)
 * @param idi_len   IDi payload data length
 * @param auth_out  Output buffer (must be >= 32 bytes)
 * @param auth_len  Output length
 * @return          0 on success, -1 on failure
 */
int ike_compute_auth_initiator(ike_sa_ctx_t *ctx,
                               const uint8_t *idi_data, int idi_len,
                               uint8_t *auth_out, int *auth_len);

/**
 * Verify PSK AUTH value from the responder.
 *
 * AUTH_r = prf(prf(PSK, "Key Pad for IKEv2"),
 *              msg2_octets | Ni | prf(SK_pr, IDr_payload_data))
 *
 * @param ctx       IKE SA context
 * @param idr_data  IDr payload data
 * @param idr_len   IDr payload data length
 * @param auth_in   Received AUTH value from peer
 * @param auth_in_len Length of received AUTH
 * @return          0 if valid, -1 if invalid
 */
int ike_verify_auth_responder(ike_sa_ctx_t *ctx,
                              const uint8_t *idr_data, int idr_len,
                              const uint8_t *auth_in, int auth_in_len);

/**
 * Encrypt an IKE message with SK payload (AES-CBC + HMAC-SHA256).
 *
 * @param key_e    Encryption key
 * @param key_e_len  Encryption key length in bytes
 * @param key_i    Integrity key
 * @param key_i_len  Integrity key length in bytes
 * @param salt     AES-GCM salt (4 bytes, only if is_aead)
 * @param is_aead  1 = AES-GCM, 0 = AES-CBC + HMAC
 * @param plaintext  Inner payloads to encrypt
 * @param pt_len   Plaintext length
 * @param out      Output SK payload data (IV + ciphertext + ICV)
 * @param out_len  Output length
 * @param seq_no   IKE message sequence number (for GCM AAD)
 * @return         0 on success, -1 on failure
 */
int ike_sk_encrypt(const uint8_t *key_e, int key_e_len,
                   const uint8_t *key_i, int key_i_len,
                   const uint8_t *salt, int is_aead,
                   const uint8_t *plaintext, int pt_len,
                   uint8_t *out, int *out_len,
                   const uint8_t *ike_hdr, int ike_hdr_len);

/**
 * Decrypt an IKE SK payload.
 *
 * @param sk_data  SK payload data (IV + ciphertext + ICV)
 * @param sk_len   SK payload data length
 * @param out      Decrypted inner payloads
 * @param out_len  Decrypted length
 * @return         0 on success, -1 on failure
 */
int ike_sk_decrypt(const uint8_t *key_e, int key_e_len,
                   const uint8_t *key_i, int key_i_len,
                   const uint8_t *salt, int is_aead,
                   const uint8_t *sk_data, int sk_len,
                   uint8_t *out, int *out_len,
                   const uint8_t *ike_hdr, int ike_hdr_len);

#endif /* IKE_CRYPTO_H */
