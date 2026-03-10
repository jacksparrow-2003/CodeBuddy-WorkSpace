/**
 * aes_utils.h - AES-CBC and AES-GCM Encryption/Decryption for IKEv2 and ESP
 */

#ifndef AES_UTILS_H
#define AES_UTILS_H

#include <stdint.h>
#include <stddef.h>

/* AES block size */
#define AES_BLOCK_SIZE   16

/* AES-GCM nonce size */
#define AES_GCM_NONCE_SIZE  12
#define AES_GCM_IV_SIZE     8
#define AES_GCM_SALT_SIZE   4
#define AES_GCM_ICV_SIZE    16

/* AES-CBC IV size */
#define AES_CBC_IV_SIZE     16

/* HMAC-SHA256 truncated ICV size (128 bits = 16 bytes) */
#define HMAC_SHA256_TRUNC_SIZE  16

/**
 * AES-CBC Encrypt.
 * @param key       AES key (16, 24, or 32 bytes)
 * @param key_len   Key length in bytes
 * @param iv        IV (16 bytes)
 * @param plaintext Input plaintext
 * @param pt_len    Plaintext length (must be multiple of 16)
 * @param ciphertext Output buffer (same size as plaintext)
 * @param ct_len    Output: ciphertext length
 * @return          0 on success, -1 on failure
 */
int aes_cbc_encrypt(const uint8_t *key, int key_len,
                    const uint8_t *iv,
                    const uint8_t *plaintext, int pt_len,
                    uint8_t *ciphertext, int *ct_len);

/**
 * AES-CBC Decrypt.
 */
int aes_cbc_decrypt(const uint8_t *key, int key_len,
                    const uint8_t *iv,
                    const uint8_t *ciphertext, int ct_len,
                    uint8_t *plaintext, int *pt_len);

/**
 * AES-GCM Encrypt.
 * @param key       AES key (16 or 32 bytes)
 * @param key_len   Key length in bytes (NOT including salt)
 * @param nonce     12-byte nonce (salt[4] || iv[8])
 * @param aad       Additional Authenticated Data
 * @param aad_len   AAD length
 * @param plaintext Input plaintext
 * @param pt_len    Plaintext length
 * @param ciphertext Output ciphertext buffer
 * @param ct_len    Output: ciphertext length
 * @param icv       Output: 16-byte ICV/tag
 * @return          0 on success, -1 on failure
 */
int aes_gcm_encrypt(const uint8_t *key, int key_len,
                    const uint8_t *nonce,
                    const uint8_t *aad, int aad_len,
                    const uint8_t *plaintext, int pt_len,
                    uint8_t *ciphertext, int *ct_len,
                    uint8_t *icv);

/**
 * AES-GCM Decrypt and verify.
 * @param icv  16-byte ICV to verify
 * @return     0 on success, -1 on failure (including authentication failure)
 */
int aes_gcm_decrypt(const uint8_t *key, int key_len,
                    const uint8_t *nonce,
                    const uint8_t *aad, int aad_len,
                    const uint8_t *ciphertext, int ct_len,
                    uint8_t *plaintext, int *pt_len,
                    const uint8_t *icv);

/**
 * Generate random bytes.
 */
int random_bytes(uint8_t *buf, int len);

/**
 * Compute HMAC-SHA256 and return first trunc_len bytes as ICV.
 */
int hmac_sha256_compute(const uint8_t *key, int key_len,
                        const uint8_t *data, int data_len,
                        uint8_t *icv, int trunc_len);

/**
 * Verify HMAC-SHA256 ICV.
 * @return 0 if valid, -1 if invalid
 */
int hmac_sha256_verify(const uint8_t *key, int key_len,
                       const uint8_t *data, int data_len,
                       const uint8_t *icv, int icv_len);

#endif /* AES_UTILS_H */
