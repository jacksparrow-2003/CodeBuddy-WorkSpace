/**
 * prf.h - PRF and PRF+ Implementation for IKEv2 Key Derivation
 *
 * Implements HMAC-SHA256 based PRF and PRF+ as defined in RFC 7296.
 */

#ifndef PRF_H
#define PRF_H

#include <stdint.h>
#include <stddef.h>

/* PRF output length in bytes (HMAC-SHA256 = 32 bytes) */
#define PRF_HMAC_SHA256_LEN  32

/**
 * Compute PRF (HMAC-SHA256).
 * @param key      PRF key
 * @param key_len  Key length
 * @param data     Input data
 * @param data_len Input data length
 * @param out      Output buffer (must be >= PRF_HMAC_SHA256_LEN bytes)
 * @param out_len  Actual output length
 * @return         0 on success, -1 on failure
 */
int prf_hmac_sha256(const uint8_t *key, int key_len,
                    const uint8_t *data, int data_len,
                    uint8_t *out, int *out_len);

/**
 * Compute PRF+ (iterated PRF, RFC 7296 Section 2.13).
 * Generates arbitrary length output.
 * @param key      PRF key
 * @param key_len  Key length
 * @param seed     Seed input data
 * @param seed_len Seed length
 * @param out      Output buffer
 * @param out_len  Desired output length
 * @return         0 on success, -1 on failure
 */
int prf_plus(const uint8_t *key, int key_len,
             const uint8_t *seed, int seed_len,
             uint8_t *out, int out_len);

/**
 * Compute HMAC-SHA256 with variable length output truncation.
 * Returns full 32 bytes; caller truncates as needed.
 */
int hmac_sha256(const uint8_t *key, int key_len,
                const uint8_t *data, int data_len,
                uint8_t *out, unsigned int *out_len);

/**
 * Compute SHA-256 hash.
 */
int sha256(const uint8_t *data, int data_len,
           uint8_t *out, unsigned int *out_len);

#endif /* PRF_H */
