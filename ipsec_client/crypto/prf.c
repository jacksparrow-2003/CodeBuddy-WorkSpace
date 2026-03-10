/**
 * prf.c - PRF and PRF+ Implementation
 *
 * Implements HMAC-SHA256 based PRF and PRF+ for IKEv2 key derivation.
 * RFC 7296 Section 2.13: prf+ function.
 */

#include "prf.h"
#include <string.h>
#include <stdio.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

int hmac_sha256(const uint8_t *key, int key_len,
                const uint8_t *data, int data_len,
                uint8_t *out, unsigned int *out_len)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int  mdlen = 0;

    unsigned char *result = HMAC(EVP_sha256(), key, key_len,
                                  data, data_len, md, &mdlen);
    if (!result) {
        fprintf(stderr, "[PRF] HMAC-SHA256 failed\n");
        return -1;
    }

    if (out_len) *out_len = mdlen;
    memcpy(out, md, mdlen);
    return 0;
}

int prf_hmac_sha256(const uint8_t *key, int key_len,
                    const uint8_t *data, int data_len,
                    uint8_t *out, int *out_len)
{
    unsigned int olen = 0;
    int ret = hmac_sha256(key, key_len, data, data_len, out, &olen);
    if (out_len) *out_len = (int)olen;
    return ret;
}

/**
 * PRF+ (RFC 7296 Section 2.13)
 *
 * prf+(K, S) = T1 | T2 | T3 | ...
 *   T1 = prf(K, S | 0x01)
 *   T2 = prf(K, T1 | S | 0x02)
 *   T3 = prf(K, T2 | S | 0x03)
 *   ...
 * Concatenate until we have enough output bytes.
 */
int prf_plus(const uint8_t *key, int key_len,
             const uint8_t *seed, int seed_len,
             uint8_t *out, int out_len)
{
    uint8_t  T[PRF_HMAC_SHA256_LEN];   /* Previous T value */
    uint8_t  T_new[PRF_HMAC_SHA256_LEN];
    int      T_len = 0;
    uint8_t  counter = 1;
    int      written = 0;

    /* Temporary buffer: T_prev | seed | counter */
    int      buf_size = PRF_HMAC_SHA256_LEN + seed_len + 1;
    uint8_t *buf = malloc(buf_size);
    if (!buf) return -1;

    while (written < out_len) {
        /* Build input: T_prev (if not first) | seed | counter */
        int buf_len = 0;
        if (T_len > 0) {
            memcpy(buf, T, T_len);
            buf_len += T_len;
        }
        memcpy(buf + buf_len, seed, seed_len);
        buf_len += seed_len;
        buf[buf_len++] = counter;

        unsigned int olen = 0;
        if (hmac_sha256(key, key_len, buf, buf_len, T_new, &olen) != 0) {
            free(buf);
            return -1;
        }

        memcpy(T, T_new, olen);
        T_len = (int)olen;

        /* Copy as much as needed */
        int copy = T_len;
        if (written + copy > out_len)
            copy = out_len - written;
        memcpy(out + written, T, copy);
        written += copy;
        counter++;

        if (counter == 0) {
            /* Counter overflow - should not happen in practice */
            fprintf(stderr, "[PRF] PRF+ counter overflow\n");
            free(buf);
            return -1;
        }
    }

    free(buf);
    return 0;
}

int sha256(const uint8_t *data, int data_len,
           uint8_t *out, unsigned int *out_len)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data, data_len);
    SHA256_Final(out, &ctx);
    if (out_len) *out_len = 32;
    return 0;
}
