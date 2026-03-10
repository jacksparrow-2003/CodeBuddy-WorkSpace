/**
 * aes_utils.c - AES-CBC and AES-GCM Implementation using OpenSSL EVP
 */

#include "aes_utils.h"
#include <string.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

static void print_ssl_err(const char *msg)
{
    fprintf(stderr, "[AES] %s: ", msg);
    ERR_print_errors_fp(stderr);
}

static const EVP_CIPHER *get_aes_cbc(int key_len)
{
    switch (key_len) {
    case 16: return EVP_aes_128_cbc();
    case 24: return EVP_aes_192_cbc();
    case 32: return EVP_aes_256_cbc();
    default: return NULL;
    }
}

int aes_cbc_encrypt(const uint8_t *key, int key_len,
                    const uint8_t *iv,
                    const uint8_t *plaintext, int pt_len,
                    uint8_t *ciphertext, int *ct_len)
{
    const EVP_CIPHER *cipher = get_aes_cbc(key_len);
    if (!cipher) {
        fprintf(stderr, "[AES] Invalid key length %d\n", key_len);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        print_ssl_err("EncryptInit");
        goto err;
    }
    /* Disable automatic padding (we handle it manually) */
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) {
        print_ssl_err("EncryptUpdate");
        goto err;
    }
    total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) {
        print_ssl_err("EncryptFinal");
        goto err;
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *ct_len = total;
    return 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_cbc_decrypt(const uint8_t *key, int key_len,
                    const uint8_t *iv,
                    const uint8_t *ciphertext, int ct_len,
                    uint8_t *plaintext, int *pt_len)
{
    const EVP_CIPHER *cipher = get_aes_cbc(key_len);
    if (!cipher) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1) {
        print_ssl_err("DecryptInit");
        goto err;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) {
        print_ssl_err("DecryptUpdate");
        goto err;
    }
    total = len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + total, &len) != 1) {
        print_ssl_err("DecryptFinal");
        goto err;
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *pt_len = total;
    return 0;

err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static const EVP_CIPHER *get_aes_gcm(int key_len)
{
    switch (key_len) {
    case 16: return EVP_aes_128_gcm();
    case 32: return EVP_aes_256_gcm();
    default: return NULL;
    }
}

int aes_gcm_encrypt(const uint8_t *key, int key_len,
                    const uint8_t *nonce,
                    const uint8_t *aad, int aad_len,
                    const uint8_t *plaintext, int pt_len,
                    uint8_t *ciphertext, int *ct_len,
                    uint8_t *icv)
{
    const EVP_CIPHER *cipher = get_aes_gcm(key_len);
    if (!cipher) {
        fprintf(stderr, "[AES] GCM: Invalid key length %d\n", key_len);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_SIZE, NULL) != 1) goto err;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto err;

    /* Set AAD */
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto err;
    }

    /* Encrypt */
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1) goto err;
        total = len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + total, &len) != 1) goto err;
    total += len;

    /* Get ICV (16 bytes) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_ICV_SIZE, icv) != 1) goto err;

    EVP_CIPHER_CTX_free(ctx);
    *ct_len = total;
    return 0;

err:
    print_ssl_err("AES-GCM encrypt");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int aes_gcm_decrypt(const uint8_t *key, int key_len,
                    const uint8_t *nonce,
                    const uint8_t *aad, int aad_len,
                    const uint8_t *ciphertext, int ct_len,
                    uint8_t *plaintext, int *pt_len,
                    const uint8_t *icv)
{
    const EVP_CIPHER *cipher = get_aes_gcm(key_len);
    if (!cipher) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, total = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) goto err;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_NONCE_SIZE, NULL) != 1) goto err;
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto err;

    /* Set AAD */
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len) != 1) goto err;
    }

    /* Decrypt */
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len) != 1) goto err;
        total = len;
    }

    /* Set expected ICV */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_ICV_SIZE,
                             (void *)icv) != 1) goto err;

    /* Verify and finalize */
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + total, &len);
    if (ret <= 0) {
        fprintf(stderr, "[AES] GCM authentication failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total += len;

    EVP_CIPHER_CTX_free(ctx);
    *pt_len = total;
    return 0;

err:
    print_ssl_err("AES-GCM decrypt");
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int random_bytes(uint8_t *buf, int len)
{
    if (RAND_bytes(buf, len) != 1) {
        print_ssl_err("RAND_bytes");
        return -1;
    }
    return 0;
}

int hmac_sha256_compute(const uint8_t *key, int key_len,
                        const uint8_t *data, int data_len,
                        uint8_t *icv, int trunc_len)
{
    uint8_t md[32];
    unsigned int mdlen = 0;

    if (!HMAC(EVP_sha256(), key, key_len, data, data_len, md, &mdlen)) {
        print_ssl_err("HMAC-SHA256");
        return -1;
    }

    if (trunc_len > (int)mdlen) trunc_len = (int)mdlen;
    memcpy(icv, md, trunc_len);
    return 0;
}

int hmac_sha256_verify(const uint8_t *key, int key_len,
                       const uint8_t *data, int data_len,
                       const uint8_t *icv, int icv_len)
{
    uint8_t md[32];
    unsigned int mdlen = 0;

    if (!HMAC(EVP_sha256(), key, key_len, data, data_len, md, &mdlen)) {
        return -1;
    }

    if (icv_len > (int)mdlen) icv_len = (int)mdlen;

    /* Constant-time comparison */
    int diff = 0;
    for (int i = 0; i < icv_len; i++) {
        diff |= (md[i] ^ icv[i]);
    }
    return (diff == 0) ? 0 : -1;
}
