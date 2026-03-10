/**
 * ike_crypto.c - IKEv2 Key Material Derivation and SK Payload Encryption
 *
 * Implements RFC 7296 Sections 2.13 (Key Material), 2.14 (Authentication),
 * and 3.6 (SK Payload).
 */

#include "ike_crypto.h"
#include "../crypto/prf.h"
#include "../crypto/aes_utils.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* "Key Pad for IKEv2" - exactly 17 ASCII bytes, no null terminator */
static const uint8_t IKE_KEYPAD[] = "Key Pad for IKEv2";
#define IKE_KEYPAD_LEN  17

/* ============================================================
 * Algorithm key length helpers
 * ============================================================ */

static int prf_output_len(uint16_t prf_id)
{
    switch (prf_id) {
    case PRF_HMAC_SHA2_256: return 32;
    case PRF_HMAC_SHA2_384: return 48;
    case PRF_HMAC_SHA2_512: return 64;
    case PRF_HMAC_SHA1:     return 20;
    default: return 32;  /* Default to SHA-256 */
    }
}

static int integ_key_len(uint16_t integ_id)
{
    switch (integ_id) {
    case AUTH_HMAC_SHA2_256_128: return 32;
    case AUTH_HMAC_SHA2_384_192: return 48;
    case AUTH_HMAC_SHA2_512_256: return 64;
    case AUTH_HMAC_SHA1_96:      return 20;
    default: return 32;
    }
}

static int encr_key_len_bytes(uint16_t encr_id, uint16_t key_bits)
{
    /* For AES-GCM: key + 4-byte salt */
    int base = key_bits / 8;
    if (encr_id == ENCR_AES_GCM_16) return base + 4;
    return base;
}

/* ============================================================
 * IKE SA Key Derivation
 * ============================================================ */

int ike_derive_keys(ike_sa_ctx_t *ctx)
{
    /* Step 1: SKEYSEED = prf(Ni | Nr, g^ir)
     *   KEY  = Ni | Nr
     *   DATA = g^ir (DH shared secret)
     */
    uint8_t nonces[64 + 32];
    int nonces_len = ctx->nonce_i_len + ctx->nonce_r_len;
    if (nonces_len > (int)sizeof(nonces)) return -1;

    memcpy(nonces, ctx->nonce_i, ctx->nonce_i_len);
    memcpy(nonces + ctx->nonce_i_len, ctx->nonce_r, ctx->nonce_r_len);

    uint8_t skeyseed[64];
    int skeyseed_len = 0;
    if (prf_hmac_sha256(nonces, nonces_len,
                        ctx->dh_secret, ctx->dh_secret_len,
                        skeyseed, &skeyseed_len) != 0) {
        fprintf(stderr, "[CRYPTO] SKEYSEED derivation failed\n");
        return -1;
    }

    if (getenv("IPSEC_DEBUG")) {
        printf("[CRYPTO] SKEYSEED: ");
        for (int i = 0; i < skeyseed_len; i++) printf("%02x", skeyseed[i]);
        printf("\n");
    }

    /* Step 2: PRF+ seed = Ni | Nr | SPIi | SPIr */
    int seed_len = ctx->nonce_i_len + ctx->nonce_r_len + 16;
    uint8_t *seed = malloc(seed_len);
    if (!seed) return -1;

    int off = 0;
    memcpy(seed + off, ctx->nonce_i, ctx->nonce_i_len); off += ctx->nonce_i_len;
    memcpy(seed + off, ctx->nonce_r, ctx->nonce_r_len); off += ctx->nonce_r_len;
    memcpy(seed + off, ctx->spi_i, 8);                  off += 8;
    memcpy(seed + off, ctx->spi_r, 8);                  off += 8;

    /* Step 3: Calculate required key material lengths */
    negotiated_alg_t *alg = &ctx->ike_alg;

    int prf_len   = prf_output_len(alg->prf_id);
    int integ_len = alg->is_aead ? 0 : integ_key_len(alg->integ_id);
    int encr_len  = encr_key_len_bytes(alg->encr_id, alg->encr_key_bits);

    ctx->sk_d_len  = prf_len;
    ctx->sk_ai_len = integ_len;
    ctx->sk_ar_len = integ_len;
    ctx->sk_ei_len = encr_len;
    ctx->sk_er_len = encr_len;
    ctx->sk_pi_len = prf_len;
    ctx->sk_pr_len = prf_len;

    int total = ctx->sk_d_len + ctx->sk_ai_len + ctx->sk_ar_len +
                ctx->sk_ei_len + ctx->sk_er_len + ctx->sk_pi_len + ctx->sk_pr_len;

    uint8_t *keymat = malloc(total);
    if (!keymat) { free(seed); return -1; }

    /* PRF+(SKEYSEED, seed) */
    if (prf_plus(skeyseed, skeyseed_len, seed, seed_len, keymat, total) != 0) {
        fprintf(stderr, "[CRYPTO] PRF+ for IKE keys failed\n");
        free(seed); free(keymat);
        return -1;
    }
    free(seed);

    /* Extract keys in order: SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr */
    int pos = 0;
    memcpy(ctx->sk_d,  keymat + pos, ctx->sk_d_len);  pos += ctx->sk_d_len;
    memcpy(ctx->sk_ai, keymat + pos, ctx->sk_ai_len); pos += ctx->sk_ai_len;
    memcpy(ctx->sk_ar, keymat + pos, ctx->sk_ar_len); pos += ctx->sk_ar_len;

    /* For AES-GCM: the last 4 bytes of SK_ei/SK_er are the salt */
    memcpy(ctx->sk_ei, keymat + pos, ctx->sk_ei_len);
    if (alg->is_aead) {
        memcpy(ctx->sk_ei_salt, ctx->sk_ei + (ctx->sk_ei_len - 4), 4);
    }
    pos += ctx->sk_ei_len;

    memcpy(ctx->sk_er, keymat + pos, ctx->sk_er_len);
    if (alg->is_aead) {
        memcpy(ctx->sk_er_salt, ctx->sk_er + (ctx->sk_er_len - 4), 4);
    }
    pos += ctx->sk_er_len;

    memcpy(ctx->sk_pi, keymat + pos, ctx->sk_pi_len); pos += ctx->sk_pi_len;
    memcpy(ctx->sk_pr, keymat + pos, ctx->sk_pr_len); pos += ctx->sk_pr_len;

    free(keymat);

    if (getenv("IPSEC_DEBUG")) {
        printf("[CRYPTO] SK_d  (%d): ", ctx->sk_d_len);
        for (int i = 0; i < ctx->sk_d_len; i++) printf("%02x", ctx->sk_d[i]);
        printf("\n[CRYPTO] SK_ei (%d): ", ctx->sk_ei_len);
        for (int i = 0; i < ctx->sk_ei_len; i++) printf("%02x", ctx->sk_ei[i]);
        printf("\n");
    }

    return 0;
}

int ike_derive_child_keys(ike_sa_ctx_t *ctx,
                          const uint8_t *nonce_i, int ni_len,
                          const uint8_t *nonce_r, int nr_len)
{
    /* KEYMAT = prf+(SK_d, Ni' | Nr') */
    int seed_len = ni_len + nr_len;
    uint8_t *seed = malloc(seed_len);
    if (!seed) return -1;
    memcpy(seed, nonce_i, ni_len);
    memcpy(seed + ni_len, nonce_r, nr_len);

    negotiated_alg_t *esp = &ctx->esp_alg;

    int integ_len = esp->is_aead ? 0 : integ_key_len(esp->integ_id);
    int encr_len  = encr_key_len_bytes(esp->encr_id, esp->encr_key_bits);

    ctx->child_sk_ei_len = encr_len;
    ctx->child_sk_ai_len = integ_len;
    ctx->child_sk_er_len = encr_len;
    ctx->child_sk_ar_len = integ_len;

    int total = encr_len + integ_len + encr_len + integ_len;

    uint8_t *keymat = malloc(total);
    if (!keymat) { free(seed); return -1; }

    if (prf_plus(ctx->sk_d, ctx->sk_d_len, seed, seed_len, keymat, total) != 0) {
        fprintf(stderr, "[CRYPTO] PRF+ for Child SA keys failed\n");
        free(seed); free(keymat);
        return -1;
    }
    free(seed);

    /* Order: SK_ei | SK_ai | SK_er | SK_ar (initiator first) */
    int pos = 0;
    memcpy(ctx->child_sk_ei, keymat + pos, encr_len);
    if (esp->is_aead)
        memcpy(ctx->child_sk_ei_salt, ctx->child_sk_ei + (encr_len - 4), 4);
    pos += encr_len;

    memcpy(ctx->child_sk_ai, keymat + pos, integ_len);
    pos += integ_len;

    memcpy(ctx->child_sk_er, keymat + pos, encr_len);
    if (esp->is_aead)
        memcpy(ctx->child_sk_er_salt, ctx->child_sk_er + (encr_len - 4), 4);
    pos += encr_len;

    memcpy(ctx->child_sk_ar, keymat + pos, integ_len);

    free(keymat);

    if (getenv("IPSEC_DEBUG")) {
        printf("[CRYPTO] Child SK_ei (%d): ", ctx->child_sk_ei_len);
        for (int i = 0; i < ctx->child_sk_ei_len; i++) printf("%02x", ctx->child_sk_ei[i]);
        printf("\n");
    }
    return 0;
}

/* ============================================================
 * PSK Authentication
 * ============================================================ */

int ike_compute_auth_initiator(ike_sa_ctx_t *ctx,
                               const uint8_t *idi_data, int idi_len,
                               uint8_t *auth_out, int *auth_len)
{
    /*
     * AUTH_i = prf(prf(PSK, "Key Pad for IKEv2"),
     *              msg1_octets | Nr | prf(SK_pi, IDi_payload_data))
     */

    /* Step 1: prf(PSK, "Key Pad for IKEv2") -> psk_key */
    uint8_t psk_key[32];
    int psk_key_len = 0;
    if (prf_hmac_sha256((const uint8_t *)ctx->psk, ctx->psk_len,
                        IKE_KEYPAD, IKE_KEYPAD_LEN,
                        psk_key, &psk_key_len) != 0) return -1;

    /* Step 2: prf(SK_pi, IDi_payload_data) -> id_prf */
    uint8_t id_prf[32];
    int id_prf_len = 0;
    if (prf_hmac_sha256(ctx->sk_pi, ctx->sk_pi_len,
                        idi_data, idi_len,
                        id_prf, &id_prf_len) != 0) return -1;

    /* Step 3: msg1_octets | Nr | id_prf */
    int input_len = ctx->msg1_raw_len + ctx->nonce_r_len + id_prf_len;
    uint8_t *input = malloc(input_len);
    if (!input) return -1;

    int off = 0;
    memcpy(input + off, ctx->msg1_raw, ctx->msg1_raw_len); off += ctx->msg1_raw_len;
    memcpy(input + off, ctx->nonce_r, ctx->nonce_r_len);   off += ctx->nonce_r_len;
    memcpy(input + off, id_prf, id_prf_len);               off += id_prf_len;

    /* Step 4: AUTH = prf(psk_key, input) */
    int alen = 0;
    int ret = prf_hmac_sha256(psk_key, psk_key_len, input, input_len,
                               auth_out, &alen);
    free(input);
    if (ret != 0) return -1;

    *auth_len = alen;
    return 0;
}

int ike_verify_auth_responder(ike_sa_ctx_t *ctx,
                              const uint8_t *idr_data, int idr_len,
                              const uint8_t *auth_in, int auth_in_len)
{
    /*
     * Expected AUTH_r = prf(prf(PSK, "Key Pad for IKEv2"),
     *                        msg2_octets | Ni | prf(SK_pr, IDr_payload_data))
     */

    uint8_t psk_key[32];
    int psk_key_len = 0;
    if (prf_hmac_sha256((const uint8_t *)ctx->psk, ctx->psk_len,
                        IKE_KEYPAD, IKE_KEYPAD_LEN,
                        psk_key, &psk_key_len) != 0) return -1;

    uint8_t id_prf[32];
    int id_prf_len = 0;
    if (prf_hmac_sha256(ctx->sk_pr, ctx->sk_pr_len,
                        idr_data, idr_len,
                        id_prf, &id_prf_len) != 0) return -1;

    int input_len = ctx->msg2_raw_len + ctx->nonce_i_len + id_prf_len;
    uint8_t *input = malloc(input_len);
    if (!input) return -1;

    int off = 0;
    memcpy(input + off, ctx->msg2_raw, ctx->msg2_raw_len); off += ctx->msg2_raw_len;
    memcpy(input + off, ctx->nonce_i, ctx->nonce_i_len);   off += ctx->nonce_i_len;
    memcpy(input + off, id_prf, id_prf_len);               off += id_prf_len;

    uint8_t expected[32];
    int expected_len = 0;
    int ret = prf_hmac_sha256(psk_key, psk_key_len, input, input_len,
                               expected, &expected_len);
    free(input);
    if (ret != 0) return -1;

    /* Constant-time comparison */
    if (auth_in_len != expected_len) {
        fprintf(stderr, "[CRYPTO] AUTH length mismatch: got %d, expected %d\n",
                auth_in_len, expected_len);
        return -1;
    }
    int diff = 0;
    for (int i = 0; i < expected_len; i++)
        diff |= (auth_in[i] ^ expected[i]);

    if (diff != 0) {
        fprintf(stderr, "[CRYPTO] PSK AUTH verification failed\n");
        return -1;
    }
    return 0;
}

/* ============================================================
 * SK Payload Encryption / Decryption
 * ============================================================ */

int ike_sk_encrypt(const uint8_t *key_e, int key_e_len,
                   const uint8_t *key_i, int key_i_len,
                   const uint8_t *salt, int is_aead,
                   const uint8_t *plaintext, int pt_len,
                   uint8_t *out, int *out_len,
                   const uint8_t *ike_hdr, int ike_hdr_len)
{
    if (is_aead) {
        /* AES-GCM:
         * SK payload data = IV(8) | Ciphertext | ICV(16)
         * Nonce = salt(4) | IV(8)
         * AAD = IKE header (28 bytes)
         */
        uint8_t iv[AES_GCM_IV_SIZE];
        if (random_bytes(iv, AES_GCM_IV_SIZE) != 0) return -1;

        uint8_t nonce[AES_GCM_NONCE_SIZE];
        memcpy(nonce, salt, AES_GCM_SALT_SIZE);
        memcpy(nonce + AES_GCM_SALT_SIZE, iv, AES_GCM_IV_SIZE);

        /* AAD = IKE header (with next_payload = SK, and correct length) */
        int required = AES_GCM_IV_SIZE + pt_len + AES_GCM_ICV_SIZE;
        if (*out_len < required) return -1;

        /* IV in output */
        memcpy(out, iv, AES_GCM_IV_SIZE);

        int actual_key_len = key_e_len - AES_GCM_SALT_SIZE; /* Remove salt */
        int ct_len = 0;
        uint8_t icv[AES_GCM_ICV_SIZE];

        if (aes_gcm_encrypt(key_e, actual_key_len, nonce,
                            ike_hdr, ike_hdr_len,
                            plaintext, pt_len,
                            out + AES_GCM_IV_SIZE, &ct_len, icv) != 0) {
            return -1;
        }

        memcpy(out + AES_GCM_IV_SIZE + ct_len, icv, AES_GCM_ICV_SIZE);
        *out_len = AES_GCM_IV_SIZE + ct_len + AES_GCM_ICV_SIZE;

    } else {
        /* AES-CBC + HMAC-SHA256:
         * SK payload data = IV(16) | Ciphertext | ICV(16)
         * Add padding so (plaintext + padding + 2) is multiple of 16
         */
        uint8_t iv[AES_CBC_IV_SIZE];
        if (random_bytes(iv, AES_CBC_IV_SIZE) != 0) return -1;

        /* Calculate padding */
        int pad_len = (AES_BLOCK_SIZE - (pt_len + 2) % AES_BLOCK_SIZE) % AES_BLOCK_SIZE;

        /* Build padded plaintext: payload | padding | pad_len | next_payload=0 */
        /* Note: for SK payload, next_payload inside encryption = first inner payload type */
        /* We prepend padding after the actual data */
        int padded_len = pt_len + pad_len + 2;
        uint8_t *padded = malloc(padded_len);
        if (!padded) return -1;

        memcpy(padded, plaintext, pt_len);
        for (int i = 0; i < pad_len; i++) padded[pt_len + i] = (uint8_t)(i + 1);
        padded[pt_len + pad_len]     = (uint8_t)pad_len;
        padded[pt_len + pad_len + 1] = 0;  /* Next header = 0 (will be patched by caller) */

        int required = AES_CBC_IV_SIZE + padded_len + HMAC_SHA256_TRUNC_SIZE;
        if (*out_len < required) { free(padded); return -1; }

        memcpy(out, iv, AES_CBC_IV_SIZE);

        int ct_len = 0;
        if (aes_cbc_encrypt(key_e, key_e_len, iv,
                            padded, padded_len,
                            out + AES_CBC_IV_SIZE, &ct_len) != 0) {
            free(padded);
            return -1;
        }
        free(padded);

        /* HMAC over IKE header | SK generic payload header | IV | ciphertext */
        /* In practice: HMAC is computed over the entire message from the IKE header
         * up to and including the ciphertext, but BEFORE the ICV field.
         * Here we pass ike_hdr as the initial bytes to authenticate, and the
         * IV+ciphertext is the SK payload data. The caller must handle the full
         * message authentication by computing HMAC over:
         * (IKE header + SK payload header (with ICV placeholder=0) + IV + ciphertext)
         * For simplicity we include ike_hdr as AAD and authenticate IV+ciphertext.
         */

        /* Build auth buffer: ike_hdr | IV | ciphertext */
        int auth_buf_len = ike_hdr_len + AES_CBC_IV_SIZE + ct_len;
        uint8_t *auth_buf = malloc(auth_buf_len);
        if (!auth_buf) return -1;
        memcpy(auth_buf, ike_hdr, ike_hdr_len);
        memcpy(auth_buf + ike_hdr_len, out, AES_CBC_IV_SIZE + ct_len);

        if (hmac_sha256_compute(key_i, key_i_len,
                                auth_buf, auth_buf_len,
                                out + AES_CBC_IV_SIZE + ct_len,
                                HMAC_SHA256_TRUNC_SIZE) != 0) {
            free(auth_buf);
            return -1;
        }
        free(auth_buf);

        *out_len = AES_CBC_IV_SIZE + ct_len + HMAC_SHA256_TRUNC_SIZE;
    }
    return 0;
}

int ike_sk_decrypt(const uint8_t *key_e, int key_e_len,
                   const uint8_t *key_i, int key_i_len,
                   const uint8_t *salt, int is_aead,
                   const uint8_t *sk_data, int sk_len,
                   uint8_t *out, int *out_len,
                   const uint8_t *ike_hdr, int ike_hdr_len)
{
    if (is_aead) {
        if (sk_len < AES_GCM_IV_SIZE + AES_GCM_ICV_SIZE) return -1;

        const uint8_t *iv  = sk_data;
        const uint8_t *ct  = sk_data + AES_GCM_IV_SIZE;
        int ct_len         = sk_len - AES_GCM_IV_SIZE - AES_GCM_ICV_SIZE;
        const uint8_t *icv = sk_data + sk_len - AES_GCM_ICV_SIZE;

        uint8_t nonce[AES_GCM_NONCE_SIZE];
        memcpy(nonce, salt, AES_GCM_SALT_SIZE);
        memcpy(nonce + AES_GCM_SALT_SIZE, iv, AES_GCM_IV_SIZE);

        int actual_key_len = key_e_len - AES_GCM_SALT_SIZE;

        return aes_gcm_decrypt(key_e, actual_key_len, nonce,
                               ike_hdr, ike_hdr_len,
                               ct, ct_len, out, out_len, icv);

    } else {
        if (sk_len < AES_CBC_IV_SIZE + HMAC_SHA256_TRUNC_SIZE) return -1;

        /* Verify HMAC first */
        int mac_offset = sk_len - HMAC_SHA256_TRUNC_SIZE;
        const uint8_t *icv = sk_data + mac_offset;

        /* Auth: ike_hdr | IV | ciphertext */
        int auth_len = ike_hdr_len + mac_offset;
        uint8_t *auth_buf = malloc(auth_len);
        if (!auth_buf) return -1;
        memcpy(auth_buf, ike_hdr, ike_hdr_len);
        memcpy(auth_buf + ike_hdr_len, sk_data, mac_offset);

        int ret = hmac_sha256_verify(key_i, key_i_len, auth_buf, auth_len,
                                     icv, HMAC_SHA256_TRUNC_SIZE);
        free(auth_buf);
        if (ret != 0) {
            fprintf(stderr, "[CRYPTO] SK payload HMAC verification failed\n");
            return -1;
        }

        /* Decrypt */
        const uint8_t *iv = sk_data;
        const uint8_t *ct = sk_data + AES_CBC_IV_SIZE;
        int ct_len = mac_offset - AES_CBC_IV_SIZE;

        if (aes_cbc_decrypt(key_e, key_e_len, iv, ct, ct_len, out, out_len) != 0)
            return -1;

        /* Remove padding: last two bytes before ICV in plaintext are pad_len, next_hdr */
        if (*out_len < 2) return -1;
        int pad_len = out[*out_len - 2];
        *out_len -= (pad_len + 2);
        if (*out_len < 0) return -1;

        return 0;
    }
}
