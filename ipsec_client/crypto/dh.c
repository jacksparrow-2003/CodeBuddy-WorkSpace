/**
 * dh.c - Diffie-Hellman Key Exchange Implementation
 *
 * Supports:
 *   - Group 14: 2048-bit MODP (RFC 3526)
 *   - Group 19: 256-bit ECP P-256 (RFC 5903)
 *
 * Uses OpenSSL for cryptographic operations.
 */

#include "dh.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

/* Group 14 (2048-bit MODP) prime - RFC 3526 */
static const char *MODP_2048_P =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

struct dh_ctx {
    int group;
    /* Group 14 */
    DH  *dh14;
    /* Group 19 */
    EVP_PKEY *ec_key;
};

static void print_openssl_error(const char *msg)
{
    fprintf(stderr, "[DH] %s: ", msg);
    ERR_print_errors_fp(stderr);
}

dh_ctx_t *dh_create(int group)
{
    dh_ctx_t *ctx = calloc(1, sizeof(dh_ctx_t));
    if (!ctx) return NULL;
    ctx->group = group;

    if (group == DH_GROUP_14) {
        ctx->dh14 = DH_new();
        if (!ctx->dh14) goto err;

        BIGNUM *p = NULL, *g = NULL;
        BN_hex2bn(&p, MODP_2048_P);
        g = BN_new();
        BN_set_word(g, 2);

        if (DH_set0_pqg(ctx->dh14, p, NULL, g) != 1) {
            BN_free(p); BN_free(g);
            print_openssl_error("DH_set0_pqg");
            goto err;
        }

        if (DH_generate_key(ctx->dh14) != 1) {
            print_openssl_error("DH_generate_key");
            goto err;
        }

    } else if (group == DH_GROUP_19) {
        EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        if (!pctx) goto err;

        if (EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,
                NID_X9_62_prime256v1) <= 0 ||
            EVP_PKEY_keygen(pctx, &ctx->ec_key) <= 0) {
            print_openssl_error("EC keygen");
            EVP_PKEY_CTX_free(pctx);
            goto err;
        }
        EVP_PKEY_CTX_free(pctx);

    } else {
        fprintf(stderr, "[DH] Unsupported group %d\n", group);
        goto err;
    }

    return ctx;

err:
    dh_free(ctx);
    return NULL;
}

int dh_get_public_key(dh_ctx_t *ctx, uint8_t *pub_out, int *pub_len)
{
    if (!ctx || !pub_out || !pub_len) return -1;

    if (ctx->group == DH_GROUP_14) {
        const BIGNUM *pub_key = NULL;
        DH_get0_key(ctx->dh14, &pub_key, NULL);
        if (!pub_key) return -1;

        int key_size = 256; /* 2048-bit = 256 bytes */
        if (*pub_len < key_size) return -1;

        /* Pad to exactly 256 bytes (big-endian, zero-padded) */
        memset(pub_out, 0, key_size);
        int bn_len = BN_num_bytes(pub_key);
        int offset = key_size - bn_len;
        BN_bn2bin(pub_key, pub_out + offset);
        *pub_len = key_size;
        return 0;

    } else if (ctx->group == DH_GROUP_19) {
        /* For ECP: encode as uncompressed point: 04 || x(32) || y(32) = 65 bytes */
        if (*pub_len < 65) return -1;

        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(ctx->ec_key);
        if (!ec) return -1;

        const EC_POINT *point = EC_KEY_get0_public_key(ec);
        const EC_GROUP *grp   = EC_KEY_get0_group(ec);

        int len = EC_POINT_point2oct(grp, point,
                      POINT_CONVERSION_UNCOMPRESSED,
                      pub_out, *pub_len, NULL);
        if (len <= 0) {
            print_openssl_error("EC_POINT_point2oct");
            return -1;
        }
        *pub_len = len;
        return 0;
    }

    return -1;
}

int dh_compute_shared(dh_ctx_t *ctx,
                      const uint8_t *peer_pub, int peer_len,
                      uint8_t *secret, int *sec_len)
{
    if (!ctx || !peer_pub || !secret || !sec_len) return -1;

    if (ctx->group == DH_GROUP_14) {
        BIGNUM *peer_bn = BN_bin2bn(peer_pub, peer_len, NULL);
        if (!peer_bn) return -1;

        int expected = DH_size(ctx->dh14);  /* 256 bytes */
        if (*sec_len < expected) {
            BN_free(peer_bn);
            return -1;
        }

        memset(secret, 0, expected);
        int ret = DH_compute_key(secret, peer_bn, ctx->dh14);
        BN_free(peer_bn);

        if (ret <= 0) {
            print_openssl_error("DH_compute_key");
            return -1;
        }

        /* DH_compute_key may return fewer bytes; right-align to expected size */
        if (ret < expected) {
            memmove(secret + (expected - ret), secret, ret);
            memset(secret, 0, expected - ret);
        }
        *sec_len = expected;
        return 0;

    } else if (ctx->group == DH_GROUP_19) {
        /* peer_pub must be uncompressed point: 04 || x || y (65 bytes) */
        if (peer_len != 65 || peer_pub[0] != 0x04) {
            fprintf(stderr, "[DH] ECP peer key must be uncompressed (65 bytes, prefix 04)\n");
            return -1;
        }

        EC_KEY *ec = EVP_PKEY_get0_EC_KEY(ctx->ec_key);
        const EC_GROUP *grp = EC_KEY_get0_group(ec);

        EC_POINT *peer_point = EC_POINT_new(grp);
        if (!peer_point) return -1;

        if (EC_POINT_oct2point(grp, peer_point, peer_pub, peer_len, NULL) != 1) {
            print_openssl_error("EC_POINT_oct2point");
            EC_POINT_free(peer_point);
            return -1;
        }

        /* Create peer EVP_PKEY */
        EC_KEY *peer_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!peer_ec || EC_KEY_set_public_key(peer_ec, peer_point) != 1) {
            EC_POINT_free(peer_point);
            if (peer_ec) EC_KEY_free(peer_ec);
            return -1;
        }
        EC_POINT_free(peer_point);

        EVP_PKEY *peer_pkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(peer_pkey, peer_ec);

        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(ctx->ec_key, NULL);
        if (!dctx) { EVP_PKEY_free(peer_pkey); return -1; }

        size_t slen = (size_t)*sec_len;
        if (EVP_PKEY_derive_init(dctx) <= 0 ||
            EVP_PKEY_derive_set_peer(dctx, peer_pkey) <= 0 ||
            EVP_PKEY_derive(dctx, secret, &slen) <= 0) {
            print_openssl_error("EVP_PKEY_derive");
            EVP_PKEY_CTX_free(dctx);
            EVP_PKEY_free(peer_pkey);
            return -1;
        }

        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_pkey);
        *sec_len = (int)slen;
        return 0;
    }

    return -1;
}

void dh_free(dh_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->dh14)   DH_free(ctx->dh14);
    if (ctx->ec_key) EVP_PKEY_free(ctx->ec_key);
    free(ctx);
}

int dh_pub_key_size(int group)
{
    switch (group) {
    case DH_GROUP_14: return 256;  /* 2048-bit */
    case DH_GROUP_19: return 65;   /* Uncompressed ECP P-256 */
    default:          return -1;
    }
}
