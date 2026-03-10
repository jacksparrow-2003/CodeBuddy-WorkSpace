/**
 * dh.h - Diffie-Hellman Key Exchange (Group 14 MODP, Group 19 ECP)
 */

#ifndef DH_H
#define DH_H

#include <stdint.h>
#include "../ikev2/ike_types.h"

/* Opaque DH context */
typedef struct dh_ctx dh_ctx_t;

/**
 * Create a DH context and generate a key pair.
 * @param group  DH group number (DH_GROUP_14 or DH_GROUP_19)
 * @return       Allocated dh_ctx, or NULL on failure.
 */
dh_ctx_t *dh_create(int group);

/**
 * Get the public key value to send in KE payload.
 * @param ctx     DH context
 * @param pub_out Buffer to write public key (caller provides)
 * @param pub_len On input: buffer size. On output: actual key size.
 * @return        0 on success, -1 on failure
 */
int dh_get_public_key(dh_ctx_t *ctx, uint8_t *pub_out, int *pub_len);

/**
 * Compute the shared secret from the peer's public key.
 * @param ctx      DH context
 * @param peer_pub Peer's public key data
 * @param peer_len Peer's public key length
 * @param secret   Buffer for shared secret
 * @param sec_len  On input: buffer size. On output: actual secret size.
 * @return         0 on success, -1 on failure
 */
int dh_compute_shared(dh_ctx_t *ctx,
                      const uint8_t *peer_pub, int peer_len,
                      uint8_t *secret, int *sec_len);

/**
 * Free a DH context.
 */
void dh_free(dh_ctx_t *ctx);

/**
 * Get the public key size in bytes for a DH group.
 */
int dh_pub_key_size(int group);

#endif /* DH_H */
