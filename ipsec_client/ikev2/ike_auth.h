/**
 * ike_auth.h - IKE_AUTH Exchange (RFC 7296 Section 1.2)
 *
 * Handles messages 3 and 4 of IKEv2:
 *   - Message 3 (initiator → responder): SK{IDi, AUTH, SAi2, TSi, TSr}
 *   - Message 4 (responder → initiator): SK{IDr, AUTH, SAr2, TSi, TSr}
 */

#ifndef IKE_AUTH_H
#define IKE_AUTH_H

#include "ike_types.h"

/**
 * Send IKE_AUTH request (Message 3).
 *
 * Builds and encrypts IDi, AUTH, SAi2, TSi, TSr payloads,
 * sends the encrypted SK payload to the peer.
 *
 * @param ctx  IKE SA context (must have completed IKE_SA_INIT)
 * @return     0 on success, -1 on failure
 */
int ike_auth_send(ike_sa_ctx_t *ctx);

/**
 * Receive and process IKE_AUTH response (Message 4).
 *
 * Decrypts SK payload, verifies IDr and AUTH,
 * extracts ESP SA parameters (SPI, algorithms),
 * derives Child SA keys.
 *
 * @param ctx  IKE SA context
 * @return     0 on success, -1 on failure
 */
int ike_auth_recv(ike_sa_ctx_t *ctx);

#endif /* IKE_AUTH_H */
