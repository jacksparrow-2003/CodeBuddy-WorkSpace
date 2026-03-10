/**
 * ike_sa_init.h - IKE_SA_INIT Exchange (RFC 7296 Section 1.2)
 *
 * Handles the first two messages of IKEv2:
 *   - Message 1 (initiator → responder): SA, KE, Ni
 *   - Message 2 (responder → initiator): SA, KE, Nr [, CERTREQ]
 */

#ifndef IKE_SA_INIT_H
#define IKE_SA_INIT_H

#include "ike_types.h"

/**
 * Send IKE_SA_INIT request (Message 1).
 *
 * Generates DH keypair, nonce, builds SA/KE/Ni payloads, and sends
 * the message via the context's UDP socket.
 *
 * @param ctx  IKE SA context (configured with local/remote IPs, algorithms, PSK)
 * @return     0 on success, -1 on failure
 */
int ike_sa_init_send(ike_sa_ctx_t *ctx);

/**
 * Receive and process IKE_SA_INIT response (Message 2).
 *
 * Parses SA, KE, Nr payloads, computes DH shared secret,
 * derives IKE SA keys.
 *
 * @param ctx  IKE SA context
 * @return     0 on success, -1 on failure
 */
int ike_sa_init_recv(ike_sa_ctx_t *ctx);

#endif /* IKE_SA_INIT_H */
