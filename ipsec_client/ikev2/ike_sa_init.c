/**
 * ike_sa_init.c - IKE_SA_INIT Exchange Implementation
 */

#include "ike_sa_init.h"
#include "ike_message.h"
#include "ike_crypto.h"
#include "../crypto/dh.h"
#include "../crypto/aes_utils.h"
#include "../config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>

/* ============================================================
 * Send IKE_SA_INIT Request (Message 1)
 * ============================================================ */

int ike_sa_init_send(ike_sa_ctx_t *ctx)
{
    printf("[IKE] Sending IKE_SA_INIT request to %s:%d\n",
           ctx->remote_ip, IKE_PORT);

    /* Step 1: Generate random SPIi */
    if (random_bytes(ctx->spi_i, 8) != 0) {
        fprintf(stderr, "[IKE] Failed to generate SPIi\n");
        return -1;
    }
    memset(ctx->spi_r, 0, 8);  /* Responder SPI = 0 for first message */

    /* Step 2: Generate Nonce */
    ctx->nonce_i_len = 32;
    if (random_bytes(ctx->nonce_i, ctx->nonce_i_len) != 0) {
        fprintf(stderr, "[IKE] Failed to generate nonce\n");
        return -1;
    }

    /* Step 3: Generate DH key pair */
    dh_ctx_t *dh = dh_create(ctx->ike_alg.dh_group);
    if (!dh) {
        fprintf(stderr, "[IKE] DH context creation failed\n");
        return -1;
    }
    ctx->dh_ctx = dh;

    int pub_size = dh_pub_key_size(ctx->ike_alg.dh_group);
    ctx->dh_pub = malloc(pub_size);
    if (!ctx->dh_pub) { dh_free(dh); return -1; }

    ctx->dh_pub_len = pub_size;
    if (dh_get_public_key(dh, ctx->dh_pub, &ctx->dh_pub_len) != 0) {
        fprintf(stderr, "[IKE] DH public key retrieval failed\n");
        return -1;
    }

    /* Step 4: Build message */
    static uint8_t msg_buf[IKE_MAX_MSG_SIZE];
    ike_msg_builder_t builder;

    ike_msg_init(&builder, msg_buf, sizeof(msg_buf),
                 IKE_EXCHANGE_SA_INIT,
                 IKE_FLAG_INITIATOR,
                 0,  /* Message ID = 0 */
                 ctx->spi_i, ctx->spi_r);

    /* SA payload */
    uint8_t sa_buf[512];
    int sa_len = build_sa_payload_ike(sa_buf, sizeof(sa_buf),
                                       ctx->ike_alg.dh_group,
                                       ctx->ike_alg.encr_id,
                                       ctx->ike_alg.encr_key_bits,
                                       ctx->ike_alg.prf_id,
                                       ctx->ike_alg.integ_id);
    if (sa_len < 0 || ike_msg_add_payload(&builder, PAYLOAD_SA, sa_buf, sa_len) != 0) {
        fprintf(stderr, "[IKE] Failed to add SA payload\n");
        return -1;
    }

    /* KE payload */
    uint8_t ke_buf[512];
    int ke_len = build_ke_payload(ke_buf, sizeof(ke_buf),
                                   ctx->dh_pub, ctx->dh_pub_len,
                                   ctx->ike_alg.dh_group);
    if (ke_len < 0 || ike_msg_add_payload(&builder, PAYLOAD_KE, ke_buf, ke_len) != 0) {
        fprintf(stderr, "[IKE] Failed to add KE payload\n");
        return -1;
    }

    /* Nonce payload */
    if (ike_msg_add_payload(&builder, PAYLOAD_NONCE,
                             ctx->nonce_i, ctx->nonce_i_len) != 0) {
        fprintf(stderr, "[IKE] Failed to add Nonce payload\n");
        return -1;
    }

    int msg_len = ike_msg_finalize(&builder);
    if (msg_len <= 0) return -1;

    /* Save raw message for AUTH computation */
    ctx->msg1_raw = malloc(msg_len);
    if (!ctx->msg1_raw) return -1;
    memcpy(ctx->msg1_raw, msg_buf, msg_len);
    ctx->msg1_raw_len = msg_len;

    if (DEBUG_IKE) {
        printf("[IKE] SA_INIT request: %d bytes\n", msg_len);
        hex_dump("SA_INIT request", msg_buf, msg_len);
    }

    /* Step 5: Send via UDP */
    struct sockaddr_in dst = {
        .sin_family = AF_INET,
        .sin_port   = htons(IKE_PORT),
    };
    inet_pton(AF_INET, ctx->remote_ip, &dst.sin_addr);

    ssize_t sent = sendto(ctx->udp_sock, msg_buf, msg_len, 0,
                          (struct sockaddr *)&dst, sizeof(dst));
    if (sent < 0 || sent != msg_len) {
        perror("[IKE] sendto failed");
        return -1;
    }

    ctx->state = IKE_STATE_SA_INIT_SENT;
    printf("[IKE] SA_INIT request sent (%zd bytes)\n", sent);
    return 0;
}

/* ============================================================
 * Receive IKE_SA_INIT Response (Message 2)
 * ============================================================ */

int ike_sa_init_recv(ike_sa_ctx_t *ctx)
{
    printf("[IKE] Waiting for IKE_SA_INIT response...\n");

    static uint8_t recv_buf[IKE_MAX_MSG_SIZE];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

    /* Set receive timeout */
    struct timeval tv = { .tv_sec = IKE_RECV_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(ctx->udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    ssize_t recvd = recvfrom(ctx->udp_sock, recv_buf, sizeof(recv_buf), 0,
                              (struct sockaddr *)&src, &src_len);
    if (recvd < 0) {
        perror("[IKE] recvfrom failed");
        return -1;
    }

    printf("[IKE] Received %zd bytes from %s\n", recvd,
           inet_ntoa(src.sin_addr));

    if (DEBUG_IKE) {
        hex_dump("SA_INIT response", recv_buf, (int)recvd);
    }

    /* Parse the message */
    parsed_ike_msg_t msg;
    if (ike_msg_parse(recv_buf, (int)recvd, &msg) != 0) {
        fprintf(stderr, "[IKE] Failed to parse SA_INIT response\n");
        return -1;
    }

    /* Validate exchange type and flags */
    if (msg.hdr.exchange_type != IKE_EXCHANGE_SA_INIT) {
        fprintf(stderr, "[IKE] Unexpected exchange type: %d\n",
                msg.hdr.exchange_type);
        return -1;
    }

    /* Check for error notifications */
    int notif_len;
    const uint8_t *notif = ike_msg_find_payload(&msg, PAYLOAD_NOTIFY, &notif_len);
    if (notif && notif_len >= (int)sizeof(notify_data_t)) {
        const notify_data_t *n = (const notify_data_t *)notif;
        uint16_t ntype = ntohs(n->notify_type);
        if (ntype < 16384) {
            /* Error notification */
            fprintf(stderr, "[IKE] Received error notification: type=%d\n", ntype);
            return -1;
        }
    }

    /* Extract SPIr */
    memcpy(ctx->spi_r, msg.hdr.spi_r, 8);
    printf("[IKE] SPIr: ");
    for (int i = 0; i < 8; i++) printf("%02x", ctx->spi_r[i]);
    printf("\n");

    /* Parse SA payload - get negotiated algorithms */
    int sa_len;
    const uint8_t *sa_data = ike_msg_find_payload(&msg, PAYLOAD_SA, &sa_len);
    if (!sa_data) {
        fprintf(stderr, "[IKE] No SA payload in response\n");
        return -1;
    }

    if (parse_negotiated_algs(sa_data, sa_len, PROTO_IKE,
                               &ctx->ike_alg, NULL, NULL) != 0) {
        fprintf(stderr, "[IKE] Failed to parse negotiated algorithms\n");
        return -1;
    }

    printf("[IKE] Negotiated: ENCR=%d(%d bits), PRF=%d, INTEG=%d, DH=%d\n",
           ctx->ike_alg.encr_id, ctx->ike_alg.encr_key_bits,
           ctx->ike_alg.prf_id, ctx->ike_alg.integ_id, ctx->ike_alg.dh_group);

    /* Parse KE payload - get peer DH public key */
    int ke_len;
    const uint8_t *ke_data = ike_msg_find_payload(&msg, PAYLOAD_KE, &ke_len);
    if (!ke_data || ke_len < (int)sizeof(ke_data_t)) {
        fprintf(stderr, "[IKE] No KE payload in response\n");
        return -1;
    }

    /* ke_data points to ke_data_t header, peer public key follows */
    const uint8_t *peer_pub = ke_data + sizeof(ke_data_t);
    int peer_pub_len = ke_len - sizeof(ke_data_t);

    printf("[IKE] Peer DH public key: %d bytes\n", peer_pub_len);

    /* Compute DH shared secret */
    int secret_size = 512;  /* Enough for MODP-4096 */
    ctx->dh_secret = malloc(secret_size);
    if (!ctx->dh_secret) return -1;

    ctx->dh_secret_len = secret_size;
    if (dh_compute_shared((dh_ctx_t *)ctx->dh_ctx,
                           peer_pub, peer_pub_len,
                           ctx->dh_secret, &ctx->dh_secret_len) != 0) {
        fprintf(stderr, "[IKE] DH shared secret computation failed\n");
        return -1;
    }
    printf("[IKE] DH shared secret computed (%d bytes)\n", ctx->dh_secret_len);

    /* Parse Nonce payload - responder nonce */
    int nr_len;
    const uint8_t *nr_data = ike_msg_find_payload(&msg, PAYLOAD_NONCE, &nr_len);
    if (!nr_data) {
        fprintf(stderr, "[IKE] No Nonce payload in response\n");
        return -1;
    }

    ctx->nonce_r_len = nr_len < 32 ? nr_len : 32;
    memcpy(ctx->nonce_r, nr_data, ctx->nonce_r_len);
    printf("[IKE] Responder nonce: %d bytes\n", ctx->nonce_r_len);

    /* Save raw message 2 for AUTH computation */
    ctx->msg2_raw = malloc(recvd);
    if (!ctx->msg2_raw) return -1;
    memcpy(ctx->msg2_raw, recv_buf, recvd);
    ctx->msg2_raw_len = (int)recvd;

    /* Derive IKE SA keys */
    if (ike_derive_keys(ctx) != 0) {
        fprintf(stderr, "[IKE] Key derivation failed\n");
        return -1;
    }

    ctx->state = IKE_STATE_SA_INIT_DONE;
    printf("[IKE] SA_INIT completed successfully\n");
    return 0;
}
