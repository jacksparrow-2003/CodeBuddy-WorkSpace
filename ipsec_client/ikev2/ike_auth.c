/**
 * ike_auth.c - IKE_AUTH Exchange Implementation
 *
 * Handles PSK authentication and Child SA establishment.
 */

#include "ike_auth.h"
#include "ike_message.h"
#include "ike_crypto.h"
#include "../crypto/aes_utils.h"
#include "../config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

/* ============================================================
 * Send IKE_AUTH Request (Message 3)
 * ============================================================ */

int ike_auth_send(ike_sa_ctx_t *ctx)
{
    printf("[IKE] Sending IKE_AUTH request\n");

    /* Generate random Child SA SPI (our inbound SPI) */
    if (random_bytes((uint8_t *)&ctx->child_spi_i, 4) != 0) return -1;
    printf("[IKE] Child SA SPIi (local): 0x%08x\n", ntohl(ctx->child_spi_i));

    /* =========================================================
     * Build the inner plaintext payload buffer
     * (will be encrypted as SK payload)
     * ========================================================= */
    static uint8_t inner_buf[IKE_MAX_MSG_SIZE];
    ike_msg_builder_t inner;

    /* We use ike_msg_builder to chain inner payloads.
     * The inner builder starts with no IKE header (offset 0). */
    inner.buf = inner_buf;
    inner.capacity = sizeof(inner_buf);
    inner.len = 0;
    inner.last_next_payload_offset = -1;

    /* Helper: track the starting next-payload type for the SK payload */
    uint8_t sk_first_payload = PAYLOAD_IDi;

    /* == IDi == */
    uint8_t id_buf[256];
    int id_data_len = strlen(ctx->local_id);
    int id_len = build_id_payload(id_buf, sizeof(id_buf),
                                   (uint8_t)ctx->local_id_type,
                                   (const uint8_t *)ctx->local_id,
                                   id_data_len);
    if (id_len < 0) return -1;

    /* First inner payload: next_payload will be chained by the builder */
    /* Manually build inner payload chain */
    /* We'll store raw payloads sequentially, chain them later */
    typedef struct { uint8_t type; uint8_t *data; int len; } inner_pl_t;
    inner_pl_t pls[8];
    int npl = 0;

    pls[npl].type = PAYLOAD_IDi;
    pls[npl].data = malloc(id_len);
    memcpy(pls[npl].data, id_buf, id_len);
    pls[npl].len = id_len;
    npl++;

    /* == AUTH == (must compute after IDi is ready) */
    /* IDi payload data starts from id_type field (4 bytes before actual ID) */
    uint8_t auth_val[64];
    int auth_val_len = 0;
    if (ike_compute_auth_initiator(ctx, id_buf, id_len,
                                   auth_val, &auth_val_len) != 0) {
        fprintf(stderr, "[IKE] AUTH computation failed\n");
        return -1;
    }
    printf("[IKE] AUTH computed (%d bytes)\n", auth_val_len);

    uint8_t auth_pl_buf[64];
    int auth_pl_len = build_auth_payload(auth_pl_buf, sizeof(auth_pl_buf),
                                          auth_val, auth_val_len);
    if (auth_pl_len < 0) return -1;

    pls[npl].type = PAYLOAD_AUTH;
    pls[npl].data = malloc(auth_pl_len);
    memcpy(pls[npl].data, auth_pl_buf, auth_pl_len);
    pls[npl].len = auth_pl_len;
    npl++;

    /* == SAi2 (Child SA ESP proposal) == */
    /* Use a fresh nonce for child SA init - not strictly required here since
     * the nonces in IKE_AUTH come from IKE_SA_INIT. Child SA uses those nonces. */
    uint8_t sa2_buf[256];
    int sa2_len = build_sa_payload_esp(sa2_buf, sizeof(sa2_buf),
                                        ctx->child_spi_i,
                                        ctx->esp_alg.encr_id,
                                        ctx->esp_alg.encr_key_bits,
                                        ctx->esp_alg.integ_id);
    if (sa2_len < 0) return -1;

    pls[npl].type = PAYLOAD_SA;
    pls[npl].data = malloc(sa2_len);
    memcpy(pls[npl].data, sa2_buf, sa2_len);
    pls[npl].len = sa2_len;
    npl++;

    /* == TSi == (wildcard: 0.0.0.0 - 255.255.255.255) */
    uint8_t tsi_buf[64];
    int tsi_len = build_ts_payload(tsi_buf, sizeof(tsi_buf),
                                   "0.0.0.0", "255.255.255.255");
    if (tsi_len < 0) return -1;

    pls[npl].type = PAYLOAD_TSi;
    pls[npl].data = malloc(tsi_len);
    memcpy(pls[npl].data, tsi_buf, tsi_len);
    pls[npl].len = tsi_len;
    npl++;

    /* == TSr == */
    uint8_t tsr_buf[64];
    int tsr_len = build_ts_payload(tsr_buf, sizeof(tsr_buf),
                                   "0.0.0.0", "255.255.255.255");
    if (tsr_len < 0) return -1;

    pls[npl].type = PAYLOAD_TSr;
    pls[npl].data = malloc(tsr_len);
    memcpy(pls[npl].data, tsr_buf, tsr_len);
    pls[npl].len = tsr_len;
    npl++;

    /* Build inner plaintext: chain payloads with generic headers */
    static uint8_t plaintext[IKE_MAX_MSG_SIZE];
    int pt_len = 0;

    for (int i = 0; i < npl; i++) {
        payload_header_t ph;
        ph.next_payload = (i + 1 < npl) ? pls[i + 1].type : PAYLOAD_NONE;
        ph.flags = 0;
        ph.length = htons((uint16_t)(sizeof(payload_header_t) + pls[i].len));

        memcpy(plaintext + pt_len, &ph, sizeof(ph));
        pt_len += sizeof(ph);
        memcpy(plaintext + pt_len, pls[i].data, pls[i].len);
        pt_len += pls[i].len;
    }

    /* Free temporary payload buffers */
    for (int i = 0; i < npl; i++) free(pls[i].data);

    /* =========================================================
     * Encrypt inner payloads as SK payload
     * ========================================================= */

    /* Build the outer IKE message first (without SK data) to get IKE header */
    static uint8_t msg_buf[IKE_MAX_MSG_SIZE * 2];
    ike_msg_builder_t outer;
    ctx->msg_id = 1;

    ike_msg_init(&outer, msg_buf, sizeof(msg_buf),
                 IKE_EXCHANGE_AUTH,
                 IKE_FLAG_INITIATOR,
                 ctx->msg_id,
                 ctx->spi_i, ctx->spi_r);

    /* Encrypt the plaintext */
    static uint8_t sk_data[IKE_MAX_MSG_SIZE];
    int sk_data_len = sizeof(sk_data);

    /* We need the IKE header as AAD for GCM, but the header length depends
     * on the SK payload size. We'll build a provisional header. */
    /* Provisional: header is 28 bytes */
    uint8_t prov_hdr[28];
    memcpy(prov_hdr, msg_buf, 28);  /* IKE header from builder */

    int is_aead = ctx->ike_alg.is_aead;
    if (ike_sk_encrypt(ctx->sk_ei, ctx->sk_ei_len,
                       ctx->sk_ai, ctx->sk_ai_len,
                       ctx->sk_ei_salt, is_aead,
                       plaintext, pt_len,
                       sk_data, &sk_data_len,
                       prov_hdr, 28) != 0) {
        fprintf(stderr, "[IKE] SK payload encryption failed\n");
        return -1;
    }

    /* Add SK payload to outer message */
    /* The SK payload's next_payload contains the type of the first inner payload */
    if (ike_msg_add_payload(&outer, PAYLOAD_SK, sk_data, sk_data_len) != 0) {
        fprintf(stderr, "[IKE] Failed to add SK payload\n");
        return -1;
    }

    /* Patch: the SK payload's next_payload should be IDi */
    /* The outer builder set it to PAYLOAD_NONE; find the SK payload header and fix */
    /* The SK payload starts after the IKE header (28 bytes) */
    msg_buf[28] = sk_first_payload;  /* next_payload in SK payload header = IDi */

    int msg_len = ike_msg_finalize(&outer);

    if (DEBUG_IKE) {
        printf("[IKE] AUTH request: %d bytes\n", msg_len);
        hex_dump("IKE_AUTH request", msg_buf, msg_len);
    }

    /* Send */
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

    ctx->state = IKE_STATE_AUTH_SENT;
    printf("[IKE] AUTH request sent (%zd bytes)\n", sent);
    return 0;
}

/* ============================================================
 * Receive IKE_AUTH Response (Message 4)
 * ============================================================ */

int ike_auth_recv(ike_sa_ctx_t *ctx)
{
    printf("[IKE] Waiting for IKE_AUTH response...\n");

    static uint8_t recv_buf[IKE_MAX_MSG_SIZE * 2];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);

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
        hex_dump("IKE_AUTH response", recv_buf, (int)recvd);
    }

    /* Parse outer message */
    parsed_ike_msg_t outer_msg;
    if (ike_msg_parse(recv_buf, (int)recvd, &outer_msg) != 0) {
        fprintf(stderr, "[IKE] Failed to parse AUTH response\n");
        return -1;
    }

    if (outer_msg.hdr.exchange_type != IKE_EXCHANGE_AUTH) {
        fprintf(stderr, "[IKE] Unexpected exchange type: %d\n",
                outer_msg.hdr.exchange_type);
        return -1;
    }

    /* Find SK payload */
    int sk_len;
    const uint8_t *sk_data = ike_msg_find_payload(&outer_msg, PAYLOAD_SK, &sk_len);
    if (!sk_data) {
        fprintf(stderr, "[IKE] No SK payload in AUTH response\n");
        return -1;
    }

    /* Decrypt SK payload using SK_er and SK_ar (responder keys) */
    static uint8_t inner_buf[IKE_MAX_MSG_SIZE * 2];
    int inner_len = sizeof(inner_buf);

    /* AAD = IKE header (first 28 bytes of raw message) */
    int is_aead = ctx->ike_alg.is_aead;
    if (ike_sk_decrypt(ctx->sk_er, ctx->sk_er_len,
                       ctx->sk_ar, ctx->sk_ar_len,
                       ctx->sk_er_salt, is_aead,
                       sk_data, sk_len,
                       inner_buf, &inner_len,
                       recv_buf, 28) != 0) {
        fprintf(stderr, "[IKE] SK payload decryption failed\n");
        return -1;
    }

    printf("[IKE] Decrypted inner payloads: %d bytes\n", inner_len);

    /* The inner payloads start with the first payload type from SK's next_payload */
    /* (stored in the SK generic header's next_payload field, offset 28 of recv_buf) */
    uint8_t first_inner_type = recv_buf[28]; /* next_payload of SK payload header */

    /* Build a fake raw message to use the parser on inner payloads */
    /* We create a minimal IKE header pointing to inner payloads */
    static uint8_t fake_msg[IKE_MAX_MSG_SIZE * 2];
    ike_header_t *fake_hdr = (ike_header_t *)fake_msg;
    memcpy(fake_hdr, recv_buf, sizeof(ike_header_t));
    fake_hdr->next_payload = first_inner_type;
    fake_hdr->length = htonl(sizeof(ike_header_t) + inner_len);
    memcpy(fake_msg + sizeof(ike_header_t), inner_buf, inner_len);

    parsed_ike_msg_t inner_msg;
    if (ike_msg_parse(fake_msg, sizeof(ike_header_t) + inner_len, &inner_msg) != 0) {
        fprintf(stderr, "[IKE] Failed to parse inner payloads\n");
        return -1;
    }

    /* == IDr == */
    int idr_len;
    const uint8_t *idr_data = ike_msg_find_payload(&inner_msg, PAYLOAD_IDr, &idr_len);
    if (idr_data) {
        const id_data_t *idr = (const id_data_t *)idr_data;
        int id_val_len = idr_len - sizeof(id_data_t);
        if (id_val_len > 0 && id_val_len < 255) {
            memcpy(ctx->remote_id, idr_data + sizeof(id_data_t), id_val_len);
            ctx->remote_id[id_val_len] = '\0';
            ctx->remote_id_type = idr->id_type;
            printf("[IKE] Peer ID: %s (type=%d)\n", ctx->remote_id, ctx->remote_id_type);
        }
    }

    /* == AUTH == */
    int auth_len;
    const uint8_t *auth_data = ike_msg_find_payload(&inner_msg, PAYLOAD_AUTH, &auth_len);
    if (!auth_data) {
        fprintf(stderr, "[IKE] No AUTH payload in response\n");
        return -1;
    }

    if (auth_len < (int)sizeof(auth_data_t)) return -1;
    const auth_data_t *auth_hdr = (const auth_data_t *)auth_data;
    if (auth_hdr->auth_method != AUTH_METHOD_PSK) {
        fprintf(stderr, "[IKE] Unexpected auth method: %d\n", auth_hdr->auth_method);
        return -1;
    }

    const uint8_t *auth_value = auth_data + sizeof(auth_data_t);
    int auth_value_len = auth_len - sizeof(auth_data_t);

    /* Verify AUTH */
    if (idr_data) {
        if (ike_verify_auth_responder(ctx, idr_data, idr_len,
                                       auth_value, auth_value_len) != 0) {
            fprintf(stderr, "[IKE] AUTH verification failed!\n");
            return -1;
        }
        printf("[IKE] AUTH verified successfully\n");
    } else {
        fprintf(stderr, "[IKE] Warning: No IDr, skipping AUTH verification\n");
    }

    /* == SAr2 == (get peer's ESP SPI and negotiated algorithms) */
    int sa2_len;
    const uint8_t *sa2_data = ike_msg_find_payload(&inner_msg, PAYLOAD_SA, &sa2_len);
    if (!sa2_data) {
        fprintf(stderr, "[IKE] No SAr2 payload in AUTH response\n");
        return -1;
    }

    uint8_t peer_spi_bytes[4] = {0};
    int peer_spi_len = 4;
    if (parse_negotiated_algs(sa2_data, sa2_len, PROTO_ESP,
                               &ctx->esp_alg,
                               peer_spi_bytes, &peer_spi_len) != 0) {
        fprintf(stderr, "[IKE] Failed to parse ESP algorithms\n");
        return -1;
    }

    memcpy(&ctx->child_spi_r, peer_spi_bytes, 4);
    printf("[IKE] Child SA SPIr (peer): 0x%08x\n", ntohl(ctx->child_spi_r));
    printf("[IKE] ESP: ENCR=%d(%d bits), INTEG=%d, AEAD=%d\n",
           ctx->esp_alg.encr_id, ctx->esp_alg.encr_key_bits,
           ctx->esp_alg.integ_id, ctx->esp_alg.is_aead);

    /* Derive Child SA keys using IKE nonces (no separate child nonces in IKE_AUTH) */
    if (ike_derive_child_keys(ctx,
                               ctx->nonce_i, ctx->nonce_i_len,
                               ctx->nonce_r, ctx->nonce_r_len) != 0) {
        fprintf(stderr, "[IKE] Child SA key derivation failed\n");
        return -1;
    }

    ctx->state = IKE_STATE_ESTABLISHED;
    printf("[IKE] IKE_AUTH completed - IPsec SA established\n");
    return 0;
}
