/**
 * xfrm_api.c - Linux XFRM SA/Policy Management via Netlink
 *
 * Implements SA and Policy installation using NETLINK_XFRM socket.
 * References: linux/xfrm.h, linux/netlink.h
 *
 * strongSwan reference: src/libcharon/plugins/kernel_netlink/kernel_netlink_ipsec.c
 */

#include "xfrm_api.h"
#include "../config.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <netinet/in.h>

/* XFRM attribute helper (uses rtattr format) */
static void nl_add_attr(struct nlmsghdr *nlh, int max_len,
                        int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    /* Ensure alignment */
    int offset = NLMSG_ALIGN(nlh->nlmsg_len);
    if (offset + len > max_len) {
        fprintf(stderr, "[XFRM] Attribute overflow: type=%d\n", type);
        return;
    }
    struct rtattr *rta = (struct rtattr *)((char *)nlh + offset);
    rta->rta_type = type;
    rta->rta_len  = len;
    if (alen > 0) memcpy(RTA_DATA(rta), data, alen);
    nlh->nlmsg_len = offset + RTA_ALIGN(len);
}

/* Receive and check netlink ACK */
static int nl_recv_ack(int sock)
{
    char buf[4096];
    ssize_t n = recv(sock, buf, sizeof(buf), 0);
    if (n < 0) {
        perror("[XFRM] recv");
        return -1;
    }

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    if (nlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
        if (err->error != 0) {
            /* -EEXIST is acceptable for add operations */
            if (err->error == -EEXIST) {
                printf("[XFRM] SA/Policy already exists (EEXIST)\n");
                return 0;
            }
            fprintf(stderr, "[XFRM] Netlink error: %s (%d)\n",
                    strerror(-err->error), err->error);
            return -1;
        }
        return 0;  /* Success */
    }
    return 0;
}

int xfrm_open_socket(void)
{
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_XFRM);
    if (sock < 0) {
        perror("[XFRM] socket");
        return -1;
    }

    struct sockaddr_nl local = {
        .nl_family = AF_NETLINK,
        .nl_pid    = (uint32_t)getpid(),
        .nl_groups = 0,
    };
    if (bind(sock, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("[XFRM] bind");
        close(sock);
        return -1;
    }

    return sock;
}

void xfrm_close_socket(int sock)
{
    if (sock >= 0) close(sock);
}

/* ============================================================
 * Add ESP SA
 * ============================================================ */

int xfrm_add_sa(int sock, const xfrm_sa_params_t *params)
{
    /* Build XFRM_MSG_NEWSA netlink message */
    struct {
        struct nlmsghdr nlh;
        struct xfrm_usersa_info sa;
        char buf[2048];
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.sa));
    req.nlh.nlmsg_type  = XFRM_MSG_NEWSA;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq   = 1;
    req.nlh.nlmsg_pid   = (uint32_t)getpid();

    /* SA info */
    req.sa.family        = AF_INET;
    req.sa.mode          = params->mode;  /* XFRM_MODE_TUNNEL */
    req.sa.reqid         = params->reqid;
    req.sa.replay_window = ESP_REPLAY_WINDOW;
    req.sa.id.spi        = params->spi;     /* Already network byte order */
    req.sa.id.proto      = IPPROTO_ESP;
    inet_pton(AF_INET, params->dst_ip, &req.sa.id.daddr.a4);
    inet_pton(AF_INET, params->src_ip, &req.sa.saddr.a4);

    /* Lifetime: unlimited */
    req.sa.lft.soft_byte_limit   = XFRM_INF;
    req.sa.lft.hard_byte_limit   = XFRM_INF;
    req.sa.lft.soft_packet_limit = XFRM_INF;
    req.sa.lft.hard_packet_limit = XFRM_INF;

    if (params->is_aead) {
        /* AES-GCM: name = "rfc4106(gcm(aes))", key = aes_key + salt */
        int total_key_bytes = params->enc_key_len + 4;  /* key + salt */
        int struct_size = sizeof(struct xfrm_algo_aead) + total_key_bytes;

        struct xfrm_algo_aead *aead = calloc(1, struct_size);
        if (!aead) return -1;
        strncpy(aead->alg_name, "rfc4106(gcm(aes))", sizeof(aead->alg_name) - 1);
        aead->alg_key_len = (unsigned int)(total_key_bytes * 8);  /* bits */
        aead->alg_icv_len = 128;  /* 16-byte ICV */
        memcpy(aead->alg_key, params->enc_key, params->enc_key_len);
        memcpy(aead->alg_key + params->enc_key_len, params->enc_salt, 4);

        nl_add_attr(&req.nlh, sizeof(req), XFRMA_ALG_AEAD, aead, struct_size);
        free(aead);

    } else {
        /* AES-CBC: name = "cbc(aes)" */
        int enc_struct_size = sizeof(struct xfrm_algo) + params->enc_key_len;
        struct xfrm_algo *enc = calloc(1, enc_struct_size);
        if (!enc) return -1;
        strncpy(enc->alg_name, "cbc(aes)", sizeof(enc->alg_name) - 1);
        enc->alg_key_len = (unsigned int)(params->enc_key_len * 8);  /* bits */
        memcpy(enc->alg_key, params->enc_key, params->enc_key_len);
        nl_add_attr(&req.nlh, sizeof(req), XFRMA_ALG_CRYPT, enc, enc_struct_size);
        free(enc);

        /* HMAC-SHA256 integrity */
        int auth_key_bytes = params->auth_key_bits / 8;
        int auth_struct_size = sizeof(struct xfrm_algo_auth) + auth_key_bytes;
        struct xfrm_algo_auth *auth = calloc(1, auth_struct_size);
        if (!auth) return -1;
        strncpy(auth->alg_name, "hmac(sha256)", sizeof(auth->alg_name) - 1);
        auth->alg_key_len   = (unsigned int)params->auth_key_bits;
        auth->alg_trunc_len = (unsigned int)params->auth_trunc_bits;
        memcpy(auth->alg_key, params->auth_key, auth_key_bytes);
        nl_add_attr(&req.nlh, sizeof(req), XFRMA_ALG_AUTH_TRUNC, auth, auth_struct_size);
        free(auth);
    }

    if (DEBUG_XFRM) {
        printf("[XFRM] Adding SA: SPI=0x%08x, dst=%s, src=%s, mode=%d\n",
               ntohl(params->spi), params->dst_ip, params->src_ip, params->mode);
    }

    /* Send netlink message */
    struct sockaddr_nl dst = {
        .nl_family = AF_NETLINK,
        .nl_pid    = 0,
        .nl_groups = 0,
    };

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("[XFRM] sendto SA");
        return -1;
    }

    return nl_recv_ack(sock);
}

int xfrm_del_sa(int sock, uint32_t spi, const char *dst_ip)
{
    struct {
        struct nlmsghdr nlh;
        struct xfrm_usersa_id sa_id;
        char buf[256];
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.sa_id));
    req.nlh.nlmsg_type  = XFRM_MSG_DELSA;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq   = 3;

    req.sa_id.spi   = spi;
    req.sa_id.proto = IPPROTO_ESP;
    req.sa_id.family = AF_INET;
    inet_pton(AF_INET, dst_ip, &req.sa_id.daddr.a4);

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    if (sendto(sock, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("[XFRM] sendto DEL_SA");
        return -1;
    }
    return nl_recv_ack(sock);
}

/* ============================================================
 * Add XFRM Policy
 * ============================================================ */

int xfrm_add_policy(int sock, const xfrm_policy_params_t *params)
{
    struct {
        struct nlmsghdr         nlh;
        struct xfrm_userpolicy_info pol;
        char buf[1024];
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.pol));
    req.nlh.nlmsg_type  = XFRM_MSG_NEWPOLICY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq   = 2;
    req.nlh.nlmsg_pid   = (uint32_t)getpid();

    req.pol.dir      = (uint8_t)params->direction;
    req.pol.action   = XFRM_POLICY_ALLOW;
    req.pol.priority = (uint32_t)params->priority;
    req.pol.index    = 0;  /* Auto-assign */

    /* Traffic selector */
    req.pol.sel.family      = AF_INET;
    req.pol.sel.prefixlen_s = (uint8_t)params->src_prefix;
    req.pol.sel.prefixlen_d = (uint8_t)params->dst_prefix;
    inet_pton(AF_INET, params->src_net, &req.pol.sel.saddr.a4);
    inet_pton(AF_INET, params->dst_net, &req.pol.sel.daddr.a4);
    req.pol.sel.proto = 0;  /* Any protocol */

    /* Lifetime */
    req.pol.lft.soft_add_expires_seconds = 0;
    req.pol.lft.hard_add_expires_seconds = 0;

    /* SA transform template */
    struct xfrm_user_tmpl tmpl;
    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.family   = AF_INET;
    tmpl.mode     = (uint8_t)params->mode;
    tmpl.reqid    = params->reqid;
    tmpl.id.proto = IPPROTO_ESP;
    tmpl.aalgos   = ~0U;
    tmpl.ealgos   = ~0U;
    tmpl.calgos   = ~0U;
    inet_pton(AF_INET, params->local_ip,  &tmpl.saddr.a4);
    inet_pton(AF_INET, params->remote_ip, &tmpl.id.daddr.a4);

    nl_add_attr(&req.nlh, sizeof(req), XFRMA_TMPL, &tmpl, sizeof(tmpl));

    if (DEBUG_XFRM) {
        printf("[XFRM] Adding Policy: %s/%d -> %s/%d dir=%d reqid=%u\n",
               params->src_net, params->src_prefix,
               params->dst_net, params->dst_prefix,
               params->direction, params->reqid);
    }

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    if (sendto(sock, &req, req.nlh.nlmsg_len, 0,
               (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        perror("[XFRM] sendto Policy");
        return -1;
    }
    return nl_recv_ack(sock);
}

int xfrm_del_policy(int sock, const char *src_net, int src_prefix,
                    const char *dst_net, int dst_prefix, int direction)
{
    struct {
        struct nlmsghdr nlh;
        struct xfrm_userpolicy_id pol_id;
        char buf[256];
    } req;
    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.pol_id));
    req.nlh.nlmsg_type  = XFRM_MSG_DELPOLICY;
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nlh.nlmsg_seq   = 4;

    req.pol_id.sel.family      = AF_INET;
    req.pol_id.sel.prefixlen_s = (uint8_t)src_prefix;
    req.pol_id.sel.prefixlen_d = (uint8_t)dst_prefix;
    inet_pton(AF_INET, src_net, &req.pol_id.sel.saddr.a4);
    inet_pton(AF_INET, dst_net, &req.pol_id.sel.daddr.a4);
    req.pol_id.dir = (uint8_t)direction;

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    sendto(sock, &req, req.nlh.nlmsg_len, 0,
           (struct sockaddr *)&dst, sizeof(dst));
    return nl_recv_ack(sock);
}

/* ============================================================
 * Install complete IPsec tunnel
 * ============================================================ */

int xfrm_install_ipsec(ike_sa_ctx_t *ctx)
{
    printf("[XFRM] Installing IPsec SAs and Policies\n");

    int sock = xfrm_open_socket();
    if (sock < 0) return -1;

    int is_aead = ctx->esp_alg.is_aead;
    uint32_t reqid = XFRM_REQID_BASE;

    /* --------------------------------------------------------
     * Outbound SA: client -> server
     * dst = server_ip, src = client_ip
     * SPI = child_spi_r (server's inbound SPI)
     * Key = child_sk_ei (initiator encryption)
     * -------------------------------------------------------- */
    xfrm_sa_params_t out_sa = {0};
    out_sa.spi      = ctx->child_spi_r;  /* Network byte order */
    strncpy(out_sa.dst_ip, ctx->remote_ip, sizeof(out_sa.dst_ip) - 1);
    strncpy(out_sa.src_ip, ctx->local_ip, sizeof(out_sa.src_ip) - 1);
    out_sa.mode     = XFRM_MODE_TUNNEL;
    out_sa.reqid    = reqid;
    out_sa.is_aead  = is_aead;

    if (is_aead) {
        /* AES-GCM: key (without salt) + salt */
        out_sa.enc_key_len = ctx->child_sk_ei_len - 4;  /* Remove salt */
        memcpy(out_sa.enc_key, ctx->child_sk_ei, out_sa.enc_key_len);
        memcpy(out_sa.enc_salt, ctx->child_sk_ei_salt, 4);
        out_sa.enc_key_bits = (out_sa.enc_key_len + 4) * 8;  /* Total bits */
    } else {
        out_sa.enc_key_len  = ctx->child_sk_ei_len;
        memcpy(out_sa.enc_key, ctx->child_sk_ei, ctx->child_sk_ei_len);
        out_sa.enc_key_bits = ctx->child_sk_ei_len * 8;
        memcpy(out_sa.auth_key, ctx->child_sk_ai, ctx->child_sk_ai_len);
        out_sa.auth_key_bits  = ctx->child_sk_ai_len * 8;
        out_sa.auth_trunc_bits = ESP_INTEG_TRUNC_BITS;
    }

    if (xfrm_add_sa(sock, &out_sa) != 0) {
        fprintf(stderr, "[XFRM] Failed to add outbound SA\n");
        xfrm_close_socket(sock);
        return -1;
    }
    printf("[XFRM] Outbound SA installed (SPI=0x%08x)\n",
           ntohl(ctx->child_spi_r));

    /* --------------------------------------------------------
     * Inbound SA: server -> client
     * dst = client_ip, src = server_ip
     * SPI = child_spi_i (our SPI)
     * Key = child_sk_er (responder encryption = our decryption)
     * -------------------------------------------------------- */
    xfrm_sa_params_t in_sa = {0};
    in_sa.spi    = ctx->child_spi_i;
    strncpy(in_sa.dst_ip, ctx->local_ip, sizeof(in_sa.dst_ip) - 1);
    strncpy(in_sa.src_ip, ctx->remote_ip, sizeof(in_sa.src_ip) - 1);
    in_sa.mode   = XFRM_MODE_TUNNEL;
    in_sa.reqid  = reqid;
    in_sa.is_aead = is_aead;

    if (is_aead) {
        in_sa.enc_key_len = ctx->child_sk_er_len - 4;
        memcpy(in_sa.enc_key, ctx->child_sk_er, in_sa.enc_key_len);
        memcpy(in_sa.enc_salt, ctx->child_sk_er_salt, 4);
        in_sa.enc_key_bits = (in_sa.enc_key_len + 4) * 8;
    } else {
        in_sa.enc_key_len  = ctx->child_sk_er_len;
        memcpy(in_sa.enc_key, ctx->child_sk_er, ctx->child_sk_er_len);
        in_sa.enc_key_bits  = ctx->child_sk_er_len * 8;
        memcpy(in_sa.auth_key, ctx->child_sk_ar, ctx->child_sk_ar_len);
        in_sa.auth_key_bits  = ctx->child_sk_ar_len * 8;
        in_sa.auth_trunc_bits = ESP_INTEG_TRUNC_BITS;
    }

    if (xfrm_add_sa(sock, &in_sa) != 0) {
        fprintf(stderr, "[XFRM] Failed to add inbound SA\n");
        xfrm_close_socket(sock);
        return -1;
    }
    printf("[XFRM] Inbound SA installed (SPI=0x%08x)\n",
           ntohl(ctx->child_spi_i));

    /* --------------------------------------------------------
     * Outbound Policy: client -> server
     * -------------------------------------------------------- */
    xfrm_policy_params_t out_pol = {0};
    strncpy(out_pol.src_net, "0.0.0.0", sizeof(out_pol.src_net) - 1);
    out_pol.src_prefix = 0;
    strncpy(out_pol.dst_net, ctx->remote_ip, sizeof(out_pol.dst_net) - 1);
    out_pol.dst_prefix = 32;
    strncpy(out_pol.local_ip, ctx->local_ip, sizeof(out_pol.local_ip) - 1);
    strncpy(out_pol.remote_ip, ctx->remote_ip, sizeof(out_pol.remote_ip) - 1);
    out_pol.direction = XFRM_POLICY_OUT;
    out_pol.mode      = XFRM_MODE_TUNNEL;
    out_pol.reqid     = reqid;
    out_pol.priority  = 100;

    if (xfrm_add_policy(sock, &out_pol) != 0) {
        fprintf(stderr, "[XFRM] Failed to add outbound policy\n");
        xfrm_close_socket(sock);
        return -1;
    }
    printf("[XFRM] Outbound policy installed\n");

    /* --------------------------------------------------------
     * Inbound Policy: server -> client
     * -------------------------------------------------------- */
    xfrm_policy_params_t in_pol = {0};
    strncpy(in_pol.src_net, ctx->remote_ip, sizeof(in_pol.src_net) - 1);
    in_pol.src_prefix = 32;
    strncpy(in_pol.dst_net, "0.0.0.0", sizeof(in_pol.dst_net) - 1);
    in_pol.dst_prefix = 0;
    strncpy(in_pol.local_ip, ctx->local_ip, sizeof(in_pol.local_ip) - 1);
    strncpy(in_pol.remote_ip, ctx->remote_ip, sizeof(in_pol.remote_ip) - 1);
    in_pol.direction = XFRM_POLICY_IN;
    in_pol.mode      = XFRM_MODE_TUNNEL;
    in_pol.reqid     = reqid;
    in_pol.priority  = 100;

    if (xfrm_add_policy(sock, &in_pol) != 0) {
        fprintf(stderr, "[XFRM] Failed to add inbound policy\n");
        xfrm_close_socket(sock);
        return -1;
    }
    printf("[XFRM] Inbound policy installed\n");

    xfrm_close_socket(sock);
    printf("[XFRM] IPsec SA/Policy installation complete\n");
    return 0;
}

int xfrm_uninstall_ipsec(ike_sa_ctx_t *ctx)
{
    int sock = xfrm_open_socket();
    if (sock < 0) return -1;

    printf("[XFRM] Removing IPsec SAs and Policies\n");

    /* Remove SAs */
    xfrm_del_sa(sock, ctx->child_spi_r, ctx->remote_ip);
    xfrm_del_sa(sock, ctx->child_spi_i, ctx->local_ip);

    /* Remove Policies */
    xfrm_del_policy(sock, "0.0.0.0", 0, ctx->remote_ip, 32, XFRM_POLICY_OUT);
    xfrm_del_policy(sock, ctx->remote_ip, 32, "0.0.0.0", 0, XFRM_POLICY_IN);

    xfrm_close_socket(sock);
    return 0;
}

int xfrm_flush_sa(int sock)
{
    struct nlmsghdr nlh = {
        .nlmsg_len   = NLMSG_LENGTH(sizeof(struct xfrm_usersa_flush)),
        .nlmsg_type  = XFRM_MSG_FLUSHSA,
        .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
        .nlmsg_seq   = 100,
    };
    struct xfrm_usersa_flush flush = { .proto = IPPROTO_ESP };

    struct {
        struct nlmsghdr h;
        struct xfrm_usersa_flush f;
    } req;
    req.h = nlh;
    req.h.nlmsg_len = sizeof(req);
    req.f = flush;

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst));
    return nl_recv_ack(sock);
}

int xfrm_flush_policy(int sock)
{
    struct {
        struct nlmsghdr h;
    } req;
    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len   = sizeof(req);
    req.h.nlmsg_type  = XFRM_MSG_FLUSHPOLICY;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.h.nlmsg_seq   = 101;

    struct sockaddr_nl dst = { .nl_family = AF_NETLINK };
    sendto(sock, &req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst));
    return nl_recv_ack(sock);
}
