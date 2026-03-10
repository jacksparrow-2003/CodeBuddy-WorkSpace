/**
 * xfrm_types.h - XFRM/Netlink Type Definitions for IPsec SA/Policy Installation
 */

#ifndef XFRM_TYPES_H
#define XFRM_TYPES_H

#include <stdint.h>
#include <arpa/inet.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>

/* XFRM SA install parameters */
typedef struct {
    uint32_t spi;           /* Network byte order */
    char     dst_ip[64];    /* SA destination (peer IP for outbound, local IP for inbound) */
    char     src_ip[64];    /* SA source */
    uint8_t  mode;          /* XFRM_MODE_TUNNEL or XFRM_MODE_TRANSPORT */
    uint32_t reqid;

    /* Encryption */
    int      is_aead;       /* 1 = AES-GCM, 0 = AES-CBC + HMAC */
    uint8_t  enc_key[64];   /* Encryption key (+ salt for GCM at end) */
    int      enc_key_len;   /* Key bytes (without salt) */
    int      enc_key_bits;  /* Key bits including salt if GCM */
    uint8_t  enc_salt[4];   /* AES-GCM salt (4 bytes) */

    /* Integrity (AES-CBC only) */
    uint8_t  auth_key[64];
    int      auth_key_bits;
    int      auth_trunc_bits;
} xfrm_sa_params_t;

/* XFRM Policy install parameters */
typedef struct {
    char     src_net[64];   /* Source network */
    int      src_prefix;    /* Source prefix length */
    char     dst_net[64];   /* Destination network */
    int      dst_prefix;    /* Destination prefix length */
    char     local_ip[64];  /* Local tunnel endpoint */
    char     remote_ip[64]; /* Remote tunnel endpoint */
    int      direction;     /* XFRM_POLICY_OUT / IN / FWD */
    int      mode;          /* XFRM_MODE_TUNNEL */
    uint32_t reqid;
    int      priority;
} xfrm_policy_params_t;

/* Netlink message buffer */
#define NL_BUF_SIZE 4096

typedef struct {
    struct nlmsghdr nlh;
    char buf[NL_BUF_SIZE];
} nl_msg_t;

#endif /* XFRM_TYPES_H */
