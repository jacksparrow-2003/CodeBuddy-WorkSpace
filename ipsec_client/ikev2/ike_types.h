/**
 * ike_types.h - IKEv2 Protocol Constants and Data Structures (RFC 7296)
 */

#ifndef IKE_TYPES_H
#define IKE_TYPES_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * IKE Header Constants
 * ============================================================ */

/* Exchange Types */
#define IKE_EXCHANGE_SA_INIT        34
#define IKE_EXCHANGE_AUTH           35
#define IKE_EXCHANGE_CREATE_CHILD   36
#define IKE_EXCHANGE_INFORMATIONAL  37

/* IKE Header Flags */
#define IKE_FLAG_INITIATOR          0x08
#define IKE_FLAG_VERSION            0x10
#define IKE_FLAG_RESPONSE           0x20

/* IKE Version */
#define IKE_VERSION_MAJOR           2
#define IKE_VERSION_MINOR           0
#define IKE_VERSION                 0x20  /* Major=2, Minor=0 */

/* ============================================================
 * Payload Type Numbers
 * ============================================================ */
#define PAYLOAD_NONE        0
#define PAYLOAD_SA          33
#define PAYLOAD_KE          34
#define PAYLOAD_IDi         35
#define PAYLOAD_IDr         36
#define PAYLOAD_CERT        37
#define PAYLOAD_CERTREQ     38
#define PAYLOAD_AUTH        39
#define PAYLOAD_NONCE       40
#define PAYLOAD_NOTIFY      41
#define PAYLOAD_DELETE      42
#define PAYLOAD_VENDOR_ID   43
#define PAYLOAD_TSi         44
#define PAYLOAD_TSr         45
#define PAYLOAD_SK          46
#define PAYLOAD_CP          47
#define PAYLOAD_EAP         48

/* ============================================================
 * Transform Types
 * ============================================================ */
#define TRANSFORM_TYPE_ENCR   1
#define TRANSFORM_TYPE_PRF    2
#define TRANSFORM_TYPE_INTEG  3
#define TRANSFORM_TYPE_DH     4
#define TRANSFORM_TYPE_ESN    5

/* Encryption Algorithms (ENCR) */
#define ENCR_AES_CBC          12
#define ENCR_AES_GCM_16       20   /* AES-GCM with 16-byte ICV */

/* PRF Algorithms */
#define PRF_HMAC_SHA1         2
#define PRF_HMAC_SHA2_256     5
#define PRF_HMAC_SHA2_384     6
#define PRF_HMAC_SHA2_512     7

/* Integrity Algorithms */
#define AUTH_NONE             0
#define AUTH_HMAC_SHA1_96     2
#define AUTH_HMAC_SHA2_256_128  12
#define AUTH_HMAC_SHA2_384_192  13
#define AUTH_HMAC_SHA2_512_256  14

/* DH Groups */
#define DH_GROUP_1            1    /* 768-bit MODP */
#define DH_GROUP_2            2    /* 1024-bit MODP */
#define DH_GROUP_14           14   /* 2048-bit MODP */
#define DH_GROUP_15           15   /* 3072-bit MODP */
#define DH_GROUP_16           16   /* 4096-bit MODP */
#define DH_GROUP_19           19   /* 256-bit ECP */
#define DH_GROUP_20           20   /* 384-bit ECP */

/* ESN */
#define ESN_NO_ESN            0
#define ESN_ESN               1

/* ============================================================
 * ID Types
 * ============================================================ */
#define ID_IPV4_ADDR          1
#define ID_FQDN               2
#define ID_RFC822_ADDR        3
#define ID_IPV6_ADDR          5
#define ID_DER_ASN1_DN        9
#define ID_KEY_ID             11

/* ============================================================
 * Auth Method
 * ============================================================ */
#define AUTH_METHOD_RSA_SIG       1
#define AUTH_METHOD_PSK           2
#define AUTH_METHOD_DSS_SIG       3
#define AUTH_METHOD_ECDSA_256     9
#define AUTH_METHOD_ECDSA_384     10
#define AUTH_METHOD_ECDSA_521     11

/* ============================================================
 * Notify Message Types
 * ============================================================ */
#define NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD  1
#define NOTIFY_INVALID_IKE_SPI               4
#define NOTIFY_INVALID_MAJOR_VERSION         5
#define NOTIFY_INVALID_SYNTAX                7
#define NOTIFY_INVALID_MESSAGE_ID            9
#define NOTIFY_INVALID_SPI                   11
#define NOTIFY_NO_PROPOSAL_CHOSEN            14
#define NOTIFY_INVALID_KE_PAYLOAD            17
#define NOTIFY_AUTHENTICATION_FAILED         24
#define NOTIFY_SINGLE_PAIR_REQUIRED          34
#define NOTIFY_NO_ADDITIONAL_SAS             35
#define NOTIFY_INTERNAL_ADDRESS_FAILURE      36
#define NOTIFY_FAILED_CP_REQUIRED            37
#define NOTIFY_TS_UNACCEPTABLE               38
#define NOTIFY_INVALID_SELECTORS             39
#define NOTIFY_UNACCEPTABLE_ADDRESSES        40
#define NOTIFY_UNEXPECTED_NAT_DETECTED       41
#define NOTIFY_USE_ASSIGNED_HoA              42
#define NOTIFY_TEMPORARY_FAILURE             43
#define NOTIFY_CHILD_SA_NOT_FOUND            44
#define NOTIFY_NAT_DETECTION_SOURCE_IP       16388
#define NOTIFY_NAT_DETECTION_DESTINATION_IP  16389
#define NOTIFY_USE_TRANSPORT_MODE            16391
#define NOTIFY_ESP_TFC_PADDING_NOT_SUPPORTED 16394
#define NOTIFY_NON_FIRST_FRAGMENTS_ALSO      16395

/* Traffic Selector Types */
#define TS_IPV4_ADDR_RANGE    7
#define TS_IPV6_ADDR_RANGE    8

/* Protocol IDs in SA Payload */
#define PROTO_IKE             1
#define PROTO_AH              2
#define PROTO_ESP             3

/* Transform Attribute Types */
#define ATTR_KEY_LENGTH       14   /* Key length in bits */

/* ============================================================
 * Wire Format Structures (packed, network byte order)
 * ============================================================ */
#pragma pack(push, 1)

/* IKE Header (28 bytes) */
typedef struct {
    uint8_t  spi_i[8];          /* Initiator SPI */
    uint8_t  spi_r[8];          /* Responder SPI */
    uint8_t  next_payload;      /* First payload type */
    uint8_t  version;           /* Major(4)|Minor(4) = 0x20 for IKEv2 */
    uint8_t  exchange_type;
    uint8_t  flags;
    uint32_t msg_id;            /* Network byte order */
    uint32_t length;            /* Total length, network byte order */
} ike_header_t;

/* Generic Payload Header (4 bytes) */
typedef struct {
    uint8_t  next_payload;
    uint8_t  flags;             /* Critical bit = 0x01 (shifted to bit 7) */
    uint16_t length;            /* Including this header, network byte order */
} payload_header_t;

/* SA Proposal Header */
typedef struct {
    uint8_t  last_or_more;      /* 0=last, 2=more */
    uint8_t  reserved;
    uint16_t length;
    uint8_t  proposal_num;
    uint8_t  protocol_id;
    uint8_t  spi_size;
    uint8_t  num_transforms;
    /* followed by SPI (spi_size bytes), then transforms */
} sa_proposal_t;

/* SA Transform Header */
typedef struct {
    uint8_t  last_or_more;      /* 0=last, 3=more */
    uint8_t  reserved;
    uint16_t length;
    uint8_t  transform_type;
    uint8_t  reserved2;
    uint16_t transform_id;
    /* followed by optional attributes */
} sa_transform_t;

/* Transform Attribute (key-value) */
typedef struct {
    uint16_t attr_type;         /* bit 15 = 1 for TV format (2 bytes value) */
    uint16_t attr_value;
} transform_attr_t;
#define TRANSFORM_ATTR_TV_FORMAT   0x8000

/* KE Payload Data */
typedef struct {
    uint16_t dh_group;
    uint16_t reserved;
    /* followed by key value */
} ke_data_t;

/* ID Payload Data */
typedef struct {
    uint8_t  id_type;
    uint8_t  reserved[3];
    /* followed by ID data */
} id_data_t;

/* AUTH Payload Data */
typedef struct {
    uint8_t  auth_method;
    uint8_t  reserved[3];
    /* followed by auth data */
} auth_data_t;

/* Nonce Payload: just raw bytes after generic header */

/* Notify Payload Data */
typedef struct {
    uint8_t  protocol_id;
    uint8_t  spi_size;
    uint16_t notify_type;
    /* followed by SPI (spi_size bytes), then notification data */
} notify_data_t;

/* Traffic Selector Entry */
typedef struct {
    uint8_t  ts_type;
    uint8_t  ip_protocol_id;    /* 0 = any */
    uint16_t length;
    uint16_t start_port;
    uint16_t end_port;
    uint8_t  start_addr[16];    /* IPv4 or IPv6 */
    uint8_t  end_addr[16];
} ts_entry_t;

/* TS Payload Data */
typedef struct {
    uint8_t  num_ts;
    uint8_t  reserved[3];
    /* followed by ts_entry_t * num_ts */
} ts_payload_data_t;

#pragma pack(pop)

/* ============================================================
 * In-memory representations (dynamic allocation)
 * ============================================================ */

/* Parsed transform */
typedef struct {
    uint8_t  type;
    uint16_t id;
    uint16_t key_length;    /* 0 if not specified */
} parsed_transform_t;

/* Parsed proposal */
typedef struct {
    uint8_t  protocol_id;
    uint8_t  spi_size;
    uint8_t  spi[4];        /* Up to 4 bytes for ESP/AH */
    int      num_transforms;
    parsed_transform_t transforms[8];
} parsed_proposal_t;

/* Negotiated algorithms (result of SA negotiation) */
typedef struct {
    uint16_t encr_id;
    uint16_t encr_key_bits;
    uint16_t prf_id;
    uint16_t integ_id;
    uint16_t dh_group;
    uint8_t  is_aead;       /* 1 if ENCR is AEAD (no separate INTEG) */
} negotiated_alg_t;

/* IKE SA context - main state machine */
typedef struct ike_sa_ctx {
    /* Endpoints */
    char     local_ip[64];
    char     remote_ip[64];
    int      udp_sock;

    /* SPIs */
    uint8_t  spi_i[8];
    uint8_t  spi_r[8];

    /* Nonces */
    uint8_t  nonce_i[32];
    int      nonce_i_len;
    uint8_t  nonce_r[32];
    int      nonce_r_len;

    /* DH */
    void    *dh_ctx;        /* Opaque DH context */
    uint8_t *dh_pub;        /* Our public key (allocated) */
    int      dh_pub_len;
    uint8_t *dh_secret;     /* Shared DH secret (allocated) */
    int      dh_secret_len;

    /* Negotiated algorithms */
    negotiated_alg_t ike_alg;
    negotiated_alg_t esp_alg;

    /* Message ID */
    uint32_t msg_id;

    /* Raw messages for AUTH calculation */
    uint8_t *msg1_raw;      /* IKE_SA_INIT request (initiator sends) */
    int      msg1_raw_len;
    uint8_t *msg2_raw;      /* IKE_SA_INIT response (responder sends) */
    int      msg2_raw_len;

    /* Derived IKE keys */
    uint8_t sk_d[64];       int sk_d_len;
    uint8_t sk_ai[64];      int sk_ai_len;
    uint8_t sk_ar[64];      int sk_ar_len;
    uint8_t sk_ei[64];      int sk_ei_len;
    uint8_t sk_er[64];      int sk_er_len;
    uint8_t sk_pi[64];      int sk_pi_len;
    uint8_t sk_pr[64];      int sk_pr_len;

    /* AES-GCM specific: salt values embedded in key material */
    uint8_t sk_ei_salt[4];
    uint8_t sk_er_salt[4];

    /* Child SA (ESP) SPIs */
    uint32_t child_spi_i;   /* Our inbound SPI (we propose) */
    uint32_t child_spi_r;   /* Peer's inbound SPI (peer proposes) */

    /* Child SA keys */
    uint8_t child_sk_ei[64]; int child_sk_ei_len;
    uint8_t child_sk_ai[64]; int child_sk_ai_len;
    uint8_t child_sk_er[64]; int child_sk_er_len;
    uint8_t child_sk_ar[64]; int child_sk_ar_len;
    uint8_t child_sk_ei_salt[4];
    uint8_t child_sk_er_salt[4];

    /* IDs */
    char     local_id[256];
    int      local_id_type;
    char     remote_id[256];
    int      remote_id_type;

    /* PSK */
    char     psk[256];
    int      psk_len;

    /* State */
    int      state;
} ike_sa_ctx_t;

/* IKE SA states */
#define IKE_STATE_INIT          0
#define IKE_STATE_SA_INIT_SENT  1
#define IKE_STATE_SA_INIT_DONE  2
#define IKE_STATE_AUTH_SENT     3
#define IKE_STATE_AUTH_DONE     4
#define IKE_STATE_ESTABLISHED   5
#define IKE_STATE_ERROR         -1

/* Maximum message buffer size */
#define IKE_MAX_MSG_SIZE        4096
#define IKE_MAX_PAYLOAD_SIZE    65535

#endif /* IKE_TYPES_H */
