/**
 * config.h - IPsec VPN Client Configuration
 *
 * Modifiable parameters for the IPsec client:
 *   - Server IP and IKE port
 *   - Pre-Shared Key (PSK)
 *   - IKE/ESP algorithm suites
 *   - DH group
 */

#ifndef CONFIG_H
#define CONFIG_H

/* ============================================================
 * Network Configuration
 * ============================================================ */
#define DEFAULT_SERVER_IP     "192.168.1.1"
#define DEFAULT_CLIENT_IP     "0.0.0.0"      /* Auto-detect local IP */
#define IKE_PORT              500
#define IKE_PORT_NAT          4500
#define HTTP_SERVER_PORT      80
#define HTTP_PATH             "/"

/* ============================================================
 * Authentication
 * ============================================================ */
#define PSK_VALUE             "supersecretkey123"
#define CLIENT_ID             "client@ipsec.local"
#define SERVER_ID             "server@ipsec.local"
#define CLIENT_ID_TYPE        ID_FQDN            /* ID_FQDN or ID_IPV4_ADDR */

/* ============================================================
 * IKE Algorithm Suite
 * ============================================================ */
/* IKE Encryption: choose one */
#define IKE_ENCR_ALG          ENCR_AES_CBC       /* AES-CBC-256 */
/* #define IKE_ENCR_ALG       ENCR_AES_GCM_16 */ /* AES-GCM-256 (AEAD) */
#define IKE_ENCR_KEY_BITS     256

/* IKE Integrity (not used when IKE_ENCR is AEAD) */
#define IKE_INTEG_ALG         AUTH_HMAC_SHA2_256_128

/* IKE PRF */
#define IKE_PRF_ALG           PRF_HMAC_SHA2_256

/* DH Group: choose one */
#define IKE_DH_GROUP          DH_GROUP_14        /* 2048-bit MODP */
/* #define IKE_DH_GROUP       DH_GROUP_19 */     /* 256-bit ECP P-256 */

/* ============================================================
 * ESP (Child SA) Algorithm Suite
 * ============================================================ */
/* ESP Encryption: choose one */
#define ESP_ENCR_ALG          ENCR_AES_CBC        /* AES-CBC-256 */
/* #define ESP_ENCR_ALG       ENCR_AES_GCM_16 */ /* AES-GCM-256 (AEAD) */
#define ESP_ENCR_KEY_BITS     256

/* ESP Integrity (not used when ESP_ENCR is AEAD) */
#define ESP_INTEG_ALG         AUTH_HMAC_SHA2_256_128
#define ESP_INTEG_KEY_BITS    256
#define ESP_INTEG_TRUNC_BITS  128               /* 16-byte ICV */

/* ============================================================
 * Timeouts
 * ============================================================ */
#define IKE_RETRANSMIT_TIMEOUT_MS   5000
#define IKE_MAX_RETRANSMIT          3
#define IKE_RECV_TIMEOUT_SEC        10
#define HTTP_RECV_TIMEOUT_SEC       15

/* ============================================================
 * Replay Window
 * ============================================================ */
#define ESP_REPLAY_WINDOW     64

/* ============================================================
 * XFRM reqid base
 * ============================================================ */
#define XFRM_REQID_BASE       1000

/* ============================================================
 * Debug
 * ============================================================ */
#define DEBUG_IKE             1    /* Print IKE exchange details */
#define DEBUG_ESP             0    /* Print ESP packet details */
#define DEBUG_XFRM            1    /* Print XFRM operations */
#define DEBUG_CRYPTO          0    /* Print crypto operations (verbose) */

#endif /* CONFIG_H */
