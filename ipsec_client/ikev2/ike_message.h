/**
 * ike_message.h - IKEv2 Message Encoding and Decoding
 *
 * Provides functions to build and parse IKE messages from/to
 * wire-format byte buffers.
 */

#ifndef IKE_MESSAGE_H
#define IKE_MESSAGE_H

#include "ike_types.h"
#include <stdint.h>

/* Message builder context */
typedef struct {
    uint8_t *buf;       /* Message buffer */
    int      capacity;  /* Buffer capacity */
    int      len;       /* Current message length */

    /* Track the "next payload" field to chain payloads */
    int      last_next_payload_offset; /* Offset of "next_payload" in last header */
} ike_msg_builder_t;

/* ============================================================
 * Message Builder API
 * ============================================================ */

/**
 * Initialize a message builder.
 * @param buf      Pre-allocated buffer
 * @param capacity Buffer size
 * @param exchange_type  IKE exchange type
 * @param flags    IKE header flags (IKE_FLAG_INITIATOR etc.)
 * @param msg_id   Message ID
 * @param spi_i    Initiator SPI (8 bytes)
 * @param spi_r    Responder SPI (8 bytes)
 */
void ike_msg_init(ike_msg_builder_t *b, uint8_t *buf, int capacity,
                  uint8_t exchange_type, uint8_t flags, uint32_t msg_id,
                  const uint8_t *spi_i, const uint8_t *spi_r);

/**
 * Append a raw payload to the message.
 * @param payload_type  The payload type number
 * @param data          Payload data (after generic payload header)
 * @param data_len      Length of data
 * @return              0 on success, -1 on overflow
 */
int ike_msg_add_payload(ike_msg_builder_t *b, uint8_t payload_type,
                        const uint8_t *data, int data_len);

/**
 * Finalize the message: patch the IKE header length field.
 * Returns the total message length.
 */
int ike_msg_finalize(ike_msg_builder_t *b);

/* ============================================================
 * Payload Construction Helpers
 * ============================================================ */

/**
 * Build an SA payload for IKE_SA_INIT (IKE SA negotiation).
 * Supports AES-CBC-256 + PRF-HMAC-SHA256 + INTEG-HMAC-SHA256-128 + DH14.
 * @param buf      Output buffer
 * @param buf_size Buffer size
 * @param dh_group DH group to include
 * @param encr_id  Encryption algorithm ID
 * @param key_bits Encryption key bits
 * @param prf_id   PRF algorithm ID
 * @param integ_id Integrity algorithm ID (0 if AEAD)
 * @return         Length of SA payload data, -1 on error
 */
int build_sa_payload_ike(uint8_t *buf, int buf_size,
                         uint16_t dh_group,
                         uint16_t encr_id, uint16_t key_bits,
                         uint16_t prf_id, uint16_t integ_id);

/**
 * Build an SA payload for Child SA (ESP).
 * @param spi      Our inbound SPI (4 bytes, network byte order)
 * @return         Length of SA payload data, -1 on error
 */
int build_sa_payload_esp(uint8_t *buf, int buf_size,
                         uint32_t spi,
                         uint16_t encr_id, uint16_t key_bits,
                         uint16_t integ_id);

/**
 * Build a KE payload.
 * @param pub_key  DH public key bytes
 * @param pub_len  Public key length
 * @param dh_group DH group number
 * @return         Length of KE payload data, -1 on error
 */
int build_ke_payload(uint8_t *buf, int buf_size,
                     const uint8_t *pub_key, int pub_len,
                     uint16_t dh_group);

/**
 * Build a Nonce payload.
 * @param nonce    Random nonce bytes
 * @param nonce_len Length of nonce
 * @return         Length of nonce payload data, -1 on error
 */
int build_nonce_payload(uint8_t *buf, int buf_size,
                        const uint8_t *nonce, int nonce_len);

/**
 * Build an IDi or IDr payload.
 * @param id_type  ID type (ID_FQDN, ID_IPV4_ADDR, etc.)
 * @param id_data  ID value bytes
 * @param id_len   ID value length
 * @return         Length of ID payload data, -1 on error
 */
int build_id_payload(uint8_t *buf, int buf_size,
                     uint8_t id_type, const uint8_t *id_data, int id_len);

/**
 * Build an AUTH payload (PSK method).
 * @param auth_data  Pre-computed AUTH value
 * @param auth_len   AUTH value length
 * @return           Length of AUTH payload data, -1 on error
 */
int build_auth_payload(uint8_t *buf, int buf_size,
                       const uint8_t *auth_data, int auth_len);

/**
 * Build TSi and TSr payloads (Traffic Selectors).
 * Creates a wildcard TS: 0.0.0.0/0:0-65535 any-protocol.
 * @return Length of TS payload data, -1 on error
 */
int build_ts_payload(uint8_t *buf, int buf_size,
                     const char *start_ip, const char *end_ip);

/* ============================================================
 * Message Parser API
 * ============================================================ */

/* Parsed payload */
typedef struct {
    uint8_t  type;
    int      offset;    /* Offset in raw message where payload data begins */
    int      data_len;  /* Length of payload data (after generic header) */
} parsed_payload_t;

/* Parsed IKE message */
typedef struct {
    ike_header_t     hdr;
    int              num_payloads;
    parsed_payload_t payloads[32];
    const uint8_t   *raw;        /* Pointer to raw message */
    int              raw_len;
} parsed_ike_msg_t;

/**
 * Parse a raw IKE message into its components.
 * @return 0 on success, -1 on error
 */
int ike_msg_parse(const uint8_t *buf, int len, parsed_ike_msg_t *msg);

/**
 * Find a payload by type in a parsed message.
 * @return Pointer to payload data, or NULL if not found.
 *         Sets *data_len to the payload data length.
 */
const uint8_t *ike_msg_find_payload(const parsed_ike_msg_t *msg,
                                     uint8_t payload_type, int *data_len);

/**
 * Parse SA payload and extract the first matching proposal.
 * For IKE SA: protocol_id = PROTO_IKE
 * For ESP SA: protocol_id = PROTO_ESP
 * @return 0 on success, -1 if no acceptable proposal found
 */
int parse_sa_payload(const uint8_t *sa_data, int sa_len,
                     uint8_t protocol_id, parsed_proposal_t *out);

/**
 * Parse SA payload and find the negotiated algorithms.
 */
int parse_negotiated_algs(const uint8_t *sa_data, int sa_len,
                          uint8_t protocol_id, negotiated_alg_t *alg,
                          uint8_t *spi_out, int *spi_len);

/**
 * Debug: print a hex dump of a buffer.
 */
void hex_dump(const char *label, const uint8_t *data, int len);

#endif /* IKE_MESSAGE_H */
