/**
 * ike_message.c - IKEv2 Message Encoding and Decoding
 *
 * Implements RFC 7296 message format serialization and deserialization.
 */

#include "ike_message.h"
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>

/* ============================================================
 * Message Builder
 * ============================================================ */

void ike_msg_init(ike_msg_builder_t *b, uint8_t *buf, int capacity,
                  uint8_t exchange_type, uint8_t flags, uint32_t msg_id,
                  const uint8_t *spi_i, const uint8_t *spi_r)
{
    b->buf = buf;
    b->capacity = capacity;
    b->len = 0;
    b->last_next_payload_offset = -1;

    if (capacity < (int)sizeof(ike_header_t)) return;

    ike_header_t *hdr = (ike_header_t *)buf;
    memcpy(hdr->spi_i, spi_i, 8);
    memcpy(hdr->spi_r, spi_r ? spi_r : "\0\0\0\0\0\0\0\0", 8);
    hdr->next_payload  = PAYLOAD_NONE;
    hdr->version       = IKE_VERSION;
    hdr->exchange_type = exchange_type;
    hdr->flags         = flags;
    hdr->msg_id        = htonl(msg_id);
    hdr->length        = 0;  /* Will be set in finalize */

    b->len = sizeof(ike_header_t);
    /* The IKE header's next_payload is at offset 16 */
    b->last_next_payload_offset = 16;
}

int ike_msg_add_payload(ike_msg_builder_t *b, uint8_t payload_type,
                        const uint8_t *data, int data_len)
{
    int total_size = sizeof(payload_header_t) + data_len;
    if (b->len + total_size > b->capacity) {
        fprintf(stderr, "[MSG] Buffer overflow adding payload type %d\n", payload_type);
        return -1;
    }

    /* Patch the previous header's next_payload field */
    if (b->last_next_payload_offset >= 0) {
        b->buf[b->last_next_payload_offset] = payload_type;
    }

    /* Write generic payload header */
    payload_header_t *ph = (payload_header_t *)(b->buf + b->len);
    ph->next_payload = PAYLOAD_NONE;  /* Will be updated by next add */
    ph->flags = 0;
    ph->length = htons((uint16_t)total_size);

    /* Save offset of this header's next_payload field for next chain */
    b->last_next_payload_offset = b->len; /* offset 0 of payload_header_t = next_payload */

    b->len += sizeof(payload_header_t);

    /* Write payload data */
    if (data && data_len > 0) {
        memcpy(b->buf + b->len, data, data_len);
    }
    b->len += data_len;
    return 0;
}

int ike_msg_finalize(ike_msg_builder_t *b)
{
    /* Patch IKE header length */
    ike_header_t *hdr = (ike_header_t *)b->buf;
    hdr->length = htonl((uint32_t)b->len);
    return b->len;
}

/* ============================================================
 * Payload Build Helpers
 * ============================================================ */

/* Helper: append a transform to a buffer */
static int append_transform(uint8_t *buf, int capacity, int offset,
                             uint8_t type, uint16_t id,
                             uint16_t key_bits, /* 0 = no key length attr */
                             uint8_t is_last)
{
    int size = sizeof(sa_transform_t);
    if (key_bits > 0) size += sizeof(transform_attr_t);
    if (offset + size > capacity) return -1;

    sa_transform_t *t = (sa_transform_t *)(buf + offset);
    t->last_or_more  = is_last ? 0 : 3;
    t->reserved      = 0;
    t->length        = htons((uint16_t)size);
    t->transform_type = type;
    t->reserved2     = 0;
    t->transform_id  = htons(id);

    if (key_bits > 0) {
        transform_attr_t *attr = (transform_attr_t *)(buf + offset +
                                    sizeof(sa_transform_t));
        attr->attr_type  = htons(ATTR_KEY_LENGTH | TRANSFORM_ATTR_TV_FORMAT);
        attr->attr_value = htons(key_bits);
    }
    return size;
}

int build_sa_payload_ike(uint8_t *buf, int buf_size,
                         uint16_t dh_group,
                         uint16_t encr_id, uint16_t key_bits,
                         uint16_t prf_id, uint16_t integ_id)
{
    /* Count transforms */
    int num_transforms = 4; /* ENCR, PRF, INTEG (if present), DH, ESN=no_esn */
    /* For AES-GCM (AEAD), no INTEG transform; for CBC, include INTEG */
    int is_aead = (encr_id == ENCR_AES_GCM_16);
    if (is_aead) num_transforms = 4; /* ENCR, PRF, DH, ESN */
    else         num_transforms = 5; /* ENCR, PRF, INTEG, DH, ESN */

    /* Build transforms */
    uint8_t tbuf[512];
    int toff = 0, tsz;

    /* Transform 1: ENCR */
    int last = (num_transforms == 1);
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_ENCR,
                           encr_id, key_bits, last);
    if (tsz < 0) return -1;
    toff += tsz;

    /* Transform 2: PRF */
    last = (is_aead ? (toff == 0) : 0);
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_PRF,
                           prf_id, 0, 0);
    if (tsz < 0) return -1;
    toff += tsz;

    /* Transform 3: INTEG (skip for AEAD) */
    if (!is_aead) {
        tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_INTEG,
                               integ_id, 0, 0);
        if (tsz < 0) return -1;
        toff += tsz;
    }

    /* Transform 4: DH */
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_DH,
                           dh_group, 0, 0);
    if (tsz < 0) return -1;
    toff += tsz;

    /* Transform 5: ESN = NO_ESN */
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_ESN,
                           ESN_NO_ESN, 0, 1 /* last */);
    if (tsz < 0) return -1;
    toff += tsz;

    /* Build proposal */
    int prop_size = sizeof(sa_proposal_t) + toff;
    if (prop_size > buf_size) return -1;

    sa_proposal_t *prop = (sa_proposal_t *)buf;
    prop->last_or_more   = 0;   /* Only one proposal */
    prop->reserved       = 0;
    prop->length         = htons((uint16_t)prop_size);
    prop->proposal_num   = 1;
    prop->protocol_id    = PROTO_IKE;
    prop->spi_size       = 0;   /* IKE SPI is in the IKE header */
    prop->num_transforms = (uint8_t)(is_aead ? 4 : 5);
    /* Actually count correctly */
    int ntrans = 0;
    if (!is_aead) ntrans = 5;
    else          ntrans = 4;
    prop->num_transforms = ntrans;

    memcpy(buf + sizeof(sa_proposal_t), tbuf, toff);
    return prop_size;
}

int build_sa_payload_esp(uint8_t *buf, int buf_size,
                         uint32_t spi,
                         uint16_t encr_id, uint16_t key_bits,
                         uint16_t integ_id)
{
    int is_aead = (encr_id == ENCR_AES_GCM_16);
    int ntrans = is_aead ? 2 : 3;  /* ENCR + (INTEG if not AEAD) + ESN */

    uint8_t tbuf[512];
    int toff = 0, tsz;

    /* ENCR */
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_ENCR,
                           encr_id, key_bits, 0);
    if (tsz < 0) return -1;
    toff += tsz;

    /* INTEG (not for AEAD) */
    if (!is_aead) {
        tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_INTEG,
                               integ_id, 0, 0);
        if (tsz < 0) return -1;
        toff += tsz;
    }

    /* ESN = NO_ESN */
    tsz = append_transform(tbuf, sizeof(tbuf), toff, TRANSFORM_TYPE_ESN,
                           ESN_NO_ESN, 0, 1);
    if (tsz < 0) return -1;
    toff += tsz;

    /* Proposal: SPI size = 4 for ESP */
    int prop_size = sizeof(sa_proposal_t) + 4 + toff;
    if (prop_size > buf_size) return -1;

    sa_proposal_t *prop = (sa_proposal_t *)buf;
    prop->last_or_more   = 0;
    prop->reserved       = 0;
    prop->length         = htons((uint16_t)prop_size);
    prop->proposal_num   = 1;
    prop->protocol_id    = PROTO_ESP;
    prop->spi_size       = 4;
    prop->num_transforms = (uint8_t)ntrans;

    /* SPI (4 bytes) */
    memcpy(buf + sizeof(sa_proposal_t), &spi, 4);

    /* Transforms */
    memcpy(buf + sizeof(sa_proposal_t) + 4, tbuf, toff);
    return prop_size;
}

int build_ke_payload(uint8_t *buf, int buf_size,
                     const uint8_t *pub_key, int pub_len,
                     uint16_t dh_group)
{
    int total = sizeof(ke_data_t) + pub_len;
    if (total > buf_size) return -1;

    ke_data_t *ke = (ke_data_t *)buf;
    ke->dh_group  = htons(dh_group);
    ke->reserved  = 0;
    memcpy(buf + sizeof(ke_data_t), pub_key, pub_len);
    return total;
}

int build_nonce_payload(uint8_t *buf, int buf_size,
                        const uint8_t *nonce, int nonce_len)
{
    if (nonce_len > buf_size) return -1;
    memcpy(buf, nonce, nonce_len);
    return nonce_len;
}

int build_id_payload(uint8_t *buf, int buf_size,
                     uint8_t id_type, const uint8_t *id_data, int id_len)
{
    int total = sizeof(id_data_t) + id_len;
    if (total > buf_size) return -1;

    id_data_t *id = (id_data_t *)buf;
    id->id_type   = id_type;
    memset(id->reserved, 0, 3);
    memcpy(buf + sizeof(id_data_t), id_data, id_len);
    return total;
}

int build_auth_payload(uint8_t *buf, int buf_size,
                       const uint8_t *auth_data, int auth_len)
{
    int total = sizeof(auth_data_t) + auth_len;
    if (total > buf_size) return -1;

    auth_data_t *auth = (auth_data_t *)buf;
    auth->auth_method = AUTH_METHOD_PSK;
    memset(auth->reserved, 0, 3);
    memcpy(buf + sizeof(auth_data_t), auth_data, auth_len);
    return total;
}

int build_ts_payload(uint8_t *buf, int buf_size,
                     const char *start_ip, const char *end_ip)
{
    /* TS payload: 1 traffic selector entry */
    int ts_entry_size = offsetof(ts_entry_t, end_addr) + 4; /* Only IPv4 addresses */
    int total = sizeof(ts_payload_data_t) + sizeof(ts_entry_t);

    /* We'll use a fixed-size TS entry with IPv4 */
    if (total > buf_size) return -1;

    ts_payload_data_t *ts_hdr = (ts_payload_data_t *)buf;
    ts_hdr->num_ts = 1;
    memset(ts_hdr->reserved, 0, 3);

    ts_entry_t *ts = (ts_entry_t *)(buf + sizeof(ts_payload_data_t));
    ts->ts_type        = TS_IPV4_ADDR_RANGE;
    ts->ip_protocol_id = 0;   /* Any protocol */
    ts->length         = htons(sizeof(ts_entry_t));
    ts->start_port     = 0;
    ts->end_port       = htons(65535);

    /* Start and end IP addresses */
    struct in_addr in;
    memset(ts->start_addr, 0, sizeof(ts->start_addr));
    memset(ts->end_addr, 0, sizeof(ts->end_addr));
    if (inet_pton(AF_INET, start_ip, &in) == 1)
        memcpy(ts->start_addr, &in, 4);
    if (inet_pton(AF_INET, end_ip, &in) == 1)
        memcpy(ts->end_addr, &in, 4);

    return sizeof(ts_payload_data_t) + sizeof(ts_entry_t);
}

/* ============================================================
 * Message Parser
 * ============================================================ */

int ike_msg_parse(const uint8_t *buf, int len, parsed_ike_msg_t *msg)
{
    if (!buf || !msg || len < (int)sizeof(ike_header_t)) return -1;

    msg->raw     = buf;
    msg->raw_len = len;
    msg->num_payloads = 0;

    /* Parse IKE header */
    const ike_header_t *hdr = (const ike_header_t *)buf;
    msg->hdr = *hdr;

    uint32_t total_len = ntohl(hdr->length);
    if ((int)total_len > len) {
        fprintf(stderr, "[PARSE] Message length mismatch: hdr=%u, actual=%d\n",
                total_len, len);
        return -1;
    }

    /* Parse payloads */
    int offset = sizeof(ike_header_t);
    uint8_t next = hdr->next_payload;

    while (next != PAYLOAD_NONE && offset < (int)total_len) {
        if (offset + (int)sizeof(payload_header_t) > (int)total_len) {
            fprintf(stderr, "[PARSE] Truncated payload header at offset %d\n", offset);
            return -1;
        }

        const payload_header_t *ph = (const payload_header_t *)(buf + offset);
        uint16_t plen = ntohs(ph->length);

        if (plen < sizeof(payload_header_t) || offset + plen > (int)total_len) {
            fprintf(stderr, "[PARSE] Invalid payload length %d at offset %d\n",
                    plen, offset);
            return -1;
        }

        if (msg->num_payloads < 32) {
            msg->payloads[msg->num_payloads].type     = next;
            msg->payloads[msg->num_payloads].offset   = offset + sizeof(payload_header_t);
            msg->payloads[msg->num_payloads].data_len = plen - sizeof(payload_header_t);
            msg->num_payloads++;
        }

        next = ph->next_payload;
        offset += plen;
    }

    return 0;
}

const uint8_t *ike_msg_find_payload(const parsed_ike_msg_t *msg,
                                     uint8_t payload_type, int *data_len)
{
    for (int i = 0; i < msg->num_payloads; i++) {
        if (msg->payloads[i].type == payload_type) {
            if (data_len) *data_len = msg->payloads[i].data_len;
            return msg->raw + msg->payloads[i].offset;
        }
    }
    return NULL;
}

int parse_sa_payload(const uint8_t *sa_data, int sa_len,
                     uint8_t protocol_id, parsed_proposal_t *out)
{
    int offset = 0;
    while (offset < sa_len) {
        if (offset + (int)sizeof(sa_proposal_t) > sa_len) return -1;

        const sa_proposal_t *prop = (const sa_proposal_t *)(sa_data + offset);
        uint16_t plen = ntohs(prop->length);

        if (prop->protocol_id == protocol_id) {
            /* Found matching proposal, extract transforms */
            out->protocol_id = prop->protocol_id;
            out->spi_size    = prop->spi_size;
            memset(out->spi, 0, sizeof(out->spi));

            int toffset = sizeof(sa_proposal_t);
            if (prop->spi_size > 0) {
                if (toffset + prop->spi_size <= plen)
                    memcpy(out->spi, sa_data + offset + toffset,
                           prop->spi_size > 4 ? 4 : prop->spi_size);
                toffset += prop->spi_size;
            }

            out->num_transforms = 0;
            for (int t = 0; t < prop->num_transforms && toffset < plen; t++) {
                if (toffset + (int)sizeof(sa_transform_t) > plen) break;

                const sa_transform_t *trans =
                    (const sa_transform_t *)(sa_data + offset + toffset);
                uint16_t tlen = ntohs(trans->length);

                if (out->num_transforms < 8) {
                    parsed_transform_t *pt = &out->transforms[out->num_transforms];
                    pt->type = trans->transform_type;
                    pt->id   = ntohs(trans->transform_id);
                    pt->key_length = 0;

                    /* Check for key-length attribute */
                    int attr_offset = sizeof(sa_transform_t);
                    while (attr_offset + (int)sizeof(transform_attr_t) <= tlen) {
                        const transform_attr_t *attr =
                            (const transform_attr_t *)((const uint8_t *)trans + attr_offset);
                        uint16_t atype = ntohs(attr->attr_type);
                        if ((atype & ~TRANSFORM_ATTR_TV_FORMAT) == ATTR_KEY_LENGTH) {
                            pt->key_length = ntohs(attr->attr_value);
                        }
                        attr_offset += sizeof(transform_attr_t);
                    }
                    out->num_transforms++;
                }
                toffset += tlen;
            }
            return 0;
        }

        if (prop->last_or_more == 0) break;  /* Last proposal */
        offset += plen;
    }
    return -1;
}

int parse_negotiated_algs(const uint8_t *sa_data, int sa_len,
                          uint8_t protocol_id, negotiated_alg_t *alg,
                          uint8_t *spi_out, int *spi_len)
{
    parsed_proposal_t prop;
    if (parse_sa_payload(sa_data, sa_len, protocol_id, &prop) != 0)
        return -1;

    memset(alg, 0, sizeof(*alg));

    if (spi_out && spi_len) {
        int copy = prop.spi_size < *spi_len ? prop.spi_size : *spi_len;
        memcpy(spi_out, prop.spi, copy);
        *spi_len = prop.spi_size;
    }

    for (int i = 0; i < prop.num_transforms; i++) {
        parsed_transform_t *t = &prop.transforms[i];
        switch (t->type) {
        case TRANSFORM_TYPE_ENCR:
            alg->encr_id       = t->id;
            alg->encr_key_bits = t->key_length > 0 ? t->key_length : 256;
            alg->is_aead       = (t->id == ENCR_AES_GCM_16);
            break;
        case TRANSFORM_TYPE_PRF:
            alg->prf_id = t->id;
            break;
        case TRANSFORM_TYPE_INTEG:
            alg->integ_id = t->id;
            break;
        case TRANSFORM_TYPE_DH:
            alg->dh_group = t->id;
            break;
        }
    }
    return 0;
}

void hex_dump(const char *label, const uint8_t *data, int len)
{
    if (label) printf("[HEX] %s (%d bytes):\n", label, len);
    for (int i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}
