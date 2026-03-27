#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

/*
  PAYLOAD_TYPE_TXT_MSG (0x02) outer payload header (per MeshCore docs):
    destination_hash  1
    source_hash       1
    cipher_mac         2 (little-endian)
    ciphertext        rest

  The plaintext inside ciphertext is "Plain text message" format:
    timestamp (4) + txt_type+attempt (1) + message (rest)
  but cannot be decoded without decrypting the ciphertext.
*/

static uint16_t u16le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void ptype_txt_msg(const onair_packet_t *pkt) {
    if (pkt->payload_len < 4) {
        printf("  TXT_MSG outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t dst = p[0];
    uint8_t srcb = p[1];
    uint16_t mac = u16le16(&p[2]);
    unsigned cipher_len = (unsigned)pkt->payload_len - 4;

    printf("  TXT_MSG outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)dst, (unsigned)srcb, (unsigned)mac, cipher_len);
}
