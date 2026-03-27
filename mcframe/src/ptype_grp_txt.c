#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

/*
  PAYLOAD_TYPE_GRP_TXT (0x05) outer payload header (per MeshCore docs):
    channel_hash  1 (first byte of SHA256(channel shared key))
    cipher_mac    2 (little-endian)
    ciphertext    rest

  The plaintext inside ciphertext matches plain text message format (timestamp + flags + message),
  but cannot be decoded without channel key.
*/

static uint16_t u16le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void ptype_grp_txt(const onair_packet_t *pkt) {
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t chan_hash = p[0];
    uint16_t mac = u16le16(&p[1]);
    unsigned cipher_len = (unsigned)pkt->payload_len - 3;

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)chan_hash, (unsigned)mac, cipher_len);
}
