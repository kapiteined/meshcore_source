#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

static uint16_t u16le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void ptype_path(const onair_packet_t *pkt) {
    if (pkt->payload_len < 4) {
        printf("  PATH outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len);
        return;
    }
    const uint8_t *p = pkt->payload;
    uint8_t dst = p[0];
    uint8_t srcb = p[1];
    uint16_t mac = u16le16(&p[2]);
    unsigned cipher_len = (unsigned)pkt->payload_len - 4;
    printf("  PATH outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)dst, (unsigned)srcb, (unsigned)mac, cipher_len);
}
