#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"
static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
void ptype_response(const onair_packet_t *pkt) {
    if (pkt->payload_len < 4) { printf("  RESPONSE outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len); return; }
    const uint8_t *p = pkt->payload;
    uint16_t mac = u16le16(&p[2]);
    printf("  RESPONSE outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)p[0], (unsigned)p[1], (unsigned)mac, (unsigned)(pkt->payload_len - 4));
}
