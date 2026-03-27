#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"
static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
void ptype_grp_txt(const onair_packet_t *pkt) {
    if (pkt->payload_len < 3) { printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)\n", (unsigned)pkt->payload_len); return; }
    const uint8_t *p = pkt->payload;
    uint16_t mac = u16le16(&p[1]);
    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n", (unsigned)p[0], (unsigned)mac, (unsigned)(pkt->payload_len - 3));
}
