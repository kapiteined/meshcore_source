#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

static uint32_t u32le32(const uint8_t *p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

void ptype_ack(const onair_packet_t *pkt) {
    if (pkt->payload_len < 4) {
        printf("  ACK: too_short payload_len=%u (need 4)\n", (unsigned)pkt->payload_len);
        return;
    }
    printf("  ACK: checksum=0x%08lX\n", (unsigned long)u32le32(pkt->payload));
}
