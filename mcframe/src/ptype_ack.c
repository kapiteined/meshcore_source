#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

static void print_path_compact(const onair_packet_t *pkt) {
    if (!pkt || pkt->path_bytes == 0) return;

    for (unsigned hop = 0; hop < pkt->hop_count; hop++) {
        if (hop) printf("->");
        const uint8_t *p = pkt->path + (hop * pkt->hash_size);
        for (unsigned j = 0; j < pkt->hash_size; j++) {
            printf("%02X", p[j]);
        }
    }
}


static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

void ptype_ack(const onair_packet_t *pkt) {
    printf("  ptype: %s(0x%X) ver=%u route=%s(0x%X)",
           onair_payload_name(pkt->ptype), (unsigned)pkt->ptype,
           (unsigned)pkt->ver,
           onair_route_name(pkt->rtype), (unsigned)pkt->rtype);

    if (pkt->has_transport) {
        printf(" tc1=0x%04X tc2=0x%04X", (unsigned)pkt->tc1, (unsigned)pkt->tc2);
    }

    printf(" path_len_raw=0x%02X hash_sz=%u hops=%u path_bytes=%u payload_len=%u\n",
           (unsigned)pkt->path_len_raw,
           (unsigned)pkt->hash_size,
           (unsigned)pkt->hop_count,
           (unsigned)pkt->path_bytes,
           (unsigned)pkt->payload_len);

    if (pkt->path_bytes) {
        printf("  path: ");
        print_path_compact(pkt);
        printf("\n");
    }

    /* ACK payload is a 4-byte checksum (CRC) of message timestamp, text, and sender pubkey. */
    if (pkt->payload_len < 4) {
        printf("  ACK: too_short payload_len=%u (need 4)\n", (unsigned)pkt->payload_len);
        return;
    }

    uint32_t crc = u32le(pkt->payload);
    printf("  ACK: checksum=0x%08lX\n", (unsigned long)crc);
}
