#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"

/*
  PAYLOAD_TYPE_PATH (0x08) outer payload header (per MeshCore docs):
    destination_hash  1
    source_hash       1
    cipher_mac         2 (little-endian)
    ciphertext        rest

  We only decode the outer header (no decryption).

  NOTE: The on-air packet's separate 'path' field (pkt->path) is still useful and is printed.
*/

static uint16_t u16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void print_path_compact(const uint8_t *path, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        if (i) printf("->");
        printf("%02X", path[i]);
    }
}

void ptype_path(const onair_packet_t *pkt) {
    printf("  ptype: %s(0x%X) ver=%u route=%s(0x%X)",
           onair_payload_name(pkt->ptype), (unsigned)pkt->ptype,
           (unsigned)pkt->ver,
           onair_route_name(pkt->rtype), (unsigned)pkt->rtype);

    if (pkt->has_transport) {
        printf(" tc1=0x%04X tc2=0x%04X", (unsigned)pkt->tc1, (unsigned)pkt->tc2);
    }

    printf(" path_len=%u payload_len=%u\n", (unsigned)pkt->path_len, (unsigned)pkt->payload_len);

    /* Restore printing of the on-air path field */
    if (pkt->path_len) {
        printf("  path: ");
        print_path_compact(pkt->path, pkt->path_len);
        printf("\n");
    }

    if (pkt->payload_len < 4) {
        printf("  PATH outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t dst = p[0];
    uint8_t src = p[1];
    uint16_t mac = u16le(&p[2]);
    unsigned cipher_len = (unsigned)pkt->payload_len - 4;

    printf("  PATH outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)dst, (unsigned)src, (unsigned)mac, cipher_len);

    /* No ciphertext dump for now. */
}
