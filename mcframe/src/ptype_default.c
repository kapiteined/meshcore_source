#include <stdio.h>
#include "ptype_dispatch.h"

static void print_path_compact(const uint8_t *path, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        if (i) printf("->");
        printf("%02X", path[i]);
    }
}

void ptype_default(const onair_packet_t *pkt) {
    /* "Decode further" at the structural level: header fields already known.
       We print ptype name, transport codes (if any), path and payload length.
       Payload bytes themselves remain undisplayed for now. */

    printf("  ptype: %s(0x%X) ver=%u route=%s(0x%X)",
           onair_payload_name(pkt->ptype), (unsigned)pkt->ptype,
           (unsigned)pkt->ver,
           onair_route_name(pkt->rtype), (unsigned)pkt->rtype);

    if (pkt->has_transport) {
        printf(" tc1=0x%04X tc2=0x%04X", (unsigned)pkt->tc1, (unsigned)pkt->tc2);
    }

    printf(" path_len=%u payload_len=%u\n", (unsigned)pkt->path_len, (unsigned)pkt->payload_len);

    if (pkt->path_len) {
        printf("  path: ");
        print_path_compact(pkt->path, pkt->path_len);
        printf("\n");
    }
}
