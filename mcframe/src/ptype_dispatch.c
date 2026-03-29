#include <stdio.h>
#include "ptype_dispatch.h"

void ptype_default(const onair_packet_t *pkt);
void ptype_req(const onair_packet_t *pkt);
void ptype_response(const onair_packet_t *pkt);
void ptype_txt_msg(const onair_packet_t *pkt);
void ptype_ack(const onair_packet_t *pkt);
void ptype_advert(const onair_packet_t *pkt);
void ptype_grp_txt(const onair_packet_t *pkt);
void ptype_path(const onair_packet_t *pkt);
void ptype_trace(const onair_packet_t *pkt);

static void print_path_compact(const onair_packet_t *pkt) {
    if (!pkt || pkt->path_bytes == 0) return;
    for (unsigned hop = 0; hop < pkt->hop_count; hop++) {
        if (hop) printf("->");
        const uint8_t *p = pkt->path + (hop * pkt->hash_size);
        for (unsigned j = 0; j < pkt->hash_size; j++) printf("%02X", p[j]);
    }
}

static void ptype_print_common(const onair_packet_t *pkt) {
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
}

void ptype_dispatch(const onair_packet_t *pkt) {
    if (!pkt) return;

    ptype_print_common(pkt);

    switch (pkt->ptype) {
        case 0x00: ptype_req(pkt); break;
        case 0x01: ptype_response(pkt); break;
        case 0x02: ptype_txt_msg(pkt); break;
        case 0x03: ptype_ack(pkt); break;
        case 0x04: ptype_advert(pkt); break;
        case 0x05: ptype_grp_txt(pkt); break;
        case 0x08: ptype_path(pkt); break;
        case 0x09: ptype_trace(pkt); break;
        default:   ptype_default(pkt); break;
    }
}
