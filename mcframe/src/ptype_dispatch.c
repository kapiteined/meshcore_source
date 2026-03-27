#include "ptype_dispatch.h"

void ptype_default(const onair_packet_t *pkt);
void ptype_path(const onair_packet_t *pkt);
void ptype_ack(const onair_packet_t *pkt);

void ptype_dispatch(const onair_packet_t *pkt) {
    if (!pkt) return;

    switch (pkt->ptype) {
        case 0x08:
            ptype_path(pkt);
            break;
        case 0x03:
            ptype_ack(pkt);
            break;
        default:
            ptype_default(pkt);
            break;
    }
}
