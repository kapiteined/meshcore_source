#include "ptype_dispatch.h"

void ptype_default(const onair_packet_t *pkt);
void ptype_path(const onair_packet_t *pkt);

void ptype_dispatch(const onair_packet_t *pkt) {
    if (!pkt) return;

    switch (pkt->ptype) {
        case 0x08: /* PATH */
            ptype_path(pkt);
            break;
        default:
            ptype_default(pkt);
            break;
    }
}
