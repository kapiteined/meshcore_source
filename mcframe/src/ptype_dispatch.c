#include "ptype_dispatch.h"

/* Only add new files when we actually decode them.
   For now: everything goes to ptype_default(). */
void ptype_default(const onair_packet_t *pkt);

void ptype_dispatch(const onair_packet_t *pkt) {
    ptype_default(pkt);
}
