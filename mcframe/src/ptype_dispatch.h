#ifndef PTYPE_DISPATCH_H
#define PTYPE_DISPATCH_H

#include "onair.h"

/** Dispatch an on-air packet payload based on pkt->ptype. */
void ptype_dispatch(const onair_packet_t *pkt);

#endif
