#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"
#include "util_hex.h"
#include "util_channels.h"

static uint16_t u16le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3) ", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t  chan_hash = p[0];
    uint16_t mac       = u16le16(&p[1]);

    /* ciphertext starts after chan_hash (1) + mac (2) */
    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u ", (unsigned)chan_hash, (unsigned)mac, ct_len);

    /* raw outer bytes + central label */
    const char *label = util_chan_hash_label(chan_hash);
    printf("  GRP_TXT raw (chan_hash+mac+ciphertext) (label=%s): ", label);
    util_hex_dump(pkt->payload, pkt->payload_len);
    printf(" ");

    util_print_undecryptable_ciphertext("GRP_TXT", ct, ct_len);
}
