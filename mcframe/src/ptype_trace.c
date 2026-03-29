#include <stdio.h>
#include <stdint.h>

#include "onair.h"

/* TRACE (ptype 0x09)
 *
 * For TRACE packets (route=DIRECT), MeshCore uses the packet's path[] field
 * as an SNR accumulator: each forwarding hop appends (int8_t)(snr*4).
 * The intended hop list (node hashes) is carried inside the TRACE payload.
 *
 * We print the planned hops and the collected SNR samples side-by-side.
 */

static void print_hash_no_prefix(const uint8_t *p, unsigned n)
{
    for (unsigned i = 0; i < n; i++) printf("%02X", p[i]);
}

void ptype_trace(const onair_packet_t *pkt)
{
    if (!pkt) return;

    /* Need at least: trace_tag(4) + auth_code(4) + flags(1) */
    if (pkt->payload_len < 9) {
        printf("  TRACE: payload too short (%u)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *pl = pkt->payload;
    uint32_t trace_tag = (uint32_t)pl[0] | ((uint32_t)pl[1] << 8) | ((uint32_t)pl[2] << 16) | ((uint32_t)pl[3] << 24);
    uint32_t auth_code = (uint32_t)pl[4] | ((uint32_t)pl[5] << 8) | ((uint32_t)pl[6] << 16) | ((uint32_t)pl[7] << 24);
    uint8_t flags = pl[8];

    /* v1.11+ convention (as used in Mesh.cpp): lower 2 bits encode hop-hash size as 1<<path_sz */
    unsigned path_sz = (unsigned)(flags & 0x03);
    unsigned hop_hash_sz = 1u << path_sz;

    const uint8_t *hoplist = pl + 9;
    unsigned hoplist_len = (unsigned)(pkt->payload_len - 9);
    unsigned planned_hops = hop_hash_sz ? (hoplist_len / hop_hash_sz) : 0;

    printf("  TRACE: tag=0x%08X auth=0x%08X flags=0x%02X hop_hash_sz=%u planned_hops=%u snr_samples=%u\n",
           trace_tag, auth_code, (unsigned)flags, hop_hash_sz, planned_hops, (unsigned)pkt->hop_count);

    if (planned_hops) {
        printf("  planned hops (%u): ", planned_hops);
        for (unsigned i = 0; i < planned_hops; i++) {
            if (i) printf("->");
            print_hash_no_prefix(hoplist + i * hop_hash_sz, hop_hash_sz);
        }
        printf("\n");
    }

    /* Side-by-side: hop[i] with snr[i] if present */
    unsigned rows = planned_hops;
    if (pkt->hop_count > rows) rows = pkt->hop_count;

    for (unsigned i = 0; i < rows; i++) {
        printf("  hop[%u]=", i);
        if (i < planned_hops) {
            print_hash_no_prefix(hoplist + i * hop_hash_sz, hop_hash_sz);
        } else {
            printf("--");
        }

        printf("  snr=");
        if (i < pkt->hop_count && pkt->path && pkt->path_bytes) {
            int8_t q = (int8_t)pkt->path[i];
            double snr_db = ((double)q) / 4.0;
            printf("%.2f dB", snr_db);
        } else {
            printf("--");
        }
        printf("\n");
    }
}
