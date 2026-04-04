
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

void op_51(const uint8_t *frame, size_t len)
{
    printf("DEBUG opcode 0x51, len=%u", (unsigned)len);
    if (len <= 1) { printf(" (no payload)"); return; }
    const uint8_t *p = frame + 1; size_t plen = len - 1; size_t q_cnt = 0;
    for (size_t i=0;i<plen;i++) if (p[i]=='Q') q_cnt++;
    printf(", payload_len=%zu, Q_count=%zu", plen, q_cnt);
}
