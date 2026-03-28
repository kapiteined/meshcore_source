#include <stdio.h>

#include "dispatch.h"
#include "ops.h"

void dispatch_frame(const uint8_t *frame, size_t len)
{
    if (!frame || len == 0) return;

    switch (frame[0]) {
        case 0x80: op_80(frame, len); break;
        case 0x83: op_83(frame, len); break;
        case 0x88: op_88(frame, len); break;
        case 0x8A: op_8A(frame, len); break;
        case 0x0C: op_0C(frame, len); break;
        default:   op_default(frame, len); break;
    }

    putchar('\n');
}
