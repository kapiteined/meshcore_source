#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

#include "ops.h"
#include "util_hex.h"

void op_default(const uint8_t *frame, size_t len)
{
    if (!frame || len == 0) {
        printf("UNKNOWN_TOPLEVEL: len=%u (leeg)", (unsigned)len);
        putchar('\n');
        return;
    }

    printf("UNKNOWN_TOPLEVEL (0x%02X): len=%u (nog niet gedecodeerd)", (unsigned)frame[0], (unsigned)len);
    putchar('\n');

    printf("  hexdump: ");
    util_hex_dump(frame, len);
    putchar('\n');
}
