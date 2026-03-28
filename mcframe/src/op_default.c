#include <stdio.h>
#include <stdint.h>

#include "util_hex.h"

void op_default(uint8_t opcode, const uint8_t *payload, unsigned len)
{
    printf("UNKNOWN_TOPLEVEL (0x%02X): len=%u (nog niet gedecodeerd)\n", (unsigned)opcode, (unsigned)len);
    if (payload && len > 0) {
        printf("  hexdump: ");
        util_hex_dump(payload, (size_t)len);
        printf("\n");
    }
}
