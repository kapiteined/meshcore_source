#include <stdio.h>
#include <stdint.h>

#include "util_hex.h"

/* Default handler for unknown top-level companion codes.
 * Prints a short message plus a full hexdump of the payload.
 */
void op_default(uint8_t opcode, const uint8_t *payload, unsigned len)
{
    printf("UNKNOWN_TOPLEVEL (0x%02X): len=%u (nog niet gedecodeerd) ", (unsigned)opcode, (unsigned)len);

    if (payload && len > 0) {
        printf("  hexdump: ");
        util_hex_dump(payload, (size_t)len);
        printf(" ");
    }
}
