#include <stdio.h>
#include <stdint.h>
#include "dispatch.h"

/*
  Reads MeshCore USB serial framed stream from stdin:

    [0x3E][len_lo][len_hi][payload...]

  Device->host commonly uses 0x3E ('>') with 16-bit little-endian length.

  This version:
  - reads ONLY from stdin
  - uses setvbuf(stdin, ...) for bursty input
  - hands complete payload frames to dispatch_frame() (one file per opcode)
*/

#define SYNC_BYTE 0x3E
#define MAX_FRAME 2048

static uint16_t u16le(uint8_t lo, uint8_t hi) {
    return (uint16_t)(lo | ((uint16_t)hi << 8));
}

int main(void) {
    /* Large stdio buffer for bursty stdin input */
    static unsigned char stdin_buf[1 << 20]; /* 1 MiB */
    setvbuf(stdin, (char*)stdin_buf, _IOFBF, sizeof(stdin_buf));

    uint8_t buf[MAX_FRAME];

    while (1) {
        int c;

        /* Scan for sync byte */
        do {
            c = fgetc(stdin);
            if (c == EOF) return 0;
        } while ((uint8_t)c != SYNC_BYTE);

        /* Read length (u16 little-endian) */
        int lo = fgetc(stdin);
        int hi = fgetc(stdin);
        if (lo == EOF || hi == EOF) return 0;

        uint16_t len = u16le((uint8_t)lo, (uint8_t)hi);
        if (len == 0 || len > MAX_FRAME) {
            /* Invalid length -> resync */
            continue;
        }

        size_t got = fread(buf, 1, len, stdin);
        if (got != len) return 0;

        dispatch_frame(buf, (size_t)len);
    }
}
