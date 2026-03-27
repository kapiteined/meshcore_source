#include <stdio.h>
#include <stdint.h>
#include "dispatch.h"

#define SYNC_BYTE 0x3E
#define MAX_FRAME 2048

static uint16_t u16le(uint8_t lo, uint8_t hi) { return (uint16_t)(lo | ((uint16_t)hi << 8)); }

int main(void) {
    static unsigned char stdin_buf[1 << 20];
    setvbuf(stdin, (char*)stdin_buf, _IOFBF, sizeof(stdin_buf));

    uint8_t buf[MAX_FRAME];

    while (1) {
        int c;
        do {
            c = fgetc(stdin);
            if (c == EOF) return 0;
        } while ((uint8_t)c != SYNC_BYTE);

        int lo = fgetc(stdin);
        int hi = fgetc(stdin);
        if (lo == EOF || hi == EOF) return 0;

        uint16_t len = u16le((uint8_t)lo, (uint8_t)hi);
        if (len == 0 || len > MAX_FRAME) continue;

        size_t got = fread(buf, 1, len, stdin);
        if (got != len) return 0;

        dispatch_frame(buf, (size_t)len);
    }
}
