#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
  Reads MeshCore USB serial framed stream:
    [0x3E][len_lo][len_hi][payload...]
  Device->host commonly uses 0x3E ('>') with 16-bit little-endian length.

  This first version only dumps which opcode types are seen.
  Later we can add a switch(opcode) and decode each type.
*/

#define SYNC_BYTE 0x3E
#define MAX_FRAME 2048

static uint16_t u16le(uint8_t lo, uint8_t hi) {
    return (uint16_t)(lo | ((uint16_t)hi << 8));
}

static const char* opcode_name(uint8_t op) {
    /* Small start: name a few common ones; everything else prints as hex. */
    switch (op) {
        case 0x88: return "PUSH_LOG_RX_DATA";
        case 0x83: return "PUSH_MSG_WAITING";
        case 0x80: return "PUSH_ADVERT";
        case 0x8A: return "PUSH_NEW_ADVERT";
        case 0x0C: return "RESP_BATT_AND_STORAGE";
        case 0x0D: return "RESP_DEVICE_INFO";
        case 0x10: return "RESP_CONTACT_MSG_RECV_V3";
        case 0x11: return "RESP_CHANNEL_MSG_RECV_V3";
        case 0x12: return "RESP_CHANNEL_INFO";
        default:   return NULL;
    }
}

int main(int argc, char** argv) {
    FILE* fp = stdin;
    if (argc == 2) {
        fp = fopen(argv[1], "rb");
        if (!fp) {
            perror("fopen");
            return 1;
        }
    } else if (argc > 2) {
        fprintf(stderr, "Usage: %s [usb_stream.bin]\n", argv[0]);
        return 2;
    }

    unsigned long counts[256];
    for (int i = 0; i < 256; i++) counts[i] = 0;

    int c;
    for (;;) {
        /* Find sync byte */
        do {
            c = fgetc(fp);
            if (c == EOF) goto done;
        } while ((uint8_t)c != SYNC_BYTE);

        int lo = fgetc(fp);
        int hi = fgetc(fp);
        if (lo == EOF || hi == EOF) break;

        uint16_t len = u16le((uint8_t)lo, (uint8_t)hi);
        if (len == 0 || len > MAX_FRAME) {
            /* Invalid length, resync */
            continue;
        }

        uint8_t buf[MAX_FRAME];
        size_t got = fread(buf, 1, len, fp);
        if (got != len) break;

        uint8_t op = buf[0];
        counts[op]++;

        const char* name = opcode_name(op);
        if (name) {
            printf("RX frame: opcode=0x%02X (%s), len=%u\n", op, name, (unsigned)len);
        } else {
            printf("RX frame: opcode=0x%02X, len=%u\n", op, (unsigned)len);
        }

        /*
          Later expansion point:

          switch (op) {
            case 0x88: ... parse ...; break;
            case 0x8A: ... parse ...; break;
            default: break;
          }
        */
    }

done:
    if (fp != stdin) fclose(fp);

    printf("\n=== Summary (opcode counts) ===\n");
    for (int i = 0; i < 256; i++) {
        if (counts[i]) {
            const char* name = opcode_name((uint8_t)i);
            if (name) printf("0x%02X %-22s : %lu\n", i, name, counts[i]);
            else      printf("0x%02X %-22s : %lu\n", i, "(unknown)", counts[i]);
        }
    }

    return 0;
}
