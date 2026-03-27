#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

/*
  Reads MeshCore USB serial framed stream from stdin:

    [0x3E][len_lo][len_hi][payload...]

  Device->host commonly uses 0x3E ('>') with 16-bit little-endian length.

  This version:
  - reads ONLY from stdin (no file open support)
  - prints one line per frame: opcode + length
  - prints a summary at EOF

  Input examples:
    cat /dev/ttyACM0 | mcframe
    cat capture.bin | mcframe
*/

#define SYNC_BYTE 0x3E
#define MAX_FRAME 2048

/*
static uint16_t u16le(uint8_t lo, uint8_t hi) {
    return (uint16_t)(lo | ((uint16_t)hi << 8));
}
*/

static const char* opcode_name(uint8_t op) {
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

int main(void)
 {
 /* Large stdio buffer for bursty stdin input */
 static unsigned char stdin_buf[1 << 20]; /* 1 MiB */
 setvbuf(stdin, (char*)stdin_buf, _IOFBF, sizeof(stdin_buf));

 unsigned long counts[256];

 for (int i = 0; i < 256; i++) counts[i] = 0;

 int c;
 int lo=0;
 int hi=0;
 uint16_t len=0;
 uint8_t buf[MAX_FRAME];
 size_t got=0;
 uint8_t op=0;
 const char* name="";

 /** a frame start with SYNC_BYTE followed by the length of the datagram **/
 while(1)
  {
  c = fgetc(stdin);
  while (c != SYNC_BYTE )     /* Find sync byte */
   {
   c = fgetc(stdin);
   if (c == EOF) goto done;
   }
      
  lo = fgetc(stdin);
  hi = fgetc(stdin);
  if (lo == EOF || hi == EOF) break;

  len = 0;
  len = hi << 8 | lo;
  if (len == 0 || len > MAX_FRAME)
   {
   /* Invalid length → resync */
   continue;
   }

  got = fread(buf, 1, len, stdin);
  if (got != len) break;

  op = buf[0];
  counts[op]++;

  name = opcode_name(op);
   if (name)
    {
    printf("RX frame: opcode=0x%02X (%s), len=%u\n", op, name, (unsigned)len);
    }
   else
    {
    printf("RX frame: opcode=0x%02X, len=%u\n", op, (unsigned)len);
    }

        /*
          Later expansion point:

          switch (op) {
            case 0x88: ... on-air decode ...; break;
            case 0x8A: ... contact decode ...; break;
            default: break;
          }
        */
  }

done:
    printf("\n=== Summary (opcode counts) ===\n");
    for (int i = 0; i < 256; i++) {
        if (counts[i]) {
            const char* name = opcode_name((uint8_t)i);
            if (name)
                printf("0x%02X %-22s : %lu\n", i, name, counts[i]);
            else
                printf("0x%02X %-22s : %lu\n", i, "(unknown)", counts[i]);
        }
    }

    return 0;
}
