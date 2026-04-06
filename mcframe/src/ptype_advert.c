#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ptype_dispatch.h"

static uint32_t u32le(const uint8_t *p) { return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24)); }
static int32_t i32le(const uint8_t *p) { return (int32_t)u32le(p); }
static uint16_t u16le(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static void print_hex(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", p[i]); }

void ptype_advert(const onair_packet_t *pkt)
    {
    if (pkt->payload_len < 100) { printf("  ADVERT: too_short payload_len=%u (need >=100)\n", (unsigned)pkt->payload_len); return; }
    const uint8_t *p = pkt->payload;
    const uint8_t *pub = &p[0];
    uint32_t ts = u32le(&p[32]);
    const uint8_t *sig = &p[36];
    const uint8_t *app = &p[100];
    size_t app_len = pkt->payload_len - 100;
    printf("  ADVERT: pubkey="); print_hex(pub, 32); printf(" ts=%lu app_len=%u\n", (unsigned long)ts, (unsigned)app_len);
    printf("  ADVERT: sig_prefix="); print_hex(sig, 4); printf("...\n");
    if (app_len == 0) { printf("  ADVERT appdata: (none)\n"); return; }
    size_t i = 0;
    uint8_t flags = app[i++];
    printf("  --------------------------------------------------------------------------------------\n");
    printf("  ADVERT appdata: flags=0x%02X", (unsigned)flags);

    if (flags & 0x10)
     {
     if (app_len < i + 8) { printf(" (truncated location)\n"); return; }
     int32_t lat_i = i32le(&app[i]);
     int32_t lon_i = i32le(&app[i + 4]);
     i += 8;
     printf(" loc=%.6f,%.6f", (double)lat_i/1000000.0, (double)lon_i/1000000.0);
     }

    if (flags & 0x20) { if (app_len < i + 2) { printf(" (truncated feature1)\n"); return; } uint16_t f1 = u16le(&app[i]); i += 2; printf(" f1=0x%04X", (unsigned)f1); }
    if (flags & 0x40) { if (app_len < i + 2) { printf(" (truncated feature2)\n"); return; } uint16_t f2 = u16le(&app[i]); i += 2; printf(" f2=0x%04X", (unsigned)f2); }
    if (flags & 0x80)
     {
     size_t nlen = (app_len > i) ? (app_len - i) : 0;
     char name[65];
     size_t copy = nlen; if (copy > 64) copy = 64;
     if (copy) memcpy(name, &app[i], copy);
     name[copy] = '\0';
     printf(" name='%s'", name);
     }
    printf("\n");
    printf("  --------------------------------------------------------------------------------------\n");
    }
