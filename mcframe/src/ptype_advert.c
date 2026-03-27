#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "ptype_dispatch.h"

/*
  PAYLOAD_TYPE_ADVERT (0x04) (Node advertisement) payload format (per MeshCore docs):
    public_key  32
    timestamp    4 (unix)
    signature   64 (Ed25519 over public_key, timestamp, appdata)
    appdata     rest

  Appdata:
    flags       1
    latitude    4 (optional, int32: degrees * 1e6) if flags & 0x10
    longitude   4 (optional, int32: degrees * 1e6) if flags & 0x10
    feature1    2 (optional) if flags & 0x20
    feature2    2 (optional) if flags & 0x40
    name        rest if flags & 0x80

  This decoder prints key fields and appdata summary; it does not verify signature.
*/

static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static int32_t i32le(const uint8_t *p) {
    return (int32_t)u32le(p);
}

static uint16_t u16le(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static void print_hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

void ptype_advert(const onair_packet_t *pkt) {
    /* Need at least 32 + 4 + 64 */
    if (pkt->payload_len < 100) {
        printf("  ADVERT: too_short payload_len=%u (need >=100)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    const uint8_t *pub = &p[0];
    uint32_t ts = u32le(&p[32]);
    const uint8_t *sig = &p[36];
    const uint8_t *app = &p[100];
    size_t app_len = pkt->payload_len - 100;

    printf("  ADVERT: pubkey=");
    print_hex(pub, 32);
    printf(" ts=%lu app_len=%u\n", (unsigned long)ts, (unsigned)app_len);

    /* Do not dump full signature; just show first 4 bytes for debugging */
    printf("  ADVERT: sig_prefix=");
    print_hex(sig, 4);
    printf("...\n");

    if (app_len == 0) {
        printf("  ADVERT appdata: (none)\n");
        return;
    }

    size_t i = 0;
    uint8_t flags = app[i++];
    printf("  ADVERT appdata: flags=0x%02X", (unsigned)flags);

    int has_loc = (flags & 0x10) != 0;
    int has_f1  = (flags & 0x20) != 0;
    int has_f2  = (flags & 0x40) != 0;
    int has_name= (flags & 0x80) != 0;

    if (has_loc) {
        if (app_len < i + 8) {
            printf(" (truncated location)\n");
            return;
        }
        int32_t lat_i = i32le(&app[i]);
        int32_t lon_i = i32le(&app[i + 4]);
        i += 8;
        printf(" loc=%.6f,%.6f", (double)lat_i/1000000.0, (double)lon_i/1000000.0);
    }

    if (has_f1) {
        if (app_len < i + 2) { printf(" (truncated feature1)\n"); return; }
        uint16_t f1 = u16le(&app[i]);
        i += 2;
        printf(" f1=0x%04X", (unsigned)f1);
    }

    if (has_f2) {
        if (app_len < i + 2) { printf(" (truncated feature2)\n"); return; }
        uint16_t f2 = u16le(&app[i]);
        i += 2;
        printf(" f2=0x%04X", (unsigned)f2);
    }

    if (has_name) {
        if (app_len <= i) {
            printf(" name=''\n");
            return;
        }
        size_t nlen = app_len - i;
        char name[65];
        size_t copy = nlen;
        if (copy > 64) copy = 64;
        memcpy(name, &app[i], copy);
        name[copy] = '\0';
        /* trim at first NUL */
        for (size_t k = 0; k < copy; k++) {
            if (name[k] == '\0') { name[k] = '\0'; break; }
        }
        printf(" name='%s'", name);
    }

    printf("\n");
}
