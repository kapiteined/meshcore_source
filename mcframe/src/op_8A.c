#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define PUB_KEY_SIZE  32
#define MAX_PATH_SIZE 64

static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}

static int32_t i32le(const uint8_t *p) {
    return (int32_t)u32le(p);
}

static void print_path_compact(const uint8_t *path, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        if (i) printf("->");
        printf("%02X", path[i]);
    }
}

void op_8A(const uint8_t *frame, size_t len) {
    if (len < 148) {
        printf("PUSH_NEW_ADVERT (0x8A): too_short len=%u\n", (unsigned)len);
        return;
    }

    const uint8_t *pubkey = &frame[1];
    uint8_t ctype = frame[33];
    uint8_t flags = frame[34];
    uint8_t out_path_len = frame[35];
    const uint8_t *out_path = &frame[36];

    char name[33];
    memcpy(name, &frame[100], 32);
    name[32] = '\0';

    uint32_t last_adv_ts = u32le(&frame[132]);
    int32_t lat_i = i32le(&frame[136]);
    int32_t lon_i = i32le(&frame[140]);
    uint32_t lastmod = u32le(&frame[144]);

    printf("PUSH_NEW_ADVERT (0x8A): len=%u type=0x%02X flags=0x%02X out_path_len=0x%02X name='%s'\n",
           (unsigned)len, ctype, flags, out_path_len, name);

    printf("  pubkey=");
    for (int i = 0; i < PUB_KEY_SIZE; i++) printf("%02x", pubkey[i]);
    printf("\n");

    if (out_path_len == 0xFF) {
        printf("  out_path=(unknown)\n");
    } else {
        unsigned used = out_path_len;
        if (used > MAX_PATH_SIZE) used = MAX_PATH_SIZE;
        printf("  out_path=");
        print_path_compact(out_path, used);
        printf("\n");
    }

    if ((lat_i >= -90000000 && lat_i <= 90000000) && (lon_i >= -180000000 && lon_i <= 180000000)) {
        printf("  gps=%.6f,%.6f (raw %ld,%ld)\n", (double)lat_i / 1000000.0, (double)lon_i / 1000000.0, (long)lat_i, (long)lon_i);
    } else {
        printf("  gps_raw=%ld,%ld\n", (long)lat_i, (long)lon_i);
    }

    printf("  last_adv_ts=%lu lastmod=%lu\n", (unsigned long)last_adv_ts, (unsigned long)lastmod);
}
