#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "onair.h"
#include "ptype_dispatch.h"
static int8_t i8(uint8_t b) { return (int8_t)b; }
void op_88(const uint8_t *frame, size_t len) {
    if (len < 4) { printf("PUSH_LOG_RX_DATA (0x88): too_short len=%u\n", (unsigned)len); return; }
    double snr_db = (double)i8(frame[1]) / 4.0;
    int rssi_dbm = (int)i8(frame[2]);
    const uint8_t *raw = frame + 3;
    size_t raw_len = len - 3;
    onair_packet_t pkt;
    int rc = onair_parse(raw, raw_len, &pkt);
    if (rc != 0) {
        printf("PUSH_LOG_RX_DATA (0x88): snr=%.2f dB rssi=%d dBm raw_len=%u (onair_parse rc=%d)\n", snr_db, rssi_dbm, (unsigned)raw_len, rc);
        return;
    }
    printf("PUSH_LOG_RX_DATA (0x88): snr=%.2f dB rssi=%d dBm raw_len=%u\n", snr_db, rssi_dbm, (unsigned)raw_len);
    ptype_dispatch(&pkt);
}
