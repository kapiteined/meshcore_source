#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

static int8_t i8(uint8_t b) { return (int8_t)b; }

void op_88(const uint8_t *frame, size_t len) {
    /* PUSH_LOG_RX_DATA (0x88): [0x88][snr*4][rssi][raw...] */
    if (len < 3) {
        printf("PUSH_LOG_RX_DATA (0x88): too_short len=%u\n", (unsigned)len);
        return;
    }

    double snr_db = (double)i8(frame[1]) / 4.0;
    int rssi_dbm = (int)i8(frame[2]);
    size_t raw_len = len - 3;

    /* Keep it minimal for now: just header info */
    printf("PUSH_LOG_RX_DATA (0x88): len=%u snr=%.2f dB rssi=%d dBm raw_len=%u\n",
           (unsigned)len, snr_db, rssi_dbm, (unsigned)raw_len);
}
