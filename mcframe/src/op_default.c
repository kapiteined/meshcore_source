#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

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

void op_default(const uint8_t *frame, size_t len) {
    const char *name = opcode_name(frame[0]);
    if (name) {
        printf("RX frame: opcode=0x%02X (%s), len=%u\n", frame[0], name, (unsigned)len);
    } else {
        printf("RX frame: opcode=0x%02X, len=%u\n", frame[0], (unsigned)len);
    }
}
