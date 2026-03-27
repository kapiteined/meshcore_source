#include "onair.h"
static uint16_t u16le(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
int onair_parse(const uint8_t *raw, size_t raw_len, onair_packet_t *out) {
    if (!raw || !out || raw_len < 2) return -1;
    out->header = raw[0];
    out->rtype = out->header & 0x03;
    out->ptype = (out->header >> 2) & 0x0F;
    out->ver   = (out->header >> 6) & 0x03;
    size_t i = 1;
    out->has_transport = (out->rtype == 0 || out->rtype == 3);
    out->tc1 = out->tc2 = 0;
    if (out->has_transport) {
        if (raw_len < i + 4) return -2;
        out->tc1 = u16le(&raw[i]);
        out->tc2 = u16le(&raw[i + 2]);
        i += 4;
    }
    if (raw_len < i + 1) return -3;
    out->path_len_raw = raw[i++];
    out->hash_size = (uint8_t)(((out->path_len_raw >> 6) & 0x03) + 1);
    out->hop_count = (uint8_t)(out->path_len_raw & 0x3F);
    out->path_bytes = (uint8_t)(out->hash_size * out->hop_count);
    if (out->path_bytes > 64) return -4;
    if (raw_len < i + out->path_bytes) return -5;
    out->path = &raw[i];
    i += out->path_bytes;
    out->payload = &raw[i];
    out->payload_len = raw_len - i;
    return 0;
}
const char* onair_route_name(uint8_t rt) {
    switch (rt) { case 0: return "TRANSPORT_FLOOD"; case 1: return "FLOOD"; case 2: return "DIRECT"; case 3: return "TRANSPORT_DIRECT"; default: return "RT_UNKNOWN"; }
}
const char* onair_payload_name(uint8_t pt) {
    switch (pt) {
        case 0x00: return "REQ"; case 0x01: return "RESPONSE"; case 0x02: return "TXT_MSG"; case 0x03: return "ACK";
        case 0x04: return "ADVERT"; case 0x05: return "GRP_TXT"; case 0x06: return "GRP_DATA"; case 0x07: return "ANON_REQ";
        case 0x08: return "PATH"; case 0x09: return "TRACE"; case 0x0A: return "MULTIPART"; case 0x0B: return "CONTROL"; case 0x0F: return "RAW_CUSTOM";
        default: return "PT_UNKNOWN";
    }
}
