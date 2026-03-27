#ifndef ONAIR_H
#define ONAIR_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t header;
    uint8_t ver;
    uint8_t rtype;
    uint8_t ptype;
    int has_transport;
    uint16_t tc1;
    uint16_t tc2;
    uint8_t path_len;
    const uint8_t *path;
    const uint8_t *payload;
    size_t payload_len;
} onair_packet_t;

int onair_parse(const uint8_t *raw, size_t raw_len, onair_packet_t *out);

const char* onair_route_name(uint8_t rt);
const char* onair_payload_name(uint8_t pt);

#endif
