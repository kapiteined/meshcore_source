#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
static uint16_t u16le(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static uint32_t u32le(const uint8_t *p) { return (uint32_t)(p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24)); }
void op_0C(const uint8_t *frame, size_t len) { if (len < 11) { printf("RESP_BATT_AND_STORAGE (0x0C): too_short len=%u\n", (unsigned)len); return; } uint16_t mv = u16le(&frame[1]); uint32_t used_kb = u32le(&frame[3]); uint32_t total_kb = u32le(&frame[7]); printf("RESP_BATT_AND_STORAGE (0x0C): battery=%u mV, storage=%lu/%lu kB\n", (unsigned)mv, (unsigned long)used_kb, (unsigned long)total_kb); }
