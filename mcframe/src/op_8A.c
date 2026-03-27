#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
void op_8A(const uint8_t *frame, size_t len) { printf("PUSH_NEW_ADVERT (0x8A): len=%u\n", (unsigned)len); (void)frame; }
