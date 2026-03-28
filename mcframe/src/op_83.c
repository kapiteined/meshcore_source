#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "ops.h"
void op_83(const uint8_t *frame, size_t len) { (void)frame; if (len != 1) { printf("PUSH_MSG_WAITING (0x83): len=%u (expected 1)\n", (unsigned)len); return; } printf("PUSH_MSG_WAITING (0x83): len=1\n"); }
