#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#define PUB_KEY_SIZE 32
void op_80(const uint8_t *frame, size_t len) {
    if (len < 1 + PUB_KEY_SIZE) {
        printf("PUSH_ADVERT (0x80): too_short len=%u\n", (unsigned)len);
        return;
    }
    printf("PUSH_ADVERT (0x80): len=%u pubkey=", (unsigned)len);
    for (int i = 0; i < PUB_KEY_SIZE; i++) printf("%02x", frame[1 + i]);
    printf("\n");
}
