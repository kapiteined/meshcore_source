#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include "ops.h"

#include "dispatch.h"

static void print_ts_prefix(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    struct tm tmv;
    {
        struct tm *ptm = localtime(&tv.tv_sec);
        if (ptm) tmv = *ptm;
        else memset(&tmv, 0, sizeof(tmv));
    }

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv);
    printf("[%s.%03ld] ", buf, (long)(tv.tv_usec / 1000));
}

void op_80(const uint8_t *frame, size_t len);
void op_83(const uint8_t *frame, size_t len);
void op_88(const uint8_t *frame, size_t len);
void op_8A(const uint8_t *frame, size_t len);
void op_0C(const uint8_t *frame, size_t len);
void op_default(const uint8_t *frame, size_t len);

void dispatch_frame(const uint8_t *frame, size_t len)
{
    if (!frame || len == 0) return;

    print_ts_prefix();

    switch (frame[0]) {
        case 0x80: op_80(frame, len); break;
        case 0x83: op_83(frame, len); break;
        case 0x88: op_88(frame, len); break;
        case 0x8A: op_8A(frame, len); break;
        case 0x0C: op_0C(frame, len); break;
        case 0x51: op_51(frame, len); break;
        default:   op_default(frame, len); break;
    }

    printf("\n");
}
