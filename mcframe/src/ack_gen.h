
#pragma once
#include <stdint.h>
#include <stddef.h>

size_t meshcore_build_txtmsg_ack(
        uint8_t *out,
        uint32_t timestamp,
        uint8_t attempt,
        const uint8_t *msg, size_t msg_len,
        const uint8_t sender_pubkey[32]);
