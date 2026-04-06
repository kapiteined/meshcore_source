
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include "ack_gen.h"

static void meshcore_txtmsg_ack_crc(
        uint8_t out_crc4[4],
        const uint8_t timestamp_le[4],
        uint8_t attempt,
        const uint8_t *msg, size_t msg_len,
        const uint8_t sender_pubkey[32])
{
    uint8_t digest[32];
    SHA256_CTX ctx;

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, timestamp_le, 4);
    SHA256_Update(&ctx, &attempt, 1);
    SHA256_Update(&ctx, msg, msg_len);
    SHA256_Update(&ctx, sender_pubkey, 32);
    SHA256_Final(digest, &ctx);

    memcpy(out_crc4, digest, 4);
}

size_t meshcore_build_txtmsg_ack(
        uint8_t *out,
        uint32_t timestamp,
        uint8_t attempt,
        const uint8_t *msg, size_t msg_len,
        const uint8_t sender_pubkey[32])
{
    uint8_t crc[4];

    meshcore_txtmsg_ack_crc(
        crc,
        (const uint8_t *)&timestamp,
        attempt,
        msg, msg_len,
        sender_pubkey
    );

    out[0] = (0x03 << 2) | 0x01; /* ACK, FLOOD */
    out[1] = 0x00;             /* path_len = 0 */
    memcpy(&out[2], crc, 4);

    return 6;
}
