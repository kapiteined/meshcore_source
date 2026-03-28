#ifndef GRP_TXT_DECRYPT_H
#define GRP_TXT_DECRYPT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Decrypt and parse MeshCore GRP_TXT payload.
 *
 * Input payload is the GRP_TXT payload bytes (starting at chan_hash), length payload_len.
 * Expected layout: [chan_hash (1)] [mac (2, little-endian)] [ciphertext (N, AES-128-ECB, N%16==0)].
 *
 * label_hex is a 32-hex-char channel secret (16 bytes) string.
 *
 * Returns 0 on successful decrypt+parse, otherwise -1.
 */
int grp_txt_decrypt_and_parse(const uint8_t *payload, uint16_t payload_len,
                             const char *label_hex,
                             uint32_t *timestamp_out,
                             uint8_t *txt_type_out,
                             uint8_t *attempt_out,
                             uint8_t signer_prefix_out[4],
                             int *has_signer_prefix_out,
                             int *mac_ok_out,
                             char *msg_out, size_t msg_out_len);

#endif
