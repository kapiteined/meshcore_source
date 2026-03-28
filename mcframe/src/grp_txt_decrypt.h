#ifndef GRP_TXT_DECRYPT_H
#define GRP_TXT_DECRYPT_H

#include <stddef.h>
#include <stdint.h>

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
