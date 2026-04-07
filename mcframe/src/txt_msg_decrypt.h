#ifndef TXT_MSG_DECRYPT_H
#define TXT_MSG_DECRYPT_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
  const char *from_label;
  const char *to_label;
  uint32_t timestamp;
  uint8_t txt_type;
  uint8_t attempt;
  int mac_ok;
  uint8_t from_prefix6[6];
  uint8_t from_ack;   /* ack policy for sender (from pubkeys.txt), default 0 */
  char msg[256];
} txt_msg_result_t;

int txt_msg_decrypt_and_parse(uint8_t dst_hash, uint8_t src_hash,
                              uint16_t mac_le,
                              const uint8_t *ciphertext, uint16_t ct_len,
                              txt_msg_result_t *out);

#endif
