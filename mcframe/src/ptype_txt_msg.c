#include <stdio.h>
#include <stdint.h>
#include "ptype_dispatch.h"
#include "util_hex.h"
#include "txt_msg_decrypt.h"

static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

void ptype_txt_msg(const onair_packet_t *pkt) {
  if (pkt->payload_len < 4) {
    printf(" TXT_MSG outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len);
    return;
  }

  const uint8_t *p = pkt->payload;
  uint8_t dst_hash = p[0];
  uint8_t src_hash = p[1];
  uint16_t mac = u16le16(&p[2]);
  unsigned ct_len = (unsigned)pkt->payload_len - 4;
  const uint8_t *ct = &p[4];

  printf(" TXT_MSG outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
         (unsigned)dst_hash, (unsigned)src_hash, (unsigned)mac, ct_len);

  txt_msg_result_t r;
  int rc = txt_msg_decrypt_and_parse(dst_hash, src_hash, mac, ct, (uint16_t)ct_len, &r);
  if (rc == 0) {
    printf(" TXT_MSG decrypted: from=%s to=%s ts=%u type=%u attempt=%u msg=\"%s\"\n",
           r.from_label ? r.from_label : "?",
           r.to_label ? r.to_label : "?",
           (unsigned)r.timestamp,
           (unsigned)r.txt_type,
           (unsigned)r.attempt,
           r.msg);
    return;
  }

  util_print_undecryptable_ciphertext("TXT_MSG", ct, ct_len);
}
