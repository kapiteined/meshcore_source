#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "ptype_dispatch.h"
#include "util_hex.h"
#include "txt_msg_decrypt.h"
#include "mc_companion_dm.h"

static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

static int is_ack_message_text(const char *s) {
  if (!s) return 0;
  return (strncmp(s, "@ack ", 5) == 0) || (strncmp(s, "ACK ", 4) == 0) || (strncmp(s, "ACK:", 4) == 0);
}

void ptype_txt_msg(const onair_packet_t *pkt) {
  if (pkt->payload_len < 4) {
    fprintf(stderr, " TXT_MSG outer: too_short payload_len=%u (need >=4)\n", (unsigned)pkt->payload_len);
    return;
  }

  const uint8_t *p = pkt->payload;
  uint8_t dst_hash = p[0];
  uint8_t src_hash = p[1];
  uint16_t mac = u16le16(&p[2]);
  unsigned ct_len = (unsigned)pkt->payload_len - 4;
  const uint8_t *ct = &p[4];

  fprintf(stderr, " TXT_MSG outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
          (unsigned)dst_hash, (unsigned)src_hash, (unsigned)mac, ct_len);

  txt_msg_result_t r;
  int rc = txt_msg_decrypt_and_parse(dst_hash, src_hash, mac, ct, (uint16_t)ct_len, &r);
  if (rc == 0) {
    fprintf(stderr, " TXT_MSG decrypted: from=%s to=%s ts=%u type=%u attempt=%u msg=\"%s\"\n",
            r.from_label ? r.from_label : "?",
            r.to_label ? r.to_label : "?",
            (unsigned)r.timestamp,
            (unsigned)r.txt_type,
            (unsigned)r.attempt,
            r.msg);

    // Receipt ACK-DM policy:
    // - default ack=0 (opt-in) via pubkeys.txt -> r.from_ack
    // - never ack ack-messages to avoid loops
    if (r.from_ack && !is_ack_message_text(r.msg)) {
      char ack_msg[128];
      snprintf(ack_msg, sizeof(ack_msg), "@ack ts=%u", (unsigned)r.timestamp);
      int s_rc = mc_companion_send_dm_prefix6_stdout(r.from_prefix6, ack_msg);
      if (s_rc == 0) {
        fprintf(stderr, " ACK_DM queued to %s (%02x%02x%02x%02x%02x%02x): %s\n",
                r.from_label ? r.from_label : "?",
                r.from_prefix6[0], r.from_prefix6[1], r.from_prefix6[2],
                r.from_prefix6[3], r.from_prefix6[4], r.from_prefix6[5],
                ack_msg);
      } else {
        fprintf(stderr, " ACK_DM failed rc=%d\n", s_rc);
      }
    }

    return;
  }

  util_print_undecryptable_ciphertext("TXT_MSG", ct, ct_len);
}
