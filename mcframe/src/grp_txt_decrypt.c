#include <string.h>
#include "grp_txt_decrypt.h"
#include "util_crypto.h"

#define MAX_PAYLOAD 512

typedef unsigned char u8;
typedef unsigned int u32;

int grp_txt_decrypt_and_parse(const uint8_t *payload, uint16_t payload_len,
                              const char *label_hex,
                              uint32_t *timestamp_out,
                              uint8_t *txt_type_out,
                              uint8_t *attempt_out,
                              uint8_t signer_prefix_out[4],
                              int *has_signer_prefix_out,
                              int *mac_ok_out,
                              char *msg_out, size_t msg_out_len)
{
  u8 secret32[32];
  u8 hmac_out[32];
  u8 plain[MAX_PAYLOAD];
  u32 mac_expected, mac_computed;
  const u8 *ct;
  int ct_len;
  int blocks;
  u8 flags;
  u8 txt_type;
  u8 attempt;
  int body_off;
  size_t tlen;
  size_t i;

  if (timestamp_out) *timestamp_out = 0;
  if (txt_type_out) *txt_type_out = 0;
  if (attempt_out) *attempt_out = 0;
  if (has_signer_prefix_out) *has_signer_prefix_out = 0;
  if (mac_ok_out) *mac_ok_out = 0;
  if (msg_out && msg_out_len > 0) msg_out[0] = '\0';

  if (!payload || payload_len < 3 || !label_hex || !msg_out || msg_out_len == 0) return -1;

  memset(secret32, 0, sizeof(secret32));
  if (util_crypto_from_hex(secret32, 16, label_hex) != 16) return -1;

  mac_expected = (u32)payload[1] | ((u32)payload[2] << 8);
  ct = (const u8 *)(payload + 3);
  ct_len = (int)payload_len - 3;

  if (ct_len <= 0 || (ct_len % 16) != 0) return -1;
  if (ct_len > (int)sizeof(plain)) return -1;
  blocks = ct_len / 16;

  util_crypto_hmac_sha256(secret32, 32, ct, (size_t)ct_len, hmac_out);
  mac_computed = (u32)hmac_out[0] | ((u32)hmac_out[1] << 8);
  if (mac_ok_out) *mac_ok_out = (mac_computed == mac_expected) ? 1 : 0;

  util_crypto_aes128_ecb_decrypt(secret32, ct, plain, blocks);

  if (ct_len < 5) return -1;
  if (timestamp_out) {
    *timestamp_out = (u32)plain[0] | ((u32)plain[1] << 8) | ((u32)plain[2] << 16) | ((u32)plain[3] << 24);
  }

  flags = plain[4];
  attempt = (u8)(flags & 0x03);
  txt_type = (u8)((flags >> 2) & 0x3F);
  if (txt_type_out) *txt_type_out = txt_type;
  if (attempt_out) *attempt_out = attempt;

  body_off = 5;
  if (txt_type == 2 && ct_len >= 9) {
    if (signer_prefix_out) {
      signer_prefix_out[0] = plain[5];
      signer_prefix_out[1] = plain[6];
      signer_prefix_out[2] = plain[7];
      signer_prefix_out[3] = plain[8];
    }
    if (has_signer_prefix_out) *has_signer_prefix_out = 1;
    body_off = 9;
  }

  tlen = 0;
  while ((int)(body_off + (int)tlen) < ct_len && plain[body_off + tlen] != '\0') tlen++;
  if (tlen + 1 > msg_out_len) tlen = msg_out_len - 1;
  for (i = 0; i < tlen; i++) msg_out[i] = (char)plain[body_off + i];
  msg_out[tlen] = '\0';

  return 0;
}
