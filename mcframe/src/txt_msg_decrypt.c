#include <string.h>
#include "txt_msg_decrypt.h"
#include "util_crypto.h"
#include "util_privkeys.h"
#include "util_pubkeys.h"
#include "crypto/ed25519/ed_25519.h"

static uint32_t u32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void ensure_keys_loaded(void) {
  if (!util_privkeys_is_loaded()) util_privkeys_load("./privkeys.txt");
  if (!util_pubkeys_is_loaded())  util_pubkeys_load("./pubkeys.txt");
}

int txt_msg_decrypt_and_parse(uint8_t dst_hash, uint8_t src_hash,
                              uint16_t mac_le,
                              const uint8_t *ciphertext, uint16_t ct_len,
                              txt_msg_result_t *out)
{
  size_t i, j;
  uint8_t shared[32];
  uint8_t h[32];
  uint8_t plain[512];
  int blocks;

  if (!ciphertext || !out || ct_len == 0 || (ct_len % 16) != 0) return -1;
  memset(out, 0, sizeof(*out));
  ensure_keys_loaded();

  blocks = (int)(ct_len / 16);
  if ((size_t)ct_len > sizeof(plain)) return -2;

  for (i = 0; i < util_privkeys_count(); i++) {
    const util_privkey_t *self = util_privkeys_get(i);
    if (!self || self->hash != dst_hash) continue;

    for (j = 0; j < util_pubkeys_count(); j++) {
      const util_pubkey_t *peer = util_pubkeys_get(j);
      uint16_t mac_calc;
      const uint8_t *body;
      size_t tlen;
      uint8_t flags;

      if (!peer || peer->hash != src_hash) continue;

      ed25519_key_exchange(shared, peer->pub, self->priv);
      util_crypto_hmac_sha256(shared, 32, ciphertext, ct_len, h);
      mac_calc = (uint16_t)h[0] | ((uint16_t)h[1] << 8);
      if (mac_calc != mac_le) continue;

      out->mac_ok = 1;
      util_crypto_aes128_ecb_decrypt(shared, ciphertext, plain, blocks);

      out->timestamp = u32le(plain);
      flags = plain[4];
      out->attempt = (uint8_t)(flags & 0x03);
      out->txt_type = (uint8_t)((flags >> 2) & 0x3F);

      body = plain + 5;
      tlen = 0;
      while (tlen < (size_t)ct_len - 5 && body[tlen] != '\0') tlen++;
      if (tlen >= sizeof(out->msg)) tlen = sizeof(out->msg) - 1;
      memcpy(out->msg, body, tlen);
      out->msg[tlen] = 0;

      out->from_label = peer->label;
      out->to_label = self->label;
      return 0;
    }
  }

  return 1;
}
