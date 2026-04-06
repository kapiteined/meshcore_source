
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ptype_dispatch.h"
#include "util_hex.h"
#include "txt_msg_decrypt.h"

#define SYNC_BYTE 0x3E
#define CMD_SEND_RAW_DATA 0x19

static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

static void print_ack_hex_stderr(const uint8_t *ack, size_t n)
{
  fputs("ACK_TX_DEBUG: ", stderr);
  for (size_t i = 0; i < n; i++) fprintf(stderr, "%02X", (unsigned)ack[i]);
  fputc(10, stderr); /* 
 */
  fflush(stderr);
}

static void emit_cmd_send_raw_data_stdout(const uint8_t *pkt, size_t pkt_len)
{
  /*
   * Host->device frame (USB serial) is length-prefixed and sync-delimited.
   * We send: SYNC(0x3E) + LEN(u16le) + CMD(0x19) + raw_packet_bytes
   * so it can be piped back into /dev/ttyACM0 via `tee`.
   */
  uint16_t len = (uint16_t)(1u + pkt_len); /* cmd byte + payload */

  fputc(SYNC_BYTE, stdout);
  fputc((int)(len & 0xFFu), stdout);
  fputc((int)((len >> 8) & 0xFFu), stdout);
  fputc((int)CMD_SEND_RAW_DATA, stdout);
  if (pkt_len) fwrite(pkt, 1, pkt_len, stdout);
  fflush(stdout);
}

/* Minimal SHA-256 (no external deps). */

typedef struct {
  uint32_t h[8];
  uint64_t len_bits;
  uint8_t  buf[64];
  size_t   buf_len;
} sha256_ctx_t;

static uint32_t rotr32(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static uint32_t bsig0(uint32_t x) { return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22); }
static uint32_t bsig1(uint32_t x) { return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25); }
static uint32_t ssig0(uint32_t x) { return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3); }
static uint32_t ssig1(uint32_t x) { return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >> 10); }

static const uint32_t k256[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

static void sha256_init(sha256_ctx_t *ctx)
{
  ctx->h[0]=0x6a09e667u; ctx->h[1]=0xbb67ae85u; ctx->h[2]=0x3c6ef372u; ctx->h[3]=0xa54ff53au;
  ctx->h[4]=0x510e527fu; ctx->h[5]=0x9b05688cu; ctx->h[6]=0x1f83d9abu; ctx->h[7]=0x5be0cd19u;
  ctx->len_bits = 0;
  ctx->buf_len = 0;
}

static void sha256_compress(sha256_ctx_t *ctx, const uint8_t block[64])
{
  uint32_t w[64];
  for (int i=0;i<16;i++) {
    w[i] = ((uint32_t)block[i*4+0] << 24)
         | ((uint32_t)block[i*4+1] << 16)
         | ((uint32_t)block[i*4+2] <<  8)
         | ((uint32_t)block[i*4+3] <<  0);
  }
  for (int i=16;i<64;i++) w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16];

  uint32_t a=ctx->h[0], b=ctx->h[1], c=ctx->h[2], d=ctx->h[3];
  uint32_t e=ctx->h[4], f=ctx->h[5], g=ctx->h[6], hv=ctx->h[7];

  for (int i=0;i<64;i++) {
    uint32_t t1 = hv + bsig1(e) + ch(e,f,g) + k256[i] + w[i];
    uint32_t t2 = bsig0(a) + maj(a,b,c);
    hv = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
  ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += hv;
}

static void sha256_update(sha256_ctx_t *ctx, const void *data, size_t len)
{
  const uint8_t *p = (const uint8_t*)data;
  ctx->len_bits += (uint64_t)len * 8u;

  while (len) {
    size_t take = 64 - ctx->buf_len;
    if (take > len) take = len;
    memcpy(ctx->buf + ctx->buf_len, p, take);
    ctx->buf_len += take;
    p += take;
    len -= take;
    if (ctx->buf_len == 64) {
      sha256_compress(ctx, ctx->buf);
      ctx->buf_len = 0;
    }
  }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t out[32])
{
  ctx->buf[ctx->buf_len++] = 0x80;

  if (ctx->buf_len > 56) {
    while (ctx->buf_len < 64) ctx->buf[ctx->buf_len++] = 0x00;
    sha256_compress(ctx, ctx->buf);
    ctx->buf_len = 0;
  }
  while (ctx->buf_len < 56) ctx->buf[ctx->buf_len++] = 0x00;

  uint64_t L = ctx->len_bits;
  ctx->buf[56] = (uint8_t)(L >> 56);
  ctx->buf[57] = (uint8_t)(L >> 48);
  ctx->buf[58] = (uint8_t)(L >> 40);
  ctx->buf[59] = (uint8_t)(L >> 32);
  ctx->buf[60] = (uint8_t)(L >> 24);
  ctx->buf[61] = (uint8_t)(L >> 16);
  ctx->buf[62] = (uint8_t)(L >>  8);
  ctx->buf[63] = (uint8_t)(L >>  0);
  sha256_compress(ctx, ctx->buf);

  for (int i=0;i<8;i++) {
    out[i*4+0] = (uint8_t)(ctx->h[i] >> 24);
    out[i*4+1] = (uint8_t)(ctx->h[i] >> 16);
    out[i*4+2] = (uint8_t)(ctx->h[i] >>  8);
    out[i*4+3] = (uint8_t)(ctx->h[i] >>  0);
  }
}

static void ack_crc4(uint8_t out4[4], uint32_t timestamp, const char *msg, const uint8_t pubkey32[32])
{
  uint8_t ts_le[4];
  uint8_t digest[32];
  sha256_ctx_t ctx;

  ts_le[0] = (uint8_t)(timestamp & 0xFF);
  ts_le[1] = (uint8_t)((timestamp >> 8) & 0xFF);
  ts_le[2] = (uint8_t)((timestamp >> 16) & 0xFF);
  ts_le[3] = (uint8_t)((timestamp >> 24) & 0xFF);

  sha256_init(&ctx);
  sha256_update(&ctx, ts_le, sizeof(ts_le));
  if (msg && msg[0]) sha256_update(&ctx, msg, strlen(msg));
  sha256_update(&ctx, pubkey32, 32);
  sha256_final(&ctx, digest);

  out4[0] = digest[0];
  out4[1] = digest[1];
  out4[2] = digest[2];
  out4[3] = digest[3];
}

void ptype_txt_msg(const onair_packet_t *pkt)
{
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

  fprintf(stderr,
          " TXT_MSG outer: dst_hash=0x%02X src_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
          (unsigned)dst_hash, (unsigned)src_hash, (unsigned)mac, ct_len);

  txt_msg_result_t r;
  int rc = txt_msg_decrypt_and_parse(dst_hash, src_hash, mac, ct, (uint16_t)ct_len, &r);
  if (rc == 0) {
    fprintf(stderr,
            " TXT_MSG decrypted: from=%s to=%s ts=%u type=%u attempt=%u msg=%s\n",
            r.from_label ? r.from_label : "?",
            r.to_label ? r.to_label : "?",
            (unsigned)r.timestamp,
            (unsigned)r.txt_type,
            (unsigned)r.attempt,
            r.msg);

    uint8_t ack_pkt[6];
    uint8_t crc[4] = {0,0,0,0};

    if (r.from_pubkey_valid) {
      ack_crc4(crc, r.timestamp, r.msg, r.from_pubkey);
    }

    /* MeshCore ACK packet: [header][path_len][crc4] */
    ack_pkt[0] = (uint8_t)((0x03u << 2) | 0x01u); /* PAYLOAD_TYPE_ACK=0x03, ROUTE_FLOOD=0x01 => 0x0D */
    ack_pkt[1] = 0x00;
    ack_pkt[2] = crc[0];
    ack_pkt[3] = crc[1];
    ack_pkt[4] = crc[2];
    ack_pkt[5] = crc[3];

    /* Debug (stderr) */
    print_ack_hex_stderr(ack_pkt, sizeof(ack_pkt));

    /* Real send (stdout) */
    emit_cmd_send_raw_data_stdout(ack_pkt, sizeof(ack_pkt));

    return;
  }

  util_print_undecryptable_ciphertext("TXT_MSG", ct, ct_len);
}
