#ifndef UTIL_CRYPTO_H
#define UTIL_CRYPTO_H
#include <stddef.h>
#include <stdint.h>

/* Hex decoding: returns bytes written, or -1 on error */
int util_crypto_from_hex(uint8_t *out, int out_max, const char *hex);

/* Compute HMAC-SHA256(key,msg) into out[32] */
void util_crypto_hmac_sha256(const uint8_t *key, size_t klen,
                             const uint8_t *msg, size_t mlen,
                             uint8_t out[32]);

/* AES-128 ECB decrypt, blocks = ct_len/16. in/out may alias. */
void util_crypto_aes128_ecb_decrypt(const uint8_t key16[16],
                                    const uint8_t *in, uint8_t *out,
                                    int blocks);

/* MeshCore MAC: first 2 bytes of HMAC-SHA256(key32, ciphertext), interpreted as little-endian uint16 */
uint16_t util_crypto_mac16_le(const uint8_t key32[32], const uint8_t *ciphertext, size_t ct_len);

#endif
