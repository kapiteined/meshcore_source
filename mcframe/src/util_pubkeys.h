#ifndef UTIL_PUBKEYS_H
#define UTIL_PUBKEYS_H

#include <stddef.h>
#include <stdint.h>

#define UTIL_KEYS_MAX 256
#define UTIL_LABEL_MAX 64

typedef struct {
  char    label[UTIL_LABEL_MAX];
  uint8_t pub[32];
  uint8_t hash;        /* pub[0] */
  uint8_t prefix6[6];  /* pub[0..5] */
  uint8_t ack;         /* 0/1: send receipt confirmation DM for incoming DMs */
} util_pubkey_t;

int util_pubkeys_load(const char *path);
int util_pubkeys_is_loaded(void);
size_t util_pubkeys_count(void);
const util_pubkey_t* util_pubkeys_get(size_t i);

#endif
