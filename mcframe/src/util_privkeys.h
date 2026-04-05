#ifndef UTIL_PRIVKEYS_H
#define UTIL_PRIVKEYS_H
#include <stddef.h>
#include <stdint.h>
#include "util_pubkeys.h"

typedef struct {
  char label[UTIL_LABEL_MAX];
  uint8_t priv[64];
  uint8_t pub[32];
  uint8_t hash;
} util_privkey_t;

int util_privkeys_load(const char *path);
int util_privkeys_is_loaded(void);
size_t util_privkeys_count(void);
const util_privkey_t* util_privkeys_get(size_t i);

#endif
