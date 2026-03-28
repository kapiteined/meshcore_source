#ifndef UTIL_CHANNELS_H
#define UTIL_CHANNELS_H

#include <stdint.h>

typedef struct {
    uint8_t chan_hash;
    const char *name;
    const char *secret_hex;
} chan_secret_entry_t;

const chan_secret_entry_t *util_chan_secret_first(uint8_t chan_hash);
const chan_secret_entry_t *util_chan_secret_next(uint8_t chan_hash, const chan_secret_entry_t *prev);

#endif
