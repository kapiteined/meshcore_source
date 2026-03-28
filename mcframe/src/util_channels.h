#ifndef UTIL_CHANNELS_H
#define UTIL_CHANNELS_H

#include <stdint.h>

/** Lookup label/secret for a 1-byte channel hash. Returns static string; unknown -> "onbekend". */
const char *util_chan_hash_label(uint8_t chan_hash);

#endif
