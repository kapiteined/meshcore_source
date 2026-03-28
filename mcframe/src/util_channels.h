#ifndef UTIL_CHANNELS_H
#define UTIL_CHANNELS_H

#include <stdint.h>

/**
 * Lookup a human-friendly label for a 1-byte channel hash.
 *
 * Returns a pointer to a static string.
 * If the channel hash is unknown, returns "onbekend".
 */
const char *util_chan_hash_label(uint8_t chan_hash);

#endif
