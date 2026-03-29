#include <stddef.h>
#include "util_channels.h"

/*
echo -n 'ca94ec5f2be22011df4d59caef646cac' | xxd -r -p | sha256sum | cut -c 1-2
*/
static const chan_secret_entry_t g_chan_secrets[] = {
    { 0x30, "onzin",       "e3df2687079486f8b0b0f9fae61822ed" },
    { 0x30, "Mytest",      "e3df2687079486f8b0b0f9fae618224d" },
    { 0xD9, "#test",       "9cd8fcf22a47333b591d96a2b848b73f" },
    { 0xD9, "Rob en Adam", "ca94ec5f2be22011df4d59caef646cac" },
    { 0x11, "Public",      "8b3387e9c5cdea6ac9e5edbaa115cd72" },
    { 0x00, NULL, NULL }
};

const chan_secret_entry_t *util_chan_secret_first(uint8_t chan_hash)
{
    const chan_secret_entry_t *e = g_chan_secrets;
    while (e->secret_hex) {
        if (e->chan_hash == chan_hash) return e;
        e++;
    }
    return NULL;
}

const chan_secret_entry_t *util_chan_secret_next(uint8_t chan_hash, const chan_secret_entry_t *prev)
{
    const chan_secret_entry_t *e;
    if (!prev) return NULL;

    e = prev + 1;
    while (e->secret_hex) {
        if (e->chan_hash == chan_hash) return e;
        e++;
    }
    return NULL;
}
