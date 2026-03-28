#include <stddef.h>
#include "util_channels.h"

typedef struct {
    uint8_t chan_hash;
    const char *label;
} chan_label_t;

static const chan_label_t g_chan_labels[] = {
    { 0x11, "8b3387e9c5cdea6ac9e5edbaa115cd72" },
    { 0xd9, "9cd8fcf22a47333b591d96a2b848b73f" },
};

const char *util_chan_hash_label(uint8_t chan_hash)
{
    for (size_t i = 0; i < (sizeof(g_chan_labels) / sizeof(g_chan_labels[0])); i++) {
        if (g_chan_labels[i].chan_hash == chan_hash) {
            return g_chan_labels[i].label;
        }
    }
    return "onbekend";
}
