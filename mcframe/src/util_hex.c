#include <stdio.h>
#include "util_hex.h"

void util_hex_dump(const uint8_t *buf, size_t len) {
    if (!buf || len == 0) return;
    for (size_t i = 0; i < len; i++) {
        fprintf(stderr, "%02x", buf[i]);
    }
}

void util_print_undecryptable_ciphertext(const char *label, const uint8_t *ct, size_t ct_len) {
    if (!ct || ct_len == 0) return;
    if (!label) label = "CIPHERTEXT";
    fprintf(stderr, "  %s: deze ciphertext kan ik niet decrypten: ", label);
    util_hex_dump(ct, ct_len);
    fprintf(stderr, "\n");
}
