#ifndef UTIL_HEX_H
#define UTIL_HEX_H

#include <stddef.h>
#include <stdint.h>

/** Dump bytes as continuous lowercase hex to stdout. */
void util_hex_dump(const uint8_t *buf, size_t len);

/** Print standardized line: "<label>: deze ciphertext kan ik niet decrypten: <hex>" */
void util_print_undecryptable_ciphertext(const char *label, const uint8_t *ct, size_t ct_len);

#endif
