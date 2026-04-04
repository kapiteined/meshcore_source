#ifndef OPS_H
#define OPS_H

#include <stddef.h>
#include <stdint.h>

void op_80(const uint8_t *frame, size_t len);
void op_83(const uint8_t *frame, size_t len);
void op_88(const uint8_t *frame, size_t len);
void op_8A(const uint8_t *frame, size_t len);
void op_0C(const uint8_t *frame, size_t len);
void op_default(const uint8_t *frame, size_t len);

#endif

void op_51(const uint8_t *frame, size_t len);
