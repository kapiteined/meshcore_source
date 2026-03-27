#ifndef DISPATCH_H
#define DISPATCH_H

#include <stddef.h>
#include <stdint.h>

/* Dispatch one companion-protocol payload frame.
   frame[0] is opcode.
*/
void dispatch_frame(const uint8_t *frame, size_t len);

#endif
