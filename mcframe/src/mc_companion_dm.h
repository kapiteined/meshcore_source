#ifndef MC_COMPANION_DM_H
#define MC_COMPANION_DM_H

#include <stdint.h>

/* Send a DM (contact message) via MeshCore Companion Protocol over STDOUT.
 *
 * stdin:  radio RX stream is read elsewhere by mcframe.
 * stdout: radio TX stream (companion commands) is written here.
 * stderr: logging must be done by the caller; this function does not print.
 */
int mc_companion_send_dm_prefix6_stdout(const uint8_t dest_prefix6[6], const char *msg_utf8);

#endif
