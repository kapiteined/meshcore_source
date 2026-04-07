#define _POSIX_C_SOURCE 200809L
#include "mc_companion_dm.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { TX_SOF = 0x3C };

enum { CMD_APP_START = 0x01, CMD_SEND_TXT_MSG = 0x02 };

static int write_exact(int fd, const uint8_t *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, buf + off, n - off);
    if (w <= 0) return -1;
    off += (size_t)w;
  }
  return 0;
}

static void u32le(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

static int send_cmd_stdout(uint8_t cmd, const uint8_t *payload, uint16_t payload_len) {
  uint16_t body_len = (uint16_t)(1 + payload_len);
  size_t frame_len = (size_t)body_len + 3;
  uint8_t *frame = (uint8_t*)malloc(frame_len);
  if (!frame) return -1;

  frame[0] = (uint8_t)TX_SOF;
  frame[1] = (uint8_t)(body_len & 0xFF);
  frame[2] = (uint8_t)((body_len >> 8) & 0xFF);
  frame[3] = cmd;
  if (payload_len) memcpy(frame + 4, payload, payload_len);

  int rc = write_exact(STDOUT_FILENO, frame, frame_len);
  free(frame);
  return rc;
}

int mc_companion_send_dm_prefix6_stdout(const uint8_t dest_prefix6[6], const char *msg_utf8) {
  if (!dest_prefix6 || !msg_utf8) return -1;

  // Emit APP_START once per process (first send).
  static int app_start_sent = 0;
  if (!app_start_sent) {
    uint8_t app_payload[7 + 5];
    memset(app_payload, 0, 7);
    memcpy(app_payload + 7, "mccli", 5);
    if (send_cmd_stdout(CMD_APP_START, app_payload, (uint16_t)sizeof(app_payload)) != 0) return -2;
    app_start_sent = 1;
  }

  uint32_t ts = (uint32_t)time(NULL);
  uint8_t tsle[4];
  u32le(tsle, ts);

  size_t msg_len = strlen(msg_utf8);
  if (msg_len > 200) msg_len = 200;

  // payload: [msg_type=0x00][attempt=0][ts_le32][dest_prefix6][msg]
  size_t payload_len = 1 + 1 + 4 + 6 + msg_len;
  uint8_t *payload = (uint8_t*)malloc(payload_len);
  if (!payload) return -3;

  size_t o = 0;
  payload[o++] = 0x00;
  payload[o++] = 0x00;
  memcpy(payload + o, tsle, 4); o += 4;
  memcpy(payload + o, dest_prefix6, 6); o += 6;
  memcpy(payload + o, msg_utf8, msg_len); o += msg_len;

  int rc = send_cmd_stdout(CMD_SEND_TXT_MSG, payload, (uint16_t)payload_len);
  free(payload);
  return (rc == 0) ? 0 : -4;
}
