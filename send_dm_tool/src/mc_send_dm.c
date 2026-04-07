// mc_send_dm.c
// Standalone MeshCore Companion USB sender: send a DM that appears in Android chat.
//
// Flow:
//  1) Open serial (115200, raw)
//  2) CMD_APP_START (0x01) with 7x00 + "mccli"
//  3) Wait for PACKET_SELF_INFO (0x05) (ignore PUSH codes >= 0x80)
//  4) CMD_SEND_TXT_MSG (0x02): [type=0x00][attempt][ts_le32][dest_prefix6][utf8 msg]
//  5) Wait for PACKET_MSG_SENT (0x06) or PACKET_ERROR (0x01)
//
// Usage:
//  ./mc_send_dm -p /dev/ttyACM0 --dest-pub <64hex> --msg "hello again" [--attempt 0]

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

enum { TX_SOF = 0x3C, RX_SOF = 0x3E };

enum { CMD_APP_START = 0x01, CMD_SEND_TXT_MSG = 0x02 };

enum {
  PACKET_OK        = 0x00,
  PACKET_ERROR     = 0x01,
  PACKET_SELF_INFO = 0x05,
  PACKET_MSG_SENT  = 0x06
};

static void die(const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
  fputc('\n', stderr);
  exit(1);
}

static void hexdump(FILE *out, const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) fprintf(out, "%02x", buf[i]);
}

// Some libc/headers require feature macros for cfmakeraw(). To keep this tool
// portable, implement a minimal equivalent of cfmakeraw().
static void make_raw_termios(struct termios *tio) {
  tio->c_iflag &= ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
  tio->c_oflag &= ~OPOST;
  tio->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
  tio->c_cflag &= ~(CSIZE | PARENB);
  tio->c_cflag |= CS8;
}

static int set_serial_raw_115200(int fd) {
  struct termios tio;
  if (tcgetattr(fd, &tio) != 0) return -1;

  make_raw_termios(&tio);

  cfsetispeed(&tio, B115200);
  cfsetospeed(&tio, B115200);

  tio.c_cflag |= (CLOCAL | CREAD);

  // Not all platforms define CRTSCTS (e.g. some musl / BSD variants).
  // Only disable hw flow control if the macro exists.
#ifdef CRTSCTS
  tio.c_cflag &= ~CRTSCTS;
#endif

  tio.c_cc[VMIN]  = 1;
  tio.c_cc[VTIME] = 0;

  if (tcsetattr(fd, TCSANOW, &tio) != 0) return -1;
  tcflush(fd, TCIOFLUSH);
  return 0;
}

static int read_exact(int fd, uint8_t *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t r = read(fd, buf + off, n - off);
    if (r < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    if (r == 0) return -1;
    off += (size_t)r;
  }
  return 0;
}

static int write_exact(int fd, const uint8_t *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    ssize_t w = write(fd, buf + off, n - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      return -1;
    }
    off += (size_t)w;
  }
  return 0;
}

static int read_frame(int fd, uint8_t *out, size_t out_cap, size_t *out_len) {
  uint8_t b;
  while (1) {
    if (read_exact(fd, &b, 1) != 0) return -1;
    if (b == RX_SOF) break;
  }
  uint8_t lenb[2];
  if (read_exact(fd, lenb, 2) != 0) return -1;
  uint16_t ln = (uint16_t)lenb[0] | ((uint16_t)lenb[1] << 8);
  if (ln > out_cap) return -1;
  if (read_exact(fd, out, ln) != 0) return -1;
  *out_len = ln;
  return 0;
}

static int send_cmd(int fd, uint8_t cmd, const uint8_t *payload, uint16_t payload_len) {
  uint16_t body_len = (uint16_t)(1 + payload_len);
  uint8_t *frame = (uint8_t*)malloc((size_t)body_len + 3);
  if (!frame) return -1;

  frame[0] = TX_SOF;
  frame[1] = (uint8_t)(body_len & 0xFF);
  frame[2] = (uint8_t)((body_len >> 8) & 0xFF);
  frame[3] = cmd;
  if (payload_len) memcpy(frame + 4, payload, payload_len);

  int rc = write_exact(fd, frame, (size_t)body_len + 3);
  free(frame);
  return rc;
}

static int read_non_push(int fd, uint8_t *buf, size_t cap, size_t *len_out) {
  while (1) {
    size_t ln = 0;
    if (read_frame(fd, buf, cap, &ln) != 0) return -1;
    if (ln == 0) continue;
    uint8_t code = buf[0];
    if (code & 0x80) continue;
    *len_out = ln;
    return 0;
  }
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
  size_t n = strlen(hex);
  if (n != out_len * 2) return -1;
  for (size_t i = 0; i < out_len; i++) {
    char tmp[3] = { hex[2*i], hex[2*i + 1], 0 };
    char *end = NULL;
    long v = strtol(tmp, &end, 16);
    if (!end || *end) return -1;
    out[i] = (uint8_t)v;
  }
  return 0;
}

static uint32_t now_secs(void) {
  return (uint32_t)time(NULL);
}

static void u32le(uint8_t out[4], uint32_t v) {
  out[0] = (uint8_t)(v & 0xFF);
  out[1] = (uint8_t)((v >> 8) & 0xFF);
  out[2] = (uint8_t)((v >> 16) & 0xFF);
  out[3] = (uint8_t)((v >> 24) & 0xFF);
}

int main(int argc, char **argv) {
  const char *port = "/dev/ttyACM0";
  const char *dest_pub_hex = NULL;
  const char *msg = "hello world";
  int attempt = 0;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      port = argv[++i];
    } else if (!strcmp(argv[i], "--dest-pub") && i + 1 < argc) {
      dest_pub_hex = argv[++i];
    } else if (!strcmp(argv[i], "--msg") && i + 1 < argc) {
      msg = argv[++i];
    } else if (!strcmp(argv[i], "--attempt") && i + 1 < argc) {
      attempt = atoi(argv[++i]);
    } else {
      die("Usage: %s -p /dev/ttyACM0 --dest-pub <64hex> --msg \"text\" [--attempt 0]", argv[0]);
    }
  }

  if (!dest_pub_hex) die("Missing --dest-pub <64hex>");

  uint8_t dest_pub[32];
  if (hex_to_bytes(dest_pub_hex, dest_pub, 32) != 0) die("Invalid dest pubkey hex (need 64 hex chars)");

  uint8_t dest_prefix6[6];
  memcpy(dest_prefix6, dest_pub, 6);

  int fd = open(port, O_RDWR | O_NOCTTY);
  if (fd < 0) die("open(%s) failed: %s", port, strerror(errno));
  if (set_serial_raw_115200(fd) != 0) die("termios setup failed: %s", strerror(errno));

  // APP_START: 7 reserved bytes + "mccli"
  uint8_t app_payload[7 + 5];
  memset(app_payload, 0, 7);
  memcpy(app_payload + 7, "mccli", 5);

  if (send_cmd(fd, CMD_APP_START, app_payload, (uint16_t)sizeof(app_payload)) != 0)
    die("APP_START send failed: %s", strerror(errno));

  uint8_t rx[512];
  size_t rxlen = 0;

  // wait for SELF_INFO
  {
    time_t t0 = time(NULL);
    bool got = false;
    while (time(NULL) - t0 < 5) {
      if (read_non_push(fd, rx, sizeof(rx), &rxlen) != 0) die("read failed waiting SELF_INFO");
      if (rx[0] == PACKET_SELF_INFO) {
        fprintf(stderr, "SELF_INFO ok: ");
        hexdump(stderr, rx, rxlen);
        fputc('\n', stderr);
        got = true;
        break;
      }
      if (rx[0] == PACKET_ERROR) {
        fprintf(stderr, "APP_START ERROR: ");
        hexdump(stderr, rx, rxlen);
        fputc('\n', stderr);
        die("APP_START failed");
      }
    }
    if (!got) die("Timeout waiting for SELF_INFO");
  }

  // SEND DM
  uint32_t ts = now_secs();
  uint8_t tsle[4];
  u32le(tsle, ts);

  size_t msg_len = strlen(msg);
  size_t payload_len = 1 + 1 + 4 + 6 + msg_len;
  if (payload_len > 240) die("Message too long for this simple sender");

  uint8_t *dm_payload = (uint8_t*)malloc(payload_len);
  if (!dm_payload) die("oom");

  size_t o = 0;
  dm_payload[o++] = 0x00; // msg_type direct/contact
  dm_payload[o++] = (uint8_t)(attempt & 0xFF);
  memcpy(dm_payload + o, tsle, 4); o += 4;
  memcpy(dm_payload + o, dest_prefix6, 6); o += 6;
  memcpy(dm_payload + o, msg, msg_len); o += msg_len;

  fprintf(stderr, "DEST pubkey  : %s\n", dest_pub_hex);
  fprintf(stderr, "DEST prefix6 : ");
  hexdump(stderr, dest_prefix6, 6);
  fputc('\n', stderr);
  fprintf(stderr, "TS (seconds) : %" PRIu32 "\n", ts);
  fprintf(stderr, "MSG          : %s\n", msg);

  if (send_cmd(fd, CMD_SEND_TXT_MSG, dm_payload, (uint16_t)payload_len) != 0)
    die("SEND_TXT_MSG send failed: %s", strerror(errno));

  free(dm_payload);

  // wait for MSG_SENT or ERROR
  {
    time_t t0 = time(NULL);
    while (time(NULL) - t0 < 8) {
      if (read_non_push(fd, rx, sizeof(rx), &rxlen) != 0) die("read failed waiting MSG_SENT");
      if (rx[0] == PACKET_MSG_SENT) {
        fprintf(stderr, "MSG_SENT     : ");
        hexdump(stderr, rx, rxlen);
        fputc('\n', stderr);
        fprintf(stderr, "DONE: DM command accepted\n");
        close(fd);
        return 0;
      }
      if (rx[0] == PACKET_ERROR) {
        fprintf(stderr, "ERROR        : ");
        hexdump(stderr, rx, rxlen);
        fputc('\n', stderr);
        die("DM failed");
      }
    }
    die("Timeout waiting for MSG_SENT/ERROR");
  }

  close(fd);
  return 0;
}
