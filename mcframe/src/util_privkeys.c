#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <errno.h>

#include "util_privkeys.h"
#include "util_crypto.h"

/* Use MeshCore's Ed25519 derive function (NOT ge_scalarmult_base).
 * MeshCore stores prv_key as 64 bytes, and derives pub_key via ed25519_derive_pub().
 */
#include "crypto/ed25519/ed_25519.h"

static util_privkey_t g_privkeys[UTIL_KEYS_MAX];
static size_t g_privkeys_n = 0;
static int g_privkeys_loaded = 0;

static void trim_eol(char *s)
 {
 size_t n = strlen(s);
 while (n && (s[n-1] == '\n' || s[n-1] == '\r'))
  {
  s[n-1] = 0;
  n--;
  }
 }

/* Split into exactly two whitespace-separated tokens: label and hex.
 * Returns: 0 for blank/comment line, 1 for success, <0 for parse error.
 */
static int split_two_tokens(char *line, char **a, char **b) {
  char *p = line;
  while (*p && isspace((unsigned char)*p)) p++;
  if (!*p || *p == '#') return 0;

  *a = p;
  while (*p && !isspace((unsigned char)*p)) p++;
  if (!*p) return -1;
  *p++ = 0;

  while (*p && isspace((unsigned char)*p)) p++;
  if (!*p) return -1;

  *b = p;
  while (*p && !isspace((unsigned char)*p)) p++;
  if (*p) {
    *p++ = 0;
    while (*p) {
      if (!isspace((unsigned char)*p)) return -2;
      p++;
    }
  }
  return 1;
}

static int is_hex_str_n(const char *s, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    if (!isxdigit((unsigned char)s[i])) return 0;
  }
  return 1;
}

int util_privkeys_load(const char *path) {
  FILE *f;
  char line[512];

  g_privkeys_n = 0;
  g_privkeys_loaded = 0;

  if (!path) path = "./privkeys.txt";

  f = fopen(path, "r");
  if (!f) {
    fprintf(stderr, "%s: error: cannot open: %s/\n", path, strerror(errno));
    return -1;
  }

  int lineno = 0;
  while (fgets(line, sizeof(line), f)) {
    lineno++;
    trim_eol(line);

    char *lab = NULL, *hex = NULL;
    int rc = split_two_tokens(line, &lab, &hex);
    if (rc == 0) continue; /* blank/comment */
    if (rc < 0) {
      fprintf(stderr, "%s:%d: error: expected exactly 2 tokens: '<label> <hex>'/\n", path, lineno);
      fclose(f);
      return -2;
    }

    if (g_privkeys_n >= UTIL_KEYS_MAX) {
      fprintf(stderr, "%s:%d: error: too many privkeys (max %d)/\n", path, lineno, UTIL_KEYS_MAX);
      fclose(f);
      return -3;
    }

    if (!*lab) {
      fprintf(stderr, "%s:%d: error: empty label/\n", path, lineno);
      fclose(f);
      return -2;
    }

    size_t hexlen = strlen(hex);
    /* Accept optional 0x prefix */
    if (hexlen >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
      hex += 2;
      hexlen -= 2;
    }

    /* priv is 64 bytes => 128 hex chars */
    if (hexlen != 128) {
      fprintf(stderr,
              "%s:%d: error: invalid privkey hex length for '%s': got %zu hex chars, expected 128 (64 bytes)/\n",
              path, lineno, lab, hexlen);
      fclose(f);
      return -5;
    }
    if (!is_hex_str_n(hex, 128)) {
      fprintf(stderr, "%s:%d: error: privkey for '%s' contains non-hex characters/\n", path, lineno, lab);
      fclose(f);
      return -5;
    }

    util_privkey_t *e = &g_privkeys[g_privkeys_n];
    memset(e, 0, sizeof(*e));

    /* Copy label */
    snprintf(e->label, sizeof(e->label), "%s", lab);

    int got = util_crypto_from_hex(e->priv, 64, hex);
    if (got != 64) {
      fprintf(stderr,
              "%s:%d: error: invalid privkey hex for '%s': decoded %d bytes, expected 64/\n",
              path, lineno, lab, got);
      fclose(f);
      return -5;
    }

    /* Derive public key from 64-byte private key */
    ed25519_derive_pub(e->pub, e->priv);
    e->hash = e->pub[0];

    g_privkeys_n++;
  }

  fclose(f);
  g_privkeys_loaded = 1;
  return 0;
}

int util_privkeys_is_loaded(void) { return g_privkeys_loaded; }
size_t util_privkeys_count(void) { return g_privkeys_n; }
const util_privkey_t* util_privkeys_get(size_t i) {
  if (i >= g_privkeys_n) return 0;
  return &g_privkeys[i];
}
