#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "util_privkeys.h"
#include "util_crypto.h"

/* Use MeshCore's Ed25519 derive function (NOT ge_scalarmult_base).
 * MeshCore stores prv_key as 64 bytes, and derives pub_key via ed25519_derive_pub().
 */
#include "crypto/ed25519/ed_25519.h"

static util_privkey_t g_privkeys[UTIL_KEYS_MAX];
static size_t g_privkeys_n = 0;
static int g_privkeys_loaded = 0;

static void trim_eol(char *s) {
  size_t n = strlen(s);
  while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[n-1] = 0; n--; }
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

int util_privkeys_load(const char *path) {
  FILE *f;
  char line[512];
  g_privkeys_n = 0;
  g_privkeys_loaded = 0;
  if (!path) path = "./privkeys.txt";

  f = fopen(path, "r");
  if (!f) return -1;

  while (fgets(line, sizeof(line), f)) {
    char *lab, *hex;
    int rc;

    trim_eol(line);
    rc = split_two_tokens(line, &lab, &hex);
    if (rc == 0) continue;
    if (rc < 0) { fclose(f); return -2; }
    if (g_privkeys_n >= UTIL_KEYS_MAX) { fclose(f); return -3; }
    if (strlen(lab) >= UTIL_LABEL_MAX) { fclose(f); return -4; }

    /* MeshCore LocalIdentity.prv_key is 64 bytes (128 hex chars). */
    if (util_crypto_from_hex(g_privkeys[g_privkeys_n].priv, 64, hex) != 64) { fclose(f); return -5; }
    strcpy(g_privkeys[g_privkeys_n].label, lab);

    /* Derive public key exactly the same way MeshCore does. */
    ed25519_derive_pub(g_privkeys[g_privkeys_n].pub, g_privkeys[g_privkeys_n].priv);

    g_privkeys[g_privkeys_n].hash = g_privkeys[g_privkeys_n].pub[0];
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
