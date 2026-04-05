#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "util_pubkeys.h"
#include "util_crypto.h"

static util_pubkey_t g_pubkeys[UTIL_KEYS_MAX];
static size_t g_pubkeys_n = 0;
static int g_pubkeys_loaded = 0;

static void trim_eol(char *s) {
  size_t n = strlen(s);
  while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[n-1] = 0; n--; }
}

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

int util_pubkeys_load(const char *path) {
  FILE *f;
  char line[512];
  g_pubkeys_n = 0;
  g_pubkeys_loaded = 0;
  if (!path) path = "./pubkeys.txt";
  f = fopen(path, "r");
  if (!f) return -1;
  while (fgets(line, sizeof(line), f)) {
    char *lab, *hex;
    int rc;
    trim_eol(line);
    rc = split_two_tokens(line, &lab, &hex);
    if (rc == 0) continue;
    if (rc < 0) { fclose(f); return -2; }
    if (g_pubkeys_n >= UTIL_KEYS_MAX) { fclose(f); return -3; }
    if (strlen(lab) >= UTIL_LABEL_MAX) { fclose(f); return -4; }
    if (util_crypto_from_hex(g_pubkeys[g_pubkeys_n].pub, 32, hex) != 32) { fclose(f); return -5; }
    strcpy(g_pubkeys[g_pubkeys_n].label, lab);
    g_pubkeys[g_pubkeys_n].hash = g_pubkeys[g_pubkeys_n].pub[0];
    g_pubkeys_n++;
  }
  fclose(f);
  g_pubkeys_loaded = 1;
  return 0;
}

int util_pubkeys_is_loaded(void) { return g_pubkeys_loaded; }
size_t util_pubkeys_count(void) { return g_pubkeys_n; }
const util_pubkey_t* util_pubkeys_get(size_t i) {
  if (i >= g_pubkeys_n) return 0;
  return &g_pubkeys[i];
}
