#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "util_pubkeys.h"
#include "util_crypto.h"

static util_pubkey_t g_pubkeys[UTIL_KEYS_MAX];
static size_t g_pubkeys_n = 0;
static int g_pubkeys_loaded = 0;

static void trim_eol(char *s) {
  size_t n = strlen(s);
  while (n && (s[n-1] == '\n' || s[n-1] == '\r')) { s[n-1] = 0; n--; }
}

static char* lskip(char *s) {
  while (*s && isspace((unsigned char)*s)) s++;
  return s;
}

static int parse_kv(const char *tok, char *k, size_t ksz, char *v, size_t vsz) {
  const char *eq = strchr(tok, '=');
  if (!eq) return 0;
  size_t kn = (size_t)(eq - tok);
  size_t vn = strlen(eq + 1);
  if (kn == 0 || kn >= ksz || vn >= vsz) return -1;
  memcpy(k, tok, kn);
  k[kn] = 0;
  memcpy(v, eq + 1, vn);
  v[vn] = 0;
  return 1;
}

static int is_hex_str_n(const char *s, size_t n)
{
  for (size_t i = 0; i < n; i++) {
    if (!isxdigit((unsigned char)s[i])) return 0;
  }
  return 1;
}

static int parse_ack_strict(const char *path, int lineno, const char *tok, int *out_ack)
{
  char k[16], v[16];
  int kv = parse_kv(tok, k, sizeof(k), v, sizeof(v));
  if (kv <= 0 || strcmp(k, "ack") != 0) {
    fprintf(stderr, "%s:%d: error: expected first token 'ack=0' or 'ack=1', got '%s'\n",
            path, lineno, tok);
    return -1;
  }
  if (strcmp(v, "0") == 0) { *out_ack = 0; return 0; }
  if (strcmp(v, "1") == 0) { *out_ack = 1; return 0; }
  fprintf(stderr, "%s:%d: error: invalid ack value '%s' in '%s' (expected 0 or 1)\n",
          path, lineno, v, tok);
  return -1;
}

static int parse_label_pubkey_strict(const char *path, int lineno, const char *tok,
                                    char *out_label, size_t out_label_sz,
                                    char out_hex[65])
{
  const char *eq = strchr(tok, '=');
  if (!eq) {
    fprintf(stderr, "%s:%d: error: expected second token 'Label=<pubkeyhex>', got '%s'\n",
            path, lineno, tok);
    return -1;
  }
  if (eq == tok) {
    fprintf(stderr, "%s:%d: error: empty label in token '%s'\n", path, lineno, tok);
    return -1;
  }

  size_t lab_len = (size_t)(eq - tok);
  if (lab_len + 1 > out_label_sz) {
    fprintf(stderr, "%s:%d: error: label too long (%zu chars, max %zu) in '%s'\n",
            path, lineno, lab_len, out_label_sz - 1, tok);
    return -1;
  }
  memcpy(out_label, tok, lab_len);
  out_label[lab_len] = '\0';

  const char *v = eq + 1;
  if (!*v) {
    fprintf(stderr, "%s:%d: error: missing pubkey value for label '%s'\n",
            path, lineno, out_label);
    return -1;
  }

  if (v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) v += 2;

  size_t n = strlen(v);
  if (n != 64) {
    fprintf(stderr, "%s:%d: error: invalid pubkey length for '%s': got %zu hex chars, expected 64\n",
            path, lineno, out_label, n);
    return -1;
  }
  if (!is_hex_str_n(v, 64)) {
    fprintf(stderr, "%s:%d: error: pubkey for '%s' contains non-hex characters: '%s'\n",
            path, lineno, out_label, eq + 1);
    return -1;
  }

  memcpy(out_hex, v, 64);
  out_hex[64] = '\0';
  return 0;
}

int util_pubkeys_load(const char *path) {
  FILE *f;
  char line[512];
  g_pubkeys_n = 0;
  g_pubkeys_loaded = 0;
  if (!path) path = "./pubkeys.txt";
  f = fopen(path, "r");
  if (!f) return -1;

  int lineno = 0;
  while (fgets(line, sizeof(line), f)) {
    lineno++;
    trim_eol(line);
    char *p = lskip(line);
    if (!*p || *p == '#') continue;

    /* Strict format: exactly "ack=0|1  Label=<64hex>" */
    int ack_flag = 0;
    char label[UTIL_LABEL_MAX] = {0};
    char hex[65] = {0};

    char *save = NULL;
    char *tok1 = strtok_r(p, " \t", &save);
    char *tok2 = tok1 ? strtok_r(NULL, " \t", &save) : NULL;
    char *tok3 = tok2 ? strtok_r(NULL, " \t", &save) : NULL;

    if (!tok1 || !tok2 || tok3) {
      fprintf(stderr, "%s:%d: error: expected exactly 2 tokens: 'ack=<0|1> Label=<pubkeyhex>'\n",
              path, lineno);
      fclose(f);
      return -2;
    }

    if (parse_ack_strict(path, lineno, tok1, &ack_flag) < 0) {
      fclose(f);
      return -2;
    }

    if (parse_label_pubkey_strict(path, lineno, tok2, label, sizeof(label), hex) < 0) {
      fclose(f);
      return -2;
    }

    if (g_pubkeys_n >= UTIL_KEYS_MAX) { fclose(f); return -3; }

    util_pubkey_t *e = &g_pubkeys[g_pubkeys_n];
    memset(e, 0, sizeof(*e));

    if (util_crypto_from_hex(e->pub, 32, hex) != 32) {
      fprintf(stderr, "%s:%d: error: failed to decode pubkey hex for '%s'\n",
              path, lineno, label);
      fclose(f);
      return -5;
    }

    snprintf(e->label, sizeof(e->label), "%s", label);
    e->hash = e->pub[0];
    memcpy(e->prefix6, e->pub, 6);
    e->ack = (uint8_t)(ack_flag ? 1 : 0);
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
