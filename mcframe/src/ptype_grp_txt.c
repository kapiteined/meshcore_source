#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "ptype_dispatch.h"
#include "util_hex.h"
#include "util_channels.h"

/* Enable external tool invocation by defining MCFRAME_EXT_TOOL_PATH at compile time, e.g.
 *   CFLAGS='-DMCFRAME_EXT_TOOL_PATH="/tmp/myprog"' ./configure && make
 */

static uint16_t u16le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

#ifdef MCFRAME_EXT_TOOL_PATH
static void hex_to_cstr(const uint8_t *buf, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2*i + 0] = hexd[(buf[i] >> 4) & 0x0F];
        out[2*i + 1] = hexd[buf[i] & 0x0F];
    }
    out[2*len] = 0;
}

static void maybe_run_external_tool(const char *label, const uint8_t *mac_ct, size_t mac_ct_len)
{
    if (!label || !mac_ct || mac_ct_len == 0) {
        return;
    }

    /* Only run the tool when label is known */
    if (strcmp(label, "onbekend") == 0) {
        return;
    }

    /* Convert mac+ciphertext to a hex C-string for argv */
    size_t hex_len = mac_ct_len * 2;
    char *hex = (char *)malloc(hex_len + 1);
    if (!hex) {
        return;
    }
    hex_to_cstr(mac_ct, mac_ct_len, hex);

    /* Capture child stdout+stderr to avoid interleaving with our own output */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(hex);
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        /* child */
        (void)close(pipefd[0]);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        (void)close(pipefd[1]);

        execl(MCFRAME_EXT_TOOL_PATH, MCFRAME_EXT_TOOL_PATH, label, hex, (char *)NULL);
        _exit(127);
    }

    /* parent */
    (void)close(pipefd[1]);

    if (pid > 0) {
        /* Read all output from tool and print it as a single block */
        char buf[4096];
        size_t used = 0;
        char *out = NULL;

        for (;;) {
            ssize_t n = read(pipefd[0], buf, sizeof(buf));
            if (n <= 0) {
                break;
            }
            char *tmp = (char *)realloc(out, used + (size_t)n + 1);
            if (!tmp) {
                free(out);
                out = NULL;
                used = 0;
                break;
            }
            out = tmp;
            memcpy(out + used, buf, (size_t)n);
            used += (size_t)n;
            out[used] = 0;
        }

        (void)close(pipefd[0]);
        (void)waitpid(pid, NULL, 0);

        if (out && used > 0) {
            /* Ensure our own output is flushed before printing the tool output */
            fflush(stdout);
            /* Prefix one line so it stays readable */
            printf("  EXTTOOL (%s): %s", label, out);
            /* If tool didn't end with newline, add one */
            if (used > 0 && out[used-1] != ' ') {
                printf(" ");
            }
        }

        free(out);
    } else {
        (void)close(pipefd[0]);
    }

    free(hex);
}
#else
static void maybe_run_external_tool(const char *label, const uint8_t *mac_ct, size_t mac_ct_len)
{
    (void)label;
    (void)mac_ct;
    (void)mac_ct_len;
}
#endif

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3) ", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t  chan_hash = p[0];
    uint16_t mac       = u16le16(&p[1]);

    /* ciphertext starts after chan_hash (1) + mac (2) */
    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u ", (unsigned)chan_hash, (unsigned)mac, ct_len);

    /* raw bytes WITHOUT chan_hash, but label lookup uses chan_hash */
    const char *label = util_chan_hash_label(chan_hash);
    const uint8_t *mac_ct = &p[1];
    size_t mac_ct_len = (size_t)pkt->payload_len - 1;

    printf("  GRP_TXT raw (mac+ciphertext) (label=%s): ", label);
    util_hex_dump(mac_ct, mac_ct_len);
    printf(" ");

    maybe_run_external_tool(label, mac_ct, mac_ct_len);

    util_print_undecryptable_ciphertext("GRP_TXT", ct, ct_len);
}
