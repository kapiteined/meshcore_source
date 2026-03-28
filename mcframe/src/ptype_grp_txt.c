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
 *   CFLAGS='-DMCFRAME_EXT_TOOL_PATH=\"/tmp/myprog\"' ./configure && make
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
    out[2*len] = '\0';
}

/*
 * Run external tool as: <prog> <label> <mac+ciphertext-hex>
 * Returns:
 *   -1  tool not run (unknown label)
 *   >=0 exit code of the tool
 * Prints captured tool output (stdout+stderr) as a single block.
 */
static int run_external_tool(const char *label, const uint8_t *mac_ct, size_t mac_ct_len)
{
    if (!label || !mac_ct || mac_ct_len == 0) {
        return -1;
    }

    /* Only run the tool when label is known */
    if (strcmp(label, "onbekend") == 0) {
        return -1;
    }

    /* Convert mac+ciphertext to a hex C-string for argv */
    size_t hex_len = mac_ct_len * 2;
    char *hex = (char *)malloc(hex_len + 1);
    if (!hex) {
        return 127;
    }
    hex_to_cstr(mac_ct, mac_ct_len, hex);

    /* Capture child stdout+stderr to avoid interleaving with our own output */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(hex);
        return 127;
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

    int rc = 127;
    int status = 0;

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
            out[used] = '\0';
        }

        (void)close(pipefd[0]);
        (void)waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            rc = WEXITSTATUS(status);
        } else {
            rc = 127;
        }

        if (out && used > 0) {
            fflush(stdout);
            if (rc == 0) {
                printf("  EXTTOOL (%s): %s", label, out);
            } else {
                printf("  EXTTOOL (%s) rc=%d: %s", label, rc, out);
            }
            if (out[used-1] != '\n') {
                printf("\n");
            }
        }

        free(out);
    } else {
        (void)close(pipefd[0]);
    }

    free(hex);
    return rc;
}
#else
static int run_external_tool(const char *label, const uint8_t *mac_ct, size_t mac_ct_len)
{
    (void)label;
    (void)mac_ct;
    (void)mac_ct_len;
    return -1;
}
#endif

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)\n",
               (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t  chan_hash = p[0];
    uint16_t mac       = u16le16(&p[1]);

    /* ciphertext starts after chan_hash (1) + mac (2) */
    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    /* raw bytes WITHOUT chan_hash, but label lookup uses chan_hash */
    const char *label = util_chan_hash_label(chan_hash);
    const uint8_t *mac_ct = &p[1];
    size_t mac_ct_len = (size_t)pkt->payload_len - 1;

    /* Run tool first; if it succeeds (rc==0), skip our duplicate prints */
    int rc = run_external_tool(label, mac_ct, mac_ct_len);
    if (rc == 0) {
        return;
    }

    /* Fallback prints (only when tool not run or rc != 0) */
    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)chan_hash, (unsigned)mac, ct_len);

    printf("  GRP_TXT raw (mac+ciphertext) (label=%s): ", label);
    util_hex_dump(mac_ct, mac_ct_len);
    printf("\n");

    util_print_undecryptable_ciphertext("GRP_TXT", ct, ct_len);
}
