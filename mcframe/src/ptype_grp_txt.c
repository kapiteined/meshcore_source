#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ptype_dispatch.h"
#include "util_hex.h"
#include "util_channels.h"
#include "grp_txt_decrypt.h"

static uint16_t u16le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t  chan_hash = p[0];
    uint16_t mac       = u16le16(&p[1]);

    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    const char *label = util_chan_hash_label(chan_hash);

    {
        uint32_t ts = 0;
        uint8_t txt_type = 0;
        uint8_t attempt = 0;
        uint8_t signer_prefix[4];
        int has_prefix = 0;
        int mac_ok = 0;
        char msg[256];

        if (label && strcmp(label, "onbekend") != 0) {
            if (grp_txt_decrypt_and_parse(p, pkt->payload_len, label,
                                          &ts, &txt_type, &attempt,
                                          signer_prefix, &has_prefix,
                                          &mac_ok,
                                          msg, sizeof(msg)) == 0) {
                printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u ", (unsigned)chan_hash, (unsigned)mac, ct_len);

                printf("  GRP_TXT raw (mac+ciphertext) (label=%s): ", label);
                util_hex_dump(&p[1], (size_t)pkt->payload_len - 1);
                printf("\n");

                printf("  GRP_TXT plaintext: ts=%u txt_type=%u attempt=%u mac=%s ", (unsigned)ts, (unsigned)txt_type, (unsigned)attempt, mac_ok ? "OK" : "BAD");
                if (has_prefix) {
                    printf(" signer_prefix=%02x%02x%02x%02x",
                           (unsigned)signer_prefix[0], (unsigned)signer_prefix[1],
                           (unsigned)signer_prefix[2], (unsigned)signer_prefix[3]);
                }
                printf(" msg=%s\n", msg);
                return;
            }
        }
    }

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n", (unsigned)chan_hash, (unsigned)mac, ct_len);

    printf("  GRP_TXT raw (mac+ciphertext) (label=%s): ", label);
    util_hex_dump(&p[1], (size_t)pkt->payload_len - 1);
    printf("\n");

    util_print_undecryptable_ciphertext("GRP_TXT", ct, ct_len);
}
