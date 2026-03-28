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
    const uint8_t *p;
    uint8_t chan_hash;
    uint16_t mac;
    unsigned ct_len;
    const uint8_t *ct;

    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)", (unsigned)pkt->payload_len);
        putchar('\n');
        return;
    }

    p = pkt->payload;
    chan_hash = p[0];
    mac = u16le16(&p[1]);
    ct_len = (unsigned)pkt->payload_len - 3;
    ct = &p[3];

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u", (unsigned)chan_hash, (unsigned)mac, ct_len);
    putchar('\n');

    printf("  GRP_TXT raw (mac+ciphertext): ");
    util_hex_dump(&p[1], (size_t)pkt->payload_len - 1);
    putchar('\n');

    {
        const chan_secret_entry_t *e = util_chan_secret_first(chan_hash);
        while (e) {
            uint32_t ts = 0;
            uint8_t txt_type = 0;
            uint8_t attempt = 0;
            uint8_t signer_prefix[4];
            int has_prefix = 0;
            int mac_ok = 0;
            char msg[256];

            if (grp_txt_decrypt_and_parse(p, pkt->payload_len, e->secret_hex,
                                          &ts, &txt_type, &attempt,
                                          signer_prefix, &has_prefix,
                                          &mac_ok,
                                          msg, sizeof(msg)) == 0 && mac_ok) {

                printf("  GRP_TXT match: channel='%s' secret=%s", e->name ? e->name : "(noname)", e->secret_hex);
                putchar('\n');

                printf("  GRP_TXT plaintext: ts=%u txt_type=%u attempt=%u mac=OK", (unsigned)ts, (unsigned)txt_type, (unsigned)attempt);
                if (has_prefix) {
                    printf(" signer_prefix=%02x%02x%02x%02x", (unsigned)signer_prefix[0], (unsigned)signer_prefix[1], (unsigned)signer_prefix[2], (unsigned)signer_prefix[3]);
                }
                printf(" msg=%s", msg);
                putchar('\n');
                return;
            }

            e = util_chan_secret_next(chan_hash, e);
        }
    }

    printf("  GRP_TXT: geen matchende secret gevonden voor chan_hash=0x%02X (MAC blijft BAD)", (unsigned)chan_hash);
    putchar('\n');
    util_print_undecryptable_ciphertext("GRP_TXT", ct, ct_len);
}
