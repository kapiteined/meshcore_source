#include <stdio.h>
#include <stdint.h>

#include "ptype_dispatch.h"
#include "util_hex.h"
#include "util_channels.h"
#include "grp_txt_decrypt.h"

static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        printf("  GRP_TXT outer: too_short payload_len=%u (need >=3)\n", (unsigned)pkt->payload_len);
        return;
    }

    const uint8_t *p = pkt->payload;
    uint8_t chan_hash = p[0];
    uint16_t mac = u16le16(&p[1]);
    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    printf("  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)chan_hash, (unsigned)mac, ct_len);

    /* Log ciphertext ALWAYS (also when decrypted) */
    printf("  GRP_TXT ciphertext: ");
    util_hex_dump(ct, ct_len);
    printf("\n");

    /* Lookup secrets for this channel hash */
    const chan_secret_entry_t *e = util_chan_secret_first(chan_hash);
    if (!e) {
        printf("  GRP_TXT decrypt: chan_hash=0x%02X -> NO SECRET (plaintext onmogelijk)\n",
               (unsigned)chan_hash);
        printf("  GRP_TXT: deze ciphertext kan ik niet decrypten\n");
        return;
    }

    /* Try all candidates (handle hash collisions) */
    int tried = 0;
    int mac_ok_any = 0;

    while (e) {
        tried++;

        uint32_t ts = 0;
        uint8_t txt_type = 0;
        uint8_t attempt = 0;
        uint8_t signer_prefix[4];
        int has_signer = 0;
        int mac_ok = 0;
        char msg[512];

        int rc = grp_txt_decrypt_and_parse(pkt->payload, (uint16_t)pkt->payload_len,
                                           e->secret_hex,
                                           &ts, &txt_type, &attempt,
                                           signer_prefix, &has_signer,
                                           &mac_ok,
                                           msg, sizeof(msg));

        if (rc == 0 && mac_ok) {
            printf("  GRP_TXT decrypt: channel=\"%s\" -> MAC OK\n",
                   e->name ? e->name : "(noname)");
            printf("  GRP_TXT plaintext: ts=%u txt_type=%u attempt=%u msg=%s\n",
                   (unsigned)ts, (unsigned)txt_type, (unsigned)attempt, msg);
            mac_ok_any = 1;
            break;
        }

        if (rc == 0) {
            printf("  GRP_TXT decrypt: geprobeerd channel=\"%s\" -> MAC BAD\n",
                   e->name ? e->name : "(noname)");
        } else {
            printf("  GRP_TXT decrypt: geprobeerd channel=\"%s\" -> DECRYPT ERROR\n",
                   e->name ? e->name : "(noname)");
        }

        e = util_chan_secret_next(chan_hash, e);
    }

    if (!mac_ok_any) {
        printf("  GRP_TXT decrypt: %d secret(s) gevonden voor chan_hash=0x%02X, maar geen MAC OK -> plaintext onderdrukt\n",
               tried, (unsigned)chan_hash);
        printf("  GRP_TXT: deze ciphertext kan ik niet decrypten\n");
    }
}
