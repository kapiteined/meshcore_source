#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "ptype_dispatch.h"
#include "util_hex.h"
#include "util_channels.h"
#include "grp_txt_decrypt.h"
#include "util_pubkeys.h"
#include "mc_companion_dm.h"

static uint16_t u16le16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }

static int is_ack_message_text(const char *s) {
  if (!s) return 0;
  return (strncmp(s, "@ack ", 5) == 0) || (strncmp(s, "ACK ", 4) == 0) || (strncmp(s, "ACK:", 4) == 0);
}

void ptype_grp_txt(const onair_packet_t *pkt)
{
    if (pkt->payload_len < 3) {
        fprintf(stderr, "  GRP_TXT outer: too_short payload_len=%u (need >=3)\n", (unsigned)pkt->payload_len);
        return;
    }

    if (!util_pubkeys_is_loaded()) {
        int rc = util_pubkeys_load("./pubkeys.txt");
        if (rc != 0) {
            fprintf(stderr, "  GRP_TXT warning: failed to load ./pubkeys.txt (rc=%d)\n", rc);
        }
    }

    const uint8_t *p = pkt->payload;
    uint8_t chan_hash = p[0];
    uint16_t mac = u16le16(&p[1]);
    unsigned ct_len = (unsigned)pkt->payload_len - 3;
    const uint8_t *ct = &p[3];

    fprintf(stderr, "  GRP_TXT outer: chan_hash=0x%02X mac=0x%04X ciphertext_len=%u\n",
           (unsigned)chan_hash, (unsigned)mac, ct_len);

    /* Log ciphertext ALWAYS (also when decrypted) */
    fprintf(stderr, "  GRP_TXT ciphertext: ");
    util_hex_dump(ct, ct_len);
    fprintf(stderr, "\n");

    /* Lookup secrets for this channel hash */
    const chan_secret_entry_t *e = util_chan_secret_first(chan_hash);
    if (!e) {
        fprintf(stderr, "  GRP_TXT decrypt: chan_hash=0x%02X -> NO SECRET (plaintext onmogelijk)\n",
               (unsigned)chan_hash);
        fprintf(stderr, "  GRP_TXT: deze ciphertext kan ik niet decrypten\n");
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

        if (rc == 0 && mac_ok)
         {
         fprintf(stderr, "  GRP_TXT decrypt: channel=\"%s\" -> MAC OK\n", e->name ? e->name : "(noname)");

         if(chan_hash == 0x11)
          {
          fprintf(stderr, "  =======================================================================================\n" );
          }
         else
          {
          fprintf(stderr, "  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
          }

         fprintf(stderr, "  GRP_TXT plaintext: ts=%u txt_type=%u attempt=%u msg=%s\n", (unsigned)ts, (unsigned)txt_type, (unsigned)attempt, msg);

         if(chan_hash == 0x11)
          {
          fprintf(stderr, "  =======================================================================================\n" );
          }
         else
          {
          fprintf(stderr, "  +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n" );
          }

         // Receipt ACK-DM policy for group texts:
         // - check if signer has ack=1 in pubkeys.txt
         // - never ack ack-messages to avoid loops
         if (has_signer) {
           char signer_hex[9];
           snprintf(signer_hex, sizeof(signer_hex), "%02X%02X%02X%02X",
                    signer_prefix[0], signer_prefix[1], signer_prefix[2], signer_prefix[3]);
           fprintf(stderr, "  GRP_TXT signer prefix: %s\n", signer_hex);

           size_t n = util_pubkeys_count();
           int signer_found = 0;
           for (size_t i = 0; i < n; i++) {
             const util_pubkey_t *pk = util_pubkeys_get(i);
             if (memcmp(pk->prefix6, signer_prefix, 4) == 0) {
               signer_found = 1;
               if (!pk->ack) {
                 fprintf(stderr, "  GRP_TXT signer %s found but ack=0 -> geen ACK_DM\n",
                         pk->label);
                 break;
               }
               if (is_ack_message_text(msg)) {
                 fprintf(stderr, "  GRP_TXT received ack message -> geen ACK_DM om lus te voorkomen\n");
                 break;
               }
               char ack_msg[128];
               snprintf(ack_msg, sizeof(ack_msg), "@ack ts=%u", (unsigned)ts);
               int s_rc = mc_companion_send_dm_prefix6_stdout(pk->prefix6, ack_msg);
               if (s_rc == 0) {
                 fprintf(stderr, "  ACK_DM queued to %s (%02x%02x%02x%02x%02x%02x): %s\n",
                         pk->label,
                         pk->prefix6[0], pk->prefix6[1], pk->prefix6[2],
                         pk->prefix6[3], pk->prefix6[4], pk->prefix6[5],
                         ack_msg);
               } else {
                 fprintf(stderr, "  ACK_DM failed rc=%d\n", s_rc);
               }
               break;
             }
           }
           if (!signer_found) {
             fprintf(stderr, "  GRP_TXT signer prefix %s niet gevonden in pubkeys.txt -> geen ACK_DM\n", signer_hex);
           }
         } else {
           fprintf(stderr, "  GRP_TXT: geen signer prefix aanwezig -> geen ACK_DM mogelijk\n");
         }

         mac_ok_any = 1;
         break;
        }

        if (rc == 0) {
            fprintf(stderr, "  GRP_TXT decrypt: geprobeerd channel=\"%s\" -> MAC BAD\n",
                   e->name ? e->name : "(noname)");
        } else {
            fprintf(stderr, "  GRP_TXT decrypt: geprobeerd channel=\"%s\" -> DECRYPT ERROR\n",
                   e->name ? e->name : "(noname)");
        }

        e = util_chan_secret_next(chan_hash, e);
    }

    if (!mac_ok_any) {
        fprintf(stderr, "  GRP_TXT decrypt: %d secret(s) gevonden voor chan_hash=0x%02X, maar geen MAC OK -> plaintext onderdrukt\n",
               tried, (unsigned)chan_hash);
        fprintf(stderr, "  GRP_TXT: deze ciphertext kan ik niet decrypten\n");
    }
}
