meshcore_source/mcframe

Build:
  autoreconf -fi
  ./configure
  make -j

Run:
  cat /dev/ttyACM0 | ./mcframe/src/mcframe

Doxygen (HTML only):
  mkdir -p docs/doxygen
  doxygen Doxyfile

Ptype handlers implemented:
  - REQ (0x00): ptype_req.c (outer header only)
  - RESPONSE (0x01): ptype_response.c
  - TXT_MSG (0x02): ptype_txt_msg.c
  - ACK (0x03): ptype_ack.c
  - ADVERT (0x04): ptype_advert.c
  - GRP_TXT (0x05): ptype_grp_txt.c
  - PATH (0x08): ptype_path.c

Note:
  Encrypted payloads are not decrypted; only outer headers are printed.
