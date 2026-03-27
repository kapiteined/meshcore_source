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
  - PATH (0x08): ptype_path.c
  - ACK (0x03): ptype_ack.c
  - RESPONSE (0x01): ptype_response.c
  - GRP_TXT (0x05): ptype_grp_txt.c
  - TXT_MSG (0x02): ptype_txt_msg.c
  - ADVERT (0x04): ptype_advert.c (parses public key + timestamp + appdata flags/location/name)

Note:
  Encrypted payloads are not decrypted; only outer headers are printed.
