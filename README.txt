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
  # open docs/doxygen/html/index.html

Ptype handlers implemented:
  - PATH (0x08): ptype_path.c
  - ACK (0x03): ptype_ack.c
  - RESPONSE (0x01): ptype_response.c
  - GRP_TXT (0x05): ptype_grp_txt.c (outer header only)
  - TXT_MSG (0x02): ptype_txt_msg.c (outer header only)

Note:
  This tool currently prints only outer headers for encrypted payloads; no decryption.
