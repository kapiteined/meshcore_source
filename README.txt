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

Change:
  For all payload types with remaining ciphertext after parsing the outer header,
  we now print a ciphertext hex line:
    "<PTYPE>: deze ciphertext kan ik niet decrypten: <hex>"

Affected ptypes:
  - REQ (0x00)
  - RESPONSE (0x01)
  - TXT_MSG (0x02)
  - GRP_TXT (0x05)
  - PATH (0x08)
