meshcore_source/mcframe

Build (top-level):
  autoreconf -fi
  ./configure
  make -j

Run (stdin):
  cat /dev/ttyACM0 | ./mcframe/src/mcframe
  cat /dev/ttyACM0 | tee capture.bin | ./mcframe/src/mcframe
  cat capture.bin | ./mcframe/src/mcframe

Structure:
  - One file per companion opcode: op_XX.c
  - op_88.c parses embedded on-air packet and forwards to per-ptype decoder.
  - ptype-specific decoders are in ptype_*.c and only added when we decode them.

Currently implemented ptype decoders:
  - ptype_path.c (PAYLOAD_TYPE_PATH / 0x08): decodes outer header (dest_hash, src_hash, cipher_mac, ciphertext_len)
