meshcore_source/mcframe

Build (top-level):
  autoreconf -fi
  ./configure
  make -j

Run (stdin):
  cat /dev/ttyACM0 | ./mcframe/src/mcframe
  cat /dev/ttyACM0 | tee capture.bin | ./mcframe/src/mcframe
  cat capture.bin | ./mcframe/src/mcframe

Companion opcode decoders (one file per opcode):
  - op_80.c  (0x80) PUSH_ADVERT
  - op_83.c  (0x83) PUSH_MSG_WAITING
  - op_88.c  (0x88) PUSH_LOG_RX_DATA -> on-air parse -> ptype dispatch
  - op_8A.c  (0x8A) PUSH_NEW_ADVERT
  - op_0C.c  (0x0C) RESP_BATT_AND_STORAGE

Ptype decoders (only added when decoded):
  - ptype_path.c (0x08) PATH outer header
  - ptype_ack.c  (0x03) ACK checksum (CRC32)

Notes:
  - On-air path length byte is decoded as: hash_size + hop_count.
