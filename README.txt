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
  - op_88.c parses embedded on-air packet and forwards to per-ptype decoder (separate files).
