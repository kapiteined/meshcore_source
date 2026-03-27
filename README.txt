meshcore_source/mcframe

Build (top-level):
  autoreconf -fi
  ./configure
  make -j

Run (stdin):
  cat /dev/ttyACM0 | ./mcframe/src/mcframe
  cat /dev/ttyACM0 | tee capture.bin | ./mcframe/src/mcframe
  cat capture.bin | ./mcframe/src/mcframe

This version prints one line per frame by default (op_default).
Per-opcode handlers live in separate files (one file per opcode).
