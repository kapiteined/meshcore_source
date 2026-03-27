myproject + mcframe (subdir)

Build (top-level):
  autoreconf -fi
  ./configure
  make -j

Run:
  cat /dev/ttyACM0 | ./mcframe/src/mcframe
  cat /dev/ttyACM0 | tee capture.bin | ./mcframe/src/mcframe

If your input is base64 text with whitespace, decode first:
  tr -d '\n\r\t ' < mesh.b64.txt | base64 -d > usb_stream.bin
  cat usb_stream.bin | ./mcframe/src/mcframe
