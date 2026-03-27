mcframe - Minimal MeshCore USB frame type dumper

Build (GNU Autotools):
  autoreconf -fi
  ./configure
  make -j

Run:
  ./src/mcframe usb_stream.bin

If your input is base64 text with whitespace, decode first:
  tr -d '\n\r\t ' < mesh.b64.txt | base64 -d > usb_stream.bin

This first version only prints which opcode types are observed.
Later you can add switch(opcode) handling for each type.
