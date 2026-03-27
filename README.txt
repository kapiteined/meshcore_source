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

Change note:
  Common header+path printing is now done in ptype_dispatch.c once per packet.
  Individual ptype handlers only print payload-specific details.
