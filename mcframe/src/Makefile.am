## mcframe/src/Makefile.am

## Bouw één programma: mcframe
bin_PROGRAMS = mcframe

## Zorg dat config.h gevonden wordt en dat includes overeenkomen met jouw build
## (jij ziet in de compilerregel: -DHAVE_CONFIG_H -I. -I../..)
AM_CPPFLAGS = \
  -I$(top_builddir) \
  -I$(top_srcdir) \
  -I$(srcdir) \
  -DHAVE_CONFIG_H

## Alle C sources die in de binary moeten komen.
## Belangrijk: hier moeten óók ptype_trace.c en util_channels.c in staan,
## anders krijg je undefined reference errors bij linken.
mcframe_SOURCES = \
  main.c \
  dispatch.c \
  onair.c \
  op_default.c \
  op_80.c \
  op_83.c \
  op_88.c \
  op_8A.c \
  op_0C.c \
  ptype_dispatch.c \
  ptype_default.c \
  ptype_req.c \
  ptype_response.c \
  ptype_txt_msg.c \
  ptype_ack.c \
  ptype_advert.c \
  ptype_grp_txt.c \
  grp_txt_decrypt.c \
  ptype_path.c \
  ptype_trace.c \
  util_hex.c \
  util_channels.c

## (Optioneel, maar netjes): headers opnemen voor distributie/IDE’s.
noinst_HEADERS = \
  dispatch.h \
  onair.h \
  ptype_dispatch.h \
  util_hex.h \
  util_channels.h \
  grp_txt_decrypt.h
