### Hotfix v3: link ed25519_derive_pub by compiling keypair.c + sha512.c (vendored)

bin_PROGRAMS = mcframe
AM_CPPFLAGS = -I$(top_builddir) -I$(top_srcdir) -I$(srcdir) -I$(srcdir)/crypto/ed25519 -DHAVE_CONFIG_H -D_POSIX_C_SOURCE=200809L
mcframe_SOURCES = op_51.c main.c dispatch.c onair.c op_default.c op_80.c op_83.c op_88.c op_8A.c op_0C.c ptype_dispatch.c ptype_default.c ptype_req.c ptype_response.c ptype_txt_msg.c ptype_ack.c ptype_advert.c ptype_grp_txt.c grp_txt_decrypt.c ptype_path.c ptype_trace.c util_hex.c util_channels.c util_crypto.c util_privkeys.c util_pubkeys.c txt_msg_decrypt.c mc_companion_dm.c crypto/ed25519/sha512.c crypto/ed25519/keypair.c crypto/ed25519/fe.c crypto/ed25519/ge.c crypto/ed25519/key_exchange.c
noinst_HEADERS = dispatch.h onair.h ptype_dispatch.h util_hex.h util_channels.h grp_txt_decrypt.h util_crypto.h util_privkeys.h util_pubkeys.h txt_msg_decrypt.h mc_companion_dm.h crypto/ed25519/ed_25519.h crypto/ed25519/sha512.h crypto/ed25519/fe.h crypto/ed25519/ge.h crypto/ed25519/fixedint.h crypto/ed25519/precomp_data.h
