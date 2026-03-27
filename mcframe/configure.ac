AC_INIT([mcframe],[0.1.0],[you@example.invalid])
AM_INIT_AUTOMAKE([foreign -Wall subdir-objects])
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADERS([config.h])

AC_PROG_CC
AC_PROG_INSTALL

# Prefer C99 if supported
AC_MSG_CHECKING([for -std=c99])
save_CFLAGS="$CFLAGS"
CFLAGS="$CFLAGS -std=c99"
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([],[])],[have_c99=yes],[have_c99=no])
CFLAGS="$save_CFLAGS"
AC_MSG_RESULT([$have_c99])
AS_IF([test "x$have_c99" = "xyes"],[CFLAGS="$CFLAGS -std=c99"])

CFLAGS="$CFLAGS -Wall -Wextra -Wpedantic"

AC_CONFIG_FILES([
  Makefile
  src/Makefile
])
AC_OUTPUT
