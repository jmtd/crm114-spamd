AC_INIT
AC_CONFIG_SRCDIR([configure.ac])

AM_INIT_AUTOMAKE(dspam-spamd, 0.0.1)

AC_PROG_CC

PKG_CHECK_MODULES(GLIB,  glib-2.0)

# Honor aclocal flags
ACLOCAL="$ACLOCAL $ACLOCAL_FLAGS"

AC_CONFIG_FILES([
Makefile
src/Makefile
])
AC_OUTPUT

