AC_INIT(treadmill-bind, m4_esyscmd_s([git describe --tags HEAD --long --match "v*" 2>/dev/null > /dev/null; if [ $? == 0 ]; then git describe --tags HEAD --long --match "v*" 2>/dev/null | cut -b 2- | cut -d '-' -f 1; else echo 0.0; fi]), andreikeis@noreply.users.github.com)
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR(config)
AC_CONFIG_SRCDIR(src/bind_preload.c)
AM_INIT_AUTOMAKE([tar-pax])
AC_PROG_CC
AC_PROG_LEX
AC_PROG_YACC
AC_PROG_LIBTOOL
AC_OUTPUT(Makefile src/Makefile)

