AC_PREREQ([2.68])
AC_INIT([getdns-examples], [0.1.0], [willem@nlnetlabs.nl])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/01-setup-context.c])
AC_CONFIG_HEADERS([config.h])

LT_INIT
AC_PROG_CC

AC_CHECK_LIB([getdns], [getdns_context_create],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.0.0 ])],)
AC_CHECK_HEADER([getdns/getdns_extra.h],,
	[AC_MSG_ERROR([Missing dependency: getdns >= 1.0.0 ])],)

LIBS_bak="$LIBS"
LIBS=""
AC_CHECK_LIB([uv], [uv_run],,
	[AC_MSG_ERROR([Missing dependency libuv])],)
AC_CHECK_HEADER([uv.h],,
	[AC_MSG_ERROR([Missing dependency libuv])],)
AC_CHECK_LIB([getdns_ext_uv], [getdns_extension_set_libuv_loop],,
	[AC_MSG_ERROR([Missing dependency libuv])],)
AC_CHECK_HEADER([getdns/getdns_ext_libuv.h],,
	[AC_MSG_ERROR([Missing dependency libuv extension for getdns])],)
UV_LIBS="$LIBS"
AC_SUBST(UV_LIBS)
LIBS="$LIBS_bak"

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
