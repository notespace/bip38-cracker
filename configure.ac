AC_INIT(cracker,0.1,paybitcoin)
AC_PREREQ(2.52)
AC_CONFIG_SRCDIR([main.c])
AM_INIT_AUTOMAKE([gnu])

AM_MAINTAINER_MODE

AC_PROG_CC
AC_PROG_RANLIB
AC_PROG_GCC_TRADITIONAL

AC_CHECK_LIB(m, log, MATH_LIBS=-lm,
  [AC_MSG_ERROR([Missing required libm])])
AC_CHECK_LIB(crypto, MD5_Init, CRYPTO_LIBS=-lcrypto,
  [AC_MSG_ERROR([Missing required libcrypto])])
AM_PATH_GLIB_2_0(2.0.0, , exit 1)

AC_SUBST(MATH_LIBS)
AC_SUBST(CRYPTO_LIBS)

AC_CONFIG_FILES([
        Makefile
        ])
AC_OUTPUT
