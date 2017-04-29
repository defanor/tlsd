#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(TLSd, 0.0.1, defanor@uberspace.net, tlsd,
        https://defanor.uberspace.net/projects/tlsd/)
AM_INIT_AUTOMAKE([-Wall])
AC_CONFIG_SRCDIR([tlsd.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# For pipe2(2)
AC_GNU_SOURCE

# Checks for libraries.
PKG_CHECK_MODULES([LIBGNUTLS], [gnutls >= 3.3.0])
AC_SUBST([LIBGNUTLS_CFLAGS])
AC_SUBST([LIBGNUTLS_LIBS])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h \
                  string.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([dup2 memset socket strerror])

AC_OUTPUT
