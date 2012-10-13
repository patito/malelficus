AC_PREREQ([2.68])
AC_INIT([malelficus], [0.1], [tiago4orion@gmail.com])

AC_MSG_RESULT([Welcome to AutoHELL])
AM_INIT_AUTOMAKE

dnl need libtool for libmalelf
LT_INIT
AC_CONFIG_SRCDIR([src/malelf/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

HAVE_TESTS=true
dnl Enable unit-tests
AC_ARG_ENABLE([tests],
    AS_HELP_STRING([--enable-tests], [Enable Malelficus Unit Tests]))

AS_IF([test "x$enable_tests" = "xyes"], [HAVE_TESTS=true], [HAVE_TESTS=false])

INCLUDE_TESTS=
INCLUDE_CUNIT=
if test "x${HAVE_TESTS}" = "xtrue"; then
   AC_MSG_RESULT([Unit tests enabled])
   INCLUDE_CUNIT=libraries/CUnit
   INCLUDE_TESTS=test
   TESTS_MAKEFILE="${INCLUDE_TESTS}/Makefile"
   AC_CONFIG_SUBDIRS([src/external-libs/CUnit])
   export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:../libraries/CUnit/CUnit/Sources/.libs"
fi

AC_SUBST([INCLUDE_CUNIT])
AC_SUBST([INCLUDE_TESTS])


# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h elf.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero getaddrinfo inet_ntoa memset socket munmap])

AC_CONFIG_FILES([     Makefile \
                      src/Makefile
                      src/external-libs/Makefile
                      src/libmalelf/Makefile
                      src/malelf/Makefile
                      ${TESTS_MAKEFILE}
                      test/test_files/Makefile])


AC_OUTPUT
