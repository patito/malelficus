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
   INCLUDE_CUNIT=CUnit
   INCLUDE_TESTS=test
   TESTS_MAKEFILE="${INCLUDE_TESTS}/Makefile"
   AC_CONFIG_SUBDIRS([src/external-libs/CUnit])
fi

AC_SUBST([INCLUDE_CUNIT])
AC_SUBST([INCLUDE_TESTS])


# Checks for programs.
AC_PROG_CC
AC_CHECK_PROG([HAVE_NASM], [nasm], [true], [false])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h elf.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

case $host_cpu in
    x86_64*|amd64*)
	if  test "x$GCC" = xyes ; then
	    SAVE_CFLAGS="$CFLAGS"
	    CFLAGS="$CFLAGS -m32"
	    AC_MSG_CHECKING([if $CC supports the -m32 Intel/AMD option])
	    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
#include <unistd.h>
int
main ()
{
  ;
  return 0;

  }]])],
		[m32_support=yes; M32_CFLAGS=-m32],
		[m32_support=no])
	    AC_MSG_RESULT([$m32_support])
	    CFLAGS="$SAVE_CFLAGS"
	fi
	;;
esac
AC_SUBST([M32_CFLAGS])

if test "x$m32_support" = "xno"; then
   AC_MSG_ERROR([Malelficus only supports x86 at the moment...
   If you can help us, write a patch ;\)

   sorry for the inconvenince...])
fi

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero getaddrinfo inet_ntoa memset socket munmap])

AC_CONFIG_FILES([     Makefile \
                      src/Makefile \
                      src/external-libs/Makefile \
                      src/libmalelf/Makefile \
                      src/malelf/Makefile \
                      test/Makefile
                      test/malwares/Makefile
                      test/host/Makefile])


AC_OUTPUT

AC_MSG_RESULT([

























01101101011000010110110001100101011011000110011001101001011000110111010101110011
00100000011010010110111001100110011001010110001101110100001000000010110101101001
00100000001011110110001001101111011011110111010000101111011101100110110101101100
01101001011011100111010101111010001000000010110101101111001000000010111101100010
01101111011011110111010000101111011101100110110101101100011010010110111001110101
01111010001011010110100101101110011001100110010101100011011101000110010101100100
00100000001011010110110100100000001100000010000000101101011100000010000001110000
01100001011100100110000101110011011010010111010001100101001011100110111100001101
00001010011010000110000101110000011100000111100100100000011010000110000101100011
01101011011010010110111001100111001000000010000100100001001000010000110100001010
00001101000010100100001001110101011001110101001101100101011000110010000001010100
01100101011000010110110100001101000010100000110100001010011010010011010001101011
00101100001000000110001100110000001100000110110000110011011100100010110000100000
01101101001100000110111001100001011001000010110000100000011100110110100101100111
01110011011001010110011101110110001011000010000001110011011011000111100101100110
01110101011011100110101101111001001011000010000001100010001011010110110101100001
01101110000011010000101000001101000010100000110100001010000011010000101000001101
0001          MalELFicus - Malware Development and Analysis Tool            0010
0011                                                                        0100
0101 Configuration:                                                         0110])

if test "x$HAVE_TESTS" = "xtrue"; then
   AC_MSG_RESULT([0111    Unit tests: enabled                                                 1000])
else
   AC_MSG_RESULT([0111    Unit tests: disabled (use ./configure --enable-tests to enable      1000])
fi

if test "x$HAVE_NASM" = "xtrue"; then
   AC_MSG_RESULT([1001    NASM: installed                                                     1010])
else
   AC_MSG_RESULT([1001    NASM: not installed... you need install nasm.                       1010])
fi

AC_MSG_RESULT([1011                                                                        1100])