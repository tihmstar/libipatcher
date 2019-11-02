AC_PREREQ([2.69])
AC_INIT([libipatcher], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [tihmstar@gmail.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL


AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])

AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])


# Checks for programs.
AC_PROG_CXX
AC_PROG_CC


# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++"
        ;;
esac

CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"

# Checks for libraries.
OPENSSL_REQUIRES_STR="openssl >= 0.9.8"


LIBPNG_REQUIRES_STR="libpng >= 1.2.0"
OPENSSL_REQUIRES_STR="openssl >= 0.9.8"
IMG4TOOL_REQUIRES_STR="libimg4tool >= 155"
LIBOFFSETFINDER64_REQUIRES_STR="liboffsetfinder64 >= 96"

PKG_CHECK_MODULES(libpng, $LIBPNG_REQUIRES_STR)
PKG_CHECK_MODULES(openssl, $OPENSSL_REQUIRES_STR)
PKG_CHECK_MODULES(libimg4tool, $IMG4TOOL_REQUIRES_STR, have_img4tool=yes, have_img4tool=no)
PKG_CHECK_MODULES(liboffsetfinder64, $LIBOFFSETFINDER64_REQUIRES_STR, have_liboffsetfinder=yes, have_liboffsetfinder=no)


AC_ARG_WITH([iBoot64Patcher],
            [AS_HELP_STRING([--without-iBoot64Patcher],
            [do not build with iBoot64Patcher support @<:@default=yes@:>@])],
            [with_ib64p=no],
            [with_ib64p=yes])


if test "x$with_ib64p" == "xyes"; then
  if test "x$have_img4tool" != "xyes"; then
    AC_MSG_ERROR([requested building with iBoot64Patcher, but img4tool could not be found])
  fi
  if test "x$have_liboffsetfinder" != "xyes"; then
    AC_MSG_ERROR([requested building with iBoot64Patcher, but liboffsetfinder64 could not be found])
  fi


  AC_DEFINE(HAVE_IMG4TOOL, 1, [Define if you have img4tool])
  AC_DEFINE(HAVE_LIBOFFSETFINDER64, 1, [Define if you have liboffsetfinder64])


  AC_SUBST(libimg4tool_CFLAGS)
  AC_SUBST(libimg4tool_LIBS)

  AC_SUBST(liboffsetfinder64_CFLAGS)
  AC_SUBST(liboffsetfinder64_LIBS)
else
  echo "*** Note: iBoot64Patcher has been disabled ***"
fi


# Checks for header files.
AC_CHECK_HEADERS([stddef.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libipatcher/Makefile
		             libipatcher.pc])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  with iBoot64Patcher .....: $with_ib64p"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
