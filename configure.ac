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
        AC_MSG_RESULT([${host_os}])
        CXXFLAGS+=" -stdlib=libc++"
        ;;
  *mingw32*|*cygwin*|*msys*)
        AC_MSG_RESULT([${host_os}])
        win32=true
        LDFLAGS+=" -no-undefined"
        ;;
esac

CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"

# Checks for libraries.
LIBFRAGMENTZIP_REQUIRES_STR="libfragmentzip >= 67"
IMG4TOOL_REQUIRES_STR="libimg4tool >= 202"
IMG3TOOL_REQUIRES_STR="libimg3tool >= 8"
LIBPATCHFINDER_REQUIRES_STR="libpatchfinder >= 153"
LIBGENERAL_REQUIRES_STR="libgeneral >= 75"


PKG_CHECK_MODULES(libfragmentzip, $LIBFRAGMENTZIP_REQUIRES_STR, have_libfragmentzip=yes, have_libfragmentzip=no)
PKG_CHECK_MODULES(libimg3tool, $IMG3TOOL_REQUIRES_STR, have_img3tool=yes, have_img3tool=no)
PKG_CHECK_MODULES(libimg4tool, $IMG4TOOL_REQUIRES_STR, have_img4tool=yes, have_img4tool=no)
PKG_CHECK_MODULES(libpatchfinder, $LIBPATCHFINDER_REQUIRES_STR)
PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)

AC_SUBST([libfragmentzip_requires], [$LIBFRAGMENTZIP_REQUIRES_STR])
AC_SUBST([img3tool_requires], [$IMG3TOOL_REQUIRES_STR])
AC_SUBST([img4tool_requires], [$IMG4TOOL_REQUIRES_STR])
AC_SUBST([libpatchfinder_requires], [$LIBPATCHFINDER_REQUIRES_STR])
AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])

AC_ARG_WITH([libfragmentzip],
            [AS_HELP_STRING([--without-libfragmentzip],
            [do not build with libfragmentzip support @<:@default=yes@:>@])],
            [with_libfragmentzip=no],
            [with_libfragmentzip=yes])

AC_ARG_WITH([iBoot64Patcher],
            [AS_HELP_STRING([--without-iBoot64Patcher],
            [do not build with iBoot64Patcher support @<:@default=yes@:>@])],
            [with_ib64p=no],
            [with_ib64p=yes])

AC_ARG_WITH([iBoot32Patcher],
            [AS_HELP_STRING([--without-iBoot32Patcher],
            [do not build with iBoot32Patcher support @<:@default=yes@:>@])],
            [with_ib32p=no],
            [with_ib32p=yes])

AC_ARG_WITH([ipsw-me-support],
            [AS_HELP_STRING([--without-ipsw-me-support],
            [do not build with ipsw.me support @<:@default=no@:>@])],
            [with_ipsw_me=no],
            [with_ipsw_me=yes])
AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

AC_ARG_ENABLE([asan],
            [AS_HELP_STRING([--enable-asan],
            [enable ASAN build(default is no)])],
            [asan_build=true],
            [asan_build=false])

AM_CONDITIONAL([WITH_IBOOT32PATCHER], [test x$with_ib32p = xyes])
AM_CONDITIONAL([WITH_IBOOT64PATCHER], [test x$with_ib64p = xyes])
AM_CONDITIONAL(WITH_IPSW_ME_SUPPORT, test "x$with_ipsw_me" = "xyes")


if test "x$with_libfragmentzip" == "xyes"; then
  if test "x$have_libfragmentzip" != "xyes"; then
    AC_MSG_ERROR([requested building with libfragmentzip, but library could not be found])
  fi

  AC_DEFINE(HAVE_LIBFRAGMENTZIP, 1, [Define if you have libfragmentzip])

  AC_SUBST(libfragmentzip_CFLAGS)
  AC_SUBST(libfragmentzip_LIBS)
else
  echo "*** Note: libfragmentzip has been disabled ***"
fi

if test "x$with_ib64p" == "xyes"; then
  if test "x$have_img4tool" != "xyes"; then
    AC_MSG_ERROR([requested building with iBoot64Patcher, but img4tool could not be found])
  fi

  AC_DEFINE(HAVE_IMG4TOOL, 1, [Define if you have img4tool])
  AC_DEFINE(WITH_IBOOT64PATCHER, 1, [Define if you build with iBoot64Patcher support])

  AC_SUBST(libimg4tool_CFLAGS)
  AC_SUBST(libimg4tool_LIBS)
else
  echo "*** Note: iBoot64Patcher has been disabled ***"
fi

if test "x$with_ib32p" == "xyes"; then
  if test "x$have_img3tool" != "xyes"; then
    AC_MSG_ERROR([requested building with iBoot32Patcher, but img3tool could not be found])
  fi

  AC_DEFINE(HAVE_IMG3TOOL, 1, [Define if you have img3tool])
  AC_DEFINE(WITH_IBOOT32PATCHER, 1, [Define if you build with iBoot64Patcher support])

  AC_SUBST(libimg3tool_CFLAGS)
  AC_SUBST(libimg3tool_LIBS)

else
  echo "*** Note: iBoot32Patcher has been disabled ***"
fi

if test "$debug_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -DDEBUG=1"
  CXXFLAGS+=" -g -O0 -DDEBUG=1"
fi

if test "$asan_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope"
  CXXFLAGS+=" -g -O0 -fsanitize=address -fno-omit-frame-pointer -fsanitize-address-use-after-scope"
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
AC_CHECK_FUNCS([memset memmem])

AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libipatcher/Makefile
		             libipatcher.pc])
AC_OUTPUT

echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  with iBoot32Patcher .....: $with_ib32p
  with iBoot64Patcher .....: $with_ib64p
  with libfragmentzip .....: $with_libfragmentzip
  with ipsw.me support ....: $with_ipsw_me
  debug build  ............: $debug_build
  asan build  .............: $asan_build"

echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
