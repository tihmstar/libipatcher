AC_PREREQ([2.69])
AC_INIT([libipatcher], [LIBRARY_GIT_VERSION_NUM], [tihmstar@gmail.com])
AC_CONFIG_HEADERS([config.h])
AM_PROG_LIBTOOL

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE(libipatcher, LIBRARY_GIT_VERSION_NUM)

# Checks for programs.
AC_PROG_CXX
CPPFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"
AC_PROG_CC

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  darwin* )
        CXXFLAGS+=" -stdlib=libc++"
        ;;
esac

AC_CONFIG_MACRO_DIRS([m4])

# Checks for libraries.
PKG_CHECK_MODULES(libpng, libpng >= 1.2.0)

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
