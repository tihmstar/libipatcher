AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/external/iBoot32Patcher -I$(top_srcdir)/external/jssy/jssy/ $(libpng_CFLAGS) $(openssl_CFLAGS) $(libimg4tool_CFLAGS) $(liboffsetfinder64_CFLAGS) $(libgeneral_CFLAGS)
AM_LDFLAGS = -L$(top_srcdir)/libipatcher -L/usr/local/lib/ -lcommon -lxpwn $(libpng_LIBS) $(openssl_LIBS) $(libimg4tool_LIBS) $(liboffsetfinder64_LIBS) $(libgeneral_LIBS)

noinst_LTLIBRARIES = libiBoot32Patcher.la libjssy.la
lib_LTLIBRARIES = libipatcher.la

libiBoot32Patcher_la_CFLAGS = $(AM_CFLAGS)
libiBoot32Patcher_la_SOURCES = ../external/iBoot32Patcher/patchers.c ../external/iBoot32Patcher/finders.c ../external/iBoot32Patcher/functions.c

libjssy_la_CFLAGS = $(AM_CFLAGS)
libjssy_la_SOURCES = ../external/jssy/jssy/jssy.c

libipatcher_la_CPPFLAGS = $(AM_CFLAGS)
libipatcher_la_LIBADD = libiBoot32Patcher.la libjssy.la $(AM_LDFLAGS)
libipatcher_la_SOURCES = libipatcher.cpp
