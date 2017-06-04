AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/external/iBoot32Patcher -I$(top_srcdir)/external/jssy/jssy/

lib_LIBRARIES = libiBoot32Patcher.a libjssy.a
lib_LTLIBRARIES = libipatcher.la

libiBoot32Patcher_a_CFLAGS = $(AM_CFLAGS)
libiBoot32Patcher_a_SOURCES = $(top_srcdir)/external/iBoot32Patcher/patchers.c $(top_srcdir)/external/iBoot32Patcher/finders.c $(top_srcdir)/external/iBoot32Patcher/functions.c

libjssy_a_CFLAGS = $(AM_CFLAGS)
libjssy_a_SOURCES = $(top_srcdir)/external/jssy/jssy/jssy.c

libipatcher_la_CPPFLAGS = $(AM_CFLAGS)
libipatcher_la_LIBADD = libiBoot32Patcher.a libjssy.a
libipatcher_la_SOURCES = libipatcher.cpp 
