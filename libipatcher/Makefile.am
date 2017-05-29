AM_CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/external/iBoot32Patcher -I$(top_srcdir)/external/jssy/jssy/



lib_LTLIBRARIES = libipatcher.la libiBoot32Patcher.la

libiBoot32Patcher_la_CFLAGS = $(AM_CFLAGS)
libiBoot32Patcher_la_SOURCES = $(top_srcdir)/external/iBoot32Patcher/patchers.c $(top_srcdir)/external/iBoot32Patcher/finders.c $(top_srcdir)/external/iBoot32Patcher/functions.c

libipatcher_la_CPPFLAGS = $(AM_CFLAGS)
libipatcher_la_LIBADD = libiBoot32Patcher.la 
libipatcher_la_SOURCES = libipatcher.cpp 
