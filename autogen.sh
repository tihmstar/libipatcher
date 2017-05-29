#!/bin/bash

aclocal
autoconf
autoheader
automake --add-missing
autoreconf -i
sed -i "" -e "s/LIBIPATCHER_VERSION_COMMIT_COUNT/$(git rev-list --count HEAD)/g" configure.ac
sed -i "" -e "s/LIBIPATCHER_VERSION_COMMIT_COUNT/$(git rev-list --count HEAD)/g" libipatcher.pc
sed -i "" -e "s/LIBIPATCHER_VERSION_COMMIT_COUNT/$(git rev-list --count HEAD)/g" libipatcher/all_libipatcher.h
sed -i "" -e "s/LIBIPATCHER_VERSION_COMMIT_SHA/$(git rev-parse HEAD)/g" libipatcher/all_libipatcher.h
./configure "$@"
