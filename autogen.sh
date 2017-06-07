#!/bin/bash

aclocal
autoconf
autoheader
automake --add-missing
autoreconf -i
sed -i "" -e "s/LIBRARY_GIT_VERSION_NUM/$(git rev-list --count HEAD)/g" configure.ac
sed -i "" -e "s/LIBRARY_GIT_VERSION_NUM/$(git rev-list --count HEAD)/g" libipatcher.pc.in
sed -i "" -e "s/LIBRARY_GIT_VERSION_NUM/$(git rev-list --count HEAD)/g" libipatcher/all_libipatcher.h
sed -i "" -e "s/LIBRARY_GIT_VERSION_SHA/$(git rev-parse HEAD)/g" libipatcher/all_libipatcher.h
./configure "$@"
