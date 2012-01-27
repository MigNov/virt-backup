#!/bin/sh

set -e
set -v

make distclean || :

aclocal
autoreconf -i -f
./configure
