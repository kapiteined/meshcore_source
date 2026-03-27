#!/bin/bash

autoheader &&\
aclocal &&\
automake --add-missing &&\
autoconf &&\
./configure --prefix /shared/"${HOME}"/scripts/meshcore --libexecdir=/shared/"${HOME}"/scripts/meshcore/scripts &&\
make
#make install
