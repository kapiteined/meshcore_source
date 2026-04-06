#!/bin/bash

make clean

#export CFLAGS='-DMCFRAME_EXT_TOOL_PATH=\"/home/ed/meshcore_source/decode/meshcore_decoder\"'
autoheader &&\
aclocal &&\
automake --add-missing &&\
autoconf &&\
./configure --prefix "${HOME}"/meshcore --libexecdir="${HOME}"/meshcore &&\
make 
#make install
