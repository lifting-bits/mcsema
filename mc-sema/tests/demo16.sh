#!/bin/bash

source env.sh

rm -f demo_test16.cfg demo_driver16.o demo_test16.o demo_test16_mine.o demo_driver16.exe

${CC} -ggdb -m32 -c -o demo_test16.o demo_test16.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -entry-symbol=shiftit -i=demo_test16.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86 -entry-symbol=shiftit -i=demo_test16.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test16.cfg -entrypoint=shiftit -o demo_test16.bc
clang-3.5 -O3 -m32 -o demo_driver16.exe demo_driver16.c ../../drivers/ELF_32_linux.S demo_test16.bc

./demo_driver16.exe
