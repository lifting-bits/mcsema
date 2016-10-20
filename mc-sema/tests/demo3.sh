#!/bin/bash

source env.sh

rm -f demo_test3.cfg demo_driver3.o demo_test3.o demo_test3_mine.o demo_driver3.exe

${CC} -ggdb -m32 -c -o demo_test3.o demo_test3.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -d -entry-symbol=demo3 -i=demo_test3.o>> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test3.cfg -entrypoint=demo3 -o demo_test3.bc
clang-3.5 -O3 -m32 -o demo_driver3.exe demo_driver3.c ../../drivers/ELF_32_linux.S demo_test3.bc

./demo_driver3.exe
