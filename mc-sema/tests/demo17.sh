#!/bin/bash

source env.sh

rm -f demo_test17.cfg demo_driver17.o demo_test17.o demo_test17_mine.o demo_driver17.exe

${CC} -ggdb -m32 -c -o demo_test17.o demo17.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -entry-symbol=main -i=demo_test17.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test17.cfg -entrypoint=main -o demo_test17.bc
clang-3.5 -O3 -m32 -o demo_driver17.exe ../../drivers/ELF_32_linux.S demo_test17.bc

./demo_driver17.exe
