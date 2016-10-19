#!/bin/bash

source env.sh

rm -f demo_test2.cfg demo_driver2.o demo_test2.o demo_test2_mine.o demo_driver2.exe

nasm -f elf32 -o demo_test2.o demo_test2.asm 

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -d -entry-symbol=start -i=demo_test2.o>> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test2.cfg -entrypoint=start -o demo_test2.bc
clang-3.5 -O3 -m32 -o demo_driver2.exe demo_driver2.c ../../drivers/ELF_32_linux.S demo_test2.bc

./demo_driver2.exe
