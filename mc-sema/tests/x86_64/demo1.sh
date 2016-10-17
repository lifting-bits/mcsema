#!/bin/bash

source env.sh

rm -f demo_test1.cfg demo_driver1.o demo_test1.o demo_test1_mine.o demo_driver1.exe

nasm -f elf64 -o demo_test1.o demo_test1.asm 

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=start -i=demo_test1.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test1.cfg -entrypoint=start -o demo_test1.bc
clang-3.5 -O3 -m64 -o demo_driver1.exe demo_driver1.c ../../../drivers/ELF_64_linux.S demo_test1.bc
./demo_driver1.exe
