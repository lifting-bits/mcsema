#!/bin/bash

source env.sh

rm -f demo_test1.cfg demo_driver1.o demo_test1.o demo_test1_mine.o demo_driver1.exe

nasm -f elf32 -o demo_test1.o demo_test1.asm 

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -entry-symbol=start -i=demo_test1.o
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -entry-symbol=start -i=demo_test1.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_test1.cfg -driver=demo1_entry,start,raw,return,C -o demo_test1.bc

${LLVM_PATH}/opt -O3 -o demo_test1_opt.bc demo_test1.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test1_mine.o demo_test1_opt.bc
${CC} -m32 -o demo_driver1.exe demo_driver1.c demo_test1_mine.o
./demo_driver1.exe
