#!/bin/bash

source env.sh

rm -f demo_test12.cfg demo_driver12.o demo_test12.o demo_test12_mine.o demo_driver12.exe

nasm -f elf32 -o demo_test12.o demo_test12.asm 

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -entry-symbol=start -i=demo_test12.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -entry-symbol=start -i=demo_test12.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_test12.cfg -driver=demo12_entry,start,raw,return,C -o demo_test12.bc

${LLVM_PATH}/opt -O3 -o demo_test12_opt.bc demo_test12.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test12_mine.o demo_test12_opt.bc
${CC} -ggdb -m32 -o demo_driver12.exe demo_driver12.c demo_test12_mine.o
./demo_driver12.exe
