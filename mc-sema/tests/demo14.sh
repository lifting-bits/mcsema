#!/bin/bash

source env.sh

rm -f demo_test14.cfg demo_driver14.o demo_test14.o demo_test14_mine.o demo_driver14.exe

${CC} -ggdb -m32 -c -o demo_test14.o demo_test14.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -func-map="demo14_defs.txt" -entry-symbol=printMessages -i=demo_test14.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86 -func-map="demo14_defs.txt" -entry-symbol=printMessages -i=demo_test14.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -march=x86 -i demo_test14.cfg -driver=demo14_entry,printMessages,0,return,C -o demo_test14.bc

${LLVM_PATH}/opt -O3 -o demo_test14_opt.bc demo_test14.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test14_mine.o demo_test14_opt.bc
${CC} -ggdb -m32 -o demo_driver14.exe demo_driver14.c demo_test14_mine.o
./demo_driver14.exe
