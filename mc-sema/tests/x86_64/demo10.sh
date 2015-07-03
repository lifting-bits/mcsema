#!/bin/bash

source env.sh

rm -f demo_test10.cfg demo_driver10.o demo_test10.o demo_test10_mine.o demo_driver10.exe

${CC} -ggdb -m64 -c -o demo_test10.o demo_test10.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="demo10_map.txt" -entry-symbol=printdata -i=demo_test10.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="demo10_map.txt" -entry-symbol=printdata -i=demo_test10.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -march=x86-64 -i demo_test10.cfg -driver=demo10_entry,printdata,0,return,C -o demo_test10.bc

${LLVM_PATH}/opt -O3 -o demo_test10_opt.bc demo_test10.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=asm -o demo_test10_mine.asm demo_test10_opt.bc
${LLVM_PATH}/llvm-mc -arch=x86-64 -filetype=obj -o demo_test10_mine.o demo_test10_mine.asm
${CC} -ggdb -m64 -o demo_driver10.exe demo_driver10.c demo_test10_mine.o
./demo_driver10.exe
