#!/bin/bash

source env.sh

rm -f demo_test13.cfg demo_driver13.o demo_test13.o demo_test13_mine.o demo_driver13.exe

${CC} -ggdb -m64 -c -o demo_test13.o demo_test13.c
#clang -m64 -emit-llvm -c -o demo_test13.bc demo_test13.c
#llc -march=x86-64 -filetype=asm -o demo_test13.asm demo_test13.bc
#llc -march=x86-64 -filetype=obj -o demo_test13.o demo_test13.bc
if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="demo13_map.txt" -entry-symbol=switches -i=demo_test13.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="demo13_map.txt" -entry-symbol=switches -i=demo_test13.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -march=x86-64 -i demo_test13.cfg -driver=demo13_entry,switches,1,return,C -o demo_test13.bc

${LLVM_PATH}/opt -O3 -o demo_test13_opt.bc demo_test13.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_test13_mine.o demo_test13_opt.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=asm -o demo_test13_mine.asm demo_test13_opt.bc
${CC} -ggdb -m64 -o demo_driver13.exe demo_driver13.c demo_test13_mine.o
./demo_driver13.exe
