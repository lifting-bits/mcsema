#!/bin/bash

source env.sh

rm -f demo_test13.cfg demo_driver13.o demo_test13.o demo_test13_mine.o demo_driver13.exe

${CC} -ggdb -m32 -c -o demo_test13.o demo_test13.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo13_map.txt" -entry-symbol=switches -i=demo_test13.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86 -d -func-map="demo13_map.txt" -entry-symbol=switches -i=demo_test13.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test13.cfg -driver=demo13_entry,switches,1,return,C -o demo_test13.bc

${LLVM_PATH}/opt -mtriple=i686-pc-linux-gnu -O3 -o demo_test13_opt.bc demo_test13.bc
${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_i386_callback.bc demo_test13_opt.bc > demo_test13_linked.bc
${LLVM_PATH}/llc -mtriple=i686-pc-linux-gnu -filetype=obj -o demo_test13_mine.o demo_test13_linked.bc
${CC} -ggdb -m32 -o demo_driver13.exe demo_driver13.c demo_test13_mine.o
./demo_driver13.exe
