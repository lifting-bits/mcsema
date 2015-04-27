#!/bin/bash

source env.sh

rm -f demo_test4.cfg demo_driver4.o demo_test4.o demo_test4_mine.o demo_driver4.exe

${CC} -ggdb -m64 -c -o demo_test4.o demo_test4.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -func-map="demo4_map.txt" -entry-symbol=doTrans -i=demo_test4.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="demo4_map.txt" -entry-symbol=doTrans -i=demo_test4.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -march=x86-64 -i demo_test4.cfg -driver=demo4_entry,doTrans,1,return,C -o demo_test4.bc

${LLVM_PATH}/opt -O3 -o demo_test4_opt.bc demo_test4.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_test4_mine.o demo_test4_opt.bc
${CC} -ggdb -m64 -o demo_driver4.exe demo_driver4.c demo_test4_mine.o
./demo_driver4.exe
