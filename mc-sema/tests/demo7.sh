#!/bin/bash

source env.sh

rm -f demo_test7.cfg demo_driver7.o demo_test7.o demo_test7_mine.o demo_driver7.exe

${CC} -ggdb -m32 -c -o demo_test7.o demo_test7.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -func-map="demo7_map.txt" -entry-symbol=checkFn -i=demo_test7.o 
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -func-map="demo7_map.txt" -entry-symbol=checkFn -i=demo_test7.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_test7.cfg -driver=demo7_entry,checkFn,1,return,C -o demo_test7.bc

${LLVM_PATH}/opt -O3 -o demo_test7_opt.bc demo_test7.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test7_mine.o demo_test7_opt.bc
${CC} -ggdb -m32 -o demo_driver7.exe demo_driver7.c demo_test7_mine.o
./demo_driver7.exe
