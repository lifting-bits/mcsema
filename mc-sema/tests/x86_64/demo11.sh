#!/bin/bash

source env.sh

rm -f demo_test11.cfg demo_driver11.o demo_test11.o demo_test11_mine.o demo_driver11.exe

${CC} -ggdb -m64 -c -o demo_test11.o demo_test11.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -func-map="demo11_map.txt" -entry-symbol=printdata -i=demo_test11.o >> logfile.txt
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="demo11_map.txt" -entry-symbol=printdata -i=demo_test11.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test11.cfg -driver=demo11_entry,printdata,0,return,C -o demo_test11.bc

${LLVM_PATH}/opt -O3 -o demo_test11_opt.bc demo_test11.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_test11_mine.o demo_test11_opt.bc
${CC} -ggdb -m64 -o demo_driver11.exe demo_driver11.c demo_test11_mine.o
./demo_driver11.exe
