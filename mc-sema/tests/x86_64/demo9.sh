#!/bin/bash

source env.sh

rm -f demo_test9.cfg demo_driver9.o demo_test9.o demo_test9_mine.o demo_driver9.exe

${CC} -ggdb -m64 -c -o demo_test9.o demo_test9.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -func-map="demo9_map.txt" -entry-symbol=printit -i=demo_test9.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="demo9_map.txt" -entry-symbol=printit -i=demo_test9.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -march=x86-64 -i demo_test9.cfg -driver=demo9_entry,printit,1,return,C -o demo_test9.bc

${LLVM_PATH}/opt -O3 -o demo_test9_opt.bc demo_test9.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_test9_mine.o demo_test9_opt.bc
${CC} -ggdb -m64 -o demo_driver9.exe demo_driver9.c demo_test9_mine.o
./demo_driver9.exe
