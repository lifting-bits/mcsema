#!/bin/bash

source env.sh

rm -f demo_stderr.cfg demo_driver_stderr.o demo_stderr.o demo_stderr_mine.o demo_driver_stderr.exe

${CC} -ggdb -m64 -c -o demo_stderr.o demo_stderr.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="stderr_map.txt" -entry-symbol=print_it -i=demo_stderr.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="stderr_map.txt" -entry-symbol=print_it -i=demo_stderr.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_stderr.cfg -driver=stderr_entry,print_it,raw,return,C -o demo_stderr.bc

${LLVM_PATH}/opt -O3 -o demo_stderr_opt.bc demo_stderr.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_stderr_mine.o demo_stderr_opt.bc
${CC} -ggdb -m64 -o demo_driver_stderr.exe demo_driver_stderr.c demo_stderr_mine.o
./demo_driver_stderr.exe

