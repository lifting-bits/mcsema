#!/bin/bash

source env.sh

rm -f demo_qsort.cfg demo_driver_qsort.o demo_qsort.o demo_qsort_mine.o demo_driver_qsort.exe

${CC} -ggdb -m64 -c -o demo_qsort.o demo_qsort.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="qsort_map.txt" -entry-symbol=print_it -i=demo_qsort.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -func-map="qsort_map.txt" -entry-symbol=print_it -i=demo_qsort.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_qsort.cfg -driver=qsort_entry,print_it,raw,return,C -o demo_qsort.bc

${LLVM_PATH}/opt -O3 -o demo_qsort_opt.bc demo_qsort.bc
${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc demo_qsort_opt.bc > demo_qsort_linked.bc
${LLVM_PATH}/llc -march=x86-64 -filetype=obj -o demo_qsort_mine.o demo_qsort_linked.bc
${CC} -ggdb -m64 -o demo_driver_qsort.exe demo_driver_qsort.c demo_qsort_mine.o
./demo_driver_qsort.exe

