#!/bin/bash

source env.sh

rm -f demo_qsort.cfg demo_driver_qsort.o demo_qsort.o demo_qsort_mine.o demo_driver_qsort.exe

${CC} -ggdb -m64 -c -o demo_qsort.o demo_qsort.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="qsort_map.txt" -entry-symbol=print_it -i=demo_qsort.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_qsort.cfg -entrypoint=print_it -o demo_qsort.bc
clang-3.5 -O3 -m64 -o demo_driver_qsort.exe demo_driver_qsort.c ../../../drivers/ELF_64_linux.S demo_qsort.bc

./demo_driver_qsort.exe
