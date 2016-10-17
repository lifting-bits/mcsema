#!/bin/bash

source env.sh

rm -f demo_stderr.cfg demo_driver_stderr.o demo_stderr.o demo_stderr_mine.o demo_driver_stderr.exe

${CC} -ggdb -m64 -c -o demo_stderr.o demo_stderr.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="stderr_map.txt" -entry-symbol=print_it -i=demo_stderr.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_stderr.cfg -entrypoint=print_it -o demo_stderr.bc
clang-3.5 -O3 -m64 -o demo_driver_stderr.exe demo_driver_stderr.c ../../../drivers/ELF_64_linux.S demo_stderr.bc

./demo_driver_stderr.exe

