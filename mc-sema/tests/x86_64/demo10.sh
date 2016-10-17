#!/bin/bash

source env.sh

rm -f demo_test10.cfg demo_driver10.o demo_test10.o demo_test10_mine.o demo_driver10.exe

${CC} -ggdb -m64 -c -o demo_test10.o demo_test10.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -march=x86-64 -func-map="demo10_map.txt" -entry-symbol=printdata -i=demo_test10.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test10.cfg -entrypoint=printdata -o demo_test10.bc
clang-3.5 -O3 -m64 -o demo_driver10.exe demo_driver10.c ../../../drivers/ELF_64_linux.S demo_test10.bc

./demo_driver10.exe
