#!/bin/bash

source env.sh

rm -f demo_test6.cfg demo_driver6.o demo_test6.o demo_test6_mine.o demo_driver6.exe

${CC} -ggdb -m64 -c -o demo_test6.o demo_test6.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map="demo6_map.txt" -entry-symbol=doWork -i=demo_test6.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test6.cfg -entrypoint=doWork -o demo_test6.bc
clang-3.5 -O3 -m64 -o demo_driver6.exe demo_driver6.c ../../../drivers/ELF_64_linux.S demo_test6.bc

./demo_driver6.exe
