#!/bin/bash

source env.sh

rm -f demo_test9.cfg demo_driver9.o demo_test9.o demo_test9_mine.o demo_driver9.exe

${CC} -ggdb -m32 -c -o demo_test9.o demo_test9.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo9_map.txt" -entry-symbol=printit -i=demo_test9.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test9.cfg -entrypoint=printit -o demo_test9.bc
clang-3.5 -O3 -m32 -o demo_driver9.exe demo_driver9.c ../../drivers/ELF_32_linux.S demo_test9.bc

./demo_driver9.exe
