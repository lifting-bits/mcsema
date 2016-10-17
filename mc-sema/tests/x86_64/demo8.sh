#!/bin/bash

source env.sh

rm -f demo_test8.cfg demo_driver8.o demo_test8.o demo_test8_mine.o demo_driver8.exe

${CC} -ggdb -m64 -c -o demo_test8.o demo_test8.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -entry-symbol=doOp -i=demo_test8.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test8.cfg -entrypoint=doOp -o demo_test8.bc
clang-3.5 -O3 -m64 -o demo_driver8.exe demo_driver8.c ../../../drivers/ELF_64_linux.S demo_test8.bc
./demo_driver8.exe
