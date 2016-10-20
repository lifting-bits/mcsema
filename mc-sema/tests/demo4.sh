#!/bin/bash

source env.sh

rm -f demo_test4.cfg demo_driver4.o demo_test4.o demo_test4_mine.o demo_driver4.exe

${CC} -ggdb -m32 -c -o demo_test4.o demo_test4.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo4_map.txt" -entry-symbol=doTrans -i=demo_test4.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test4.cfg -entrypoint=doTrans -o demo_test4.bc
clang-3.5 -O3 -m32 -o demo_driver4.exe demo_driver4.c ../../drivers/ELF_32_linux.S demo_test4.bc

./demo_driver4.exe
