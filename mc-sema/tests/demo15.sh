#!/bin/bash

source env.sh

rm -f demo_test15.cfg demo_driver15.o demo_test15.o demo_test15_mine.o demo_driver15.exe

${CC} -ggdb -m32 -c -o demo_test15.o demo_test15.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo15_map.txt" -entry-symbol=imcdecl,imstdcall,imfastcall -i=demo_test15.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test15.cfg -entrypoint=imcdecl -entrypoint=imstdcall -entrypoint=imfastcall -o demo_test15.bc
clang-3.5 -O3 -m32 -o demo_driver15.exe demo_driver15.c ../../drivers/ELF_32_linux.S demo_test15.bc

./demo_driver15.exe
