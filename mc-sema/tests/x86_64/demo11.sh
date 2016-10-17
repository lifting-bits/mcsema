#!/bin/bash

source env.sh

rm -f demo_test11.cfg demo_driver11.o demo_test11.o demo_test11_mine.o demo_driver11.exe

${CC} -ggdb -m64 -c -o demo_test11.o demo_test11.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -func-map="demo11_map.txt" -entry-symbol=printdata -i=demo_test11.o >> logfile.txt
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_test11.cfg -entrypoint=printdata -o demo_test11.bc
clang-3.5 -O3 -m64 -o demo_driver11.exe demo_driver11.c ../../../drivers/ELF_64_linux.S demo_test11.bc

./demo_driver11.exe
