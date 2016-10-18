#!/bin/bash

source env.sh

rm -f demo_fpu1.cfg demo_driver_fpu1.o demo_fpu1.o demo_fpu1_mine.o demo_driver_fpu1.exe

${CC} -ggdb -m64 -c -o demo_fpu1.o demo_fpu1.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=timespi -i=demo_fpu1.o>> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_fpu1.cfg -entrypoint=timespi -o demo_fpu1.bc
clang-3.5 -O3 -m64 -o demo_driver_fpu1.exe demo_driver_fpu1.c ../../../drivers/ELF_64_linux.S demo_fpu1.bc

./demo_driver_fpu1.exe
