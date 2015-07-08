#!/bin/bash

source env.sh

rm -f demo_fpu1.cfg demo_driver_fpu1.o demo_fpu1.o demo_fpu1_mine.o demo_driver_fpu1.exe

${CC} -ggdb -m64 -c -o demo_fpu1.o demo_fpu1.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=timespi -i=demo_fpu1.o>> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86-64 -d -entry-symbol=timespi -i=demo_fpu1.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i demo_fpu1.cfg -driver=demo_fpu1_entry,timespi,raw,return,C -o demo_fpu1.bc

${LLVM_PATH}/opt -march=x86-64 -O3 -o demo_fpu1_opt.bc demo_fpu1.bc
${LLVM_PATH}/llc -filetype=obj -o demo_fpu1_mine.o demo_fpu1_opt.bc
${CC} -ggdb -m64 -o demo_driver_fpu1.exe demo_driver_fpu1.c demo_fpu1_mine.o
./demo_driver_fpu1.exe
