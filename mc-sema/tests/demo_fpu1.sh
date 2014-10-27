#!/bin/bash

source env.sh

rm -f demo_fpu1.cfg demo_driver_fpu1.o demo_fpu1.o demo_fpu1_mine.o demo_driver_fpu1.exe

${CC} -ggdb -m32 -c -o demo_fpu1.o demo_fpu1.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -entry-symbol=timespi -i=demo_fpu1.o
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -entry-symbol=timespi -i=demo_fpu1.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_fpu1.cfg -driver=demo_fpu1_entry,timespi,raw,return,C -o demo_fpu1.bc

${LLVM_PATH}/opt -O3 -o demo_fpu1_opt.bc demo_fpu1.bc
${LLVM_PATH}/llc -filetype=obj -o demo_fpu1_mine.o demo_fpu1_opt.bc
${CC} -ggdb -m32 -o demo_driver_fpu1.exe demo_driver_fpu1.c demo_fpu1_mine.o
./demo_driver_fpu1.exe
