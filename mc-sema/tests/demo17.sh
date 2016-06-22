#!/bin/bash

source env.sh

rm -f demo17 demo17.bc demo17.cfg demo17_opt.bc demo17_out.exe

${CC} -ggdb -m32 -o demo17 demo17.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    IDALOG=logfile_demo17.txt
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -func-map=${STD_DEFS}/linux.txt -i=demo17 -entry-symbol=main >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86 -func-map=${STD_DEFS}/linux.txt -i=demo17 -entry-symbol=main
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo17.cfg -driver=mcsema_main,main,2,return,C -o demo17.bc
${LLVM_PATH}/opt -O3 -o demo17_opt.bc demo17.bc
${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_i386_callback.bc demo17_opt.bc > demo17_linked.bc
${LLVM_PATH}/llc -filetype=obj -o demo17.o demo17_linked.bc

${CC} -m32 -ggdb -o demo17_out.exe driver_demo17.c demo17.o

./demo17_out.exe
