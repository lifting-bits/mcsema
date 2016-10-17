#!/bin/bash

source env.sh

rm -f sailboat.o sailboat_mine.o sailboat.cfg sailboat.bc sailboat_opt.bc sailboat_run.exe

${CC} -O2 -ggdb -m64 -c -o sailboat.o sailboat.c 

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -func-map=sailboat.txt -entry-symbol=keycomp -i=sailboat.o>> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i sailboat.cfg -entrypoint=keycomp -o sailboat.bc
clang-3.5 -O3 -m64 -o sailboat_run.exe sailboat_run.c ../../../drivers/ELF_64_linux.S sailboat.bc

./sailboat_run.exe "key{d9dd1cb9dc13ebc3dc3780d76123ee34}"
