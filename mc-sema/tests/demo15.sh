#!/bin/bash

source env.sh

rm -f demo_test15.cfg demo_driver15.o demo_test15.o demo_test15_mine.o demo_driver15.exe

${CC} -ggdb -m32 -c -o demo_test15.o demo_test15.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo15_map.txt" -entry-symbol=imcdecl,imstdcall,imfastcall -i=demo_test15.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86 -func-map="demo15_map.txt" -entry-symbol=imcdecl,imstdcall,imfastcall -i=demo_test15.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test15.cfg -driver=imcdecl,imcdecl,2,return,C -driver=imstdcall,imstdcall,2,return,E -driver=imfastcall,imfastcall,2,return,F -o demo_test15.bc

${LLVM_PATH}/opt -O3 -o demo_test15_opt.bc demo_test15.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test15_mine.o demo_test15_opt.bc
${CC} -ggdb -m32 -o demo_driver15.exe demo_driver15.c demo_test15_mine.o
./demo_driver15.exe
