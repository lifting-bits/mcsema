#!/bin/bash

source env.sh

rm -f demo_cpp.bc demo_cpp.cfg

${CXX} -ggdb -m32 -o demo_cpp demo_cpp.cpp

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -func-map=linux_map.txt -i=demo_cpp -entry-symbol=main
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -func-map=linux_map.txt -i=demo_cpp -entry-symbol=main
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_cpp.cfg -driver=mcsema_main,main,2,return,C -o demo_cpp.bc

#${LLVM_PATH}/opt -O3 -o demo_test3_opt.bc demo_test3.bc
#${LLVM_PATH}/llc -filetype=obj -o demo_test3_mine.o demo_test3_opt.bc
#${CC} -ggdb -m32 -o demo_driver3.exe demo_driver3.c demo_test3_mine.o
#./demo_driver3.exe
