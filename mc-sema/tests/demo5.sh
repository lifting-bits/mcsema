#!/bin/bash

source env.sh

rm -f demo_test5.cfg demo_driver5.o demo_test5.o demo_test5_mine.o demo_driver5.exe

${CC} -ggdb -m32 -c -o demo_test5.o demo_test5.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -func-map="demo5_map.txt" -entry-symbol=foo -i=demo_test5.o >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -func-map="demo5_map.txt" -entry-symbol=foo -i=demo_test5.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -i demo_test5.cfg -driver=demo5_entry,foo,1,return,C -o demo_test5.bc

${LLVM_PATH}/opt -O3 -o demo_test5_opt.bc demo_test5.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test5_mine.o demo_test5_opt.bc
${CC} -ggdb -m32 -o demo_driver5.exe demo_driver5.c demo_test5_mine.o
./demo_driver5.exe
echo "driver5" > /tmp/demo5_foo.txt
./demo_driver5.exe
rm -f /tmp/demo5_foo.txt
