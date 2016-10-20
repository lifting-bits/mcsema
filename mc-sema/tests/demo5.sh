#!/bin/bash

source env.sh

rm -f demo_test5.cfg demo_driver5.o demo_test5.o demo_test5_mine.o demo_driver5.exe

${CC} -ggdb -m32 -c -o demo_test5.o demo_test5.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86 -func-map="demo5_map.txt" -entry-symbol=foo -i=demo_test5.o >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test5.cfg -entrypoint=foo -o demo_test5.bc
clang-3.5 -O3 -m32 -o demo_driver5.exe demo_driver5.c ../../drivers/ELF_32_linux.S demo_test5.bc

./demo_driver5.exe
echo "driver5" > /tmp/demo5_foo.txt
./demo_driver5.exe
rm -f /tmp/demo5_foo.txt
