
#!/bin/bash

source env.sh

rm -f demo_test8.cfg demo_driver8.o demo_test8.o demo_test8_mine.o demo_driver8.exe

${CC} -ggdb -m32 -c -o demo_test8.o demo_test8.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    export IDALOG=logfile_demo8.txt
    rm -f ${IDALOG}
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -d -march=x86 -entry-symbol=doOp -i=demo_test8.o >> ${IDALOG}
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -march=x86 -d -entry-symbol=doOp -i=demo_test8.o
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=i686-pc-linux-gnu -i demo_test8.cfg -driver=demo8_entry,doOp,1,return,C -o demo_test8.bc

${LLVM_PATH}/opt -O3 -o demo_test8_opt.bc demo_test8.bc
${LLVM_PATH}/llc -filetype=obj -o demo_test8_mine.o demo_test8_opt.bc
${CC} -ggdb -m32 -o demo_driver8.exe demo_driver8.c demo_test8_mine.o
./demo_driver8.exe
