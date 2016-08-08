#!/bin/bash

source env.sh

rm -f linked_elf linked_elf.bc linked_elf.cfg linked_elf_opt.bc linked_elf_out.exe

${CC} -ggdb -m64 -o linked_elf linked_elf.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -func-map=${STD_DEFS} -i=linked_elf -entry-symbol=main >> /dev/null
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86-64 -func-map=${STD_DEFS} -i=linked_elf -entry-symbol=main
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i linked_elf.cfg -driver=mcsema_main,main,2,return,C -o linked_elf.bc
${LLVM_PATH}/opt -O3 -o linked_elf_opt.bc linked_elf.bc
${LLVM_PATH}/llc -filetype=obj -o linked_elf.o linked_elf_opt.bc

${CC} -m64 -ggdb -o linked_elf_out.exe driver_linked_elf.c linked_elf.o

./linked_elf_out.exe
