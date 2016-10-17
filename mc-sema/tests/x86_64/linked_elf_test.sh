#!/bin/bash

source env.sh

rm -f linked_elf linked_elf.bc linked_elf.cfg linked_elf_opt.bc linked_elf_out.exe

${CC} -ggdb -m64 -o linked_elf linked_elf.c

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 -d -func-map=${STD_DEFS} -i=linked_elf -entry-symbol=main >> /dev/null
else
    echo "Please install IDA to recover the control flow graph; bin_descend is now deprecated"
    exit 1
fi

${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i linked_elf.cfg -entrypoint=main -o linked_elf.bc
clang-3.5 -O3 -m64 -o linked_elf_out.exe ../../../drivers/ELF_64_linux.S linked_elf.bc

./linked_elf_out.exe
