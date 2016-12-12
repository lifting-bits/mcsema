#!/bin/bash

source env.sh

BINF=$1
LIBS=$2

IDALOG=${BINF}_log.txt
rm -f ${IDALOG} ${BINF}{_out,.cfg,.bc,_opt.bc}

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    echo "${BIN_DESCEND_PATH}/bin_descend_wrapper.py --pie-mode -entry-symbol=main -march=x86-64 -d -func-map=${STD_DEFS} -i=${BINF} >> out.txt"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py --pie-mode -entry-symbol=main -march=x86-64 -d -func-map=${STD_DEFS},../../std_defs/apr_defs.txt,../../std_defs/pcre_defs.txt -i=${BINF} >> out.txt
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86_64 -func-map=${STD_DEFS} -i=${BINF} -entry-symbol=main
fi

echo "${CFG_TO_BC_PATH}/cfg_to_bc -put-instrs-in-blocks -mtriple=x86_64-pc-linux-gnu -i ${BINF}.cfg -entrypoint=main -o ${BINF}.bc >> $IDALOG"
${CFG_TO_BC_PATH}/cfg_to_bc -put-instrs-in-blocks -mtriple=x86_64-pc-linux-gnu -i ${BINF}.cfg -entrypoint=main -o ${BINF}.bc >> $IDALOG

cp ${BINF}.bc ${BINF}_opt.bc
echo "${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc ${BINF}_opt.bc > ${BINF}_linked.bc"
${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc ${BINF}_opt.bc > ${BINF}_linked.bc

echo "${CC} -O3 -m64 -ggdb -o ${BINF}_out ../../../drivers/ELF_64_linux.S -fPIC -fPIE -pie ${BINF}_linked.bc -lcrypt ${LIBS}/*  -lpcre -lm -lpthread"
${CC} -O3 -m64 -ggdb -o ${BINF}_out ../../../drivers/ELF_64_linux.S -fPIC -fPIE -pie ${BINF}_linked.bc -lcrypt ${LIBS}/*  -lpcre -lm -lpthread

execstack -c ${BINF}_out
