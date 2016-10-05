#!/bin/bash

source env.sh

BINF=$1

IDALOG=${BINF}_log.txt
rm -f ${IDALOG} ${BINF}{_out,.cfg,.bc,_opt.bc}

if [ -e "${IDA_PATH}/idaq" ]
then
    echo "Using IDA to recover CFG"
    echo "${BIN_DESCEND_PATH}/bin_descend_wrapper.py -march=x86-64 --stack-vars -d -func-map=${STD_DEFS} -i=${BINF} >> out.txt"
    ${BIN_DESCEND_PATH}/bin_descend_wrapper.py -entry-symbol=main -march=x86-64 --stack-vars -d -func-map=${STD_DEFS} -i=${BINF} >> out.txt
else
    echo "Using bin_descend to recover CFG"
    ${BIN_DESCEND_PATH}/bin_descend -d -march=x86_64 -func-map=${STD_DEFS} -i=${BINF} -entry-symbol=main
fi

echo "${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i ${BINF}.cfg -driver=mcsema_main,main,raw,return,C -o ${BINF}.bc >> $IDALOG"
${CFG_TO_BC_PATH}/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i ${BINF}.cfg -driver=mcsema_main,main,raw,return,C -o ${BINF}.bc >> $IDALOG

#${LLVM_PATH}/opt -O0 -o ${BINF}_opt.bc ${BINF}.bc
cp ${BINF}.bc ${BINF}_opt.bc
echo "${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc ${BINF}_opt.bc > ${BINF}_linked.bc"
${LLVM_PATH}/llvm-link ${RUNTIME_PATH}/linux_amd64_callback.bc ${BINF}_opt.bc > ${BINF}_linked.bc
${LLVM_PATH}/llc -filetype=obj -o ${BINF}.o ${BINF}_linked.bc

${CC} -m64 -ggdb -o ${BINF}_out driver_amd64.c ${BINF}.o -lcrypt
