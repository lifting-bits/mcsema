#!/bin/bash

set -u

BCONLY=0

if [ "$1" == "--bitcode_only" ]
then
    BCONLY=1
    shift
fi

WHICHBIN=$1
DIR=$(dirname ${0})
source ${DIR}/mcsema_common.sh
source ${DIR}/env.sh

sanity_check

export TVHEADLESS=1
TARGET=thttpd

WORKSPACE=$(mktemp -d --tmpdir=`pwd` ${TARGET}_XXXX)
export IDALOG=${WORKSPACE}/logfile_${TARGET}.txt
rm -f ${IDALOG} ${WHICHBIN}_out.exe ${WHICHBIN}.cfg ${WHICHBIN}.bc ${WHICHBIN}_opt.bc

echo "IDA Binary: ${IDA}"
echo "${TARGET} binary: ${WHICHBIN}"
echo "External definition files in: ${STD_DEFS}"
echo "Runtime files: ${RUNTIME_PATH}"
echo ""
echo "Workspace directory: ${WORKSPACE}" 
echo "IDA Log: ${IDALOG}"

cp ${WHICHBIN} ${WORKSPACE}/${TARGET}
WHICHBIN=${WORKSPACE}/${TARGET}
recover_cfg ${WHICHBIN} ${WORKSPACE}/${TARGET}.cfg

convert_to_bc ${WORKSPACE}/${TARGET}.cfg ${WORKSPACE}/${TARGET}.bc

optimize_bc ${WORKSPACE}/${TARGET}.bc ${WORKSPACE}/${TARGET}_opt.bc

link_amd64_callback ${WORKSPACE}/${TARGET}_opt.bc ${WORKSPACE}/${TARGET}_linked.bc

if [ ${BCONLY} == 1 ]
then
    echo "Final bitcode saved to: ${WORKSPACE}/${TARGET}_linked.bc"
else
    call_llc ${WORKSPACE}/${TARGET}_linked.bc ${WORKSPACE}/${TARGET}.o 

    echo "Relinking with dependent libraries (${WORKSPACE}/${TARGET}_out.exe)"
    ${CC} -I${DRIVER_PATH} -m64 -ggdb -o ${WORKSPACE}/${TARGET}_out.exe ${DRIVER_PATH}/httpd_linux_amd64.c ${WORKSPACE}/${TARGET}.o -lcrypt

    echo "Run with:"
    echo "${WORKSPACE}/${TARGET}_out.exe"
fi
