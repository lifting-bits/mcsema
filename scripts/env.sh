#!/bin/bash

MYDIR=$(dirname ${0})/..
LLVM_PATH=${MYDIR}/bin
CFG_TO_BC_PATH=${MYDIR}/bin
BIN_DESCEND_PATH=${MYDIR}/bin
IDA=$(locate idal64 | head -n1)
if [ ! -e "${IDA}" ]
then
  echo "Could not locate IDA! Please edit ${DIR}/env.sh and manually specify it"
  exit 1
fi
IDA_PATH=$(dirname ${IDA})
GET_CFG_PY=${BIN_DESCEND_PATH}/get_cfg.py
CC=clang
CXX=clang++
RUNTIME_PATH=${MYDIR}/runtime
STD_DEFS=${MYDIR}/stddefs
DRIVER_PATH=${MYDIR}/drivers
export TVHEADLESS=1
export IDA_PATH
