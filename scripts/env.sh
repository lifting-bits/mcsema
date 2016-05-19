#!/bin/bash

MYDIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))/..
LLVM_PATH=${MYDIR}/bin
CFG_TO_BC_PATH=${MYDIR}/bin
BIN_DESCEND_PATH=${MYDIR}/bin
IDA=$(locate idal64 | head -n1)
IDA_PATH=$(dirname ${IDA})
GET_CFG_PY=${BIN_DESCEND_PATH}/get_cfg.py
CC=clang
CXX=clang++
RUNTIME_PATH=${MYDIR}/runtime
STD_DEFS=${MYDIR}/stddefs
DRIVER_PATH=${MYDIR}/drivers
export TVHEADLESS=1
export IDA_PATH
