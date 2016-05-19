#!/bin/bash

DIR=$(dirname ${0})/..
LLVM_PATH=${DIR}/bin
CFG_TO_BC_PATH=${DIR}/bin
BIN_DESCEND_PATH=${DIR}/bin
IDA=$(locate idal64 | head -n1)
IDA_PATH=$(dirname ${IDA})
GET_CFG_PY=${BIN_DESCEND_PATH}/get_cfg.py
CC=clang
CXX=clang++
RUNTIME_PATH=${DIR}/runtime
STD_DEFS=${DIR}/stddefs
DRIVER_PATH=${DIR}/drivers
export TVHEADLESS=1
export IDA_PATH
