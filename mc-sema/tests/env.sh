LLVM_PATH=$(<./LLVM_PATH.linux)
CFG_TO_BC_PATH=$(<./CFG_TO_BC_PATH.linux)
BIN_DESCEND_PATH=$(<./BIN_DESCEND_PATH.linux)
IDA_PATH=$(<./IDA_PATH.linux)
GET_CFG_PY=${BIN_DESCEND_PATH}/get_cfg.py
STD_DEFS=$(<./STD_DEFS.linux)
RUNTIME_PATH=$(<./RUNTIME_PATH.linux)
CC=clang
CXX=clang++
export TVHEADLESS=1
export IDALOG=/dev/null
export IDA_PATH
