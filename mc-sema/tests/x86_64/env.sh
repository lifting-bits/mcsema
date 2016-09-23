LLVM_PATH=$(<./LLVM_PATH.linux)
CFG_TO_BC_PATH=$(<./CFG_TO_BC_PATH.linux)
BIN_DESCEND_PATH=$(<./BIN_DESCEND_PATH.linux)
IDA_PATH=$(<./IDA_PATH.linux)
GET_CFG_PY=${BIN_DESCEND_PATH}/get_cfg.py
STD_DEFS=$(<./STD_DEFS.linux)
CC=clang
CXX=clang++
RUNTIME_PATH=$(<./RUNTIME_PATH.linux)
export TVHEADLESS=1
export IDALOG=logfile.txt
export IDA_PATH
