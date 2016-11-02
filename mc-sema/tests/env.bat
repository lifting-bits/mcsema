set /p LLVM_PATH= < LLVM_PATH.win32
if not exist "%LLVM_PATH%\llc.exe" (
set LLVM_PATH=%LLVM_PATH%\..
)
set /p CFG_TO_BC_PATH= < CFG_TO_BC_PATH.win32
if not exist "%CFG_TO_BC_PATH%\cfg_to_bc.exe" (
set CFG_TO_BC_PATH=%CFG_TO_BC_PATH%\..
)
set /p BIN_DESCEND_PATH=< BIN_DESCEND_PATH.win32
if not exist "%BIN_DESCEND_PATH%\bin_descend.exe" (
set BIN_DESCEND_PATH=%BIN_DESCEND_PATH%\..
)
set /p NASM_PATH=< NASM_PATH.win32
set /p IDA_PATH=< IDA_PATH.win32
set GET_CFG_PY=%BIN_DESCEND_PATH%\get_cfg.py
set STD_DEFS=..\std_defs\windows.txt
set PYTHON=C:\Python27\python.exe
