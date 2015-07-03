@echo off
call env.bat

del /q demo_test13.obj demo_test13_lifted.obj demo_test13.cfg demo_test13.bc demo_test13_opt.bc demo_driver13.exe
cl /nologo /c demo_test13.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=%STD_DEFS% -entry-symbol=switches -i=demo_test13.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -march=x86-64 -func-map=%STD_DEFS% -entry-symbol=switches -i=demo_test13.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86-64 -i demo_test13.cfg -driver=demo13_entry,switches,1,return,C -o demo_test13.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test13_opt.bc demo_test13.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test13_lifted.obj demo_test13_opt.bc
cl /Zi /nologo demo_driver13.c demo_test13_lifted.obj
demo_driver13.exe
