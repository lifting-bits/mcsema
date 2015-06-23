@echo off
call env.bat

del /q demo_test10.obj demo_test10_mine.obj demo_test10.cfg demo_test10.bc demo_test10_opt.bc demo_driver10.exe
cl /nologo /c demo_test10.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=%STD_DEFS% -entry-symbol=_printdata -i=demo_test10.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -march=x86-64 -func-map=%STD_DEFS% -entry-symbol=printdata -i=demo_test10.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86-64 -i demo_test10.cfg -driver=demo10_entry,printdata,0,return,C -o demo_test10.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test10_opt.bc demo_test10.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test10_mine.obj demo_test10_opt.bc
cl /Zi /nologo demo_driver10.c demo_test10_mine.obj
demo_driver10.exe
