@echo off
call env.bat

del /q demo_test11.obj demo_test11_mine.obj demo_test11.cfg demo_test11.bc demo_test11_opt.bc demo_driver11.exe
cl /nologo /c demo_test11.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=%STD_DEFS% -entry-symbol=_printdata -i=demo_test11.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -func-map=%STD_DEFS% -entry-symbol=_printdata -i=demo_test11.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_test11.cfg -driver=demo11_entry,_printdata,0,return,C -o demo_test11.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test11_opt.bc demo_test11.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test11_mine.obj demo_test11_opt.bc
cl /Zi /nologo demo_driver11.c demo_test11_mine.obj
demo_driver11.exe
