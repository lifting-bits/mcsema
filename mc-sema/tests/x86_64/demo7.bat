@echo off
call env.bat

del /q demo_test7.obj demo_test7_mine.obj demo_test7.cfg demo_test7.bc demo_test7_opt.bc demo_driver7.exe
cl /nologo /c demo_test7.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map="%STD_DEFS%" -entry-symbol=checkFn -i=demo_test7.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -march=x86-64 -func-map="%STD_DEFS%" -entry-symbol=checkFn -i=demo_test7.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-win32 -i demo_test7.cfg -driver=demo7_entry,checkFn,1,return,C -o demo_test7.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test7_opt.bc demo_test7.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test7_mine.obj demo_test7_opt.bc
cl /Zi /nologo demo_driver7.c demo_test7_mine.obj
demo_driver7.exe
