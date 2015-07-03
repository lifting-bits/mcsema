@echo off

call env.bat

del /q demo_test3.cfg demo_driver3.obj demo_test3.obj demo_test3_mine.obj demo_driver3.exe 
cl /nologo /c demo_test3.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=_demo3 -i=demo_test3.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -entry-symbol=_demo3 -i=demo_test3.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86 -i demo_test3.cfg -driver=demo3_entry,_demo3,2,return,C -o demo_test3.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test3_opt.bc demo_test3.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test3_mine.obj demo_test3_opt.bc
cl /Zi /nologo demo_driver3.c demo_test3_mine.obj
demo_driver3.exe
