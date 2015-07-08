@echo off
call env.bat

del /q demo_test2.cfg demo_driver2.obj demo_test2.obj demo_test2_mine.obj demo_driver2.exe 
%NASM_PATH%\nasm.exe -f win64 -o demo_test2.obj demo_test2.asm 

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=start -i=demo_test2.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -march=x86-64 -entry-symbol=start -i=demo_test2.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-win32 -i demo_test2.cfg -driver=demo2_entry,start,raw,return,C -o demo_test2.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test2_opt.bc demo_test2.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test2_mine.obj demo_test2_opt.bc
cl /Zi /nologo demo_driver2.c demo_test2_mine.obj
demo_driver2.exe
