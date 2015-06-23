@echo off
call env.bat

del /q demo_test12.cfg demo_driver12.obj demo_test12.obj demo_test12_mine.obj demo_driver12.exe 
%NASM_PATH%\nasm.exe -f win64 -o demo_test12.obj demo_test12.asm 

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=start -i=demo_test12.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86-64 -d -entry-symbol=start -i=demo_test12.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86-64 -i demo_test12.cfg -driver=demo12_entry,start,raw,return,C -o demo_test12.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test12_opt.bc demo_test12.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test12_mine.obj demo_test12_opt.bc
cl /Zi /nologo demo_driver12.c demo_test12_mine.obj
demo_driver12.exe
