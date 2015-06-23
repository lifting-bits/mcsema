@echo off

call env.bat

del /q demo_test1.cfg demo_driver1.obj demo_test1.obj demo_test1_mine.obj demo_driver1.exe 

%NASM_PATH%\nasm.exe -f win64 -o demo_test1.obj demo_test1.asm 


if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=start -i=demo_test1.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86-64 -d -entry-symbol=start -i=demo_test1.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_test1.cfg -march=x86-64 -driver=demo1_entry,start,raw,return,C -o demo_test1.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test1_opt.bc demo_test1.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test1_mine.obj demo_test1_opt.bc
%LLVM_PATH%\llc.exe -filetype=asm -o demo_test1_mine.asm demo_test1_opt.bc
cl /Zi /nologo demo_driver1.c demo_test1_mine.obj
@demo_driver1.exe
