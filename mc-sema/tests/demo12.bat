@echo off
call env.bat

del /q demo_test12.cfg demo_driver12.obj demo_test12.obj demo_test12_mine.obj demo_driver12.exe 
%NASM_PATH%\nasm.exe -f win32 -o demo_test12.obj demo_test12.asm 

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=start -i=demo_test12.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test12.cfg -entrypoint=start -o demo_test12.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo12_bc.obj demo_test12.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo12_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver12.c demo12_bc.obj demo12_asm.obj

demo_driver12.exe
