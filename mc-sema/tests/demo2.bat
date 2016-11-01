@echo off
call env.bat

del /q demo_test2.cfg demo_driver2.obj demo_test2.obj demo_test2_mine.obj demo_driver2.exe 
%NASM_PATH%\nasm.exe -f win32 -o demo_test2.obj demo_test2.asm 

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -march=x86 -entry-symbol=start -i=demo_test2.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test2.cfg -entrypoint=start -o demo_test2.bc
clang -O3 -m32 -o demo_driver2.exe demo_driver2.c ..\..\drivers\PE_32_windows.asm demo_test2.bc

demo_driver2.exe
