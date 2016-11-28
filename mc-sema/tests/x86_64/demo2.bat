@echo off
call env.bat

del /q demo_test2.cfg demo_driver2.obj demo_test2.obj demo_test2_mine.obj demo_driver2.exe 
%NASM_PATH%\nasm.exe -f win64 -o demo_test2.obj demo_test2.asm 

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=start -i=demo_test2.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test2.cfg -entrypoint=start -o demo_test2.bc
clang-cl -O3 -m64 -o demo_driver2.exe demo_driver2.c ..\..\..\drivers\PE_64_windows.asm demo_test2.bc

demo_driver2.exe
