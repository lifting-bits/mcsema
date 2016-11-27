@echo off

call env.bat

del /q demo_test1.cfg demo_driver1.obj demo_test1.obj demo_test1_mine.obj demo_driver1.exe 

%NASM_PATH%\nasm.exe -f win64 -o demo_test1.obj demo_test1.asm 


set TVHEADLESS=1
set IDALOG=ida.log
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=start -i=demo_test1.obj > %IDALOG%
) else (
    echo Bin_descend is no longer supported
    REM exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test1.cfg -entrypoint=start -o demo_test1.bc

clang-cl -O3 -m64 -o demo_driver1.exe demo_driver1.c ..\..\..\drivers\PE_64_windows.asm demo_test1.bc
demo_driver1.exe
