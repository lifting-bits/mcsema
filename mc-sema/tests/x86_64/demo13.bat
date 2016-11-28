@echo off
call env.bat

del /q demo_test13.obj demo_test13_lifted.obj demo_test13.cfg demo_test13.bc demo_test13_opt.bc demo_driver13.exe
cl /nologo /c demo_test13.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map=%STD_DEFS% -entry-symbol=switches -i=demo_test13.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test13.cfg -entrypoint=switches -o demo_test13.bc
clang-cl /Zi -O3 -m64 -o demo_driver13.exe demo_driver13.c ..\..\..\drivers\PE_64_windows.asm demo_test13.bc
demo_driver13.exe
