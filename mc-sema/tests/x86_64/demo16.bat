@echo off
call env.bat

del /q demo_test16.obj demo_test16_lifted.obj demo_test16.cfg demo_test16.bc demo_test16_opt.bc demo_driver16.exe
cl /nologo /c demo_test16.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map=%STD_DEFS% -entry-symbol=shiftit -i=demo_test16.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test16.cfg -entrypoint=shiftit -o demo_test16.bc
clang-cl /Zi -O3 -m64 -o demo_driver16.exe demo_driver16.c ..\..\..\drivers\PE_64_windows.asm demo_test16.bc
demo_driver16.exe
