@echo off
call env.bat

del /q demo_test11.obj demo_test11_mine.obj demo_test11.cfg demo_test11.bc demo_test11_opt.bc demo_driver11.exe
cl /nologo /c demo_test11.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map=%STD_DEFS% -entry-symbol=printdata -i=demo_test11.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test11.cfg -entrypoint=printdata -o demo_test11.bc
clang-cl /Zi -O3 -m64 -o demo_driver11.exe demo_driver11.c ..\..\..\drivers\PE_64_windows.asm demo_test11.bc
demo_driver11.exe
