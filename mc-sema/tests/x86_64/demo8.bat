@echo off
call env.bat

del /q demo_test8.obj demo_test8_mine.obj demo_test8.cfg demo_test8.bc demo_test8_opt.bc demo_driver8.exe
cl /nologo /c demo_test8.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=doOp -i=demo_test8.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test8.cfg -entrypoint=doOp -o demo_test8.bc
clang-cl /Zi -O3 -m64 -o demo_driver8.exe demo_driver8.c ..\..\..\drivers\PE_64_windows.asm demo_test8.bc
demo_driver8.exe
