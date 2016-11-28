@echo off

call env.bat

del /q demo_test3.cfg demo_driver3.obj demo_test3.obj demo_test3_mine.obj demo_driver3.exe 
cl /nologo /c demo_test3.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=demo3 -i=demo_test3.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test3.cfg -entrypoint=demo3 -o demo_test3.bc

clang-cl /Zi -O3 -m64 -o demo_driver3.exe demo_driver3.c ..\..\..\drivers\PE_64_windows.asm demo_test3.bc
demo_driver3.exe
