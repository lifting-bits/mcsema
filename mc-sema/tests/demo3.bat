@echo off

call env.bat

del /q demo_test3.cfg demo_driver3.obj demo_test3.obj demo_test3_mine.obj demo_driver3.exe 
cl /nologo /c demo_test3.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=_demo3 -i=demo_test3.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test3.cfg -entrypoint=_demo3 -o demo_test3.bc

clang -O3 -m32 -c -o demo3_bc.obj demo_test3.bc
clang -O3 -m32 -c -o demo3_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /NOLOGO demo_driver3.c demo3_bc.obj demo3_asm.obj

demo_driver3.exe
