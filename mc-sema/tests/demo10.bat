@echo off
call env.bat

del /q demo_test10.obj demo_test10_mine.obj demo_test10.cfg demo_test10.bc demo_test10_opt.bc demo_driver10.exe
cl /nologo /c demo_test10.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=%STD_DEFS% -entry-symbol=_printdata -i=demo_test10.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test10.cfg -entrypoint=_printdata -o demo_test10.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo10_bc.obj demo_test10.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo10_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver10.c demo10_bc.obj demo10_asm.obj

demo_driver10.exe
