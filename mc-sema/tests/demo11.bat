@echo off
call env.bat

del /q demo_test11.obj demo_test11_mine.obj demo_test11.cfg demo_test11.bc demo_test11_opt.bc demo_driver11.exe
cl /nologo /c demo_test11.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=%STD_DEFS% -entry-symbol=_printdata -i=demo_test11.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test11.cfg -entrypoint=_printdata -o demo_test11.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo11_bc.obj demo_test11.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo11_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver11.c demo11_bc.obj demo11_asm.obj

demo_driver11.exe
