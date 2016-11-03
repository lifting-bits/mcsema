@echo off

call env.bat

del /q demo_test6.obj demo_test6_mine.obj demo_test6.cfg demo_test6.bc demo_test6_opt.bc demo_driver6.exe
cl /nologo /c demo_test6.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_doWork -i=demo_test6.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test6.cfg -entrypoint=_doWork -o demo_test6.bc

clang -target i386-pc-win32 -O3 -m32 -c -o demo6_bc.obj demo_test6.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo6_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver6.c demo6_bc.obj demo6_asm.obj

demo_driver6.exe
