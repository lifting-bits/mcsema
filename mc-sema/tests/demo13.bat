@echo off
call env.bat

del /q demo_test13.obj demo_test13_lifted.obj demo_test13.cfg demo_test13.bc demo_test13_opt.bc demo_driver13.exe
cl /nologo /c demo_test13.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=%STD_DEFS% -entry-symbol=_switches -i=demo_test13.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test13.cfg -entrypoint=_switches -o demo_test13.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo13_bc.obj demo_test13.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo13_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver13.c demo13_bc.obj demo13_asm.obj

demo_driver13.exe
