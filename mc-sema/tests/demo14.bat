@echo off
call env.bat

del /q demo_test14.obj demo_test14_lifted.obj demo_test14.cfg demo_test14.bc demo_test14_opt.bc demo_driver14.exe
cl /nologo /c demo_test14.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=demo14_defs.txt -entry-symbol=_printMessages -i=demo_test14.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test14.cfg -entrypoint=_printMessages -o demo_test14.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo14_bc.obj demo_test14.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo14_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver14.c demo14_bc.obj demo14_asm.obj

demo_driver14.exe
