@echo off
call env.bat

del /q demo_test16.obj demo_test16_lifted.obj demo_test16.cfg demo_test16.bc demo_test16_opt.bc demo_driver16.exe
cl /nologo /c demo_test16.c

set TVHEADLESS=1
set IDALOG=ida.log
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=demo16_defs.txt,%STD_DEFS% -entry-symbol=_shiftit -i=demo_test16.obj > %IDALOG%
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -post-analysis=false -mtriple=i686-pc-win32 -i demo_test16.cfg -entrypoint=_shiftit -o demo_test16.bc

clang -target i686-pc-win32 -O3 -m32 -c -o demo16_bc.obj demo_test16.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo16_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver16.c aullshr.c demo16_bc.obj demo16_asm.obj
demo_driver16.exe
