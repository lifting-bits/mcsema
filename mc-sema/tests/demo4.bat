@echo off

call env.bat

del /q demo_test4.obj demo_test4_mine.obj demo_test4.cfg demo_test4.bc demo_test4_opt.bc demo_driver4.exe
cl /nologo /c demo_test4.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_doTrans -i=demo_test4.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test4.cfg -entrypoint=_doTrans -o demo_test4.bc

clang -O3 -m32 -c -o demo4_bc.obj demo_test4.bc
clang -O3 -m32 -c -o demo4_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver4.c demo4_bc.obj demo4_asm.obj
demo_driver4.exe
