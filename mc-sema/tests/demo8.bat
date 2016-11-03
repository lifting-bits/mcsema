@echo off
call env.bat

del /q demo_test8.obj demo_test8_mine.obj demo_test8.cfg demo_test8.bc demo_test8_opt.bc demo_driver8.exe
cl /nologo /c demo_test8.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=_doOp -i=demo_test8.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -post-analysis=false -mtriple=i386-pc-win32 -i demo_test8.cfg -entrypoint=_doOp -o demo_test8.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo8_bc.obj demo_test8.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo8_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver8.c demo8_bc.obj demo8_asm.obj

demo_driver8.exe
