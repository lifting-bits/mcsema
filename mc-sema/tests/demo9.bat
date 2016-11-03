@echo off
call env.bat

del /q demo_test9.obj demo_test9_mine.obj demo_test9.cfg demo_test9.bc demo_test9_opt.bc demo_driver9.exe
cl /nologo /c demo_test9.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_printit -i=demo_test9.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test9.cfg -entrypoint=_printit -o demo_test9.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo9_bc.obj demo_test9.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo9_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver9.c demo9_bc.obj demo9_asm.obj

demo_driver9.exe
