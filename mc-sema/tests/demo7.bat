@echo off
call env.bat

del /q demo_test7.obj demo_test7_mine.obj demo_test7.cfg demo_test7.bc demo_test7_opt.bc demo_driver7.exe
cl /nologo /c demo_test7.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_checkFn -i=demo_test7.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test7.cfg -entrypoint=_checkFn -o demo_test7.bc

clang -target i386-pc-win32 -O3 -m32 -c -o demo7_bc.obj demo_test7.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo7_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver7.c demo7_bc.obj demo7_asm.obj

demo_driver7.exe
