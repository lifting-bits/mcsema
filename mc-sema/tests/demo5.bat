@echo off
call env.bat

del /q demo_test5.obj demo_test5_mine.obj demo_test5.cfg demo_test5.bc demo_test5_opt.bc demo_driver5.exe
cl /nologo /c demo_test5.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_foo -i=demo_test5.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test5.cfg -entrypoint=_foo -o demo_test5.bc

clang -target i386-pc-win32 -O3 -m32 -c -o demo5_bc.obj demo_test5.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo5_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver5.c demo5_bc.obj demo5_asm.obj

demo_driver5.exe
echo "driver5" > C:\windows\temp\foo.txt
demo_driver5.exe
del /q C:\windows\temp\foo.txt
