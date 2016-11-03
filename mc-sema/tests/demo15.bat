@echo off
call env.bat

del /q demo_test15.obj demo_test15_lifted.obj demo_test15.cfg demo_test15.bc demo_test15_opt.bc demo_driver15.exe
cl /nologo /c demo_test15.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=%STD_DEFS% -entry-symbol=_imcdecl,_imstdcall@8,@imfastcall@8 -i=demo_test15.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test15.cfg -entrypoint=_imcdecl -entrypoint=_imstdcall@8 -entrypoint=@imfastcall@8 -o demo_test15.bc

clang -target i386-pc-win32 -O3 -m32 -c -o demo15_bc.obj demo_test15.bc
clang -target i386-pc-win32 -O3 -m32 -c -o demo15_asm.obj ..\..\drivers\PE_32_windows.asm
cl /Zi /nologo demo_driver15.c demo15_bc.obj demo15_asm.obj

demo_driver15.exe
