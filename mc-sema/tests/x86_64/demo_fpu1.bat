@echo off
call env.bat

del /q demo_fpu1.obj demo_fpu1_mine.obj demo_fpu1.cfg demo_fpu1.bc demo_fpu1_opt.bc demo_driver_fpu1.exe
cl /nologo /c demo_fpu1.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=timespi -i=demo_fpu1.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-win32 -i demo_fpu1.cfg -entrypoint=timespi -o demo_fpu1.bc
clang-cl /Zi -O3 -m64 -o demo_driver_fpu1.exe demo_driver_fpu1.c ..\..\..\drivers\PE_64_windows.asm demo_fpu1.bc

demo_driver_fpu1.exe
