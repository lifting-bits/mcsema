@echo off

call env.bat

del /q demo_test4.obj demo_test4_mine.obj demo_test4.cfg demo_test4.bc demo_test4_opt.bc demo_driver4.exe
cl /nologo /c demo_test4.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map="%STD_DEFS%" -entry-symbol=doTrans -i=demo_test4.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)


%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test4.cfg -entrypoint=doTrans -o demo_test4.bc

clang-cl /Zi -O3 -m64 -o demo_driver4.exe demo_driver4.c ..\..\..\drivers\PE_64_windows.asm demo_test4.bc
demo_driver4.exe
