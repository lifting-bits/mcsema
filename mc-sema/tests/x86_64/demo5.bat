@echo off
call env.bat

del /q demo_test5.obj demo_test5_mine.obj demo_test5.cfg demo_test5.bc demo_test5_opt.bc demo_driver5.exe
cl /nologo /c demo_test5.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map="%STD_DEFS%" -entry-symbol=foo -i=demo_test5.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_test5.cfg -entrypoint=foo -o demo_test5.bc
clang-cl /Zi -O3 -m64 -o demo_driver5.exe demo_driver5.c ..\..\..\drivers\PE_64_windows.asm demo_test5.bc

demo_driver5.exe
echo "driver5" > %TMP%\foo.txt
demo_driver5.exe
del /q %TMP%\foo.txt
