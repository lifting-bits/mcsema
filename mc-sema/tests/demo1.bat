@echo off

call env.bat

del /q demo_test1.cfg demo_driver1.obj demo_test1.obj demo_test1_mine.obj demo_driver1.exe 

%NASM_PATH%\nasm.exe -f win32 -o demo_test1.obj demo_test1.asm 


if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    echo %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=start -i=demo_test1.obj
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=start -i=demo_test1.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test1.cfg -entrypoint=start -o demo_test1.bc

clang -O3 -m32 -o demo_driver1.exe demo_driver1.c ..\..\drivers\PE_32_windows.asm demo_test1.bc
demo_driver1.exe
