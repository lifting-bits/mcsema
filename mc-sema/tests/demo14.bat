@echo off
call env.bat

del /q demo_test14.obj demo_test14_lifted.obj demo_test14.cfg demo_test14.bc demo_test14_opt.bc demo_driver14.exe
cl /nologo /c demo_test14.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=demo14_defs.txt -entry-symbol=_printMessages -i=demo_test14.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -func-map=demo14_defs.txt -entry-symbol=_printMessages -i=demo_test14.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test14.cfg -driver=demo14_entry,_printMessages,0,return,C -o demo_test14.bc

%LLVM_PATH%\opt.exe -O1 -o demo_test14_opt.bc demo_test14.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test14_lifted.obj demo_test14_opt.bc
"%VCINSTALLDIR%\bin\cl.exe" /Zi /nologo demo_driver14.c demo_test14_lifted.obj
demo_driver14.exe
