@echo off
call env.bat

del /q demo_test8.obj demo_test8_mine.obj demo_test8.cfg demo_test8.bc demo_test8_opt.bc demo_driver8.exe
cl /nologo /c demo_test8.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -entry-symbol=_doOp -i=demo_test8.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -entry-symbol=_doOp -i=demo_test8.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i demo_test8.cfg -driver=demo8_entry,_doOp,1,return,C -o demo_test8.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test8_opt.bc demo_test8.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test8_mine.obj demo_test8_opt.bc
"%VCINSTALLDIR%\bin\cl.exe" /Zi /nologo demo_driver8.c demo_test8_mine.obj
demo_driver8.exe
