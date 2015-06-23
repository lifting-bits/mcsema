@echo off

call env.bat

del /q demo_test6.obj demo_test6_mine.obj demo_test6.cfg demo_test6.bc demo_test6_opt.bc demo_driver6.exe
cl /nologo /c demo_test6.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map="%STD_DEFS%" -entry-symbol=_doWork -i=demo_test6.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86-64 -d -func-map="%STD_DEFS%"  -entry-symbol=doWork -i=demo_test6.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86-64 -i demo_test6.cfg -driver=demo6_entry,doWork,2,return,C -o demo_test6.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test6_opt.bc demo_test6.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test6_mine.obj demo_test6_opt.bc
cl /Zi /nologo demo_driver6.c demo_test6_mine.obj
demo_driver6.exe
