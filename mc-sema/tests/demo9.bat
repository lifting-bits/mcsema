@echo off
call env.bat

del /q demo_test9.obj demo_test9_mine.obj demo_test9.cfg demo_test9.bc demo_test9_opt.bc demo_driver9.exe
cl /nologo /c demo_test9.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_printit -i=demo_test9.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_printit -i=demo_test9.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86 -i demo_test9.cfg -driver=demo9_entry,_printit,1,return,C -o demo_test9.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test9_opt.bc demo_test9.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test9_mine.obj demo_test9_opt.bc
cl /Zi /nologo demo_driver9.c demo_test9_mine.obj
demo_driver9.exe
