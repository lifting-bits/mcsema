@echo off

call env.bat

del /q demo_test4.obj demo_test4_mine.obj demo_test4.cfg demo_test4.bc demo_test4_opt.bc demo_driver4.exe
cl /nologo /c demo_test4.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map="%STD_DEFS%" -entry-symbol=_doTrans -i=demo_test4.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -func-map="%STD_DEFS%" -entry-symbol=_doTrans -i=demo_test4.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_test4.cfg -driver=demo4_entry,_doTrans,1,return,C -o demo_test4.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test4_opt.bc demo_test4.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test4_mine.obj demo_test4_opt.bc
cl /Zi /nologo demo_driver4.c demo_test4_mine.obj
demo_driver4.exe
