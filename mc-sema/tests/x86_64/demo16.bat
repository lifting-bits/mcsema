@echo off
call env.bat

del /q demo_test16.obj demo_test16_lifted.obj demo_test16.cfg demo_test16.bc demo_test16_opt.bc demo_driver16.exe
cl /nologo /c demo_test16.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=demo16_defs.txt,%STD_DEFS% -entry-symbol=_shiftit -i=demo_test16.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86-64 -d -func-map=demo16_defs.txt,%STD_DEFS% -entry-symbol=shiftit -i=demo_test16.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86-64 -i demo_test16.cfg -driver=shiftit,shiftit,2,return,C  -o demo_test16.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test16_opt.bc demo_test16.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test16_lifted.obj demo_test16_opt.bc
cl /Zi /nologo demo_driver16.c demo_test16_lifted.obj
demo_driver16.exe
