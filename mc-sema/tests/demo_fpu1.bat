@echo off
call env.bat

del /q demo_fpu1.obj demo_fpu1_mine.obj demo_fpu1.cfg demo_fpu1.bc demo_fpu1_opt.bc demo_driver_fpu1.exe
cl /nologo /arch:IA32 /c demo_fpu1.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=_timespi -i=demo_fpu1.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -entry-symbol=_timespi -i=demo_fpu1.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_fpu1.cfg -driver=demo_fpu1_entry,_timespi,raw,return,C -o demo_fpu1.bc

%LLVM_PATH%\opt.exe -O3 -o demo_fpu1_opt.bc demo_fpu1.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_fpu1_mine.obj demo_fpu1_opt.bc
cl /Zi /nologo demo_driver_fpu1.c demo_fpu1_mine.obj
demo_driver_fpu1.exe
