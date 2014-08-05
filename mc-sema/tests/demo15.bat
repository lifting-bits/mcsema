@echo off
call env.bat

del /q demo_test15.obj demo_test15_lifted.obj demo_test15.cfg demo_test15.bc demo_test15_opt.bc demo_driver15.exe
cl /nologo /c demo_test15.c

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=%STD_DEFS% -entry-symbol=_imcdecl,_imstdcall@8,@imfastcall@8 -i=demo_test15.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -func-map=%STD_DEFS% -entry-symbol=_imcdecl,_imstdcall@8,@imfastcall@8 -i=demo_test15.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_test15.cfg -driver=imcdecl,_imcdecl,2,return,C -driver=imstdcall,_imstdcall@8,2,return,E -driver=imfastcall,@imfastcall@8,2,return,F -o demo_test15.bc

%LLVM_PATH%\opt.exe -O1 -o demo_test15_opt.bc demo_test15.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test15_lifted.obj demo_test15_opt.bc
cl /Zi /nologo demo_driver15.c demo_test15_lifted.obj
demo_driver15.exe
