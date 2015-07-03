@echo off
call env.bat

del /q demo_test5.obj demo_test5_mine.obj demo_test5.cfg demo_test5.bc demo_test5_opt.bc demo_driver5.exe
cl /nologo /c demo_test5.c


if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_foo -i=demo_test5.obj
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -func-map="%STD_DEFS%" -entry-symbol=_foo -i=demo_test5.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -march=x86 -i demo_test5.cfg -driver=demo5_entry,_foo,1,return,C -o demo_test5.bc

%LLVM_PATH%\opt.exe -O3 -o demo_test5_opt.bc demo_test5.bc
%LLVM_PATH%\llc.exe -filetype=obj -o demo_test5_mine.obj demo_test5_opt.bc
cl /Zi /nologo demo_driver5.c demo_test5_mine.obj
demo_driver5.exe
echo "driver5" > C:\windows\temp\foo.txt
demo_driver5.exe
del /q C:\windows\temp\foo.txt
