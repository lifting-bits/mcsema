@echo off

call env.bat

del /q linked_cfg linked_elf.idb linked_elf.nam linked_elf.id0 linked_elf.id1 linked_elf.til

if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -func-map=linux_map.txt -i=linked_elf -entry-symbol=_start
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -func-map=linux_map.txt -i=linked_elf -entry-symbol=_start
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i686-pc-linux-gnu -i linked_cfg -driver=mcsema_start,_start,raw,return,C -o demo_linked_elf.bc

REM %LLVM_PATH%\opt.exe -O3 -o demo_test1_opt.bc demo_test1.bc
REM %LLVM_PATH%\llc.exe -filetype=obj -o demo_test1_mine.obj demo_test1_opt.bc
REM cl /Zi /nologo demo_driver1.c demo_test1_mine.obj
REM demo_driver1.exe
