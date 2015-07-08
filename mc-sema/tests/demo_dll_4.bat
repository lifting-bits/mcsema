@echo off
call env.bat

REM cleanup old files
del /q demo_dll_4.exp demo_dll_4.lib demo_dll_4.dll demo_dll_4.bc demo_dll_4_lifted.obj demo_dll_4_opt.bc demo_driver_dll_4.exe demo_dll_4.obj

REM Compile DLL file
cl /Og /Oy /Ob0 /GS- /nologo /Zi /EHs-c- /c demo_dll_4.c
link /NODEFAULTLIB /DLL demo_dll_4.obj kernel32.lib user32.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=call_ptrs -ignore-native-entry-points=true -i=demo_dll_4.dll -func-map="%STD_DEFS%"
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -entry-symbol=call_ptrs -ignore-native-entry-points=true -i=demo_dll_4.dll -func-map="%STD_DEFS%"
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_4.cfg -driver=demo_dll_4_driver,call_ptrs,0,return,C -o demo_dll_4.bc

REM Optimize LLVM
%LLVM_PATH%\opt.exe -O3 -o demo_dll_4_opt.bc demo_dll_4.bc
REM %LLVM_PATH%\opt.exe -disable-opt -o demo_dll_4_opt.bc demo_dll_4.bc

%LLVM_PATH%\llc.exe -filetype=obj -o demo_dll_4_lifted.obj demo_dll_4_opt.bc

REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /Ox /nologo /Zi demo_driver_dll_4.c demo_dll_4_lifted.obj user32.lib kernel32.lib

REM Running application
demo_driver_dll_4.exe
