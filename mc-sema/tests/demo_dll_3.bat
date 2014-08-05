@echo off
call env.bat

REM cleanup old files
del /q demo_dll_3.exp demo_dll_3.lib demo_dll_3.dll demo_dll_3.bc demo_dll_3_lifted.obj demo_dll_3_opt.bc demo_driver_dll_3.exe demo_dll_3.obj

REM Compile DLL file
cl /GS- /nologo /Zi /EHs-c- /c demo_dll_3.c
link /NODEFAULTLIB /DLL demo_dll_3.obj ws2_32.lib kernel32.lib msvcrt.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=StartServer -ignore-native-entry-points=true -i=demo_dll_3.dll -func-map="%STD_DEFS%"
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -entry-symbol=StartServer -ignore-native-entry-points=true -i=demo_dll_3.dll -func-map="%STD_DEFS%"
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_3.cfg -driver=demo_dll_3_driver,StartServer,0,return,C -o demo_dll_3.bc

REM Optimize LLVM
%LLVM_PATH%\opt.exe -O3 -o demo_dll_3_opt.bc demo_dll_3.bc

%LLVM_PATH%\llc.exe -filetype=obj -o demo_dll_3_lifted.obj demo_dll_3_opt.bc

REM Compiling driver
cl /nologo /Zi demo_driver_dll_3.c demo_dll_3_lifted.obj user32.lib kernel32.lib ws2_32.lib

REM Running application
demo_driver_dll_3.exe
