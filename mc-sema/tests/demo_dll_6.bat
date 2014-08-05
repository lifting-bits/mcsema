@echo off
call env.bat

REM cleanup old files
del /q demo_dll_6.exp demo_dll_6.lib demo_dll_6.dll demo_dll_6.bc demo_dll_6_lifted.obj demo_dll_6_opt.bc demo_driver_dll_6.exe demo_dll_6.obj

REM Compile DLL file
cl /Og /Oy /Ob0 /GS- /nologo /Zi /EHs-c- /c demo_dll_6_data.c
link /NODEFAULTLIB /DLL demo_dll_6_data.obj

cl /Og /Oy /Ob0 /GS- /nologo /Zi /EHs-c- /c demo_dll_6.c
link /NODEFAULTLIB:LIBCMT /DLL demo_dll_6.obj demo_dll_6_data.lib kernel32.lib msvcrt.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=get_value -ignore-native-entry-points=true -i=demo_dll_6.dll -func-map="%STD_DEFS%",demo_6_defs.txt
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -entry-symbol=get_value -ignore-native-entry-points=true -i=demo_dll_6.dll -func-map="%STD_DEFS%",demo_6_defs.txt
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_6.cfg -driver=d_get_value,get_value,0,return,C -o demo_dll_6.bc

REM Optimize LLVM
%LLVM_PATH%\opt.exe -O3 -o demo_dll_6_opt.bc demo_dll_6.bc

%LLVM_PATH%\llc.exe -filetype=obj -o demo_dll_6_lifted.obj demo_dll_6_opt.bc

REM Compiling driver
cl /Ox /nologo /Zi demo_driver_dll_6.c demo_dll_6_lifted.obj demo_dll_6_data.lib msvcrt.lib kernel32.lib

REM Running application
demo_driver_dll_6.exe
