@echo off
call env.bat

REM cleanup old files
del /q demo_dll_1.exp demo_dll_1.lib demo_dll_1.dll demo_dll_1.bc demo_dll_1_lifted.obj demo_dll_1_opt.bc demo_driver_dll_1.exe

REM Compile DLL file
cl /nologo /Zi /EHs-c- /GS- /LD /c demo_dll_1.c 
link /NODEFAULTLIB:libcmt /DLL demo_dll_1.obj user32.lib msvcrt.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=HelloWorld -ignore-native-entry-points=true -i=demo_dll_1.dll -func-map="%STD_DEFS%"
) else (
    echo Using bin_descend to recover CFG
    %BIN_DESCEND_PATH%\bin_descend.exe -d -entry-symbol=HelloWorld -ignore-native-entry-points=true -i=demo_dll_1.dll -func-map="%STD_DEFS%"
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_1.cfg -driver=demo_dll_1_driver,HelloWorld,0,return,C -o demo_dll_1.bc

REM Optimize LLVM
%LLVM_PATH%\opt.exe -O3 -o demo_dll_1_opt.bc demo_dll_1.bc

%LLVM_PATH%\llc.exe -filetype=obj -o demo_dll_1_lifted.obj demo_dll_1_opt.bc

REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /nologo /Zi demo_driver_dll_1.c demo_dll_1_lifted.obj user32.lib

REM Running application
demo_driver_dll_1.exe
