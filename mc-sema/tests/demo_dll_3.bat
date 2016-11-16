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
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=StartServer -ignore-native-entry-points=true -i=demo_dll_3.dll -func-map=test.txt -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i686-pc-win32 -i demo_dll_3.cfg -entrypoint=StartServer -o demo_dll_3.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_3_bc.obj demo_dll_3.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_3_asm.obj ..\..\drivers\PE_32_windows.asm

REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /nologo /Zi demo_driver_dll_3.c demo_dll_3_asm.obj demo_dll_3_bc.obj ws2_32.lib user32.lib kernel32.lib msvcrt.lib


REM Running application
demo_driver_dll_3.exe
