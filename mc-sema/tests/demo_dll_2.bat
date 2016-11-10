@echo off
call env.bat

REM cleanup old files
del /q demo_dll_2.exp demo_dll_2.lib demo_dll_2.dll demo_dll_2.bc demo_dll_2_lifted.obj demo_dll_2_opt.bc demo_driver_dll_2.exe demo_dll_2.obj

REM Compile DLL file
cl /Ox /GS- /nologo /Zi /EHs-c- /c demo_dll_2.c
link /NODEFAULTLIB /DLL demo_dll_2.obj kernel32.lib user32.lib msvcrt.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=StartThread -ignore-native-entry-points=true -i=demo_dll_2.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -post-analysis=false -mtriple=i686-pc-win32 -i demo_dll_2.cfg -entrypoint=StartThread -o demo_dll_2.bc
clang -target i686-pc-win32 -O0 -m32 -c -o demo_dll_2_bc.obj demo_dll_2.bc
clang -target i686-pc-win32 -O0 -m32 -c -o demo_dll_2_asm.obj ..\..\drivers\PE_32_windows.asm

REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /nologo /Zi demo_driver_dll_2.c demo_dll_2_asm.obj demo_dll_2_bc.obj user32.lib kernel32.lib msvcrt.lib

REM Running application
demo_driver_dll_2.exe
