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
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=call_ptrs -ignore-native-entry-points=true -i=demo_dll_4.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i686-pc-win32 -i demo_dll_4.cfg -entrypoint=call_ptrs -o demo_dll_4.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_4_bc.obj demo_dll_4.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_4_asm.obj ..\..\drivers\PE_32_windows.asm

REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /nologo /Zi demo_driver_dll_4.c demo_dll_4_asm.obj demo_dll_4_bc.obj user32.lib kernel32.lib msvcrt.lib

REM Running application
demo_driver_dll_4.exe
