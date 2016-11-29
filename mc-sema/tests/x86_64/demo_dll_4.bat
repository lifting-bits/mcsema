@echo off
call env.bat

REM cleanup old files
del /q demo_dll_4.exp demo_dll_4.lib demo_dll_4.dll demo_dll_4.bc demo_dll_4_lifted.obj demo_dll_4_opt.bc demo_driver_dll_4.exe demo_dll_4.obj

REM Compile DLL file
cl /LD /MD /Ox /GS- /nologo /Zi /EHs-c- demo_dll_4.c ucrt.lib user32.lib kernel32.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=call_ptrs -ignore-native-entry-points=true -i=demo_dll_4.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_dll_4.cfg -entrypoint=call_ptrs -o demo_dll_4.bc
clang-cl /Zi -m64 -o demo_driver_dll_4.exe demo_driver_dll_4.c demo_dll_4.bc ..\..\..\drivers\PE_64_windows.asm user32.lib kernel32.lib

REM Running application
demo_driver_dll_4.exe
