@echo off
call env.bat

REM cleanup old files
del /q demo_dll_2.exp demo_dll_2.lib demo_dll_2.dll demo_dll_2.bc demo_dll_2_lifted.obj demo_dll_2_opt.bc demo_driver_dll_2.exe demo_dll_2.obj

REM Compile DLL file
cl /LD /MD /Ox /GS- /nologo /Zi /EHs-c- demo_dll_2.c ucrt.lib user32.lib kernel32.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=StartThread -ignore-native-entry-points=true -i=demo_dll_2.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i demo_dll_2.cfg -entrypoint=StartThread -o demo_dll_2.bc
clang-cl /Zi -m64 -o demo_driver_dll_2.exe demo_driver_dll_2.c demo_dll_2.bc ..\..\..\drivers\PE_64_windows.asm user32.lib kernel32.lib

REM Running application
demo_driver_dll_2.exe
