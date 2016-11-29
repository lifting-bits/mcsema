@echo off
call env.bat

REM cleanup old files
del /q demo_dll_5.exp demo_dll_5.lib demo_dll_5.dll demo_dll_5.bc demo_dll_5_lifted.obj demo_dll_5_opt.bc demo_driver_dll_5.exe demo_dll_5.obj

REM Compile DLL file
cl /LD /MD /Ox /GS- /nologo /Zi /EHs-c- demo_dll_5.c ucrt.lib user32.lib kernel32.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=who_is_spartacus,who_is_spartacus2,get_response -ignore-native-entry-points=true -i=demo_dll_5.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_5.cfg -mtriple=x86_64-pc-windows-msvc -entrypoint=who_is_spartacus -entrypoint=who_is_spartacus2 -entrypoint=get_response -o demo_dll_5.bc
clang-cl /Zi -m64 -o demo_driver_dll_5.exe demo_driver_dll_5.c demo_dll_5.bc ..\..\..\drivers\PE_64_windows.asm user32.lib kernel32.lib

REM Running application
demo_driver_dll_5.exe
