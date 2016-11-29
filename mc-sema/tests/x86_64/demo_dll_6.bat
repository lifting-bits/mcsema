@echo off
call env.bat

REM cleanup old files
del /q demo_dll_6.exp demo_dll_6.lib demo_dll_6.dll demo_dll_6.bc demo_dll_6_lifted.obj demo_dll_6_opt.bc demo_driver_dll_6.exe demo_dll_6.obj

REM Compile DLL file
cl /LD /MD /Od /GS- /nologo /Zi /EHs-c- demo_dll_6_data.c ucrt.lib user32.lib kernel32.lib
cl /LD /MD /Ox /GS- /nologo /Zi /EHs-c- demo_dll_6.c demo_dll_6_data.lib ucrt.lib user32.lib kernel32.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -entry-symbol=get_value -ignore-native-entry-points=true -i=demo_dll_6.dll -func-map="%STD_DEFS%",demo_6_defs.txt
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_6.cfg -mtriple=x86_64-pc-windows-msvc -entrypoint=get_value -o demo_dll_6.bc
clang-cl /Zi -m64 -c -o bitcode.obj demo_dll_6.bc 
clang-cl /Zi -m64 -c -o asm.obj ..\..\..\drivers\PE_64_windows.asm 
REM cl /MD /GS- /nologo /Zi /EHs-c- demo_driver_dll_6.c bitcode.obj asm.obj demo_dll_6_data.lib demo_dll_6.lib
clang-cl /Zi -m64 -o demo_driver_dll_6.exe demo_driver_dll_6.c bitcode.obj asm.obj demo_dll_6_data.lib demo_dll_6.lib

REM Running application
demo_driver_dll_6.exe
