@echo off
call env.bat

REM cleanup old files
del /q demo_dll_5.exp demo_dll_5.lib demo_dll_5.dll demo_dll_5.bc demo_dll_5_lifted.obj demo_dll_5_opt.bc demo_driver_dll_5.exe demo_dll_5.obj

REM Compile DLL file
cl /Og /Oy /Ob0 /GS- /nologo /Zi /EHs-c- /c demo_dll_5.c
link /NODEFAULTLIB:LIBCMT /DLL demo_dll_5.obj kernel32.lib msvcrt.lib

REM recover CFG
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=who_is_spartacus,who_is_spartacus2,get_response -ignore-native-entry-points=true -i=demo_dll_5.dll -func-map="%STD_DEFS%"
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -i demo_dll_5.cfg -entrypoint=who_is_spartacus -entrypoint=who_is_spartacus2 -entrypoint=get_response -o demo_dll_5.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_5_bc.obj demo_dll_5.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_5_asm.obj ..\..\drivers\PE_32_windows.asm


REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /Ox /nologo /Zi demo_driver_dll_5.c demo_dll_5_bc.obj demo_dll_5_asm.obj msvcrt.lib user32.lib kernel32.lib

REM Running application
demo_driver_dll_5.exe
