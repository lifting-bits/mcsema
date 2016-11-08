@echo off
call env.bat

REM cleanup old files
del /q demo_dll_1.exp demo_dll_1.lib demo_dll_1.dll demo_dll_1.bc demo_dll_1_lifted.obj demo_dll_1_opt.bc demo_driver_dll_1.exe

REM Compile DLL file
cl /nologo /Zi /EHs-c- /GS- /LD /c demo_dll_1.c 
link /NODEFAULTLIB:libcmt /DLL demo_dll_1.obj user32.lib msvcrt.lib

REM recover CFG
set TVHEADLESS=1
set IDALOG=ida.log
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -d -entry-symbol=HelloWorld -ignore-native-entry-points=true -i=demo_dll_1.dll -func-map="%STD_DEFS%" > %IDALOG%
) else (
    echo Bin_descend is no longer supported
    exit 1
)

REM Convert to LLVM
%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i686-pc-win32 -i demo_dll_1.cfg -entrypoint=HelloWorld -o demo_dll_1.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_1_bc.obj demo_dll_1.bc
clang -target i686-pc-win32 -O3 -m32 -c -o demo_dll_1_asm.obj ..\..\drivers\PE_32_windows.asm


REM Compiling driver
"%VCINSTALLDIR%\bin\cl.exe" /nologo /Zi demo_driver_dll_1.c demo_dll_1_asm.obj demo_dll_1_bc.obj user32.lib msvcrt.lib

REM Running application
demo_driver_dll_1.exe
