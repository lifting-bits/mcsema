@echo off
call env.bat

del /q sailboat.obj sailboat_mine.obj sailboat.cfg sailboat.bc sailboat_opt.bc sailboat_run.exe
cl /nologo /c sailboat.c
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %PYTHON% %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86-64 -d -func-map=sailboat.txt,"%STD_DEFS%" -entry-symbol=keycomp -i=sailboat.obj
) else (
    echo Bin_descend is no longer supported
    exit 1
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=x86_64-pc-windows-msvc -i sailboat.cfg -entrypoint=keycomp -o sailboat.bc

clang-cl /Zi -O3 -m64 -o sailboat_run.exe sailboat_run.c ..\..\..\drivers\PE_64_windows.asm sailboat.bc
sailboat_run.exe "key{d9dd1cb9dc13ebc3dc3780d76123ee34}"
