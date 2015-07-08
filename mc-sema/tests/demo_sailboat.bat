@echo off
call env.bat

del /q sailboat.obj sailboat_mine.obj sailboat.cfg sailboat.bc sailboat_opt.bc sailboat_run.exe
cl /nologo /c sailboat.c
if exist "%IDA_PATH%\idaq.exe" (
    echo Using IDA to recover CFG
    %BIN_DESCEND_PATH%\bin_descend_wrapper.py -march=x86 -d -func-map=sailboat.txt,"%STD_DEFS%" -entry-symbol=_keycomp -i=sailboat.obj
) else (
    echo Using bin_descend to recover CFG
    echo %BIN_DESCEND_PATH%\bin_descend.exe -d -func-map=sailboat.txt,"%STD_DEFS%" -entry-symbol=_keycomp -i=sailboat.obj
    %BIN_DESCEND_PATH%\bin_descend.exe -march=x86 -d -func-map=sailboat.txt,"%STD_DEFS%" -entry-symbol=_keycomp -i=sailboat.obj
)

%CFG_TO_BC_PATH%\cfg_to_bc.exe -mtriple=i386-pc-win32 -i sailboat.cfg -driver=sailboat,_keycomp,1,return,C -o sailboat.bc

%LLVM_PATH%\opt.exe -O3 -o sailboat_opt.bc sailboat.bc
%LLVM_PATH%\llc.exe -filetype=obj -o sailboat_mine.obj sailboat_opt.bc
"%VCINSTALLDIR%\bin\cl.exe" /Zi /nologo sailboat_run.c sailboat_mine.obj
sailboat_run.exe "key{d9dd1cb9dc13ebc3dc3780d76123ee34}"

