@echo off

set /p IDA_PATH= < IDA_PATH

set /p SCRIPT_PATH= < SCRIPT_PATH
if not exist "%SCRIPT_PATH%\get_cfg.py" (
set SCRIPT_PATH=%SCRIPT_PATH%\..
)
