@echo off

:main
  if "%~1" == "" (
    echo The installation prefix parameter is missing
    exit /B 1
  )

  setlocal enableextensions

  set install_folder=%1
  set PYTHONPATH=%install_folder%\Lib\site-packages
  set install_log=%TEMP%\%RANDOM%

  if not exist "%PYTHONPATH%\\" (
    echo Creating %PYTHONPATH%
    md "%PYTHONPATH%"
    if errorlevel 1 (
      echo Failed to create the site-packages folder in %PYTHONPATH%
      exit /B 1
    )
  )

  echo Installing mcsema-disass
  echo - Destination folder: %install_folder%
  echo - PYTHONPATH: %PYTHONPATH%
  
  python setup.py install -f --prefix="%install_folder%" > %install_log% 2>&1
  if errorlevel 1 (
    echo Failed to install the Python package to %install_folder%. Error output follows

    type %install_log%
    del %install_log%

    endlocal
    exit /B 1
  )

  endlocal
  exit /B 0

call :main %1
exit /B %ERRORLEVEL%
