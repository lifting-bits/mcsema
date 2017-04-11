@echo off
rem Copyright 2017 Peter Goodman, all rights reserved.

set DIR=%~dp0
if "%DIR:~-1%"=="\" set DIR=%DIR:~0,-1%

set MCSEMA_DIR=%DIR%
set BUILD_DIR=%DIR%\build
set THIRD_PARTY_DIR=%DIR%\third_party
set LLVM_DIR=%THIRD_PARTY_DIR%\llvm
set PROTO_DIR=%THIRD_PARTY_DIR%\protobuf

echo [+] Creating directories
if not exist third_party mkdir third_party
if not exist build mkdir build
if not exist build\mcsema_generated mkdir build\mcsema_generated

if defined ProgramFiles(x86) (
    set "PATH=%PATH%;%ProgramFiles(x86)%\7-zip"
)
set "PATH=%PATH%;%ProgramFiles%\7-zip"

REM add third-party installs to our path
set "PATH=%PATH%;%MCSEMA_DIR%\bin"

REM sanity checks for installed software
where cl >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "[!] Visual Studio (cl.exe) is not found. Please run from a Visual Studio build prompt"
    exit /B 1
)
where 7z >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo [+] The 7z command is not found. Attempting to install
    powershell -Command "(new-object System.Net.WebClient).DownloadFile('http://www.7-zip.org/a/7z1604.msi','%THIRD_PARTY_DIR%\7z.msi')"
    msiexec /quiet /i %THIRD_PARTY_DIR%\7z.msi
)
where 7z >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo [!] Could not install 7zip, aborting
    exit /B 1
)
where cmake >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo [!] The cmake command is not found. Please install cmake
    exit /B 1
)

where python >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "[!] The python command is not found. Please install python (or add it to your PATH)"
    exit /B 1
)

python -V 2>&1 | findstr /R /C:"Python 2.7" > NUL
if not %ERRORLEVEL% == 0 (
    echo [!] Detected python != 2.7
    echo [!] Please install Python 2.7 and make sure it appears first in your system path
    exit /B 1
)

REM This check is *SEPARATE* from the 3.8 check below for good reason
REM Clang needs to be "installed" via the installer to it is available
REM as a visual studio toolset. Mcsema uses it for the assembler and
REM to build mcsema. We don't care as much what version this is, since 
REM it will not generate bitcode
where clang-cl.exe >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo [!] The llvm-based Visual Studio compiler 'clang-cl.exe' is not found. Please install visual studio and clang for Windows
    exit /B 1
)

REM We need a clang 3.8 on the system to generate bitcode-based semantics
REM If one is not found, download it and extract it (but not install!)
REM of course, it does't come with llvm-link.exe, so we *STILL* have to
REM build llvm 3.8 from source as well
if exist %THIRD_PARTY_DIR%\CLANG_38 goto check_vs
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" ( 
    set CLANGBITS=64) else (
    set CLANGBITS=32)
clang-cl 2>&1 -v | findstr /R /C:"version 3.8" > NUL
if not %ERRORLEVEL% == 0 (
    echo [+] Detected clang != 3.8; downloading clang 3.8
    echo [+] Downloading LLVM-3.8.1-win%CLANGBITS%.exe
    powershell -Command "(new-object System.Net.WebClient).DownloadFile('http://releases.llvm.org/3.8.1/LLVM-3.8.1-win%CLANGBITS%.exe','%THIRD_PARTY_DIR%\CLANG_38.exe')"
    echo [+] Extracting LLVM-3.8.1-win%CLANGBITS%.exe
    7z -bd -o%THIRD_PARTY_DIR%\CLANG_38 x -y %THIRD_PARTY_DIR%\CLANG_38.exe > NUL
)


REM echo [+] Upgrading PIP
REM pip install --upgrade pip

:check_vs

echo Go into the mcsema directory
pushd "%~dp0" 


if "%PROCESSOR_ARCHITECTURE%"=="AMD64" ( 
    set BITNESS= Win64) else (
    set BITNESS=)

set VSBUILD=UNKNOWN
set VSTOOLSET=UNKNOWN
echo Checking for Visual Studio
cl /? 2>&1 | findstr /C:"Version 18" > nul
if %ERRORLEVEL% == 0 (
    set VSBUILD=Visual Studio 12 2013%BITNESS%
    set VSTOOLSET=llvm-vs2013
) 
cl /? 2>&1 | findstr /C:"Version 19" > nul
if %ERRORLEVEL% == 0 (
    set VSBUILD=Visual Studio 14 2015%BITNESS%
    REM The 2014 below is intentional. Its called that even for VS2015.
    set VSTOOLSET=llvm-vs2014
) 

clang-cl 2>&1 -v | findstr /R /C:"version 3.[0-8]" > NUL
if "%VSTOOLSET%"=="llvm-vs2014" (
    REM Visual Studio integration and the clang-cl in PATH do not always match
    REM but we should check for unsupported clangs just to be sure, or people will
    REM think mcsema doesnt build, when its clang that can't parse new-ish MSVC headers
    if %ERRORLEVEL% == 0 (
        echo "[!] Detected clang <= 3.8. This version of clang is too old to build VS2015 header files"
        echo "[!] Please install Clang 3.9 or newer"
        echo "[!] ***You may have multiple clangs installed, including 3.9+ and still be get this message***"
        echo "[!] ***If you are SURE that Visual Studio integration uses clang 3.9+ please comment out this code in bootstrap***"
        exit /B 1
    )
)

if "%VSBUILD%"=="UNKNOWN" (
    echo [!] Could not identify Visual Studio Version
    echo [!] This build requires at least VS 2013
    exit /B 1
)

echo Found Visual Studio: %VSBUILD%

pushd third_party
if exist protobuf goto compile_proto
echo [+] Download and extract Google Protocol Buffers 2.6.1
powershell -Command "(new-object System.Net.WebClient).DownloadFile('https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.zip','protobuf-2.6.1.zip')"
7z -bd x -y protobuf-2.6.1.zip > NUL
move protobuf-2.6.1 protobuf

:compile_proto
pushd protobuf
if not exist build mkdir build
pushd build
REM Google protobufs crashes clang-cl 3.8.1, so build with
REM the normal VS2013 toolset
cmake.exe ^
  -G "%VSBUILD%" ^
  -DPROTOBUF_ROOT="%PROTO_DIR%" ^
  -DCMAKE_INSTALL_PREFIX="%MCSEMA_DIR%" ^
  %MCSEMA_DIR%\cmake\protobuf
cmake --build . --config Release --target install
popd

echo "[+] Installing protobuf for python"
pushd python
python setup.py build
python setup.py install
popd

popd

popd


echo [+] Download and extract LLVM
pushd third_party
if exist llvm goto compile_llvm

powershell -Command "(new-object System.Net.WebClient).DownloadFile('http://releases.llvm.org/3.8.1/llvm-3.8.1.src.tar.xz', 'llvm-3.8.1.src.tar.xz')"
7z -bd x -y llvm-3.8.1.src.tar.xz > NUL
del llvm-3.8.1.src.tar.xz
7z -bd x -y llvm-3.8.1.src.tar > NUL
del llvm-3.8.1.src.tar
move llvm-3.8.1.src llvm
:compile_llvm

if not exist "%BUILD_DIR%\llvm" mkdir "%BUILD_DIR%\llvm"
pushd "%BUILD_DIR%\llvm"
cmake.exe ^
  -G "%VSBUILD%" ^
  -DCMAKE_INSTALL_PREFIX="%MCSEMA_DIR%" ^
  -DLLVM_TARGETS_TO_BUILD="X86" ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %LLVM_DIR%
REM Enable parallel building with MSBuild
cmake --build . --config Release --target install -- /maxcpucount:%NUMBER_OF_PROCESSORS% /p:BuildInParallel=true
  
popd
popd

rem Create McSema build files
pushd build

echo [+] Building mcsema-lift
cmake.exe ^
  -G "%VSBUILD%" ^
  -T "%VSTOOLSET%" ^
  -DCMAKE_BUILD_TYPE="Release" ^
  -DCMAKE_INSTALL_PREFIX="%MCSEMA_DIR%" ^
  %MCSEMA_DIR%
REM Enable parallel building with MSBuild
cmake --build . --config Release --target install -- /maxcpucount:%NUMBER_OF_PROCESSORS% /p:BuildInParallel=true

popd

echo "[+] Installing mcsema-disass"
python %MCSEMA_DIR%\tools\setup.py install --user --install-scripts %MCSEMA_DIR%\bin

popd

