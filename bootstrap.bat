REM @echo off
rem Copyright 2017 Peter Goodman, all rights reserved.

set DIR=%~dp0
if "%DIR:~-1%"=="\" set DIR=%DIR:~0,-1%

set MCSEMA_DIR=%DIR%
set BUILD_DIR=%DIR%\build
set THIRD_PARTY_DIR=%DIR%\third_party
set LLVM_DIR=%THIRD_PARTY_DIR%\llvm
set PROTO_DIR=%THIRD_PARTY_DIR%\protobuf
set GEN_DIR=%DIR%\generated

echo [+] Creating directories
if not exist third_party mkdir third_party
if not exist build mkdir build
if not exist generated mkdir generated

if defined ProgramFiles(x86) (
    set "PATH=%PATH%;%ProgramFiles(x86)%\7-zip"
)
set "PATH=%PATH%;%ProgramFiles%\7-zip"

REM sanity checks for installed software
where 7z >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "The 7z command is not found. Attempting to install"
    powershell -Command "(new-object System.Net.WebClient).DownloadFile('http://www.7-zip.org/a/7z1604.msi','%THIRD_PARTY_DIR%\7z.msi')"
    msiexec /quiet /i %THIRD_PARTY_DIR%\7z.msi
)
where 7z >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "Could not install 7zip, aborting"
    exit /B 1
)
where cmake >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "The cmake command is not found. Please install cmake"
    exit /B 1
)
where clang-cl.exe >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "The llvm-based Visual Studio compiler (clang-cl) is not found. Please install visual studio and clang for Windows"
    exit /B 1
)

REM echo [+] Upgrading PIP
REM pip install --upgrade pip

echo Go into the mcsema directory
pushd "%~dp0" 

if "%PROCESSOR_ARCHITECTURE%"=="AMD64" ( 
    set BITNESS= Win64) else (
    set BITNESS=)

set VSBUILD=UNKNOWN
set VSTOOLSET=UNKNOWN
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
        echo "Detected clang <= 3.8. This version of clang is too old to build VS2015 header files"
        echo "Please install Clang 3.9 or newer"
        echo "***You may have multiple clangs installed, including 3.9+ and still be get this message***"
        echo "***If you are SURE that Visual Studio integration uses clang 3.9+ please comment out this code in bootstrap***"
        exit /B 1
    )
)

if "%VSBUILD%"=="UNKNOWN" (
    echo "Could not identify Visual Studio Version"
    echo "This build requires at least VS 2013"
    exit /B 1
)

echo "Found Visual Studio: %VSBUILD%"

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
  %MCSEMA_DIR%\cmake\protobuf
cmake --build . --config Release
popd
popd

popd

if exist %GEN_DIR%\CFG.pb.h goto download_llvm
echo [+] Auto-generating protobuf files
set PROTO_PATH=%MCSEMA_DIR%\mcsema\CFG
pushd %GEN_DIR% 
%THIRD_PARTY_DIR%\protobuf\build\protoc\Release\protoc.exe ^
  --cpp_out "%GEN_DIR%" ^
  --python_out "%GEN_DIR%" ^
  --proto_path "%PROTO_PATH%" ^
  "%PROTO_PATH%\CFG.proto"
popd
:download_llvm

echo [+] Download and extract LLVM
pushd third_party
if exist llvm goto compile_llvm

powershell -Command "(new-object System.Net.WebClient).DownloadFile('http://releases.llvm.org/3.8.1/llvm-3.8.1.src.tar.xz', 'llvm-3.8.1.src.tar.xz')"
7z -bd x -y llvm-3.8.1.src.tar.xz > NUL
7z -bd x -y llvm-3.8.1.src.tar > NUL
move llvm-3.8.1.src llvm
:compile_llvm

if not exist "%BUILD_DIR%\llvm" mkdir "%BUILD_DIR%\llvm"
pushd "%BUILD_DIR%\llvm"
cmake.exe ^
  -G "%VSBUILD%" ^
  -T "%VSTOOLSET%" ^
  -DCMAKE_INSTALL_PREFIX="%MCSEMA_DIR%" ^
  -DLLVM_TARGETS_TO_BUILD="X86" ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %LLVM_DIR%
cmake --build . --config Release
REM Enable parallel building with MSBuild
cmake --build . --config Release --target install -- /m /p:BuildInParallel=true
  
popd
popd

rem Create McSema build files
pushd build

cmake.exe ^
  -G "%VSBUILD%" ^
  -T "%VSTOOLSET%" ^
  -DLLVM_DIR="%BUILD_DIR%\llvm\share\llvm\cmake" ^
  -DMCSEMA_LLVM_DIR="%LLVM_DIR%" ^
  -DMCSEMA_BUILD_DIR="%BUILD_DIR%" ^
  -DMCSEMA_GEN_DIR="%GEN_DIR%" ^
  -DCMAKE_BUILD_TYPE="Release" ^
  -DCMAKE_INSTALL_PREFIX="%MCSEMA_DIR%" ^
  %MCSEMA_DIR%
cmake --build . --config Release
REM Enable parallel building with MSBuild
cmake --build . --config Release --target install -- /m /p:BuildInParallel=true

popd

popd
