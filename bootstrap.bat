rem Copyright 2017 Peter Goodman, all rights reserved.

@echo off

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

set PATH=%ProgramFiles%\7-zip\;%PATH%
if defined ProgramFiles(x86) (
    set PATH=%ProgramFiles(x86)%\7-zip\;%PATH%
)

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
where cl.exe >NUL 2>NUL
if not %ERRORLEVEL% == 0 (
    echo "The Visual Studio Compiler s not found. Please run from a Visual Studio command prompt"
    exit /B 1
)

REM echo [+] Upgrading PIP
REM pip install --upgrade pip

echo Go into the mcsema directory
pushd "%~dp0" 

if "%PROCESSOR_ARCHITECTURE%"=="AMD64" ( 
    set BITNESS=Win64 ) else (
    set BITNESS=)

set VSBUILD=UNKNOWN
cl /? 2>&1 | findstr /C:"Version 18" > nul
if %ERRORLEVEL% == 0 (
    set VSBUILD=Visual Studio 12 2013%BITNESS%
) 
cl /? 2>&1 | findstr /C:"Version 19" > nul
if %ERRORLEVEL% == 0 (
    set VSBUILD=Visual Studio 14 2015%BITNESS%
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
  -DLLVM_TARGETS_TO_BUILD="X86" ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %LLVM_DIR%
cmake --build . --config Release
  
popd
popd

REM cl does not have a flag to specify 32-bit or 64-bit output
REM TODO(artem): Use the path of cl.exe to find the other CL that will 
REM output the correct bitness code
if "%BITNESS%"=="Win64" (

    if exist %GEN_DIR%\ELF_64_linux.S goto create_mcsema_files
    echo [+] Generating runtimes
    
    cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\Runtime\print_ELF_64_linux.cpp
    a.out.exe > %GEN_DIR%\ELF_64_linux.S
    
    cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\Runtime\print_PE_64_windows.cpp
    a.out.exe > %GEN_DIR%\PE_64_windows.asm
    del a.out.exe a.out.obj

) else (

    if exist %GEN_DIR%\ELF_32_linux.S goto create_mcsema_files
    echo [+] Generating runtimes

    cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\Runtime\print_ELF_32_linux.cpp
    a.out.exe > %GEN_DIR%\ELF_32_linux.S
    
    cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\Runtime\print_PE_32_windows.cpp
    a.out.exe > %GEN_DIR%\PE_32_windows.asm
    del a.out.exe a.out.obj
)

:create_mcsema_files

rem Create McSema build files
pushd build

cmake.exe ^
  -G "%VSBUILD%" ^
  -DLLVM_DIR="%BUILD_DIR%\llvm\share\llvm\cmake" ^
  -DMCSEMA_LLVM_DIR="%LLVM_DIR%" ^
  -DMCSEMA_DIR="%DIR%" ^
  -DMCSEMA_BUILD_DIR="%BUILD_DIR%" ^
  -DMCSEMA_GEN_DIR="%GEN_DIR%" ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %MCSEMA_DIR%
cmake --build . --config Release

popd

popd
