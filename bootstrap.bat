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

echo [+] Upgrading PIP
pip install --upgrade pip

echo Go into the mcsema directory
pushd "%~dp0" 

echo [+] Creating directories
if not exist third_party mkdir third_party
if not exist build mkdir build
if not exist generated mkdir generated

echo [+] Download and extract Google Protocol Buffers 2.6.1
pushd third_party
if exist protobuf goto compile_proto
wget https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.zip
unzip protobuf-2.6.1.zip
move protobuf-2.6.1 protobuf
:compile_proto

rem Compile protobuf to get protoc.exe
pushd protobuf
if not exist build mkdir build
pushd build
"C:\Program Files\CMake\bin\cmake.exe" ^
  -G "Visual Studio 14 2015 Win64" ^
  -DPROTOBUF_ROOT="%PROTO_DIR%" ^
  %MCSEMA_DIR%\cmake\protobuf
msbuild /p:Configuration=Release /p:Platform="x64" Protobuf.sln
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
wget http://releases.llvm.org/3.8.1/llvm-3.8.1.src.tar.xz
"C:\Program Files\7-Zip\7z.exe" x -y llvm-3.8.1.src.tar.xz
"C:\Program Files\7-Zip\7z.exe" x -y llvm-3.8.1.src.tar
move llvm-3.8.1.src llvm
:compile_llvm
if not exist "%BUILD_DIR%\llvm" mkdir "%BUILD_DIR%\llvm"
pushd "%BUILD_DIR%\llvm"
"C:\Program Files\CMake\bin\cmake.exe" ^
  -G "NMake Makefiles" ^
  -DLLVM_TARGETS_TO_BUILD="X86" ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %LLVM_DIR%
nmake
  
popd
popd

if exist %GEN_DIR%\ELF_32_linux.S goto create_mcsema_files
echo [+] Generating runtimes
cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\print_ELF_32_linux.cpp
a.out.exe > %GEN_DIR%\ELF_32_linux.S

cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\print_ELF_64_linux.cpp
a.out.exe > %GEN_DIR%\ELF_64_linux.S

cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\print_PE_32_windows.cpp
a.out.exe > %GEN_DIR%\PE_32_windows.asm

cl.exe /nologo /Fe:a.out.exe /Fo:a.out.obj %MCSEMA_DIR%\mcsema\Arch\X86\print_PE_64_windows.cpp
a.out.exe > %GEN_DIR%\PE_64_windows.asm

del a.out.exe a.out.obj
:create_mcsema_files

rem Create McSema build files
pushd build

"C:\Program Files\CMake\bin\cmake.exe" ^
  -DLLVM_DIR="%BUILD_DIR%\llvm\share\llvm\cmake" ^
  -DMCSEMA_LLVM_DIR="%LLVM_DIR%" ^
  -DMCSEMA_DIR="%DIR%" ^
  -DMCSEMA_BUILD_DIR="%BUILD_DIR%" ^
  -DMCSEMA_GEN_DIR="%GEN_DIR%" ^
  -DCMAKE_BUILD_TYPE="Release" ^
  %MCSEMA_DIR%
nmake

popd

popd
