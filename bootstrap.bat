rem Copyright 2017 Peter Goodman, all rights reserved.

@echo off

set DIR=%~dp0
set BUILD_DIR=%DIR%\build
set THIRD_PARTY_DIR=%DIR%\third_party
set LLVM_DIR=%THIRD_PARTY_DIR%\llvm
set PROTO_DIR=%THIRD_PARTY_DIR%\protobuf
set GEN_DIR=%DIR%\generated

echo "[+] Upgrading PIP"
pip install --upgrade pip

echo Go into the mcsema directory
pushd "%~dp0" 

echo "[+] Creating directories"
if not exist third_party mkdir third_party
if not exist build mkdir build
if not exist generated mkdir generated

echo "[+} Download and extract Google Protocol Buffers 2.6.1"
pushd third_party
if exist protobuf goto compile_proto
wget https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.zip
unzip -j protobuf-2.6.1.zip
mv protobuf-2.6.1 protobuf
:compile_proto
popd

echo "[+] Download and extract LLVM"
pushd third_party
if exist llvm goto compile_llvm
wget http://releases.llvm.org/3.8.1/llvm-3.8.1.src.tar.xz
"C:\Program Files\7-Zip\7z.exe" x -y llvm-3.8.1.src.tar.xz
"C:\Program Files\7-Zip\7z.exe" x -y llvm-3.8.1.src.tar
mv llvm-3.8.1.src llvm
:compile_llvm
if not exist "%BUILD_DIR%\llvm" mkdir "%BUILD_DIR%\llvm"
pushd "%BUILD_DIR%\llvm"
"C:\Program Files\CMake\bin\cmake.exe" ^
  -G "NMake Makefiles" ^
  -DLLVM_TARGETS_TO_BUILD="X86" ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DLLVM_INCLUDE_TESTS=OFF ^
  %LLVM_DIR%

popd
popd

rem Create McSema build files
pushd build

cmake ^
  -DLLVM_DIR="%BUILD_DIR%\llvm\share\llvm\cmake" ^
  -DMCSEMA_LLVM_DIR="%LLVM_DIR%" ^
  -DMCSEMA_DIR="%DIR%" ^
  -DMCSEMA_BUILD_DIR="%BUILD_DIR%" ^
  -DMCSEMA_GEN_DIR="%GEN_DIR%" ^
  ${MCSEMA_DIR}

popd

popd
