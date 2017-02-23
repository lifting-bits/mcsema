#!/usr/bin/env bash
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=${DIR}/build
THIRD_PARTY_DIR=${DIR}/third_party
LLVM_DIR=${DIR}/third_party/llvm

GEN_DIR=${DIR}/generated

DEBUG_BUILD_ARGS=
if [ $# -eq 0 ]; then
  echo "No arguments supplied. Defaulting to DCMAKE_BUILD_TYPE=Release"
  BUILD_TYPE=Debug
  DEBUG_BUILD_ARGS="-g3 -O0"
else
  BUILD_TYPE=$1
fi

echo "[x] Installing dependencies via apt-get"
sudo apt-get update -qq
sudo apt-get install -yqq \
  git \
  cmake \
  libprotoc-dev libprotobuf-dev libprotobuf-dev protobuf-compiler \
  python2.7 python-pip \
  llvm-3.8 clang-3.8 \
  realpath

echo "[+] Upgrading PIP"

sudo pip install --upgrade pip

# Create the build dir.
echo "[+] Creating '${BUILD_DIR}'"
mkdir -p ${BUILD_DIR}

# Download and extract LLVM.
if [ ! -d ${LLVM_DIR} ]; then
  mkdir -p ${LLVM_DIR}
  pushd ${LLVM_DIR}
  echo "[+] Downloading LLVM.."
  LLVM_VER=3.8.1
  FILE=llvm-${LLVM_VER}.src.tar.xz
  if [ ! -e ${FILE} ]; then
    wget http://releases.llvm.org/${LLVM_VER}/${FILE}
  fi
  echo "[+] Extracting.."
  tar xf ${FILE} -C ./ --strip-components=1 
  popd
fi

echo "[+] Installing python-protobuf"
sudo pip install 'protobuf==2.6.1'

# Generate protobuf files.
mkdir -p ${GEN_DIR}
if [ ! -e ${GEN_DIR}/CFG.pb.h ]; then
  echo "[+] Auto-generating protobuf files"
  pushd ${GEN_DIR}
  PROTO_PATH=${DIR}/mcsema/CFG
  protoc \
    --cpp_out ${GEN_DIR} \
    --python_out ${GEN_DIR} \
    --proto_path ${PROTO_PATH} \
    ${PROTO_PATH}/CFG.proto


  # Copy this into the IDA disassembly dir to make importing the CFG_pb2
  # file easier.
  cp CFG_pb2.py ${DIR}/tools/mcsema_disass/ida
  
  popd
fi

# Produce the runtimes.
if [ ! -e ${GEN_DIR}/ELF_32_linux.S ]; then
  echo "[+] Generating runtimes"
  clang++-3.8 -std=gnu++11 ${DIR}/mcsema/Arch/X86/print_ELF_32_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_32_linux.S

  clang++-3.8 -std=gnu++11 ${DIR}/mcsema/Arch/X86/print_ELF_64_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_64_linux.S

  clang++-3.8 -std=gnu++11 ${DIR}/mcsema/Arch/X86/print_PE_32_windows.cpp
  ./a.out > ${GEN_DIR}/PE_32_windows.asm

  clang++-3.8 -std=gnu++11 ${DIR}/mcsema/Arch/X86/print_PE_64_windows.cpp
  ./a.out > ${GEN_DIR}/PE_64_windows.asm

  rm a.out
fi

# Install the disassembler
echo "[+] Installing the disassembler"
sudo python ${DIR}/tools/setup.py install

# Create makefiles
echo "[+] Creating Makefiles"
pushd ${BUILD_DIR}
MCSEMA_DIR=$(realpath ${DIR})
BUILD_DIR=$(realpath ${BUILD_DIR})
LLVM_DIR=$(realpath ${LLVM_DIR})
GEN_DIR=$(realpath ${GEN_DIR})

echo "[x] Building LLVM"
mkdir -p llvm
pushd llvm
CC=clang-3.8 \
CXX=clang++-3.8 \
CFLAGS="${DEBUG_BUILD_ARGS}" \
CXXFLAGS="${DEBUG_BUILD_ARGS}" \
cmake \
  -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  ${LLVM_DIR}

make -j4
popd

echo "[x] Creating Makefiles"

CC=clang-3.8 \
CXX=clang++-3.8 \
CFLAGS="-g3 -O0" \
CXXFLAGS="-g3 -O0" \
cmake \
  -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
  -DLLVM_DIR="${BUILD_DIR}/llvm/share/llvm/cmake" \
  -DMCSEMA_LLVM_DIR="${LLVM_DIR}" \
  -DMCSEMA_DIR="${MCSEMA_DIR}" \
  -DMCSEMA_BUILD_DIR="${BUILD_DIR}" \
  -DMCSEMA_GEN_DIR="${GEN_DIR}" \
  ${MCSEMA_DIR}

make -j4
sudo make install

popd
 