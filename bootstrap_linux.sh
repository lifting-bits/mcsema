#!/usr/bin/env bash

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=${DIR}/build
THIRD_PARTY_DIR=${DIR}/third_party
LLVM_DIR=${DIR}/third_party/llvm
PROTO_DIR=${DIR}/third_party/protobuf
GEN_DIR=${DIR}/generated

if [ $# -eq 0 ]; then
  echo "No arguments supplied. Defaulting to DCMAKE_BUILD_TYPE=Release"
  BUILD_TYPE=Debug
else
  BUILD_TYPE=$1
fi

echo "[x] Installing dependencies via apt-get"
sudo apt-get install -y \
  gcc-multilib g++-multilib realpath \
  python2.7 python-pip \
  clang-3.8

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

# Download and extract Google Protocol Buffers.
if [ ! -d ${PROTO_DIR} ]; then
  echo "[+] Downloading Google Protocol Buffers"
  mkdir -p ${PROTO_DIR}
  pushd ${PROTO_DIR}
  PROTO_VER=2.6.1
  FILE=protobuf-${PROTO_VER}.tar.gz
  if [ ! -e ${FILE} ]; then
    wget https://github.com/google/protobuf/releases/download/v${PROTO_VER}/${FILE}
  fi
  echo "[+] Extracting.."
  tar xf ${FILE} -C ./ --strip-components=1 
  popd
fi

# Compile protobufs.
if [ ! -e ${BUILD_DIR}/bin/protoc ]; then
  echo "[+] Building protobuf"
  pushd ${PROTO_DIR}

  CFLAGS="-DGOOGLE_PROTOBUF_NO_RTTI=1" \
  CXXFLAGS="-DGOOGLE_PROTOBUF_NO_RTTI=1"\
  ./configure --prefix ${BUILD_DIR}
  
  make
  make install
  popd
fi

echo "[+] Installing python-protobuf"
sudo pip install 'protobuf==2.6.1'

# Generate protobuf files.
mkdir -p ${GEN_DIR}
if [ ! -e ${GEN_DIR}/CFG.pb.h ]; then
  echo "[+] Auto-generating protobuf files"
  pushd ${GEN_DIR}
  PROTO_PATH=${DIR}/mc-sema/CFG
  ${BUILD_DIR}/bin/protoc \
    --cpp_out ${GEN_DIR} \
    --python_out ${GEN_DIR} \
    --proto_path ${PROTO_PATH} \
    ${PROTO_PATH}/CFG.proto


  # Copy this into the IDA disassembly dir to make importing the CFG_pb2
  # file easier.
  cp CFG_pb2.py ${DIR}/tools/disass/ida
  
  popd
fi

# Produce the runtimes.
if [ ! -e ${GEN_DIR}/ELF_32_linux.S ]; then
  echo "[+] Generating runtimes"
  clang++-3.8 -std=gnu++11 ${DIR}/mc-sema/Arch/X86/print_ELF_32_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_32_linux.S

  clang++-3.8 -std=gnu++11 ${DIR}/mc-sema/Arch/X86/print_ELF_64_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_64_linux.S

  clang++-3.8 -std=gnu++11 ${DIR}/mc-sema/Arch/X86/print_PE_32_windows.cpp
  ./a.out > ${GEN_DIR}/PE_32_windows.asm

  clang++-3.8 -std=gnu++11 ${DIR}/mc-sema/Arch/X86/print_PE_64_windows.cpp
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
PROTO_DIR=$(realpath ${PROTO_DIR})
GEN_DIR=$(realpath ${GEN_DIR})

echo "[x] Creating Makefiles"

CC=clang-3.8 \
CXX=clang++-3.8 \
CFLAGS="-g3 -O0" \
CXXFLAGS="-g3 -O0" \
cmake \
  -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_DIR="${LLVM_DIR}" \
  -DMCSEMA_LLVM_DIR="${LLVM_DIR}" \
  -DMCSEMA_DIR="${MCSEMA_DIR}" \
  -DMCSEMA_BUILD_DIR="${BUILD_DIR}" \
  -DMCSEMA_GEN_DIR="${GEN_DIR}" \
  ${MCSEMA_DIR}

popd
