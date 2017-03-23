#!/usr/bin/env bash
# Copyright 2017 Trail of Bits, see LICENSE for details

set -e

usage() {
  echo "Usage:"
  echo "$0 [--prefix <PREFIX>] [--build <BUILD TYPE>] [--enable-rtti]"
  echo "PREFIX: Installation directory prefix"
  echo "BUILDTYPE: Built type (e.g. Debug, Release, etc.)"
  echo "--enable-rtti: Enable RTTI for building LLVM"
  exit 1
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=${DIR}/build
THIRD_PARTY_DIR=${DIR}/third_party
LLVM_DIR=${DIR}/third_party/llvm
GEN_DIR=${DIR}/generated

# default argument values
# Debug Build
BUILD_TYPE=Debug
#Install to directory of the git clone
PREFIX=${DIR}

CC=${CC:-clang-3.8}
CXX=${CXX:-clang++-3.8}

LLVM_CMAKE_OPTIONS=

# taken from:
# http://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
while [[ $# -gt 0 ]]
do
  key="$1"

  case $key in
      -p|--prefix)
        PREFIX=$2
        shift # past argument
      ;;
      -b|--build)
        BUILD_TYPE="$2"
        shift # past argument
      ;;
      --enable-rtti)
        LLVM_CMAKE_OPTIONS="${LLVM_CMAKE_OPTIONS} -DLLVM_ENABLE_RTTI=ON"
      ;;

      *)
        # unknown option
        echo "Unknown option: $key"
        usage
      ;;
  esac
  shift # past argument or value
done

if [ ! -d "${PREFIX}" ]; then
  echo "Cannot find installation prefix directory: ${PREFIX}"
  exit 1
else
    echo "Installation directory prefix: ${PREFIX}"
fi

DEBUG_BUILD_ARGS=
if [[ "${BUILD_TYPE}" == "Debug" ]]; then
  echo "Build type set to: ${BUILD_TYPE}"
  echo "  Setting build arguments for DCMAKE_BUILD_TYPE=Debug"
  BUILD_TYPE=Debug
  DEBUG_BUILD_ARGS="-g3 -O0"
else
  echo "Build type set to: ${BUILD_TYPE}"
fi

brew install wget git cmake coreutils || true

echo "[+] Upgrading PIP"

sudo -H pip install --upgrade pip

# Create the build dir.
echo "[+] Creating '${BUILD_DIR}'"
mkdir -p ${BUILD_DIR}

# Download and extract LLVM.
if [ ! -e ${LLVM_DIR}/CMakeLists.txt ]; then
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

if [ ! -e ${THIRD_PARTY_DIR}/protobuf ]; then
    mkdir -p ${THIRD_PARTY_DIR}/protobuf
    pushd ${THIRD_PARTY_DIR}/protobuf
    wget https://github.com/google/protobuf/releases/download/v2.6.1/protobuf-2.6.1.tar.gz
    tar xf protobuf-2.6.1.tar.gz -C ./ --strip-components=1
    ./configure --prefix=$(realpath build)
    make
    make install
    popd
fi

echo "[+] Installing python-protobuf"
sudo -H pip install 'protobuf==2.6.1'

if [ -d /usr/local/lib/python2.7/dist-packages/google ] ; then
  sudo touch /usr/local/lib/python2.7/dist-packages/google/__init__.py
fi

# Generate protobuf files.
mkdir -p ${GEN_DIR}
if [ ! -e ${GEN_DIR}/CFG.pb.h ]; then
  echo "[+] Auto-generating protobuf files"
  pushd ${GEN_DIR}
  PROTO_PATH=${DIR}/mcsema/CFG
  ${THIRD_PARTY_DIR}/protobuf/build/bin/protoc \
    --cpp_out ${GEN_DIR} \
    --python_out ${GEN_DIR} \
    --proto_path ${PROTO_PATH} \
    ${PROTO_PATH}/CFG.proto


  # Copy this into the IDA disassembly dir to make importing the CFG_pb2
  # file easier.
  cp CFG_pb2.py ${DIR}/tools/mcsema_disass/ida
  
  popd
fi

OSX_SDK=$(xcrun -sdk macosx --show-sdk-path)

# Produce the runtimes.
if [ ! -e ${GEN_DIR}/ELF_32_linux.S ]; then
  echo "[+] Generating runtimes"
  ${CXX} -m32 -std=gnu++11 -isysroot ${OSX_SDK} ${DIR}/mcsema/Arch/X86/Runtime/print_ELF_32_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_32_linux.S

  ${CXX} -m64 -std=gnu++11 -isysroot ${OSX_SDK} ${DIR}/mcsema/Arch/X86/Runtime/print_ELF_64_linux.cpp
  ./a.out > ${GEN_DIR}/ELF_64_linux.S

  ${CXX} -m32 -std=gnu++11 -isysroot ${OSX_SDK} ${DIR}/mcsema/Arch/X86/Runtime/print_PE_32_windows.cpp
  ./a.out > ${GEN_DIR}/PE_32_windows.asm

  ${CXX} -m64 -std=gnu++11 -isysroot ${OSX_SDK} ${DIR}/mcsema/Arch/X86/Runtime/print_PE_64_windows.cpp
  ./a.out > ${GEN_DIR}/PE_64_windows.asm

  rm a.out
fi

# Install the disassembler
echo "[+] Installing the disassembler"
if [ ! -d "${PREFIX}/bin" ]; then 
    mkdir -p "${PREFIX}/bin"
fi
# by default install to the user's python package directory
# and copy the script itself to ${PREFIX}/bin
python ${DIR}/tools/setup.py install --user --install-scripts "${PREFIX}/bin"

PROCS=$(sysctl -n hw.ncpu)

# Create makefiles
echo "[+] Creating Makefiles"
pushd ${BUILD_DIR}
MCSEMA_DIR=$(realpath ${DIR})
BUILD_DIR=$(realpath ${BUILD_DIR})
LLVM_DIR=$(realpath ${LLVM_DIR})
GEN_DIR=$(realpath ${GEN_DIR})

echo "[x] Building LLVM"
echo "[x] Additional Options: ${LLVM_CMAKE_OPTIONS}"
mkdir -p llvm
pushd llvm
CC=${CC} \
CXX=${CXX} \
CFLAGS="${DEBUG_BUILD_ARGS}" \
CXXFLAGS="${DEBUG_BUILD_ARGS}" \
cmake \
  -G "Unix Makefiles" \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_TESTS=OFF \
  ${LLVM_CMAKE_OPTIONS} \
  ${LLVM_DIR}

make -j${PROCS}
popd

echo "[x] Creating Makefiles"

CC=${CC} \
CXX=${CXX} \
CFLAGS="-g3 -O0" \
CXXFLAGS="-g3 -O0" \
cmake \
  -G "Unix Makefiles" \
  -DCMAKE_INSTALL_PREFIX=${PREFIX} \
  -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
  -DLLVM_DIR="${BUILD_DIR}/llvm/share/llvm/cmake" \
  -DMCSEMA_LLVM_DIR="${LLVM_DIR}" \
  -DMCSEMA_DIR="${MCSEMA_DIR}" \
  -DMCSEMA_BUILD_DIR="${BUILD_DIR}" \
  -DMCSEMA_GEN_DIR="${GEN_DIR}" \
  ${MCSEMA_DIR}

make -j${PROCS}
make install

popd

