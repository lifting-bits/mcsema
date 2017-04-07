#!/usr/bin/env bash
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

# build and output directories (by default, install in the same folder as the git repository)
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR=${DIR}/build
THIRD_PARTY_DIR=${DIR}/third_party
LLVM_DIR=${DIR}/third_party/llvm
GEN_DIR=${BUILD_DIR}/mcsema_generated

# we may not have realpath yet (installation comes later), so do use python to simulate
PREFIX=$(python -c "import os; import sys; sys.stdout.write(os.path.abspath('${DIR}'))")

# locate the osx sdk
OSX_SDK=

which xcrun > /dev/null 2>&1
if [ $? -eq 0 ] ; then
  OSX_SDK=$(xcrun -sdk macosx --show-sdk-path)
fi

# set the default compiler if no one is currently selected
CC=${CC:-clang-3.8}
CXX=${CXX:-clang++-3.8}

# default argument values
BUILD_TYPE=Debug
LLVM_CMAKE_OPTIONS=

function main
{
  #
  # parse the arguments
  #

  # taken from: http://stackoverflow.com/questions/192249/how-do-i-parse-command-line-arguments-in-bash
  while [[ $# -gt 0 ]] ; do
    key="$1"

    case $key in
      -p|--prefix)
      PREFIX=$(python -c "import os; import sys; sys.stdout.write(os.path.abspath('${2}'))")
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
      ShowUsage

      return 1
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

  local job_count="$NPROC"
  if [ -z "$job_count" ] ; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
      job_count=$(sysctl -n hw.ncpu)
    else
      job_count=`nproc`
    fi
  fi

  echo "Make job count: $job_count"

  echo "Build type set to: ${BUILD_TYPE}"
  if [[ "${BUILD_TYPE}" == "Debug" ]]; then
    echo "  Setting build arguments for DCMAKE_BUILD_TYPE=Debug"

    BUILD_TYPE=Debug
    DEBUG_BUILD_ARGS="-g3 -O0"
  fi

  #
  # install the required dependencies
  #

  echo "[+] Creating '${BUILD_DIR}'"
  mkdir -p ${BUILD_DIR}

  InstallDependencies
  if [ $? -ne 0 ] ; then
    return 1
  fi

  InstallPythonPackages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  InstallDisassembler
  if [ $? -ne 0 ] ; then
    return 1
  fi

  #
  # build both llvm and mcsema
  #

  mkdir -p ${LLVM_DIR}
  if [ $? -ne 0 ] ; then 
    echo "Failed to create the third-party/llvm folder"
    return 1
  fi

  MCSEMA_DIR=$(realpath ${DIR})
  BUILD_DIR=$(realpath ${BUILD_DIR})
  LLVM_DIR=$(realpath ${LLVM_DIR})
  GEN_DIR=$(realpath ${GEN_DIR})

  BuildLLVM
  if [ $? -ne 0 ] ; then
    return 1
  fi

  BuildMcSema
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# installs the required packages for the system in use
# returns 0 in case of success or 1 otherwise
function InstallDependencies
{
  # mac os x packages
  if [[ "$OSTYPE" == "darwin"* ]]; then
    local osx_dependencies="wget git cmake coreutils protobuf"

    for osx_dep in ${osx_dependencies[@]} ; do
      # homebrew errors on installing already installed things
      brew outdated ${osx_dep} || brew upgrade ${osx_dep} || brew install ${osx_dep}
    done

    return 0

  # unsupported systems
  elif [[ "$OSTYPE" != "linux-gnu" ]]; then
    return 1
  fi

  # attempt to detect the distribution
  local distribution_name=`cat /etc/issue`

  case "$distribution_name" in
    *Ubuntu*)
      InstallUbuntuPackages
      return $?
    ;;

    *Arch\ Linux*)
      InstallArchLinuxPackages
      return $?
    ;;

    *)
      printf '[x] Failed to install the required dependencies; please make sure the following packages are installed: git, cmake, protobuf, python 2, pip 2, llvm, clang\n'
      return 0
  esac
}

# installs the required packages for ubuntu
# returns 0 in case of success or 1 otherwise
function InstallUbuntuPackages
{
  local required_package_list=(
    'git'
    'cmake'
    'libprotoc-dev'
    'libprotobuf-dev'
    'protobuf-compiler'
    'python2.7'
    'python-pip'
    'llvm-3.8'
    'clang-3.8'
    'realpath'

    # gcc-multilib required only for 32-bit integration tests
    # g++-multilib required to build 32-bit generated code

    'gcc-multilib'
    'g++-multilib'

    # liblzma-dev needed for the xz integration test
    # libpcre3-dev needed for some integration tests
    # libbsd-dev needed for netcat test

    'liblzma-dev'
    'libpcre3-dev'
    'libbsd-dev'
  )

  local installed_package_list=`dpkg -l | tail -n+6 | awk '{ print $2 }'`
  local missing_packages=""

  for required_package in ${required_package_list[@]} ; do
    if [[ ${installed_package_list} == *"$required_package"* ]] ; then
      continue
    fi

    missing_packages="$missing_packages $required_package"
  done

  if [ -z "$missing_packages" ] ; then
    echo "[+] All the required dependencies are installed. Continuing..."
    return 0
  fi

  echo "[+] Installing dependencies..."

  sudo apt-get update -qq
  if [ $? -ne 0 ] ; then
    return 1
  fi

  sudo apt-get install -yqq $missing_packages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# installs the required packages for arch linux
# returns 0 in case of success or 1 otherwise
function InstallArchLinuxPackages
{
  local required_package_list=(
    'git'
    'cmake'
    'protobuf'
    'protobuf-c'
    'python2'
    'python2-pip'
    'clang'
    'llvm'

    # liblzma-dev needed for the xz integration test
    # libpcre3-dev needed for some integration tests
    # libbsd-dev needed for netcat test

    'pcre'
    'libbsd'
    'xz'
  )

  local installed_package_list=`pacman -Q | awk '{ print $1 }'`
  local missing_packages=""

  for required_package in ${required_package_list[@]} ; do
    if [[ ${installed_package_list} == *"$required_package"* ]] ; then
      continue
    fi

    missing_packages="$missing_packages $required_package"
  done

  if [ -z "$missing_packages" ] ; then
    echo "[+] All the required dependencies are installed. Continuing..."
    return 0
  fi

  echo "[+] Installing dependencies..."
  sudo pacman -S $missing_packages
  if [ $? -ne 0 ] ; then
    return 1
  fi

  return 0
}

# locates the correct pip path (some distributions use Python 3 as default interpreter)
# returns the pip path in case of success, or an empty string otherwise
function GetPythonPIPLocation
{
  which pip2 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local pip_path=`which pip2`
  fi

  if [ -z "$pip_path" ] ; then
    which pip > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      local pip_path=`which pip`
    fi
  fi

  "$pip_path" --version 2>&1 | grep 2.7 > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    echo ""
    return
  fi

  printf "$pip_path"
}

# updates pip and installs the protobuf dependency
# returns 0 in case of success, or 1 otherwise
function InstallPythonPackages
{
  local pip_path=`GetPythonPIPLocation`
  if [ -z "$pip_path" ] ; then
    echo "Failed to locate the PIP executable"
    return 1
  fi

  echo "[+] Upgrading PIP"
  sudo -H "$pip_path" install --upgrade pip
  if [ $? -ne 0 ] ; then
    echo "Failed to upgrade PIP"
    return 1
  fi

  echo "[+] Installing python-protobuf"
  sudo -H "$pip_path" install 'protobuf==2.6.1'
  if [ $? -ne 0 ] ; then
    echo "Failed to install protobuf with PIP"
    return 1
  fi

  if [ -d /usr/local/lib/python2.7/dist-packages/google ] ; then
    sudo touch /usr/local/lib/python2.7/dist-packages/google/__init__.py
    if [ $? -ne 0 ] ; then
      echo "Failed to create the following file: /usr/local/lib/python2.7/dist-packages/google/__init__.py"
      return 1
    fi
  fi

  return 0
}

# downloads and extracts the LLVM source tarball
# returns 0 in case of success, or 1 otherwise
function DownloadLLVMTarball
{
  local LLVM_VER=3.8.1

  local llvm_find_package_directive=`cat $DIR/CMakeLists.txt | grep -i find_package | grep LLVM`
  local short_llvm_version=`echo $LLVM_VER | cut -d '.' -f 1-2`

  if [[ "$llvm_find_package_directive" != *"$short_llvm_version"* ]] ; then
    echo "[x] Warning: the main CMakeLists.txt imports a different LLVM version than the one used inside third-party/llvm"
  fi

  if [ -e ${LLVM_DIR}/CMakeLists.txt ] ; then
    if [ -f ${LLVM_DIR}/llvm_version ] ; then
      local local_llvm_version=`cat ${LLVM_DIR}/llvm_version`

      if [ "$LLVM_VER" != "$local_llvm_version" ]; then
        echo "The local LLVM copy differs from the required version"
        echo "Please delete the following folder and re-run the bootstrap script: ${LLVM_DIR}"
        return 1    
      fi
    else

      echo "Warning: the following file could not be found: ${LLVM_DIR}/llvm_version"
      echo "Make sure the tarball you extracted matches the following version: ${LLVM_VER}"
    fi

    return 0
  fi

  # Download and extract LLVM.
  echo "[+] Downloading LLVM.."

  mkdir -p ${LLVM_DIR}
  if [ $? -ne 0 ] ; then
    echo "Failed to create the following folder: ${LLVM_DIR}"
    return 1
  fi

  pushd ${LLVM_DIR}
  FILE=llvm-${LLVM_VER}.src.tar.xz

  # the bootstrap script will stop working if you leave a broken tarball here (connection problems,
  # ctrl+c being pressed, etc..). it is then best to always remove it in case of error

  if [ ! -e ${FILE} ]; then
    wget http://releases.llvm.org/${LLVM_VER}/${FILE}
    if [ $? -ne 0 ] ; then
      rm ${LLVM_DIR}/${FILE}
      return 1
    fi
  fi

  echo "[+] Extracting LLVM.."
  tar xf ${FILE} -C ./ --strip-components=1 
  if [ $? -ne 0 ] ; then
    rm ${LLVM_DIR}/${FILE}
    return 1
  fi

  echo "$LLVM_VER" > llvm_version
  popd

  return 0
}

# locates the correct python version
# returns the executable path in case of success, or an empty string otherwise
function GetPythonLocation
{
  which python2 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local python_path=`which python2`
  fi

  if [ -z "$python_path" ] ; then
    which python > /dev/null 2>&1
    if [ $? -eq 0 ] ; then
      local python_path=`which python`
    fi
  fi

  "$python_path" --version 2>&1 | grep 2.7 > /dev/null 2>&1
  if [ $? -ne 0 ] ; then
    echo ""
    return
  fi

  printf "$python_path"
}

# installs the disassembler module
# returns 0 in case of success, or 1 otherwise
function InstallDisassembler
{
  echo "[+] Installing the disassembler"
  if [ ! -d "${PREFIX}/bin" ]; then 
    mkdir -p "${PREFIX}/bin"
    if [ $? -ne 0 ] ; then
      echo "Failed to create the bin folder inside the prefix directory"
      return 1
    fi
  fi

  # by default install to the user's python package directory
  # and copy the script itself to ${PREFIX}/bin
  local python_path=`GetPythonLocation`
  if [ -z "$python_path" ] ; then
    echo "Failed to locate a suitable python interpreter"
    return 1
  fi

  if [[ "$OSTYPE" == "darwin"* ]]; then
    # python install on osx travis (and maybe normal osx with homebrew?) is broken, workaround
    "$python_path" ${DIR}/tools/setup.py install --user --prefix= --install-scripts "${PREFIX}/bin"
  else
    "$python_path" ${DIR}/tools/setup.py install --user --install-scripts "${PREFIX}/bin"
  fi
  if [ $? -ne 0 ] ; then
    echo "Failed to install the disassembler"
    return 1
  fi

  return 0
}

# builds the llvm source code inside the third-party folder
# returns 0 in case of success, or 1 otherwise
function BuildLLVM
{
  DownloadLLVMTarball
  if [ $? -ne 0 ] ; then
    return 1
  fi

  pushd ${BUILD_DIR}

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

  if [ $? -ne 0 ] ; then
    echo "CMake could not generate the makefiles for LLVM"
    return 1
  fi

  make -j${job_count}
  if [ $? -ne 0 ] ; then
    echo "Failed to compile LLVM"
    return 1
  fi

  popd
  popd

  return 0
}

# builds mcsema, installing it inside the prefix directory
# returns 0 in case of success, or 1 otherwise
function BuildMcSema
{
  pushd ${BUILD_DIR}

  echo "[+] Configuring: McSema"

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
      -DMCSEMA_BUILD_DIR="${BUILD_DIR}" \
      -DMCSEMA_GEN_DIR="${GEN_DIR}" \
      ${MCSEMA_DIR}

  if [ $? -ne 0 ] ; then
    echo "CMake could not generate the makefiles for McSema"
    return 1
  fi

  echo "[+] Building: McSema"

  make -j${job_count}
  if [ $? -ne 0 ] ; then
    echo "Failed to build McSema"
    return 1
  fi

  echo "[+] Installing: McSema"

  make install
  if [ $? -ne 0 ] ; then
    echo "Failed to install McSema to the prefix directory"
    return 1
  fi

  popd

  return 0
}

function ShowUsage() {
  echo "Usage:"
  echo "$0 [--prefix <PREFIX>] [--build <BUILD TYPE>] [--enable-rtti]"
  echo "PREFIX: Installation directory prefix"
  echo "BUILDTYPE: Built type (e.g. Debug, Release, etc.)"
  echo "--enable-rtti: Enable RTTI for building LLVM"
}

main $@
exit $?
