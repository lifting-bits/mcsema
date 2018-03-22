#!/usr/bin/env bash

# Copyright (c) 2017 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specifi

main() {
  if [ $# -ne 2 ] ; then
    printf "Usage:\n\ttravis.sh <linux|osx> <initialize|build>\n"
    return 1
  fi

  local platform_name="$1"
  local operation_type="$2"

  if [[ "${platform_name}" != "osx" && "${platform_name}" != "linux" ]] ; then
    printf "Invalid platform: ${platform_name}\n"
    return 1
  fi

  if [[ "${operation_type}" == "initialize" ]] ; then
    "${platform_name}_initialize"
    return $?

  elif [[ "$operation_type" == "build" ]] ; then
    "${platform_name}_build"
    return $?
  
  else
    printf "Invalid operation\n"
    return 1
  fi
}

linux_initialize() {
  printf "Initializing platform: linux\n"

  printf " > Updating the system...\n"
  sudo apt-get -qq update
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n"
    return 1
  fi

  printf " > Installing the required packages...\n"
  sudo apt-get install -qqy python2.7 build-essential realpath python-setuptools git python2.7 wget libtinfo-dev gcc-multilib g++-multilib lsb-release liblzma-dev zlib1g-dev gnat
  if [ $? -ne 0 ] ; then
    printf " x Could not install the required dependencies\n"
    return 1
  fi

  printf " > The system has been successfully initialized\n"
  return 0
}

osx_initialize() {
  printf "Initializing platform: osx\n"

  printf " x This platform is not yet supported\n"
  return 1
}

# Travis: do not delete the cxxcommon folder, because it is configured to be cached!
linux_build() {
  local original_path="${PATH}"
  local log_file=`mktemp`

  llvm_version_list=( "35" "36" "37" "38" "39" "40" "50" )
  for llvm_version in "${llvm_version_list[@]}" ; do
    printf "#\n"
    printf "# Running CI tests for LLVM version ${llvm_version}...\n"
    printf "#\n\n"

    printf " > Cleaning up the environment variables...\n"
    export PATH="${original_path}"

    unset TRAILOFBITS_LIBRARIES
    unset CC
    unset CXX
    
    printf " > Cleaning up the build folders...\n"
    if [ -d "remill" ] ; then
      sudo rm -rf remill > "${log_file}" 2>&1
      if [ $? -ne 0 ] ; then
        printf " x Failed to remove the existing remill folder. Error output follows:\n"
        printf "===\n"
        cat "${log_file}"
        return 1
      fi
    fi

    if [ -d "build" ] ; then
      sudo rm -rf build > "${log_file}" 2>&1
      if [ $? -ne 0 ] ; then
        printf " x Failed to remove the existing build folder. Error output follows:\n"
        printf "===\n"
        cat "${log_file}"
        return 1
      fi
    fi

    if [ -d "libraries" ] ; then
      sudo rm -rf libraries > "${log_file}" 2>&1
      if [ $? -ne 0 ] ; then
        printf " x Failed to remove the existing libraries folder. Error output follows:\n"
        printf "===\n"
        cat "${log_file}"
        return 1
      fi
    fi

    linux_build_helper "${llvm_version}"
    if [ $? -ne 0 ] ; then
      printf " ! One or more tests have failed for LLVM ${llvm_version}\n"
      return 1
    fi

    printf "\n\n"
  done

  return $?
}

osx_build() {
  printf "Building for platform: osx\n"

  printf " x This platform is not yet supported\n"
  return 1
}

linux_build_helper() {
  if [ $# -ne 1 ] ; then
    printf "Usage:\n\tlinux_build_helper <llvm_version>\n\nllvm_version: 35, 40, ...\n"
    return 1
  fi

  local llvm_version="$1"
  local ubuntu_version=`cat /etc/issue | awk '{ print $2 }' | cut -d '.' -f 1-2 | tr -d '.'`

  local log_file=`mktemp`

  printf " > Cloning remill...\n"
  local remill_commit_id=`cat .remill_commit_id`
  if [ $? -ne 0 ] ; then
    printf " x Failed to read the Remill commit id from file. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  git clone "https://github.com/trailofbits/remill.git" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to clone the remill repository. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  ( cd remill && git checkout -b temp $remill_commit_id ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to switch to the correct remill commit. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  # we are supposed to put mcsema inside the remill folder
  mkdir "remill/tools/mcsema" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to create the remill/tools/mcsema folder. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Copying the mcsema folder...\n"
  local file_list=( ".remill_commit_id" "docs" "examples" "generated" "mcsema" "tests" "tools" ".gdbinit" ".gitignore" ".travis.yml" "ACKNOWLEDGEMENTS.md" "CMakeLists.txt" "LICENSE" "README.md" "scripts")
  for file_name in "${file_list[@]}" ; do
    cp -r "${file_name}" "remill/tools/mcsema" > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to copy the mcsema files in remill/tools/mcsema. Error output follows:\n"
      printf "===\n"
      cat "${log_file}"
      return 1
    fi
  done

  # acquire the cxx-common package
  printf " > Acquiring the cxx-common package: LLVM${llvm_version}/Ubuntu ${ubuntu_version}\n"

  if [ ! -d "cxxcommon" ] ; then
    mkdir "cxxcommon" > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
        printf " x Failed to create the cxxcommon folder. Error output follows:\n"
        printf "===\n"
        cat "${log_file}"
        return 1
    fi
  fi

  local cxx_common_tarball_name="libraries-llvm${llvm_version}-ubuntu${ubuntu_version}-amd64.tar.gz"
  if [ ! -f "${cxx_common_tarball_name}" ] ; then
    ( cd "cxxcommon" && wget "https://s3.amazonaws.com/cxx-common/${cxx_common_tarball_name}" ) > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to download the cxx-common package. Error output follows:\n"
      printf "===\n"
      cat "${log_file}"
      return 1
    fi
  fi

  if [ ! -d "libraries" ] ; then
    tar xzf "cxxcommon/${cxx_common_tarball_name}" > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x The archive appears to be corrupted. Error output follows:\n"
      printf "===\n"
      cat "${log_file}"

      rm "cxxcommon/${cxx_common_tarball_name}"
      rm -rf libraries
      return 1
    fi
  fi

  export TRAILOFBITS_LIBRARIES=`realpath libraries`
  export PATH="${TRAILOFBITS_LIBRARIES}/llvm/bin:${TRAILOFBITS_LIBRARIES}/cmake/bin:${TRAILOFBITS_LIBRARIES}/protobuf/bin:${PATH}"

  export CC="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang"
  export CXX="${TRAILOFBITS_LIBRARIES}/llvm/bin/clang++"

  printf " > Generating the project...\n"
  mkdir build > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to create the build folder. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  ( cd build && cmake -DCMAKE_VERBOSE_MAKEFILE=True ../remill ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to generate the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Building...\n"
  if [ "${llvm_version:0:1}" != "4" ] ; then
    printf " i Clang static analyzer not supported on this LLVM release\n"
    ( cd build && make -j `nproc` ) > "${log_file}" 2>&1
  else
    printf " i Clang static analyzer enabled\n"
    ( cd build && scan-build --show-description --status-bugs make -j `nproc` ) > "${log_file}" 2>&1
  fi

  if [ $? -ne 0 ] ; then
    printf " x Failed to build the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Installing...\n"
  ( cd build && sudo make install ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to install the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Build succeeded\n"

  printf "\n\n\nCalling the integration test suite...\n"
  local test_log_file=`mktemp`
  ( cd ./remill/tools/mcsema/tests/test_suite && ./start.py ) > "${test_log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed the integration test suite:\n"
    printf "===\n"
    cat "${test_log_file}"
    return 1
  fi

  return 0
}

main $@
exit $?
