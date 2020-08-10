#!/usr/bin/env bash

# Copyright (c) 2020 Trail of Bits, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
SOURCE_DIR="${SCRIPT_DIR}/../"

install_binja () {
  # this file is the decrypted version and placed there by the
  # before-install action in .travis.yml
  local BINJA_TARGZ="${SCRIPT_DIR}/mcsema_binja.tar.gz"
	local BINJA_INSTALL="${SOURCE_DIR}/binaryninja"

  # make sure our PYTHONPATH is setup for binja
  export PYTHONPATH=${BINJA_INSTALL}/python
	python2.7 -c "import binaryninja" 2>/dev/null
	if [ ! "$?" = "0" ]; then
		if [ ! -e ${BINJA_INSTALL}/python/binaryninja/__init__.py ]; then

			echo "Extracting Binary Ninja" && \
        tar -xzf ${BINJA_TARGZ} -C ${SOURCE_DIR} && \
        echo "Extracted to ${SOURCE_DIR}"

			if [ ! "$?" = "0" ]; then
				echo "FAILED: Binja extraction failed"
				return 1
			fi

		else
			echo "Found a copy of Binja, skipping install, using existing copy"
		fi

		if [ ! -e ${HOME}/.binaryninja/license.dat ]; then
			echo "Could not find Binja license, checking for ~/.binaryninja"
			if [ ! -e ${HOME}/.binaryninja ]; then
				echo "~/.binaryninja does not exist, creating directory..."
				mkdir ${HOME}/.binaryninja
			fi

			echo "Copying our CI Binja license to ${HOME}/.binaryninja/license.dat"
			cp ${BINJA_INSTALL}/mcsema_binja_license.txt ${HOME}/.binaryninja/license.dat
		else
			echo "Found existing Binja license, ignoring..."
		fi

    # sanity check the install
    python2.7 -c "import binaryninja" 2>/dev/null
    if [ ! "$?" = "0" ]; then
      echo "FAILED: still can't use Binary Ninja, aborting"
      return 1
    else
      echo "BinaryNinja installed successfully"
    fi

    echo "Updating Binary Ninja to Dev Channel latest"
    python2.7 ${SCRIPT_DIR}/update_binja.py

	else
		echo "Binja already exists; skipping..."
	fi

  return 0
}

main() {
  if [ $# -ne 2 ] ; then
    printf "Usage:\n\ttravis.sh <linux|osx> <initialize|build>\n"
    return 1
  fi

  local platform_name="$1"
  local operation_type="$2"

  # This makes life simpler for github actions
  if [[ "${platform_name}" == "macos-latest" ]] ; then
    platform_name="osx"
  elif [[ "${platform_name}" == "ubuntu-latest" ]] ; then
    platform_name="linux"
  fi

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
  sudo dpkg --add-architecture i386
  sudo apt-get -qq update
  if [ $? -ne 0 ] ; then
    printf " x The package database could not be updated\n"
    return 1
  fi

  printf " > Installing the required packages...\n"
  sudo apt-get install -qqy python2.7 \
                            build-essential \
                            realpath \
                            python-setuptools \
                            git \
                            python2.7 \
                            wget \
                            libtinfo-dev \
                            gcc-multilib \
                            g++-multilib \
                            lsb-release \
                            liblzma-dev \
                            zlib1g-dev \
                            libprotobuf-dev \
                            protobuf-compiler \
                            ccache

  sudo apt-get install -qqy libc6:i386 \
                            libstdc++6:i386 \
                            zlib1g-dev:i386 \
                            liblzma-dev:i386 \
                            libtinfo-dev:i386

  # install clang and ccsyspath for ABI libraries generation
  pip install clang ccsyspath

  if [ $? -ne 0 ] ; then
    printf " x Could not install the required dependencies\n"
    return 1
  fi

  install_binja
  if [ $? -ne 0 ] ; then
    printf " x Could not install binary ninja"
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

  # set up ada support for cmake
  # Old supported versions: "35" "36" "37" "38" "39" "40" 
  llvm_version_list=( "50" "60" )
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

    # create the cache folder for ccache
    local cache_folder_name="ccache_llvm${llvm_version}"
    printf " > Setting up ccache folder...\n"

    if [ ! -d "${cache_folder_name}" ] ; then
      mkdir "${cache_folder_name}" > "${log_file}" 2>&1
      if [ $? -ne 0 ] ; then
          printf " x Failed to create the ccache folder: ${cache_folder_name}. Error output follows:\n"
          printf "===\n"
          cat "${log_file}"
          return 1
      fi
    fi

    export CCACHE_DIR="$(realpath ${cache_folder_name})"
    printf " i ${CCACHE_DIR}\n"

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
  git clone "https://github.com/lifting-bits/remill.git" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to clone the remill repository. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi
  
  cd remill

  # we are supposed to put mcsema inside the remill folder
  mkdir -p "remill/tools/mcsema" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to create the remill/tools/mcsema folder. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Copying the mcsema folder...\n"
  local file_list=( "cmake" "tools" "examples" "scripts" "tests" "docs" "mcsema" "generated" "CMakeLists.txt" "README.md" "CONTRIBUTING.md" ".gdbinit" "LICENSE" "ACKNOWLEDGEMENTS.md" ".gitignore" ".travis.yml" )
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

  ( cd build && cmake -DMCSEMA_DISABLED_ABI_LIBRARIES:STRING="" -DCMAKE_VERBOSE_MAKEFILE=True ../remill ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to generate the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Building...\n"
  if [ "${llvm_version:0:1}" != "4" ] ; then
    printf " i Clang static analyzer not supported on this LLVM release\n"
    #( cd build && make -j `nproc` ) > "${log_file}" 2>&1
  else
    printf " i Clang static analyzer enabled\n"
    #( cd build && scan-build --show-description --status-bugs make -j `nproc` ) > "${log_file}" 2>&1
  fi

  if [ $? -ne 0 ] ; then
    printf " x Failed to build the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Installing...\n"
  ( cd build && sudo make install -j `nproc` ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to install the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Build succeeded\n"

  printf " > Building Integration Test Suite...\n"
  pushd ./remill/tools/mcsema/tests/test_suite_generator
  mkdir build
  ( cd build && cmake -DMCSEMA_PREBUILT_CFG_PATH=$(pwd)/../generated/prebuilt_cfg -DCMAKE_VERBOSE_MAKEFILE=True .. ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to generate test suite project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  ( cd build && make -j `nproc` ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to build test suite. Output below:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  ( cd build && make install ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to install test suite. Output below:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  popd

  printf "\n\n\nCalling the integration test suite...\n"
  local test_log_file=`mktemp`
  ( cd ./remill/tools/mcsema/tests/test_suite_generator/test_suite && ./start.py ) > "${test_log_file}" 2>&1
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
