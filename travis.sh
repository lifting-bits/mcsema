#!/usr/bin/env bash

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
  sudo apt-get install -qqy python2.7 build-essential realpath python-setuptools git python2.7 wget libtinfo-dev gcc-multilib g++-multilib lsb-release
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

linux_build() {
  local ubuntu_version=`cat /etc/issue | awk '{ print $2 }' | cut -d '.' -f 1-2 | tr -d '.'`
  printf "Building platform: linux (ubuntu ${ubuntu_version})\n"

  local log_file=`mktemp`

  printf " > Cleaning up...\n"
  if [ -d "remill" ] ; then
    rm -rf remill > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to remove the existing remill folder. Error output follows:\n"
      printf "===\n"
      cat "${log_file}"
      return 1
    fi
  fi

  if [ -d "build" ] ; then
    rm -rf remill > "${log_file}" 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to remove the existing build folder. Error output follows:\n"
      printf "===\n"
      cat "${log_file}"
      return 1
    fi
  fi

  printf " > Cloning remill...\n"
  git clone "https://github.com/trailofbits/remill.git" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to clone the remill repository. Error output follows:\n"
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
  local file_list=( "docs" "generated" "mcsema" "tests" "tools" ".gdbinit" ".gitignore" ".travis.yml" "ACKNOWLEDGEMENTS.md" "CMakeLists.txt" "LICENSE" "README.md" "travis.sh")
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
  printf " > Acquiring the cxx-common package...\n"
  wget "https://s3.amazonaws.com/cxx-common/libraries-llvm40-ubuntu${ubuntu_version}-amd64.tar.gz" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to download the cxx-common package. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  tar xzf "libraries-llvm40-ubuntu1404-amd64.tar.gz" > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x The archive appears to be corrupted. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  export TRAILOFBITS_LIBRARIES=`realpath libraries`

  printf " > Generating the project...\n"
  mkdir build > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to create the build folder. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  ( cd build && cmake ../remill ) > "${log_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Failed to generate the project. Error output follows:\n"
    printf "===\n"
    cat "${log_file}"
    return 1
  fi

  printf " > Building...\n"
  ( cd build && make -j `nproc` ) > "${log_file}" 2>&1
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

  print "\n\n\nCalling the testing suite...\n"
  ./tests/test_suite/start.py

  return $?
}

osx_build() {
  printf "Building for platform: osx\n"

  printf " x This platform is not yet supported\n"
  return 1
}

main $@
exit $?
