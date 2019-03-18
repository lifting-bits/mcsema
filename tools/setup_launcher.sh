#!/usr/bin/env bash

main() {
  if [ $# -ne 1 ] ; then
    printf "Pass the install folder to the script!\n"
    return 1
  fi

  local install_folder="$1"

  printf "Looking for the Python interpreter\n"
  which python2.7 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local python_interpreter="python2.7"
  else
    which python2 > /dev/null 2>&1
    if [ $? -ne 0 ] ; then
      which python > /dev/null 2>&1
      if [ $? -ne 0 ] ; then
        printf " x Failed to find a Python interpreter\n"
        return 1
      else
        local python_interpreter="python"
      fi
    else
      local python_interpreter="python2"
    fi
  fi

  local python_version=`"${python_interpreter}" --version 2>&1 | awk '{ print $2 }' | cut -d '.' -f 1-2`
  if [ "${python_version}" != "2.7" ]; then
    printf " x Python 2.7 was not found\n"
    return 1
  fi

  printf " i Python 2.7 found: ${python_interpreter}\n\n"

  echo "Installing mcsema-disass"
  export PYTHONPATH="${install_folder}/lib/python2.7/site-packages"
  if [ ! -d "${PYTHONPATH}" ] ; then
    mkdir -p "${PYTHONPATH}" > /dev/null 2>&1
    if [ $? -ne 0 ] ; then
      printf " x Failed to create the site-packages folder\n"
      return 1
    fi
  fi

  printf " i site-packages: ${PYTHONPATH}\n"

  local temp_file=`mktemp`
  "${python_interpreter}" setup.py install -f --prefix=${install_folder} > "${temp_file}" 2>&1
  if [ $? -ne 0 ] ; then
    printf " x Install failed\n\n"

    printf "Output follows\n===\n"
    cat "${temp_file}"
    rm "${temp_file}"

    return 1
  else
    printf " i Successfully installed\n"
  fi

  return 0
}

main $@
exit $?
