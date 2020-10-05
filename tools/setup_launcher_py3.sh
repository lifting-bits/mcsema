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

main() {
  if [ $# -ne 1 ] ; then
    printf "Pass the install folder to the script!\n"
    return 1
  fi

  local install_folder="$1"

  printf "Looking for the Python interpreter\n"
  which python3.8 > /dev/null 2>&1
  if [ $? -eq 0 ] ; then
    local python_interpreter="python3.8"
  else
    which python3 > /dev/null 2>&1
    if [ $? -ne 0 ] ; then
      which python > /dev/null 2>&1
      if [ $? -ne 0 ] ; then
        printf " x Failed to find a Python interpreter\n"
        return 1
      else
        local python_interpreter="python"
      fi
    else
      local python_interpreter="python3"
    fi
  fi

  local python_version=`"${python_interpreter}" --version 2>&1 | awk '{ print $2 }' | cut -d '.' -f 1-2`

  printf " i Python ${python_version} found: ${python_interpreter}\n\n"

  echo "Installing mcsema-disass"
  export PYTHONPATH="${install_folder}/lib/python${python_version}/site-packages"
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
    rm "${temp_file}"
  fi

  return 0
}

main $@
exit $?
