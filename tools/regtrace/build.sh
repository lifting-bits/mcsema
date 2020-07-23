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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [[ "${PIN_ROOT}" -eq "" ]] ; then
  PIN_ROOT=/opt/pin-3.2-81205-gcc-linux/
fi

if [[ ! -e "${PIN_ROOT}/pin" ]] ; then
  echo "Could not find PIN at ${PIN_ROOT}. Try to set the PIN_ROOT environment variable."
  exit 1
fi

pushd ${DIR}

mkdir obj-ia32
mkdir obj-intel64

echo "[+] Compiling 32-bit program tracing pintool"
make \
  TARGET=ia32 \
  PIN_ROOT="${PIN_ROOT}" \
  CXX="g++ -std=gnu++11 " \
  obj-ia32/Trace.so

echo "[+] Compiling 64-bit program tracing pintool"
make \
  TARGET=intel64 \
  PIN_ROOT="${PIN_ROOT}" \
  CXX="g++ -std=gnu++11 " \
  obj-intel64/Trace.so

popd