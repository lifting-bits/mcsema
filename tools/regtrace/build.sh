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
# See the License for the specific language governing permissions and
# limitations under the License.

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