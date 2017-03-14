#!/usr/bin/env bash
# Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved.

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