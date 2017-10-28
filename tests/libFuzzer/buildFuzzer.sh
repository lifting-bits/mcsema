#!/bin/sh

set -e

clang-3.8 -c -g -O2 -std=c++11 ../../third_party/llvm/lib/Fuzzer/*.cpp -I../../../third_party/llvm/lib/Fuzzer/
