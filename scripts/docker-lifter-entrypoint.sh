#!/bin/sh

# Needed to process multiple arguments to docker image

V=""
case ${LLVM_VERSION} in 
  llvm35*)
    V=3.5
  ;;
  llvm36*)
    V=3.6
  ;;
  llvm37*)
    V=3.7
  ;;
  llvm38*)
    V=3.8
  ;;
  llvm39*)
    V=3.9
  ;;
  # There is an llvm401 that we treat as 4.0
  llvm40*)
    V=4.0
  ;;
  llvm50*)
    V=5.0
  ;;
  llvm60*)
    V=6.0
  ;;
  llvm70*)
    V=7.0
  ;;
  llvm80*)
    V=8.0
  ;;
  llvm90*)
    V=9.0
  ;;
  llvm100*)
    V=10.0
  ;;
  *)
    echo "Unknown LLVM version: ${LLVM_VERSION}"
    exit 1
  ;;
esac

mcsema-lift-${V} "$@"
