#!/bin/sh

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
