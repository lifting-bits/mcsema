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

set -e

if [ $# -ne 2 ] ; then
    echo 'Usage:'
	echo "${0} <input llvm 3.8 bitcode> <output llvm 3.5 bitcode>"
    exit 1
fi

INFILE=$(basename ${1} .bc)
TEMPFILE=${INFILE}.ll
OUTFILE=${2}

llvm-dis-3.8 ${INFILE}.bc -o ${TEMPFILE}

sed -i 's/inbounds [%A-Za-z0-9]\+,//g' ${TEMPFILE}
sed -i 's/load i[0-9]\+,/load/g' ${TEMPFILE}
sed -i 's/load \(half\|float\|double\|x86_fp80\|fp128\),/load/g' ${TEMPFILE}
sed -i 's/load volatile i[0-9]\+,/load volatile/g' ${TEMPFILE}
sed -i 's/load volatile \(half\|float\|double\|x86_fp80\|fp128\),/load volatile/g' ${TEMPFILE}
sed -i 's/ = !{i64/ = i64 !{i64/g' ${TEMPFILE}

llvm-as-3.5 ${TEMPFILE} -o ${OUTFILE}

rm -f ${TEMPFILE}
