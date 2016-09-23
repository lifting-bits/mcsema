#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
IDA=`locate idal64 | head -n1`

# Copy the binary to a temporary file.
BIN=$1
# Extract the CFG file. This will use the produced name->address mapping to symbolize
# the code.
$IDA -B -S"${DIR}/mc-sema/bin_descend/get_cfg.py --std-defs=${DIR}/mc-sema/std_defs/std_defs.txt --batch --entry-symbol main --output=${BIN}.cfg" ${BIN}

#$DIR/mc-sema/bin_descend/bin_descend_wrapper.py -i=$1 -func-map=$DIR/mc-sema/std_defs/std_defs.txt -entry-symbol=main
#$DIR/build/mc-sema/bitcode_from_cfg/cfg_to_bc -i $1.cfg -driver=mcsema_main,main,raw,noreturn,C -o $1.ll

echo "Decoded"
