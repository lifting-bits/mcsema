#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
BIN=$1
$DIR/build/mc-sema/bitcode_from_cfg/cfg_to_bc -mtriple=x86_64-pc-linux-gnu -i=${BIN}.cfg -driver=mcsema_main,main,raw,return,C -o=${BIN}.bc

echo "Saved bitcode to ${BIN}.bc"
