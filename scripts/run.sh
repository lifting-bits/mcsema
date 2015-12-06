#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

# Copy the binary to a temporary file.
BIN=$(mktemp --tmpdir=/tmp bin_XXXXXXXXXX)
cp $1 $BIN
chmod a+x $BIN
CXX=$(which c++)

LDLIBS=$(ldd ${BIN} | grep -o -P '/.* ' | tr '\n' ' ')

# Convert the binary into a CFG file.
echo "Decoding"
$DIR/scripts/ida_get_cfg.sh $BIN

# Convert the CFG file into a bitcode file.
echo "Lifting"
$DIR/scripts/cfg_to_bc.sh $BIN &>/dev/null

echo "Optimizing"
$DIR/build/llvm-3.5/bin/opt -Oz -o=${BIN}.opt.bc ${BIN}.bc

echo "Compiling"
$DIR/build/llvm-3.5/bin/llc -filetype=obj -o=${BIN}.o ${BIN}.opt.bc

echo "Linking"
$CXX -g3 -m64 -std=gnu++11 -I${DIR} ${BIN}.o $DIR/drivers/ELF_64_linux.cpp $LDLIBS -o ${BIN}.lifted -lpthread

echo "Done! Produced ${BIN}.lifted"
