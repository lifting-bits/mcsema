#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))

# Copy the binary to a temporary file.
BIN=$(mktemp --tmpdir=/tmp bin_XXXXXXXXXX)
cp $1 $BIN
chmod a+x $BIN
CXX=$(which c++)

LDLIBS=$(ldd ${BIN} | grep -o -P '/.* ' | sed -s 's/^/-Wl,-L/' | tr '\n' ' ')

# Convert the binary into a CFG file.
$DIR/scripts/ida_get_cfg.sh $BIN

# Convert the CFG file into a bitcode file.
$DIR/scripts/cfg_to_bc.sh $BIN

exit

$DIR/build/llvm-3.5/bin/llc -filetype=obj -o=${BIN}.o ${BIN}.bc

$CXX -m64 -std=gnu++11 ${BIN}.o $DIR/drivers/ELF_64_linux.cpp -o ${BIN}.lifted -lpthread $LDLIBS

echo "Saved to ${BIN}.lifted"