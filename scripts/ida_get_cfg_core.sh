#!/usr/bin/env bash

DIR=$(dirname $( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd ))
IDA=`locate idal64`

# Copy the binary to a temporary file.
BIN=`mktemp --tmpdir=/tmp bin_XXXXXXXXXX`
cp $1 $BIN
chmod a+x $BIN

# Generate a GDB script.
touch ${BIN}_script
echo file ${BIN} >> ${BIN}_script
echo set env LD_BIND_NOW 1 >> ${BIN}_script
echo b main >> ${BIN}_script
echo r >> ${BIN}_script
echo generate-core-file ${BIN}_core >> ${BIN}_script
echo define find-symbol >> ${BIN}_script
echo info address \$arg0 >> ${BIN}_script
echo end >> ${BIN}_script
echo set logging file ${BIN}_sym_info >> ${BIN}_script
echo set logging on >> ${BIN}_script
echo set logging redirect on >> ${BIN}_script

# Get the functions from the binary and its librariers and place the symbol-finding stuff into a script.
readelf --syms --wide $BIN > ${BIN}_elf_syms
(ldd $BIN | grep -o -P '/.* ' | xargs readelf --syms --wide) >> ${BIN}_elf_syms
grep FUNC ${BIN}_elf_syms | sed -s 's/@.*$//' | grep -o -P ' ([a-zA-Z0-9_])+$' | sort | uniq | sed 's/ /find-symbol /' >> ${BIN}_script

echo q >> ${BIN}_script
echo y >> ${BIN}_script

# Execute the just-created GDB script. This script will find the addresses of
# functions and save that stuff to `${BIN}_sym_info`.
gdb -x ${BIN}_script

# Parse the `${BIN}_sym_info` file and pull out just the name and address for
# each function.
grep '0x' ${BIN}_sym_info | sed -s 's/^.*"\(.*\)" is.*0x\([0-9a-f]*\).*\.$/\1 \2/' > ${BIN}_syms

# Extract the CFG file. This will use the produced name->address mapping to symbolize
# the code.
$IDA -B -S"${DIR}/mc-sema/bin_descend/get_cfg.py --batch --entry-symbol main --output=${BIN}.cfg --syms=${BIN}_syms" ${BIN}_core

#$DIR/mc-sema/bin_descend/bin_descend_wrapper.py -i=$1 -func-map=$DIR/mc-sema/std_defs/std_defs.txt -entry-symbol=main
#$DIR/build/mc-sema/bitcode_from_cfg/cfg_to_bc -i $1.cfg -driver=mcsema_main,main,raw,noreturn,C -o $1.ll

echo "Saved CFG to ${BIN}.cfg"
