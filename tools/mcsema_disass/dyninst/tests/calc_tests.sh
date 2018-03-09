#!/bin/bash

function run_case() {
    diff <(./a.out < $1) <(./calc_lifted.out < $1) > /dev/null && echo OK || echo Error
}

set -e

if [ $1 == "help" ]; 
    then echo "\$1 dissas \$2 std_defs \$3 lift \$4 lib_dir"; exit;
fi

disass=$1
lift=$3
lib_dir=$4
std_def=$2

$CC calc.c 
$disass -o calc.cfg --std-defs $std_def a.out
$lift --arch amd64 --os linux --cfg calc.cfg --output calc.bc

$CC -m64 -o calc_lifted.out calc.bc $lib_dir/libmcsema_rt64-4.0.a -lm

prefix="calc_inputs"
run_case $prefix/input1.txt
run_case $prefix/input2.txt
run_case $prefix/input3.txt
run_case $prefix/input4.txt

rm a.out
rm calc.cfg
rm calc.bc
rm calc_lifted.out
