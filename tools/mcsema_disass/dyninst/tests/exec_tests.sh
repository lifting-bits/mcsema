#!/bin/bash

build_path=$1

function run_tests() {
    ./$1 $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass /home/laky/Programming/Paradise/mc/mcsema/tools/mcsema_disass/defs/linux.txt $build_path/mcsema-lift-4.0 $build_path/mcsema/Arch/X86/Runtime/
}


./run_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs /home/laky/Programming/Paradise/mc/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/

run_tests "calc_tests.sh"
