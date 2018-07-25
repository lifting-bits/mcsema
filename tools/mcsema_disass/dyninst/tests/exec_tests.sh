#!/bin/bash

build_path=$1

./run_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null

./no_flags_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null

