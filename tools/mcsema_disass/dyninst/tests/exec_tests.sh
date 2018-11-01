#!/bin/bash

# Copyright (c) 2018 Trail of Bits, Inc.
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

build_path=$1

./run_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null

./no_flags_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null

./pie_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null

./pie_s_tests.py --disass $build_path/tools/mcsema_disass/dyninst/mcsema-dyninst-disass --std_defs $build_path/../../../tools/mcsema/tools/mcsema_disass/defs/linux.txt --lift $build_path/mcsema-lift-4.0 --lib_dir $build_path/mcsema/Arch/X86/Runtime/ > /dev/null
