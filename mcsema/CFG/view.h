/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#pragma once

#include "mcsema/CFG/sqlCFG.h"

#include <iostream>

namespace mcsema {
namespace cfg {

void run()
{
  // So far Letter_ is the top level class of the API
  // Letter from frontend to backend with possibly several Modules
  Letter letter;

  // Insert
  letter.CreateSchema();
  auto lib = letter.module("lib.so");
  auto bin = letter.module("bin.out");

  auto main = letter.func(bin, 12, true);
  auto foo = letter.func(bin, 32, false);
  auto library_func = letter.func(lib, 0, false);

  // TODO: Calculate automatically size
  auto text = bin.AddMemoryRange(400400, 20, "push rax ... pop rax");

  auto entry_bb = bin.AddBasicBlock(400400, 8, text);
  auto exit_bb = bin.AddBasicBlock(400415, 7, text);

  std::cout << entry_bb.data().size() << "_" << entry_bb.data()[0] << "_" << std::endl;
  std::cout << exit_bb.data().size() << std::endl;

  main.AttachBlock(entry_bb);
  main.AttachBlock(exit_bb);

  foo.AttachBlocks( { entry_bb, exit_bb } );
}


} // namespace cfg
} // namespace mcsema
