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
  using namespace std::string_literals;
  // So far Letter_ is the top level class of the API
  // Letter from frontend to backend with possibly several Modules
  Init("example.sql");
  Letter letter;

  // Insert
  letter.CreateSchema();
  auto lib = letter.module("lib.so");
  auto bin = letter.module("bin.out");

  auto main = letter.func(bin, 12, true);
  auto foo = letter.func(bin, 32, false);
  auto library_func = letter.func(lib, 0, false);

  // TODO: Calculate automatically size
  std::string bin_data = "push rax ... pop rax\0";
  auto text = bin.AddMemoryRange(400400, 20, bin_data);
  auto copy_of_text = bin.AddMemoryRange(400400, bin_data);

  auto entry_bb = bin.AddBasicBlock(400400, 8, text);
  auto exit_bb = bin.AddBasicBlock(400415, 7, text);

  std::cout << "*** BasicBlock::Data()" << std::endl;
  std::cout << entry_bb.Data().size() << ": " << entry_bb.Data() << std::endl;
  std::cout << exit_bb.Data().size() << ": " << exit_bb.Data() << std::endl;

  std::string my_favorite_str = "Hello\0\0World\n\0\0\0\0\0\0\0\0\0\0L"s;
  auto rodata = bin.AddMemoryRange(600800, my_favorite_str.size(), my_favorite_str);

  auto hello = rodata.AddSegment(600800, 6, { true, true, false, false }, "hello");
  auto one_off = rodata.AddSegment(600801, 5, { true, true, false, false }, "hello");
  auto res = rodata.AddSegment(600806, 9, { true, true, false, false }, "rest_of_rodata");
  auto last = rodata.AddSegment(600823, 1, {true, true, true, true }, "last");

  std::cout << "*** Segment::Data()" << std::endl;
  std::cout << hello.Data().size() << " " << hello.Data() << std::endl;
  std::cout << res.Data().size() << " " << res.Data() << std::endl;
  std::cout << one_off.Data().size() << " " << one_off.Data() << std::endl;
  std::cout << last.Data().size() << " " << last.Data() << std::endl;


  Segment::Flags new_flags = { true, true, false, true };
  res.SetFlags( new_flags );

  main.AttachBlock(entry_bb);
  main.AttachBlock(exit_bb);

  foo.AttachBlocks( { entry_bb, exit_bb } );
}


} // namespace cfg
} // namespace mcsema
