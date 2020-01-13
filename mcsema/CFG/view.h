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

template<typename T>
void CheckName(T &t, const std::string& who) {
  auto maybe_name = t.Name();
  if (maybe_name) {
    std::cout << who << ": has name" << std::endl;
  } else {
    std::cout << who << ": does not have name" << std::endl;
  }
}

void TrySomeErase(mcsema::cfg::Module &m) {
    std::cerr << " > Let's print all current blocks with their xrefs" << std::endl;
    // 1 query
    for (auto bb_it = m.Blocks(); auto bb = bb_it.Fetch();) {
        // |bb_it| queries
        std::cerr << bb->ea() << std::endl;
        // |bb_it| queries
        for (auto ref_it = bb->CodeXrefs_d(); auto code_xref = ref_it.Fetch();) {
            std::cerr << '\t' << *code_xref << std::endl;
        }
    }

    std::cerr << " > Now we remove some block, let's say the second one" << std::endl;
    auto bb_it = m.Blocks();
    bb_it.Fetch();
    bb_it.Fetch()->Erase();

    std::cerr << " > We are left with:" << std::endl;
    for (auto bb_it = m.Blocks(); auto bb = bb_it.Fetch();)
        std::cerr << bb->ea() << std::endl;
}

void run()
{
  using namespace std::string_literals;
  // So far Letter_ is the top level class of the API
  // Letter from frontend to backend with possibly several Modules
  Letter letter("example.sql");

  // Insert
  letter.CreateSchema();
  std::cout << " > Creating modules" << std::endl;
  auto lib = letter.AddModule("lib.so");
  auto bin = letter.AddModule("bin.out");

  std::cout << " > Adding symtab entries to modules" << std::endl;
  auto s_main = bin.AddSymtabEntry("main", SymtabEntryType::Internal);
  auto error_name = bin.AddSymtabEntry("error_name", SymtabEntryType::Internal);
  error_name.Erase();

  std::cout << " > Adding some functions to bin module" << std::endl;
  auto main = letter.AddFunction(bin, 12, true);
  main.Name(s_main);
  auto foo = letter.AddFunction(bin, 32, false);

  CheckName(main, "main");
  CheckName(foo, "foo");

  std::cout << "s_main holds " << (*s_main).name << " with type "
            << static_cast<int>((*s_main).type)
            << std::endl;
  std::cout << "main has name: " << (*(main.Name())) << std::endl;

  auto library_func = letter.AddFunction(lib, 0, false);

  std::string bin_data = "push rax ... pop rax\0";
  auto text = bin.AddMemoryRange(400400, 20, bin_data);
  auto copy_of_text = bin.AddMemoryRange(400400, bin_data);

  auto entry_bb = bin.AddBasicBlock(400400, 8, text);
  auto exit_bb = bin.AddBasicBlock(400415, 7, text);

  std::cout << "*** BasicBlock::Data()" << std::endl;
  std::cout << entry_bb.Data().size() << ": " << entry_bb.Data() << std::endl;
  std::cout << exit_bb.Data().size() << ": " << exit_bb.Data() << std::endl;

  // Add CodeXrefs
  // TODO: Check validity of entry
  auto xref = entry_bb.AddXref(400407, 600800, OperandType::Immediate);
  auto masked_xref = entry_bb.AddXref(400409, 600800,
                                      OperandType::Immediate,
                                      bin.AddSymtabEntry("Reference 1",
                                                         SymtabEntryType::Artificial),
                                      0xffffffff);

  auto maybe_masked_xref_name = masked_xref.Name();
  std::cout << "Name of code xref at " << masked_xref.ea() << " is "
            << ((maybe_masked_xref_name) ? *maybe_masked_xref_name : "NOT SET!")
            << std::endl;

  auto c_xref = exit_bb.AddXref(400415, 600825, OperandType::Immediate);
  auto maybe_c_xref_name = c_xref.Name();
  std::cout << "Name of code xref at " << c_xref.ea() << " is "
            << ((maybe_c_xref_name) ? *maybe_c_xref_name : "NOT SET!")
            << std::endl;

  std::cout << "Giving name to the poor thingy." << std::endl;
  c_xref.Name(s_main);
  maybe_c_xref_name = c_xref.Name();
  std::cout << "Name of code xref at " << c_xref.ea() << " is "
            << ((maybe_c_xref_name) ? *maybe_c_xref_name : "NOT SET!")
            << std::endl;


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

  std::cout << "*** MemoryRange::Data()" << std::endl;
  std::cout << rodata.Data() << " " << rodata.Data().size() << std::endl;

  std::cout << "** BasicBlock::Data()" << std::endl;
  std::cout << entry_bb.Data() << std::endl;
  std::cout << exit_bb.Data() << std::endl;

  // Add DataXrefs
  auto d_xref = hello.AddXref(600800, 600823, 8,
                              FixupKind::Absolute,
                              bin.AddSymtabEntry("Variable X",
                                                 SymtabEntryType::Artificial)
                              );
  std::cout << "d_xref has ea: " << d_xref.ea() << std::endl;

  Segment::Flags new_flags = { true, true, false, true };
  res.SetFlags( new_flags );

  main.AttachBlock(entry_bb);
  main.AttachBlock(exit_bb);

  foo.AttachBlocks( { entry_bb, exit_bb } );

  auto matrix_add = bin.AddExternalFunction(
      600650,
      bin.AddSymtabEntry("matrix_add", SymtabEntryType::Imported),
      CC::X86_64_SysV, true, true);
  std::cout << "External functiom matrix_add has name: " << matrix_add.Name()
            << ", and ea: " << matrix_add.ea() << std::endl;

  // Iterate over all symtab entry data_t
  {
    std::cout << "Going to print all symbols" << std::endl;
    for (auto weak_it = bin.Symbols_d(); auto data = weak_it.Fetch(); ) {
      std::cout << (*data).name << std::endl;
    }

    std::cout << "Print all symbols names and types" << std::endl;
    auto printer= [](const auto& data) {
      std::cout << data.name << ", type: "
                << static_cast<int>(data.type) << std::endl;
    };
    bin.ForEachSymbol_d(printer);
  }

  // Iterate over all Function objects
  {
    std::cout << "Iterating over all functions, printing eas" << std::endl;
    for (auto weak_it = bin.Functions(); auto obj = weak_it.Fetch(); ) {
      std::cout << (*obj).ea() << std::endl;
    }

  }

  // Try all data_t operator*() const;
  {
    auto main_data = *main;
    auto foo_data = *foo;

    auto s_main_data = *s_main;
    auto main_symbol = main.Symbol();

    auto text_data = *text;

    auto entry_bb_data = *entry_bb;

    auto xref_data = *xref;
    auto masked_xref_data = *masked_xref;
    auto c_cref_data = *c_xref;

    auto d_xref_data = *d_xref;

  }

  TrySomeErase(bin);
}


} // namespace cfg
} // namespace mcsema
