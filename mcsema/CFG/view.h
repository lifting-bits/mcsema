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

#include "mcsema/CFG/sqlCFG.h"

namespace mcsema {
namespace cfg {

void run()
{
  static const char * db_name = R"(example.sql)";
  // So far Letter_ is the top level class of the API
  // Letter from frontend to backend with possibly several Modules
  Letter_< db_name > letter;

  // Insert
  letter.CreateSchema();
  auto lib = letter.module("lib.so");
  auto bin = letter.module("bin.out");

  auto main = letter.func(bin, 12, true);
  auto foo = letter.func(bin, 32, false);
  auto library_func = letter.func(lib, 0, false);
#if 0

  // Ask for an "abstract" class that does not encapsulate any particular bb
  auto bb = letter.bb();

  // Two ways to add bb
  bb.insert( 8, "Hello" );

  // Probably remove this one though
  letter.add_bb( 12, "World" );

  {
    uint64_t ea;
    std::string data;
    auto print =
      []( auto ea, auto data ) { std::cerr << ea << " " << data << std::endl; };

    util::iterate( letter.bb().all(), print, ea, data );
  }

  // Same "abstract" class to handle functions
  auto f = letter.func();
  f.insert_bare( 0, true, "hello" );

  // concrete_f is now one particular function, one that starts at ea 0
  auto concrete_f = f.insert_bare( 0, false, "targ124" );

  // Same as f.bind_bbs( 0, { 8, 12 } ) but more convenient
  concrete_f.bind_bbs( { 8, 12 } );

  // Special iteration over "bare" function e.g only "metadata" without bbs
  f.iterate( f.all(), f.print_f() );


  f.bind_bbs( 1, { 12 } );

  // Some tests
  std::cerr << "Example" << std::endl;
  {
    uint64_t ea;
    std::string data;
    auto print =
      []( auto ea, auto data ) { std::cerr << ea << " " << data << std::endl; };
    util::iterate( f.bbs( 0 ), print, ea, data );
  }

  f.unbind_bbs( 0, { 8 } );
  std::cerr << "After unbind" << std::endl;
  {
    uint64_t ea;
    std::string data;
    auto print =
      []( auto ea, auto data ) { std::cerr << ea << " " << data << std::endl; };
    util::iterate( f.bbs( 0 ), print, ea, data );
  }
#endif
}


} // namespace cfg
} // namespace mcsema
