/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <glog/logging.h>
#include <gflags/gflags.h>

#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>

#include "mcsema/CFG/CFG.h"

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

namespace {

static void DumpCFG(const mcsema::NativeModule *native_module) {
  std::ios::fmtflags original_stream_flags(std::cout.flags());

  // Print the header on stderr so that the user can easily pipe the
  // output to grep/awk.
  std::cerr
      << "Type Attr Address          Blocks   Instrs   Name\n";

  for (const auto &pair : native_module->ea_to_func) {
    std::uint64_t virtual_address = pair.first;
    const auto *native_func = pair.second;

    std::cout
        << "FUNC " << (native_func->is_external ? "EXT  " : "INT  ")
        << std::hex << std::setfill('0') << std::setw(16)
        << virtual_address << " ";

    if (native_func->is_external) {
        std::cout
            << std::setfill(' ') << std::setw(8) << "NA" << " "
            << std::setfill(' ') << std::setw(8) << "NA" << " ";
    } else {
      std::size_t basic_block_count = 0;
      std::size_t instruction_count = 0;

      for (const auto &address_block_pair : native_func->blocks) {
        ++basic_block_count;
        instruction_count += address_block_pair.second->instructions.size();
      }

      std::cout
          << std::dec << std::setfill('0') << std::setw(8)
          << basic_block_count << " " << std::dec << std::setfill('0')
          << std::setw(8) << instruction_count << " ";
    }

    if (native_func->name.empty()) {
      std::cout << native_func->lifted_name;
    } else {
      std::cout << native_func->lifted_name;
    }

    std::cout << std::endl;
  }

  for (const auto &pair : native_module->ea_to_var) {
    std::uint64_t virtual_address = pair.first;
    const auto &native_var = pair.second;

    std::cout
        << "VAR  " << (native_var->is_external ? "EXT  " : "INT  ")
        << std::hex << std::setfill('0') << std::setw(16) << virtual_address
        << " " << std::setfill(' ') << std::setw(8) << "NA" << " "
        << std::setfill(' ') << std::setw(8) << "NA" << " ";

    if (native_var->name.empty()) {
      std::cout << native_var->lifted_name;
    } else {
      std::cout << native_var->lifted_name;
    }

    std::cout << std::endl;
  }
  std::cout << std::endl;

  // Make sure we don't leave the stream in a bad state.
  std::cout.flags(original_stream_flags);
}

}  // namespace

// TODO(pag): Support more output formats, e.g. DT digraphs for function
//            control-flow graphs, or for call graphs, or perhaps things
//            somehow related to cross-references.
int main(int argc, char *argv[]) {
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --cfg CFG_FILE \\" << std::endl
     << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);
  DumpCFG(mcsema::ReadProtoBuf(FLAGS_cfg, 8 /* pointer_size */));
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();

  return EXIT_SUCCESS;
}
