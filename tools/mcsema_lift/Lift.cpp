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

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>
#include <remill/BC/Version.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"

#ifndef LLVM_VERSION_STRING
# define LLVM_VERSION_STRING LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR
#endif

#ifndef MCSEMA_VERSION_STRING
# define MCSEMA_VERSION_STRING "unknown"
#endif  // MCSEMA_VERSION_STRING

#ifndef MCSEMA_BRANCH_NAME
# define MCSEMA_BRANCH_NAME "unknown"
#endif  // MCSEMA_BRANCH_NAME

DECLARE_string(arch);
DECLARE_string(os);

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

DEFINE_string(output, "", "Output bitcode file name.");

DECLARE_bool(version);
DEFINE_bool(dump_cfg, false, "Dump the CFG contents to screen.");

namespace {

static void PrintVersion(void) {
  std::cout
      << "This is mcsema-lift version: " << MCSEMA_VERSION_STRING << std::endl
      << "Built from branch: " << MCSEMA_BRANCH_NAME << std::endl
      << "Using LLVM " << LLVM_VERSION_STRING << std::endl;
}

static void DumpCFG(const mcsema::NativeModule *native_module) {
  std::ios::fmtflags original_stream_flags(std::cout.flags());

  // print the header on stderr so that the user can easily pipe the output to grep/awk
  std::cerr << "Type Attr Address          Blocks   Instrs   Name\n";

  for (const auto &pair : native_module->ea_to_func) {
    std::uint64_t virtual_address = pair.first;
    const auto *native_func = pair.second;

    std::cout << "FUNC " << (native_func->is_external ? "EXT  " : "INT  ");
    std::cout << std::hex << std::setfill('0') << std::setw(16) << virtual_address << " ";

    if (native_func->is_external) {
        std::cout << std::setfill(' ') << std::setw(8) << "NA" << " ";
        std::cout << std::setfill(' ') << std::setw(8) << "NA" << " ";
    } else {
      std::size_t basic_block_count = 0;
      std::size_t instruction_count = 0;

      for (const auto &address_block_pair : native_func->blocks) {
        ++basic_block_count;
        instruction_count += address_block_pair.second->instructions.size();
      }

      std::cout << std::dec << std::setfill('0') << std::setw(8) << basic_block_count << " ";
      std::cout << std::dec << std::setfill('0') << std::setw(8) << instruction_count << " ";
    }

    std::cout << (native_func->name.empty() ? native_func->lifted_name : native_func->name) << "\n";
  }

  for (const auto &pair : native_module->ea_to_var) {
    std::uint64_t virtual_address = pair.first;
    const auto &native_var = pair.second;

    std::cout << "VAR  " << (native_var->is_external ? "EXT  " : "INT  ");
    std::cout << std::hex << std::setfill('0') << std::setw(16) << virtual_address << " ";

    std::cout << std::setfill(' ') << std::setw(8) << "NA" << " ";
    std::cout << std::setfill(' ') << std::setw(8) << "NA" << " ";

    std::cout << (native_var->name.empty() ? native_var->lifted_name : native_var->name) << "\n";
  }
  std::cout << std::endl;

  // make sure we don't leave the stream in a bad state
  std::cout.flags(original_stream_flags);
}

}  // namespace

int main(int argc, char *argv[]) {
  std::stringstream ss;
  ss << std::endl << std::endl
     << "  " << argv[0] << " \\" << std::endl
     << "    --output OUTPUT_BC_FILE \\" << std::endl
     << "    --arch ARCH_NAME \\" << std::endl
     << "    --os OS_NAME \\" << std::endl
     << "    --cfg CFG_FILE \\" << std::endl
     << "    [--dump_cfg] \\" << std::endl
     << "    [--version]" << std::endl
     << std::endl;

  google::InitGoogleLogging(argv[0]);
  google::SetUsageMessage(ss.str());
  google::ParseCommandLineFlags(&argc, &argv, true);

  if (FLAGS_version) {
    PrintVersion();
    return EXIT_SUCCESS;
  }

  CHECK(!FLAGS_os.empty())
      << "Must specify an operating system name to --os.";

  CHECK(!FLAGS_arch.empty())
      << "Must specify a machine code architecture name to --arch.";

  CHECK(!FLAGS_cfg.empty())
      << "Must specify the path to a CFG file to --cfg.";

  CHECK(FLAGS_dump_cfg && FLAGS_output.empty() || !FLAGS_dump_cfg && !FLAGS_output.empty())
      << "Must either specify the bitcode output path (--output) or the --dump_cfg parameter.";

  mcsema::gContext = new llvm::LLVMContext;

  CHECK(mcsema::InitArch(FLAGS_os, FLAGS_arch))
      << "Cannot initialize for arch " << FLAGS_arch
      << " and OS " << FLAGS_os << std::endl;

  auto cfg_module = mcsema::ReadProtoBuf(FLAGS_cfg);
  if (FLAGS_dump_cfg) {
    DumpCFG(cfg_module);
    return EXIT_SUCCESS;
  }

  auto input = remill::FindSemanticsBitcodeFile("", FLAGS_arch);
  mcsema::gModule = remill::LoadModuleFromFile(mcsema::gContext, input);
  mcsema::gArch->PrepareModule(mcsema::gModule);

  CHECK(mcsema::LiftCodeIntoModule(cfg_module))
      << "Unable to lift CFG from " << FLAGS_cfg << " into module "
      << FLAGS_output;

  remill::StoreModuleToFile(mcsema::gModule, FLAGS_output);
  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();

  return EXIT_SUCCESS;
}
