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

DECLARE_bool(disable_optimizer);
DECLARE_bool(keep_memops);
DECLARE_bool(explicit_args);
DECLARE_string(pc_annotation);

DEFINE_bool(legacy_mode, false,
            "Try to make the output bitcode resemble the original McSema.");

namespace {

static void PrintVersion(void) {
  std::cout
      << "This is mcsema-lift version: " << MCSEMA_VERSION_STRING << std::endl
      << "Built from branch: " << MCSEMA_BRANCH_NAME << std::endl
      << "Using LLVM " << LLVM_VERSION_STRING << std::endl;
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

  mcsema::gContext = new llvm::LLVMContext;

  CHECK(mcsema::InitArch(FLAGS_os, FLAGS_arch))
      << "Cannot initialize for arch " << FLAGS_arch
      << " and OS " << FLAGS_os << std::endl;

  if (FLAGS_legacy_mode) {
    LOG_IF(WARNING, FLAGS_keep_memops)
        << "Disabling --keep_memops in legacy mode.";
    FLAGS_keep_memops = false;

    LOG_IF(WARNING, !FLAGS_explicit_args)
        << "Enabling --explicit_args in legacy mode.";
    FLAGS_explicit_args = true;

    LOG_IF(WARNING, !FLAGS_pc_annotation.empty())
        << "Changing --pc_annotation to mcsema_real_eip in legacy mode.";
    FLAGS_pc_annotation = "mcsema_real_eip";

    LOG_IF(WARNING, FLAGS_disable_optimizer)
        << "Re-enabling the optimizer in legacy mode.";
    FLAGS_disable_optimizer = false;
  }

  auto cfg_module = mcsema::ReadProtoBuf(
      FLAGS_cfg, (mcsema::gArch->address_size / 8));
  auto input = remill::FindSemanticsBitcodeFile(FLAGS_arch);
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
