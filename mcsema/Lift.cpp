/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <iostream>
#include <string>
#include <sstream>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>

#include <remill/Arch/Arch.h>
#include <remill/BC/Util.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"

#ifndef MCSEMA_OS
# if defined(__APPLE__)
#   define MCSEMA_OS "mac"
# elif defined(__linux__)
#   define MCSEMA_OS "linux"
# endif
#endif

#ifndef MCSEMA_VERSION_STRING
# define MCSEMA_VERSION_STRING "unknown"
#endif  // MCSEMA_VERSION_STRING

#ifndef MCSEMA_BRANCH_NAME
# define MCSEMA_BRANCH_NAME "unknown"
#endif  // MCSEMA_BRANCH_NAME

DEFINE_string(arch, "", "Architecture of the code being translated. "
                         "Valid architectures: x86, amd64 (with or without "
                         "`_avx` or `_avx512` appended).");

DEFINE_string(os, MCSEMA_OS, "Source OS. Valid OSes: linux, mac.");

DEFINE_string(cfg, "", "Path to the CFG file containing code to lift.");

DEFINE_string(output, "", "Output bitcode file name.");

DECLARE_bool(version);

namespace {

static void PrintVersion(void) {
  std::cout
      << "This is mcsema-lift version: " << MCSEMA_VERSION_STRING << std::endl
      << "Built from branch: " << MCSEMA_BRANCH_NAME << std::endl;
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

  CHECK(!FLAGS_output.empty())
      << "Must specify the lifted bitcode output path to --output.";

  mcsema::gContext = new llvm::LLVMContext;

  CHECK(mcsema::InitArch(FLAGS_os, FLAGS_arch))
      << "Cannot initialize for arch " << FLAGS_arch
      << " and OS " << FLAGS_os << std::endl;

  auto input = remill::FindSemanticsBitcodeFile("", FLAGS_arch);
  mcsema::gModule = remill::LoadModuleFromFile(mcsema::gContext, input);
  mcsema::gArch->PrepareModule(mcsema::gModule);

  auto cfg_module = mcsema::ReadProtoBuf(FLAGS_cfg);
  mcsema::ArchInitAttachDetach();

  CHECK(mcsema::LiftCodeIntoModule(cfg_module))
      << "Unable to lift CFG from " << FLAGS_cfg << " into module "
      << FLAGS_output;

  remill::StoreModuleToFile(mcsema::gModule, FLAGS_output);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();

  return EXIT_SUCCESS;
}
