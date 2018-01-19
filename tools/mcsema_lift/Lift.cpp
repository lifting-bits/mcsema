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

#include <iomanip>
#include <iostream>
#include <memory>
#include <string>
#include <sstream>

#include <llvm/IR/Function.h>
#include <llvm/IR/GlobalVariable.h>
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

DEFINE_string(library, "", "Path to an LLVM bitcode or IR file that contains "
                           "external library definitions.");

DECLARE_bool(version);

DECLARE_bool(disable_optimizer);
DECLARE_bool(keep_memops);
DECLARE_bool(explicit_args);
DECLARE_string(pc_annotation);

DEFINE_bool(list_supported, false,
            "List instructions that can be lifted.");
DEFINE_bool(legacy_mode, false,
            "Try to make the output bitcode resemble the original McSema.");

namespace {

static void PrintVersion(void) {
  std::cout
      << "This is mcsema-lift version: " << MCSEMA_VERSION_STRING << std::endl
      << "Built from branch: " << MCSEMA_BRANCH_NAME << std::endl
      << "Using LLVM " << LLVM_VERSION_STRING << std::endl;
}

// Print a list of instructions that Remill can lift.
static void PrintSupportedInstructions(void) {
  remill::ForEachISel(mcsema::gModule,
                      [=](llvm::GlobalVariable *isel, llvm::Function *) {
                        std::cout << isel->getName().str() << std::endl;
                      });
}

static std::unique_ptr<llvm::Module> gLibrary;

// Load in a separate bitcode or IR library, and copy function and variable
// declarations from that library into our module. We can use this feature
// to provide better type information to McSema.
static void LoadLibraryIntoModule(void) {
  gLibrary.reset(remill::LoadModuleFromFile(mcsema::gContext, FLAGS_library));

  // Declare the functions from the library in McSema's target module.
  for (auto &func : *gLibrary) {
    auto func_name = func.getName();
    if (func_name.startswith("__mcsema") || func_name.startswith("__remill")) {
      continue;
    }

    if (!func.hasExternalLinkage()) {
      continue;
    }

    if (mcsema::gModule->getFunction(func_name)) {
      continue;
    }

    auto dest_func = llvm::Function::Create(
        func.getFunctionType(), func.getLinkage(),
        func_name, mcsema::gModule);

    dest_func->copyAttributesFrom(&func);
    dest_func->setVisibility(func.getVisibility());
  }

  // Declare the global variables from the library in McSema's target module.
  for (auto &var : gLibrary->globals()) {
    auto var_name = var.getName();
    if (var_name.startswith("__mcsema") || var_name.startswith("__remill")) {
      continue;
    }

    if (!var.hasExternalLinkage()) {
      continue;
    }

    if (mcsema::gModule->getGlobalVariable(var_name)) {
      continue;
    }

    auto dest_var = new llvm::GlobalVariable(
        *mcsema::gModule, var.getType()->getElementType(),
        var.isConstant(), var.getLinkage(), nullptr,
        var_name, nullptr, var.getThreadLocalMode(),
        var.getType()->getAddressSpace());

    dest_var->copyAttributesFrom(&var);
  }
}

// Remove unused functions and globals brought in from the library.
static void UnloadLibraryFromModule(void) {
  for (auto &func : *gLibrary) {
    auto our_func = mcsema::gModule->getFunction(func.getName());
    if (our_func && !our_func->hasNUsesOrMore(1)) {
      our_func->eraseFromParent();
    }
  }

  for (auto &var : gLibrary->globals()) {
    auto our_var = mcsema::gModule->getGlobalVariable(var.getName());
    if (our_var && !our_var->hasNUsesOrMore(1)) {
      our_var->eraseFromParent();
    }
  }
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

     // This option is very useful for debugging McSema-lifted bitcode. It
     // injects so-called breakpoint functions before every lifted instruction.
     // For example, the the instruction at PC `0xf00` is lifted, then this
     // option will inject a call to `breakpoint_f00`. With this feature, we
     // can add breakpoints in a debugger on these breakpoint functions, and
     // know that they correspond to locations in the original program.
     << "    [--add_breakpoints] \\" << std::endl

     // This option injects a function call before every lifted instruction.
     // This function is implemented in the McSema runtime and it prints the
     // values of the general purpose registers to `stderr`.
     << "    [--add_reg_tracer] \\" << std::endl

     // This option tells McSema not to optimize the bitcode. This is useful
     // for debugging, especially in conjunction with `--add_breakpoints`.
     << "    [--disable_optimizer] \\" << std::endl

     // This option tells McSema not to lower Remill's memory access intrinsic
     // functions into LLVM `load` and `store` instructions.
     << "    [--keep_memops] \\" << std::endl

     // There are roughly two ways of using McSema-lifted bitcode. The default
     // use case is to compile the bitcode into an executable that behaves like
     // the original program. The other use case is to do some kind of static
     // analysis, e.g. with KLEE. In this use case, calls to external functions
     // are emulated so that we also try to explicitly lift parameter passing.
     // This mode of passing arguments explicitly is enabled by
     // `--explicit_args`, and in situations where we have no knowledge of the
     // argument counts expected by an external function, we fall back on
     // passing `--explicit_args_count` number of arguments to that function.
     << "    [--explicit_args] \\" << std::endl
     << "    [--explicit_args_count NUM_ARGS_FOR_EXTERNALS] \\" << std::endl

     // This option is most useful when using `--explicit_args` (or
     // `--legacy_mode`, which enables `--explicit_args`). In general, McSema
     // doesn't have type information about externals, and so it assumes all
     // externals operate on integer-typed arguments, and return integer values.
     // This is wrong in many ways, but tends to work out about 80% of the time.
     // To get McSema better information about externals, one should create a
     // C or C++ file with the declarations of the externals (perhaps by
     // `#include`ing standard headers). Then, should add to this file something
     // like:
     //         __attribute__((used))
     //         void *__mcsema_used_funcs[] = {
     //           (void *) external_func_name_1,
     //           (void *) external_func_name_2,
     //           ...
     //         };
     // And compile this file to bitcode using `remill-clang-M.m` (Major.minor).
     // This bitcode file will then be the source of type information for
     // McSema.
     << "    [--library BITCODE_FILE] \\" << std::endl

     // Annotate each LLVM IR instruction with some metadata that includes the
     // original program counter. The name of the LLVM metadats is
     // `PC_METADATA_ID`. This is enabled by default with `--legacy_mode`,
     // which sets `--pc_annotation` to be `mcsema_real_eip`.
     << "    [--pc_annotation PC_METADATA_ID] \\" << std::endl

     // Try to produce bitcode that looks like McSema version 1. This enables
     // `--explicit_args` and `--pc_annotation`.
     << "    [--legacy_mode] \\" << std::endl
     
     // Print a list of the instructions that can be lifted.
     << "    [--list-supported]" << std::endl

     // Print the version and exit.
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
  mcsema::gModule = remill::LoadTargetSemantics(mcsema::gContext);
  mcsema::gArch->PrepareModule(mcsema::gModule);

  if (FLAGS_list_supported) {
    PrintSupportedInstructions();
  }

  if (!FLAGS_library.empty()) {
    LoadLibraryIntoModule();
  }

  CHECK(mcsema::LiftCodeIntoModule(cfg_module))
      << "Unable to lift CFG from " << FLAGS_cfg << " into module "
      << FLAGS_output;

  if (!FLAGS_library.empty()) {
    UnloadLibraryFromModule();
    gLibrary.reset(nullptr);
  }

  remill::StoreModuleToFile(mcsema::gModule, FLAGS_output);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();

  return EXIT_SUCCESS;
}
