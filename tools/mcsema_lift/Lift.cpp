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
#include <remill/BC/Annotate.h>
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

// Using ',' as it will work well enough on Windows and Linux
// Other suggestions were ':', which is a path character on Windows
// and ';', which is an end of statement escape on Linux shells
static const char kPathDelimeter = ',';
DEFINE_string(abi_libraries, "", "Path to one or more bitcode files that contain "
                               "external library definitions for the C/C++ ABI.");

DECLARE_bool(version);

DECLARE_bool(disable_optimizer);
DECLARE_bool(keep_memops);
DECLARE_bool(explicit_args);
DECLARE_string(pc_annotation);
DECLARE_uint64(explicit_args_count);

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
  remill::ForEachISel(mcsema::gModule.get(),
                      [=](llvm::GlobalVariable *isel, llvm::Function *) {
                        std::cout << isel->getName().str() << std::endl;
                      });
}

// simple function to split a string on a delimeter
// used to separate comma separated arguments
static std::vector<std::string> Split(const std::string &s, const char delim) {

	std::vector<std::string> res;
	std::string rem;
	std::istringstream instream(s);

	while(std::getline(instream, rem, delim)) {
		res.push_back(rem);
	}

	return res;
}

#define _S(x) #x
#define S(x) _S(x)
#define MAJOR_MINOR S(LLVM_VERSION_MAJOR) "." S(LLVM_VERSION_MINOR)


struct Options {
  bool explicit_args;
  uint64_t explicit_args_count;
};

struct ABILibsLoader {

  llvm::Module &module;
  llvm::LLVMContext &ctx;

  Options opts;

  static constexpr const char * g_var_kind = "mcsema.abi.libraries";

  std::array<std::string, 3> abi_search_paths = {
    // TODO(pag): Use build and CMake install dirs to find the libraries too.
    "/usr/local/share/mcsema/" MAJOR_MINOR "/ABI/",
    "/usr/share/mcsema/" MAJOR_MINOR "/ABI/",
    "/share/mcsema/" MAJOR_MINOR "/ABI/",
  };

  ABILibsLoader(llvm::Module &module_, const Options &opts_)
    : module(module_),
      ctx(module.getContext()),
      opts(opts_)
  {}

  bool IsBlacklisted(const llvm::Function &func) {
    auto func_name = func.getName();
    if (func_name.startswith("__mcsema")
        || func_name.startswith("__remill")) {
      return true;
    }

    if (!func.hasExternalLinkage()) {
      return true;
    }

    // We simply cannot handle va_args properly yet. (Issue #599)
    if (func.isVarArg() && !opts.explicit_args) {
        LOG(WARNING) << "Skipped " << func.getName().str()
                     << ": va_args. (See Issue #599)";
        return true;
    }

    // There are some problems related to native <-> lifted synchronization
    // without explicit args and function ptrs (entrypoint behaviour)
    if (!FLAGS_explicit_args) {
      if (HasFunctionPtrArg(func)) {
        LOG(WARNING) << "Skipped " << func.getName().str()
                     << ": function pointer in arguments. (See Issue #599)";
        return true;
      }
    }

    return false;
  }

  void Load(const std::string &paths, char delim) {
    Load( Split(FLAGS_abi_libraries, kPathDelimeter) );
  }

  void Load(const std::string &path) {
      LOG(INFO) << "Loading ABI Library: " << path;
      LoadLibraryIntoModule(path);
  }

  void Load(const std::vector<std::string> &files) {
    for (auto file : files) {
      Load(file);
    }
  }

  // Note(lukas): Not sure, which util file this belongs to
  bool HasFunctionPtrArg(const llvm::Function &func) {
    for (auto &arg : func.args()) {

      auto ptr = llvm::dyn_cast<llvm::PointerType>(arg.getType());
      if(!ptr || !ptr->getElementType()->isFunctionTy()) {
        return true;
      }
    }
    return false;
  }


  // Copy function into module with `name` as it's name (useful if there are aliases)
  void Copy(llvm::Function &func, llvm::FunctionType *fn_t, const std::string &name) {

    auto dest_func = llvm::Function::Create(fn_t, func.getLinkage(),
                                            name, &module);

    dest_func->copyAttributesFrom(&func);
    dest_func->setVisibility(func.getVisibility());

    remill::Annotate<remill::AbiLibraries>(dest_func);
  }


  bool ShouldCopy(llvm::Function &func, const std::string &name) {
    return !mcsema::gModule->getFunction(name) && !IsBlacklisted(func) && name != "main";
  }

  // If function is variadic, mcsema uses generic prototype in form
  // i64 (*)(i64 x explicit_args_count)
  // This however throws away real return type, which this function preserves.
  llvm::FunctionType *GetFnType(llvm::Function &func, llvm::LLVMContext &ctx) {
    if (!func.isVarArg())
      return func.getFunctionType();

    auto ret_type = func.getReturnType();
    auto old_type = func.getFunctionType();

    std::vector<llvm::Type *> args = { old_type->param_begin(), old_type->param_end() };
    while (args.size() < opts.explicit_args_count)
      args.push_back( llvm::Type::getInt64Ty( ctx ) );

    return llvm::FunctionType::get(ret_type, args, false);

  }

  void CloneFunction(llvm::Function &func, const std::string &name="") {

    auto new_name = (name.empty()) ? func.getName().str() : name;

    if (!ShouldCopy(func, new_name)) {
      return;
    }

    auto new_type = GetFnType(func, module.getContext());
    Copy(func, new_type, new_name);
  }

  template<typename C>
  std::unique_ptr<llvm::Module> LoadABILib(const std::string &path,
                                           const C &search_paths) {

    std::unique_ptr<llvm::Module> abi_lib(remill::LoadModuleFromFile(&ctx, path, true));
    if (abi_lib) {
      return abi_lib;
    }

    // Go searching for a library.
    for (auto base_path : search_paths) {
      std::stringstream ss;
      ss <<  base_path << FLAGS_os << "/ABI_" << path << "_"
         << FLAGS_arch << ".bc";

      const auto inferred_path = ss.str();
      abi_lib = remill::LoadModuleFromFile(&ctx, inferred_path, true);
      if (abi_lib) {
        return abi_lib;
      }
    }

    return {};
  }


  // Load in a separate bitcode or IR library, and copy function and variable
  // declarations from that library into our module. We can use this feature
  // to provide better type information to McSema.
  void LoadLibraryIntoModule(const std::string &path) {

    auto abi_lib = LoadABILib(path, abi_search_paths);
    LOG_IF(FATAL, !abi_lib)
        << "Could not load ABI library " << path;

    mcsema::gArch->PrepareModuleDataLayout(abi_lib);

    // Declare the functions from the library in McSema's target module.
    for (auto &func : *abi_lib) {
      CloneFunction(func);
    }

    for (auto &alias : abi_lib->aliases()) {
      if (auto fn = llvm::dyn_cast<llvm::Function>(alias.getAliasee())) {
        CloneFunction(*fn, alias.getName());
      }
    }

    // Declare the global variables from the library in McSema's target module.
    for (auto &var : abi_lib->globals()) {
      auto var_name = var.getName();
      if (var_name.startswith("__mcsema") || var_name.startswith("__remill")) {
        continue;
      }

      if (!var.hasExternalLinkage()) {
        continue;
      }

      if (module.getGlobalVariable(var_name)) {
        continue;
      }


      auto dest_var = new llvm::GlobalVariable(
          module, var.getType()->getElementType(),
          var.isConstant(), var.getLinkage(), nullptr,
          var_name, nullptr, var.getThreadLocalMode(),
          var.getType()->getAddressSpace());

      dest_var->copyAttributesFrom(&var);
      auto node = llvm::MDNode::get(ctx, llvm::MDString::get(ctx, path));
      dest_var->setMetadata(g_var_kind, node);
    }
  }

  void RemoveUnused() {
    UnloadLibraryFromModule(module);
  }

  // Remove unused functions and globals brought in from the library.
  void UnloadLibraryFromModule(llvm::Module &module) {

    auto copied_funcs = remill::GetFunctionsByOrigin<
      std::vector<llvm::Function *>,remill::AbiLibraries>(module);
    for (auto func : copied_funcs) {
      if (!func->hasNUsesOrMore(1))
        func->eraseFromParent();
    }

    for (auto &var : module.globals()) {
      auto md = var.getMetadata(g_var_kind);
      if (!md) {
        continue;
      }

      if (var.hasName() && var.getName().startswith("llvm.global")) {
        continue;
      }

      if (!var.hasNUsesOrMore(1)) {
        var.eraseFromParent();
      }
    }
  }


};

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

     // McSema doesn't have type information about externals, and so it assumes all
     // externals operate on integer-typed arguments, and return integer values.
     // This is wrong in many ways, but tends to work out about 80% of the time.
     // To get McSema better information about externals, one should create a
     // C or C++ file with the declarations of the externals (perhaps by
     // `#include`ing standard headers). Then, should add to this file something
     // like:
     //         __attribute__((used))
     //         void *__mcsema_externs[] = {
     //           (void *) external_func_name_1,
     //           (void *) external_func_name_2,
     //           ...
     //         };
     // And compile this file to bitcode using `remill-clang-M.m` (Major.minor).
     // This bitcode file will then be the source of type information for
     // McSema.
     //
     // One may want multiple such files, such as one for libc, one for exception
     // handling and one for zlib, and so on. McSema supports loading multiple
     // ABI library definitions via a ';' separated list of paths
     << "    [--abi_libraries BITCODE_FILE[" << kPathDelimeter <<
        "BITCODE_FILE" << kPathDelimeter << "...] ] \\" << std::endl

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

     // Assign the personality function for exception handling ABIs. It is
     // `__gxx_personality_v0` for libstdc++ and `__gnat_personality_v0` for ADA ABIs.
     << "    [--exception_personality_func]" << std::endl

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

  if (FLAGS_os.empty() || FLAGS_arch.empty() || FLAGS_cfg.empty()){
    std::cout << google::ProgramUsage() << std::endl;
    return EXIT_FAILURE;
  }

  CHECK(!FLAGS_os.empty())
      << "Must specify an operating system name to --os.";

  CHECK(!FLAGS_arch.empty())
      << "Must specify a machine code architecture name to --arch.";

  CHECK(!FLAGS_cfg.empty())
      << "Must specify the path to a CFG file to --cfg.";

  mcsema::gContext = std::make_shared<llvm::LLVMContext>();

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

  mcsema::gModule = remill::LoadTargetSemantics(*mcsema::gContext);
  mcsema::gArch->PrepareModule(mcsema::gModule.get());

  // Load in a special library before CFG processing. This affects the
  // renaming of exported functions.
  ABILibsLoader abi_loader(*mcsema::gModule, {FLAGS_explicit_args, FLAGS_explicit_args_count});
  abi_loader.Load(FLAGS_abi_libraries, kPathDelimeter);

  auto cfg_module = mcsema::ReadProtoBuf(FLAGS_cfg, (mcsema::gArch->address_size / 8));

  if (FLAGS_list_supported) {
    PrintSupportedInstructions();
  }

  CHECK(mcsema::LiftCodeIntoModule(cfg_module))
      << "Unable to lift CFG from " << FLAGS_cfg << " into module "
      << FLAGS_output;

  abi_loader.RemoveUnused();

  remill::StoreModuleToFile(mcsema::gModule.get(), FLAGS_output);

  google::ShutDownCommandLineFlags();
  google::ShutdownGoogleLogging();

  return EXIT_SUCCESS;
}
