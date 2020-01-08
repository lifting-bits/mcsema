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

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"
#include "remill/BC/ABI.h"
#include "remill/BC/IntrinsicTable.h"
#include "remill/BC/Lifter.h"
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Function.h"
#include "mcsema/BC/Legacy.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

DECLARE_bool(legacy_mode);
DECLARE_bool(explicit_args);
DECLARE_string(pc_annotation);

namespace mcsema {
namespace {

// Add entrypoint functions for any exported functions.
static void ExportFunctions(const NativeModule *cfg_module) {
  for (auto ea : cfg_module->exported_funcs) {
    auto cfg_func = cfg_module->ea_to_func.at(ea)->Get();
    CHECK(gModule->getFunction(cfg_func->lifted_name) != nullptr)
        << "Cannot find lifted version of exported function "
        << cfg_func->lifted_name;

    LOG(INFO)
        << "Exporting function " << cfg_func->name;

    auto ep = GetNativeToLiftedEntryPoint(cfg_func);
    ep->setLinkage(llvm::GlobalValue::ExternalLinkage);
    ep->setVisibility(llvm::GlobalValue::DefaultVisibility);
  }
}

// Export any variables that should be externally visible. This will rename
// the lifted variable names to have their original names.
static void ExportVariables(const NativeModule *cfg_module) {
  for (auto ea : cfg_module->exported_vars) {
    auto cfg_var = cfg_module->ea_to_var.at(ea)->Get();
    auto var = gModule->getGlobalVariable(cfg_var->lifted_name);
    CHECK(var != nullptr)
        << "Cannot find lifted version of exported variable "
        << cfg_var->name;

    var->setName(cfg_var->name);
    var->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }
}

// Handle the GCC stack protector. Normally we'd do this in `External.cpp`,
// but it seems like optimizing a global that is `AvailableExternallyLinkage`
// with an initializer somewhere in the code (in our case, a `LazyInitXref`),
// results in the linkage being changed to `ExternalLinkage`. We want
// `AvailableExternallyLinkage` for the sake of something like KLEE.
static void DefineGCCStackGuard(void) {
  if (auto stack_guard = gModule->getGlobalVariable("__stack_chk_guard")) {
    stack_guard->setInitializer(
        llvm::Constant::getNullValue(stack_guard->getType()->getElementType()));
    stack_guard->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
  }
}

// Define the function `__mcsema_debug_get_reg_state`. Normally this is part of
// the McSema runtime, but if we are lifting with `--explicit_args`, and are
// also compiling the lifted bitcode back to native, then we may not use the
// runtime and so might not have this useful debugging function available to us.
static void DefineDebugGetRegState(void) {
  auto get_reg_state = gModule->getFunction("__mcsema_debug_get_reg_state");
  if (get_reg_state) {
    return;
  }

  auto reg_state = gModule->getGlobalVariable("__mcsema_reg_state", true);
  if (!reg_state) {
    return;
  }

  auto state_ptr_type = reg_state->getType();
  auto reg_func_type = llvm::FunctionType::get(state_ptr_type, false);
  // ExternalWeakLinkage causes crash with --explicit_args. The function is not available in the library
  get_reg_state = llvm::Function::Create(
      reg_func_type, llvm::GlobalValue::ExternalLinkage,
      "__mcsema_debug_get_reg_state", gModule);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", get_reg_state));
  ir.CreateRet(reg_state);

  get_reg_state->addFnAttr(llvm::Attribute::NoInline);
  get_reg_state->addFnAttr(llvm::Attribute::OptimizeNone);
}

// Define some of the remill error intrinsics.
static void DefineErrorIntrinsics(llvm::FunctionType *lifted_func_type) {
  const char *func_names[] = {"__remill_error", "__remill_missing_block"};
  auto trap = llvm::Intrinsic::getDeclaration(gModule, llvm::Intrinsic::trap);
  for (auto func_name : func_names) {
    auto func = gModule->getFunction(func_name);
    if (!func) {
      continue;
    }
    if (func->isDeclaration()) {
      llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));
      ir.CreateCall(trap);
      ir.CreateUnreachable();
    }
  }
}

}  // namespace

bool LiftCodeIntoModule(const NativeModule *cfg_module) {

  DeclareExternals(cfg_module);
  DeclareLiftedFunctions(cfg_module);

  DeclareDataSegments(cfg_module);

  // Segments are only filled in after the lifted function declarations,
  // external vars, and segments are declared so that cross-references to
  // lifted things can be resolved.
  DefineDataSegments(cfg_module);

  auto lifted_func_type = remill::LiftedFunctionType(gModule);

  // Lift the blocks of instructions into the declared functions.
  if (!DefineLiftedFunctions(cfg_module)) {
    return false;
  }

  // Add entrypoint functions for any exported functions.
  ExportFunctions(cfg_module);

  // Export any variables that should be externally visible.
  ExportVariables(cfg_module);

  // Generate code to call pre-`main` function static object constructors, and
  // post-`main` functions destructors.
  CallInitFiniCode(cfg_module);

  if (FLAGS_legacy_mode) {
    legacy::DowngradeModule();
  }

  OptimizeModule();

  if (FLAGS_explicit_args) {
    DefineGCCStackGuard();
    DefineDebugGetRegState();
    DefineErrorIntrinsics(lifted_func_type);
  }

  if (!FLAGS_pc_annotation.empty()) {
    legacy::PropagateInstAnnotations();
  }

  return true;
}

}  // namespace mcsema
