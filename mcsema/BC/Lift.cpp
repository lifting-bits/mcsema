/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "Lift.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wconversion"
#pragma clang diagnostic ignored "-Wold-style-cast"
#pragma clang diagnostic ignored "-Wdocumentation"
#pragma clang diagnostic ignored "-Wswitch-enum"
#include <gflags/gflags.h>
#include <glog/logging.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#pragma clang diagnostic pop

#include <remill/Arch/Arch.h>
#include <remill/Arch/Instruction.h>
#include <remill/BC/ABI.h>
#include <remill/BC/Annotate.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Function.h"
#include "mcsema/BC/Legacy.h"
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
  for (auto [ea, cfg_func] : cfg_module->ea_to_func) {
    (void) ea;

    if (cfg_func->function) {
      cfg_func->function = gModule->getFunction(cfg_func->name);
    }

    if (auto ep = cfg_func->function; ep) {
      if (cfg_func->is_exported) {
        LOG(INFO) << "Exporting function " << cfg_func->name;

        //    remill::TieFunctions(ep, gModule->getFunction(cfg_func->lifted_name));
        remill::Annotate<remill::EntrypointFunction>(ep);
        ep->setLinkage(llvm::GlobalValue::ExternalLinkage);
        ep->setVisibility(llvm::GlobalValue::DefaultVisibility);

      } else {
        ep->setVisibility(llvm::GlobalValue::HiddenVisibility);
        ep->setLinkage(llvm::GlobalValue::PrivateLinkage);
        if (!ep->hasNUsesOrMore(1)) {
          LOG(INFO) << "Removing function " << cfg_func->name;
          ep->eraseFromParent();
        }
      }
    }
  }
}

// Export any variables that should be externally visible. This will rename
// the lifted variable names to have their original names.
static void ExportVariables(const NativeModule *cfg_module) {
  for (auto ea : cfg_module->exported_vars) {
    auto cfg_var = cfg_module->ea_to_var.at(ea)->Get();
    auto var = gModule->getGlobalVariable(cfg_var->lifted_name);
    CHECK(var != nullptr) << "Cannot find lifted version of exported variable "
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

  // ExternalWeakLinkage causes crash with --explicit_args. The function is not
  // available in the library
  get_reg_state =
      llvm::Function::Create(reg_func_type, llvm::GlobalValue::ExternalLinkage,
                             "__mcsema_debug_get_reg_state", gModule.get());

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", get_reg_state));
  ir.CreateRet(reg_state);

  get_reg_state->addFnAttr(llvm::Attribute::NoInline);
  get_reg_state->addFnAttr(llvm::Attribute::OptimizeNone);
}

// Remove calls to error-related intrinsics.
static void ImplementErrorIntrinsic(const char *name) {
  auto func = gModule->getFunction(name);
  if (!func || !func->isDeclaration()) {
    return;
  }

  auto void_type = llvm::Type::getVoidTy(*gContext);
  auto abort_func = gModule->getFunction("abort");
  if (!abort_func) {
    abort_func = llvm::Function::Create(
        llvm::FunctionType::get(void_type, false),
        llvm::GlobalValue::ExternalLinkage, "abort", gModule.get());

    abort_func->addFnAttr(llvm::Attribute::NoReturn);

  // Might be an externally-defined function :-/
  } else if (abort_func->getFunctionType()->getNumParams() ||
             !abort_func->getFunctionType()->getReturnType()->isVoidTy()) {
    abort_func =
        llvm::Intrinsic::getDeclaration(gModule.get(), llvm::Intrinsic::trap);
  }

  func->setLinkage(llvm::GlobalValue::InternalLinkage);
  func->removeFnAttr(llvm::Attribute::NoInline);
  func->removeFnAttr(llvm::Attribute::OptimizeNone);
  func->addFnAttr(llvm::Attribute::NoReturn);
  func->addFnAttr(llvm::Attribute::InlineHint);
  func->addFnAttr(llvm::Attribute::AlwaysInline);

  llvm::IRBuilder<> ir(llvm::BasicBlock::Create(*gContext, "", func));

  ir.CreateCall(abort_func);
  ir.CreateUnreachable();
}

// Define some of the remill error intrinsics.
static void DefineErrorIntrinsics(void) {
  ImplementErrorIntrinsic("__remill_error");
  ImplementErrorIntrinsic("__remill_missing_block");
}

}  // namespace

TranslationContext::TranslationContext(void) {}

TranslationContext::~TranslationContext(void) {}

bool LiftCodeIntoModule(const NativeModule *cfg_module) {
  DeclareLiftedFunctions(cfg_module);

  // Lift the blocks of instructions into the declared functions.
  if (!DefineLiftedFunctions(cfg_module)) {
    return false;
  }

  DefineErrorIntrinsics();

  // Optimize the lifted bitcode.
  OptimizeModule(cfg_module);

  // Segments are only filled in after the lifted function declarations,
  // external vars, and segments are declared so that cross-references to
  // lifted things can be resolved.
  DefineDataSegments(cfg_module);

  // Generate code to call pre-`main` function static object constructors, and
  // post-`main` functions destructors.
  CallInitFiniCode(cfg_module);

  // Remove leftover Remill intrinsics, and lower memory access intrincis into
  // `load` and `store` instructions.
  CleanUpModule(cfg_module);

  // Add entrypoint functions for any exported functions.
  ExportFunctions(cfg_module);

  // Export any variables that should be externally visible.
  ExportVariables(cfg_module);

  if (FLAGS_explicit_args) {
    DefineGCCStackGuard();
    DefineDebugGetRegState();
  }

  if (!FLAGS_pc_annotation.empty()) {
    legacy::PropagateInstAnnotations();
  }

  MergeSegments(cfg_module);

  return true;
}

}  // namespace mcsema
