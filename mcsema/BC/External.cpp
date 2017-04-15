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

#include <sstream>
#include <vector>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/BC/External.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace {

static void MakeExternal(llvm::Constant *val) {
  llvm::dyn_cast<llvm::GlobalValue>(val)->setLinkage(
      llvm::GlobalValue::ExternalLinkage);
}

}  // namespace

void DeclareExternals(const NativeModule *cfg_module) {
  auto lifted_func_type = LiftedFunctionType();

  // TODO(pag): Use the info from the CFG proto.
  auto func_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(*gContext), true);

  // Declare external functions.
  //
  // TODO(pag): Calling conventions, argument counts, etc.
  for (const auto &entry : cfg_module->name_to_extern_func) {
    auto cfg_func = reinterpret_cast<const NativeExternalFunction *>(
        entry.second->Get());

    // The "actual" external function.
    auto func = llvm::dyn_cast<llvm::Function>(
        gModule->getOrInsertFunction(cfg_func->name, func_type) \
            ->stripPointerCasts());
    MakeExternal(func);

    if (cfg_func->is_weak) {
      CHECK(cfg_func->name == cfg_func->lifted_name);
      func->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);

    } else {
      CHECK(cfg_func->name != cfg_func->lifted_name);

      // Stub that will marshal lifted state into the native state.
        gModule->getOrInsertFunction(cfg_func->lifted_name, lifted_func_type);

        LOG(INFO)
            << "Adding external " << cfg_func->name << " implemented by thunk "
            << cfg_func->lifted_name;
    }
  }

  // Declare external variables.
  for (const auto &entry : cfg_module->name_to_extern_var) {
    auto cfg_var = reinterpret_cast<const NativeExternalVariable *>(
        entry.second->Get());
    auto var_type = llvm::Type::getIntNTy(*gContext, cfg_var->size * 8);
    MakeExternal(gModule->getOrInsertGlobal(cfg_var->name, var_type));
  }
}

}  // namespace mcsema
