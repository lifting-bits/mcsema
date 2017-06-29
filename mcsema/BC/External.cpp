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

#include "mcsema/BC/Callback.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace {

static void DeclareExternal(const NativeExternalFunction *cfg_func) {
  //get(Type *Result, ArrayRef<Type*> Params, bool isVarArg)
  //std::vector<llvm::Type *> params;
  //for(int i = 0; i < cfg_func->num_args; i++)
  //  params.push_back(llvm::Type::getVoidTy(*gContext));
  auto func_type = llvm::FunctionType::get(
      //llvm::Type::getVoidTy(*gContext), params, true);
      llvm::Type::getVoidTy(*gContext), true);

  auto func = llvm::Function::Create(
      func_type, llvm::GlobalValue::ExternalLinkage,
      cfg_func->name, gModule);

  if (cfg_func->is_weak) {
    func->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
  }

  //func->setCallingConv(llvm::CallingConv::McSemaCall);
}

}  // namespace

// Declare external functions.
//
// TODO(pag): Calling conventions, argument counts, etc.
void DeclareExternals(const NativeModule *cfg_module) {
  for (const auto &entry : cfg_module->name_to_extern_func) {
    auto cfg_func = reinterpret_cast<const NativeExternalFunction *>(
        entry.second->Get());

    CHECK(cfg_func->is_external)
        << "Trying to declare function " << cfg_func->name << " as external.";

    CHECK(cfg_func->name != cfg_func->lifted_name);

    // The "actual" external function.
    if (!gModule->getFunction(cfg_func->name)) {
      LOG(INFO)
          << "Adding external function " << cfg_func->name;
      DeclareExternal(cfg_func);
    }
  }

  // Declare external variables.
  for (const auto &entry : cfg_module->name_to_extern_var) {
    auto cfg_var = reinterpret_cast<const NativeExternalVariable *>(
        entry.second->Get());

    if (!gModule->getGlobalVariable(cfg_var->name)) {
      LOG(INFO)
          << "Adding external variable " << cfg_var->name;

      auto var_type = llvm::Type::getIntNTy(
          *gContext, static_cast<unsigned>(cfg_var->size * 8));

      (void) new llvm::GlobalVariable(
          *gModule, var_type, false, llvm::GlobalValue::ExternalLinkage,
          nullptr, cfg_var->name);
    }
  }
}

}  // namespace mcsema
