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
  auto func_type = llvm::FunctionType::get(
      llvm::Type::getVoidTy(*gContext), true);

  // Declare external functions.
  //
  // TODO(pag): Calling conventions, argument counts, etc.
  for (const auto &entry : cfg_module->name_to_extern_func) {
    auto cfg_func = entry.second;

    // The "actual" external function.
    MakeExternal(gModule->getOrInsertFunction(cfg_func->name, func_type));

    // Stub that will marshal lifted state into the native state.
    gModule->getOrInsertFunction(cfg_func->lifted_name, LiftedFunctionType());
  }

  // Declare external variables.
  for (const auto &entry : cfg_module->name_to_extern_var) {
    auto cfg_var = entry.second;
    auto var_type = llvm::Type::getIntNTy(*gContext, cfg_var->size * 8);
    MakeExternal(gModule->getOrInsertGlobal(cfg_var->name, var_type));
  }
}

}  // namespace mcsema
