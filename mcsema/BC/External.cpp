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

#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/Arch/Name.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace {

// For an external named `external`, return a function with the prototype
// `uintptr_t external(uintptr_t arg0, uintptr_t arg1, ...);`.
//
// TODO(pag,car,artem): Handle floating point types eventually.
static void DeclareExternal(
    const NativeExternalFunction *cfg_func) {

  std::vector<llvm::Type *> tys(cfg_func->num_args, gWordType);

  auto extfun = llvm::Function::Create(
      llvm::FunctionType::get(gWordType, tys, false),
      llvm::GlobalValue::ExternalLinkage,
      cfg_func->name, gModule);

  if (cfg_func->is_weak) {
    extfun->setLinkage(llvm::GlobalValue::ExternalWeakLinkage);
  }

  extfun->setCallingConv(cfg_func->cc);
  extfun->addFnAttr(llvm::Attribute::NoInline);
}

static llvm::GlobalValue::ThreadLocalMode ThreadLocalMode(
    const NativeObject *cfg_obj) {
  if (cfg_obj->is_thread_local) {
    return llvm::GlobalValue::GeneralDynamicTLSModel;
  } else {
    return llvm::GlobalValue::NotThreadLocal;
  }
}

}  // namespace

// Declare external functions.
void DeclareExternals(const NativeModule *cfg_module) {
  for (const auto &entry : cfg_module->name_to_extern_func) {
    auto cfg_func = reinterpret_cast<const NativeExternalFunction *>(
        entry.second->Get());

    CHECK(cfg_func->is_external)
        << "Trying to declare function " << cfg_func->name << " as external.";

    CHECK_NE(cfg_func->name, cfg_func->lifted_name);

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

    auto ll_var = gModule->getGlobalVariable(cfg_var->name,
                                             true  /* AllowInternal */);
    if (!ll_var) {
      LOG(INFO)
          << "Adding external variable " << cfg_var->name;

      llvm::Type* var_type = nullptr;

      CHECK_NE(0, cfg_var->size)
          << "The size of the external variable ["
          << cfg_var->name << "] cannot be zero";

      // Handle external variables of up to 128 bits as intgers
      // Anything else is treated as an array of bytes
      switch(cfg_var->size) {
        case 0:
          // Why is this zero length? This should never happen
          // Attempt a fix and output a warning
          LOG(ERROR)
              << "The variable [" << cfg_var->name
              << "] has size of zero. Assuming it should be size 1";
          var_type = llvm::Type::getInt8Ty(*gContext);
          break;
        case 1: // 8 bit integer
        case 2: // 16 bit integer
        case 4: // 32 bit integer
        case 8: // 64 bit integer
        case 16: // 128 bit integer
          var_type = llvm::Type::getIntNTy(
            *gContext, static_cast<unsigned>(cfg_var->size * 8));
          break;
        
        // An array of bytes
        default: {
          auto byte_type = llvm::Type::getInt8Ty(*gContext);
          var_type = llvm::ArrayType::get(byte_type, static_cast<unsigned>(cfg_var->size));
          break;
        }
      }

      auto linkage = llvm::GlobalValue::ExternalLinkage;
      ll_var = new llvm::GlobalVariable(*gModule, var_type, false,
                                        linkage, nullptr, cfg_var->name,
                                        nullptr, ThreadLocalMode(cfg_var));
      if (cfg_var->ea) {
        ll_var->setAlignment(1 << __builtin_ctzl(cfg_var->ea));
      }

    // This could happen if the variable is declared as a segment variable,
    // but is not exported, and there is also another exported/imported
    // global of the same name.
    //
    // TODO(pag): Another reasonable interpretation of this is to rename the
    //            existing symbol so that the names don't clash.
    } else {
      LOG_IF(ERROR, !ll_var->hasExternalLinkage())
          << "Variable '" << cfg_var->name
          << "' is external but was not previously declared as such";

      ll_var->setLinkage(llvm::GlobalValue::ExternalLinkage);
    }

    if (!cfg_var->address) {
      cfg_var->address = llvm::ConstantExpr::getPtrToInt(ll_var, gWordType);
    }
  }
}

}  // namespace mcsema
