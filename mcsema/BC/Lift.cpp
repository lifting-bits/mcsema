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
#include <llvm/IR/InstIterator.h>
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

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Callback.h"
#include "mcsema/BC/External.h"
#include "mcsema/BC/Function.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Segment.h"
#include "mcsema/BC/Util.h"
#include "mcsema/CFG/CFG.h"

namespace mcsema {
namespace {

// Add entrypoint functions for any exported functions.
static void ExportFunction(const NativeModule *cfg_module) {
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
    auto var = gModule->getNamedAlias(cfg_var->lifted_name);
    CHECK(var != nullptr)
        << "Cannot find lifted version of exported variable "
        << cfg_var->name;

    var->setName(cfg_var->name);
    var->setLinkage(llvm::GlobalValue::ExternalLinkage);
  }
}

}  // namespace

bool LiftCodeIntoModule(const NativeModule *cfg_module) {
  DeclareExternals(cfg_module);
  DeclareLiftedFunctions(cfg_module);

  // Segments are inserted after the lifted function declarations are added
  // so that cross-references to lifted code are handled.
  AddDataSegments(cfg_module);

  if (!DefineLiftedFunctions(cfg_module)) {
    return false;
  }

  ExportFunction(cfg_module);
  ExportVariables(cfg_module);
  CallInitFiniCode(cfg_module);
  OptimizeModule();
  return true;
}

}  // namespace mcsema
