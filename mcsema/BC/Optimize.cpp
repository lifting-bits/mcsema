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
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Type.h>

#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils/Local.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Transforms/Utils/ValueMapper.h>

#include "mcsema/BC/Optimize.h"
#include "mcsema/BC/Util.h"

namespace mcsema {
namespace {
static void RunO3(void) {
  llvm::legacy::FunctionPassManager func_manager(gModule);
  llvm::legacy::PassManager module_manager;

  auto TLI = new llvm::TargetLibraryInfoImpl(
      llvm::Triple(gModule->getTargetTriple()));
  TLI->disableAllFunctions();

  llvm::PassManagerBuilder builder;
  builder.OptLevel = 3;
  builder.SizeLevel = 2;
  builder.Inliner = llvm::createFunctionInliningPass(100);
  builder.LibraryInfo = TLI;  // Deleted by `llvm::~PassManagerBuilder`.
  builder.DisableTailCalls = false;  // Enable tail calls.
  builder.DisableUnrollLoops = false;  // Unroll loops!
  builder.DisableUnitAtATime = false;
  builder.SLPVectorize = false;  // Don't produce vector operations.
  builder.LoopVectorize = false;  // Don't produce vector operations.
  builder.LoadCombine = false;  // Don't coalesce loads.
  builder.MergeFunctions = false;  // Try to deduplicate functions.
  builder.VerifyInput = false;
  builder.VerifyOutput = false;

  builder.populateFunctionPassManager(func_manager);
  builder.populateModulePassManager(module_manager);
  func_manager.doInitialization();
  for (auto &func : *gModule) {
    func_manager.run(func);
  }
  func_manager.doFinalization();
  module_manager.run(*gModule);
}

static std::vector<llvm::GlobalVariable *> FindISELs(void) {
  std::vector<llvm::GlobalVariable *> isels;
  auto basic_block = gModule->getFunction("__remill_basic_block");
  if (!basic_block) {
    LOG(ERROR)
        << "Not removing any ISELs or SEMs; can't find __remill_basic_block.";
    return isels;
  }

  auto lifted_func_type = basic_block->getFunctionType();
  auto mem_type = lifted_func_type->getParamType(0);
  auto state_type = lifted_func_type->getParamType(1);

  isels.reserve(gModule->size());
  for (auto &isel : gModule->globals()) {
    if (!isel.hasInitializer()) {
      continue;
    }

    auto sem = llvm::dyn_cast<llvm::Function>(
        isel.getInitializer()->stripPointerCasts());
    if (!sem) {
      continue;
    }

    auto sem_type = sem->getFunctionType();

    if (mem_type == sem_type->getParamType(0) &&
        state_type == sem_type->getParamType(1)) {
      DLOG(INFO)
          << "Found ISEL " << isel.getName().str();
      isels.push_back(&isel);
    }
  }

  return isels;
}

// Remove the ISEL variables used for finding the instruction semantics.
static void RemoveISELs(std::vector<llvm::GlobalVariable *> &isels) {
  std::vector<llvm::GlobalVariable *> next_isels;
  while (isels.size()) {
    next_isels.clear();
    for (auto isel : isels) {
      isel->setLinkage(llvm::GlobalValue::InternalLinkage);
      if (1 >= isel->getNumUses()) {
        DLOG(INFO)
            << "Removing ISEL " << isel->getName().str();
        isel->eraseFromParent();
      } else {
        next_isels.push_back(isel);
      }
    }
    isels.swap(next_isels);
  }
}

// Remove some of the remill intrinsics.
static void RemoveIntrinsics(void) {
  if (auto used = gModule->getGlobalVariable("llvm.used")) {
    used->eraseFromParent();
  }

  if (auto intrinsic_keeper = gModule->getFunction("__remill_intrinsics")) {
    intrinsic_keeper->eraseFromParent();
  }

  if (auto basic_block = gModule->getFunction("__remill_basic_block")) {
    basic_block->eraseFromParent();
  }

  if (auto mark_used = gModule->getFunction("__remill_mark_as_used")) {
    mark_used->eraseFromParent();
  }
}

}  // namespace

void OptimizeBitcode(void) {
  auto isels = FindISELs();
  RemoveIntrinsics();
  LOG(INFO)
      << "Optimizing module.";
  RemoveISELs(isels);
  RunO3();
}

}  // namespace mcsema
