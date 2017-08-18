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

#include <unordered_set>

#include <llvm/ADT/ArrayRef.h>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include "remill/Arch/Arch.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

namespace mcsema {

const remill::Arch *gArch = nullptr;

bool InitArch(const std::string &os, const std::string &arch) {
  LOG(INFO)
      << "Initializing for " << arch << " code on " << os;

  gArch = remill::GetTargetArch();
  gWordType = llvm::Type::getIntNTy(
      *gContext, static_cast<unsigned>(gArch->address_size));
  return true;
}

}  // namespace mcsema
