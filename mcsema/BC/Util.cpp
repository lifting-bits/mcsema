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

#include <string>

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/MDBuilder.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "remill/Arch/Arch.h"
#include "remill/BC/Util.h"
#include "remill/BC/Version.h"

#include "mcsema/Arch/Arch.h"
#include "mcsema/BC/Util.h"

namespace mcsema {

llvm::LLVMContext *gContext = nullptr;
llvm::IntegerType *gWordType = nullptr;
llvm::Module *gModule = nullptr;

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    func_type = remill::LiftedFunctionType(gModule);
  }
  return func_type;
}

}  // namespace mcsema
