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

#pragma once

#include <llvm/IR/IRBuilder.h>

#include <cstdint>
#include <list>
#include <vector>

#include "mcsema/CFG/CFG.h"

namespace llvm {

class BasicBlock;
class Constant;
class ConstantInt;
class Instruction;
class IntegerType;
class LLVMContext;
class Module;

}  // namespace llvm
namespace mcsema {

struct NativeSegment;

extern std::shared_ptr<llvm::LLVMContext> gContext;
extern llvm::IntegerType *gWordType;
extern std::unique_ptr<llvm::Module> gModule;
extern llvm::Constant *gZero;
extern uint64_t gWordMask;

llvm::Value *GetConstantInt(unsigned size, uint64_t value);

// Get a lifted representation of a reference (in code) to `ea`.
llvm::Constant *LiftXrefInCode(uint64_t ea);

// Get a lifted representation of a reference (in data) to `ea`.
llvm::Constant *LiftXrefInData(const NativeSegment *cfg_seg, uint64_t ea,
                               bool cast_to_int = true);

// Create a global register state pointer to pass to lifted functions.
llvm::Constant *GetStatePointer(void);

// Return the address of the base of the TLS data.
llvm::Value *GetTLSBaseAddress(llvm::IRBuilder<> &ir);

}  // namespace mcsema
