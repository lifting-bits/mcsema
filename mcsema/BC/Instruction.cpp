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
#include <string>
#include <vector>

#include <llvm/IR/Constants.h>
#include <llvm/IR/DataLayout.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "Instruction.h"
#include "remill/Arch/Arch.h"
#include "remill/Arch/Instruction.h"

#include "mcsema/Arch/Arch.h"

#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Instruction.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"

namespace mcsema {

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(llvm::IntegerType *word_type_,
                                     const remill::IntrinsicTable *intrinsics_,
                                     TranslationContext &ctx_)
      : remill::InstructionLifter(word_type_, intrinsics_),
        ctx(ctx_),
        instr(nullptr),
        block(nullptr),
        mem_ref(nullptr),
        disp_ref(nullptr),
        imm_ref(nullptr) {}


// Lift a single instruction into a basic block.
remill::LiftStatus InstructionLifter::LiftIntoBlock(
    remill::Instruction *instr_, llvm::BasicBlock *block_) {
  instr = instr_;
  block = block_;

  mem_ref = GetAddress(ctx.cfg_inst->mem);
  imm_ref = GetAddress(ctx.cfg_inst->imm);
  disp_ref = GetAddress(ctx.cfg_inst->disp);

  return this->remill::InstructionLifter::LiftIntoBlock(instr, block);
}

llvm::Value *InstructionLifter::GetAddress(const NativeXref *cfg_xref) {
  if (!cfg_xref) {
    return nullptr;
  }

  llvm::IRBuilder<> ir(block);
  if (cfg_xref->func) {
    auto cfg_func = cfg_xref->func;
    llvm::Function *func = nullptr;

    // If this is a lifted function, then create a wrapper around it. The
    // idea is that this reference to a lifted function can be leaked to
    // native code as a callback, and so native code calling it must be able
    // to swap into the lifted context.
    if (!cfg_func->is_external) {
      func = GetNativeToLiftedEntryPoint(cfg_func);
    } else {
      func = gModule->getFunction(cfg_func->name);
    }

    CHECK(func != nullptr)
        << "Can't resolve reference to function "
        << cfg_func->name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(func, word_type);

  } else if (cfg_xref->var) {
    auto cfg_var = cfg_xref->var;
    const auto &global_name = cfg_var->lifted_name;
    auto global = gModule->getNamedAlias(global_name);
    CHECK(global != nullptr)
        << "Can't resolve reference to variable "
        << global_name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(global, word_type);

  } else {
    auto cfg_seg = cfg_xref->target_segment;
    CHECK(cfg_seg != nullptr)
        << "A non-function, non-variable cross-reference from "
        << std::hex << instr->pc << " to " << std::hex << cfg_xref->target_ea
        << " must be in a known segment.";

    llvm::Constant *global = gModule->getNamedAlias(cfg_seg->lifted_name);
    CHECK(global != nullptr)
        << "Cannot find global variable for segment " << cfg_seg->name
        << " referenced by " << std::hex << instr->pc;


    auto offset = cfg_xref->target_ea - cfg_seg->ea;
    auto byte_type = llvm::Type::getInt8Ty(*gContext);
    auto byte_ptr_type = llvm::PointerType::get(byte_type, 0);
    CHECK(global->getType() == byte_ptr_type);

    global = llvm::ConstantExpr::getInBoundsGetElementPtr(
        byte_type, global, llvm::ConstantInt::get(word_type, offset));

    return ir.CreatePtrToInt(global, word_type);
  }
}

llvm::Value *InstructionLifter::LiftImmediateOperand(
    remill::Instruction *instr, llvm::BasicBlock *block,
    llvm::Type *arg_type, remill::Operand &op) {

  if (imm_ref) {
    llvm::DataLayout data_layout(gModule);
    auto arg_size = data_layout.getTypeSizeInBits(arg_type);

    CHECK(arg_size <= gArch->address_size)
        << "Immediate operand size " << op.size << " of "
        << op.Debug() << " in instruction " << std::hex << instr->pc
        << " is wider than the architecture pointer size ("
        << std::dec << gArch->address_size << ").";

    if (arg_type != imm_ref->getType() && arg_size < gArch->address_size) {
      llvm::IRBuilder<> ir(block);
      imm_ref = ir.CreateTrunc(imm_ref, arg_type);
    }

    return imm_ref;
  }

  return this->remill::InstructionLifter::LiftImmediateOperand(
      instr, block, arg_type, op);
}

// Lift an indirect memory operand to a value.
llvm::Value *InstructionLifter::LiftAddressOperand(
    remill::Instruction *instr, llvm::BasicBlock *block,
    remill::Operand &op) {

  auto &mem = op.addr;

  // A higher layer will resolve any code refs; this is a static address and
  // we want to preserve it in the register state structure.
  if (mem.IsControlFlowTarget()) {
    return this->remill::InstructionLifter::LiftAddressOperand(
        instr, block, op);
  }

  if ((mem.base_reg.name.empty() && mem.index_reg.name.empty()) ||
      (mem.base_reg.name == "PC" && mem.index_reg.name.empty())) {
    if (mem_ref) {
      return mem_ref;
    }

  } else {
    LOG_IF(ERROR, mem_ref != nullptr)
        << "IDA probably incorrectly decoded memory operand "
        << op.Debug() << " of instruction " << std::hex << instr->pc
        << "as an absolute memory reference when it should be treated as a "
        << "displacement memory reference.";

    // It's a reference located in the displacement. We'll clear out the
    // displacement, calculate the address operand stuff, then add the address
    // of the external back in. E.g. `mov rax, [extern_jump_table + rdi]`.
    if (disp_ref) {
      mem.displacement = 0;
      auto dynamic_addr = this->remill::InstructionLifter::LiftAddressOperand(
          instr, block, op);
      llvm::IRBuilder<> ir(block);
      return ir.CreateAdd(dynamic_addr, disp_ref);
    }
  }

  return this->remill::InstructionLifter::LiftAddressOperand(instr, block, op);
}

}  // namespace mcsema
