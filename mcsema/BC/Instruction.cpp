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
    const auto &func_name = cfg_func->lifted_name;
    llvm::GlobalObject *func = gModule->getFunction(func_name);
    if (func) {
      func = GetEntryPoint(reinterpret_cast<const NativeFunction *>(cfg_func),
                         llvm::dyn_cast<llvm::Function>(func));
    } else {
      func = gModule->getNamedGlobal(func_name);
      LOG_IF(ERROR, func != nullptr)
          << "Function pointer to " << std::hex << cfg_func->ea
          << " with symbol " << func_name
          << " was resolved to a global variable from " << std::hex
          << instr->pc << ". There is probably an error in the CFG script.";
    }

    CHECK(func != nullptr)
        << "Can't resolve external code reference to "
        << func_name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(func, word_type);

  } else if (cfg_xref->var) {
    auto cfg_var = cfg_xref->var;
    const auto &global_name = cfg_var->lifted_name;
    llvm::GlobalObject *global = gModule->getNamedGlobal(global_name);
    if (!global && (global = gModule->getFunction(global_name))) {
      auto is_weak = llvm::GlobalValue::isExternalWeakLinkage(
          global->getLinkage());
      LOG_IF(ERROR, !is_weak)
          << "Data pointer to " << std::hex << cfg_var->ea
          << " with symbol " << global_name
          << " was resolved to a subroutine from " << std::hex << instr->pc
          << ". There is probably an error in the CFG script.";

      global = GetEntryPoint(reinterpret_cast<const NativeFunction *>(cfg_var),
                           llvm::dyn_cast<llvm::Function>(global));
    }

    CHECK(global != nullptr)
        << "Can't resolve external data reference to "
        << global_name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(global, word_type);

  } else {
    auto cfg_seg = cfg_xref->target_segment;
    CHECK(cfg_seg != nullptr)
        << "A non-function, non-variable cross-reference from "
        << std::hex << instr->pc << " to " << std::hex << cfg_xref->target_ea
        << " must be in a known segment.";

    auto global = gModule->getNamedGlobal(cfg_seg->lifted_name);
    CHECK(global != nullptr)
        << "Cannot find global variable for segment " << cfg_seg->name
        << " referenced by " << std::hex << instr->pc;

    auto offset = cfg_xref->target_ea - cfg_seg->ea;
    return ir.CreateAdd(
        ir.CreatePtrToInt(global, word_type),
        llvm::ConstantInt::get(word_type, offset, false));
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
