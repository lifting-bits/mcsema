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
#include "remill/BC/Util.h"

#include "mcsema/Arch/Arch.h"

#include "mcsema/BC/Callback.h"
#include "mcsema/BC/Instruction.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"

namespace {

// Load the address of a register.
static llvm::Value *LoadRegAddress(llvm::BasicBlock *block,
                                   std::string reg_name) {
  return new llvm::LoadInst(
      remill::FindVarInFunction(block->getParent(), reg_name), "", block);
}

// Load the value of a register.
static llvm::Value *LoadRegValue(llvm::BasicBlock *block,
                                 std::string reg_name) {
  return new llvm::LoadInst(LoadRegAddress(block, reg_name), "", block);
}

static llvm::Value *LoadAddressRegValOrZero(llvm::BasicBlock *block,
                                         const remill::Operand::Register &reg,
                                         llvm::ConstantInt *zero) {
  if (reg.name.empty()) {
    return zero;
  }

  auto value = LoadRegValue(block, reg.name);
  auto value_type = llvm::dyn_cast_or_null<llvm::IntegerType>(value->getType());
  auto word_type = zero->getType();

  CHECK(value_type)
      << "Register " << reg.name << " expected to be an integer.";

  auto value_size = value_type->getBitWidth();
  auto word_size = word_type->getBitWidth();
  CHECK(value_size <= word_size)
      << "Register " << reg.name << " expected to be no larger than the "
      << "machine word size (" << word_type->getBitWidth() << " bits).";

  if (value_size < word_size) {
    value = new llvm::ZExtInst(value, word_type, "", block);
  }

  return value;
}

}

namespace mcsema {

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(const remill::IntrinsicTable *intrinsics_,
                                     TranslationContext &ctx_)
      : remill::InstructionLifter(gWordType, intrinsics_),
        ctx(ctx_),
        inst_ptr(nullptr),
        block(nullptr),
        mem_ref(nullptr),
        disp_ref(nullptr),
        imm_ref(nullptr),
        mem_ref_used(false),
        disp_ref_used(false),
        imm_ref_used(false) {}

// Lift a single instruction into a basic block.
bool InstructionLifter::LiftIntoBlock(
    remill::Instruction &inst, llvm::BasicBlock *block_) {

  inst_ptr = &inst;
  block = block_;
  mem_ref = GetAddress(ctx.cfg_inst->mem);
  imm_ref = GetMaskedAddress(ctx.cfg_inst->imm);
  disp_ref = GetMaskedAddress(ctx.cfg_inst->disp);

  mem_ref_used = false;
  disp_ref_used = false;
  imm_ref_used = false;

  auto ret = this->remill::InstructionLifter::LiftIntoBlock(inst, block);

  CHECK(!mem_ref || mem_ref_used)
      << "Unused mem reference to " << std::hex << ctx.cfg_inst->ea
      << " in instruction at " << std::hex << inst.pc;

  CHECK(!imm_ref || imm_ref_used)
      << "Unused imm reference to " << std::hex << ctx.cfg_inst->ea
      << " in instruction at " << std::hex << inst.pc;

  CHECK(!disp_ref || disp_ref_used)
      << "Unused disp reference to " << std::hex << ctx.cfg_inst->ea
      << " in instruction at " << std::hex << inst.pc;

  return ret;
}

llvm::Value *InstructionLifter::GetMaskedAddress(const NativeXref *cfg_xref) {
  auto addr = GetAddress(cfg_xref);
  if (!addr || !cfg_xref->mask) {
    return addr;
  }

  auto mask = llvm::ConstantInt::get(word_type, cfg_xref->mask);
  llvm::IRBuilder<> ir(block);
  return ir.CreateAnd(addr, mask);
}

llvm::Value *InstructionLifter::GetAddress(const NativeXref *cfg_xref) {
  if (!cfg_xref) {
    return nullptr;
  }

  llvm::IRBuilder<> ir(block);
  if (auto cfg_func = cfg_xref->func) {
    llvm::Function *func = nullptr;
    llvm::Value *func_val = nullptr;

    // If this is a lifted function, then create a wrapper around it. The
    // idea is that this reference to a lifted function can be leaked to
    // native code as a callback, and so native code calling it must be able
    // to swap into the lifted context.
    if (cfg_func->is_external) {
      func = gModule->getFunction(cfg_func->name);
    } else {
      func = GetNativeToLiftedCallback(cfg_func);
    }

    CHECK(func != nullptr)
        << "Can't resolve reference to function "
        << cfg_func->name << " from " << std::hex << inst_ptr->pc;

    func_val = func;

    // Functions attributed with weak linkage may be defined, but aren't
    // necessarily. What you end up getting is code that checks if the function
    // pointer is non-null, and if so, calls the function.
    //
    //      mov     rax, cs:__gmon_start___ptr
    //      test    rax, rax
    //
    // In the CFG, we get `__gmon_start__` instead of `__gmon_start___ptr`,
    // but we don't want to actually read the machine code bytes of
    // `__gmon_start__`, which is likely to be an ELF thunk. So we throw in
    // an extra layer of indirection here.
    //
    // TODO(pag): This is an awful hack for now that won't generalize.
    if (func->hasExternalWeakLinkage()) {
      LOG(ERROR)
          << "Adding pseudo-load of weak function " << cfg_func->name
          << " at " << std::hex << inst_ptr->pc;

      auto temp_loc = ir.CreateAlloca(func->getType());
      ir.CreateStore(func, temp_loc);
      func_val = temp_loc;
    }

    return ir.CreatePtrToInt(func_val, word_type);

  } else if (auto cfg_var = cfg_xref->var) {
    if (cfg_var->address) {
      return cfg_var->address;
    }

    LOG(ERROR)
        << "Variable " << cfg_var->name << " at " << std::hex << cfg_var->ea
        << " was not lifted.";
    // Fall through.
  }

  CHECK(cfg_xref->target_segment != nullptr)
      << "A non-function, non-variable cross-reference from "
      << std::hex << inst_ptr->pc << " to " << std::hex << cfg_xref->target_ea
      << " must be in a known segment.";

  return LiftEA(cfg_xref->target_segment, cfg_xref->target_ea);
}

llvm::Value *InstructionLifter::LiftImmediateOperand(
    remill::Instruction &inst, llvm::BasicBlock *block,
    llvm::Argument *arg, remill::Operand &op) {
  auto arg_type = arg->getType();
  if (imm_ref) {
    imm_ref_used = true;

    llvm::DataLayout data_layout(gModule);
    auto arg_size = data_layout.getTypeSizeInBits(arg_type);

    CHECK(arg_size <= gArch->address_size)
        << "Immediate operand size " << op.size << " of "
        << op.Serialize() << " in instuction " << std::hex << inst.pc
        << " is wider than the architecture pointer size ("
        << std::dec << gArch->address_size << ").";

    if (arg_type != imm_ref->getType() && arg_size < gArch->address_size) {
      llvm::IRBuilder<> ir(block);
      imm_ref = ir.CreateTrunc(imm_ref, arg_type);
    }

    return imm_ref;
  }

  return this->remill::InstructionLifter::LiftImmediateOperand(
      inst, block, arg, op);
}

// Lift an indirect memory operand to a value.
llvm::Value *InstructionLifter::LiftAddressOperand(
    remill::Instruction &inst, llvm::BasicBlock *block,
    llvm::Argument *arg, remill::Operand &op) {

  auto &mem = op.addr;

  // A higher layer will resolve any code refs; this is a static address and
  // we want to preserve it in the register state structure.
  if (mem.IsControlFlowTarget()) {
    return this->remill::InstructionLifter::LiftAddressOperand(
        inst, block, arg, op);
  }

  // Check if the instruction is referring to stack variable
  if (ctx.cfg_inst->stack_var) {
    llvm::IRBuilder<> ir(block);
    auto map_it = ctx.cfg_inst->stack_var->refs.find(ctx.cfg_inst->ea);
    auto base = ir.CreatePtrToInt(ctx.cfg_inst->stack_var->llvm_var, word_type);
    auto var_offset = llvm::ConstantInt::get(word_type, static_cast<uint64_t>(map_it->second), true);
    base = ir.CreateAdd(base, var_offset);
    LOG(INFO) << "Lifting stack variable access at : " << std::hex << map_it->first
        << " var_offset " << map_it->second << " variable name " << ctx.cfg_inst->stack_var->name <<std::endl;

    if(!mem.base_reg.name.empty() && !mem.index_reg.name.empty()) {
      auto zero = llvm::ConstantInt::get(word_type, 0, false);
      auto index = LoadAddressRegValOrZero(block, mem.index_reg, zero);
      auto scale = llvm::ConstantInt::get(word_type, static_cast<uint64_t>(mem.scale), true);

      if (zero != index) {
        return ir.CreateAdd(base, ir.CreateMul(index, scale));
      }
    }
    return base;
  }

  if ((mem.base_reg.name.empty() && mem.index_reg.name.empty()) ||
      (mem.base_reg.name == "PC" && mem.index_reg.name.empty())) {

    if (mem_ref) {
      mem_ref_used = true;
      return mem_ref;

    } else if (disp_ref) {
      disp_ref_used = true;
      return disp_ref;
    }

  } else {
    LOG_IF(ERROR, mem_ref != nullptr)
        << "IDA probably incorrectly decoded memory operand "
        << op.Serialize() << " of instruction " << std::hex << inst.pc
        << " as an absolute memory reference when it should be treated as a "
        << "displacement memory reference.";

    // It's a reference located in the displacement. We'll clear out the
    // displacement, calculate the address operand stuff, then add the address
    // of the external back in. E.g. `mov rax, [extern_jump_table + rdi]`.
    if (disp_ref) {
      disp_ref_used = true;
      mem.displacement = 0;
      auto dynamic_addr = this->remill::InstructionLifter::LiftAddressOperand(
          inst, block, arg, op);
      llvm::IRBuilder<> ir(block);
      return ir.CreateAdd(dynamic_addr, disp_ref);
    }
  }

  return this->remill::InstructionLifter::LiftAddressOperand(
      inst, block, arg, op);
}

}  // namespace mcsema
