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

namespace mcsema {

namespace {

// Load the address of a register.
static llvm::Value *LoadRegAddress(llvm::BasicBlock *block,
                                   std::string reg_name) {
  return remill::FindVarInFunction(block->getParent(), reg_name);
}

// Load the value of a register.
static llvm::Value *LoadRegValue(llvm::BasicBlock *block,
                                 std::string reg_name) {
  return new llvm::LoadInst(LoadRegAddress(block, reg_name), "", block);
}

static llvm::Value *LoadAddressRegVal(llvm::BasicBlock *block,
                                         const remill::Operand::Register &reg,
                                         llvm::ConstantInt *zero) {
  if (reg.name.empty()) {
    return zero;
  }

  auto value = LoadRegValue(block, reg.name);
  auto value_type = llvm::dyn_cast<llvm::IntegerType>(value->getType());
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

static bool IsFramePointerReg(const remill::Operand::Register &reg) {

  if (reg.name.empty()) {
    return false;
  }

  if (mcsema::gArch->IsAMD64()) {
    return reg.name == "RBP";
  } else if (mcsema::gArch->IsX86()) {
    return reg.name == "EBP";
  }
  return false;
}

static bool IsStackPointerReg(const remill::Operand::Register &reg) {

  if (reg.name.empty()) {
    return false;
  }

  if (mcsema::gArch->IsAMD64()) {
    return reg.name == "RSP";
  } else if (mcsema::gArch->IsX86()) {
    return reg.name == "ESP";
  } else if (mcsema::gArch->IsAArch64()) {
    return reg.name == "SP" || reg.name == "WSP";
  }
  return false;
}

}  // namespace

InstructionLifter::~InstructionLifter(void) {}

InstructionLifter::InstructionLifter(const remill::IntrinsicTable *intrinsics_,
                                     TranslationContext &ctx_)
      : remill::InstructionLifter(gArch, intrinsics_),
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
remill::LiftStatus InstructionLifter::LiftIntoBlock(
    remill::Instruction &inst, llvm::BasicBlock *block_) {

  inst_ptr = &inst;
  block = block_;
  mem_ref = GetAddress(ctx.cfg_inst->mem);
  imm_ref = GetMaskedAddress(ctx.cfg_inst->imm);
  disp_ref = GetMaskedAddress(ctx.cfg_inst->disp);

  mem_ref_used = false;
  disp_ref_used = false;
  imm_ref_used = false;

  auto status = this->remill::InstructionLifter::LiftIntoBlock(inst, block);

  // If we have semantics for the instruction, then make sure that we were
  // able to match cross-reference information to the instruction's operands.
  if (remill::kLiftedInstruction == status) {
    if (mem_ref && !mem_ref_used) {
      LOG(FATAL)
          << "Unused memory reference operand to " << std::hex
          << ctx.cfg_inst->mem->target_ea << " in instruction "
          << inst.Serialize() << std::dec;
    }

    if (imm_ref && !imm_ref_used) {
      LOG(FATAL)
          << "Unused immediate operand reference to " << std::hex
          << ctx.cfg_inst->imm->target_ea << " in instruction "
          << inst.Serialize() << std::dec;
    }

    if (disp_ref && !disp_ref_used) {
      LOG(FATAL)
          << "Unused displacement operand reference to " << std::hex
          << ctx.cfg_inst->disp->target_ea << " in instruction "
          << inst.Serialize() << std::dec;
    }
  }

  return status;
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

// Returns `true` if a given cross-reference is self-referential. That is,
// we'll have something like `jmp cs:EnterCriticalSection`, which references
// `EnterCriticalSection` in the `.idata` section of a PE file. But this
// location is our only "place" for the external `EnterCriticalSection`, so
// we point it back at itself.
static bool IsSelfReferential(const NativeXref *cfg_xref) {
  if (!cfg_xref->target_segment) {
    return false;
  }

  auto it = cfg_xref->target_segment->entries.find(cfg_xref->target_ea);
  if (it == cfg_xref->target_segment->entries.end()) {
    return false;
  }

  const auto &entry = it->second;
  if (!entry.xref) {
    return false;
  }

  return entry.xref->target_ea == entry.ea;
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
      if (IsSelfReferential(cfg_xref)) {
        LOG(WARNING)
            << "Reference from " << std::hex << cfg_xref->ea
            << " to self-referential function reference "
            << cfg_xref->target_name << " at " << cfg_xref->target_ea
            << " being lifted as address into "
            << cfg_xref->target_segment->name << std::dec;

        return LiftEA(cfg_xref->target_segment, cfg_xref->target_ea);

      } else {
        func = gModule->getFunction(cfg_func->name);
      }
    } else {
      func = GetNativeToLiftedCallback(cfg_func);
    }

    CHECK(func != nullptr)
        << "Can't resolve reference to function "
        << cfg_func->name << " from " << std::hex << inst_ptr->pc << std::dec;

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
#if 0
    // TODO(akshayk): Discuss a better solution to handle the weak external functions
    // It causes the garbage address for _ZNSt12out_of_rangeD1Ev

    // TODO(pag): This is an awful hack for now that won't generalize.
    if (func->hasExternalWeakLinkage()) {
      LOG(ERROR)
          << "Adding pseudo-load of weak function " << cfg_func->name
          << " at " << std::hex << inst_ptr->pc << std::dec;

      auto temp_loc = ir.CreateAlloca(func->getType());
      ir.CreateStore(func, temp_loc);
      func_val = temp_loc;
    }
#endif

    return ir.CreatePtrToInt(func_val, word_type);

  } else if (auto cfg_var = cfg_xref->var) {
    if (cfg_var->address) {
      return cfg_var->address;
    }

    LOG(ERROR)
        << "Variable " << cfg_var->name << " at " << std::hex << cfg_var->ea
        << std::dec << " was not lifted.";
    // Fall through.
  }

  CHECK(cfg_xref->target_segment != nullptr)
      << "A non-function, non-variable cross-reference from "
      << std::hex << inst_ptr->pc << " to " << cfg_xref->target_ea << std::dec
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
    auto base = ir.CreatePtrToInt(ctx.cfg_inst->stack_var->llvm_var, word_type);
    auto map_it = ctx.cfg_inst->stack_var->refs.find(ctx.cfg_inst->ea);
    if (map_it != ctx.cfg_inst->stack_var->refs.end()) {
      auto var_offset = llvm::ConstantInt::get(
          word_type, static_cast<uint64_t>(map_it->second), true);
      base = ir.CreateAdd(base, var_offset);
      LOG(INFO)
        << "Lifting stack variable access at : " << std::hex << map_it->first
        << " var_offset " << map_it->second  << std::dec
        << " variable name " << ctx.cfg_inst->stack_var->name;

      if (!mem.index_reg.name.empty()) {
        auto zero = llvm::ConstantInt::get(word_type, 0, false);
        auto index = LoadAddressRegVal(block, mem.index_reg, zero);
        auto scale = llvm::ConstantInt::get(
            word_type, static_cast<uint64_t>(mem.scale), true);
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

// Lift the register operand to a value.
llvm::Value *InstructionLifter::LiftRegisterOperand(
    remill::Instruction &inst, llvm::BasicBlock *block,
    llvm::Argument *arg, remill::Operand &op) {

  auto &reg = op.reg;

  // Check if the instruction is referring to the base pointer which
  // might be accessing stack variable indirectly
  if (ctx.cfg_inst->stack_var) {
    if ((IsFramePointerReg(reg) || IsStackPointerReg(reg)) &&
        (op.action == remill::Operand::kActionRead)) {
      llvm::IRBuilder<> ir(block);
      auto variable = ir.CreatePtrToInt(
          ctx.cfg_inst->stack_var->llvm_var, word_type);
      auto map_it = ctx.cfg_inst->stack_var->refs.find(ctx.cfg_inst->ea);
      if (map_it != ctx.cfg_inst->stack_var->refs.end()) {
        auto var_offset = llvm::ConstantInt::get(
            word_type, static_cast<uint64_t>(map_it->second), true);
        variable = ir.CreateAdd(variable, var_offset);
      }
      LOG(INFO)
          << "Lifting stack variable reference at : " << std::hex
          << ctx.cfg_inst->ea << std::dec;
      return variable;
    }
  }

  return this->remill::InstructionLifter::LiftRegisterOperand(
      inst, block, arg, op);
}

}  // namespace mcsema
