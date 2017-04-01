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

#include "mcsema/BC/Instruction.h"
#include "mcsema/BC/Lift.h"
#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"
#include "mcsema/CFG/Externals.h"

namespace mcsema {
namespace {

// Try to get the base address of a data section containing `addr`.
bool TryGetBaseAddress(NativeModulePtr mod, VA addr, VA *base,
                       std::string *sym_name) {
  *sym_name = "";
  for (auto &section : mod->getData()) {
    const VA low = section.getBase();
    const VA high = low + section.getSize();

    if (low <= addr && addr < high) {
      *base = low;
      // TODO(pag): Eventually what I would like is for this to refer to
      //            the name of an actual global variable. So, if the original
      //            binary has a global variable, then we have a constant GEP
      //            into the lifted data with the same name as the global.
//      for (const auto &entry : section.getEntries()) {
//        if (entry.getBase() == addr) {
//          entry.getSymbol(*sym_name);
//        }
//      }
      return true;
    }
  }

  return false;
}

}  // namespace

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
bool InstructionLifter::LiftIntoBlock(remill::Instruction *instr_,
                                      llvm::BasicBlock *block_) {
  instr = instr_;
  block = block_;

  mem_ref = GetAddress(ctx.cfg_inst->external_mem_code_ref,
                       ctx.cfg_inst->external_mem_data_ref,
                       ctx.cfg_inst->mem_ref_code_addr,
                       ctx.cfg_inst->mem_ref_data_addr);

  imm_ref = GetAddress(ctx.cfg_inst->external_imm_code_ref,
                       ctx.cfg_inst->external_imm_data_ref,
                       ctx.cfg_inst->imm_ref_code_addr,
                       ctx.cfg_inst->imm_ref_data_addr);

  disp_ref = GetAddress(ctx.cfg_inst->external_disp_code_ref,
                       ctx.cfg_inst->external_disp_data_ref,
                       ctx.cfg_inst->disp_ref_code_addr,
                       ctx.cfg_inst->disp_ref_data_addr);

  return this->remill::InstructionLifter::LiftIntoBlock(instr, block);
}

llvm::Value *InstructionLifter::GetAddress(
    ExternalCodeRefPtr code, ExternalDataRefPtr data,
    uint64_t code_addr, uint64_t data_addr) {

  llvm::IRBuilder<> ir(block);
  if (code) {
    const auto &func_name = code->getSymbolName();
    llvm::GlobalObject *func = gModule->getFunction(func_name);
    if (!func) {
      func = gModule->getNamedGlobal(func_name);
      LOG_IF(ERROR, func != nullptr)
          << "Function pointer to " << std::hex << code_addr << " with symbol "
          << func_name << " was resolved to a global variable from "
          << std::hex << instr->pc << ". There is "
          << "probably an error in the CFG script.";
    }

    CHECK(func != nullptr)
        << "Can't resolve external code reference to "
        << func_name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(func, word_type);

  } else if (data) {
    const auto &global_name = data->getSymbolName();
    llvm::GlobalObject *global = gModule->getNamedGlobal(global_name);
    if (!global) {
      global = gModule->getFunction(global_name);
      LOG_IF(ERROR,
             global &&
             !llvm::GlobalValue::isExternalWeakLinkage(global->getLinkage()))
          << "Data pointer to " << std::hex << data_addr << " with symbol "
          << global_name << " was resolved to a subroutine from "
          << std::hex << instr->pc << ". There is probably "
          << "an error in the CFG script.";
    }

    CHECK(global != nullptr)
        << "Can't resolve external data reference to "
        << global_name << " from " << std::hex << instr->pc;

    return ir.CreatePtrToInt(global, word_type);

  } else if (~0ULL != code_addr) {
    auto &funcs = ctx.cfg_module->get_funcs();
    auto func_it = funcs.find(code_addr);
    if (func_it == funcs.end()) {
      LOG(ERROR)
          << "Cannot find function for code reference to "
          << std::hex << code_addr << " from " << std::hex << instr->pc;
      return nullptr;

    } else if (auto func = gModule->getFunction(func_it->second->get_name())) {
      return ir.CreatePtrToInt(func, word_type);

    } else {
      LOG(ERROR)
          << "Cannot find function " << func_it->second->get_name()
          << " at address " << std::hex << func_it->second->get_start()
          << " referenced using address " << std::hex << code_addr
          << " from " << std::hex << instr->pc;
      return nullptr;
    }

  } else if (~0ULL != data_addr) {
    VA base_addr = ~0ULL;
    std::string sym_name;
    if (TryGetBaseAddress(ctx.cfg_module, data_addr, &base_addr, &sym_name)) {

      if (!sym_name.empty()) {
        if (auto global = gModule->getNamedGlobal(sym_name)) {
          return ir.CreatePtrToInt(global, word_type);
        }
      }

      // Go find the section base, and add to it.
      std::stringstream ss;
      ss << "data_" << std::hex << base_addr;
      auto sym_name = ss.str();

      if (auto global = gModule->getNamedGlobal(sym_name)) {
        return ir.CreateAdd(
            ir.CreatePtrToInt(global, word_type),
            llvm::ConstantInt::get(word_type, (data_addr - base_addr), false));

      } else {
        LOG(ERROR)
            << "Can't find global variable " << sym_name << " for section "
            << "that should contain the memory referenced by immediate "
            << std::hex << data_addr << " in instruction "
            << std::hex << instr->pc;
        return nullptr;
      }
    } else {
      LOG(ERROR)
          << "Data reference to " << std::hex << data_addr
          << " from " << std::hex << instr->pc
          << " does not belong to any lifted data section.";
      return nullptr;
    }

  } else {
    return nullptr;
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
