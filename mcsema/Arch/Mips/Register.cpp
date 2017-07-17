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

 Neither the name of the {organization} nor the names of its
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

#include <inttypes.h>
#include <iostream>
#include <unordered_map>
#include <vector>

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Register.h"
#include "mcsema/BC/Util.h"

namespace {

struct RegInfo {
  std::string name;
  MCSemaRegs reg;
  bool is_sub_reg;
  llvm::Type *read_type;
  llvm::Type *write_type;
  size_t state_offset;
  MCSemaRegs parent_reg;
  size_t parent_offset;
};

static const std::string gBadReg = "MISSING_REG";

static std::unordered_map<MCSemaRegs, RegInfo> gRegInfo;
static std::vector<RegInfo> gOrderedRegInfo;
static std::unordered_map<std::string, MCSemaRegs> gRegNum;

static std::vector<llvm::Type *> gRegFields;

static llvm::StructType *gRegStateStruct = nullptr;

static MCSemaRegs gLastAddedReg = llvm::Mips::NoRegister;
static unsigned gNumRegs = 0;

static void AddPadding(llvm::Type *type, int num_elements) {
  gNumRegs++;
  gRegFields.push_back(llvm::ArrayType::get(type, num_elements));
  gLastAddedReg = llvm::Mips::NoRegister;
}

static void AddReg(MCSemaRegs reg, const char *name, llvm::Type *type) {
  RegInfo info = {name, reg, false, type, type, gNumRegs++, reg, 0};
  gRegInfo[reg] = info;
  gRegNum[name] = reg;
  gRegFields.push_back(type);
  gOrderedRegInfo.push_back(info);
  gLastAddedReg = reg;
}

static void AddSubReg(MCSemaRegs reg, const char *name,
                      llvm::Type *read_type, llvm::Type *write_type,
                      size_t parent_offset) {
  RegInfo info = {name, reg, true, read_type, write_type,
                  gNumRegs, gLastAddedReg, parent_offset};
  gRegInfo[reg] = info;
  gOrderedRegInfo.push_back(info);

  if (!parent_offset) {
    gLastAddedReg = reg;
  }
}

}  // namespace

void MipsInitRegisterState(llvm::LLVMContext *context) {
  if (!gContext) {
    gContext = context;
  }
  auto reg_type = llvm::Type::getIntNTy(*context, ArchAddressSize());
  auto int8_type = llvm::Type::getInt8Ty(*context);
  auto int16_type = llvm::Type::getInt16Ty(*context);
  auto int32_type = llvm::Type::getInt32Ty(*context);
  auto int64_type = llvm::Type::getInt64Ty(*context);
  auto int128_type = llvm::Type::getInt128Ty(*context);
  auto float80_type = llvm::Type::getX86_FP80Ty(*context);

  AddReg(llvm::Mips::PC, "PC", int32_type);
  AddReg(llvm::Mips::ZERO, "ZERO", int32_type);
  AddReg(llvm::Mips::AT, "AT", int32_type);
  
  AddReg(llvm::Mips::V0, "V0", int32_type);
  AddReg(llvm::Mips::V1, "V1", int32_type);
  
  AddReg(llvm::Mips::A0, "A0", int32_type);
  AddReg(llvm::Mips::A1, "A1", int32_type);
  AddReg(llvm::Mips::A2, "A2", int32_type);
  AddReg(llvm::Mips::A3, "A3", int32_type);
  
  AddReg(llvm::Mips::T0, "T0", int32_type);
  AddReg(llvm::Mips::T1, "T1", int32_type);
  AddReg(llvm::Mips::T2, "T2", int32_type);
  AddReg(llvm::Mips::T3, "T3", int32_type);
  AddReg(llvm::Mips::T4, "T4", int32_type);
  AddReg(llvm::Mips::T5, "T5", int32_type);
  AddReg(llvm::Mips::T6, "T6", int32_type);
  AddReg(llvm::Mips::T7, "T7", int32_type);
  
  AddReg(llvm::Mips::S0, "S0", int32_type);
  AddReg(llvm::Mips::S1, "S1", int32_type);
  AddReg(llvm::Mips::S2, "S2", int32_type);
  AddReg(llvm::Mips::S3, "S3", int32_type);
  AddReg(llvm::Mips::S4, "S4", int32_type);
  AddReg(llvm::Mips::S5, "S5", int32_type);
  AddReg(llvm::Mips::S6, "S6", int32_type);
  AddReg(llvm::Mips::S7, "S7", int32_type);
  
  AddReg(llvm::Mips::T8, "T8", int32_type);
  AddReg(llvm::Mips::T9, "T9", int32_type);
  
  AddReg(llvm::Mips::K0, "K0", int32_type);
  AddReg(llvm::Mips::K1, "K1", int32_type);

  AddReg(llvm::Mips::GP, "GP", int32_type);
  AddReg(llvm::Mips::SP, "SP", int32_type);
  AddReg(llvm::Mips::FP, "FP", int32_type);
  AddReg(llvm::Mips::RA, "RA", int32_type);
 

  //AddPadding(int8_type, 10);

  gRegStateStruct = llvm::StructType::create(*context, gRegFields, "RegState", false);
}

const std::string &MipsRegisterName(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR Mips: Can't find register name for number " << reg << std::endl;
    return gBadReg;
  } else {
    return it->second.name;
  }
}

MCSemaRegs MipsRegisterNumber(const std::string &name) {
  return gRegNum[name];
}

unsigned MipsRegisterOffset(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register offset for number " << reg << std::endl;
    return 0;
  } else {
    return static_cast<unsigned>(it->second.state_offset);
  }
}

MCSemaRegs MipsRegisterParent(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register parent for number " << reg << std::endl;
    return reg;
  } else {
    return it->second.parent_reg;
  }
}

void MipsAllocRegisterVars(llvm::BasicBlock *b) {
  auto func = b->getParent();
  llvm::Argument *state_ptr = &*func->arg_begin();
  auto state_ptr_type = llvm::dyn_cast<llvm::PointerType>(state_ptr->getType());
  auto state_type = state_ptr_type->getElementType();
  llvm::IRBuilder<> ir(b);

  std::unordered_map<MCSemaRegs, llvm::Value *> regs;

  for (const auto &info : gOrderedRegInfo) {
    auto write_var_name = info.name + "_write";
    auto read_var_name = info.name + "_read";

    // Add in the write reg version.
    llvm::Value *write_reg = nullptr;
    if (info.reg == info.parent_reg) {
      write_reg = ir.CreateConstInBoundsGEP2_32(
          state_type, state_ptr, 0, info.state_offset, write_var_name);

    } else if (!info.parent_offset) {
      write_reg = llvm::CastInst::Create(
          llvm::Instruction::BitCast,
          regs[info.parent_reg],
          llvm::PointerType::get(info.write_type, 0),
          write_var_name, b);

    } else {
      auto parent_reg = ir.CreateBitCast(
          regs[info.parent_reg], llvm::PointerType::get(info.write_type, 0), "");
      write_reg = ir.CreateConstInBoundsGEP1_32(
          info.write_type, parent_reg, info.parent_offset, write_var_name);
    }

    // Add in the read register version.
    regs[info.reg] = llvm::CastInst::Create(
        llvm::Instruction::BitCast,
        write_reg,
        llvm::PointerType::get(info.read_type, 0),
        read_var_name, b);
  }
//  b->dump();
//  exit(0);
}

unsigned MipsRegisterSize(MCSemaRegs reg) {
  const auto it = gRegInfo.find(reg);
  if (it == gRegInfo.end()) {
    std::cerr
        << "ERROR: Can't find register for number " << reg << std::endl;
    return 0;
  } else {
    return it->second.read_type->getScalarSizeInBits();
  }
}

llvm::StructType *MipsRegStateStructType(void) {
  return gRegStateStruct;
}

static llvm::Function *GetPrintf(llvm::Module *M) {
  // ; Function Attrs: nounwind
  // declare i32 @printf(i8* nocapture readonly, ...) local_unnamed_addr #1

  auto F = M->getFunction("printf");
  if (F) {
    return F;
  }

  auto &C = M->getContext();
  auto FTy = llvm::FunctionType::get(
      llvm::Type::getInt32Ty(C),
      {llvm::Type::getInt8PtrTy(C, 0)},
      true /* IsVarArg */);

  F = llvm::Function::Create(
      FTy, llvm::GlobalValue::ExternalLinkage, "printf", M);
  F->addFnAttr(llvm::Attribute::NoUnwind);
  return F;
}

llvm::Function *MipsGetOrCreateRegStateTracer(llvm::Module *M) {
  auto F = M->getFunction("__mcsema_trace_regs");
  if (F) {
    return F;
  }

  F = llvm::Function::Create(
      LiftedFunctionType(), llvm::GlobalValue::ExternalLinkage,
      "__mcsema_trace_regs", M);
  F->addFnAttr(llvm::Attribute::NoInline);

  auto &C = M->getContext();
  auto B = llvm::BasicBlock::Create(C, "", F);
  MipsAllocRegisterVars(B);

  const char *format = nullptr;
  if (Pointer32 == ArchAddressSize()) {
    format = "EIP=%" PRIx32 " EAX=%" PRIx32 " EBX=%" PRIx32
             " ECX=%" PRIx32 " EDX=%" PRIx32 " ESI=%" PRIx32
             " EDI=%" PRIx32 " ESP=%" PRIx32 " EBP=%" PRIx32
             "\n";
  }
  else {
   printf("Error in Address Size MIPS\n");
  }

  auto fmt_str = llvm::ConstantDataArray::getString(C, format, true);
  auto fmt = llvm::dyn_cast<llvm::GlobalVariable>(
      M->getOrInsertGlobal("reg_trace_fmt", fmt_str->getType()));

  fmt->setLinkage(llvm::GlobalValue::PrivateLinkage);
  fmt->setInitializer(fmt_str);

  auto i32_ty = llvm::Type::getInt32Ty(C);
  auto str_ty = llvm::Type::getInt8PtrTy(C);
  auto zero = llvm::ConstantInt::get(i32_ty, 0, false);

  std::vector<llvm::Value *> args;
  args.push_back(zero);
  args.push_back(zero);
  auto gep = llvm::GetElementPtrInst::CreateInBounds(fmt, args, "", B);

  args.clear();
  args.push_back(gep);

  if (Pointer32 == ArchAddressSize()) {
    args.push_back(R_READ<32>(B, llvm::Mips::AT));
    args.push_back(R_READ<32>(B, llvm::Mips::GP));
    args.push_back(R_READ<32>(B, llvm::Mips::SP));
    args.push_back(R_READ<32>(B, llvm::Mips::FP));
    args.push_back(R_READ<32>(B, llvm::Mips::RA));
    args.push_back(R_READ<32>(B, llvm::Mips::A0));
    args.push_back(R_READ<32>(B, llvm::Mips::A1));
    args.push_back(R_READ<32>(B, llvm::Mips::A2));
    args.push_back(R_READ<32>(B, llvm::Mips::A3));
  }
 else {
   printf("Error in Address Size MIPS. here \n");
 }

  llvm::IRBuilder<> ir(B);
  ir.CreateCall(GetPrintf(M), args);
  ir.CreateRetVoid();
  return F;
}
