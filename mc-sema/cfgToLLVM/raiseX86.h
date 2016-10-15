/*
 Copyright (c) 2013, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
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
#pragma once
#include <list>
#include <set>
#include <vector>

#include "TransExcn.h"
#include "llvm/IR/BasicBlock.h"
#include "peToCFG.h"
#include "toModule.h"
#include <llvm/IR/Constants.h>
#include "RegisterUsage.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/Triple.h"
#include "ArchOps.h"

enum InstTransResult {
  ContinueBlock,
  EndBlock,
  EndCFG,
  TranslateErrorUnsupported,
  TranslateError
};

enum StoreSpillType {
  AllRegs = (1 << 0),   // store/spill all regs
  ABICallStore = (1 << 1),   // store regs in preparation for CALL
  ABICallSpill = (1 << 2),   // spill regs at function prolog
  ABIRetStore = (1 << 3),   // Store regs in preparation for RET
  ABIRetSpill = (1 << 4)    // spill regs right after a RET
};

//type that maps registers to their Value defn in a flow
typedef std::vector<llvm::Value*> regDefT;

//setup code in the first block of the function that defines all of the
//registers via alloca and then copies into them from the structure argument
void setupFlow(llvm::Function *, regDefT &);

llvm::BasicBlock *bbFromStrName(std::string n, llvm::Function *F);

///////////////////////////////////////////////////////////////////////////////
// state modeling functions
///////////////////////////////////////////////////////////////////////////////

llvm::Instruction * noAliasMCSemaScope(llvm::Instruction * inst);
llvm::Instruction * aliasMCSemaScope(llvm::Instruction * inst);

// Architecture specific utilities are under namespace
namespace x86 {
enum {
  REG_SIZE = 32,
};
llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);
}

namespace x86_64 {
enum {
  REG_SIZE = 64,
};
llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);
}

template<int width>
llvm::ConstantInt *CONST_V_INT(llvm::LLVMContext &ctx, uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(ctx, width);
  return llvm::ConstantInt::get(bTy, val);
}

template<int width>
llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(b->getContext(), width);
  return llvm::ConstantInt::get(bTy, val);
}

static llvm::ConstantInt *CONST_V(llvm::BasicBlock *b, uint64_t width,
                                  uint64_t val) {
  llvm::IntegerType *bTy = llvm::Type::getIntNTy(b->getContext(), width);
  return llvm::ConstantInt::get(bTy, val);
}


llvm::Value *MCRegToValue(llvm::BasicBlock *b, unsigned reg);

void GENERIC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v);
llvm::Value *GENERIC_READREG(llvm::BasicBlock *b, MCSemaRegs reg);

void GENERIC_MC_WRITEREG(llvm::BasicBlock *b, int reg, llvm::Value *v);
llvm::Value *GENERIC_MC_READREG(llvm::BasicBlock *b, int reg, int desired_size);

template<int width>
void R_WRITE(llvm::BasicBlock *b, int reg, llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, int reg) {
  return GENERIC_MC_READREG(b, reg, width);
}

namespace x86 {
template<int width>
void R_WRITE(llvm::BasicBlock *b, int reg, llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, int reg) {
  return GENERIC_MC_READREG(b, reg, width);
}
}

namespace x86_64 {
template<int width>
void R_WRITE(llvm::BasicBlock *b, int reg, llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
llvm::Value *R_READ(llvm::BasicBlock *b, int reg) {
  return GENERIC_MC_READREG(b, reg, width);
}
}

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace, llvm::BasicBlock *b,
                             llvm::Value *addr);

template<int width>
llvm::Value *M_READ(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr) {
  return INTERNAL_M_READ(width, ip->get_addr_space(), b, addr);
}

template<int width>
llvm::Value *M_READ_0(llvm::BasicBlock *b, llvm::Value *addr) {
  return INTERNAL_M_READ(width, 0, b, addr);
}

// defined in raiseX86.cpp
void M_WRITE_T(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
               llvm::Value *data, llvm::Type *ptrtype);

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data);

template<int width>
void M_WRITE(InstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
             llvm::Value *data) {
  return INTERNAL_M_WRITE(width, ip->get_addr_space(), b, addr, data);
}

template<int width>
void M_WRITE_0(llvm::BasicBlock *b, llvm::Value *addr, llvm::Value *data) {
  return INTERNAL_M_WRITE(width, 0, b, addr, data);
}
llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag);

void F_WRITE(llvm::BasicBlock *b, MCSemaRegs flag, llvm::Value *v);

void F_ZAP(llvm::BasicBlock *b, MCSemaRegs flag);

void F_SET(llvm::BasicBlock *b, MCSemaRegs flag);

void F_CLEAR(llvm::BasicBlock *b, MCSemaRegs flag);

void allocateLocals(llvm::Function *, int);

llvm::BasicBlock *bbFromStrName(std::string, llvm::Function *);

///////////////////////////////////////////////////////////////////////////////
// API usage functions
///////////////////////////////////////////////////////////////////////////////

InstTransResult liftInstr(InstPtr ip, llvm::BasicBlock *&block,
                         NativeBlockPtr nb, llvm::Function *F,
                         NativeFunctionPtr natF, NativeModulePtr natM,
                         bool doAnnotation);

llvm::Value *makeCallbackForLocalFunction(llvm::Module *M, VA local_target);

void dataSectionToTypesContents(const std::list<DataSection> &globaldata,
                                DataSection& ds, llvm::Module *M,
                                std::vector<llvm::Constant*>& secContents,
                                std::vector<llvm::Type*>& data_section_types,
                                bool convert_to_callback);

extern bool ignoreUnsupportedInsts;

template<int width, int maskbits>
static void SHR_SET_FLAG_V(llvm::BasicBlock *block, llvm::Value *val,
                           MCSemaRegs flag, llvm::Value *shrbit_val) {
  llvm::Value *shr = llvm::BinaryOperator::CreateLShr(val, shrbit_val, "",
                                                      block);
  llvm::Value *mask_pre = CONST_V<maskbits>(block, 0);
  llvm::Value *mask = llvm::BinaryOperator::CreateNot(mask_pre, "", block);
  llvm::Value *shr_trunc = new llvm::TruncInst(
      shr, llvm::Type::getIntNTy(block->getContext(), maskbits), "", block);

  llvm::Value *anded = llvm::BinaryOperator::CreateAnd(shr_trunc, mask, "",
                                                       block);

  F_WRITE(block, flag, anded);
}

template<int width, int maskbits>
static void SHR_SET_FLAG(llvm::BasicBlock *block, llvm::Value *val,
                         MCSemaRegs flag, int shrbits) {
  SHR_SET_FLAG_V<width, maskbits>(block, val, flag,
                                  CONST_V<width>(block, shrbits));
}
