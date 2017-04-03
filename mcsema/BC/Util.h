/*
 Copyright (c) 2013, Trail of Bits
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

#ifndef MCSEMA_BC_UTIL_H_
#define MCSEMA_BC_UTIL_H_

#include <cstdint>
#include <vector>

#include "mcsema/Arch/Register.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/CFG/CFG.h"

namespace llvm {

class BasicBlock;
class ConstantInt;
class LLVMContext;
class Module;

}  // namespace llvm

extern llvm::LLVMContext *gContext;

// Create a new module for the current arch/os pair.
llvm::Module *CreateModule(llvm::LLVMContext *context);

// Return a constnat integer of width `width` and value `val`.
llvm::ConstantInt *CreateConstantInt(int width, uint64_t val);

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void);

template <int width>
inline static llvm::ConstantInt *CONST_V_INT(
    llvm::LLVMContext &, uint64_t val) {
  return CreateConstantInt(width, val);
}

template <int width>
inline static llvm::ConstantInt *CONST_V(llvm::BasicBlock *, uint64_t val) {
  return CreateConstantInt(width, val);
}

inline static llvm::ConstantInt *CONST_V(llvm::BasicBlock *, unsigned width,
                                         uint64_t val) {
  return CreateConstantInt(width, val);
}

enum StoreSpillType {
  AllRegs = (1 << 0),   // store/spill all regs
  ABICallStore = (1 << 1),   // store regs in preparation for CALL
  ABICallSpill = (1 << 2),   // spill regs at function prolog
  ABIRetStore = (1 << 3),   // Store regs in preparation for RET
  ABIRetSpill = (1 << 4)    // spill regs right after a RET
};

///////////////////////////////////////////////////////////////////////////////
// state modeling functions
///////////////////////////////////////////////////////////////////////////////

#define noAliasMCSemaScope(...) \
    reinterpret_cast<llvm::Instruction *>(__VA_ARGS__)
#define aliasMCSemaScope(...) \
    reinterpret_cast<llvm::Instruction *>(__VA_ARGS__)

void GENERIC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v);
llvm::Value *GENERIC_READREG(llvm::BasicBlock *b, MCSemaRegs reg);

void GENERIC_MC_WRITEREG(llvm::BasicBlock *b, MCSemaRegs reg, llvm::Value *v);
llvm::Value *GENERIC_MC_READREG(llvm::BasicBlock *b, MCSemaRegs reg,
                                int desired_size);

template<int width>
inline static void R_WRITE(llvm::BasicBlock *b, MCSemaRegs reg,
                           llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
inline static llvm::Value *R_READ(llvm::BasicBlock *b, MCSemaRegs reg) {
  return GENERIC_MC_READREG(b, reg, width);
}

namespace x86 {

template<int width>
inline static void R_WRITE(llvm::BasicBlock *b, MCSemaRegs reg,
                           llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
inline static llvm::Value *R_READ(llvm::BasicBlock *b, MCSemaRegs reg) {
  return GENERIC_MC_READREG(b, reg, width);
}

}  // namespace x86

namespace x86_64 {

template<int width>
inline static void R_WRITE(llvm::BasicBlock *b, MCSemaRegs reg,
                           llvm::Value *write) {
  GENERIC_MC_WRITEREG(b, reg, write);
}

template<int width>
inline static llvm::Value *R_READ(llvm::BasicBlock *b, MCSemaRegs reg) {
  return GENERIC_MC_READREG(b, reg, width);
}

}  // namespace x86_64

llvm::Value *INTERNAL_M_READ(unsigned width, unsigned addrspace,
                             llvm::BasicBlock *b, llvm::Value *addr);

template<int width>
inline static llvm::Value *M_READ(NativeInstPtr ip, llvm::BasicBlock *b,
                                  llvm::Value *addr) {
  return INTERNAL_M_READ(width, ip->get_addr_space(), b, addr);
}

template<int width>
inline static llvm::Value *M_READ_0(llvm::BasicBlock *b, llvm::Value *addr) {
  return INTERNAL_M_READ(width, 0, b, addr);
}

// defined in raiseX86.cpp
void M_WRITE_T(NativeInstPtr ip, llvm::BasicBlock *b, llvm::Value *addr,
               llvm::Value *data, llvm::Type *ptrtype);

void INTERNAL_M_WRITE(int width, unsigned addrspace, llvm::BasicBlock *b,
                      llvm::Value *addr, llvm::Value *data);

template<int width>
inline static void M_WRITE(NativeInstPtr ip, llvm::BasicBlock *b,
                           llvm::Value *addr, llvm::Value *data) {
  return INTERNAL_M_WRITE(width, ip->get_addr_space(), b, addr, data);
}

template<int width>
inline static void M_WRITE_0(llvm::BasicBlock *b, llvm::Value *addr,
                             llvm::Value *data) {
  return INTERNAL_M_WRITE(width, 0, b, addr, data);
}

llvm::Value *ADDR_TO_POINTER_V(llvm::BasicBlock *b, llvm::Value *memAddr,
                               llvm::Type *ptrType);

llvm::Value *ADDR_TO_POINTER(llvm::BasicBlock *b, llvm::Value *memAddr,
                             int width);

template<int width>
inline static llvm::Value *ADDR_TO_POINTER(llvm::BasicBlock *b,
                                           llvm::Value *memAddr) {
  return ADDR_TO_POINTER(b, memAddr, width);
}

llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag);
llvm::Value *F_READ(llvm::BasicBlock *b, MCSemaRegs flag, int size);

void F_WRITE(llvm::BasicBlock *b, MCSemaRegs flag, llvm::Value *v);

void F_ZAP(llvm::BasicBlock *b, MCSemaRegs flag);

void F_SET(llvm::BasicBlock *b, MCSemaRegs flag);

void F_CLEAR(llvm::BasicBlock *b, MCSemaRegs flag);

///////////////////////////////////////////////////////////////////////////////
// API usage functions
///////////////////////////////////////////////////////////////////////////////

llvm::Value *makeCallbackForLocalFunction(llvm::Module *M, VA local_target);

void dataSectionToTypesContents(const std::list<DataSection> &globaldata,
                                const DataSection &ds, llvm::Module *M,
                                std::vector<llvm::Constant *>& secContents,
                                std::vector<llvm::Type *>& data_section_types,
                                bool convert_to_callback);


#define OP(x) inst.getOperand(x)

#define ADDR_NOREF(x) \
    ArchPointerSize(block->getParent()->getParent()) == Pointer32 ? \
    ADDR_NOREF_IMPL<32>(natM, block, x, ip, inst) :\
    ADDR_NOREF_IMPL<64>(natM, block, x, ip, inst)

#define CREATE_BLOCK(nm, b) \
    auto block_ ## nm = llvm::BasicBlock::Create( \
        (b)->getContext(), #nm, (b)->getParent())

#define MEM_REFERENCE(which) MEM_AS_DATA_REF(block, natM, inst, ip, which)

#define GENERIC_TRANSLATION_MI(NAME, NOREFS, MEMREF, IMMREF, TWOREFS) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      if (ip->has_mem_reference && ip->has_imm_reference) { \
          TWOREFS; \
      } else if (ip->has_mem_reference ) { \
          MEMREF; \
      } else if (ip->has_imm_reference ) { \
          IMMREF; \
      } else { \
          NOREFS; \
      } \
      (void)(natM);\
      (void)(F);\
      (void)(ip);\
      (void)(inst);\
      return ContinueBlock;\
    }


#define GENERIC_TRANSLATION_REF(NAME, NOREFS, HASREF) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      if (ip->has_mem_reference || ip->has_imm_reference || \
         ip->has_external_ref()) { \
          HASREF; \
      } else {\
          NOREFS; \
      } \
      (void)(natM);\
      (void)(F);\
      (void)(ip);\
      (void)(inst);\
      return ContinueBlock; \
    }

#define GENERIC_TRANSLATION(NAME, NOREFS) \
    static InstTransResult translate_ ## NAME ( \
        TranslationContext &ctx, llvm::BasicBlock *&block) { \
      InstTransResult ret;\
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      ret = NOREFS; \
      (void)(natM);\
      (void)(F);\
      (void)(ip);\
      (void)(inst);\
      return ret; \
    }

// this template and macro simplify referencing semantics defined in external bitcode
// the EXTERNAL_SEMANTICS macro will create a global string constant necessary to 
// instantiate this template. The constant gets shoved in the mcsema_const_strings namespace.
//
// The template will call a function with the same prototype as the current translation semantics
// The function itself is retrieved by ArchGetOrCreateSemantics
template <char const *fname>
static InstTransResult EXTERNAL_BITCODE_HELPER(TranslationContext &ctx, llvm::BasicBlock *&block) {
  auto F = ctx.F;
  auto M = F->getParent();
  auto externSemanticsF = ArchGetOrCreateSemantics(M, fname);
  // we are calling a translation function, it gets the same args
  // as our function
  std::vector<llvm::Value *> subArgs;
  for (auto &arg : F->args()) {
    subArgs.push_back(&arg);
  }
  auto ci = llvm::CallInst::Create(externSemanticsF, subArgs, "", block);
  ArchSetCallingConv(M, ci);
  return ContinueBlock;
}

#define EXTERNAL_SEMANTICS(NAME) \
  namespace mcsema_const_strings { char name_ ## NAME [] = #NAME; } \
  static InstTransResult translate_ ## NAME (TranslationContext &ctx, llvm::BasicBlock *&block) { \
      return EXTERNAL_BITCODE_HELPER<mcsema_const_strings::name_ ## NAME >(ctx, block); \
  }


#endif  // MCSEMA_BC_UTIL_H_
