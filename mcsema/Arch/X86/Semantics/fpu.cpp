/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

 Neither the name of Trail of Bits nor the names of its
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

#define __USE_GNU

#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include <llvm/MC/MCInst.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/Arch/X86/Util.h"
#include "mcsema/Arch/X86/Semantics/fpu.h"

#include "mcsema/BC/Util.h"

#ifndef M_PIl
# define M_PIl    3.141592653589793238462643383279502884L /* pi */
# define M_LN2l   0.693147180559945309417232121458176568L /* log_e 2 */
# define M_LOG2El 1.442695040888963407359924681001892137L /* log_2 e */
# define M_LOG10El  0.434294481903251827651128918916605082L /* log_10 e */
#endif

#define M_FLDLG2 0.301029995663981195214

#define NASSERT(cond) TASSERT(cond, "")

#define MAKEWORD(x, y) (((x) << 8) | (y))
#define MAKE_FOPCODE(x, y) (MAKEWORD(x, y) & 0x7FF)

template<int width>
static llvm::Value *SHL_NOTXOR_V(llvm::BasicBlock *block, llvm::Value *val,
                                 llvm::Value *val_to_shift, int shlbits) {
  auto fv = val_to_shift;
  auto nfv = llvm::BinaryOperator::CreateNot(fv, "", block);
  auto nzfv = new llvm::ZExtInst(
      nfv, llvm::Type::getIntNTy(block->getContext(), width), "", block);
  auto shl = llvm::BinaryOperator::CreateShl(nzfv,
                                             CONST_V<width>(block, shlbits), "",
                                             block);
  return llvm::BinaryOperator::CreateXor(shl, val, "", block);
}

template<int width>
static llvm::Value *SHL_NOTXOR_FLAG(llvm::BasicBlock *block, llvm::Value *val,
                                    MCSemaRegs flag, int shlbits) {
  auto fv = F_READ(block, flag);
  return SHL_NOTXOR_V<width>(block, val, fv, shlbits);
}

static llvm::Value *adjustFpuPrecision(llvm::BasicBlock *&b,
                                       llvm::Value *fpuval) {
  return fpuval;
}

static llvm::Value *CONSTFP_V(llvm::BasicBlock *&b, long double val) {
  auto bTy = llvm::Type::getX86_FP80Ty(b->getContext());
  return llvm::ConstantFP::get(bTy, val);
}

// Read the value of X86::STi as specified by fpreg.
static llvm::Value *FPUR_READ(llvm::BasicBlock *&b, MCSemaRegs fpreg) {
  return GENERIC_READREG(b, fpreg);
}

// Write val to X86::STi (specified by fpreg).
static void FPUR_WRITE(llvm::BasicBlock *&b, MCSemaRegs fpreg, llvm::Value *val) {
  GENERIC_WRITEREG(b, fpreg, val);
}

// Decrement Top, set ST(TOP) = fpuval.
static void FPU_PUSHV(llvm::BasicBlock *&b, llvm::Value *fpuval) {

  // The FPUR_WRITEV will mark the currentTOP as valid in the tag registers.
  FPUR_WRITE(b, llvm::X86::ST7, FPUR_READ(b, llvm::X86::ST6));
  FPUR_WRITE(b, llvm::X86::ST6, FPUR_READ(b, llvm::X86::ST5));
  FPUR_WRITE(b, llvm::X86::ST5, FPUR_READ(b, llvm::X86::ST4));
  FPUR_WRITE(b, llvm::X86::ST4, FPUR_READ(b, llvm::X86::ST3));
  FPUR_WRITE(b, llvm::X86::ST3, FPUR_READ(b, llvm::X86::ST2));
  FPUR_WRITE(b, llvm::X86::ST2, FPUR_READ(b, llvm::X86::ST1));
  FPUR_WRITE(b, llvm::X86::ST1, FPUR_READ(b, llvm::X86::ST0));
  FPUR_WRITE(b, llvm::X86::ST0, fpuval);
}

static void FPU_POP(llvm::BasicBlock *&b) {
  auto st0 = FPUR_READ(b, llvm::X86::ST0);
  FPUR_WRITE(b, llvm::X86::ST0, FPUR_READ(b, llvm::X86::ST1));
  FPUR_WRITE(b, llvm::X86::ST1, FPUR_READ(b, llvm::X86::ST2));
  FPUR_WRITE(b, llvm::X86::ST2, FPUR_READ(b, llvm::X86::ST3));
  FPUR_WRITE(b, llvm::X86::ST3, FPUR_READ(b, llvm::X86::ST4));
  FPUR_WRITE(b, llvm::X86::ST4, FPUR_READ(b, llvm::X86::ST5));
  FPUR_WRITE(b, llvm::X86::ST5, FPUR_READ(b, llvm::X86::ST6));
  FPUR_WRITE(b, llvm::X86::ST6, FPUR_READ(b, llvm::X86::ST7));
  FPUR_WRITE(b, llvm::X86::ST7, st0);
}

static llvm::Value *FPUM_READ(NativeInstPtr ip, int memwidth,
                              llvm::BasicBlock *&b, llvm::Value *addr) {
  auto &C = b->getContext();
  auto readLoc = addr;
  llvm::Type *ptrTy = nullptr;
  unsigned addrspace = ip->get_addr_space();

  switch (memwidth) {
    case 16:
      throw TErr(__LINE__, __FILE__, "HALFPTR TYPE NOT YET SUPPORTED!");
      break;
    case 32:
      ptrTy = llvm::Type::getFloatPtrTy(C, addrspace);
      break;
    case 64:
      ptrTy = llvm::Type::getDoublePtrTy(C, addrspace);
      break;
    case 80:
      ptrTy = llvm::Type::getX86_FP80PtrTy(C, addrspace);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "FPU TYPE NOT IMPLEMENTED!");
      break;
  }

  readLoc = ADDR_TO_POINTER_V(b, addr, ptrTy);

  auto read = noAliasMCSemaScope(new llvm::LoadInst(readLoc, "", b));

  // Convert precision - this is here for cases like FPU compares where the
  // compare would fail unless both precisions were adjusted.
  llvm::Value *extended = nullptr;

  if (memwidth < 80) {
    extended = new llvm::FPExtInst(read, llvm::Type::getX86_FP80Ty(C), "", b);
  } else if (memwidth == 80) {
    extended = read;
  } else {
    throw TErr(__LINE__, __FILE__, "Unsupported FPU type!");
  }

  // Precision adjust works on 80-bit FPU.
  auto precision_adjusted = adjustFpuPrecision(b, extended);

  // Re-truncate back to requested size.
  llvm::Value *returnval = nullptr;

  switch (memwidth) {
    case 32:
      returnval = new llvm::FPTruncInst(precision_adjusted, llvm::Type::getFloatTy(C),
                                  "", b);
      break;
    case 64:
      returnval = new llvm::FPTruncInst(precision_adjusted,
                                  llvm::Type::getDoubleTy(C), "", b);
      break;
    case 80:
      // Do nothing.
      returnval = precision_adjusted;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "FPU TYPE NOT IMPLEMENTED!");
      break;
  }

  return returnval;
}

// Create a new basic block and jump to it from the previous block.
// This is used to set the last FPU instruction pointer via BlockAddr later.
static llvm::BasicBlock *createNewFpuBlock(llvm::Function *F,
                                           llvm::BasicBlock *&b,
                                           std::string instname) {
  auto newb = llvm::BasicBlock::Create(
      F->getContext(), ("fpuinst_" + instname), F);
  (void) llvm::BranchInst::Create(newb, b);
  return newb;
}

static llvm::BasicBlock *createNewFpuBlock(llvm::BasicBlock *&b,
                                           std::string instName) {
  return createNewFpuBlock(b->getParent(), b, instName);
}

#define SET_STRUCT_MEMBER(st, index, member, b) do {\
    llvm::Value *stGEPV[] = {\
        CONST_V<32>(b, 0),\
        CONST_V<32>(b, index) };\
    auto gepreg = llvm::GetElementPtrInst::CreateInBounds(st, stGEPV, "", b);\
    auto storeIt = noAliasMCSemaScope(new llvm::StoreInst(member, gepreg, b));\
    NASSERT(storeIt != NULL);\
    } while(0);

template<int width, bool reverse>
static InstTransResult doFiOpMR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                MCSemaRegs dstReg, llvm::Value *memAddr,
                                unsigned opcode,
                                llvm::Instruction::BinaryOps fpop) {
  // Read register.
  auto dstVal = FPUR_READ(b, dstReg);

  // Read memory value.
  auto memVal = M_READ<width>(ip, b, memAddr);

  auto fp_mem_val = llvm::CastInst::Create(
      llvm::Instruction::SIToFP, memVal,
      llvm::Type::getX86_FP80Ty(b->getContext()), "", b);

  llvm::Value *result = nullptr;
  if (reverse == false) {
    result = llvm::BinaryOperator::Create(fpop, dstVal, fp_mem_val, "", b);
  } else {
    result = llvm::BinaryOperator::Create(fpop, fp_mem_val, dstVal, "", b);
  }

  // Store result in dstReg.
  FPUR_WRITE(b, dstReg, result);

  // Next instruction.
  return ContinueBlock;

}

template<int width, bool reverse>
static InstTransResult doFOpMR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               MCSemaRegs dstReg, llvm::Value *memAddr,
                               unsigned opcode,
                               llvm::Instruction::BinaryOps fpop) {
  // Read register.
  auto dstVal = FPUR_READ(b, dstReg);

  // Read memory value.
  auto memVal = FPUM_READ(ip, width, b, memAddr);

  // Extend memory value to be native FPU type.
  auto extVal = new llvm::FPExtInst(memVal,
                                    llvm::Type::getX86_FP80Ty(b->getContext()),
                                    "", b);

  llvm::Value *result = nullptr;
  if ( !reverse) {
    result = llvm::BinaryOperator::Create(fpop, dstVal, extVal, "", b);
  } else {
    result = llvm::BinaryOperator::Create(fpop, extVal, dstVal, "", b);
  }

  // Store result in dstReg.
  FPUR_WRITE(b, dstReg, result);

  // Next instruction.
  return ContinueBlock;
}

template<bool reverse>
static InstTransResult doFOpRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               MCSemaRegs srcReg, MCSemaRegs dstReg,
                               unsigned opcode,
                               llvm::Instruction::BinaryOps fpop) {
  // Load source.
  auto srcVal = FPUR_READ(b, srcReg);

  // Load destination.
  auto dstVal = FPUR_READ(b, dstReg);

  llvm::Value *result = nullptr;
  if ( !reverse) {
    result = llvm::BinaryOperator::Create(fpop, srcVal, dstVal, "", b);
  } else {
    result = llvm::BinaryOperator::Create(fpop, dstVal, srcVal, "", b);
  }

  // Store result in dstReg.
  FPUR_WRITE(b, dstReg, result);

  // Set if result is rounded up, clear otherwise.
  F_CLEAR(b, llvm::X86::FPU_C1);

  // Next instruction.
  return ContinueBlock;
}

template<bool reverse>
static InstTransResult doFOpPRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                MCSemaRegs srcReg, MCSemaRegs dstReg,
                                unsigned opcode,
                                llvm::Instruction::BinaryOps fpop) {
  // Do the operation.
  doFOpRR<reverse>(ip, b, srcReg, dstReg, opcode, fpop);

  // Pop the stack.
  FPU_POP(b);

  // Next instruction.
  return ContinueBlock;
}

static InstTransResult doFldcw(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  auto memPtr = ADDR_TO_POINTER<16>(b, memAddr);
  auto memVal = M_READ<16>(ip, b, memPtr);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_IM, 0);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_DM, 1);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_ZM, 2);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_OM, 3);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_UM, 4);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_PM, 5);
  SHR_SET_FLAG<16, 2>(b, memVal, llvm::X86::FPU_PC, 8);
  SHR_SET_FLAG<16, 2>(b, memVal, llvm::X86::FPU_RC, 10);
  SHR_SET_FLAG<16, 1>(b, memVal, llvm::X86::FPU_X, 12);
  return ContinueBlock;
}

static InstTransResult doFstcw(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  auto memPtr = ADDR_TO_POINTER<16>(b, memAddr);

  // Pre-clear reserved FPU bits.
  llvm::Value *cw = CONST_V<16>(b, 0x1F7F);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_IM, 0);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_DM, 1);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_ZM, 2);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_OM, 3);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_UM, 4);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_PM, 5);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_PC, 8);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_RC, 10);
  cw = SHL_NOTXOR_FLAG<16>(b, cw, llvm::X86::FPU_X, 12);

  (void) noAliasMCSemaScope(new llvm::StoreInst(cw, memPtr, b));

  return ContinueBlock;
}

template<int width>
static InstTransResult doFildM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  NASSERT(memAddr != NULL);

  // Read memory value.
  auto memVal = M_READ<width>(ip, b, memAddr);

  auto fp_mem_val = llvm::CastInst::Create(
      llvm::Instruction::SIToFP, memVal,
      llvm::Type::getX86_FP80Ty(b->getContext()), "", b);

  // Step 3: Adjust FPU stack: TOP = TOP - 1
  // Step 4: ST(0) = fpuVal
  FPU_PUSHV(b, fp_mem_val);

  // Next instruction.
  return ContinueBlock;
}

template<int width>
static InstTransResult doFldM(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *memAddr) {
  NASSERT(memAddr != NULL);

  // Step 1: read value from memory.
  auto memVal = FPUM_READ(ip, width, b, memAddr);

  // Step 2: Convert value to x87 double precision FP.
  auto fpuType = llvm::Type::getX86_FP80Ty(b->getContext());
  llvm::Value *fpuVal = nullptr;

  if ( !memVal->getType()->isX86_FP80Ty()) {
    fpuVal = new llvm::FPExtInst(memVal, fpuType, "", b);
  } else {
    fpuVal = memVal;
  }

  // Step 3: Adjust FPU stack: TOP = TOP - 1
  // Step 4: ST(0) = fpuVal

  FPU_PUSHV(b, fpuVal);

  // Step 5: set flags.

  // Next instruction.
  return ContinueBlock;
}

static InstTransResult doFldC(NativeInstPtr ip, llvm::BasicBlock *&b,
                              long double constv) {

  // load constant onto FPU stack
  auto fp_const = CONSTFP_V(b, constv);
  FPU_PUSHV(b, fp_const);
  return ContinueBlock;

}

static InstTransResult doFldR(NativeInstPtr ip, llvm::BasicBlock *&b,
                              const llvm::MCOperand &r) {
  // Make sure that this is a register.
  NASSERT(r.isReg());

  // Read register.
  auto srcVal = FPUR_READ(b, r.getReg());

  // Push value on stack.
  FPU_PUSHV(b, srcVal);

  // Next instruction.
  return ContinueBlock;
}

template<int width>
static InstTransResult doFistM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  NASSERT(memAddr != NULL);

  auto regVal = FPUR_READ(b, llvm::X86::ST0);
  auto ToInt = llvm::CastInst::Create(
      llvm::Instruction::FPToSI, regVal,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  M_WRITE<width>(ip, b, memAddr, ToInt);

  // Next instruction.
  return ContinueBlock;
}

template<int width>
static InstTransResult doFstM(NativeInstPtr ip, llvm::BasicBlock *&b,
                              llvm::Value *memAddr) {
  NASSERT(memAddr != NULL);
  auto &C = b->getContext();
  auto regVal = FPUR_READ(b, llvm::X86::ST0);
  llvm::Type *destType = nullptr;
  llvm::Type *ptrType = nullptr;
  unsigned addrspace = ip->get_addr_space();

  switch (width) {
    case 32:
      destType = llvm::Type::getFloatTy(C);
      ptrType = llvm::Type::getFloatPtrTy(C, addrspace);
      break;
    case 64:
      destType = llvm::Type::getDoubleTy(C);
      ptrType = llvm::Type::getDoublePtrTy(C, addrspace);
      break;
    case 80:
      //destType = llvm::Type::getX86_FP80Ty(C);
      ptrType = llvm::Type::getX86_FP80PtrTy(C, addrspace);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid width specified for FST");
      break;
  }

  // do not truncate 80-bit to 80-bit, causes a truncation error
  if (width < 80) {
    auto trunc = new llvm::FPTruncInst(regVal, destType, "", b);
    M_WRITE_T(ip, b, memAddr, trunc, ptrType);
  } else if (width == 80) {
    M_WRITE_T(ip, b, memAddr, regVal, ptrType);
  } else {
    throw TErr(__LINE__, __FILE__,
               "FPU Registers >80 bits not implemented for FST");
  }

  // Next instruction.
  return ContinueBlock;
}

template<int width>
static InstTransResult doFstpM(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *memAddr) {
  // Do the FST.
  doFstM<width>(ip, b, memAddr);

  // Pop the stack.
  FPU_POP(b);

  // Next instruction.
  return ContinueBlock;
}

// TODO: This is like FISTP, but FISTTP does not check rounding mode and
// always rounds to zero. 
template<int width>
static InstTransResult doFistTpM(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 llvm::Value *memAddr) {
  // Do the FST.
  doFistM<width>(ip, b, memAddr);

  // Pop the stack.
  FPU_POP(b);

  // Next instruction.
  return ContinueBlock;
}

template<int width>
static InstTransResult doFistpM(NativeInstPtr ip, llvm::BasicBlock *&b,
                                llvm::Value *memAddr) {
  // Do the FST.
  doFistM<width>(ip, b, memAddr);

  // Pop the stack.
  FPU_POP(b);

  // Next instruction.
  return ContinueBlock;
}

static InstTransResult doFstR(NativeInstPtr ip, llvm::BasicBlock *&b,
                              const llvm::MCOperand &r) {
  // Make sure that this is a register.
  NASSERT(r.isReg());

  // Read ST0.
  auto srcVal = FPUR_READ(b, llvm::X86::ST0);

  // Write register.
  FPUR_WRITE(b, r.getReg(), srcVal);

  // Next instruction.
  return ContinueBlock;
}

static InstTransResult doFstpR(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &r) {
  // Do the FST.
  doFstR(ip, b, r);

  // Pop the stack.
  FPU_POP(b);

  // Next instruction.
  return ContinueBlock;
}

static InstTransResult doFsin(NativeInstPtr ip, llvm::BasicBlock *&b,
                              MCSemaRegs reg) {
  auto M = b->getParent()->getParent();
  auto regval = FPUR_READ(b, reg);

  // get a declaration for llvm.fsin
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto fsin_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::sin, t);

  NASSERT(fsin_func != NULL);

  // call llvm.fsin(reg)
  std::vector<llvm::Value *> args;
  args.push_back(regval);

  auto fsin_val = llvm::CallInst::Create(fsin_func, args, "", b);

  // store return in reg
  FPUR_WRITE(b, reg, fsin_val);

  return ContinueBlock;
}

static InstTransResult doFucom(NativeInstPtr ip, llvm::BasicBlock *&b,
                               MCSemaRegs reg, unsigned int stackPops) {
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto sti_val = FPUR_READ(b, reg);

  // TODO: Make sure these treat negative zero and positive zero
  // as the same value.
  auto is_lt = new llvm::FCmpInst( *b, llvm::FCmpInst::FCMP_ULT, st0_val,
                                  sti_val);
  auto is_eq = new llvm::FCmpInst( *b, llvm::FCmpInst::FCMP_UEQ, st0_val,
                                  sti_val);

  // if BOTH the equql AND less than is true
  // it means that one of the ops is a QNaN

  auto lt_and_eq = llvm::BinaryOperator::CreateAnd(is_lt, is_eq, "", b);

  F_WRITE(b, llvm::X86::FPU_C0, is_lt);        // C0 is 1 if either is QNaN or op1 < op2
  F_WRITE(b, llvm::X86::FPU_C3, is_eq);        // C3 is 1 if either is QNaN or op1 == op2
  F_WRITE(b, llvm::X86::FPU_C2, lt_and_eq);    // C2 is 1 if either op is a QNaN

  while (stackPops > 0) {
    FPU_POP(b);
    stackPops -= 1;
  }

  return ContinueBlock;
}

static InstTransResult doFucomi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                unsigned reg, unsigned int stackPops) {
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto sti_val = FPUR_READ(b, reg);

  // TODO: Make sure these treat negative zero and positive zero
  // as the same value.
  auto is_lt = new llvm::FCmpInst( *b, llvm::FCmpInst::FCMP_ULT, st0_val,
                                  sti_val);
  auto is_eq = new llvm::FCmpInst( *b, llvm::FCmpInst::FCMP_UEQ, st0_val,
                                  sti_val);

  // if BOTH the equql AND less than is true
  // it means that one of the ops is a QNaN

  auto lt_and_eq = llvm::BinaryOperator::CreateAnd(is_lt, is_eq, "", b);

  F_WRITE(b, llvm::X86::CF, is_lt);        // C0 is 1 if either is QNaN or op1 < op2
  F_WRITE(b, llvm::X86::ZF, is_eq);        // C3 is 1 if either is QNaN or op1 == op2
  F_WRITE(b, llvm::X86::PF, lt_and_eq);    // C2 is 1 if either op is a QNaN

  while (stackPops > 0) {
    FPU_POP(b);
    stackPops -= 1;
  }

  return ContinueBlock;
}

static llvm::Value *EXT16_AND_SHL(llvm::BasicBlock *&b, MCSemaRegs reg, int shift, int mask) {
  auto &C = b->getContext();
  auto int16ty = llvm::Type::getInt16Ty(C);
  auto val = GENERIC_READREG(b, reg);
  val = new llvm::ZExtInst(val, int16ty, "", b);
  val = llvm::BinaryOperator::Create(
      llvm::Instruction::And, val,
      llvm::ConstantInt::get(val->getType(), mask), "", b);
  val = llvm::BinaryOperator::Create(
      llvm::Instruction::Shl, val,
      llvm::ConstantInt::get(val->getType(), shift), "", b);
  return val;
}

static llvm::Value *OR(llvm::BasicBlock *&b, llvm::Value *x, llvm::Value *y) {
  return llvm::BinaryOperator::Create(llvm::Instruction::Or, x, y, "", b);
}

static llvm::Value *doFstsV(llvm::BasicBlock *&b) {
  llvm::Value *sw = CONST_V<16>(b, 0);
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_IE, 0, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_DE, 1, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_ZE, 2, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_OE, 3, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_UE, 4, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_PE, 5, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_SF, 6, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_ES, 7, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_C0, 8, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_C1, 9, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_C2, 10, 1));
  // no top.
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_C3, 14, 1));
  sw = OR(b, sw, EXT16_AND_SHL(b, llvm::X86::FPU_B, 15, 1));
  return sw;
}

static InstTransResult doFstswm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                llvm::Value *memAddr) {
  auto memPtr = ADDR_TO_POINTER<16>(b, memAddr);
  auto status_word = doFstsV(b);
  M_WRITE<16>(ip, b, memPtr, status_word);
  return ContinueBlock;
}

static InstTransResult doFstswr(NativeInstPtr ip, llvm::BasicBlock *&b) {
  auto status_word = doFstsV(b);
  R_WRITE<16>(b, llvm::X86::AX, status_word);
  return ContinueBlock;
}

static InstTransResult doFxch(llvm::MCInst &inst, NativeInstPtr ip,
                              llvm::BasicBlock *&b) {
  // Check num operands.
  // No operands implies ST1
  unsigned src_reg = llvm::X86::ST1;
  if (inst.getNumOperands() > 0) {
    src_reg = inst.getOperand(0).getReg();
  }
  auto src_val = FPUR_READ(b, src_reg);
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  FPUR_WRITE(b, llvm::X86::ST0, src_val);
  FPUR_WRITE(b, src_reg, st0_val);

  return ContinueBlock;
}

static InstTransResult doF2XM1(llvm::MCInst &inst, NativeInstPtr ip,
                               llvm::BasicBlock *&b) {

  /*
   * Computes (2**st0)-1 and stores in ST0
   */

  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto exp_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::exp2, t);
  NASSERT(exp_func != nullptr);

  std::vector<llvm::Value *> args;

  args.push_back(st0_val);

  auto exp2_val = llvm::CallInst::Create(exp_func, args, "", b);
  auto one = CONSTFP_V(b, 1.0);
  auto exp2_m_1 = llvm::BinaryOperator::Create(llvm::Instruction::FSub,
                                               exp2_val, one, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST0, exp2_m_1);

  return ContinueBlock;
}

static InstTransResult doFSCALE(llvm::MCInst &inst, NativeInstPtr ip,
                                llvm::BasicBlock *&b) {

  /*
   * st0 = st0 * (2 ** RoundToZero(st1))
   */

  auto M = b->getParent()->getParent();
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto st1_val = FPUR_READ(b, llvm::X86::ST1);
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto exp_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::exp2, t);
  auto trunc_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trunc,
                                                    t);

  NASSERT(exp_func != nullptr);
  NASSERT(trunc_func != nullptr);

  // round st1 to zero
  std::vector<llvm::Value *> args;
  args.push_back(st1_val);
  auto trunc_st1_val = llvm::CallInst::Create(trunc_func, args, "", b);

  // calculate 2^st1
  std::vector<llvm::Value *> exp_args;
  exp_args.push_back(trunc_st1_val);
  auto exp2_val = llvm::CallInst::Create(exp_func, exp_args, "", b);

  // st0 * 2*st1
  auto scaled_val = llvm::BinaryOperator::Create(llvm::Instruction::FMul,
                                                 st0_val, exp2_val, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST0, scaled_val);

  return ContinueBlock;
}

template<bool p>
static InstTransResult doFYL2Xx(llvm::MCInst &inst, NativeInstPtr ip,
                                llvm::BasicBlock *&b) {

  /*
   * Computes (ST(1) ∗ log2(ST(0))), stores the result in ST(1), and pops the x87 register stack. The value
   * in ST(0) must be greater than zero.
   * If the zero-divide-exception mask (ZM) bit in the x87 control word is set to 1 and ST(0) contains ±zero, the instruction returns ∞ with the opposite sign of the value in register ST(1).
   */
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto st1_val = FPUR_READ(b, llvm::X86::ST1);
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto flog2_func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::log2,
                                                    t);

  NASSERT(flog2_func != NULL);

  std::vector<llvm::Value *> args;

  if (p) {  // FYLX2P1 case
    auto one = llvm::ConstantFP::get(llvm::Type::getX86_FP80Ty(b->getContext()),
                                     1.0);

    auto st0_plus_one = llvm::BinaryOperator::Create(llvm::Instruction::FAdd,
                                                     st0_val, one, "", b);
    args.push_back(st0_plus_one);
  } else {
    args.push_back(st0_val);
  }

  auto flog2_val = llvm::CallInst::Create(flog2_func, args, "", b);
  auto result = llvm::BinaryOperator::Create(llvm::Instruction::FMul, flog2_val,
                                             st1_val, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST1, result);
  FPU_POP(b);
  return ContinueBlock;
}

static InstTransResult doFRNDINT(llvm::MCInst &inst, NativeInstPtr ip,
                                 llvm::BasicBlock *&b) {
  auto M = b->getParent()->getParent();
  auto regVal = FPUR_READ(b, llvm::X86::ST0);
  auto fpTy = llvm::Type::getX86_FP80Ty(b->getContext());

  // get our intrinsics
  /// nearest
  auto round_nearest = llvm::Intrinsic::getDeclaration(
      M, llvm::Intrinsic::nearbyint, fpTy);

  // round will round away from zero
  auto round_down = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::round,
                                                    fpTy);

  // round will round away from zero
  auto round_up = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::round,
                                                  fpTy);

  // truncate
  auto round_zero = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trunc,
                                                    fpTy);

  CREATE_BLOCK(nearest, b);
  CREATE_BLOCK(down, b);
  CREATE_BLOCK(up, b);
  CREATE_BLOCK(zero, b);
  CREATE_BLOCK(finished, b);

  // switch on Rounding control
  auto rc = F_READ(b, llvm::X86::FPU_RC, 2);
  auto rcSwitch = llvm::SwitchInst::Create(rc, block_nearest, 4, b);
  rcSwitch->addCase(CONST_V<2>(b, 0), block_nearest);
  rcSwitch->addCase(CONST_V<2>(b, 1), block_down);
  rcSwitch->addCase(CONST_V<2>(b, 2), block_up);
  rcSwitch->addCase(CONST_V<2>(b, 3), block_zero);

  std::vector<llvm::Value *> args;
  args.push_back(regVal);

  auto nearest_val = llvm::CallInst::Create(round_nearest, args, "",
                                            block_nearest);
  llvm::BranchInst::Create(block_finished, block_nearest);

  auto down_val = llvm::CallInst::Create(round_down, args, "", block_down);
  llvm::BranchInst::Create(block_finished, block_down);

  auto up_val = llvm::CallInst::Create(round_up, args, "", block_up);
  llvm::BranchInst::Create(block_finished, block_up);

  auto zero_val = llvm::CallInst::Create(round_zero, args, "", block_zero);
  llvm::BranchInst::Create(block_finished, block_zero);

  // adjust to whichever branch we did
  auto roundedVal = llvm::PHINode::Create(
      llvm::Type::getX86_FP80Ty(block_finished->getContext()), 4, "fpu_round",
      block_finished);

  roundedVal->addIncoming(nearest_val, block_nearest);
  roundedVal->addIncoming(down_val, block_down);
  roundedVal->addIncoming(up_val, block_up);
  roundedVal->addIncoming(zero_val, block_zero);

  b = block_finished;

  // write it back
  FPUR_WRITE(b, llvm::X86::ST0, roundedVal);

  return ContinueBlock;
}

static InstTransResult doFABS(llvm::MCInst &inst, NativeInstPtr ip,
                              llvm::BasicBlock *&b) {

  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::fabs, t);
  std::vector<llvm::Value *> args;
  args.push_back(st0_val);
  auto result = llvm::CallInst::Create(func, args, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST0, result);

  return ContinueBlock;
}

static InstTransResult doFSQRT(llvm::MCInst &inst, NativeInstPtr ip,
                               llvm::BasicBlock *&b) {
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::sqrt, t);
  std::vector<llvm::Value *> args;
  args.push_back(st0_val);

  auto result = llvm::CallInst::Create(func, args, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST0, result);

  return ContinueBlock;
}

static InstTransResult doFCOS(llvm::MCInst &inst, NativeInstPtr ip,
                              llvm::BasicBlock *&b) {
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto func = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::cos, t);
  std::vector<llvm::Value *> args;
  args.push_back(st0_val);

  auto result = llvm::CallInst::Create(func, args, "", b);

  // store return in reg
  FPUR_WRITE(b, llvm::X86::ST0, result);

  /* XXX: If the radian value lies outside the valid range of –263
   *  to +263 radians, the instruction sets the C2 flag in the x87
   *  status word to 1 to indicate the value is out of range and
   *  does not change the value in ST(0).
   */

  return ContinueBlock;
}
static InstTransResult doFSINCOS(llvm::MCInst &inst, NativeInstPtr ip,
                                 llvm::BasicBlock *&b) {

  /*
   * Computes the sine and cosine of the value in ST(0), stores the sine in ST(0),
   *   and pushes the cosine onto the x87 register stack. The source value must be
   *   in the range –263 to +263 radians.
   */

  auto st0_val = FPUR_READ(b, llvm::X86::ST0);

  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto sin = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::sin, t);
  auto cos = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::cos, t);

  // Compute the sin of st(0)
  std::vector<llvm::Value *> args;
  args.push_back(st0_val);
  auto sin_result = llvm::CallInst::Create(sin, args, "", b);

  // store the result of the sin call back into st(0)
  FPUR_WRITE(b, llvm::X86::ST0, sin_result);

  // Compute the cos of st(0)
  args.clear();
  args.push_back(st0_val);
  auto cos_result = llvm::CallInst::Create(cos, args, "", b);

  // Push the result of the cos on the register stack
  FPU_PUSHV(b, cos_result);

  return ContinueBlock;
}

static InstTransResult doFINCSTP(llvm::MCInst &inst, NativeInstPtr ip,
                                 llvm::BasicBlock *&b) {
  FPU_PUSHV(b, FPUR_READ(b, llvm::X86::ST7));
  return ContinueBlock;
}

static InstTransResult doFDECSTP(llvm::MCInst &inst, NativeInstPtr ip,
                                 llvm::BasicBlock *&b) {
  FPU_POP(b);
  return ContinueBlock;
}

static InstTransResult doFPTAN(llvm::MCInst &inst, NativeInstPtr ip,
                               llvm::BasicBlock *&b) {
  auto M = b->getParent()->getParent();
  auto t = llvm::Type::getX86_FP80Ty(b->getContext());
  auto sin = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::sin, t);
  auto cos = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::cos, t);
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);

  // Compute the sin of st(0)
  std::vector<llvm::Value *> args;
  args.push_back(st0_val);
  auto sin_result = llvm::CallInst::Create(sin, args, "", b);

  // Compute the cos of st(0)
  args.clear();
  args.push_back(st0_val);
  auto cos_result = llvm::CallInst::Create(cos, args, "", b);

  // tan = sin/cos

  auto tan_result = llvm::BinaryOperator::Create(llvm::Instruction::FDiv,
                                                 sin_result, cos_result, "", b);

  FPUR_WRITE(b, llvm::X86::ST0, tan_result);
  auto one = CONSTFP_V(b, 1.0);
  FPU_PUSHV(b, one);
  return ContinueBlock;
}

static InstTransResult doCHS(llvm::MCInst &inst, NativeInstPtr ip,
                             llvm::BasicBlock *&b) {
  auto st0_val = FPUR_READ(b, llvm::X86::ST0);
  auto negone = CONSTFP_V(b, -1.0);
  auto signchange = llvm::BinaryOperator::Create(llvm::Instruction::FMul, st0_val,
                                           negone, "", b);
  FPUR_WRITE(b, llvm::X86::ST0, signchange);
  return ContinueBlock;
}

//mem_src =  IMM_AS_DATA_REF(block, natM, ip);
#define FPU_TRANSLATION(NAME, SETPTR, SETDATA, SETFOPCODE, ACCESSMEM, THECALL) \
    static InstTransResult translate_ ## NAME (TranslationContext &ctx, \
                                               llvm::BasicBlock *&block) { \
      auto natM = ctx.natM; \
      auto F = ctx.F; \
      auto ip = ctx.natI; \
      auto &inst = ip->get_inst(); \
      InstTransResult ret;\
      block = createNewFpuBlock(block, #NAME);\
      llvm::Value *mem_src = nullptr;\
      if (ACCESSMEM) {\
        if(ip->has_mem_reference) {\
          mem_src =  MEM_REFERENCE(0);\
        } else {\
          mem_src = ADDR_NOREF(0);\
        }\
      }\
      ret = THECALL;\
      (void)(natM);\
      (void)(F);\
      (void)(ip);\
      (void)(inst);\
      return ret;\
    }

/***************************
 ***************************

 WARNING WARNING WARNING

 ***************************
 ***************************

 Many of these templated functions take an argument
 named "reverse". This will reverse the order of operands
 in the instruction. It is used to have a common implementation
 for things like SUB and SUBR.

 *** for *DIV* instructions, reverse is the OPPOSITE of normal, since *DIV*
 instructions have an operand order opposite of other instructions ***
 ** EXCEPT for those that use memory operands. Since there is no write to
 memory, the order stays the same. Yes, this is confusing.**


 ***************************
 ***************************
 */

FPU_TRANSLATION(
    ADD_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::ADD_F32m,
                        llvm::Instruction::FAdd)))
FPU_TRANSLATION(
    ADD_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::ADD_F64m,
                        llvm::Instruction::FAdd)))
FPU_TRANSLATION(
    ADD_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::ADD_FI16m, llvm::Instruction::FAdd)))
FPU_TRANSLATION(
    ADD_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::ADD_FI32m, llvm::Instruction::FAdd)))
FPU_TRANSLATION(
    ADD_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(),
                    llvm::X86::ADD_FPrST0, llvm::Instruction::FAdd))
FPU_TRANSLATION(
    ADD_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, OP(0).getReg(), llvm::X86::ST0,
                   llvm::X86::ADD_FST0r, llvm::Instruction::FAdd))
FPU_TRANSLATION(
    ADD_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(),
                   llvm::X86::ADD_FrST0, llvm::Instruction::FAdd))
FPU_TRANSLATION(
    DIVR_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, true>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::DIVR_F32m,
                       llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIVR_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, true>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::DIVR_F64m,
                       llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIVR_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, true>(ip, block, llvm::X86::ST0, mem_src,
                        llvm::X86::DIVR_FI16m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIVR_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, true>(ip, block, llvm::X86::ST0, mem_src,
                        llvm::X86::DIVR_FI32m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIVR_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(),
                    llvm::X86::DIVR_FPrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(
    DIVR_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, OP(0).getReg(), llvm::X86::ST0,
                   llvm::X86::DIVR_FST0r, llvm::Instruction::FDiv))
FPU_TRANSLATION(
    DIVR_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(),
                   llvm::X86::DIVR_FrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(
    DIV_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::DIV_F32m,
                        llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIV_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::DIV_F64m,
                        llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIV_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::DIV_FI16m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIV_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::DIV_FI32m, llvm::Instruction::FDiv)))
FPU_TRANSLATION(
    DIV_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<true>(ip, block, llvm::X86::ST0, OP(0).getReg(),
                   llvm::X86::DIV_FPrST0, llvm::Instruction::FDiv))
FPU_TRANSLATION(
    DIV_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, OP(0).getReg(), llvm::X86::ST0,
                  llvm::X86::DIV_FST0r, llvm::Instruction::FDiv))
FPU_TRANSLATION(
    DIV_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::DIV_FrST0, llvm::Instruction::FDiv))

FPU_TRANSLATION(LD_F32m, true, true, true, true, doFldM<32>(ip, block, mem_src))
FPU_TRANSLATION(LD_F64m, true, true, true, true, doFldM<64>(ip, block, mem_src))
FPU_TRANSLATION(LD_F80m, true, true, true, true, doFldM<80>(ip, block, mem_src))
FPU_TRANSLATION(LD_Frr, true, false, true, false, doFldR(ip, block, OP(0)))
FPU_TRANSLATION(
    MUL_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::MUL_F32m,
                        llvm::Instruction::FMul)))
FPU_TRANSLATION(
    MUL_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::MUL_F64m,
                        llvm::Instruction::FMul)))
FPU_TRANSLATION(
    MUL_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::MUL_FI16m, llvm::Instruction::FMul)))
FPU_TRANSLATION(
    MUL_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::MUL_FI32m, llvm::Instruction::FMul)))
FPU_TRANSLATION(
    MUL_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::MUL_FPrST0, llvm::Instruction::FMul))
FPU_TRANSLATION(
    MUL_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, OP(0).getReg(), llvm::X86::ST0, llvm::X86::MUL_FST0r, llvm::Instruction::FMul))
FPU_TRANSLATION(
    MUL_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::MUL_FrST0, llvm::Instruction::FMul))
FPU_TRANSLATION(ST_F32m, true, true, true, true, doFstM<32>(ip, block, mem_src))
FPU_TRANSLATION(ST_F64m, true, true, true, true, doFstM<64>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP32m, true, true, true, true,
                doFstpM<32>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP64m, true, true, true, true,
                doFstpM<64>(ip, block, mem_src))
FPU_TRANSLATION(ST_FP80m, true, true, true, true,
                doFstpM<80>(ip, block, mem_src))
FPU_TRANSLATION(ST_FPrr, true, false, true, false, doFstpR(ip, block, OP(0)))
FPU_TRANSLATION(ST_Frr, true, false, true, false, doFstR(ip, block, OP(0)))
FPU_TRANSLATION(
    SUBR_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, true>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::SUBR_F32m,
                       llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUBR_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, true>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::SUBR_F64m,
                       llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUBR_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, true>(ip, block, llvm::X86::ST0, mem_src,
                        llvm::X86::SUBR_FI16m, llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUBR_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, true>(ip, block, llvm::X86::ST0, mem_src,
                        llvm::X86::SUBR_FI32m, llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUBR_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<true>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::SUBR_FPrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(
    SUBR_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, OP(0).getReg(), llvm::X86::ST0, llvm::X86::SUBR_FST0r, llvm::Instruction::FSub))
FPU_TRANSLATION(
    SUBR_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::SUBR_FrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(
    SUB_F32m,
    true,
    true,
    true,
    true,
    (doFOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::SUB_F32m,
                        llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUB_F64m,
    true,
    true,
    true,
    true,
    (doFOpMR<64, false>(ip, block, llvm::X86::ST0, mem_src, llvm::X86::SUB_F64m,
                        llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUB_FI16m,
    true,
    true,
    true,
    true,
    (doFiOpMR<16, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::SUB_FI16m, llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUB_FI32m,
    true,
    true,
    true,
    true,
    (doFiOpMR<32, false>(ip, block, llvm::X86::ST0, mem_src,
                         llvm::X86::SUB_FI32m, llvm::Instruction::FSub)))
FPU_TRANSLATION(
    SUB_FPrST0,
    true,
    false,
    true,
    false,
    doFOpPRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::SUB_FPrST0, llvm::Instruction::FSub))
FPU_TRANSLATION(
    SUB_FST0r,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, OP(0).getReg(), llvm::X86::ST0, llvm::X86::SUB_FST0r, llvm::Instruction::FSub))
FPU_TRANSLATION(
    SUB_FrST0,
    true,
    false,
    true,
    false,
    doFOpRR<false>(ip, block, llvm::X86::ST0, OP(0).getReg(), llvm::X86::SUB_FrST0, llvm::Instruction::FSub))

// take the remainder of (DST_VAL[st0] / SRC_VAL[st1]), store in st0
FPU_TRANSLATION(
    FPREM,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, llvm::X86::ST1, llvm::X86::ST0, llvm::X86::FPREM,
                  llvm::Instruction::FRem))
FPU_TRANSLATION(
    FPREM1,
    true,
    false,
    true,
    false,
    doFOpRR<true>(ip, block, llvm::X86::ST1, llvm::X86::ST0, llvm::X86::FPREM1,
                  llvm::Instruction::FRem))

FPU_TRANSLATION(SIN_F, true, false, true, false,
                doFsin(ip, block, llvm::X86::ST0))

FPU_TRANSLATION(LD_F0, true, false, true, false, doFldC(ip, block, 0.0))
FPU_TRANSLATION(LD_F1, true, false, true, false, doFldC(ip, block, 1.0))

FPU_TRANSLATION(FLDPI, true, false, true, false, doFldC(ip, block, M_PIl))
FPU_TRANSLATION(FLDLN2, true, false, true, false, doFldC(ip, block, M_LN2l))

FPU_TRANSLATION(FLDL2E, true, false, true, false, doFldC(ip, block, M_LOG2El))

FPU_TRANSLATION(FLDLG2, true, false, true, false, doFldC(ip, block, M_FLDLG2))

FPU_TRANSLATION(ILD_F16m, true, true, true, true,
                doFildM<16>(ip, block, mem_src))
FPU_TRANSLATION(ILD_F32m, true, true, true, true,
                doFildM<32>(ip, block, mem_src))
FPU_TRANSLATION(ILD_F64m, true, true, true, true,
                doFildM<64>(ip, block, mem_src))

FPU_TRANSLATION(FNSTCW16m, false, false, true, true,
                doFstcw(ip, block, mem_src))
FPU_TRANSLATION(FLDCW16m, false, false, true, true, doFldcw(ip, block, mem_src))

FPU_TRANSLATION(IST_F16m, true, true, true, true,
                doFistM<16>(ip, block, mem_src))
FPU_TRANSLATION(IST_F32m, true, true, true, true,
                doFistM<32>(ip, block, mem_src))

FPU_TRANSLATION(IST_FP16m, true, true, true, true,
                doFistpM<16>(ip, block, mem_src))
FPU_TRANSLATION(IST_FP32m, true, true, true, true,
                doFistpM<32>(ip, block, mem_src))
FPU_TRANSLATION(IST_FP64m, true, true, true, true,
                doFistpM<64>(ip, block, mem_src))

FPU_TRANSLATION(ISTT_FP64m, true, true, true, true,
                doFistTpM<64>(ip, block, mem_src))
FPU_TRANSLATION(ISTT_FP32m, true, true, true, true,
                doFistTpM<32>(ip, block, mem_src))
FPU_TRANSLATION(ISTT_FP16m, true, true, true, true,
                doFistTpM<16>(ip, block, mem_src))

FPU_TRANSLATION(XCH_F, true, false, true, false, doFxch(inst, ip, block))

FPU_TRANSLATION(FYL2X, true, false, true, false,
                doFYL2Xx<false>(inst, ip, block))
FPU_TRANSLATION(FYL2XP1, true, false, true, false,
                doFYL2Xx<true>(inst, ip, block))

FPU_TRANSLATION(UCOM_FPPr, true, false, true, false,
                doFucom(ip, block, llvm::X86::ST1, 2))
FPU_TRANSLATION(UCOM_FPr, true, false, true, false,
                doFucom(ip, block, OP(0).getReg(), 1))
FPU_TRANSLATION(UCOM_Fr, true, false, true, false,
                doFucom(ip, block, OP(0).getReg(), 0))

FPU_TRANSLATION(UCOM_FIPr, true, false, true, false,
                doFucomi(ip, block, OP(0).getReg(), 1))
FPU_TRANSLATION(UCOM_FIr, true, false, true, false,
                doFucomi(ip, block, OP(0).getReg(), 0))

FPU_TRANSLATION(FNSTSW16r, false, false, true, false, doFstswr(ip, block))
FPU_TRANSLATION(FNSTSWm, false, false, true, true, doFstswm(ip, block, mem_src))

FPU_TRANSLATION(FRNDINT, true, false, true, false, doFRNDINT(inst, ip, block))

FPU_TRANSLATION(F2XM1, true, false, true, false, doF2XM1(inst, ip, block))

FPU_TRANSLATION(FSCALE, true, false, true, false, doFSCALE(inst, ip, block))

FPU_TRANSLATION(FABS, true, false, true, false, doFABS(inst, ip, block))
FPU_TRANSLATION(FSQRT, true, false, true, false, doFSQRT(inst, ip, block))
FPU_TRANSLATION(FCOS, true, false, true, false, doFCOS(inst, ip, block))
FPU_TRANSLATION(FSINCOS, true, false, true, false, doFSINCOS(inst, ip, block))

FPU_TRANSLATION(FINCSTP, true, false, true, false, doFINCSTP(inst, ip, block))
FPU_TRANSLATION(FDECSTP, true, false, true, false, doFDECSTP(inst, ip, block))

FPU_TRANSLATION(FPTAN, true, false, true, false, doFPTAN(inst, ip, block))

FPU_TRANSLATION(CHS_F, true, false, true, false, doCHS(inst, ip, block))

static InstTransResult translate_WAIT(TranslationContext &, llvm::BasicBlock *&) {
  return ContinueBlock;
}

EXTERNAL_SEMANTICS(FXAM);

void FPU_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::ADD_F32m] = translate_ADD_F32m;
  m[llvm::X86::ADD_F64m] = translate_ADD_F64m;
  m[llvm::X86::ADD_FI16m] = translate_ADD_FI16m;
  m[llvm::X86::ADD_FI32m] = translate_ADD_FI32m;
  m[llvm::X86::ADD_FPrST0] = translate_ADD_FPrST0;
  m[llvm::X86::ADD_FST0r] = translate_ADD_FST0r;
  m[llvm::X86::ADD_FrST0] = translate_ADD_FrST0;
  m[llvm::X86::DIVR_F32m] = translate_DIVR_F32m;
  m[llvm::X86::DIVR_F64m] = translate_DIVR_F64m;
  m[llvm::X86::DIVR_FI16m] = translate_DIVR_FI16m;
  m[llvm::X86::DIVR_FI32m] = translate_DIVR_FI32m;
  m[llvm::X86::DIVR_FPrST0] = translate_DIVR_FPrST0;
  m[llvm::X86::DIVR_FST0r] = translate_DIVR_FST0r;
  m[llvm::X86::DIVR_FrST0] = translate_DIVR_FrST0;
  m[llvm::X86::DIV_F32m] = translate_DIV_F32m;
  m[llvm::X86::DIV_F64m] = translate_DIV_F64m;
  m[llvm::X86::DIV_FI16m] = translate_DIV_FI16m;
  m[llvm::X86::DIV_FI32m] = translate_DIV_FI32m;
  m[llvm::X86::DIV_FPrST0] = translate_DIV_FPrST0;
  m[llvm::X86::DIV_FST0r] = translate_DIV_FST0r;
  m[llvm::X86::DIV_FrST0] = translate_DIV_FrST0;
  m[llvm::X86::LD_F32m] = translate_LD_F32m;
  m[llvm::X86::LD_F64m] = translate_LD_F64m;
  m[llvm::X86::LD_F80m] = translate_LD_F80m;
  m[llvm::X86::LD_Frr] = translate_LD_Frr;
  m[llvm::X86::MUL_F32m] = translate_MUL_F32m;
  m[llvm::X86::MUL_F64m] = translate_MUL_F64m;
  m[llvm::X86::MUL_FI16m] = translate_MUL_FI16m;
  m[llvm::X86::MUL_FI32m] = translate_MUL_FI32m;
  m[llvm::X86::MUL_FPrST0] = translate_MUL_FPrST0;
  m[llvm::X86::MUL_FST0r] = translate_MUL_FST0r;
  m[llvm::X86::MUL_FrST0] = translate_MUL_FrST0;
  m[llvm::X86::ST_F32m] = translate_ST_F32m;
  m[llvm::X86::ST_F64m] = translate_ST_F64m;

  m[llvm::X86::IST_FP32m] = translate_IST_FP32m;
  m[llvm::X86::IST_FP64m] = translate_IST_FP64m;
  m[llvm::X86::IST_F32m] = translate_IST_F32m;
  m[llvm::X86::IST_F16m] = translate_IST_F16m;
  m[llvm::X86::IST_FP16m] = translate_IST_FP16m;

  m[llvm::X86::ISTT_FP64m] = translate_ISTT_FP64m;
  m[llvm::X86::ISTT_FP32m] = translate_ISTT_FP32m;
  m[llvm::X86::ISTT_FP16m] = translate_ISTT_FP16m;

  m[llvm::X86::ST_FP32m] = translate_ST_FP32m;
  m[llvm::X86::ST_FP64m] = translate_ST_FP64m;
  m[llvm::X86::ST_FP80m] = translate_ST_FP80m;
  m[llvm::X86::ST_FPrr] = translate_ST_FPrr;
  m[llvm::X86::ST_Frr] = translate_ST_Frr;
  m[llvm::X86::SUBR_F32m] = translate_SUBR_F32m;
  m[llvm::X86::SUBR_F64m] = translate_SUBR_F64m;
  m[llvm::X86::SUBR_FI16m] = translate_SUBR_FI16m;
  m[llvm::X86::SUBR_FI32m] = translate_SUBR_FI32m;
  m[llvm::X86::SUBR_FPrST0] = translate_SUBR_FPrST0;
  m[llvm::X86::SUBR_FST0r] = translate_SUBR_FST0r;
  m[llvm::X86::SUBR_FrST0] = translate_SUBR_FrST0;
  m[llvm::X86::SUB_F32m] = translate_SUB_F32m;
  m[llvm::X86::SUB_F64m] = translate_SUB_F64m;
  m[llvm::X86::SUB_FI16m] = translate_SUB_FI16m;
  m[llvm::X86::SUB_FI32m] = translate_SUB_FI32m;
  m[llvm::X86::SUB_FPrST0] = translate_SUB_FPrST0;
  m[llvm::X86::SUB_FST0r] = translate_SUB_FST0r;
  m[llvm::X86::SUB_FrST0] = translate_SUB_FrST0;

  m[llvm::X86::WAIT] = translate_WAIT;
  m[llvm::X86::SIN_F] = translate_SIN_F;
  m[llvm::X86::LD_F0] = translate_LD_F0;
  m[llvm::X86::LD_F1] = translate_LD_F1;
  m[llvm::X86::FLDPI] = translate_FLDPI;
  m[llvm::X86::FLDLN2] = translate_FLDLN2;
  m[llvm::X86::FLDL2E] = translate_FLDL2E;
  m[llvm::X86::FLDLG2] = translate_FLDLG2;

  m[llvm::X86::ILD_F16m] = translate_ILD_F16m;
  m[llvm::X86::ILD_F32m] = translate_ILD_F32m;
  m[llvm::X86::ILD_F64m] = translate_ILD_F64m;
  m[llvm::X86::FNSTCW16m] = translate_FNSTCW16m;
  m[llvm::X86::FLDCW16m] = translate_FLDCW16m;

  m[llvm::X86::XCH_F] = translate_XCH_F;

  m[llvm::X86::FYL2X] = translate_FYL2X;
  m[llvm::X86::FYL2XP1] = translate_FYL2XP1;

  m[llvm::X86::UCOM_FPPr] = translate_UCOM_FPPr;
  m[llvm::X86::UCOM_FPr] = translate_UCOM_FPr;
  m[llvm::X86::UCOM_Fr] = translate_UCOM_Fr;

  m[llvm::X86::UCOM_FIPr] = translate_UCOM_FIPr;
  m[llvm::X86::UCOM_FIr] = translate_UCOM_FIr;

  m[llvm::X86::FNSTSW16r] = translate_FNSTSW16r;
  m[llvm::X86::FNSTSWm] = translate_FNSTSWm;

  m[llvm::X86::FRNDINT] = translate_FRNDINT;
  m[llvm::X86::F2XM1] = translate_F2XM1;
  m[llvm::X86::FSCALE] = translate_FSCALE;

  m[llvm::X86::ABS_F] = translate_FABS;
  m[llvm::X86::SQRT_F] = translate_FSQRT;
  m[llvm::X86::COS_F] = translate_FCOS;
  m[llvm::X86::FPTAN] = translate_FPTAN;
  m[llvm::X86::FSINCOS] = translate_FSINCOS;

  m[llvm::X86::FDECSTP] = translate_FDECSTP;
  m[llvm::X86::FINCSTP] = translate_FINCSTP;

  m[llvm::X86::FPREM] = translate_FPREM;
  m[llvm::X86::FPREM1] = translate_FPREM1;

  m[llvm::X86::CHS_F] = translate_CHS_F;

  m[llvm::X86::FXAM] = translate_FXAM;
}

