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
#include "mcsema/Arch/X86/Semantics/SSE.h"
#include "mcsema/Arch/X86/Semantics/MOV.h"

#include "mcsema/BC/Util.h"

#include <tuple>

#define NASSERT(cond) TASSERT(cond, "")

static std::tuple<llvm::VectorType *, llvm::Type *> getIntVectorTypes(
    llvm::BasicBlock *b, int ewidth, int count) {
  auto elem_ty = llvm::Type::getIntNTy(b->getContext(), ewidth);
  auto vt = llvm::VectorType::get(elem_ty, count);

  return std::tuple<llvm::VectorType *, llvm::Type *>(vt, elem_ty);
}

static std::tuple<llvm::VectorType *, llvm::Type *> getFPVectorTypes(
    llvm::BasicBlock *b, int ewidth, int count) {
  llvm::Type *elem_ty = nullptr;

  switch (ewidth) {
    case 64:
      elem_ty = llvm::Type::getDoubleTy(b->getContext());
      break;
    case 32:
      elem_ty = llvm::Type::getFloatTy(b->getContext());
      break;
    default:
      TASSERT(false, "Invalid width for fp vector")
      ;
  }

  auto vt = llvm::VectorType::get(elem_ty, count);
  return std::tuple<llvm::VectorType *, llvm::Type *>(vt, elem_ty);
}

template<int width, int elementwidth>
static llvm::Value *INT_AS_VECTOR(llvm::BasicBlock *b, llvm::Value *input) {

  NASSERT(width % elementwidth == 0);

  unsigned count = width / elementwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elementwidth, count);

  // convert our base value to a vector
  return llvm::CastInst::Create(llvm::Instruction::BitCast, input, vt, "", b);
}

template<int width, int elementwidth>
static llvm::Value *INT_AS_FPVECTOR(llvm::BasicBlock *b, llvm::Value *input) {

  NASSERT(width % elementwidth == 0);

  unsigned count = width / elementwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getFPVectorTypes(b, elementwidth, count);

  // convert our base value to a vector
  return llvm::CastInst::Create(llvm::Instruction::BitCast, input, vt, "", b);
}

template<int width>
static llvm::Value *VECTOR_AS_INT(llvm::BasicBlock *b, llvm::Value *vector) {

  // convert our base value to a vector
  return llvm::CastInst::Create(llvm::Instruction::BitCast, vector,
                                llvm::Type::getIntNTy(b->getContext(), width),
                                "", b);
}

static llvm::Type *getFpTypeForWidth(const llvm::BasicBlock *block,
                                     int fpwidth) {
  llvm::Type *fpType = nullptr;

  switch (fpwidth) {
    case 32:
      fpType = llvm::Type::getFloatTy(block->getContext());
      break;
    case 64:
      fpType = llvm::Type::getDoubleTy(block->getContext());
      break;
    default:
      TASSERT(false, "Invalid width for getFpTypeForWidth")
      ;
  }

  return fpType;
}

template<int width>
static InstTransResult MOVAndZextRV(llvm::BasicBlock *& block,
                                    const llvm::MCOperand &dst,
                                    llvm::Value *src) {

  NASSERT(dst.isReg());

  llvm::Value *zext = src;

  if (width < 128) {
    zext = new llvm::ZExtInst(src,
                              llvm::Type::getIntNTy(block->getContext(), 128),
                              "", block);
  } else if (width > 128) {
    TASSERT(false, "Invalid width");
  }

  R_WRITE<128>(block, dst.getReg(), zext);
  return ContinueBlock;
}

template<int width>
static InstTransResult MOVAndZextRR(llvm::BasicBlock *& block,
                                    const llvm::MCOperand &dst,
                                    const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  auto src_val = R_READ<width>(block, src.getReg());

  return MOVAndZextRV<width>(block, dst, src_val);
}

template<int width>
static InstTransResult MOVAndZextRM(NativeInstPtr ip, llvm::BasicBlock *& block,
                                    const llvm::MCOperand &dst,
                                    llvm::Value *mem_val) {
  auto src_val = M_READ<width>(ip, block, mem_val);

  return MOVAndZextRV<width>(block, dst, src_val);
}

template<int width>
static InstTransResult doMOVSrm(TranslationContext &ctx,
                                llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  InstTransResult ret;
  auto F = block->getParent();
  // MOV from memory to XMM register will set the unused portion
  // of the XMM register to 0s.
  // Just set the whole thing to zero, and let the subsequent
  // write take care of the rest
  R_WRITE<128>(block, OP(0).getReg(), CONST_V<128>(block, 0));

  if (ip->has_external_ref()) {
    auto addrInt = getValueForExternal<width>(F->getParent(), ip, block);
    TASSERT(addrInt != nullptr, "Could not get address for external");
    ret = doRMMov<width>(ip, block, addrInt, OP(0));
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    ret = doRMMov<width>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 1),
                         OP(0));
  } else {
    ret = doRMMov<width>(ip, block, ADDR_NOREF(1), OP(0));
  }
  return ret;

}

template<int width>
static InstTransResult doMOVSmr(TranslationContext &ctx,
                                llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  InstTransResult ret;
  auto F = block->getParent();
  if (ip->has_external_ref()) {
    auto addrInt = getValueForExternal<width>(F->getParent(), ip, block);
    TASSERT(addrInt != nullptr, "Could not get address for external");
    return doMRMov<width>(ip, block, addrInt, OP(5));
  } else if (ip->has_mem_reference) {
    ret = doMRMov<width>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0),
                         OP(5));
  } else {
    ret = doMRMov<width>(ip, block, ADDR_NOREF(0), OP(5));
  }
  return ret;
}

template<int width, int op1, int op2>
static InstTransResult doMOVSrr(TranslationContext &ctx,
                                llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  return doRRMov<width>(ip, block, OP(op1), OP(op2));
}

template<int fpwidth>
static llvm::Value *INT_AS_FP(llvm::BasicBlock *&block, llvm::Value *in) {
  auto fpType = getFpTypeForWidth(block, fpwidth);
  return llvm::CastInst::Create(llvm::Instruction::BitCast, in, fpType, "",
                                block);
}

template<int fpwidth>
static llvm::Value *FP_AS_INT(llvm::BasicBlock *&block, llvm::Value *in) {
  auto intType = llvm::Type::getIntNTy(block->getContext(), fpwidth);
  return llvm::CastInst::Create(llvm::Instruction::BitCast, in, intType, "",
                                block);
}

template<int fpwidth>
static llvm::Value *INT_TO_FP_TO_INT(llvm::BasicBlock *&block,
                                     llvm::Value *in) {

  auto fpType = getFpTypeForWidth(block, fpwidth);
  auto intType = llvm::Type::getIntNTy(block->getContext(), fpwidth);

  //TODO: Check rounding modes!
  auto fp_value = llvm::CastInst::Create(llvm::Instruction::SIToFP, in, fpType,
                                         "", block);

  return llvm::CastInst::Create(llvm::Instruction::BitCast, fp_value, intType,
                                "", block);

}

template<int width>
static InstTransResult doCVTSI2SrV(NativeModulePtr natM,
                                   llvm::BasicBlock *&block, NativeInstPtr ip,
                                   llvm::MCInst &inst, llvm::Value *src,
                                   const llvm::MCOperand &dst) {

  auto final_v = INT_TO_FP_TO_INT<width>(block, src);
  // write them to destination
  R_WRITE<width>(block, dst.getReg(), final_v);

  return ContinueBlock;
}

// Converts a signed doubleword integer (or signed quadword integer if operand size is 64 bits) 
// in the second source operand to a double-precision floating-point value in the destination operand. 
// The result is stored in the low quad- word of the destination operand, and the high quadword left unchanged. 

template<int width>
static InstTransResult translate_CVTSI2SDrr(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const auto &dst = OP(0);
  const auto &src = OP(1);

  NASSERT(src.isReg());
  NASSERT(dst.isReg());

  // read reg from source
  auto rval = R_READ<width>(block, src.getReg());

  return doCVTSI2SrV<64>(natM, block, ip, inst, rval, dst);
}

template<int width>
static InstTransResult translate_CVTSI2SDrm(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const auto &dst = OP(0);
  NASSERT(dst.isReg());

  auto src = ADDR_NOREF(1);

  // read 32 bits from memory
  auto mval = M_READ<width>(ip, block, src);

  return doCVTSI2SrV<64>(natM, block, ip, inst, mval, dst);
}

//Converts a double-precision floating-point value in the source operand (second operand) 
//to a single-precision floating-point value in the destination operand (first operand).
template<int width>
static InstTransResult doCVTSD2SSrV(NativeModulePtr natM,
                                    llvm::BasicBlock *&block, NativeInstPtr ip,
                                    llvm::MCInst &inst, llvm::Value *src,
                                    const llvm::MCOperand &dst) {

  // convert the 64-bits we are reading into an FPU double
  //TODO: Check rounding modes!
  auto to_double = llvm::CastInst::Create(
      llvm::Instruction::BitCast, src,
      llvm::Type::getDoubleTy(block->getContext()), "", block);

  // Truncate double to a single
  auto fp_single = new llvm::FPTruncInst(
      to_double, llvm::Type::getFloatTy(block->getContext()), "", block);

  // treat the bits as a 32-bit int
  auto to_int = llvm::CastInst::Create(
      llvm::Instruction::BitCast, fp_single,
      llvm::Type::getIntNTy(block->getContext(), 32), "", block);

  // write them to destination
  R_WRITE<width>(block, dst.getReg(), to_int);

  return ContinueBlock;
}

// read 64-bits from memory, convert to single precision fpu value, 
// write the 32-bit value into register dst
static InstTransResult translate_CVTSD2SSrm(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  NASSERT(dst.isReg());

  llvm::Value *mem = ADDR_NOREF(1);

  llvm::Value *double_val = M_READ<64>(ip, block, mem);

  return doCVTSD2SSrV<32>(natM, block, ip, inst, double_val, dst);
}

// read 64-bits from register src, convert to single precision fpu value, 
// write the 32-bit value into register dst
static InstTransResult translate_CVTSD2SSrr(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  const llvm::MCOperand &src = OP(1);
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  // read 64 bits from source
  llvm::Value *rval = R_READ<64>(block, src.getReg());

  return doCVTSD2SSrV<32>(natM, block, ip, inst, rval, dst);
}

template<int width>
static InstTransResult doCVTSS2SDrV(NativeModulePtr natM,
                                    llvm::BasicBlock *& block, NativeInstPtr ip,
                                    llvm::MCInst &inst, llvm::Value *src,
                                    const llvm::MCOperand &dst) {

  // convert the 32 bits we read into an fpu single
  auto to_single = llvm::CastInst::Create(
      llvm::Instruction::BitCast, src,
      llvm::Type::getFloatTy(block->getContext()), "", block);

  // extend to a double
  llvm::Value *fp_double = new llvm::FPExtInst(
      to_single, llvm::Type::getDoubleTy(block->getContext()), "", block);

  // treat the bits as a 64-bit int
  llvm::Value *to_int = llvm::CastInst::Create(
      llvm::Instruction::BitCast, fp_double,
      llvm::Type::getIntNTy(block->getContext(), 64), "", block);

  // write them to destination
  R_WRITE<width>(block, dst.getReg(), to_int);

  return ContinueBlock;
}

// Convert Scalar Single-Precision FP llvm::Value to Scalar Double-Precision FP llvm::Value
// read 32-bits from memory, convert to double precision fpu value,
// write the 64-bit value into register dst
static InstTransResult translate_CVTSS2SDrm(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  NASSERT(dst.isReg());

  llvm::Value *mem = ADDR_NOREF(1);

  // read 32 bits from mem
  llvm::Value *single_val = M_READ<32>(ip, block, mem);

  return doCVTSS2SDrV<64>(natM, block, ip, inst, single_val, dst);
}

// Convert Scalar Single-Precision FP llvm::Value to Scalar Double-Precision FP llvm::Value
// read 32-bits from register src, convert to double precision fpu value,
// write the 64-bit value into register dst
static InstTransResult translate_CVTSS2SDrr(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  const llvm::MCOperand &src = OP(1);
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  // read 32 bits from source
  llvm::Value *rval = R_READ<32>(block, src.getReg());

  return doCVTSS2SDrV<64>(natM, block, ip, inst, rval, dst);
}

template<int width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_VV(unsigned reg, llvm::BasicBlock *& block,
                                     llvm::Value *o1, llvm::Value *o2) {
  llvm::Value *xoredVal = llvm::BinaryOperator::Create(bin_op, o1, o2, "",
                                                       block);
  R_WRITE<width>(block, reg, xoredVal);

  return ContinueBlock;
}

template<int width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_RR(NativeInstPtr ip,
                                     llvm::BasicBlock *& block,
                                     const llvm::MCOperand &o1,
                                     const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_INT_VV<width, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

template<int width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_RM(NativeInstPtr ip,
                                     llvm::BasicBlock *& block,
                                     const llvm::MCOperand &o1,
                                     llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  return do_SSE_INT_VV<width, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

// convert signed integer (register) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SSrr(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  const llvm::MCOperand &src = OP(1);

  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *src_val = R_READ<32>(block, src.getReg());

  return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);
}

// convert signed integer (memory) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SSrm(TranslationContext &ctx,
                                            llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  llvm::Value *mem_addr = ADDR_NOREF(1);

  NASSERT(dst.isReg());

  llvm::Value *src_val = M_READ<32>(ip, block, mem_addr);

  return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);

}

// convert signed integer (register) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SS64rr(TranslationContext &ctx,
                                              llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  const llvm::MCOperand &src = OP(1);

  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *src_val = R_READ<64>(block, src.getReg());

  return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);
}

// convert signed integer (memory) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SS64rm(TranslationContext &ctx,
                                              llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const llvm::MCOperand &dst = OP(0);
  llvm::Value *mem_addr = ADDR_NOREF(1);

  NASSERT(dst.isReg());

  llvm::Value *src_val = M_READ<64>(ip, block, mem_addr);

  return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);

}

template<int width, int regwidth>
static InstTransResult doCVTTS2SIrV(NativeModulePtr natM,
                                    llvm::BasicBlock *& block, NativeInstPtr ip,
                                    llvm::MCInst &inst, llvm::Value *src,
                                    const llvm::MCOperand &dst) {
  llvm::Value *final_v = nullptr;

  llvm::Value *to_int = llvm::CastInst::Create(
      llvm::Instruction::FPToSI, INT_AS_FP<width>(block, src),
      llvm::Type::getIntNTy(block->getContext(), regwidth), "", block);

  R_WRITE<regwidth>(block, dst.getReg(), to_int);

  return ContinueBlock;

}

// convert w/ truncation scalar single-precision fp value to dword integer
template<int fpwidth, int regwidth>
static InstTransResult doCVTT_to_SI_rm(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  const llvm::MCOperand &dst = OP(0);
  llvm::Value *mem_addr = ADDR_NOREF(1);

  NASSERT(dst.isReg());

  llvm::Value *src_val = M_READ<fpwidth>(ip, block, mem_addr);

  return doCVTTS2SIrV<fpwidth, regwidth>(natM, block, ip, inst, src_val, dst);

}

// convert w/ truncation scalar single-precision fp value (xmm reg) to dword integer
template<int fpwidth, int regwidth>
static InstTransResult doCVTT_to_SI_rr(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  const llvm::MCOperand &dst = OP(0);
  const llvm::MCOperand &src = OP(1);

  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *src_val = R_READ<fpwidth>(block, src.getReg());

  return doCVTTS2SIrV<fpwidth, regwidth>(natM, block, ip, inst, src_val, dst);

}

template<int fpwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VV(unsigned reg, llvm::BasicBlock *& block,
                                 llvm::Value *o1, llvm::Value *o2) {

  llvm::Value *sumVal = llvm::BinaryOperator::Create(
      bin_op, INT_AS_FP<fpwidth>(block, o1), INT_AS_FP<fpwidth>(block, o2), "",
      block);
  R_WRITE<fpwidth>(block, reg, FP_AS_INT<fpwidth>(block, sumVal));

  return ContinueBlock;
}

template<int fpwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_RR(NativeInstPtr ip, llvm::BasicBlock *& block,
                                 const llvm::MCOperand &o1,
                                 const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<fpwidth>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<fpwidth>(block, o2.getReg());

  return do_SSE_VV<fpwidth, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

template<int fpwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_RM(NativeInstPtr ip, llvm::BasicBlock *& block,
                                 const llvm::MCOperand &o1, llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<fpwidth>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<fpwidth>(ip, block, addr);

  return do_SSE_VV<fpwidth, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

static InstTransResult doUCOMISvv(llvm::BasicBlock *& block, llvm::Value *op1,
                                  llvm::Value *op2) {

  // TODO: Make sure these treat negative zero and positive zero
  // as the same value.
  llvm::Value *is_lt = new llvm::FCmpInst( *block, llvm::FCmpInst::FCMP_ULT,
                                          op1, op2);
  llvm::Value *is_eq = new llvm::FCmpInst( *block, llvm::FCmpInst::FCMP_UEQ,
                                          op1, op2);

  // if BOTH the equql AND less than is true
  // it means that one of the ops is a QNaN
  llvm::Value *is_qnan = llvm::BinaryOperator::CreateAnd(is_lt, is_eq, "",
                                                         block);

  F_WRITE(block, llvm::X86::ZF, is_eq);  // ZF is 1 if either is QNaN or op1 == op2
  F_WRITE(block, llvm::X86::PF, is_qnan);      // PF is 1 if either op is a QNaN
  F_WRITE(block, llvm::X86::CF, is_lt);  // CF is 1 if either is QNaN or op1 < op2

  F_WRITE(block, llvm::X86::OF, CONST_V<1>(block, 0));
  F_WRITE(block, llvm::X86::SF, CONST_V<1>(block, 0));
  F_WRITE(block, llvm::X86::AF, CONST_V<1>(block, 0));

  return ContinueBlock;
}

template<int width>
static InstTransResult doUCOMISrr(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &op1,
                                  const llvm::MCOperand &op2) {
  NASSERT(op1.isReg());
  NASSERT(op2.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = R_READ<width>(b, op2.getReg());

  llvm::Value *fp1_val = INT_AS_FP<width>(b, op1_val);
  llvm::Value *fp2_val = INT_AS_FP<width>(b, op2_val);

  return doUCOMISvv(b, fp1_val, fp2_val);

}

template<int width>
static InstTransResult doUCOMISrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &op1,
                                  llvm::Value *memAddr) {
  NASSERT(op1.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = M_READ<width>(ip, b, memAddr);

  llvm::Value *fp1_val = INT_AS_FP<width>(b, op1_val);
  llvm::Value *fp2_val = INT_AS_FP<width>(b, op2_val);

  return doUCOMISvv(b, fp1_val, fp2_val);
}

template<int elementwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult doNewShift(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *shift_count,
                                  llvm::Value *fallback = nullptr) {
  NASSERT(dst.isReg());
  NASSERT(128 % elementwidth == 0);

  llvm::Value *max_count = CONST_V<64>(b, elementwidth - 1);

  auto int_t = llvm::dyn_cast<llvm::IntegerType>(shift_count->getType());
  if (int_t->getBitWidth() > 64) {
    shift_count = new llvm::TruncInst(
        shift_count, llvm::Type::getIntNTy(b->getContext(), 64), "", b);
  }
  // check if our shift count is over the
  // allowable limit
  llvm::Value *countOverLimit = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_UGT,
                                                   shift_count, max_count);

  // max the shift count at elementwidth
  // real_count = over limit ? max count : original count
  llvm::Value *real_count = llvm::SelectInst::Create(countOverLimit, max_count,
                                                     shift_count, "", b);

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elementwidth,
                                            128 / elementwidth);

  // convert our base value to a vector
  llvm::Value *to_shift = R_READ<128>(b, dst.getReg());
  llvm::Value *vecValue = INT_AS_VECTOR<128, elementwidth>(b, to_shift);

  // truncate shift count to element size since we
  // need to shove it in a vector
  int_t = llvm::dyn_cast<llvm::IntegerType>(real_count->getType());
  auto elem_int_t = llvm::dyn_cast<llvm::IntegerType>(elem_ty);
  llvm::Value *trunc_shift = nullptr;

  // size of shift count has to be the size of the vector elements
  if (elem_int_t->getBitWidth() < int_t->getBitWidth()) {
    trunc_shift = new llvm::TruncInst(real_count, elem_ty, "", b);
  } else if (elem_int_t->getBitWidth() == int_t->getBitWidth()) {
    trunc_shift = real_count;
  } else {
    trunc_shift = new llvm::ZExtInst(real_count, elem_ty, "", b);
  }

  llvm::Value *vecShiftPtr = new llvm::AllocaInst(vt, nullptr, "", b);
  llvm::Value *shiftVector = noAliasMCSemaScope(
      new llvm::LoadInst(vecShiftPtr, "", b));

  int elem_count = 128 / elementwidth;

  // build a shift vector of elem_count
  // entries of trunc_shift
  for (int i = 0; i < elem_count; i++) {
    shiftVector = llvm::InsertElementInst::Create(shiftVector, trunc_shift,
                                                  CONST_V<32>(b, i), "", b);
  }

  // shift each element of the vector
  llvm::Value *shifted = llvm::BinaryOperator::Create(bin_op, vecValue,
                                                      shiftVector, "", b);

  // convert value back to a 128bit int
  llvm::Value *back_to_int = llvm::CastInst::Create(
      llvm::Instruction::BitCast, shifted,
      llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  // write back to register
  llvm::Value *final_to_write = back_to_int;

  // if this is an instruction that needs
  // a special case for shifts of
  // count >= width, then check for the fallback
  // option
  if (fallback != nullptr) {
    // yes,. this means all th work above was not
    // necessary. Ideally the optimizer will only
    // keep the fallback case. And this way
    // we don't need to generate multiple BBs
    final_to_write = llvm::SelectInst::Create(countOverLimit, fallback,
                                              back_to_int, "", b);
  }

  R_WRITE<128>(b, dst.getReg(), final_to_write);

  return ContinueBlock;
}

template<int width>
static InstTransResult doPSRArr(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  llvm::Value *shift_count = R_READ<128>(b, src.getReg());

  return doNewShift<width, llvm::Instruction::AShr>(b, dst, shift_count,
                                                    nullptr);
}

template<int width>
static InstTransResult doPSRArm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                llvm::Value *memAddr) {
  llvm::Value *shift_count = M_READ<128>(ip, b, memAddr);

  return doNewShift<width, llvm::Instruction::AShr>(b, dst, shift_count,
                                                    nullptr);
}

template<int width>
static InstTransResult doPSRAri(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isImm());

  llvm::Value *shift_count = CONST_V<128>(b, src.getImm());

  return doNewShift<width, llvm::Instruction::AShr>(b, dst, shift_count,
                                                    nullptr);
}

template<int width>
static InstTransResult doPSLLrr(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  llvm::Value *shift_count = R_READ<128>(b, src.getReg());

  return doNewShift<width, llvm::Instruction::Shl>(b, dst, shift_count,
                                                   CONST_V<128>(b, 0));
}

template<int width>
static InstTransResult doPSLLrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                llvm::Value *memAddr) {
  llvm::Value *shift_count = M_READ<128>(ip, b, memAddr);

  return doNewShift<width, llvm::Instruction::Shl>(b, dst, shift_count,
                                                   CONST_V<128>(b, 0));
}

template<int width>
static InstTransResult doPSRLrr(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  llvm::Value *shift_count = R_READ<128>(b, src.getReg());

  return doNewShift<width, llvm::Instruction::LShr>(b, dst, shift_count,
                                                    CONST_V<128>(b, 0));
}

template<int width>
static InstTransResult doPSRLrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                llvm::Value *memAddr) {
  llvm::Value *shift_count = M_READ<128>(ip, b, memAddr);

  return doNewShift<width, llvm::Instruction::LShr>(b, dst, shift_count,
                                                    CONST_V<128>(b, 0));
}

template<int width>
static InstTransResult doPSRLri(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isImm());

  llvm::Value *shift_count = CONST_V<128>(b, src.getImm());

  return doNewShift<width, llvm::Instruction::LShr>(b, dst, shift_count,
                                                    CONST_V<128>(b, 0));
}

template<int width>
static InstTransResult doPSLLri(llvm::BasicBlock *&b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  NASSERT(src.isImm());

  llvm::Value *shift_count = CONST_V<128>(b, src.getImm());

  return doNewShift<width, llvm::Instruction::Shl>(b, dst, shift_count,
                                                   CONST_V<128>(b, 0));
}

template<int width, int elemwidth>
static llvm::Value* doDoubleShuffle(llvm::BasicBlock *&b, llvm::Value *input1,
                                    llvm::Value *input2, unsigned order) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, input1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, input2);

  llvm::Value *vecShuffle;
  if (32 == elemwidth) {
    // Based on order, take two doublewords from first vector of 4 double words, and
    // two next two double words from second vector of 4 double words.
    llvm::Constant *shuffle_vec[4] = {CONST_V<32>(b, (order >> 0) & 3), CONST_V<
        32>(b, (order >> 2) & 3), CONST_V<32>(b,
                                              elem_count + ((order >> 4) & 3)),
        CONST_V<32>(b, elem_count + ((order >> 6) & 3)), };

    vecShuffle = llvm::ConstantVector::get(shuffle_vec);
  } else if (64 == elemwidth) {
    // Based on order, take one quadword from first vector of 2 quadwords,
    // and next quadword from second vector of 2 quadwords
    llvm::Constant *shuffle_vec[2] = {CONST_V<32>(b, (order >> 0) & 1), CONST_V<
        32>(b, elem_count + ((order >> 1) & 1)), };

    vecShuffle = llvm::ConstantVector::get(shuffle_vec);
  }
  // do the shuffle
  llvm::Value *shuffled = new llvm::ShuffleVectorInst(vecInput1, vecInput2,
                                                      vecShuffle, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, shuffled,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  return intOutput;
}

template<int width, int elemwidth>
static llvm::Value* doShuffle(llvm::BasicBlock *&b, llvm::Value *input,
                              unsigned order) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput = INT_AS_VECTOR<width, elemwidth>(b, input);

  llvm::Constant *shuffle_vec[4] = {CONST_V<32>(b, (order >> 0) & 3),
      CONST_V<32>(b, (order >> 2) & 3), CONST_V<32>(b, (order >> 4) & 3),
      CONST_V<32>(b, (order >> 6) & 3), };

  llvm::Value *vecShuffle = llvm::ConstantVector::get(shuffle_vec);

  // we are only shuffling one vector, so the
  // other one is undefined
  llvm::Value *vecUndef = llvm::UndefValue::get(vt);

  // do the shuffle
  llvm::Value *shuffled = new llvm::ShuffleVectorInst(vecInput, vecUndef,
                                                      vecShuffle, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, shuffled,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  return intOutput;
}

template<int width, int elemwidth>
static llvm::Value* doBlendVV(llvm::BasicBlock *&b, llvm::Value *input1,
                              llvm::Value *input2, llvm::Value *order) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, input1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, input2);

  llvm::Value *vecOrder = INT_AS_VECTOR<width, elemwidth>(b, order);

  llvm::Value *resultAlloc = new llvm::AllocaInst(vt, nullptr, "", b);
  llvm::Value *vecResult = noAliasMCSemaScope(
      new llvm::LoadInst(resultAlloc, "", b));

  for (int i = 0; i < elem_count; i++) {
    // get input value
    llvm::Value *toTest = llvm::ExtractElementInst::Create(vecOrder,
                                                           CONST_V<32>(b, i),
                                                           "", b);

    // check if high bit is set
    llvm::Value *highBitSet = llvm::BinaryOperator::CreateAnd(
        toTest, CONST_V<elemwidth>(b, 1 << (elemwidth - 1)), "", b);

    int mask = 0xF;
    switch (width) {
      case 128:
        mask = 0xF;
        break;
      case 64:
        mask = 0x7;
        break;
      default:
        TASSERT(false, "UNSUPPORTED BIT WIDTH FOR BLEND")
        ;
    }

    llvm::Value *origPiece = llvm::ExtractElementInst::Create(vecInput1,
                                                              CONST_V<32>(b, i),
                                                              "", b);
    llvm::Value *newPiece = llvm::ExtractElementInst::Create(vecInput2,
                                                             CONST_V<32>(b, i),
                                                             "", b);

    // check if high bit was not set
    llvm::Value *isZero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ,
                                             highBitSet,
                                             CONST_V<elemwidth>(b, 0));

    // pick either other byte position, or zero
    llvm::Value *whichValue = llvm::SelectInst::Create(isZero,  // if highBit is zero (aka not set), we keep old piece
        origPiece,  // use dst version
        newPiece,  // use src version (high bit is 1)
        "", b);

    vecResult = llvm::InsertElementInst::Create(vecResult, whichValue,
                                                CONST_V<32>(b, i), "", b);
  }

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, vecResult,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  return intOutput;
}

template<int width, int elemwidth>
static llvm::Value* doShuffleRR(llvm::BasicBlock *&b, llvm::Value *input,
                                llvm::Value *order) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput = INT_AS_VECTOR<width, elemwidth>(b, input);
  llvm::Value *vecOrder = INT_AS_VECTOR<width, elemwidth>(b, order);

  llvm::Value *resultAlloc = new llvm::AllocaInst(vt, nullptr, "", b);
  llvm::Value *vecResult = noAliasMCSemaScope(
      new llvm::LoadInst(resultAlloc, "", b));

  for (int i = 0; i < elem_count; i++) {
    // get input value
    llvm::Value *toTest = llvm::ExtractElementInst::Create(vecOrder,
                                                           CONST_V<32>(b, i),
                                                           "", b);

    // check if high bit is set
    llvm::Value *highBitSet = llvm::BinaryOperator::CreateAnd(
        toTest, CONST_V<elemwidth>(b, 1 << (elemwidth - 1)), "", b);

    int mask = 0xF;
    switch (width) {
      case 128:
        mask = 0xF;
        break;
      case 64:
        mask = 0x7;
        break;
      default:
        TASSERT(false, "UNSUPPORTED BIT WIDTH FOR PSHUFB")
        ;
    }

    // extract the low bits
    llvm::Value *lowBits = llvm::BinaryOperator::CreateAnd(
        toTest, CONST_V<elemwidth>(b, mask), "", b);

    llvm::Value *origPiece = llvm::ExtractElementInst::Create(vecInput, lowBits,
                                                              "", b);

    // check if high bit was not set
    llvm::Value *isZero = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ,
                                             highBitSet,
                                             CONST_V<elemwidth>(b, 0));

    // pick either other byte position, or zero
    llvm::Value *whichValue = llvm::SelectInst::Create(isZero,  // if highBit is zero (aka not set), we take a piece of the vector
        origPiece,  // vector piece
        CONST_V<elemwidth>(b, 0),  // if it is set, we take zero
        "", b);

    vecResult = llvm::InsertElementInst::Create(vecResult, whichValue,
                                                CONST_V<32>(b, i), "", b);
  }

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, vecResult,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  return intOutput;
}

template<int width>
static InstTransResult doBLENDVBrr(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *input1 = R_READ<width>(b, dst.getReg());
  llvm::Value *input2 = R_READ<width>(b, src.getReg());
  llvm::Value *order = R_READ<width>(b, llvm::X86::XMM0);

  llvm::Value *blended = doBlendVV<width, 8>(b, input1, input2, order);

  R_WRITE<width>(b, dst.getReg(), blended);
  return ContinueBlock;
}

template<int width>
static InstTransResult doBLENDVBrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *memAddr) {
  NASSERT(dst.isReg());
  NASSERT(memAddr != nullptr);

  llvm::Value *input1 = R_READ<width>(b, dst.getReg());
  llvm::Value *input2 = M_READ<width>(ip, b, memAddr);
  llvm::Value *order = R_READ<width>(b, llvm::X86::XMM0);

  llvm::Value *blended = doBlendVV<width, 8>(b, input1, input2, order);
  R_WRITE<width>(b, dst.getReg(), blended);
  return ContinueBlock;
}

template<int width>
static InstTransResult doPSHUFBrr(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *input = R_READ<width>(b, dst.getReg());
  llvm::Value *order = R_READ<width>(b, src.getReg());

  llvm::Value *shuffled = doShuffleRR<width, 8>(b, input, order);

  R_WRITE<width>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

template<int width>
static InstTransResult doPSHUFBrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *memAddr) {
  NASSERT(dst.isReg());
  NASSERT(memAddr != nullptr);

  llvm::Value *order = M_READ<width>(ip, b, memAddr);
  llvm::Value *input = R_READ<width>(b, dst.getReg());

  llvm::Value *shuffled = doShuffleRR<width, 8>(b, input, order);
  R_WRITE<width>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static InstTransResult doPSHUFDri(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  const llvm::MCOperand &src,
                                  const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *input = R_READ<128>(b, src.getReg());

  llvm::Value *shuffled = doShuffle<128, 32>(b, input, order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static InstTransResult doPSHUFDmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *mem_addr,
                                  const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(order.isImm());

  llvm::Value *input = M_READ<128>(ip, b, mem_addr);

  llvm::Value *shuffled = doShuffle<128, 32>(b, input, order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

template<int width, int elementwidth>
static llvm::Value* doInsertion(llvm::BasicBlock *&b, llvm::Value *input,
                                llvm::Value *what, unsigned position) {
  llvm::Value *vec = INT_AS_VECTOR<width, elementwidth>(b, input);

  llvm::Value *newvec = llvm::InsertElementInst::Create(
      vec, what, CONST_V<32>(b, position), "", b);

  llvm::Value *newint = VECTOR_AS_INT<width>(b, newvec);

  return newint;
}

static InstTransResult doPINSRWrri(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *vec = R_READ<128>(b, dst.getReg());
  llvm::Value *elem = R_READ<16>(b, src.getReg());

  llvm::Value *new_vec = doInsertion<128, 16>(b, vec, elem, order.getImm());

  R_WRITE<128>(b, dst.getReg(), new_vec);
  return ContinueBlock;
}

static InstTransResult doPINSRWrmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *memAddr,
                                   const llvm::MCOperand &order) {

  NASSERT(dst.isReg());
  NASSERT(order.isImm());

  llvm::Value *vec = R_READ<128>(b, dst.getReg());
  llvm::Value *elem = M_READ<16>(ip, b, memAddr);

  llvm::Value *new_vec = doInsertion<128, 16>(b, vec, elem, order.getImm());

  R_WRITE<128>(b, dst.getReg(), new_vec);
  return ContinueBlock;
}

template<int width, int elementwidth>
static llvm::Value* doExtraction(llvm::BasicBlock *&b, llvm::Value *input,
                                 unsigned position) {
  llvm::Value *vec = INT_AS_VECTOR<width, elementwidth>(b, input);

  llvm::Value *element = llvm::ExtractElementInst::Create(
      vec, CONST_V<32>(b, position), "", b);

  return element;
}

static InstTransResult doPEXTRWri(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  const llvm::MCOperand &src,
                                  const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *vec = R_READ<128>(b, src.getReg());

  llvm::Value *item = doExtraction<128, 16>(b, vec, order.getImm());

  // upper bits are set to zero
  llvm::Value *extItem = new llvm::ZExtInst(
      item, llvm::Type::getInt32Ty(b->getContext()), "", b);

  R_WRITE<32>(b, dst.getReg(), extItem);
  return ContinueBlock;
}

static InstTransResult doPEXTRWmr(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  llvm::Value *memAddr,
                                  const llvm::MCOperand &src,
                                  const llvm::MCOperand &order) {
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *vec = R_READ<128>(b, src.getReg());

  llvm::Value *item = doExtraction<128, 16>(b, vec, order.getImm());

  M_WRITE<16>(ip, b, memAddr, item);
  return ContinueBlock;
}

enum UnpackType {
  UNPACK_LOW,
  UNPACK_HIGH
};
template<int width, int elemwidth, UnpackType upt>
static llvm::Value* doUnpack(llvm::BasicBlock *&b, llvm::Value *v1,
                             llvm::Value *v2) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, v1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, v2);

  std::vector<llvm::Constant *> shuffle_vec;

  int elem_start = 0;
  if (upt == UNPACK_HIGH) {
    elem_start = elem_count / 2;
  }

  for (int i = 0; i < elem_count / 2; i++) {
    shuffle_vec.push_back(CONST_V<32>(b, elem_start + i + elem_count));
    shuffle_vec.push_back(CONST_V<32>(b, elem_start + i));
  }
  llvm::Value *vecShuffle = llvm::ConstantVector::get(shuffle_vec);

  // do the shuffle
  llvm::Value *shuffled = new llvm::ShuffleVectorInst(vecInput1, vecInput2,
                                                      vecShuffle, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, shuffled,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  return intOutput;
}

template<int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKVV(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst, llvm::Value *v1,
                                  llvm::Value *v2) {

  NASSERT(dst.isReg());

  llvm::Value *shuffled = doUnpack<width, slice_width, upt>(b, v1, v2);

  R_WRITE<width>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

template<int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKrr(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *srcVal = R_READ<width>(b, src.getReg());
  llvm::Value *dstVal = R_READ<width>(b, dst.getReg());

  return doPUNPCKVV<width, slice_width, upt>(b, dst, srcVal, dstVal);
}

template<int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *memAddr) {
  NASSERT(dst.isReg());
  NASSERT(memAddr != nullptr);

  llvm::Value *srcVal = M_READ<width>(ip, b, memAddr);
  llvm::Value *dstVal = R_READ<width>(b, dst.getReg());

  return doPUNPCKVV<width, slice_width, upt>(b, dst, srcVal, dstVal);
}

template<int width, int elemwidth, llvm::CmpInst::Predicate cmp_op>
static llvm::Value* do_SATURATED_SUB(llvm::BasicBlock *&b, llvm::Value *v1,
                                     llvm::Value *v2) {
  NASSERT(width % elemwidth == 0);
  int elem_count = width / elemwidth;
  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;
  llvm::Type *int32ty = llvm::Type::getIntNTy(b->getContext(), 32);
  llvm::VectorType *vt_int32ty = llvm::VectorType::get(int32ty, elem_count);

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);
  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, v1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, v2);

  // result = v1 - v2
  llvm::Value *op_result = llvm::BinaryOperator::Create(llvm::Instruction::Sub,
                                                        vecInput1, vecInput2,
                                                        "", b);

  // if v1 is => v2, then we keep the original value (mask with 0xFF...)
  // else, if v1 < v2, make it saturate to 0x00 (mask with 0x00...)
  // The mask can be made as a sign extend of the (v1 => v2) vector op

  llvm::Value *comparison = llvm::CmpInst::Create(llvm::Instruction::ICmp,
                                                  cmp_op, vecInput1, vecInput2,
                                                  "", b);
  // values we should keep get sign extended to 0b11111...
  // values we want to set to zero get sign extended to 0b000000...
  llvm::Value *saturate_mask = new llvm::SExtInst(comparison, vt, "", b);

  // mask result with the saturation mask
  llvm::Value *saturated = llvm::BinaryOperator::Create(llvm::Instruction::And,
                                                        op_result,
                                                        saturate_mask, "", b);

  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, saturated,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);
  return intOutput;
}

template<int width, int elemwidth, llvm::CmpInst::Predicate cmp_op>
static InstTransResult do_SATURATED_SUB_RR(NativeInstPtr ip,
                                           llvm::BasicBlock *& block,
                                           const llvm::MCOperand &o1,
                                           const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  llvm::Value *result = do_SATURATED_SUB<width, elemwidth, cmp_op>(block,
                                                                   opVal1,
                                                                   opVal2);
  R_WRITE<width>(block, o1.getReg(), result);
  return ContinueBlock;
}

template<int width, int elemwidth, llvm::CmpInst::Predicate cmp_op>
static InstTransResult do_SATURATED_SUB_RM(NativeInstPtr ip,
                                           llvm::BasicBlock *& block,
                                           const llvm::MCOperand &o1,
                                           llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  llvm::Value *result = do_SATURATED_SUB<width, elemwidth, cmp_op>(block,
                                                                   opVal1,
                                                                   opVal2);
  R_WRITE<width>(block, o1.getReg(), result);
  return ContinueBlock;
}

template<int width, int elemwidth, llvm::CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE(const llvm::MCOperand &dst,
                                      llvm::BasicBlock *&b, llvm::Value *v1,
                                      llvm::Value *v2) {
  NASSERT(width % elemwidth == 0);

  int elem_count = width / elemwidth;

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;

  std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, v1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, v2);

  llvm::Value *op_out = llvm::CmpInst::Create(llvm::Instruction::ICmp, cmp_op,
                                              vecInput1, vecInput2, "", b);

  // SExt to width since CmpInst returns
  // a vector of i1
  llvm::Value *sext_out = new llvm::SExtInst(op_out, vt, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, sext_out,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, dst.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, int elem_width, llvm::CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE_RM(NativeInstPtr ip,
                                         llvm::BasicBlock *& block,
                                         const llvm::MCOperand &o1,
                                         llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  return do_SSE_COMPARE<width, elem_width, cmp_op>(o1, block, opVal1, opVal2);
}

template<int width, int elem_width, llvm::CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE_RR(NativeInstPtr ip,
                                         llvm::BasicBlock *& block,
                                         const llvm::MCOperand &o1,
                                         const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_COMPARE<width, elem_width, cmp_op>(o1, block, opVal1, opVal2);
}

template<int width, int elemwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_OP(const llvm::MCOperand &dst,
                                        llvm::BasicBlock *&b, llvm::Value *v1,
                                        llvm::Value *v2) {
  NASSERT(width % elemwidth == 0);
  llvm::Value *vecInput1 = INT_AS_VECTOR<width, elemwidth>(b, v1);
  llvm::Value *vecInput2 = INT_AS_VECTOR<width, elemwidth>(b, v2);

  llvm::Value *op_out = llvm::BinaryOperator::Create(bin_op, vecInput1,
                                                     vecInput2, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, op_out,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, dst.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, int elemwidth, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_OP(const llvm::MCOperand &dst,
                                           llvm::BasicBlock *&b,
                                           llvm::Value *v1, llvm::Value *v2) {
  NASSERT(width % elemwidth == 0);
  llvm::Value *vecInput1 = INT_AS_FPVECTOR<width, elemwidth>(b, v1);
  llvm::Value *vecInput2 = INT_AS_FPVECTOR<width, elemwidth>(b, v2);

  llvm::Value *op_out = llvm::BinaryOperator::Create(bin_op, vecInput1,
                                                     vecInput2, "", b);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, op_out,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, dst.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, int elem_width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_RM(NativeInstPtr ip,
                                        llvm::BasicBlock *& block,
                                        const llvm::MCOperand &o1,
                                        llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  return do_SSE_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template<int width, int elem_width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_RR(NativeInstPtr ip,
                                        llvm::BasicBlock *& block,
                                        const llvm::MCOperand &o1,
                                        const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template<int width, int elem_width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_RM(NativeInstPtr ip,
                                           llvm::BasicBlock *& block,
                                           const llvm::MCOperand &o1,
                                           llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  return do_SSE_FP_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1,
                                                        opVal2);
}

template<int width, int elem_width, llvm::Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_RR(NativeInstPtr ip,
                                           llvm::BasicBlock *& block,
                                           const llvm::MCOperand &o1,
                                           const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_FP_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1,
                                                        opVal2);
}

template<llvm::FCmpInst::Predicate binop>
static llvm::Value* doMAXMINvv(llvm::BasicBlock *&block, llvm::Value *op1,
                               llvm::Value *op2) {

  // TODO: handle the zero case
  llvm::Value *is_gt = new llvm::FCmpInst( *block, binop, op1, op2);

  // if op1 > op2, use op1, else op2
  llvm::Value *which_op = llvm::SelectInst::Create(is_gt, op1, op2, "", block);

  return which_op;
}

template<int width, int elemwidth, llvm::FCmpInst::Predicate binop>
static InstTransResult doMAXMIN_FP_VECTOR_rr(llvm::BasicBlock *&b,
                                             const llvm::MCOperand &op1,
                                             const llvm::MCOperand &op2) {
  NASSERT(op1.isReg());
  NASSERT(op2.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = R_READ<width>(b, op2.getReg());

  NASSERT(width % elemwidth == 0);
  llvm::Value *vecInput1 = INT_AS_FPVECTOR<width, elemwidth>(b, op1_val);
  llvm::Value *vecInput2 = INT_AS_FPVECTOR<width, elemwidth>(b, op2_val);

  llvm::Value *max = doMAXMINvv<binop>(b, vecInput1, vecInput2);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, max,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, op1.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, int elemwidth, llvm::FCmpInst::Predicate binop>
static InstTransResult doMAXMIN_FP_VECTOR_rm(NativeInstPtr ip,
                                             llvm::BasicBlock *&b,
                                             const llvm::MCOperand &op1,
                                             llvm::Value *memAddr) {
  NASSERT(op1.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = M_READ<width>(ip, b, memAddr);

  NASSERT(width % elemwidth == 0);
  llvm::Value *vecInput1 = INT_AS_FPVECTOR<width, elemwidth>(b, op1_val);
  llvm::Value *vecInput2 = INT_AS_FPVECTOR<width, elemwidth>(b, op2_val);

  llvm::Value *max = doMAXMINvv<binop>(b, vecInput1, vecInput2);

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, max,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, op1.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, llvm::FCmpInst::Predicate binop>
static InstTransResult doMAXMINrr(llvm::BasicBlock *&b,
                                  const llvm::MCOperand &op1,
                                  const llvm::MCOperand &op2) {
  NASSERT(op1.isReg());
  NASSERT(op2.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = R_READ<width>(b, op2.getReg());

  llvm::Value *fp1_val = INT_AS_FP<width>(b, op1_val);
  llvm::Value *fp2_val = INT_AS_FP<width>(b, op2_val);

  llvm::Value *max = doMAXMINvv<binop>(b, fp1_val, fp2_val);
  R_WRITE<width>(b, op1.getReg(), FP_AS_INT<width>(b, max));
  return ContinueBlock;
}

template<int width, llvm::FCmpInst::Predicate binop>
static InstTransResult doMAXMINrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &op1,
                                  llvm::Value *memAddr) {
  NASSERT(op1.isReg());

  llvm::Value *op1_val = R_READ<width>(b, op1.getReg());
  llvm::Value *op2_val = M_READ<width>(ip, b, memAddr);

  llvm::Value *fp1_val = INT_AS_FP<width>(b, op1_val);
  llvm::Value *fp2_val = INT_AS_FP<width>(b, op2_val);

  llvm::Value *max = doMAXMINvv<binop>(b, fp1_val, fp2_val);
  R_WRITE<width>(b, op1.getReg(), FP_AS_INT<width>(b, max));
  return ContinueBlock;
}

template<int width>
static InstTransResult do_PANDNrr(NativeInstPtr ip, llvm::BasicBlock *& block,
                                  const llvm::MCOperand &o1,
                                  const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *notVal1 = llvm::BinaryOperator::CreateNot(opVal1, "", block);
  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_INT_VV<width, llvm::Instruction::And>(o1.getReg(), block,
                                                      notVal1, opVal2);
}

template<int width>
static InstTransResult do_PANDNrm(NativeInstPtr ip, llvm::BasicBlock *& block,
                                  const llvm::MCOperand &o1,
                                  llvm::Value *addr) {
  NASSERT(o1.isReg());

  llvm::Value *opVal1 = R_READ<width>(block, o1.getReg());
  llvm::Value *notVal1 = llvm::BinaryOperator::CreateNot(opVal1, "", block);
  llvm::Value *opVal2 = M_READ<width>(ip, block, addr);

  return do_SSE_INT_VV<width, llvm::Instruction::And>(o1.getReg(), block,
                                                      notVal1, opVal2);
}

enum ExtendOp {
  SEXT,
  ZEXT
};

template<int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_OP(const llvm::MCOperand &dst,
                                        llvm::BasicBlock *&b, llvm::Value *v1) {
  NASSERT(width % srcelem == 0);
  NASSERT(width % dstelem == 0);
  TASSERT(dstelem > srcelem, "Must use SSE extend to a bigger element size");

  int src_elem_count = width / srcelem;
  int dst_elem_count = width / dstelem;

  llvm::Type *src_elem_ty = nullptr;
  llvm::Type *dst_elem_ty = nullptr;
  llvm::VectorType *src_vt = nullptr;
  llvm::VectorType *dst_vt = nullptr;

  std::tie(src_vt, src_elem_ty) = getIntVectorTypes(b, srcelem, src_elem_count);
  std::tie(dst_vt, dst_elem_ty) = getIntVectorTypes(b, dstelem, dst_elem_count);

  // read input vector
  llvm::Value *vecInput1 = INT_AS_VECTOR<width, srcelem>(b, v1);

  llvm::Value *resultAlloc = new llvm::AllocaInst(dst_vt, nullptr, "", b);
  llvm::Value *vecResult = noAliasMCSemaScope(
      new llvm::LoadInst(resultAlloc, "", b));

  // we take lower dst_elem_count values
  for (int i = 0; i < dst_elem_count; i++) {
    // read source element
    llvm::Value *item = llvm::ExtractElementInst::Create(vecInput1,
                                                         CONST_V<32>(b, i), "",
                                                         b);
    llvm::Value *newitem = nullptr;
    // op it to dst element type
    switch (op) {
      case SEXT:
        newitem = new llvm::SExtInst(item, dst_elem_ty, "", b);
        break;
      case ZEXT:
        newitem = new llvm::ZExtInst(item, dst_elem_ty, "", b);
        break;
      default:
        TASSERT(false, "Invalid operation for do_SSE_EXTEND_OP")
        ;
    }

    // store dst element
    vecResult = llvm::InsertElementInst::Create(vecResult, newitem,
                                                CONST_V<32>(b, i), "", b);

  }

  // convert the output back to an integer
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, vecResult,
      llvm::Type::getIntNTy(b->getContext(), width), "", b);

  R_WRITE<width>(b, dst.getReg(), intOutput);
  return ContinueBlock;
}

template<int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_RM(NativeInstPtr ip,
                                        llvm::BasicBlock *& block,
                                        const llvm::MCOperand &o1,
                                        llvm::Value *addr) {
  NASSERT(o1.isReg());

  // memory operands are weird -- its the minimum
  // bytes needed to unpack to width / dstelem
  const int count = width / dstelem * srcelem;
  TASSERT(count < width, "Must SSE extend to greater size");
  llvm::dbgs() << "Reading: " << count << " bytes\n";
  llvm::Value *opVal1 = M_READ<count>(ip, block, addr);

  llvm::Value *zext = new llvm::ZExtInst(
      opVal1, llvm::Type::getIntNTy(block->getContext(), width), "", block);

  return do_SSE_EXTEND_OP<width, srcelem, dstelem, op>(o1, block, zext);
}

template<int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_RR(NativeInstPtr ip,
                                        llvm::BasicBlock *& block,
                                        const llvm::MCOperand &o1,
                                        const llvm::MCOperand &o2) {
  NASSERT(o1.isReg());
  NASSERT(o2.isReg());

  llvm::Value *opVal2 = R_READ<width>(block, o2.getReg());

  return do_SSE_EXTEND_OP<width, srcelem, dstelem, op>(o1, block, opVal2);
}

template<int width>
static InstTransResult doMOVHLPSrr(NativeInstPtr ip, llvm::BasicBlock *b,
                                   const llvm::MCOperand &dest,
                                   const llvm::MCOperand &src) {
  NASSERT(dest.isReg());
  NASSERT(src.isReg());

  llvm::Value *r_dest = R_READ<width>(b, dest.getReg());
  llvm::Value *r_src = R_READ<width>(b, src.getReg());

  // capture top half of src
  llvm::Value *dest_keep = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, r_dest, CONST_V<width>(b, width / 2), "", b);
  // put it back in top part
  dest_keep = llvm::BinaryOperator::Create(llvm::Instruction::Shl, dest_keep,
                                           CONST_V<width>(b, width / 2), "", b);

  // get top of src
  llvm::Value *src_keep = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, r_src, CONST_V<width>(b, width / 2), "", b);

  // or top half of src with the old
  // top half of dst, which is now the bottom
  llvm::Value *res = llvm::BinaryOperator::Create(llvm::Instruction::Or,
                                                  src_keep, dest_keep, "", b);

  R_WRITE<width>(b, dest.getReg(), res);
  return ContinueBlock;
}

template<int width>
static InstTransResult doMOVLHPSrr(NativeInstPtr ip, llvm::BasicBlock *b,
                                   const llvm::MCOperand &dest,
                                   const llvm::MCOperand &src) {
  NASSERT(dest.isReg());
  NASSERT(src.isReg());

  llvm::Value *r_dest = R_READ<width>(b, dest.getReg());
  llvm::Value *r_src = R_READ<width>(b, src.getReg());

  // put low into high
  llvm::Value* dest_keep = llvm::BinaryOperator::Create(
      llvm::Instruction::Shl, r_src, CONST_V<width>(b, width / 2), "", b);

  TASSERT(width >= 64, "Can't truncate from smaller width");

  llvm::Value* bottom_part = new llvm::TruncInst(
      r_dest, llvm::Type::getIntNTy(b->getContext(), 64), "", b);
  llvm::Value *zext = new llvm::ZExtInst(
      bottom_part, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  // or top half of src with the old
  // top half of dst, which is now the bottom
  llvm::Value *res = llvm::BinaryOperator::Create(llvm::Instruction::Or, zext,
                                                  dest_keep, "", b);

  R_WRITE<width>(b, dest.getReg(), res);
  return ContinueBlock;
}

static llvm::Value *doPMULUDQVV(llvm::BasicBlock *b, llvm::Value *dest,
                                llvm::Value *src) {

  // get top of src
  llvm::Value *vecSrc = INT_AS_VECTOR<128, 32>(b, src);
  llvm::Value *vecDst = INT_AS_VECTOR<128, 32>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *src2 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 2), "",
                                                       b);

  llvm::Value *src1_e = new llvm::ZExtInst(
      src1, llvm::Type::getIntNTy(b->getContext(), 128), "", b);
  llvm::Value *src2_e = new llvm::ZExtInst(
      src2, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  llvm::Value *dst1 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *dst2 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 2), "",
                                                       b);

  llvm::Value *dst1_e = new llvm::ZExtInst(
      dst1, llvm::Type::getIntNTy(b->getContext(), 128), "", b);
  llvm::Value *dst2_e = new llvm::ZExtInst(
      dst2, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  llvm::Value *res1 = llvm::BinaryOperator::Create(llvm::Instruction::Mul,
                                                   src1_e, dst1_e, "", b);

  llvm::Value *res2 = llvm::BinaryOperator::Create(llvm::Instruction::Mul,
                                                   src2_e, dst2_e, "", b);

  llvm::Value *res_shift = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                        res2,
                                                        CONST_V<128>(b, 64), "",
                                                        b);

  llvm::Value *res_or = llvm::BinaryOperator::Create(llvm::Instruction::Or,
                                                     res_shift, res1, "", b);

  return res_or;
}

static InstTransResult doPMULUDQrr(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());

  llvm::Value *srcVal = R_READ<128>(b, src.getReg());
  llvm::Value *dstVal = R_READ<128>(b, dst.getReg());

  llvm::Value *res = doPMULUDQVV(b, dstVal, srcVal);
  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static InstTransResult doPMULUDQrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *memAddr) {
  NASSERT(dst.isReg());

  llvm::Value *dstVal = R_READ<128>(b, dst.getReg());
  llvm::Value *srcVal = M_READ<128>(ip, b, memAddr);
  llvm::Value *res = doPMULUDQVV(b, dstVal, srcVal);
  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static InstTransResult doMOVHPDmr(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  llvm::Value *memAddr,
                                  const llvm::MCOperand &src) {
  NASSERT(src.isReg());

  llvm::Value *dstVal = R_READ<128>(b, src.getReg());

  llvm::Value *sright = llvm::BinaryOperator::Create(llvm::Instruction::LShr,
                                                     dstVal,
                                                     CONST_V<128>(b, 64), "",
                                                     b);

  llvm::Value *trunc_upper_64 = new llvm::TruncInst(
      sright, llvm::Type::getIntNTy(b->getContext(), 64), "", b);

  M_WRITE<64>(ip, b, memAddr, trunc_upper_64);
  return ContinueBlock;
}

static InstTransResult doMOVHPDrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *memAddr) {
  NASSERT(dst.isReg());

  llvm::Value *dstVal = R_READ<128>(b, dst.getReg());
  llvm::Value *srcVal = M_READ<64>(ip, b, memAddr);

  // Extend the type of src to 128 bits
  llvm::Value *srcExt = new llvm::ZExtInst(
      srcVal, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  //Left sheft 64 LSB to hihger quadword
  llvm::Value *srcLShift = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                        srcExt,
                                                        CONST_V<128>(b, 64), "",
                                                        b);

  //Clean up the upper 64 bits of dest reg
  llvm::Value *sleft = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                    dstVal, CONST_V<128>(b, 64),
                                                    "", b);
  llvm::Value *sright = llvm::BinaryOperator::Create(llvm::Instruction::LShr,
                                                     sleft, CONST_V<128>(b, 64),
                                                     "", b);

  llvm::Value *ored = llvm::BinaryOperator::Create(llvm::Instruction::Or,
                                                   sright, srcLShift, "", b);

  R_WRITE<128>(b, dst.getReg(), ored);
  return ContinueBlock;
}

static InstTransResult doMOVLPDrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  const llvm::MCOperand &dst,
                                  llvm::Value *memAddr) {
  NASSERT(dst.isReg());

  llvm::Value *dstVal = R_READ<128>(b, dst.getReg());
  llvm::Value *srcVal = M_READ<64>(ip, b, memAddr);

  llvm::Value *srcExt = new llvm::ZExtInst(
      srcVal, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  llvm::Value *sright = llvm::BinaryOperator::Create(llvm::Instruction::LShr,
                                                     dstVal,
                                                     CONST_V<128>(b, 64), "",
                                                     b);
  llvm::Value *sleft = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                    sright, CONST_V<128>(b, 64),
                                                    "", b);

  llvm::Value *ored = llvm::BinaryOperator::Create(llvm::Instruction::Or, sleft,
                                                   srcExt, "", b);

  R_WRITE<128>(b, dst.getReg(), ored);
  return ContinueBlock;
}

llvm::Value *doCVTTPS2DQvv(llvm::BasicBlock *&b, llvm::Value *in) {
  // read in as FP vector
  //
  llvm::Value *fpv = INT_AS_FPVECTOR<128, 32>(b, in);
  //
  // truncate
  //
  //

  llvm::Type *elem_ty = nullptr;
  llvm::VectorType *vt = nullptr;
  std::tie(vt, elem_ty) = getIntVectorTypes(b, 32, 4);

  llvm::Value *as_ints = llvm::CastInst::Create(llvm::Instruction::FPToSI, fpv,
                                                vt, "", b);

  // cast as int
  llvm::Value *intOutput = llvm::CastInst::Create(
      llvm::Instruction::BitCast, as_ints,
      llvm::Type::getIntNTy(b->getContext(), 128), "", b);
  // return
  return intOutput;
}

static InstTransResult doCVTTPS2DQrm(NativeInstPtr ip, llvm::BasicBlock *&b,
                                     const llvm::MCOperand &dst,
                                     llvm::Value *memAddr) {
  NASSERT(dst.isReg());
  NASSERT(memAddr != nullptr);

  llvm::Value *memval = M_READ<128>(ip, b, memAddr);
  llvm::Value *out = doCVTTPS2DQvv(b, memval);
  R_WRITE<128>(b, dst.getReg(), out);

  return ContinueBlock;
}

static InstTransResult doCVTTPS2DQrr(llvm::BasicBlock *&b,
                                     const llvm::MCOperand &dst,
                                     const llvm::MCOperand &src)

                                     {
  NASSERT(dst.isReg());

  llvm::Value *inval = R_READ<128>(b, src.getReg());
  llvm::Value *out = doCVTTPS2DQvv(b, inval);
  R_WRITE<128>(b, dst.getReg(), out);

  return ContinueBlock;
}

static InstTransResult doSHUFPDrri(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *input1 = R_READ<128>(b, src.getReg());
  llvm::Value *input2 = R_READ<128>(b, dst.getReg());

  llvm::Value *shuffled = doDoubleShuffle<128, 64>(b, input2, input1,
                                                   order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static InstTransResult doSHUFPDrmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *mem_addr,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(order.isImm());
  NASSERT(mem_addr != nullptr);

  llvm::Value *input1 = M_READ<128>(ip, b, mem_addr);
  llvm::Value *input2 = R_READ<128>(b, dst.getReg());

  llvm::Value *shuffled = doDoubleShuffle<128, 64>(b, input2, input1,
                                                   order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static InstTransResult doSHUFPSrri(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *input1 = R_READ<128>(b, src.getReg());
  llvm::Value *input2 = R_READ<128>(b, dst.getReg());

  llvm::Value *shuffled = doDoubleShuffle<128, 32>(b, input2, input1,
                                                   order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static InstTransResult doSHUFPSrmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *mem_addr,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(order.isImm());
  NASSERT(mem_addr != nullptr);

  llvm::Value *input1 = M_READ<128>(ip, b, mem_addr);
  llvm::Value *input2 = R_READ<128>(b, dst.getReg());

  llvm::Value *shuffled = doDoubleShuffle<128, 32>(b, input2, input1,
                                                   order.getImm());

  R_WRITE<128>(b, dst.getReg(), shuffled);
  return ContinueBlock;
}

static llvm::Value* doPSHUFHWvv(llvm::BasicBlock *&b, llvm::Value *in,
                                llvm::Value *dstVal,
                                const llvm::MCOperand &order) {
  llvm::Value *shuffled = doShuffle<64, 16>(b, in, order.getImm());

  llvm::Value *shufExt = new llvm::ZExtInst(
      shuffled, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  llvm::Value *shufAdjusted = llvm::BinaryOperator::Create(
      llvm::Instruction::Shl, shufExt, CONST_V<128>(b, 64), "", b);

  // Clear the bits [127:64] of dstVal
  llvm::Value *sleft = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                    dstVal, CONST_V<128>(b, 64),
                                                    "", b);
  llvm::Value *sright = llvm::BinaryOperator::Create(llvm::Instruction::LShr,
                                                     sleft, CONST_V<128>(b, 64),
                                                     "", b);

  llvm::Value *ored = llvm::BinaryOperator::Create(llvm::Instruction::Or,
                                                   sright, shufAdjusted, "", b);

  return ored;
}

static InstTransResult doPSHUFHWri(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *input1 = R_READ<128>(b, src.getReg());

  llvm::Value *rightShiftedHigher = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, input1, CONST_V<128>(b, 64), "", b);

  llvm::Value *i1_lower = new llvm::TruncInst(
      rightShiftedHigher, llvm::Type::getIntNTy(b->getContext(), 64), "", b);

  llvm::Value *res = doPSHUFHWvv(b, i1_lower, input1, order);

  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static InstTransResult doPSHUFHWmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *mem_addr,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(order.isImm());
  NASSERT(mem_addr != nullptr);

  llvm::Value *input1 = M_READ<128>(ip, b, mem_addr);

  llvm::Value *rightShiftedHigher = llvm::BinaryOperator::Create(
      llvm::Instruction::LShr, input1, CONST_V<128>(b, 64), "", b);

  llvm::Value *i1_lower = new llvm::TruncInst(
      rightShiftedHigher, llvm::Type::getIntNTy(b->getContext(), 64), "", b);

  llvm::Value *res = doPSHUFHWvv(b, i1_lower, input1, order);

  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static llvm::Value* doPSHUFLWvv(llvm::BasicBlock *&b, llvm::Value *in,
                                llvm::Value *dstVal,
                                const llvm::MCOperand &order) {
  llvm::Value *shuffled = doShuffle<64, 16>(b, in, order.getImm());

  llvm::Value *sright = llvm::BinaryOperator::Create(llvm::Instruction::LShr,
                                                     dstVal,
                                                     CONST_V<128>(b, 64), "",
                                                     b);
  llvm::Value *sleft = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                    sright, CONST_V<128>(b, 64),
                                                    "", b);

  llvm::Value *shufExt = new llvm::ZExtInst(
      shuffled, llvm::Type::getIntNTy(b->getContext(), 128), "", b);
  llvm::Value *ored = llvm::BinaryOperator::Create(llvm::Instruction::Or, sleft,
                                                   shufExt, "", b);

  return ored;
}

static InstTransResult doPSHUFLWri(llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   const llvm::MCOperand &src,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  NASSERT(order.isImm());

  llvm::Value *input1 = R_READ<128>(b, src.getReg());
  llvm::Value *i1_lower = new llvm::TruncInst(
      input1, llvm::Type::getIntNTy(b->getContext(), 64), "", b);

  llvm::Value *res = doPSHUFLWvv(b, i1_lower, input1, order);

  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static InstTransResult doPSHUFLWmi(NativeInstPtr ip, llvm::BasicBlock *&b,
                                   const llvm::MCOperand &dst,
                                   llvm::Value *mem_addr,
                                   const llvm::MCOperand &order) {
  NASSERT(dst.isReg());
  NASSERT(order.isImm());
  NASSERT(mem_addr != nullptr);

  llvm::Value *input1 = M_READ<128>(ip, b, mem_addr);

  llvm::Value *i1_lower = new llvm::TruncInst(
      input1, llvm::Type::getIntNTy(b->getContext(), 64), "", b);

  llvm::Value *res = doPSHUFLWvv(b, i1_lower, input1, order);

  R_WRITE<128>(b, dst.getReg(), res);
  return ContinueBlock;
}

static llvm::Value *doUNPCKLPSvv(llvm::BasicBlock *b, llvm::Value *dest,
                                 llvm::Value *src) {
  llvm::Value *vecSrc = INT_AS_VECTOR<128, 32>(b, src);
  llvm::Value *vecDst = INT_AS_VECTOR<128, 32>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *src2 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 1), "",
                                                       b);

  llvm::Value *dst1 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *dst2 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 1), "",
                                                       b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, dst1,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, src1,
                                                      CONST_V<32>(b, 1), "", b);
  llvm::Value *res3 = llvm::InsertElementInst::Create(res2, dst2,
                                                      CONST_V<32>(b, 2), "", b);
  llvm::Value *res4 = llvm::InsertElementInst::Create(res3, src2,
                                                      CONST_V<32>(b, 3), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res4);
}

static llvm::Value *doUNPCKLPDvv(llvm::BasicBlock *b, llvm::Value *dest,
                                 llvm::Value *src) {
  llvm::Value *vecSrc = INT_AS_VECTOR<128, 64>(b, src);
  llvm::Value *vecDst = INT_AS_VECTOR<128, 64>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *dst1 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 0), "",
                                                       b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, dst1,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, src1,
                                                      CONST_V<32>(b, 1), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res2);
}

static InstTransResult doUNPCKLPSrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doUNPCKLPSvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

static InstTransResult doUNPCKLPSrm(NativeInstPtr ip, llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    llvm::Value *src) {
  R_WRITE<128>(
      b, dest.getReg(),
      doUNPCKLPSvv(b, R_READ<128>(b, dest.getReg()), M_READ<128>(ip, b, src)));
  return ContinueBlock;
}

static InstTransResult doUNPCKLPDrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doUNPCKLPDvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

static InstTransResult doUNPCKLPDrm(NativeInstPtr ip, llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    llvm::Value *src) {
  R_WRITE<128>(
      b, dest.getReg(),
      doUNPCKLPDvv(b, R_READ<128>(b, dest.getReg()), M_READ<128>(ip, b, src)));
  return ContinueBlock;
}

static llvm::Value *doUNPCKHPDvv(llvm::BasicBlock *b, llvm::Value *dest,
                                 llvm::Value *src) {
  llvm::Value *vecSrc = INT_AS_VECTOR<128, 64>(b, src);
  llvm::Value *vecDst = INT_AS_VECTOR<128, 64>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 1), "",
                                                       b);
  llvm::Value *dst1 = llvm::ExtractElementInst::Create(vecDst,
                                                       CONST_V<32>(b, 1), "",
                                                       b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, dst1,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, src1,
                                                      CONST_V<32>(b, 1), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res2);
}

static InstTransResult doUNPCKHPDrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doUNPCKHPDvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

llvm::Value *doCVTPS2PDvv(llvm::BasicBlock *&b, llvm::Value *dest,
                          llvm::Value *src) {
  llvm::Type *DoubleTy = llvm::Type::getDoubleTy(b->getContext());

  llvm::Value *vecSrc = INT_AS_FPVECTOR<128, 32>(b, src);
  llvm::Value *vecDst = INT_AS_FPVECTOR<128, 64>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *src2 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 1), "",
                                                       b);

  llvm::Value *src1_ext = llvm::CastInst::Create(llvm::Instruction::FPExt, src1,
                                                 DoubleTy, "", b);
  llvm::Value *src2_ext = llvm::CastInst::Create(llvm::Instruction::FPExt, src2,
                                                 DoubleTy, "", b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, src1_ext,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, src2_ext,
                                                      CONST_V<32>(b, 1), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res2);
}

llvm::Value *doCVTPD2PSvv(llvm::BasicBlock *&b, llvm::Value *dest,
                          llvm::Value *src) {
  llvm::Type *FloatTy = llvm::Type::getFloatTy(b->getContext());

  llvm::Value *vecSrc = INT_AS_FPVECTOR<128, 64>(b, src);
  llvm::Value *vecDst = INT_AS_FPVECTOR<128, 32>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *src2 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 1), "",
                                                       b);

  llvm::Value *src1_trunc = new llvm::FPTruncInst(src1, FloatTy, "", b);
  llvm::Value *src2_trunc = new llvm::FPTruncInst(src2, FloatTy, "", b);

  llvm::Value *zero = CONST_V<32>(b, 0);

  llvm::Value *zero_as_fp = llvm::CastInst::Create(llvm::Instruction::BitCast,
                                                   zero, FloatTy, "", b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, src1_trunc,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, src2_trunc,
                                                      CONST_V<32>(b, 1), "", b);
  llvm::Value *res3 = llvm::InsertElementInst::Create(res2, zero_as_fp,
                                                      CONST_V<32>(b, 2), "", b);
  llvm::Value *res4 = llvm::InsertElementInst::Create(res3, zero_as_fp,
                                                      CONST_V<32>(b, 3), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res4);
}

static InstTransResult doCVTPS2PDrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doCVTPS2PDvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

llvm::Value *doCVTDQ2PSvv(llvm::BasicBlock *&b, llvm::Value *dest,
                          llvm::Value *src) {
  llvm::Type *FloatTy = llvm::Type::getFloatTy(b->getContext());

  llvm::Value *vecSrc = INT_AS_VECTOR<128, 32>(b, src);
  llvm::Value *vecDst = INT_AS_FPVECTOR<128, 32>(b, dest);

  llvm::Value *src1 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 0), "",
                                                       b);
  llvm::Value *src2 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 1), "",
                                                       b);
  llvm::Value *src3 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 2), "",
                                                       b);
  llvm::Value *src4 = llvm::ExtractElementInst::Create(vecSrc,
                                                       CONST_V<32>(b, 3), "",
                                                       b);

  llvm::Type *fpType = getFpTypeForWidth(b, 32);
  //TODO: Check rounding modes!
  llvm::Value *fp_value1 = llvm::CastInst::Create(llvm::Instruction::SIToFP,
                                                  src1, fpType, "", b);
  llvm::Value *fp_value2 = llvm::CastInst::Create(llvm::Instruction::SIToFP,
                                                  src2, fpType, "", b);
  llvm::Value *fp_value3 = llvm::CastInst::Create(llvm::Instruction::SIToFP,
                                                  src3, fpType, "", b);
  llvm::Value *fp_value4 = llvm::CastInst::Create(llvm::Instruction::SIToFP,
                                                  src4, fpType, "", b);

  llvm::Value *res1 = llvm::InsertElementInst::Create(vecDst, fp_value1,
                                                      CONST_V<32>(b, 0), "", b);
  llvm::Value *res2 = llvm::InsertElementInst::Create(res1, fp_value2,
                                                      CONST_V<32>(b, 1), "", b);
  llvm::Value *res3 = llvm::InsertElementInst::Create(res2, fp_value3,
                                                      CONST_V<32>(b, 2), "", b);
  llvm::Value *res4 = llvm::InsertElementInst::Create(res3, fp_value4,
                                                      CONST_V<32>(b, 3), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res4);
}

static InstTransResult doCVTDQ2PSrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doCVTDQ2PSvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

static InstTransResult doCVTPS2PDrm(NativeInstPtr ip, llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    llvm::Value *src) {
  R_WRITE<128>(
      b, dest.getReg(),
      doCVTPS2PDvv(b, R_READ<128>(b, dest.getReg()), M_READ<128>(ip, b, src)));
  return ContinueBlock;
}

static InstTransResult doCVTPD2PSrr(llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    const llvm::MCOperand &src) {
  R_WRITE<128>(
      b,
      dest.getReg(),
      doCVTPD2PSvv(b, R_READ<128>(b, dest.getReg()),
                   R_READ<128>(b, src.getReg())));
  return ContinueBlock;
}

static InstTransResult doCVTPD2PSrm(NativeInstPtr ip, llvm::BasicBlock *b,
                                    const llvm::MCOperand &dest,
                                    llvm::Value *src) {
  R_WRITE<128>(
      b, dest.getReg(),
      doCVTPD2PSvv(b, R_READ<128>(b, dest.getReg()), M_READ<128>(ip, b, src)));
  return ContinueBlock;
}

static InstTransResult doMOVDDUPrr(llvm::BasicBlock *b,
                                   const llvm::MCOperand &dest,
                                   const llvm::MCOperand &src) {
  llvm::Value *s = R_READ<128>(b, src.getReg());

  llvm::Value* lower = new llvm::TruncInst(
      s, llvm::Type::getIntNTy(b->getContext(), 64), "", b);
  llvm::Value *lower_ext = new llvm::ZExtInst(
      lower, llvm::Type::getIntNTy(b->getContext(), 128), "", b);

  // duplicate it in upper half
  llvm::Value *top_half = llvm::BinaryOperator::Create(llvm::Instruction::Shl,
                                                       lower_ext,
                                                       CONST_V<128>(b, 64), "",
                                                       b);

  // combine the halves
  llvm::Value *combined = llvm::BinaryOperator::CreateAnd(lower_ext, top_half,
                                                          "", b);

  R_WRITE<128>(b, dest.getReg(), combined);

  return ContinueBlock;
}

GENERIC_TRANSLATION(MOVHLPSrr, (doMOVHLPSrr<128>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION(MOVLHPSrr, (doMOVLHPSrr<128>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION(PMOVSXBWrr,
                    (do_SSE_EXTEND_RR<128,8,16,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXBWrm,
    (do_SSE_EXTEND_RM<128,8,16,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,16,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVSXBDrr,
                    (do_SSE_EXTEND_RR<128,8,32,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXBDrm,
    (do_SSE_EXTEND_RM<128,8,32,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,32,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVSXBQrr,
                    (do_SSE_EXTEND_RR<128,8,64,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXBQrm,
    (do_SSE_EXTEND_RM<128,8,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVSXWDrr,
                    (do_SSE_EXTEND_RR<128,16,32,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXWDrm,
    (do_SSE_EXTEND_RM<128,16,32,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,16,32,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVSXWQrr,
                    (do_SSE_EXTEND_RR<128,16,64,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXWQrm,
    (do_SSE_EXTEND_RM<128,16,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,16,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVSXDQrr,
                    (do_SSE_EXTEND_RR<128,32,64,SEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVSXDQrm,
    (do_SSE_EXTEND_RM<128,32,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,32,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(PMOVZXBWrr,
                    (do_SSE_EXTEND_RR<128,8,16,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXBWrm,
    (do_SSE_EXTEND_RM<128,8,16,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,16,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVZXBDrr,
                    (do_SSE_EXTEND_RR<128,8,32,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXBDrm,
    (do_SSE_EXTEND_RM<128,8,32,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,32,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVZXBQrr,
                    (do_SSE_EXTEND_RR<128,8,64,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXBQrm,
    (do_SSE_EXTEND_RM<128,8,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,8,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVZXWDrr,
                    (do_SSE_EXTEND_RR<128,16,32,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXWDrm,
    (do_SSE_EXTEND_RM<128,16,32,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,16,32,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVZXWQrr,
                    (do_SSE_EXTEND_RR<128,16,64,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXWQrm,
    (do_SSE_EXTEND_RM<128,16,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,16,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(PMOVZXDQrr,
                    (do_SSE_EXTEND_RR<128,32,64,ZEXT>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(
    PMOVZXDQrm,
    (do_SSE_EXTEND_RM<128,32,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
    (do_SSE_EXTEND_RM<128,32,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(PANDNrr, (do_PANDNrr<128>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PANDNrm,
                        (do_PANDNrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
                        (do_PANDNrm<128>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PANDrr,
    (do_SSE_INT_RR<128,llvm::Instruction::And>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PANDrm,
    (do_SSE_INT_RM<128, llvm::Instruction::And>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_INT_RM<128, llvm::Instruction::And>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PORrr, (do_SSE_INT_RR<128,llvm::Instruction::Or>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PORrm,
    (do_SSE_INT_RM<128, llvm::Instruction::Or>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_INT_RM<128, llvm::Instruction::Or>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MMX_PORirr,
    (do_SSE_INT_RR<64,llvm::Instruction::Or>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MMX_PORirm,
    (do_SSE_INT_RM<64, llvm::Instruction::Or>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_INT_RM<64, llvm::Instruction::Or>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    XORPSrr,
    (do_SSE_INT_RR<128, llvm::Instruction::Xor>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    XORPSrm,
    (do_SSE_INT_RM<128, llvm::Instruction::Xor>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_INT_RM<128, llvm::Instruction::Xor>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    ADDSDrr, (do_SSE_RR<64, llvm::Instruction::FAdd>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    ADDSDrm,
    (do_SSE_RM<64, llvm::Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<64, llvm::Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    ADDSSrr, (do_SSE_RR<32, llvm::Instruction::FAdd>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    ADDSSrm,
    (do_SSE_RM<32, llvm::Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<32, llvm::Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    SUBSDrr, (do_SSE_RR<64, llvm::Instruction::FSub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    SUBSDrm,
    (do_SSE_RM<64, llvm::Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<64, llvm::Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    SUBSSrr, (do_SSE_RR<32, llvm::Instruction::FSub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    SUBSSrm,
    (do_SSE_RM<32, llvm::Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<32, llvm::Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    DIVSDrr, (do_SSE_RR<64, llvm::Instruction::FDiv>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    DIVSDrm,
    (do_SSE_RM<64, llvm::Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<64, llvm::Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    DIVSSrr, (do_SSE_RR<32, llvm::Instruction::FDiv>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    DIVSSrm,
    (do_SSE_RM<32, llvm::Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<32, llvm::Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MULSDrr, (do_SSE_RR<64, llvm::Instruction::FMul>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MULSDrm,
    (do_SSE_RM<64, llvm::Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<64, llvm::Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MULSSrr, (do_SSE_RR<32, llvm::Instruction::FMul>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MULSSrm,
    (do_SSE_RM<32, llvm::Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_RM<32, llvm::Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(MOVDI2PDIrr, (MOVAndZextRR<32>(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(MOVDI2PDIrm,
                        (MOVAndZextRM<32>(ip, block, OP(0), ADDR_NOREF(1))),
                        (MOVAndZextRM<32>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(MOVSS2DIrr, (doRRMov<32>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION(UCOMISSrr, (doUCOMISrr<32>(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(UCOMISSrm,
                        (doUCOMISrm<32>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doUCOMISrm<32>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(UCOMISDrr, (doUCOMISrr<64>(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(UCOMISDrm,
                        (doUCOMISrm<64>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doUCOMISrm<64>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(PSRAWrr, (doPSRArr<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSRAWri, (doPSRAri<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSRAWrm,
                        (doPSRArm<16>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSRArm<16>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSRADrr, (doPSRArr<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSRADri, (doPSRAri<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSRADrm,
                        (doPSRArm<32>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSRArm<32>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSLLDrr, (doPSLLrr<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSLLDri, (doPSLLri<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSLLDrm,
                        (doPSLLrm<32>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSLLrm<32>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSRLWrr, (doPSRLrr<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSRLWri, (doPSRLri<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSRLWrm,
                        (doPSRLrm<16>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSRLrm<16>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSRLDrr, (doPSRLrr<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSRLDri, (doPSRLri<32>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSRLDrm,
                        (doPSRLrm<32>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSRLrm<32>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSRLQrr, (doPSRLrr<64>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSRLQri, (doPSRLri<64>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSRLQrm,
                        (doPSRLrm<64>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSRLrm<64>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSLLWrr, (doPSLLrr<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSLLWri, (doPSLLri<16>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSLLWrm,
                        (doPSLLrm<16>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSLLrm<16>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSLLQrr, (doPSLLrr<64>(block, OP(1), OP(2))))
GENERIC_TRANSLATION(PSLLQri, (doPSLLri<64>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSLLQrm,
                        (doPSLLrm<64>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSLLrm<64>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSLLDQri, (doPSLLri<128>(block, OP(1), OP(2))))

GENERIC_TRANSLATION(PSHUFDri, (doPSHUFDri(block, OP(0), OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSHUFDmi,
                        (doPSHUFDmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
                        (doPSHUFDmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))))

GENERIC_TRANSLATION(PSHUFBrr, (doPSHUFBrr<128>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSHUFBrm,
                        (doPSHUFBrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPSHUFBrm<128>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSHUFHWri, (doPSHUFHWri(block, OP(0), OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSHUFHWmi, (doPSHUFHWmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
    (doPSHUFHWmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))))

GENERIC_TRANSLATION(PSHUFLWri, (doPSHUFLWri(block, OP(0), OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSHUFLWmi, (doPSHUFLWmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
    (doPSHUFLWmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))))

GENERIC_TRANSLATION(PINSRWrri, (doPINSRWrri(block, OP(1), OP(2), OP(3))))
GENERIC_TRANSLATION_REF(
    PINSRWrmi, (doPINSRWrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
    (doPINSRWrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))))

GENERIC_TRANSLATION(PEXTRWri, (doPEXTRWri(block, OP(0), OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PEXTRWmr,
                        (doPEXTRWmr(ip, block, ADDR_NOREF(0), OP(5), OP(6))),
                        (doPEXTRWmr(ip, block, MEM_REFERENCE(0), OP(5), OP(6))))

GENERIC_TRANSLATION(PUNPCKLBWrr,
                    (doPUNPCKrr<128,8,UNPACK_LOW>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKLBWrm,
    (doPUNPCKrm<128,8,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,8,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKLWDrr,
                    (doPUNPCKrr<128,16,UNPACK_LOW>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKLWDrm,
    (doPUNPCKrm<128,16,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,16,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKLDQrr,
                    (doPUNPCKrr<128,32,UNPACK_LOW>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKLDQrm,
    (doPUNPCKrm<128,32,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,32,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKLQDQrr,
                    (doPUNPCKrr<128,64,UNPACK_LOW>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKLQDQrm,
    (doPUNPCKrm<128,64,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,64,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKHBWrr,
                    (doPUNPCKrr<128,8,UNPACK_HIGH>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKHBWrm,
    (doPUNPCKrm<128,8,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,8,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKHWDrr,
                    (doPUNPCKrr<128,16,UNPACK_HIGH>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKHWDrm,
    (doPUNPCKrm<128,16,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,16,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKHDQrr,
                    (doPUNPCKrr<128,32,UNPACK_HIGH>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKHDQrm,
    (doPUNPCKrm<128,32,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,32,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PUNPCKHQDQrr,
                    (doPUNPCKrr<128,64,UNPACK_HIGH>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PUNPCKHQDQrm,
    (doPUNPCKrm<128,64,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
    (doPUNPCKrm<128,64,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PCMPGTBrr,
    (do_SSE_COMPARE_RR<128, 8, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPGTBrm,
    (do_SSE_COMPARE_RM<128, 8, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 8, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPGTWrr,
    (do_SSE_COMPARE_RR<128, 16, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPGTWrm,
    (do_SSE_COMPARE_RM<128, 16, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 16, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPGTDrr,
    (do_SSE_COMPARE_RR<128, 32, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPGTDrm,
    (do_SSE_COMPARE_RM<128, 32, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 32, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPGTQrr,
    (do_SSE_COMPARE_RR<128, 64, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPGTQrm,
    (do_SSE_COMPARE_RM<128, 64, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 64, llvm::ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PCMPEQBrr,
    (do_SSE_COMPARE_RR<128, 8, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPEQBrm,
    (do_SSE_COMPARE_RM<128, 8, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 8, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPEQWrr,
    (do_SSE_COMPARE_RR<128, 16, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPEQWrm,
    (do_SSE_COMPARE_RM<128, 16, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 16, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPEQDrr,
    (do_SSE_COMPARE_RR<128, 32, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPEQDrm,
    (do_SSE_COMPARE_RM<128, 32, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128, 32, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PCMPEQQrr,
    (do_SSE_COMPARE_RR<128, 64, llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PCMPEQQrm,
    (do_SSE_COMPARE_RM<128,64,llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_COMPARE_RM<128,64,llvm::ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PADDBrr,
    (do_SSE_VECTOR_RR<128,8,llvm::Instruction::Add>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PADDBrm,
    (do_SSE_VECTOR_RM<128,8,llvm::Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,8,llvm::Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PADDWrr,
    (do_SSE_VECTOR_RR<128,16,llvm::Instruction::Add>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PADDWrm,
    (do_SSE_VECTOR_RM<128,16,llvm::Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,16,llvm::Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PADDDrr,
    (do_SSE_VECTOR_RR<128,32,llvm::Instruction::Add>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PADDDrm,
    (do_SSE_VECTOR_RM<128,32,llvm::Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,32,llvm::Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PADDQrr,
    (do_SSE_VECTOR_RR<128,64,llvm::Instruction::Add>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PADDQrm,
    (do_SSE_VECTOR_RM<128,64,llvm::Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,64,llvm::Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    SUBPSrr,
    (do_SSE_FP_VECTOR_RR<128,32,llvm::Instruction::FSub>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    SUBPSrm,
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    SUBPDrr,
    (do_SSE_FP_VECTOR_RR<128,64,llvm::Instruction::FSub>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    SUBPDrm,
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    ADDPSrr,
    (do_SSE_FP_VECTOR_RR<128,32,llvm::Instruction::FAdd>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    ADDPSrm,
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    ADDPDrr,
    (do_SSE_FP_VECTOR_RR<128,64,llvm::Instruction::FAdd>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    ADDPDrm,
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MULPSrr,
    (do_SSE_FP_VECTOR_RR<128,32,llvm::Instruction::FMul>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    MULPSrm,
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MULPDrr,
    (do_SSE_FP_VECTOR_RR<128,64,llvm::Instruction::FMul>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    MULPDrm,
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    DIVPSrr,
    (do_SSE_FP_VECTOR_RR<128,32,llvm::Instruction::FDiv>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    DIVPSrm,
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,32,llvm::Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    DIVPDrr,
    (do_SSE_FP_VECTOR_RR<128,64,llvm::Instruction::FDiv>(ip, block, OP(1), OP(2))))

GENERIC_TRANSLATION_REF(
    DIVPDrm,
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_FP_VECTOR_RM<128,64,llvm::Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PSUBUSBrr,
    (do_SATURATED_SUB_RR<128,8,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBUSBrm,
    (do_SATURATED_SUB_RM<128,8,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SATURATED_SUB_RM<128,8,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PSUBUSWrr,
    (do_SATURATED_SUB_RR<128,16,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBUSWrm,
    (do_SATURATED_SUB_RM<128,16,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SATURATED_SUB_RM<128,16,llvm::ICmpInst::ICMP_UGE>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    PSUBBrr,
    (do_SSE_VECTOR_RR<128,8,llvm::Instruction::Sub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBBrm,
    (do_SSE_VECTOR_RM<128,8,llvm::Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,8,llvm::Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PSUBWrr,
    (do_SSE_VECTOR_RR<128,16,llvm::Instruction::Sub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBWrm,
    (do_SSE_VECTOR_RM<128,16,llvm::Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,16,llvm::Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PSUBDrr,
    (do_SSE_VECTOR_RR<128,32,llvm::Instruction::Sub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBDrm,
    (do_SSE_VECTOR_RM<128,32,llvm::Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,32,llvm::Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(
    PSUBQrr,
    (do_SSE_VECTOR_RR<128,64,llvm::Instruction::Sub>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    PSUBQrm,
    (do_SSE_VECTOR_RM<128,64,llvm::Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
    (do_SSE_VECTOR_RM<128,64,llvm::Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MAXPSrr,
    (doMAXMIN_FP_VECTOR_rr<128, 32, llvm::FCmpInst::FCMP_UGT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MAXPSrm,
    (doMAXMIN_FP_VECTOR_rm<128, 32, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMIN_FP_VECTOR_rm<128, 32, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MAXPDrr,
    (doMAXMIN_FP_VECTOR_rr<128, 64, llvm::FCmpInst::FCMP_UGT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MAXPDrm,
    (doMAXMIN_FP_VECTOR_rm<128, 64, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMIN_FP_VECTOR_rm<128, 64, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MAXSSrr, (doMAXMINrr<32, llvm::FCmpInst::FCMP_UGT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MAXSSrm,
    (doMAXMINrm<32, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMINrm<32, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MAXSDrr, (doMAXMINrr<64, llvm::FCmpInst::FCMP_UGT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MAXSDrm,
    (doMAXMINrm<64, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMINrm<64, llvm::FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MINPSrr,
    (doMAXMIN_FP_VECTOR_rr<128, 32, llvm::FCmpInst::FCMP_ULT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MINPSrm,
    (doMAXMIN_FP_VECTOR_rm<128, 32, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMIN_FP_VECTOR_rm<128, 32, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MINPDrr,
    (doMAXMIN_FP_VECTOR_rr<128, 64, llvm::FCmpInst::FCMP_ULT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MINPDrm,
    (doMAXMIN_FP_VECTOR_rm<128, 64, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMIN_FP_VECTOR_rm<128, 64, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MINSSrr, (doMAXMINrr<32, llvm::FCmpInst::FCMP_ULT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MINSSrm,
    (doMAXMINrm<32, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMINrm<32, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(
    MINSDrr, (doMAXMINrr<64, llvm::FCmpInst::FCMP_ULT>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(
    MINSDrm,
    (doMAXMINrm<64, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
    (doMAXMINrm<64, llvm::FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PBLENDVBrr0, (doBLENDVBrr<128>(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PBLENDVBrm0,
                        (doBLENDVBrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
                        (doBLENDVBrm<128>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PMULUDQrr, (doPMULUDQrr(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PMULUDQrm,
                        (doPMULUDQrm(ip, block, OP(1), ADDR_NOREF(2))),
                        (doPMULUDQrm(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(CVTTPS2DQrr, (doCVTTPS2DQrr(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(CVTTPS2DQrm,
                        (doCVTTPS2DQrm(ip, block, OP(0), ADDR_NOREF(1))),
                        (doCVTTPS2DQrm(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION_REF(MOVHPDrm, (doMOVHPDrm(ip, block, OP(1), ADDR_NOREF(2))),
                        (doMOVHPDrm(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION_REF(MOVHPDmr, (doMOVHPDmr(ip, block, ADDR_NOREF(0), OP(5))),
                        (doMOVHPDmr(ip, block, MEM_REFERENCE(0), OP(5))))

GENERIC_TRANSLATION_REF(MOVLPDrm, (doMOVLPDrm(ip, block, OP(1), ADDR_NOREF(2))),
                        (doMOVLPDrm(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(SHUFPDrri, (doSHUFPDrri(block, OP(1), OP(2), OP(3))))
GENERIC_TRANSLATION_REF(
    SHUFPDrmi, (doSHUFPDrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
    (doSHUFPDrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))))

GENERIC_TRANSLATION(SHUFPSrri, (doSHUFPSrri(block, OP(1), OP(2), OP(3))))
GENERIC_TRANSLATION_REF(
    SHUFPSrmi, (doSHUFPSrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
    (doSHUFPSrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))))

GENERIC_TRANSLATION(UNPCKLPSrr, (doUNPCKLPSrr(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(UNPCKLPSrm,
                        (doUNPCKLPSrm(ip, block, OP(1), ADDR_NOREF(2))),
                        (doUNPCKLPSrm(ip, block, OP(1), MEM_REFERENCE(2))))
GENERIC_TRANSLATION(UNPCKLPDrr, (doUNPCKLPDrr(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(UNPCKLPDrm,
                        (doUNPCKLPDrm(ip, block, OP(1), ADDR_NOREF(2))),
                        (doUNPCKLPDrm(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(UNPCKHPDrr, (doUNPCKHPDrr(block, OP(1), OP(2))))

GENERIC_TRANSLATION(CVTDQ2PSrr, (doCVTDQ2PSrr(block, OP(0), OP(1))))

GENERIC_TRANSLATION(CVTPS2PDrr, (doCVTPS2PDrr(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(CVTPS2PDrm,
                        (doCVTPS2PDrm(ip, block, OP(0), ADDR_NOREF(1))),
                        (doCVTPS2PDrm(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(CVTPD2PSrr, (doCVTPD2PSrr(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(CVTPD2PSrm,
                        (doCVTPD2PSrm(ip, block, OP(0), ADDR_NOREF(1))),
                        (doCVTPD2PSrm(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(MOV64toPQIrr, (MOVAndZextRR<64>(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(MOV64toSDrm,
                        (MOVAndZextRM<64>(ip, block, OP(0), ADDR_NOREF(1))),
                        (MOVAndZextRM<64>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVQI2PQIrm,
                        (MOVAndZextRM<64>(ip, block, OP(0), ADDR_NOREF(1))),
                        (MOVAndZextRM<64>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION(MOVDDUPrr, (doMOVDDUPrr(block, OP(0), OP(1))))

void SSE_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::MOVSDrm] = doMOVSrm<64>;
  m[llvm::X86::MOVSDmr] = doMOVSmr<64>;

  m[llvm::X86::CVTSI2SDrr] = translate_CVTSI2SDrr<32>;
  m[llvm::X86::CVTSI2SDrm] = translate_CVTSI2SDrm<32>;
  m[llvm::X86::CVTSI2SD64rr] = translate_CVTSI2SDrr<64>;
  m[llvm::X86::CVTSI2SD64rm] = translate_CVTSI2SDrm<64>;

  m[llvm::X86::CVTSD2SSrm] = translate_CVTSD2SSrm;
  m[llvm::X86::CVTSD2SSrr] = translate_CVTSD2SSrr;
  m[llvm::X86::CVTSS2SDrm] = translate_CVTSS2SDrm;
  m[llvm::X86::CVTSS2SDrr] = translate_CVTSS2SDrr;
  m[llvm::X86::MOVSSrm] = (doMOVSrm<32> );
  m[llvm::X86::MOVSSmr] = (doMOVSmr<32> );
  m[llvm::X86::XORPSrr] = translate_XORPSrr;
  m[llvm::X86::XORPSrm] = translate_XORPSrm;
  // XORPD = XORPS = PXOR, for the purposes of translation
  // it just operates on different bitwidth and changes internal register type
  // which is not exposed to outside world but affects performance
  m[llvm::X86::XORPDrr] = translate_XORPSrr;
  m[llvm::X86::XORPDrm] = translate_XORPSrm;
  m[llvm::X86::PXORrr] = translate_XORPSrr;
  m[llvm::X86::PXORrm] = translate_XORPSrm;

  // these should be identical
  m[llvm::X86::ORPDrr] = translate_PORrr;
  m[llvm::X86::ORPDrm] = translate_PORrm;
  m[llvm::X86::ORPSrr] = translate_PORrr;
  m[llvm::X86::ORPSrm] = translate_PORrm;

  m[llvm::X86::CVTSI2SSrr] = translate_CVTSI2SSrr;
  m[llvm::X86::CVTSI2SSrm] = translate_CVTSI2SSrm;

  m[llvm::X86::CVTSI2SS64rr] = translate_CVTSI2SS64rr;
  m[llvm::X86::CVTSI2SS64rm] = translate_CVTSI2SS64rm;

  m[llvm::X86::CVTTSD2SIrm] = doCVTT_to_SI_rm<64, 32>;
  m[llvm::X86::CVTTSD2SIrr] = doCVTT_to_SI_rr<64, 32>;
  m[llvm::X86::CVTTSS2SIrm] = doCVTT_to_SI_rm<32, 32>;
  m[llvm::X86::CVTTSS2SIrr] = doCVTT_to_SI_rr<32, 32>;

  m[llvm::X86::CVTTSD2SI64rm] = doCVTT_to_SI_rm<64, 64>;
  m[llvm::X86::CVTTSD2SI64rr] = doCVTT_to_SI_rr<64, 64>;
  m[llvm::X86::CVTTSS2SI64rm] = doCVTT_to_SI_rm<32, 64>;
  m[llvm::X86::CVTTSS2SI64rr] = doCVTT_to_SI_rr<32, 64>;

  m[llvm::X86::ADDSDrr] = translate_ADDSDrr;
  m[llvm::X86::ADDSDrm] = translate_ADDSDrm;
  m[llvm::X86::ADDSSrr] = translate_ADDSSrr;
  m[llvm::X86::ADDSSrm] = translate_ADDSSrm;
  m[llvm::X86::SUBSDrr] = translate_SUBSDrr;
  m[llvm::X86::SUBSDrm] = translate_SUBSDrm;
  m[llvm::X86::SUBSSrr] = translate_SUBSSrr;
  m[llvm::X86::SUBSSrm] = translate_SUBSSrm;
  m[llvm::X86::DIVSDrr] = translate_DIVSDrr;
  m[llvm::X86::DIVSDrm] = translate_DIVSDrm;
  m[llvm::X86::DIVSSrr] = translate_DIVSSrr;
  m[llvm::X86::DIVSSrm] = translate_DIVSSrm;
  m[llvm::X86::MULSDrr] = translate_MULSDrr;
  m[llvm::X86::MULSDrm] = translate_MULSDrm;
  m[llvm::X86::MULSSrr] = translate_MULSSrr;
  m[llvm::X86::MULSSrm] = translate_MULSSrm;
  m[llvm::X86::PORrr] = translate_PORrr;
  m[llvm::X86::PORrm] = translate_PORrm;

  m[llvm::X86::MOVDQUrm] = doMOVSrm<128>;
  m[llvm::X86::MOVDQUmr] = doMOVSmr<128>;
  m[llvm::X86::MOVDQUrr] = doMOVSrr<128, 0, 1>;
  m[llvm::X86::MOVDQUrr_REV] = doMOVSrr<128, 0, 1>;

  m[llvm::X86::MOVDQArm] = doMOVSrm<128>;
  m[llvm::X86::MOVDQAmr] = doMOVSmr<128>;
  m[llvm::X86::MOVDQArr] = doMOVSrr<128, 0, 1>;
  m[llvm::X86::MOVDQArr_REV] = doMOVSrr<128, 0, 1>;

  m[llvm::X86::MOVUPDrm] = doMOVSrm<128>;
  m[llvm::X86::MOVUPDmr] = doMOVSmr<128>;

  m[llvm::X86::MOVUPSrm] = doMOVSrm<128>;
  m[llvm::X86::MOVUPSmr] = doMOVSmr<128>;
  m[llvm::X86::MOVUPSrr] = doMOVSrr<128, 0, 1>;
  m[llvm::X86::MOVUPSrr_REV] = doMOVSrr<128, 0, 1>;

  m[llvm::X86::MOVAPSrm] = doMOVSrm<128>;
  m[llvm::X86::MOVAPSmr] = doMOVSmr<128>;
  m[llvm::X86::MOVAPSrr] = doMOVSrr<128, 0, 1>;
  m[llvm::X86::MOVAPSrr_REV] = doMOVSrr<128, 0, 1>;

  m[llvm::X86::MOVAPDrm] = doMOVSrm<128>;
  m[llvm::X86::MOVAPDmr] = doMOVSmr<128>;
  m[llvm::X86::MOVAPDrr] = doMOVSrr<128, 0, 1>;
  m[llvm::X86::MOVAPDrr_REV] = doMOVSrr<128, 0, 1>;

  m[llvm::X86::MOVSDrr] = doMOVSrr<64, 1, 2>;
  m[llvm::X86::MOVSSrr] = doMOVSrr<32, 1, 2>;

  m[llvm::X86::MOVDI2PDIrr] = translate_MOVDI2PDIrr;
  m[llvm::X86::MOVDI2PDIrm] = translate_MOVDI2PDIrm;

  m[llvm::X86::MOVPDI2DIrr] = doMOVSrr<32, 0, 1>;
  m[llvm::X86::MOVPDI2DImr] = doMOVSmr<32>;

  m[llvm::X86::MOVSS2DIrr] = translate_MOVSS2DIrr;
  m[llvm::X86::MOVSS2DImr] = doMOVSmr<32>;

  m[llvm::X86::UCOMISSrr] = translate_UCOMISSrr;
  m[llvm::X86::UCOMISSrm] = translate_UCOMISSrm;
  m[llvm::X86::UCOMISDrr] = translate_UCOMISDrr;
  m[llvm::X86::UCOMISDrm] = translate_UCOMISDrm;

  m[llvm::X86::PSRAWrr] = translate_PSRAWrr;
  m[llvm::X86::PSRAWrm] = translate_PSRAWrm;
  m[llvm::X86::PSRAWri] = translate_PSRAWri;
  m[llvm::X86::PSRADrr] = translate_PSRADrr;
  m[llvm::X86::PSRADrm] = translate_PSRADrm;
  m[llvm::X86::PSRADri] = translate_PSRADri;

  m[llvm::X86::PSLLWrr] = translate_PSLLWrr;
  m[llvm::X86::PSLLWrm] = translate_PSLLWrm;
  m[llvm::X86::PSLLWri] = translate_PSLLWri;

  m[llvm::X86::PSLLDrr] = translate_PSLLDrr;
  m[llvm::X86::PSLLDrm] = translate_PSLLDrm;
  m[llvm::X86::PSLLDri] = translate_PSLLDri;

  m[llvm::X86::PSLLQrr] = translate_PSLLQrr;
  m[llvm::X86::PSLLQrm] = translate_PSLLQrm;
  m[llvm::X86::PSLLQri] = translate_PSLLQri;

  m[llvm::X86::PSLLDQri] = translate_PSLLDQri;

  m[llvm::X86::PSRLWrr] = translate_PSRLWrr;
  m[llvm::X86::PSRLWrm] = translate_PSRLWrm;
  m[llvm::X86::PSRLWri] = translate_PSRLWri;

  m[llvm::X86::PSRLDrr] = translate_PSRLDrr;
  m[llvm::X86::PSRLDrm] = translate_PSRLDrm;
  m[llvm::X86::PSRLDri] = translate_PSRLDri;

  m[llvm::X86::PSRLQrr] = translate_PSRLQrr;
  m[llvm::X86::PSRLQrm] = translate_PSRLQrm;
  m[llvm::X86::PSRLQri] = translate_PSRLQri;

  m[llvm::X86::PSHUFDri] = translate_PSHUFDri;
  m[llvm::X86::PSHUFDmi] = translate_PSHUFDmi;

  m[llvm::X86::PSHUFBrr] = translate_PSHUFBrr;
  m[llvm::X86::PSHUFBrm] = translate_PSHUFBrm;

  m[llvm::X86::PINSRWrri] = translate_PINSRWrri;
  m[llvm::X86::PINSRWrmi] = translate_PINSRWrmi;

  m[llvm::X86::PEXTRWri] = translate_PEXTRWri;
  m[llvm::X86::PEXTRWmr] = translate_PEXTRWmr;

  m[llvm::X86::PUNPCKLBWrr] = translate_PUNPCKLBWrr;
  m[llvm::X86::PUNPCKLBWrm] = translate_PUNPCKLBWrm;
  m[llvm::X86::PUNPCKLWDrr] = translate_PUNPCKLWDrr;
  m[llvm::X86::PUNPCKLWDrm] = translate_PUNPCKLWDrm;
  m[llvm::X86::PUNPCKLDQrr] = translate_PUNPCKLDQrr;
  m[llvm::X86::PUNPCKLDQrm] = translate_PUNPCKLDQrm;
  m[llvm::X86::PUNPCKLQDQrr] = translate_PUNPCKLQDQrr;
  m[llvm::X86::PUNPCKLQDQrm] = translate_PUNPCKLQDQrm;

  m[llvm::X86::PUNPCKHBWrr] = translate_PUNPCKHBWrr;
  m[llvm::X86::PUNPCKHBWrm] = translate_PUNPCKHBWrm;
  m[llvm::X86::PUNPCKHWDrr] = translate_PUNPCKHWDrr;
  m[llvm::X86::PUNPCKHWDrm] = translate_PUNPCKHWDrm;
  m[llvm::X86::PUNPCKHDQrr] = translate_PUNPCKHDQrr;
  m[llvm::X86::PUNPCKHDQrm] = translate_PUNPCKHDQrm;
  m[llvm::X86::PUNPCKHQDQrr] = translate_PUNPCKHQDQrr;
  m[llvm::X86::PUNPCKHQDQrm] = translate_PUNPCKHQDQrm;

  m[llvm::X86::PADDBrr] = translate_PADDBrr;
  m[llvm::X86::PADDBrm] = translate_PADDBrm;
  m[llvm::X86::PADDWrr] = translate_PADDWrr;
  m[llvm::X86::PADDWrm] = translate_PADDWrm;
  m[llvm::X86::PADDDrr] = translate_PADDDrr;
  m[llvm::X86::PADDDrm] = translate_PADDDrm;
  m[llvm::X86::PADDQrr] = translate_PADDQrr;
  m[llvm::X86::PADDQrm] = translate_PADDQrm;

  m[llvm::X86::PSUBUSBrr] = translate_PSUBUSBrr;
  m[llvm::X86::PSUBUSBrm] = translate_PSUBUSBrm;

  m[llvm::X86::PSUBUSWrr] = translate_PSUBUSWrr;
  m[llvm::X86::PSUBUSWrm] = translate_PSUBUSWrm;

  m[llvm::X86::PSUBBrr] = translate_PSUBBrr;
  m[llvm::X86::PSUBBrm] = translate_PSUBBrm;
  m[llvm::X86::PSUBWrr] = translate_PSUBWrr;
  m[llvm::X86::PSUBWrm] = translate_PSUBWrm;
  m[llvm::X86::PSUBDrr] = translate_PSUBDrr;
  m[llvm::X86::PSUBDrm] = translate_PSUBDrm;
  m[llvm::X86::PSUBQrr] = translate_PSUBQrr;
  m[llvm::X86::PSUBQrm] = translate_PSUBQrm;

  m[llvm::X86::MAXPSrr] = translate_MAXPSrr;
  m[llvm::X86::MAXPSrm] = translate_MAXPSrm;
  m[llvm::X86::MAXPDrr] = translate_MAXPDrr;
  m[llvm::X86::MAXPDrm] = translate_MAXPDrm;
  m[llvm::X86::MAXSSrr] = translate_MAXSSrr;
  m[llvm::X86::MAXSSrm] = translate_MAXSSrm;
  m[llvm::X86::MAXSDrr] = translate_MAXSDrr;
  m[llvm::X86::MAXSDrm] = translate_MAXSDrm;

  m[llvm::X86::MINPSrr] = translate_MINPSrr;
  m[llvm::X86::MINPSrm] = translate_MINPSrm;
  m[llvm::X86::MINPDrr] = translate_MINPDrr;
  m[llvm::X86::MINPDrm] = translate_MINPDrm;
  m[llvm::X86::MINSSrr] = translate_MINSSrr;
  m[llvm::X86::MINSSrm] = translate_MINSSrm;
  m[llvm::X86::MINSDrr] = translate_MINSDrr;
  m[llvm::X86::MINSDrm] = translate_MINSDrm;

  // all the same AND op
  m[llvm::X86::PANDrr] = translate_PANDrr;
  m[llvm::X86::PANDrm] = translate_PANDrm;
  m[llvm::X86::ANDPDrr] = translate_PANDrr;
  m[llvm::X86::ANDPDrm] = translate_PANDrm;
  m[llvm::X86::ANDPSrr] = translate_PANDrr;
  m[llvm::X86::ANDPSrm] = translate_PANDrm;

  // all the same NAND op
  m[llvm::X86::PANDNrr] = translate_PANDNrr;
  m[llvm::X86::PANDNrm] = translate_PANDNrm;
  m[llvm::X86::ANDNPDrr] = translate_PANDNrr;
  m[llvm::X86::ANDNPDrm] = translate_PANDNrm;
  m[llvm::X86::ANDNPSrr] = translate_PANDNrr;
  m[llvm::X86::ANDNPSrm] = translate_PANDNrm;

  // compares
  m[llvm::X86::PCMPGTBrr] = translate_PCMPGTBrr;
  m[llvm::X86::PCMPGTBrm] = translate_PCMPGTBrm;
  m[llvm::X86::PCMPGTWrr] = translate_PCMPGTWrr;
  m[llvm::X86::PCMPGTWrm] = translate_PCMPGTWrm;
  m[llvm::X86::PCMPGTDrr] = translate_PCMPGTDrr;
  m[llvm::X86::PCMPGTDrm] = translate_PCMPGTDrm;
  m[llvm::X86::PCMPGTQrr] = translate_PCMPGTQrr;
  m[llvm::X86::PCMPGTQrm] = translate_PCMPGTQrm;

  m[llvm::X86::PCMPEQBrr] = translate_PCMPEQBrr;
  m[llvm::X86::PCMPEQBrm] = translate_PCMPEQBrm;
  m[llvm::X86::PCMPEQWrr] = translate_PCMPEQWrr;
  m[llvm::X86::PCMPEQWrm] = translate_PCMPEQWrm;
  m[llvm::X86::PCMPEQDrr] = translate_PCMPEQDrr;
  m[llvm::X86::PCMPEQDrm] = translate_PCMPEQDrm;
  m[llvm::X86::PCMPEQQrr] = translate_PCMPEQQrr;
  m[llvm::X86::PCMPEQQrm] = translate_PCMPEQQrm;

  m[llvm::X86::PMOVSXBWrr] = translate_PMOVSXBWrr;
  m[llvm::X86::PMOVSXBWrm] = translate_PMOVSXBWrm;
  m[llvm::X86::PMOVSXBDrr] = translate_PMOVSXBDrr;
  m[llvm::X86::PMOVSXBDrm] = translate_PMOVSXBDrm;
  m[llvm::X86::PMOVSXBQrr] = translate_PMOVSXBQrr;
  m[llvm::X86::PMOVSXBQrm] = translate_PMOVSXBQrm;
  m[llvm::X86::PMOVSXWDrr] = translate_PMOVSXWDrr;
  m[llvm::X86::PMOVSXWDrm] = translate_PMOVSXWDrm;
  m[llvm::X86::PMOVSXWQrr] = translate_PMOVSXWQrr;
  m[llvm::X86::PMOVSXWQrm] = translate_PMOVSXWQrm;
  m[llvm::X86::PMOVSXDQrr] = translate_PMOVSXDQrr;
  m[llvm::X86::PMOVSXDQrm] = translate_PMOVSXDQrm;

  m[llvm::X86::PMOVZXBWrr] = translate_PMOVZXBWrr;
  m[llvm::X86::PMOVZXBWrm] = translate_PMOVZXBWrm;
  m[llvm::X86::PMOVZXBDrr] = translate_PMOVZXBDrr;
  m[llvm::X86::PMOVZXBDrm] = translate_PMOVZXBDrm;
  m[llvm::X86::PMOVZXBQrr] = translate_PMOVZXBQrr;
  m[llvm::X86::PMOVZXBQrm] = translate_PMOVZXBQrm;
  m[llvm::X86::PMOVZXWDrr] = translate_PMOVZXWDrr;
  m[llvm::X86::PMOVZXWDrm] = translate_PMOVZXWDrm;
  m[llvm::X86::PMOVZXWQrr] = translate_PMOVZXWQrr;
  m[llvm::X86::PMOVZXWQrm] = translate_PMOVZXWQrm;
  m[llvm::X86::PMOVZXDQrr] = translate_PMOVZXDQrr;
  m[llvm::X86::PMOVZXDQrm] = translate_PMOVZXDQrm;

  m[llvm::X86::PBLENDVBrr0] = translate_PBLENDVBrr0;
  m[llvm::X86::PBLENDVBrm0] = translate_PBLENDVBrm0;

  m[llvm::X86::MOVHLPSrr] = translate_MOVHLPSrr;
  m[llvm::X86::MOVLHPSrr] = translate_MOVLHPSrr;

  m[llvm::X86::PMULUDQrr] = translate_PMULUDQrr;
  m[llvm::X86::PMULUDQrm] = translate_PMULUDQrm;

  m[llvm::X86::CVTTPS2DQrr] = translate_CVTTPS2DQrr;
  m[llvm::X86::CVTTPS2DQrm] = translate_CVTTPS2DQrm;

  m[llvm::X86::MOVHPDrm] = translate_MOVHPDrm;
  m[llvm::X86::MOVHPDmr] = translate_MOVHPDmr;

  m[llvm::X86::MOVLPDrm] = translate_MOVLPDrm;
  m[llvm::X86::MOVLPDmr] = doMOVSmr<64>;

  // we don't care if its moving two single precision floats
  // or a double precision float. 64 bits are 64 bits
  m[llvm::X86::MOVLPSrm] = translate_MOVLPDrm;
  m[llvm::X86::MOVLPSmr] = doMOVSmr<64>;

  m[llvm::X86::SHUFPSrri] = translate_SHUFPSrri;
  m[llvm::X86::SHUFPSrmi] = translate_SHUFPSrmi;
  m[llvm::X86::SHUFPDrri] = translate_SHUFPDrri;
  m[llvm::X86::SHUFPDrmi] = translate_SHUFPDrmi;

  m[llvm::X86::PSHUFHWri] = translate_PSHUFHWri;
  m[llvm::X86::PSHUFHWmi] = translate_PSHUFHWmi;
  m[llvm::X86::PSHUFLWri] = translate_PSHUFLWri;
  m[llvm::X86::PSHUFLWmi] = translate_PSHUFLWmi;

  m[llvm::X86::UNPCKLPSrm] = translate_UNPCKLPSrm;
  m[llvm::X86::UNPCKLPSrr] = translate_UNPCKLPSrr;
  m[llvm::X86::UNPCKLPDrm] = translate_UNPCKLPDrm;
  m[llvm::X86::UNPCKLPDrr] = translate_UNPCKLPDrr;

  m[llvm::X86::UNPCKHPDrr] = translate_UNPCKHPDrr;

  m[llvm::X86::CVTPS2PDrm] = translate_CVTPS2PDrm;
  m[llvm::X86::CVTPS2PDrr] = translate_CVTPS2PDrr;

  m[llvm::X86::CVTDQ2PSrr] = translate_CVTDQ2PSrr;

  m[llvm::X86::CVTPD2PSrm] = translate_CVTPD2PSrm;
  m[llvm::X86::CVTPD2PSrr] = translate_CVTPD2PSrr;

  m[llvm::X86::MOV64toPQIrr] = translate_MOV64toPQIrr;
  m[llvm::X86::MOVPQIto64rr] = doMOVSrr<64, 0, 1>;
  m[llvm::X86::MOV64toSDrm] = translate_MOV64toSDrm;
  m[llvm::X86::MOVQI2PQIrm] = translate_MOVQI2PQIrm;
  m[llvm::X86::MOVPQI2QImr] = doMOVSmr<64>;

  m[llvm::X86::MOVDDUPrr] = translate_MOVDDUPrr;

  m[llvm::X86::SUBPDrr] = translate_SUBPDrr;
  m[llvm::X86::SUBPDrm] = translate_SUBPDrm;

  m[llvm::X86::SUBPSrr] = translate_SUBPSrr;
  m[llvm::X86::SUBPSrm] = translate_SUBPSrm;

  m[llvm::X86::ADDPDrr] = translate_ADDPDrr;
  m[llvm::X86::ADDPDrm] = translate_ADDPDrm;

  m[llvm::X86::ADDPSrr] = translate_ADDPSrr;
  m[llvm::X86::ADDPSrm] = translate_ADDPSrm;

  m[llvm::X86::MULPDrr] = translate_MULPDrr;
  m[llvm::X86::MULPDrm] = translate_MULPDrm;

  m[llvm::X86::MULPSrr] = translate_MULPSrr;
  m[llvm::X86::MULPSrm] = translate_MULPSrm;

  m[llvm::X86::DIVPSrr] = translate_DIVPSrr;
  m[llvm::X86::DIVPSrm] = translate_DIVPSrm;

  m[llvm::X86::DIVPDrr] = translate_DIVPDrr;
  m[llvm::X86::DIVPDrm] = translate_DIVPDrm;

  m[llvm::X86::MMX_PORirr] = translate_MMX_PORirr;
  m[llvm::X86::MMX_PORirm] = translate_MMX_PORirm;
}
