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
#include "mcsema/Arch/X86/Semantics/MOV.h"

#include "mcsema/BC/Util.h"

#include "mcsema/CFG/Externals.h"

#include "mcsema/cfgToLLVM/JumpTables.h"

#define NASSERT(cond) TASSERT(cond, "")

template<int width>
static int GET_XAX() {
  if (64 == width) {
    return llvm::X86::RAX;
  } else if (32 == width) {
    return llvm::X86::EAX;
  } else if (16 == width) {
    return llvm::X86::AX;
  } else if (8 == width) {
    return llvm::X86::AL;
  } else {
    throw TErr(__LINE__, __FILE__, "Unknown width!");
  }
}

template<int width>
static InstTransResult doMRMovBE(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 llvm::Value *dstAddr,
                                 const llvm::MCOperand &src) {
  //MOV <mem>, <r>
  TASSERT(src.isReg(), "src is not a register");
  TASSERT(dstAddr != NULL, "Destination addr can't be null");

  auto srcReg = R_READ<width>(b, src.getReg());

  switch (width) {
    case 16: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcReg,
                                                 CONST_V<width>(b, width / 2),
                                                 "", b);
      auto o2 = llvm::BinaryOperator::CreateShl(srcReg,
                                                CONST_V<width>(b, width / 2),
                                                "", b);
      srcReg = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                            b);
      break;
    }

    case 32: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcReg, CONST_V<width>(b, 8),
                                                 "", b);
      o1 = llvm::BinaryOperator::Create(llvm::Instruction::And, o1,
                                        CONST_V<width>(b, 0xFF00FF), "", b);

      auto o2 = llvm::BinaryOperator::CreateShl(srcReg, CONST_V<width>(b, 8),
                                                "", b);
      o2 = llvm::BinaryOperator::Create(llvm::Instruction::And, o2,
                                        CONST_V<width>(b, 0xFF00FF00), "", b);

      auto val = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                              b);

      auto val1 = llvm::BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16),
                                                   "", b);
      auto val2 = llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 16),
                                                  "", b);

      srcReg = llvm::BinaryOperator::Create(llvm::Instruction::Or, val1, val2,
                                            "", b);
      break;
    }

    case 64: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcReg, CONST_V<width>(b, 8),
                                                 "", b);
      o1 = llvm::BinaryOperator::Create(llvm::Instruction::And, o1,
                                        CONST_V<width>(b, 0x00FF00FF00FF00FF),
                                        "", b);

      auto o2 = llvm::BinaryOperator::CreateShl(srcReg, CONST_V<width>(b, 8),
                                                "", b);
      o2 = llvm::BinaryOperator::Create(llvm::Instruction::And, o2,
                                        CONST_V<width>(b, 0xFF00FF00FF00FF00),
                                        "", b);

      auto val = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                              b);

      auto o3 = llvm::BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "",
                                                 b);
      o3 = llvm::BinaryOperator::Create(llvm::Instruction::And, o3,
                                        CONST_V<width>(b, 0x0000FFFF0000FFFF),
                                        "", b);

      auto o4 = llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "",
                                                b);
      o4 = llvm::BinaryOperator::Create(llvm::Instruction::And, o3,
                                        CONST_V<width>(b, 0xFFFF0000FFFF0000),
                                        "", b);

      auto val1 = llvm::BinaryOperator::Create(llvm::Instruction::Or, o3, o4,
                                               "", b);

      srcReg = llvm::BinaryOperator::Create(
          llvm::Instruction::Or,
          llvm::BinaryOperator::CreateLShr(val1, CONST_V<width>(b, 32), "", b),
          llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 32), "", b),
          "", b);
      break;
    }
    default:
      throw TErr(__LINE__, __FILE__, "Unknown width!");
      break;
  }

  // Does not affect any flags
  M_WRITE<width>(ip, b, dstAddr, srcReg);
  return ContinueBlock;
}

template<int width>
static InstTransResult doRRMovD(NativeInstPtr ip, llvm::BasicBlock *b,
                                const llvm::MCOperand &dst,
                                const llvm::MCOperand &src) {
  //MOV <r>, <r>
  TASSERT(src.isReg(), "");
  TASSERT(dst.isReg(), "");
  R_WRITE<width>(b, dst.getReg(), R_READ<width>(b, src.getReg()));
  return ContinueBlock;
}

template<int width>
static InstTransResult doRMMovBE(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 llvm::Value *srcAddr,
                                 const llvm::MCOperand &dst) {
  //MOV <r>, <mem>
  TASSERT(dst.isReg(), "dst is not a register");
  TASSERT(srcAddr != NULL, "Destination addr can't be null");

  llvm::Value *srcVal = M_READ<width>(ip, b, srcAddr);

  switch (width) {
    case 16: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcVal,
                                                 CONST_V<width>(b, width / 2),
                                                 "", b);
      auto o2 = llvm::BinaryOperator::CreateShl(srcVal,
                                                CONST_V<width>(b, width / 2),
                                                "", b);
      srcVal = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                            b);
    }
      break;

    case 32: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcVal, CONST_V<width>(b, 8),
                                                 "", b);
      o1 = llvm::BinaryOperator::Create(llvm::Instruction::And, o1,
                                        CONST_V<width>(b, 0xFF00FF), "", b);

      auto o2 = llvm::BinaryOperator::CreateShl(srcVal, CONST_V<width>(b, 8),
                                                "", b);
      o2 = llvm::BinaryOperator::Create(llvm::Instruction::And, o2,
                                        CONST_V<width>(b, 0xFF00FF00), "", b);

      auto val = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                              b);

      auto val1 = llvm::BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16),
                                                   "", b);
      auto val2 = llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 16),
                                                  "", b);

      srcVal = llvm::BinaryOperator::Create(llvm::Instruction::Or, val1, val2,
                                            "", b);
    }
      break;

    case 64: {
      auto o1 = llvm::BinaryOperator::CreateLShr(srcVal, CONST_V<width>(b, 8),
                                                 "", b);
      o1 = llvm::BinaryOperator::Create(llvm::Instruction::And, o1,
                                        CONST_V<width>(b, 0x00FF00FF00FF00FF),
                                        "", b);

      auto o2 = llvm::BinaryOperator::CreateShl(srcVal, CONST_V<width>(b, 8),
                                                "", b);
      o2 = llvm::BinaryOperator::Create(llvm::Instruction::And, o2,
                                        CONST_V<width>(b, 0xFF00FF00FF00FF00),
                                        "", b);

      auto val = llvm::BinaryOperator::Create(llvm::Instruction::Or, o1, o2, "",
                                              b);

      auto o3 = llvm::BinaryOperator::CreateLShr(val, CONST_V<width>(b, 16), "",
                                                 b);
      o3 = llvm::BinaryOperator::Create(llvm::Instruction::And, o3,
                                        CONST_V<width>(b, 0x0000FFFF0000FFFF),
                                        "", b);

      auto o4 = llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 16), "",
                                                b);
      o4 = llvm::BinaryOperator::Create(llvm::Instruction::And, o3,
                                        CONST_V<width>(b, 0xFFFF0000FFFF0000),
                                        "", b);

      auto val1 = llvm::BinaryOperator::Create(llvm::Instruction::Or, o3, o4,
                                               "", b);

      auto o5 = llvm::BinaryOperator::CreateLShr(val1, CONST_V<width>(b, 32),
                                                 "", b);

      auto o6 = llvm::BinaryOperator::CreateShl(val, CONST_V<width>(b, 32), "",
                                                b);

      srcVal = llvm::BinaryOperator::Create(llvm::Instruction::Or, o5, o6, "",
                                            b);
    }
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Unknown width!");
      break;
  }

  // Does not affect any flags

  R_WRITE<width>(b, dst.getReg(), srcVal);

  return ContinueBlock;
}

// given a pointer, attempt to load its value into a
// <width> sized integer.
//
// Will check for pointers to integers and pointers to
// arrays of size <= width.
template<int width>
static llvm::Value* getLoadableValue(llvm::Value *ptr,
                                     llvm::BasicBlock *block) {

  if ( !ptr->getType()->isPointerTy()) {
    // not a pointer, can't load it
    std::cout << __FUNCTION__ << ": Can't load value, not a pointer type"
              << std::endl;
    return nullptr;
  }

  auto ptr_ty = llvm::dyn_cast<llvm::PointerType>(ptr->getType());
  auto ut = ptr_ty->getPointerElementType();

  if (ut->isFloatingPointTy()) {
    throw TErr(__LINE__, __FILE__,
               "NIY: Floating point externs not yet supported");
  }

  // check if its an integer of acceptable width
  if (auto it = llvm::dyn_cast<llvm::IntegerType>(ut)) {
    unsigned bw = it->getIntegerBitWidth();

    if (bw == width) {
      return noAliasMCSemaScope(new llvm::LoadInst(ptr, "", block));
    } else if (bw < width) {
      llvm::Value *to_ext = noAliasMCSemaScope(
          new llvm::LoadInst(ptr, "", block));
      return new llvm::ZExtInst(
          to_ext, llvm::Type::getIntNTy(block->getContext(), width), "", block);
    } else {
      // can't load this -- its bigger than register width
      std::cout << __FUNCTION__ << ": Integer bigger than bitwidth (" << bw
                << " > " << width << ")" << std::endl;
      return nullptr;
    }
  }

  // check if its an array that we can bitcast as an acceptable integer
  if (auto arrt = llvm::dyn_cast<llvm::ArrayType>(ut)) {
    uint64_t elements = arrt->getNumElements();
    auto elem_t = arrt->getElementType();

    unsigned elem_size = elem_t->getPrimitiveSizeInBits();

    uint64_t total_size = elem_size * elements;

    if (total_size == 0) {
      // not an array of primitives. can't deal with this yet
      std::cout << __FUNCTION__ << ": array has no elements" << std::endl;
      return nullptr;
    } else if (total_size <= width) {

      auto new_int_ty = llvm::Type::getIntNTy(block->getContext(), total_size);
      auto new_ptr_ty = llvm::PointerType::get(new_int_ty,
                                               ptr_ty->getAddressSpace());
      auto int_ptr = llvm::CastInst::CreatePointerCast(ptr, new_ptr_ty, "",
                                                       block);
      auto as_int = noAliasMCSemaScope(new llvm::LoadInst(int_ptr, "", block));
      // bitcast to integer
      TASSERT(as_int != NULL, "Can't load pointer");

      if (total_size == width) {
        return as_int;
      }

      // and then zext if its less than width
      return new llvm::ZExtInst(
          as_int, llvm::Type::getIntNTy(block->getContext(), width), "", block);

    } else {
      // too big to load
      std::cout << __FUNCTION__ << ": total array size bigger than bitwidth ("
                << total_size << " > " << width << ")" << std::endl;
      return nullptr;
    }
  }

  throw TErr(__LINE__, __FILE__, "NIY: Unknown external data type");
  return nullptr;
}

template<int width>
static llvm::Value* getSegmentValue(llvm::BasicBlock *&b, unsigned sreg) {
  llvm::Value *val = nullptr;
  switch (sreg) {
    case llvm::X86::SS:
      val = CONST_V<width>(b, 0x23);
      break;
    case llvm::X86::CS:
      val = CONST_V<width>(b, 0x1B);
      break;
    case llvm::X86::DS:
      val = CONST_V<width>(b, 0x23);
      break;
    case llvm::X86::ES:
      val = CONST_V<width>(b, 0x23);
      break;
    case llvm::X86::FS:
      val = CONST_V<width>(b, 0x3B);
      break;
    case llvm::X86::GS:
      val = CONST_V<width>(b, 0x00);
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Unknown Segment Register");
      break;
  }

  return val;

}

template<int width>
static InstTransResult doMSMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *dstAddr,
                               const llvm::MCOperand &src) {
  NASSERT(dstAddr != NULL);
  NASSERT(src.isReg());
  auto seg_val = getSegmentValue<width>(b, src.getReg());
  M_WRITE<width>(ip, b, dstAddr, seg_val);
  return ContinueBlock;
}

template<int width>
static InstTransResult doSMMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *dstAddr,
                               const llvm::MCOperand &src) {
  NASSERT(dstAddr != NULL);
  NASSERT(src.isReg());
  auto seg_val = getSegmentValue<width>(b, src.getReg());
  M_WRITE<width>(ip, b, dstAddr, seg_val);
  return ContinueBlock;
}

template<int width>
static InstTransResult doRSMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &dst,
                               const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  auto seg_val = getSegmentValue<width>(b, src.getReg());
  R_WRITE<width>(b, dst.getReg(), seg_val);
  return ContinueBlock;
}

template<int dstWidth>
static llvm::Value *doMovSXV(NativeInstPtr ip, llvm::BasicBlock * b,
                             llvm::Value *src) {
  // do an SX
  return new llvm::SExtInst(src,
                            llvm::Type::getIntNTy(b->getContext(), dstWidth),
                            "", b);
}

template<int width>
static InstTransResult doRIMovV(NativeInstPtr ip, llvm::BasicBlock *&b,
                                llvm::Value *src, const llvm::MCOperand &dst) {
  //MOV <r>, <imm>
  NASSERT(src != NULL);
  NASSERT(dst.isReg());

  //write the constant into the supplied register
  R_WRITE<width>(b, dst.getReg(), src);

  return ContinueBlock;
}

template<int width>
static InstTransResult doRIMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               const llvm::MCOperand &src,
                               const llvm::MCOperand &dst) {
  //MOV <r>, <imm>
  NASSERT(src.isImm());
  NASSERT(dst.isReg());

  //write the constant into the supplied register
  R_WRITE<width>(b, dst.getReg(), CONST_V<width>(b, src.getImm()));

  return ContinueBlock;
}

template<int width>
static InstTransResult doMIMovV(NativeInstPtr ip, llvm::BasicBlock *&b,
                                llvm::Value *dstAddr, llvm::Value *src) {
  //MOV <m>, <imm>
  //store the constant in src into dstAddr

  M_WRITE<width>(ip, b, dstAddr, src);

  return ContinueBlock;
}

template<int width>
static InstTransResult doMIMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *dstAddr,
                               const llvm::MCOperand &src) {
  //MOV <m>, <imm>
  //store the constant in src into dstAddr
  NASSERT(dstAddr != NULL);
  NASSERT(src.isImm());

  return doMIMovV<width>(ip, b, dstAddr, CONST_V<width>(b, src.getImm()));
}

template<int dstWidth, int srcWidth>
static InstTransResult doMIMov(NativeInstPtr ip, llvm::BasicBlock *&b,
                               llvm::Value *dstAddr,
                               const llvm::MCOperand &src) {
  //MOV <m>, <imm>
  //store the constant in src into dstAddr
  NASSERT(dstAddr != NULL);
  NASSERT(src.isImm());
  return doMIMovV<dstWidth>(ip, b, dstAddr, CONST_V<srcWidth>(b, src.getImm()));
}

template<int dstWidth, int srcWidth>
static InstTransResult doMovZXRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst,
                                 const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  TASSERT(dstWidth > srcWidth, "Must ZExt to a greater bitwidth")

  //do a read from src of the appropriate width
  auto fromSrc = R_READ<srcWidth>(b, src.getReg());

  //extend
  auto toT = llvm::Type::getIntNTy(b->getContext(), dstWidth);
  auto xt = new llvm::ZExtInst(fromSrc, toT, "", b);

  //write into dst
  R_WRITE<dstWidth>(b, dst.getReg(), xt);

  return ContinueBlock;
}

template<int dstWidth, int srcWidth>
static InstTransResult doMovZXRM(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst, llvm::Value *src) {
  NASSERT(dst.isReg());
  NASSERT(src != NULL);

  if (dstWidth == 32 && srcWidth == 8 && ip->has_jump_index_table()) {
    doJumpIndexTableViaSwitch(b, ip);
    return ContinueBlock;
  }

  TASSERT(dstWidth > srcWidth, "Must ZExt to a greater bitwidth")
  //do a read from src of the appropriate width
  auto fromSrc = M_READ<srcWidth>(ip, b, src);

  //extend
  auto toT = llvm::Type::getIntNTy(b->getContext(), dstWidth);
  auto xt = new llvm::ZExtInst(fromSrc, toT, "", b);

  //write into dst
  R_WRITE<dstWidth>(b, dst.getReg(), xt);

  return ContinueBlock;
}

template<int dstWidth, int srcWidth>
static InstTransResult doMovSXRR(NativeInstPtr ip, llvm::BasicBlock *&b,
                                 const llvm::MCOperand &dst,
                                 const llvm::MCOperand &src) {
  NASSERT(dst.isReg());
  NASSERT(src.isReg());
  llvm::Value *regOp = nullptr;
  regOp = R_READ<srcWidth>(b, src.getReg());
  auto r = doMovSXV<dstWidth>(ip, b, regOp);
  R_WRITE<dstWidth>(b, dst.getReg(), r);
  return ContinueBlock;
}

template<int dstWidth, int srcWidth>
static InstTransResult doMovSXRM(NativeInstPtr ip, llvm::BasicBlock *&block,
                                 const llvm::MCOperand &dst, llvm::Value *src) {
  NASSERT(dst.isReg());
  NASSERT(src != NULL);
  auto r = doMovSXV<dstWidth>(ip, block, M_READ<srcWidth>(ip, block, src));
  R_WRITE<dstWidth>(block, dst.getReg(), r);
  return ContinueBlock;
}

GENERIC_TRANSLATION(MOV8rr, doRRMov<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV8rr_REV, doRRMov<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV16rr, doRRMov<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV16rr_REV, doRRMov<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV32rr, doRRMov<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV32rr_REV, doRRMov<32>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION(MOV64rr, doRRMov<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV64rr_REV, doRRMov<64>(ip, block, OP(0), OP(1)))

//MOVPQIto64rr
GENERIC_TRANSLATION(MOVPQIto64rr, doRRMovD<64>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION(MOV8ri, doRIMov<8>(ip, block, OP(1), OP(0)))
GENERIC_TRANSLATION(MOV16ri, doRIMov<16>(ip, block, OP(1), OP(0)))

GENERIC_TRANSLATION_REF(MOV8mi, doMIMov<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMIMov<8>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV16mi, doMIMov<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMIMov<16>(ip, block, MEM_REFERENCE(0), OP(5)))

static InstTransResult translate_MOV32mi(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_code_ref()) {
    llvm::Value *addrInt = IMM_AS_DATA_REF<32>(block, natM, ip);
    if (ip->has_mem_reference) {
      ret = doMIMovV<32>(ip, block, MEM_REFERENCE(0), addrInt);
    } else {
      ret = doMIMovV<32>(ip, block, ADDR_NOREF(0), addrInt);
    }
  } else {
    if (ip->has_mem_reference && ip->has_imm_reference) {
      llvm::Value *data_v = nullptr;
      if (shouldSubtractImageBase(M)) {
        // if we're here, then
        // * archGetImageBase is defined
        // * we are on win64

        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
        data_v = doSubtractImageBase<32>(data_v, block);
      } else {
        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
      }
      doMIMovV<32>(ip, block, MEM_REFERENCE(0), data_v);
    } else if (ip->has_mem_reference) {
      doMIMov<32>(ip, block, MEM_REFERENCE(0), OP(5));
    } else if (ip->has_imm_reference) {
      llvm::Value *data_v = nullptr;
      if (shouldSubtractImageBase(M)) {
        // if we're here, then
        // * archGetImageBase is defined
        // * we are on win64

        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
        data_v = doSubtractImageBase<32>(data_v, block);
      } else {
        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
      }

      doMIMovV<32>(ip, block, ADDR_NOREF(0), data_v);
    } else {
      // no references
      doMIMov<32>(ip, block, ADDR_NOREF(0), OP(5));
    }
  }
  ret = ContinueBlock;
  return ret;
}

static InstTransResult translate_MOV64mi32(TranslationContext &ctx,
                                           llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_code_ref()) {
    llvm::Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
    if (ip->has_mem_reference) {
      ret = doMIMovV<64>(ip, block, MEM_REFERENCE(0), addrInt);
    } else {
      ret = doMIMovV<64>(ip, block, ADDR_NOREF(0), addrInt);
    }
  } else {
    if (ip->has_mem_reference && ip->has_imm_reference) {
      llvm::Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
      if (shouldSubtractImageBase(M)) {
        data_v = doSubtractImageBase<64>(data_v, block);
      }
      doMIMovV<64>(ip, block, MEM_REFERENCE(0), data_v);

    } else if (ip->has_imm_reference) {
      llvm::Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
      if (shouldSubtractImageBase(M)) {
        data_v = doSubtractImageBase<64>(data_v, block);
      }
      doMIMovV<64>(ip, block, ADDR_NOREF(0), data_v);
    } else if (ip->has_mem_reference) {
      doMIMov<64>(ip, block, MEM_REFERENCE(0), OP(5));
    } else {
      ret = doMIMov<64>(ip, block, ADDR_NOREF(0), OP(5));
    }

  }
  return ContinueBlock;
}

template <int dest_width, int addr_width>
static InstTransResult translate_MOV_NaoM(
    TranslationContext &ctx, llvm::BasicBlock *&block) {
  auto &inst = ctx.natI->get_inst();
  auto &imm_addr_op = inst.getOperand(0);
  auto &reg_op = inst.getOperand(1);
  auto F = block->getParent();
  auto ip = ctx.natI;

  if (!imm_addr_op.isImm() || !reg_op.isReg()) {
    return TranslateErrorUnsupported;
  }

  // this is awful, but sometimes IDA detects the immediate
  // as a memory reference. However, this instruction can only
  // have an immediate, so this is safe
  if (ip->has_imm_reference || ip->has_mem_reference) {
    ip->has_imm_reference = true;
    ip->set_reference(NativeInst::IMMRef,
                      ip->get_reference(NativeInst::MEMRef));
  }

  reg_op = llvm::MCOperand::createReg(GET_XAX<dest_width>());
  llvm::Value *addr = nullptr;

  // loading functions only available if its a 32-bit offset
  if (ctx.natI->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ctx.natI, block);
    TASSERT(addrInt != 0, "Could not get external data reference");
    addr = addrInt;
  } else if (ctx.natI->has_imm_reference) {
    addr = IMM_AS_DATA_REF(block, ctx.natM, ctx.natI);
  } else {
    addr = ADDR_TO_POINTER<dest_width>(block, CONST_V<addr_width>(block, imm_addr_op.getImm()));
  }

  return doRMMov<dest_width>(ctx.natI, block, addr, reg_op);
}

template <int dest_width, int addr_width>
static InstTransResult translate_MOV_NoaM(
    TranslationContext &ctx, llvm::BasicBlock *&block) {
  auto &inst = ctx.natI->get_inst();
  auto &imm_addr_op = inst.getOperand(0);
  auto &reg_op = inst.getOperand(1);
  auto F = block->getParent();
  auto ip = ctx.natI;

  if (!imm_addr_op.isImm() || !reg_op.isReg()) {
    return TranslateErrorUnsupported;
  }

  // this is awful, but sometimes IDA detects the immediate
  // as a memory reference. However, this instruction can only
  // have an immediate, so this is safe
  if (ip->has_imm_reference || ip->has_mem_reference) {
    ip->has_imm_reference = true;
    ip->set_reference(NativeInst::IMMRef,
                      ip->get_reference(NativeInst::MEMRef));
  }

  reg_op = llvm::MCOperand::createReg(GET_XAX<dest_width>());

  llvm::Value *addr = nullptr;
  // loading functions only available if its a 32-bit offset
  if (ctx.natI->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ctx.natI, block);
    TASSERT(addrInt != 0, "Could not get external data reference");
    addr = addrInt;
  } else if (ctx.natI->has_imm_reference) {
    addr = IMM_AS_DATA_REF(block, ctx.natM, ctx.natI);
  } else {
    addr = ADDR_TO_POINTER<dest_width>(block, CONST_V<addr_width>(block, imm_addr_op.getImm()));
  }

  return doMRMov<dest_width>(ctx.natI, block, addr, reg_op);
}

GENERIC_TRANSLATION_REF(MOV8mr, doMRMov<8>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMRMov<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOV16mr, doMRMov<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMRMov<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOV8rm, doRMMov<8>(ip, block, ADDR_NOREF(1), OP(0)),
                        doRMMov<8>(ip, block, MEM_REFERENCE(1), OP(0)))
GENERIC_TRANSLATION_REF(MOV16rm, doRMMov<16>(ip, block, ADDR_NOREF(1), OP(0)),
                        doRMMov<16>(ip, block, MEM_REFERENCE(1), OP(0)))
GENERIC_TRANSLATION(MOVZX16rr8, (doMovZXRR<16,8>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION(MOVZX32rr8, (doMovZXRR<32,8>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION(MOVZX32rr16, ( doMovZXRR<32,16>(ip, block, OP(0), OP(1))))

GENERIC_TRANSLATION(MOV16rs, doRSMov<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV32rs, doRSMov<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV64rs, doRSMov<64>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION_REF(MOV64ms, doMSMov<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMSMov<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV64sm, doSMMov<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doSMMov<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV32ms, doMSMov<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMSMov<32>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV16ms, doMSMov<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMSMov<16>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOVZX16rm8,
                        (doMovZXRM<16,8>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovZXRM<16,8>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVZX32rm8,
                        (doMovZXRM<32,8>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovZXRM<32,8>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVZX32rm16,
                        (doMovZXRM<32,16>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovZXRM<32,16>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION(MOVSX16rr8, (doMovSXRR<16,8>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION(MOVSX32rr16, ( doMovSXRR<32,16>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION(MOVSX32rr8, (doMovSXRR<32,8>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION(MOVSX64rr32, (doMovSXRR<64,32>(ip, block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(MOVSX16rm8,
                        (doMovSXRM<16,8>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<16,8>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVSX32rm8,
                        (doMovSXRM<32,8>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<32,8>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVSX32rm16,
                        (doMovSXRM<32,16>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<32,16>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION_REF(MOVSX64rm8,
                        (doMovSXRM<64,8>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<64,8>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVSX64rm16,
                        (doMovSXRM<64,16>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<64,16>(ip, block, OP(0), MEM_REFERENCE(1))))
GENERIC_TRANSLATION_REF(MOVSX64rm32,
                        (doMovSXRM<64, 32>(ip, block, OP(0), ADDR_NOREF(1))),
                        (doMovSXRM<64, 32>(ip, block, OP(0), MEM_REFERENCE(1))))

GENERIC_TRANSLATION_REF(MOVBE16rm,
                        doMRMovBE<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMRMovBE<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE32rm,
                        doMRMovBE<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMRMovBE<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE64rm,
                        doMRMovBE<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doMRMovBE<64>(ip, block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOVBE16mr,
                        doRMMovBE<16>(ip, block, ADDR_NOREF(0), OP(5)),
                        doRMMovBE<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE32mr,
                        doRMMovBE<32>(ip, block, ADDR_NOREF(0), OP(5)),
                        doRMMovBE<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE64mr,
                        doRMMovBE<64>(ip, block, ADDR_NOREF(0), OP(5)),
                        doRMMovBE<64>(ip, block, MEM_REFERENCE(0), OP(5)))

static InstTransResult translate_MOV32ri(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_code_ref()) {
    llvm::Value *addrInt = IMM_AS_DATA_REF<32>(block, natM, ip);
    ret = doRIMovV<32>(ip, block, addrInt, OP(0));
  } else {
    if (ip->has_imm_reference) {
      llvm::Value *data_v = nullptr;
      if (shouldSubtractImageBase(M)) {
        // if we're here, then
        // * archGetImageBase is defined
        // * we are on win64

        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
        data_v = doSubtractImageBase<32>(data_v, block);
      } else {
        data_v = IMM_AS_DATA_REF<32>(block, natM, ip);
      }

      ret = doRIMovV<32>(ip, block, data_v, OP(0));

    } else {
      ret = doRIMov<32>(ip, block, OP(1), OP(0));
    }
  }
  return ret;
}

static InstTransResult translate_MOV64ri(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_code_ref()) {
    llvm::Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
    ret = doRIMovV<64>(ip, block, addrInt, OP(0));
  } else if (ip->has_imm_reference) {
    llvm::Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
    if (shouldSubtractImageBase(M)) {
      // if we're here, then
      // * archGetImageBase is defined
      // * we are on win64

      data_v = doSubtractImageBase<64>(data_v, block);
    }

    ret = doRIMovV<64>(ip, block, data_v, OP(0));
  } else {
    ret = doRIMov<64>(ip, block, OP(1), OP(0));
  }
  return ret;
}

//write to memory
template<int width>
static InstTransResult translate_MOVoa(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  InstTransResult ret;

  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();
  unsigned eaxReg = GET_XAX<width>();

  // loading functions only available if its a 32-bit offset
  if (ip->has_external_ref() && width == 32) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    TASSERT(addrInt != 0, "Could not get external data reference");
    doMRMov<width>(ip, block, addrInt, llvm::MCOperand::createReg(eaxReg));
    return ContinueBlock;
  }

  // this is awful, but sometimes IDA detects the immediate
  // as a memory reference. However, this instruction can only
  // have an immediate, so this is safe
  if (ip->has_imm_reference || ip->has_mem_reference) {
    ip->has_imm_reference = true;
    ip->set_reference(NativeInst::IMMRef,
                      ip->get_reference(NativeInst::MEMRef));
  }

  if (ip->has_imm_reference) {

    llvm::Value *data_v = nullptr;
    if (width == 32 && shouldSubtractImageBase(M)) {
      // if we're here, then
      // * archGetImageBase is defined
      // * we are on win64

      data_v = IMM_AS_DATA_REF(block, natM, ip);
      data_v = doSubtractImageBase<32>(data_v, block);
    } else {
      data_v = IMM_AS_DATA_REF(block, natM, ip);
    }
    ret = doMRMov<width>(ip, block, data_v,
                         llvm::MCOperand::createReg(eaxReg));
  } else {
    llvm::Value *addrv = CONST_V<width>(block, OP(0).getImm());
    ret = doMRMov<width>(ip, block, addrv,
                         llvm::MCOperand::createReg(eaxReg));
  }
  return ret;
}

//write to EAX
template<int width>
static InstTransResult translate_MOVao(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  unsigned eaxReg = GET_XAX<width>();

  // loading functions only available if its a 32-bit offset
  if (ip->has_external_ref() && width == 32) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    TASSERT(addrInt != 0, "Could not get external data reference");
    doRMMov<width>(ip, block, addrInt, llvm::MCOperand::createReg(eaxReg));
    return ContinueBlock;
  }

  // this is awful, but sometimes IDA detects the immediate
  // as a memory reference. However, this instruction can only
  // have an immediate, so this is safe
  if (ip->has_imm_reference || ip->has_mem_reference) {
    ip->has_imm_reference = true;
    ip->set_reference(NativeInst::IMMRef,
                      ip->get_reference(NativeInst::MEMRef));
  }

  if (ip->has_code_ref()) {
    llvm::Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
    ret = doRMMov<width>(ip, block, addrInt,
                         llvm::MCOperand::createReg(eaxReg));
  } else {
    if (ip->has_imm_reference) {
      llvm::Value *data_v = nullptr;
      if (width == 32 && shouldSubtractImageBase(M)) {
        // if we're here, then
        // * archGetImageBase is defined
        // * we are on win64

        data_v = IMM_AS_DATA_REF(block, natM, ip);
        data_v = doSubtractImageBase<32>(data_v, block);
      } else {
        data_v = IMM_AS_DATA_REF(block, natM, ip);
      }
      ret = doRMMov<width>(ip, block, data_v,
                           llvm::MCOperand::createReg(eaxReg));
    } else {
      llvm::Value *addrv = CONST_V<width>(block, OP(0).getImm());
      ret = doRMMov<width>(ip, block, addrv,
                           llvm::MCOperand::createReg(eaxReg));
    }
  }
  return ret;
}

static InstTransResult translate_MOV32rm(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {

  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    ret = doRMMov<32>(ip, block, addrInt, OP(0));
    TASSERT(addrInt != NULL, "Could not get address for external");
    return ContinueBlock;
  } else if (ip->has_mem_reference) {

    llvm::Value *data_v = nullptr;
    if (shouldSubtractImageBase(M)) {
      // if we're here, then
      // * archGetImageBase is defined
      // * we are on win64

      data_v = MEM_AS_DATA_REF(block, natM, inst, ip, 1);
      data_v = doSubtractImageBase<32>(data_v, block);
    } else {
      data_v = MEM_AS_DATA_REF(block, natM, inst, ip, 1);
    }

    ret = doRMMov<32>(ip, block, data_v, OP(0));
  } else {
    ret = doRMMov<32>(ip, block, ADDR_NOREF(1), OP(0));
  }
  return ret;
}

static InstTransResult translate_MOV32mr(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
    TASSERT(addrInt != NULL, "Could not get address for external");
    return doMRMov<32>(ip, block, addrInt, OP(5));
  } else if (ip->has_mem_reference) {
    ret = doMRMov<32>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0),
                      OP(5));
  } else {
    ret = doMRMov<32>(ip, block, ADDR_NOREF(0), OP(5));
  }
  return ret;
}

static InstTransResult translate_MOV64rm(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
    TASSERT(addrInt != NULL, "Could not get address for external");
    doRMMov<64>(ip, block, addrInt, OP(0));
    return ContinueBlock;
  } else if (ip->has_mem_reference) {
    llvm::Value *data_v = nullptr;
    if (shouldSubtractImageBase(M)) {
      // if we're here, then
      // * archGetImageBase is defined
      // * we are on win64

      data_v = MEM_AS_DATA_REF(block, natM, inst, ip, 1);
      data_v = doSubtractImageBase<64>(data_v, block);
    } else {
      data_v = MEM_AS_DATA_REF(block, natM, inst, ip, 1);
    }
    ret = doRMMov<64>(ip, block, data_v, OP(0));
  } else {
    ret = doRMMov<64>(ip, block, ADDR_NOREF(1), OP(0));
  }
  return ret;
}

static InstTransResult translate_MOV64mr(TranslationContext &ctx,
                                         llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  if (ip->has_external_ref()) {
    llvm::Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
    TASSERT(addrInt != NULL, "Could not get address for external");
    return doMRMov<64>(ip, block, addrInt, OP(5));
  } else if (ip->has_mem_reference) {
    ret = doMRMov<64>(ip, block, MEM_AS_DATA_REF(block, natM, inst, ip, 0),
                      OP(5));
  } else {
    ret = doMRMov<64>(ip, block, ADDR_NOREF(0), OP(5));
  }
  return ret;
}

// sign extend %eax to %rax
static InstTransResult translate_CDQE(TranslationContext &ctx,
                                      llvm::BasicBlock *&block) {
  InstTransResult ret = ContinueBlock;
  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto natM = ctx.natM;
  auto &inst = ip->get_inst();

  llvm::Value *eax = R_READ<32>(block, llvm::X86::EAX);
  llvm::Value *rax = new llvm::SExtInst(
      eax, llvm::Type::getInt64Ty(block->getContext()), "", block);
  R_WRITE<64>(block, llvm::X86::RAX, rax);
  return ret;
}

void MOV_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::MOV8rr] = translate_MOV8rr;
  m[llvm::X86::MOV8rr_REV] = translate_MOV8rr_REV;
  m[llvm::X86::MOV16rr] = translate_MOV16rr;
  m[llvm::X86::MOV16rr_REV] = translate_MOV16rr_REV;
  m[llvm::X86::MOV32rr] = translate_MOV32rr;
  m[llvm::X86::MOV32rr_REV] = translate_MOV32rr_REV;
  m[llvm::X86::MOV64rr] = translate_MOV64rr;
  m[llvm::X86::MOV64rr_REV] = translate_MOV64rr_REV;

  m[llvm::X86::MOV8ri] = translate_MOV8ri;
  m[llvm::X86::MOV16ri] = translate_MOV16ri;
  m[llvm::X86::MOV32ao32] = translate_MOVao<32>;
  m[llvm::X86::MOV16ao16] = translate_MOVao<16>;
//  m[llvm::X86::MOV8ao8] = translate_MOVao<8>;
  m[llvm::X86::MOV32o32a] = translate_MOVoa<32>;
  m[llvm::X86::MOV16o16a] = translate_MOVoa<16>;
//  m[llvm::X86::MOV8o8a] = translate_MOVoa<8>;
  m[llvm::X86::MOV32ri] = translate_MOV32ri;
  m[llvm::X86::MOV32ri_alt] = translate_MOV32ri;
  m[llvm::X86::MOV64ri] = translate_MOV64ri;
  m[llvm::X86::MOV64ri32] = translate_MOV64ri;

  m[llvm::X86::MOV8mi] = translate_MOV8mi;
  m[llvm::X86::MOV16mi] = translate_MOV16mi;
  m[llvm::X86::MOV32mi] = translate_MOV32mi;
  m[llvm::X86::MOV64mi32] = translate_MOV64mi32;

  m[llvm::X86::MOV8mr] = translate_MOV8mr;
  m[llvm::X86::MOV16mr] = translate_MOV16mr;

  m[llvm::X86::MOV8o32a] = translate_MOV_NoaM<8, 32>;
  m[llvm::X86::MOV8ao32] = translate_MOV_NaoM<8, 32>;

  m[llvm::X86::MOV16o32a] = translate_MOV_NoaM<16, 32>;
  m[llvm::X86::MOV16ao32] = translate_MOV_NaoM<16, 32>;

  m[llvm::X86::MOV32mr] = translate_MOV32mr;
  m[llvm::X86::MOV64mr] = translate_MOV64mr;

  m[llvm::X86::MOV8rm] = translate_MOV8rm;
  m[llvm::X86::MOV16rm] = translate_MOV16rm;
  m[llvm::X86::MOV32rm] = translate_MOV32rm;
  m[llvm::X86::MOV64rm] = translate_MOV64rm;

  m[llvm::X86::MOVZX16rr8] = translate_MOVZX16rr8;
  m[llvm::X86::MOVZX32rr8] = translate_MOVZX32rr8;
  m[llvm::X86::MOVZX32rr16] = translate_MOVZX32rr16;

  m[llvm::X86::MOVZX16rm8] = translate_MOVZX16rm8;
  m[llvm::X86::MOVZX32rm8] = translate_MOVZX32rm8;
  m[llvm::X86::MOVZX32rm16] = translate_MOVZX32rm16;

  m[llvm::X86::MOVSX16rr8] = translate_MOVSX16rr8;
  m[llvm::X86::MOVSX32rr16] = translate_MOVSX32rr16;
  m[llvm::X86::MOVSX32rr8] = translate_MOVSX32rr8;
  m[llvm::X86::MOVSX64rr8] = translate_MOVSX32rr8;
  m[llvm::X86::MOVSX64rr16] = translate_MOVSX32rr8;
  m[llvm::X86::MOVSX64rr32] = translate_MOVSX64rr32;

  m[llvm::X86::MOVSX16rm8] = translate_MOVSX16rm8;
  m[llvm::X86::MOVSX32rm8] = translate_MOVSX32rm8;
  m[llvm::X86::MOVSX32rm16] = translate_MOVSX32rm16;
  m[llvm::X86::MOVSX64rm8] = translate_MOVSX64rm8;
  m[llvm::X86::MOVSX64rm16] = translate_MOVSX64rm16;
  m[llvm::X86::MOVSX64rm32] = translate_MOVSX64rm32;

  m[llvm::X86::MOV16rs] = translate_MOV16rs;
  m[llvm::X86::MOV32rs] = translate_MOV32rs;
  m[llvm::X86::MOV64rs] = translate_MOV64rs;

  m[llvm::X86::MOV16ms] = translate_MOV16ms;
  m[llvm::X86::MOV32ms] = translate_MOV32ms;
  m[llvm::X86::MOV64ms] = translate_MOV64ms;

  m[llvm::X86::MOV16sr] = translate_MOV32rs;
  m[llvm::X86::MOV32sr] = translate_MOV32rs;
  m[llvm::X86::MOV64sr] = translate_MOV32rs;

  //m[llvm::X86::MOV16sm] = translate_MOV16sm;
  // m[llvm::X86::MOV32sm] = translate_MOV32sm;
  // m[llvm::X86::MOV64sm] = translate_MOV64sm;

  m[llvm::X86::MOVBE16rm] = translate_MOVBE16rm;
  m[llvm::X86::MOVBE32rm] = translate_MOVBE32rm;
  m[llvm::X86::MOVBE64rm] = translate_MOVBE64rm;

  m[llvm::X86::MOVBE16mr] = translate_MOVBE16mr;
  m[llvm::X86::MOVBE32mr] = translate_MOVBE32mr;
  m[llvm::X86::MOVBE64mr] = translate_MOVBE64mr;

  m[llvm::X86::CDQE] = translate_CDQE;

}

