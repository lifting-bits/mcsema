/*
Copyright (c) 2014, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
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
#include "InstructionDispatch.h"
#include "toLLVM.h"
#include "X86.h"
#include "raiseX86.h"
#include "x86Helpers.h"
#include "x86Instrs_flagops.h"
#include "x86Instrs_String.h"

template<int width, int regWidth>
static BasicBlock *doCmpsV(BasicBlock *pred) {
  auto lhsRegVal = R_READ<regWidth>(pred, llvm::X86::RSI);
  auto lhsFromMem = M_READ_0<width>(pred, lhsRegVal);

  auto rhsRegVal = R_READ<regWidth>(pred, llvm::X86::RDI);
  auto rhsFromMem = M_READ_0<width>(pred, rhsRegVal);

  //perform a subtraction
  auto res = llvm::BinaryOperator::CreateSub(lhsFromMem, rhsFromMem, "", pred);

  //set flags according to this result
  WritePF<width>(pred, res);
  WriteZF<width>(pred, res);
  WriteSF<width>(pred, res);
  WriteCFSub(pred, lhsFromMem, rhsFromMem);
  WriteAFAddSub<width>(pred, res, lhsFromMem, rhsFromMem);
  WriteOFSub<width>(pred, res, lhsFromMem, rhsFromMem);

  //now, either increment or decrement EDI based on the DF flag
  CREATE_BLOCK(df_zero, pred);
  CREATE_BLOCK(df_one, pred);

  CREATE_BLOCK(post_write, pred);

  auto df = F_READ(pred, DF);
  auto dfSwitch = llvm::SwitchInst::Create(df, block_df_zero, 2, pred);
  dfSwitch->addCase(CONST_V<1>(pred, 0), block_df_zero);
  dfSwitch->addCase(CONST_V<1>(pred, 1), block_df_one);

  uint32_t disp = 0;
  switch (width) {
    case 8:
      disp = 1;
      break;
    case 16:
      disp = 2;
      break;
    case 32:
      disp = 4;
      break;
    case 64:
      disp = 8;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid width");
  }

  //if zero, then add to src and dst registers
  auto add_lhs = llvm::BinaryOperator::CreateAdd(
      lhsRegVal, CONST_V<regWidth>(block_df_zero, disp), "", block_df_zero);

  auto add_rhs = llvm::BinaryOperator::CreateAdd(
      rhsRegVal, CONST_V<regWidth>(block_df_zero, disp), "", block_df_zero);

  R_WRITE<regWidth>(block_df_zero, llvm::X86::RSI, add_lhs);
  R_WRITE<regWidth>(block_df_zero, llvm::X86::RDI, add_rhs);

  // return to a single block, to which we will add new instructions
  llvm::BranchInst::Create(block_post_write, block_df_zero);

  //if one, then sub to src and dst registers
  auto sub_lhs = llvm::BinaryOperator::CreateSub(
      lhsRegVal, CONST_V<regWidth>(block_df_one, disp), "", block_df_one);

  auto sub_rhs = llvm::BinaryOperator::CreateSub(
      rhsRegVal, CONST_V<regWidth>(block_df_one, disp), "", block_df_one);

  R_WRITE<regWidth>(block_df_one, llvm::X86::RSI, sub_lhs);
  R_WRITE<regWidth>(block_df_one, llvm::X86::RDI, sub_rhs);

  // return to a single block, to which we will add new instructions
  llvm::BranchInst::Create(block_post_write, block_df_one);

  return block_post_write;
}

template <int width>
static llvm::BasicBlock *doCmps(llvm::BasicBlock *b) {
  auto M = b->getParent()->getParent();
  auto bitWidth = ArchPointerSize(M);
  if (Pointer32 == bitWidth) {
    return doCmpsV<width, 32>(b);
  } else {
    return doCmpsV<width, 64>(b);
  }
}

template<int opSize, int regWidth>
static llvm::BasicBlock *doStosV(llvm::BasicBlock *pred) {
  //write EAX to [EDI]
  auto dstRegVal = R_READ<regWidth>(pred, llvm::X86::RDI);
  auto fromEax = R_READ<opSize>(pred, llvm::X86::RAX);

  // store EAX in [EDI]
  M_WRITE_0<opSize>(pred, dstRegVal, fromEax);

  //now, either increment or decrement EDI based on the DF flag
  auto &C = pred->getContext();
  auto F = pred->getParent();
  auto isZero = llvm::BasicBlock::Create(C, "", F);
  auto isOne = llvm::BasicBlock::Create(C, "", F);
  auto doWrite = llvm::BasicBlock::Create(C, "", F);

  //compare DF against 0
  auto cmpRes = new llvm::ICmpInst( *pred, llvm::CmpInst::ICMP_EQ,
                                   F_READ(pred, DF), CONST_V<1>(pred, 0), "");

  //do a branch based on the cmp
  llvm::BranchInst::Create(isZero, isOne, cmpRes, pred);

  uint64_t disp = 0;
  switch (opSize) {
    case 8:
      disp = 1;
      break;
    case 16:
      disp = 2;
      break;
    case 32:
      disp = 4;
      break;
    case 64:
      disp = 8;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid width");
  }

  //populate the isZero branch
  //if zero, then add to src and dst registers
  auto zeroDst = llvm::BinaryOperator::CreateAdd(
      dstRegVal, CONST_V<regWidth>(isZero, disp), "", isZero);
  llvm::BranchInst::Create(doWrite, isZero);

  //populate the isOne branch
  //if one, then sub from src and dst registers
  auto oneDst = llvm::BinaryOperator::CreateSub(dstRegVal,
                                                CONST_V<regWidth>(isOne, disp),
                                                "", isOne);
  llvm::BranchInst::Create(doWrite, isOne);

  //populate the update of the source/dest registers
  auto newDst = llvm::PHINode::Create(llvm::Type::getIntNTy(C, regWidth), 2, "",
                                      doWrite);

  newDst->addIncoming(zeroDst, isZero);
  newDst->addIncoming(oneDst, isOne);

  R_WRITE<regWidth>(doWrite, llvm::X86::RDI, newDst);

  return doWrite;
}

template<int width, int regWidth>
static llvm::BasicBlock *doScasV(llvm::BasicBlock *pred) {
  //do a read from the memory pointed to by EDI
  auto dstRegVal = R_READ<regWidth>(pred, llvm::X86::RDI);
  auto fromMem = M_READ_0<width>(pred, dstRegVal);
  //read the value in EAX
  auto fromEax = R_READ<width>(pred, llvm::X86::RAX);

  //perform a subtraction
  auto res = llvm::BinaryOperator::CreateSub(fromEax, fromMem, "", pred);

  //set flags according to this result
  WritePF<width>(pred, res);
  WriteZF<width>(pred, res);
  WriteSF<width>(pred, res);
  WriteCFSub(pred, fromEax, fromMem);
  WriteAFAddSub<width>(pred, res, fromEax, fromMem);
  WriteOFSub<width>(pred, res, fromEax, fromMem);

  auto F = pred->getParent();
  auto &C = pred->getContext();

  //now, either increment or decrement EDI based on the DF flag

  auto isZero = llvm::BasicBlock::Create(C, "", F);
  auto isOne = llvm::BasicBlock::Create(C, "", F);
  auto doWrite = llvm::BasicBlock::Create(C, "", F);

  //compare DF against 0
  auto cmpRes = new llvm::ICmpInst( *pred, llvm::CmpInst::ICMP_EQ,
                                   F_READ(pred, DF), CONST_V<1>(pred, 0), "");

  //do a branch based on the cmp
  llvm::BranchInst::Create(isZero, isOne, cmpRes, pred);

  uint64_t disp = 0;
  switch (width) {
    case 8:
      disp = 1;
      break;
    case 16:
      disp = 2;
      break;
    case 32:
      disp = 4;
      break;
    case 64:
      disp = 8;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid width");
  }

  //populate the isZero branch
  //if zero, then add to src and dst registers
  auto zeroDst = llvm::BinaryOperator::CreateAdd(
      dstRegVal, CONST_V<regWidth>(isZero, disp), "", isZero);
  llvm::BranchInst::Create(doWrite, isZero);

  //populate the isOne branch
  //if one, then sub from src and dst registers
  auto oneDst = llvm::BinaryOperator::CreateSub(dstRegVal,
                                                CONST_V<regWidth>(isOne, disp),
                                                "", isOne);
  llvm::BranchInst::Create(doWrite, isOne);

  //populate the update of the source/dest registers
  auto newDst = llvm::PHINode::Create(llvm::Type::getIntNTy(C, regWidth), 2, "",
                                      doWrite);

  newDst->addIncoming(zeroDst, isZero);
  newDst->addIncoming(oneDst, isOne);

  R_WRITE<regWidth>(doWrite, llvm::X86::RDI, newDst);

  return doWrite;
}

template<int width>
static llvm::BasicBlock *doScas(llvm::BasicBlock *B) {
  auto M = B->getParent()->getParent();
  const auto bitWidth = ArchPointerSize(M);
  if (bitWidth == Pointer32) {
    return doScasV<width, x86::REG_SIZE>(B);
  } else {
    return doScasV<width, x86_64::REG_SIZE>(B);
  }
}

// Uses RDI & RSI registers 
template <int width>
static llvm::BasicBlock *doMovsV(llvm::BasicBlock *pred) {
  auto F = pred->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();
  uint32_t bitWidth = ArchPointerSize(M);
  llvm::Value *dstRegVal = nullptr;
  llvm::Value *srcRegVal = nullptr;

  if(bitWidth == x86::REG_SIZE){
    dstRegVal = x86::R_READ<32>(pred, llvm::X86::EDI);
    srcRegVal = x86::R_READ<32>(pred, llvm::X86::ESI);
  } else {
    dstRegVal = x86_64::R_READ<64>(pred, llvm::X86::RDI);
    srcRegVal = x86_64::R_READ<64>(pred, llvm::X86::RSI);
  }

  //do the actual move
  M_WRITE_0<width>(pred, dstRegVal, M_READ_0<width>(pred, srcRegVal));

  //we need to make a few new basic blocks
  auto isZero = llvm::BasicBlock::Create(C, "", F);
  auto isOne = llvm::BasicBlock::Create(C, "", F);
  auto doWrite = llvm::BasicBlock::Create(C, "", F);

  //compare DF against 0
  auto cmpRes = new llvm::ICmpInst(
      *pred, CmpInst::ICMP_EQ, F_READ(pred, DF), CONST_V<1>(pred, 0), "");

  //do a branch based on the cmp
  llvm::BranchInst::Create(isZero, isOne, cmpRes, pred);

  uint64_t disp = 0;
  switch (width) {
    case 8:
      disp = 1;
      break;
    case 16:
      disp = 2;
      break;
    case 32:
      disp = 4;
      break;
    case 64:
      disp = 8;
      break;
    default:
      throw TErr(__LINE__, __FILE__, "Invalid width");
  }

  //populate the isZero branch
  //if zero, then add to src and dst registers
  auto zeroSrc = llvm::BinaryOperator::CreateAdd(
      srcRegVal, CONST_V(isZero, bitWidth, disp), "", isZero);
  auto zeroDst = llvm::BinaryOperator::CreateAdd(
      dstRegVal, CONST_V(isZero, bitWidth, disp), "", isZero);

  llvm::BranchInst::Create(doWrite, isZero);

  //populate the isOne branch
  //if one, then sub from src and dst registers
  auto oneSrc = llvm::BinaryOperator::CreateSub(
      srcRegVal, CONST_V(isOne, bitWidth, disp), "", isOne);

  auto oneDst = llvm::BinaryOperator::CreateSub(
      dstRegVal, CONST_V(isOne, bitWidth, disp), "", isOne);

  llvm::BranchInst::Create(doWrite, isOne);

  //populate the update of the source/dest registers
  auto RegTy = llvm::Type::getIntNTy(C, bitWidth);
  auto newSrc = llvm::PHINode::Create(RegTy, 2, "", doWrite);
  auto newDst = llvm::PHINode::Create(RegTy, 2, "", doWrite);

  newSrc->addIncoming(zeroSrc, isZero);
  newDst->addIncoming(zeroDst, isZero);
  newSrc->addIncoming(oneSrc, isOne);
  newDst->addIncoming(oneDst, isOne);

  if(bitWidth == x86::REG_SIZE){
    x86::R_WRITE<32>(doWrite, llvm::X86::ESI, newSrc);
    x86::R_WRITE<32>(doWrite, llvm::X86::EDI, newDst);
  } else {
    x86_64::R_WRITE<64>(doWrite, llvm::X86::RSI, newSrc);
    x86_64::R_WRITE<64>(doWrite, llvm::X86::RDI, newDst);
  }

  return doWrite;
}

template<int opSize, int bitWidth, bool use_condition>
static llvm::BasicBlock *doRep(llvm::BasicBlock *b, llvm::BasicBlock *bodyB,
                               llvm::BasicBlock *bodyE,
                               llvm::CmpInst::Predicate check_op) {
  auto F = b->getParent();
  auto &C = F->getContext();
  //WHILE countReg != 0 do 'body'
  auto loopHeader = llvm::BasicBlock::Create(C, "", F);

  // final exit block
  auto rest = llvm::BasicBlock::Create(C, "", F);

  //create a branch in the beginning block to the loop header
  llvm::BranchInst::Create(loopHeader, b);

  auto xcx = 32 == bitWidth ? llvm::X86::ECX : llvm::X86::RCX;

  // check if ECX == 0; if so, bail
  auto counter_entry = R_READ<bitWidth>(loopHeader, xcx);
  auto cmp_entry = new llvm::ICmpInst( *loopHeader, llvm::CmpInst::ICMP_NE,
                                      counter_entry,
                                      CONST_V<bitWidth>(loopHeader, 0));
  // branch either to the body of the loop, or to the final exit block
  llvm::BranchInst::Create(bodyB, rest, cmp_entry, loopHeader);

  //Add REP code to the end of the body implementation
  auto cTmp = R_READ<bitWidth>(bodyE, xcx);
  auto cTmpDec = llvm::BinaryOperator::CreateSub(cTmp,
                                                 CONST_V<bitWidth>(bodyE, 1),
                                                 "", bodyE);
  R_WRITE<bitWidth>(bodyE, xcx, cTmpDec);

  // check if ECX == 0
  auto cmp = new llvm::ICmpInst( *bodyE, llvm::CmpInst::ICMP_EQ, cTmpDec,
                                CONST_V<bitWidth>(bodyE, 0));

  llvm::Value *final_condition = nullptr;

  if (use_condition) {
    //do a test on the REP condition
    auto zf_val = F_READ(bodyE, ZF);
    // ICMP_EQ ==  "terminate if ZF == 0"
    // ICMP_NE ==  "temrinate if ZF == 1"
    auto rep_condition = new llvm::ICmpInst( *bodyE, check_op, zf_val,
                                            CONST_V<1>(bodyE, 0));

    final_condition = llvm::BinaryOperator::Create(llvm::Instruction::Or, cmp,
                                                   rep_condition, "", bodyE);

  } else {
    final_condition = cmp;
  }

  //if either_cond is true, exit; otherwise, redo loop
  llvm::BranchInst::Create(rest,  // exit block
      bodyB,  // redo loop block
      final_condition,  // test condition
      bodyE  // where to insert this check
      );

  // this is the final return block
  return rest;
} 

template<int opSize, int bitWidth>
static llvm::BasicBlock *doRepN(llvm::BasicBlock *b, llvm::BasicBlock *bodyB,
                                llvm::BasicBlock *bodyE) {
  return doRep<opSize, bitWidth, false>(
      b, bodyB, bodyE, llvm::CmpInst::ICMP_EQ);

}

template<int opSize, int bitWidth>
static llvm::BasicBlock *doRepe(llvm::BasicBlock *b, llvm::BasicBlock *bodyB,
                                llvm::BasicBlock *bodyE) {
  return doRep<opSize, bitWidth, true>(
      b, bodyB, bodyE, llvm::CmpInst::ICMP_EQ);

}

template<int opSize, int bitWidth>
static llvm::BasicBlock *doRepNe(llvm::BasicBlock *b, llvm::BasicBlock *bodyB,
                                 llvm::BasicBlock *bodyE) {
  return doRep<opSize, bitWidth, true>(
      b, bodyB, bodyE, llvm::CmpInst::ICMP_NE);

}

#define DO_REP_CALL(CALL, NAME) \
    template <int opSize> \
    static InstTransResult doRep ## NAME (llvm::BasicBlock *&b) {\
      llvm::BasicBlock *bodyBegin =  \
          llvm::BasicBlock::Create(b->getContext(), "", b->getParent()); \
      llvm::BasicBlock  *bodyEnd = (CALL); \
      llvm::Module *M = b->getParent()->getParent();\
      if (ArchPointerSize(M) == Pointer32) {\
        b = doRepN<opSize,32>(b, bodyBegin, bodyEnd); \
      } else {\
        b = doRepN<opSize,64>(b, bodyBegin, bodyEnd); \
      }\
      return ContinueBlock; \
    }

#define DO_REPE_CALL(CALL, NAME) \
    template <int opSize> \
    static InstTransResult doRepe ## NAME (llvm::BasicBlock *&b) {\
      llvm::BasicBlock *bodyBegin =  \
          llvm::BasicBlock::Create(b->getContext(), "", b->getParent()); \
      llvm::BasicBlock  *bodyEnd = (CALL); \
      llvm::Module *M = b->getParent()->getParent();\
      if (ArchPointerSize(M) == Pointer32) {\
        b = doRepe<opSize,32>(b, bodyBegin, bodyEnd); \
      } else {\
        b = doRepe<opSize,64>(b, bodyBegin, bodyEnd); \
      }\
      return ContinueBlock; \
    }

#define DO_REPNE_CALL(CALL, NAME) \
    template <int opSize> \
    static InstTransResult doRepNe ## NAME (llvm::BasicBlock *&b) {\
      llvm::BasicBlock *bodyBegin =  \
          llvm::BasicBlock::Create(b->getContext(), "", b->getParent()); \
      llvm::BasicBlock  *bodyEnd = (CALL); \
      llvm::Module *M = b->getParent()->getParent();\
      if (ArchPointerSize(M) == Pointer32) {\
        b = doRepNe<opSize,32>(b, bodyBegin, bodyEnd); \
      } else {\
        b = doRepNe<opSize,64>(b, bodyBegin, bodyEnd); \
      }\
      return ContinueBlock; \
    }

DO_REPE_CALL(doCmps<opSize>(bodyBegin), Cmps)
DO_REPNE_CALL(doCmps<opSize>(bodyBegin), Cmps)
DO_REPNE_CALL(doScas<opSize>(bodyBegin), Scas)

template<int opSize, int bitWidth>
static InstTransResult doRepMovs(llvm::BasicBlock *&b) {

  auto bodyBegin = llvm::BasicBlock::Create(b->getContext(), "",
                                            b->getParent());
  auto bodyEnd = doMovsV<opSize>(bodyBegin);

  b = doRepN<opSize, bitWidth>(b, bodyBegin, bodyEnd);

  return ContinueBlock;
}

template<int width>
static InstTransResult doMovs(llvm::BasicBlock *&b, InstPtr ip) {
  //we will just kind of paste a new block into the end
  //here so that we have less duplicated logic
  llvm::Module *M = b->getParent()->getParent();
  int bitWidth = ArchPointerSize(M);
  Inst::Prefix pfx = ip->get_prefix();
  if (pfx == Inst::RepPrefix) {
    if (bitWidth == Pointer32) {
      doRepMovs<width, x86::REG_SIZE>(b);
    } else {
      doRepMovs<width, x86_64::REG_SIZE>(b);
    }
  } else {
    b = doMovsV<width>(b);
  }

  return ContinueBlock;
}

template <int opSize, int bitWidth>
static InstTransResult doRepStos(llvm::BasicBlock *&b) {
  auto bodyBegin = llvm::BasicBlock::Create(
      b->getContext(), "", b->getParent());
  auto bodyEnd = doStosV<opSize, bitWidth>(bodyBegin);
  b = doRepN<opSize, bitWidth>(b, bodyBegin, bodyEnd);
  return ContinueBlock;
}

template <int width>
static InstTransResult doStos(llvm::BasicBlock *&b, InstPtr ip) {
  auto M = b->getParent()->getParent();
  auto bitWidth = ArchPointerSize(M);
  Inst::Prefix pfx = ip->get_prefix();
  if (bitWidth == Pointer32) {
    if (pfx == Inst::RepPrefix) {
      doRepStos<width, x86::REG_SIZE>(b);
    } else {
      b = doStosV<width, x86::REG_SIZE>(b);
    }
  } else {
    if (pfx == Inst::RepPrefix) {
      doRepStos<width, x86_64::REG_SIZE>(b);
    } else {
      b = doStosV<width, x86_64::REG_SIZE>(b);
    }
  }
  return ContinueBlock;
}

GENERIC_TRANSLATION(MOVSD, doMovs<32>(block, ip))
GENERIC_TRANSLATION(REP_MOVSD_32, (doRepMovs<32, 32>(block)))
GENERIC_TRANSLATION(MOVSW, doMovs<16>(block, ip))
GENERIC_TRANSLATION(REP_MOVSW_32, (doRepMovs<16, 32>(block)))
GENERIC_TRANSLATION(MOVSB, doMovs<8>(block, ip))
GENERIC_TRANSLATION(REP_MOVSB_32, (doRepMovs<8, 32>(block)))

GENERIC_TRANSLATION(MOVSQ, doMovs<64>(block, ip))
GENERIC_TRANSLATION(REP_MOVSB_64, (doRepMovs<8, 64>(block)))
GENERIC_TRANSLATION(REP_MOVSW_64, (doRepMovs<16, 64>(block)))
GENERIC_TRANSLATION(REP_MOVSD_64, (doRepMovs<32, 64>(block)))
GENERIC_TRANSLATION(REP_MOVSQ_64, (doRepMovs<64, 64>(block)))

GENERIC_TRANSLATION(STOSQ, doStos<64>(block, ip))
GENERIC_TRANSLATION(STOSD, doStos<32>(block, ip))
GENERIC_TRANSLATION(STOSW, doStos<16>(block, ip))
GENERIC_TRANSLATION(STOSB, doStos<8>(block, ip))

GENERIC_TRANSLATION(REP_STOSB_64, (doRepStos<8, 64>(block)))
GENERIC_TRANSLATION(REP_STOSW_64, (doRepStos<16, 64>(block)))
GENERIC_TRANSLATION(REP_STOSD_64, (doRepStos<32, 64>(block)))
GENERIC_TRANSLATION(REP_STOSQ_64, (doRepStos<64, 64>(block)))

#define SCAS_TRANSLATION(NAME, WIDTH) \
    static InstTransResult translate_ ## NAME ( \
        NativeModulePtr natM, llvm::BasicBlock *& block, \
        InstPtr ip, llvm::MCInst &inst) {\
    InstTransResult ret = TranslateError;\
    Inst::Prefix pfx = ip->get_prefix();\
    switch(pfx) { \
      case Inst::NoPrefix: \
        throw TErr(__LINE__, __FILE__, "NIY"); \
        break; \
      case Inst::RepPrefix: \
        throw TErr(__LINE__, __FILE__, "NIY"); \
        break; \
      case Inst::RepNePrefix: \
        ret = doRepNeScas<WIDTH>(block); \
        break; \
      default: \
        throw TErr(__LINE__, __FILE__, "NIY"); \
    } \
    return ret ;\
}

#define CMPS_TRANSLATION(NAME, WIDTH) \
    static InstTransResult translate_ ## NAME ( \
        NativeModulePtr natM, llvm::BasicBlock *&block, \
        InstPtr ip, llvm::MCInst &inst) {\
    InstTransResult ret;\
    Inst::Prefix pfx = ip->get_prefix();\
    switch(pfx) { \
      case Inst::NoPrefix: \
        block = doCmps<WIDTH>(block); \
        ret = ContinueBlock; \
        break; \
      case Inst::RepPrefix: \
        ret = doRepeCmps<WIDTH>(block); \
        break; \
      case Inst::RepNePrefix: \
        ret = doRepNeCmps<WIDTH>(block); \
        break; \
      default: \
        throw TErr(__LINE__, __FILE__, "NIY"); \
    } \
    return ret ;\
}

SCAS_TRANSLATION(SCAS16, 16)
SCAS_TRANSLATION(SCAS32, 32)
SCAS_TRANSLATION(SCAS8, 8)

CMPS_TRANSLATION(CMPS8, 8)
CMPS_TRANSLATION(CMPS16, 16)
CMPS_TRANSLATION(CMPS32, 32)

void String_populateDispatchMap(DispatchMap &m) {
  m[llvm::X86::MOVSL] = translate_MOVSD;
  m[llvm::X86::REP_MOVSD_32] = translate_REP_MOVSD_32;
  m[llvm::X86::MOVSW] = translate_MOVSW;
  m[llvm::X86::REP_MOVSW_32] = translate_REP_MOVSW_32;
  m[llvm::X86::MOVSB] = translate_MOVSB;
  m[llvm::X86::REP_MOVSB_32] = translate_REP_MOVSB_32;

  m[llvm::X86::MOVSQ] = translate_MOVSQ;
  m[llvm::X86::REP_MOVSB_64] = translate_REP_MOVSB_64;
  m[llvm::X86::REP_MOVSW_64] = translate_REP_MOVSW_64;
  m[llvm::X86::REP_MOVSD_64] = translate_REP_MOVSD_64;
  m[llvm::X86::REP_MOVSQ_64] = translate_REP_MOVSQ_64;

  m[llvm::X86::STOSL] = translate_STOSD;
  m[llvm::X86::STOSW] = translate_STOSW;
  m[llvm::X86::STOSB] = translate_STOSB;

  m[llvm::X86::STOSQ] = translate_STOSQ;
  m[llvm::X86::REP_STOSB_64] = translate_REP_STOSB_64;
  m[llvm::X86::REP_STOSW_64] = translate_REP_STOSW_64;
  m[llvm::X86::REP_STOSD_64] = translate_REP_STOSD_64;
  m[llvm::X86::REP_STOSQ_64] = translate_REP_STOSQ_64;

  m[llvm::X86::SCASW] = translate_SCAS16;
  m[llvm::X86::SCASL] = translate_SCAS32;
  m[llvm::X86::SCASB] = translate_SCAS8;
  m[llvm::X86::CMPSB] = translate_CMPS8;
  m[llvm::X86::CMPSW] = translate_CMPS16;
  m[llvm::X86::CMPSL] = translate_CMPS32;
}
