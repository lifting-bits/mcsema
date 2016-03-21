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

using namespace llvm;

template <int width, int regWidth>
static BasicBlock *doCmpsV(BasicBlock *pred) {
    Value   *lhsRegVal = R_READ<regWidth>(pred, X86::RSI);
    Value   *lhsFromMem = M_READ_0<width>(pred, lhsRegVal);

    Value   *rhsRegVal = R_READ<regWidth>(pred, X86::RDI);
    Value   *rhsFromMem = M_READ_0<width>(pred, rhsRegVal);

    //perform a subtraction
    Value   *res = BinaryOperator::CreateSub(lhsFromMem, rhsFromMem, "", pred);

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

    Value *df = F_READ(pred, DF);
    SwitchInst *dfSwitch = SwitchInst::Create(df, block_df_zero, 2, pred);
    dfSwitch->addCase(CONST_V<1>(pred, 0), block_df_zero);
    dfSwitch->addCase(CONST_V<1>(pred, 1), block_df_one);

    uint32_t    disp;
    switch(width) {
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
    Value   *add_lhs = 
        BinaryOperator::CreateAdd(  lhsRegVal,
                                    CONST_V<regWidth>(block_df_zero, disp), 
                                    "", 
                                    block_df_zero);

    Value   *add_rhs = 
        BinaryOperator::CreateAdd(  rhsRegVal,
                                    CONST_V<regWidth>(block_df_zero, disp), 
                                    "", 
                                    block_df_zero);

    R_WRITE<regWidth>(block_df_zero, X86::RSI, add_lhs);
    R_WRITE<regWidth>(block_df_zero, X86::RDI, add_rhs);
    // return to a single block, to which we will add new instructions
    BranchInst::Create(block_post_write, block_df_zero);

    //if one, then sub to src and dst registers
    Value   *sub_lhs = 
        BinaryOperator::CreateSub(  lhsRegVal,
                                    CONST_V<regWidth>(block_df_one, disp), 
                                    "", 
                                    block_df_one);

    Value   *sub_rhs = 
        BinaryOperator::CreateSub(  rhsRegVal,
                                    CONST_V<regWidth>(block_df_one, disp), 
                                    "", 
                                    block_df_one);

    R_WRITE<regWidth>(block_df_one, X86::RSI, sub_lhs);
    R_WRITE<regWidth>(block_df_one, X86::RDI, sub_rhs);
    // return to a single block, to which we will add new instructions
    BranchInst::Create(block_post_write, block_df_one);

    return block_post_write;
}

template <int width>
static BasicBlock* doCmps(BasicBlock *b) {
	llvm::Module *M = b->getParent()->getParent();
	int bitWidth = getPointerSize(M);
	if(bitWidth == Pointer32)
    {
		return doCmpsV<width, x86::REG_SIZE>(b);
    }
	else
    {
		return doCmpsV<width, x86_64::REG_SIZE>(b);
    }
}

template <int opSize, int bitWidth>
static BasicBlock *doStosV(BasicBlock *pred) {
    //write EAX to [EDI]
    Value   *dstRegVal = R_READ<bitWidth>(pred, X86::RDI);
    Value   *fromEax = R_READ<opSize>(pred, X86::RAX);

    // store EAX in [EDI]
    M_WRITE_0<opSize>(pred, dstRegVal, fromEax);

    //now, either increment or decrement EDI based on the DF flag
    BasicBlock  *isZero = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());
    BasicBlock  *isOne = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());
    BasicBlock  *doWrite = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());

    //compare DF against 0
    Value   *cmpRes = new ICmpInst( *pred, 
                                    CmpInst::ICMP_EQ, 
                                    F_READ(pred, DF), 
                                    CONST_V<1>(pred, 0), 
                                    "");

    //do a branch based on the cmp
    BranchInst::Create(isZero, isOne, cmpRes, pred);

    uint64_t    disp;
    switch(opSize) {
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
    Value   *zeroDst = 
        BinaryOperator::CreateAdd(  dstRegVal, 
                                    CONST_V<bitWidth>(isZero, disp), 
                                    "", 
                                    isZero);
    BranchInst::Create(doWrite, isZero);

    //populate the isOne branch
    //if one, then sub from src and dst registers
    Value   *oneDst = 
        BinaryOperator::CreateSub(  dstRegVal, 
                                    CONST_V<bitWidth>(isOne, disp), 
                                    "", 
                                    isOne);
    BranchInst::Create(doWrite, isOne);

    //populate the update of the source/dest registers
    PHINode *newDst = 
        PHINode::Create(Type::getIntNTy(pred->getContext(), bitWidth), 
                        2, 
                        "", 
                        doWrite);

    newDst->addIncoming(zeroDst, isZero);
    newDst->addIncoming(oneDst, isOne);

    R_WRITE<bitWidth>(doWrite, X86::RDI, newDst);

    return doWrite;
}

template <int width, int regWidth>
static BasicBlock *doScasV(BasicBlock *pred) {
    //do a read from the memory pointed to by EDI
    Value   *dstRegVal = R_READ<regWidth>(pred, X86::RDI);
    Value   *fromMem = M_READ_0<width>(pred, dstRegVal);
    //read the value in EAX
    Value   *fromEax = R_READ<width>(pred, X86::RAX);

    //perform a subtraction
    Value   *res = BinaryOperator::CreateSub(fromEax, fromMem, "", pred);

    //set flags according to this result
    WritePF<width>(pred, res);
    WriteZF<width>(pred, res);
    WriteSF<width>(pred, res);
    WriteCFSub(pred, fromEax, fromMem);
    WriteAFAddSub<width>(pred, res, fromEax, fromMem);
    WriteOFSub<width>(pred, res, fromEax, fromMem);

    //now, either increment or decrement EDI based on the DF flag

    BasicBlock  *isZero = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());
    BasicBlock  *isOne = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());
    BasicBlock  *doWrite = 
        BasicBlock::Create(pred->getContext(), "", pred->getParent());

    //compare DF against 0
    Value   *cmpRes = new ICmpInst( *pred, 
                                    CmpInst::ICMP_EQ, 
                                    F_READ(pred, DF), 
                                    CONST_V<1>(pred, 0), 
                                    "");

    //do a branch based on the cmp
    BranchInst::Create(isZero, isOne, cmpRes, pred);

    uint64_t    disp;
    switch(width) {
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
    Value   *zeroDst = 
        BinaryOperator::CreateAdd(  dstRegVal, 
                                    CONST_V<regWidth>(isZero, disp), 
                                    "", 
                                    isZero);
    BranchInst::Create(doWrite, isZero);

    //populate the isOne branch
    //if one, then sub from src and dst registers
    Value   *oneDst = 
        BinaryOperator::CreateSub(  dstRegVal, 
                                    CONST_V<regWidth>(isOne, disp), 
                                    "", 
                                    isOne);
    BranchInst::Create(doWrite, isOne);

    //populate the update of the source/dest registers
    PHINode *newDst = 
        PHINode::Create(Type::getIntNTy(pred->getContext(), regWidth), 
                        2, 
                        "", 
                        doWrite);

    newDst->addIncoming(zeroDst, isZero);
    newDst->addIncoming(oneDst, isOne);

    R_WRITE<regWidth>(doWrite, X86::RDI, newDst);

    return doWrite;
}

template <int width>
static BasicBlock* doScas(BasicBlock *b) {
	llvm::Module *M = b->getParent()->getParent();
	int bitWidth = getPointerSize(M);
	if(bitWidth == Pointer32)
    {
		return doScasV<width, x86::REG_SIZE>(b);
    }
	else
    {
		return doScasV<width, x86_64::REG_SIZE>(b);
    }
}

// Uses RDI & RSI registers 
template <int width>
static BasicBlock *doMovsV(BasicBlock *pred) {
	llvm::Module *M = pred->getParent()->getParent();
	uint32_t bitWidth = getPointerSize(M);
	Value	*dstRegVal, *srcRegVal;
	
	if(bitWidth == x86::REG_SIZE){
		dstRegVal = x86::R_READ<32>(pred, X86::EDI);
		srcRegVal = x86::R_READ<32>(pred, X86::ESI);
	} else {
		dstRegVal = x86_64::R_READ<64>(pred, X86::RDI);
		srcRegVal = x86_64::R_READ<64>(pred, X86::RSI);
	}

	//do the actual move
	M_WRITE_0<width>(pred, dstRegVal, M_READ_0<width>(	pred, srcRegVal));

	//we need to make a few new basic blocks
	BasicBlock	*isZero = 
		BasicBlock::Create(pred->getContext(), "", pred->getParent());
	BasicBlock  *isOne = 
		BasicBlock::Create(pred->getContext(), "", pred->getParent());
	BasicBlock	*doWrite = 
		BasicBlock::Create(pred->getContext(), "", pred->getParent());

	//compare DF against 0
	Value	*cmpRes = new ICmpInst(	*pred, 
									CmpInst::ICMP_EQ, 
									F_READ(pred, DF), 
									CONST_V<1>(pred, 0), 
									"");

	//do a branch based on the cmp
    BranchInst::Create(isZero, isOne, cmpRes, pred);

	uint64_t	disp;
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
	Value	*zeroSrc = 
		BinaryOperator::CreateAdd(	srcRegVal, 
									CONST_V(isZero, bitWidth, disp), 
									"", 
									isZero);
	Value	*zeroDst = 
		BinaryOperator::CreateAdd(	dstRegVal, 
									CONST_V(isZero, bitWidth, disp), 
									"", 
									isZero);
	BranchInst::Create(doWrite, isZero);

	//populate the isOne branch
	//if one, then sub from src and dst registers
	Value	*oneSrc = 
		BinaryOperator::CreateSub(	srcRegVal, 
									CONST_V(isOne, bitWidth, disp), 
									"", 
									isOne);
	Value	*oneDst = 
		BinaryOperator::CreateSub(	dstRegVal, 
									CONST_V(isOne, bitWidth, disp), 
									"", 
									isOne);
	BranchInst::Create(doWrite, isOne);

	//populate the update of the source/dest registers
	PHINode	*newSrc = 
		PHINode::Create(Type::getIntNTy(pred->getContext(), bitWidth), 
						2, 
						"", 
						doWrite);
	PHINode	*newDst = 
		PHINode::Create(Type::getIntNTy(pred->getContext(), bitWidth), 
						2, 
						"", 
						doWrite);

	newSrc->addIncoming(zeroSrc, isZero);
	newDst->addIncoming(zeroDst, isZero);
	newSrc->addIncoming(oneSrc, isOne);
	newDst->addIncoming(oneDst, isOne);

	if(bitWidth == x86::REG_SIZE){
		x86::R_WRITE<32>(doWrite, X86::ESI, newSrc);
		x86::R_WRITE<32>(doWrite, X86::EDI, newDst);
	} else {
		x86_64::R_WRITE<64>(doWrite, X86::RSI, newSrc);
		x86_64::R_WRITE<64>(doWrite, X86::RDI, newDst);
	}

	return doWrite;
}

template <int opSize, int bitWidth, bool use_condition>
static BasicBlock *doRep(BasicBlock *b, BasicBlock *bodyB, BasicBlock *bodyE, CmpInst::Predicate check_op) {
    Function    *F = b->getParent();
    //WHILE countReg != 0 do 'body'
    BasicBlock  *loopHeader = BasicBlock::Create(F->getContext(), "", F);

    // final exit block
    BasicBlock  *rest = BasicBlock::Create(F->getContext(), "", F);

    //create a branch in the beginning block to the loop header
    BranchInst::Create(loopHeader, b);

    // check if ECX == 0; if so, bail
    Value   *counter_entry = R_READ<bitWidth>(loopHeader, X86::RCX);
    Value   *cmp_entry = new ICmpInst(*loopHeader,
                                CmpInst::ICMP_NE,
                                counter_entry,
                                CONST_V<bitWidth>(loopHeader, 0));
    // branch either to the body of the loop, or to the final exit block
    BranchInst::Create(bodyB, rest, cmp_entry, loopHeader);

    //Add REP code to the end of the body implementation
    Value   *cTmp = R_READ<bitWidth>(bodyE, X86::RCX);
    Value   *cTmpDec =
        BinaryOperator::CreateSub(cTmp, CONST_V<bitWidth>(bodyE, 1), "", bodyE);
    R_WRITE<bitWidth>(bodyE, X86::RCX, cTmpDec);

    // check if ECX == 0
    Value   *cmp = new ICmpInst(*bodyE,
                                CmpInst::ICMP_EQ,
                                cTmpDec,
                                CONST_V<bitWidth>(bodyE, 0));

    Value *final_condition =  nullptr;

    if(use_condition) {
        //do a test on the REP condition
        Value *zf_val = F_READ(bodyE, ZF);
        // ICMP_EQ ==  "terminate if ZF == 0"
        // ICMP_NE ==  "temrinate if ZF == 1"
        Value *rep_condition = new ICmpInst(*bodyE,
                check_op,
                zf_val,
                CONST_V<1>(bodyE, 0));

        final_condition =  BinaryOperator::Create(Instruction::Or, cmp, rep_condition, "", bodyE);

    } else {
        final_condition = cmp;
    }

    //if either_cond is true, exit; otherwise, redo loop
    BranchInst::Create(rest, // exit block
            bodyB, // redo loop block
            final_condition, // test condition
            bodyE // where to insert this check
            );

    // this is the final return block
    return rest;
} 

template <int opSize, int bitWidth>
static BasicBlock *doRepN(BasicBlock *b, BasicBlock *bodyB, BasicBlock *bodyE) {

    return doRep<opSize, bitWidth, false>(b, bodyB, bodyE, CmpInst::ICMP_EQ);

}

template <int opSize, int bitWidth>
static BasicBlock *doRepe(BasicBlock *b, BasicBlock *bodyB, BasicBlock *bodyE) {

    return doRep<opSize, bitWidth, true>(b, bodyB, bodyE, CmpInst::ICMP_EQ);

}

template <int opSize, int bitWidth>
static BasicBlock *doRepNe(BasicBlock *b, BasicBlock *bodyB, BasicBlock *bodyE) {

    return doRep<opSize, bitWidth, true>(b, bodyB, bodyE, CmpInst::ICMP_NE);

}

#define DO_REP_CALL(CALL, NAME) template <int opSize> static InstTransResult doRep ## NAME (BasicBlock *&b) {\
	BasicBlock	*bodyBegin =  \
		BasicBlock::Create(b->getContext(), "", b->getParent()); \
	BasicBlock	*bodyEnd = (CALL); \
    Module *M = b->getParent()->getParent();\
    if(getPointerSize(M) == Pointer32) {\
	b = doRepN<opSize,32>(b, bodyBegin, bodyEnd); \
    } else {\
	b = doRepN<opSize,64>(b, bodyBegin, bodyEnd); \
    }\
	return ContinueBlock; \
}

#define DO_REPE_CALL(CALL, NAME) template <int opSize> static InstTransResult doRepe ## NAME (BasicBlock *&b) {\
	BasicBlock	*bodyBegin =  \
		BasicBlock::Create(b->getContext(), "", b->getParent()); \
	BasicBlock	*bodyEnd = (CALL); \
    Module *M = b->getParent()->getParent();\
    if(getPointerSize(M) == Pointer32) {\
	b = doRepe<opSize,32>(b, bodyBegin, bodyEnd); \
    } else {\
	b = doRepe<opSize,64>(b, bodyBegin, bodyEnd); \
    }\
	return ContinueBlock; \
}

#define DO_REPNE_CALL(CALL, NAME) template <int opSize> static InstTransResult doRepNe ## NAME (BasicBlock *&b) {\
	BasicBlock	*bodyBegin =  \
		BasicBlock::Create(b->getContext(), "", b->getParent()); \
	BasicBlock	*bodyEnd = (CALL); \
    Module *M = b->getParent()->getParent();\
    if(getPointerSize(M) == Pointer32) {\
	b = doRepNe<opSize,32>(b, bodyBegin, bodyEnd); \
    } else {\
	b = doRepNe<opSize,64>(b, bodyBegin, bodyEnd); \
    }\
    return ContinueBlock; \
}

DO_REPE_CALL(doCmps<opSize>(bodyBegin), Cmps)
DO_REPNE_CALL(doCmps<opSize>(bodyBegin), Cmps)
DO_REPNE_CALL(doScas<opSize>(bodyBegin), Scas)

template <int opSize, int bitWidth>
static InstTransResult doRepMovs(BasicBlock *&b) {

    BasicBlock	*bodyBegin = 
        BasicBlock::Create(b->getContext(), "", b->getParent());
    BasicBlock	*bodyEnd = doMovsV<opSize>(bodyBegin);

    b = doRepN<opSize, bitWidth>(b, bodyBegin, bodyEnd);

    return ContinueBlock;
}

template <int width>
static InstTransResult doMovs(BasicBlock *&b, InstPtr ip) {
	//we will just kind of paste a new block into the end
	//here so that we have less duplicated logic
	llvm::Module *M = b->getParent()->getParent();
	int bitWidth = getPointerSize(M);
    Inst::Prefix pfx = ip->get_prefix();
    if(pfx == Inst::RepPrefix) {
        if(bitWidth == Pointer32)
        {
            doRepMovs<width, x86::REG_SIZE>(b);
        }
        else
        {
            doRepMovs<width, x86_64::REG_SIZE>(b);
        }
    } else {
        b = doMovsV<width>(b);
    }

	return ContinueBlock;
}

template <int opSize, int bitWidth>
static InstTransResult doRepStos(BasicBlock *&b) {

    BasicBlock	*bodyBegin = 
        BasicBlock::Create(b->getContext(), "", b->getParent());
    BasicBlock	*bodyEnd = doStosV<opSize, bitWidth>(bodyBegin);

    b = doRepN<opSize, bitWidth>(b, bodyBegin, bodyEnd);

    return ContinueBlock;
}

template <int width>
static InstTransResult doStos(BasicBlock *&b, InstPtr ip) {
	llvm::Module *M = b->getParent()->getParent();
	int bitWidth = getPointerSize(M);
    Inst::Prefix pfx = ip->get_prefix();
	if(bitWidth == Pointer32)
    {
        if(pfx == Inst::RepPrefix) {
            doRepStos<width, x86::REG_SIZE>(b);
        } else {
            b = doStosV<width, x86::REG_SIZE>(b);
        }
    }
	else
    {
        if(pfx == Inst::RepPrefix) {
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

#define SCAS_TRANSLATION(NAME, WIDTH) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Inst::Prefix        pfx = ip->get_prefix();\
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

#define CMPS_TRANSLATION(NAME, WIDTH) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {\
    InstTransResult ret;\
    Inst::Prefix        pfx = ip->get_prefix();\
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
        m[X86::MOVSL] = translate_MOVSD;
        m[X86::REP_MOVSD_32] = translate_REP_MOVSD_32;
        m[X86::MOVSW] = translate_MOVSW;
        m[X86::REP_MOVSW_32] = translate_REP_MOVSW_32;
        m[X86::MOVSB] = translate_MOVSB;
        m[X86::REP_MOVSB_32] = translate_REP_MOVSB_32;
		
		m[X86::MOVSQ] = translate_MOVSQ;
		m[X86::REP_MOVSB_64] = translate_REP_MOVSB_64;
		m[X86::REP_MOVSW_64] = translate_REP_MOVSW_64;
		m[X86::REP_MOVSD_64] = translate_REP_MOVSD_64;
		m[X86::REP_MOVSQ_64] = translate_REP_MOVSQ_64;

        m[X86::STOSL] = translate_STOSD;
        m[X86::STOSW] = translate_STOSW;
        m[X86::STOSB] = translate_STOSB;
		
		m[X86::STOSQ] = translate_STOSQ;
		m[X86::REP_STOSB_64] = translate_REP_STOSB_64;
		m[X86::REP_STOSW_64] = translate_REP_STOSW_64;
		m[X86::REP_STOSD_64] = translate_REP_STOSD_64;
		m[X86::REP_STOSQ_64] = translate_REP_STOSQ_64;
		

        m[X86::SCASW] = translate_SCAS16;
        m[X86::SCASL] = translate_SCAS32;
        m[X86::SCASB] = translate_SCAS8;
        m[X86::CMPSB] = translate_CMPS8;
        m[X86::CMPSW] = translate_CMPS16;
        m[X86::CMPSL] = translate_CMPS32;
}
