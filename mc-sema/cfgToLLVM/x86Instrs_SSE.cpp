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
#include "x86Instrs_SSE.h"
#include "x86Instrs_MOV.h"
#include "llvm/Support/Debug.h"

#include <tuple>

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

static std::tuple<VectorType*, Type*> getIntVectorTypes(BasicBlock *b, int ewidth, int count) {
    Type *elem_ty = Type::getIntNTy(b->getContext(), ewidth);
    VectorType *vt = VectorType::get(
            elem_ty,
            count);

    return std::tuple<VectorType*,Type*>(vt, elem_ty);
}

static std::tuple<VectorType*, Type*> getFPVectorTypes(BasicBlock *b, int ewidth, int count) {
    Type *elem_ty = nullptr;
    
    switch(ewidth) {
        case 64:
            elem_ty = Type::getDoubleTy(b->getContext());
            break;
        case 32:
            elem_ty = Type::getFloatTy(b->getContext());
            break;
        default:
            TASSERT(false, "Invalid width for fp vector");
    }

    VectorType *vt = VectorType::get(
            elem_ty,
            count);

    return std::tuple<VectorType*,Type*>(vt, elem_ty);
}

template<int width, int elementwidth>
static Value *INT_AS_VECTOR(BasicBlock *b, Value *input) {

    NASSERT(width % elementwidth == 0);

    unsigned count = width/elementwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elementwidth, count);

    // convert our base value to a vector
    Value *vecValue = CastInst::Create(
            Instruction::BitCast,
            input,
            vt,
            "",
            b);

    return vecValue;
}

template<int width, int elementwidth>
static Value *INT_AS_FPVECTOR(BasicBlock *b, Value *input) {

    NASSERT(width % elementwidth == 0);

    unsigned count = width/elementwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getFPVectorTypes(b, elementwidth, count);

    // convert our base value to a vector
    Value *vecValue = CastInst::Create(
            Instruction::BitCast,
            input,
            vt,
            "",
            b);

    return vecValue;
}


template <int width>
static Value *VECTOR_AS_INT(BasicBlock *b, Value *vector) {

    // convert our base value to a vector
    Value *intValue = CastInst::Create(
            Instruction::BitCast,
            vector,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intValue;
}

static Type *getFpTypeForWidth(const BasicBlock *block, int fpwidth) {
    Type *fpType;

    switch(fpwidth)
    {
        case 32:
            fpType = Type::getFloatTy(block->getContext());
            break;
        case 64:
            fpType = Type::getDoubleTy(block->getContext());
            break;
        default:
            TASSERT(false, "Invalid width for getFpTypeForWidth");
            fpType = nullptr;
    }

    return fpType;
}

template <int width>
static InstTransResult MOVAndZextRV(BasicBlock *& block, const MCOperand &dst, Value *src)
{

    NASSERT(dst.isReg());

    Value *zext = src;

    if(width < 128) {
        zext = new llvm::ZExtInst(src, 
                llvm::Type::getIntNTy(block->getContext(), 128),
                "",
                block);
    } else if (width > 128) {
        TASSERT(false, "Invalid width");
    }

    R_WRITE<128>(block, dst.getReg(), zext);
    return ContinueBlock;
}


template <int width>
static InstTransResult MOVAndZextRR(BasicBlock *& block, const MCOperand &dst, const MCOperand &src) {
    NASSERT(src.isReg());

    Value *src_val = R_READ<width>(block, src.getReg());

    return MOVAndZextRV<width>(block, dst, src_val);
}

template <int width>
static InstTransResult MOVAndZextRM(InstPtr ip, BasicBlock *& block, const MCOperand &dst, Value *mem_val)
{
    Value *src_val = M_READ<width>(ip, block, mem_val);

    return MOVAndZextRV<width>(block, dst, src_val);
}

template <int width>
static InstTransResult doMOVSrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    // MOV from memory to XMM register will set the unused poriton
    // of the XMM register to 0s.
    // Just set the whole thing to zero, and let the subsequent
    // write take care of the rest
    R_WRITE<128>(block, OP(0).getReg(), CONST_V<128>(block, 0));

    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<width>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        ret = doRMMov<width>(ip, block, 
                addrInt,
                OP(0) );
        return ContinueBlock;
    }
    else if( ip->has_mem_reference ) {
        ret = doRMMov<width>(ip, block, 
                MEM_AS_DATA_REF( block, natM, inst, ip, 1 ),
                OP(0) );
    } else {
        ret = doRMMov<width>(ip, block, ADDR_NOREF(1), OP(0));
    }
    return ret ;

}

template <int width>
static InstTransResult doMOVSmr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<width>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        return doMRMov<width>(ip, block, addrInt, OP(5) );
    }
    else if( ip->has_mem_reference ) {
        ret = doMRMov<width>(ip, block, MEM_AS_DATA_REF( block, natM, inst, ip, 0), OP(5) );
    } else { 
        ret = doMRMov<width>(ip, block, ADDR_NOREF(0), OP(5)) ; 
    }
    return ret ; 
}

template <int width, int op1, int op2>
static InstTransResult doMOVSrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    return doRRMov<width>(ip, block, OP(op1), OP(op2));
}

template <int fpwidth>
static Value* INT_AS_FP(BasicBlock *& block, Value *in)
{
    Type *fpType = getFpTypeForWidth(block, fpwidth);


    Value *fp_value = CastInst::Create(
            Instruction::BitCast,
            in,
            fpType,
            "",
            block);
    return fp_value;
}

template <int fpwidth>
static Value * FP_AS_INT(BasicBlock *& block, Value *in)
{
    Type *intType = Type::getIntNTy(block->getContext(), fpwidth);

    Value *to_int = CastInst::Create(
            Instruction::BitCast,
            in,
            intType,
            "",
            block);
    return to_int;
}

template <int fpwidth>
static Value* INT_TO_FP_TO_INT(BasicBlock *& block, Value *in) {

    Type *fpType = getFpTypeForWidth(block, fpwidth);
    Type *intType = Type::getIntNTy(block->getContext(), fpwidth);


    //TODO: Check rounding modes!
    Value *fp_value = CastInst::Create(
            Instruction::SIToFP,
            in,
            fpType,
            "",
            block);

    Value *to_int =  CastInst::Create(
            Instruction::BitCast,
            fp_value,
            intType,
            "",
            block);

    return to_int;

}

template <int width>
static InstTransResult doCVTSI2SrV(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst,
        Value *src,
        const MCOperand &dst) 
{

    Value *final_v = INT_TO_FP_TO_INT<width>(block, src);
    // write them to destination
    R_WRITE<width>(block, dst.getReg(), final_v);

    return ContinueBlock;
}

// Converts a signed doubleword integer (or signed quadword integer if operand size is 64 bits) 
// in the second source operand to a double-precision floating-point value in the destination operand. 
// The result is stored in the low quad- word of the destination operand, and the high quadword left unchanged. 

template <int width>
static InstTransResult translate_CVTSI2SDrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(src.isReg()); 
    NASSERT(dst.isReg()); 

    // read reg from source
    Value *rval = R_READ<width>(block, src.getReg());

    return doCVTSI2SrV<64>(natM, block, ip, inst, rval, dst);
}

template <int width>
static InstTransResult translate_CVTSI2SDrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    NASSERT(dst.isReg()); 

    Value *src = ADDR_NOREF(1);

    // read 32 bits from memory
    Value *mval = M_READ<width>(ip, block, src);

    return doCVTSI2SrV<64>(natM, block, ip, inst, mval, dst);
}

//Converts a double-precision floating-point value in the source operand (second operand) 
//to a single-precision floating-point value in the destination operand (first operand).
template <int width>
static InstTransResult doCVTSD2SSrV(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst,
        Value *src,
        const MCOperand &dst) 
{

    // convert the 64-bits we are reading into an FPU double
    //TODO: Check rounding modes!
    Value *to_double =  CastInst::Create(
            Instruction::BitCast,
            src,
            Type::getDoubleTy(block->getContext()),
            "",
            block);
    
    // Truncate double to a single
    Value *fp_single = new FPTruncInst(to_double,
            Type::getFloatTy(block->getContext()), 
            "", 
            block);

    // treat the bits as a 32-bit int
    Value *to_int =  CastInst::Create(
            Instruction::BitCast,
            fp_single,
            Type::getIntNTy(block->getContext(), 32),
            "",
            block);

    // write them to destination
    R_WRITE<width>(block, dst.getReg(), to_int);

    return ContinueBlock;
}

// read 64-bits from memory, convert to single precision fpu value, 
// write the 32-bit value into register dst
static InstTransResult translate_CVTSD2SSrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    NASSERT(dst.isReg()); 

    Value *mem = ADDR_NOREF(1);

    Value *double_val = M_READ<64>(ip, block, mem);

    return doCVTSD2SSrV<32>(natM, block, ip, inst, double_val, dst);
}

// read 64-bits from register src, convert to single precision fpu value, 
// write the 32-bit value into register dst
static InstTransResult translate_CVTSD2SSrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);
    NASSERT(dst.isReg()); 
    NASSERT(src.isReg()); 

    // read 64 bits from source
    Value *rval = R_READ<64>(block, src.getReg());

    return doCVTSD2SSrV<32>(natM, block, ip, inst, rval, dst);
}

template <int width>
static InstTransResult doCVTSS2SDrV(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst,
        Value *src,
        const MCOperand &dst) 
{
   
	// convert the 32 bits we read into an fpu single
	Value *to_single = CastInst::Create(
		Instruction::BitCast,
		src,
		Type::getFloatTy(block->getContext()),
		"",
		block);

	// extend to a double
	Value *fp_double = new FPExtInst(to_single,
		Type::getDoubleTy(block->getContext()),
		"",
		block);

	// treat the bits as a 64-bit int
	Value *to_int = CastInst::Create(
		Instruction::BitCast,
		fp_double,
		Type::getIntNTy(block->getContext(), 64),
		"",
		block);
	
	// write them to destination
    R_WRITE<width>(block, dst.getReg(), to_int);

    return ContinueBlock;
}


// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP Value
// read 32-bits from memory, convert to double precision fpu value,
// write the 64-bit value into register dst
static InstTransResult translate_CVTSS2SDrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    NASSERT(dst.isReg()); 

	Value *mem = ADDR_NOREF(1);

	// read 32 bits from mem
	Value *single_val = M_READ<32>(ip, block, mem);
	
    return doCVTSS2SDrV<64>(natM, block, ip, inst, single_val, dst);
}

// Convert Scalar Single-Precision FP Value to Scalar Double-Precision FP Value
// read 32-bits from register src, convert to double precision fpu value,
// write the 64-bit value into register dst
static InstTransResult translate_CVTSS2SDrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);
    NASSERT(dst.isReg()); 
    NASSERT(src.isReg()); 

    // read 32 bits from source
    Value *rval = R_READ<32>(block, src.getReg());

    return doCVTSS2SDrV<64>(natM, block, ip, inst, rval, dst);
}

template <int width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_VV(unsigned reg, BasicBlock *& block, Value *o1, Value *o2)
{
    Value *xoredVal = BinaryOperator::Create(bin_op, o1, o2, "", block);
    R_WRITE<width>(block, reg, xoredVal);

    return ContinueBlock;
}

template <int width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_INT_VV<width, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

template <int width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_INT_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = M_READ<width>(ip, block, addr);

    return do_SSE_INT_VV<width, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

// convert signed integer (register) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SSrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(dst.isReg()); 
    NASSERT(src.isReg()); 

    Value *src_val = R_READ<32>(block, src.getReg());
    
    return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);
}

// convert signed integer (memory) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SSrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    const MCOperand &dst = OP(0);
    Value *mem_addr = ADDR_NOREF(1);

    NASSERT(dst.isReg()); 

    Value *src_val = M_READ<32>(ip, block, mem_addr);

    return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);

}

// convert signed integer (register) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SS64rr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *src_val = R_READ<64>(block, src.getReg());

    return doCVTSI2SrV<64>(natM, block, ip, inst, src_val, dst);
}

// convert signed integer (memory) to single precision float (xmm register)
static InstTransResult translate_CVTSI2SS64rm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    const MCOperand &dst = OP(0);
    Value *mem_addr = ADDR_NOREF(1);

    NASSERT(dst.isReg());

    Value *src_val = M_READ<64>(ip, block, mem_addr);

    return doCVTSI2SrV<64>(natM, block, ip, inst, src_val, dst);

}


template <int width, int regwidth>
static InstTransResult doCVTTS2SIrV(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst, Value *src, const MCOperand &dst)
{
    Value *final_v = NULL;

    Value *to_int = CastInst::Create(
            Instruction::FPToSI,
            INT_AS_FP<width>(block, src),
            Type::getIntNTy(block->getContext(), regwidth),
            "",
            block);

    R_WRITE<regwidth>(block, dst.getReg(), to_int);

    return ContinueBlock;

}

// convert w/ truncation scalar single-precision fp value to dword integer
template <int fpwidth, int regwidth>
static InstTransResult doCVTT_to_SI_rm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    Value *mem_addr = ADDR_NOREF(1);

    NASSERT(dst.isReg());
    
    Value *src_val = M_READ<fpwidth>(ip, block, mem_addr);
    
    return doCVTTS2SIrV<fpwidth, regwidth>(natM, block, ip, inst, src_val, dst);

}

// convert w/ truncation scalar single-precision fp value (xmm reg) to dword integer
template <int fpwidth, int regwidth>
static InstTransResult doCVTT_to_SI_rr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    
    Value *src_val = R_READ<fpwidth>(block, src.getReg());
    
    return doCVTTS2SIrV<fpwidth,regwidth>(natM, block, ip, inst, src_val, dst);

}


template <int fpwidth, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VV(unsigned reg, BasicBlock *& block, Value *o1, Value *o2)
{
    Value *sumVal = BinaryOperator::Create(
        bin_op,
        INT_AS_FP<fpwidth>(block, o1),
        INT_AS_FP<fpwidth>(block, o2),
        "",
        block);
    R_WRITE<fpwidth>(block, reg, FP_AS_INT<fpwidth>(block, sumVal));

    return ContinueBlock;
}

template <int fpwidth, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<fpwidth>(block, o1.getReg());
    Value *opVal2 = R_READ<fpwidth>(block, o2.getReg());

    return do_SSE_VV<fpwidth, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

template <int fpwidth, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<fpwidth>(block, o1.getReg());
    Value *opVal2 = M_READ<fpwidth>(ip, block, addr);

    return do_SSE_VV<fpwidth, bin_op>(o1.getReg(), block, opVal1, opVal2);
}

static InstTransResult doUCOMISvv(BasicBlock *& block, Value *op1, Value *op2)
{

    // TODO: Make sure these treat negative zero and positive zero
    // as the same value.
    Value *is_lt = new FCmpInst(*block, FCmpInst::FCMP_ULT, op1, op2);
    Value *is_eq = new FCmpInst(*block, FCmpInst::FCMP_UEQ, op1, op2);

    // if BOTH the equql AND less than is true
    // it means that one of the ops is a QNaN
    Value *is_qnan = BinaryOperator::CreateAnd(is_lt, is_eq, "", block);

    F_WRITE(block, ZF, is_eq);            // ZF is 1 if either is QNaN or op1 == op2
    F_WRITE(block, PF, is_qnan);          // PF is 1 if either op is a QNaN
    F_WRITE(block, CF, is_lt);            // CF is 1 if either is QNaN or op1 < op2

    F_WRITE(block, OF, CONST_V<1>(block, 0));
    F_WRITE(block, SF, CONST_V<1>(block, 0));
    F_WRITE(block, AF, CONST_V<1>(block, 0));


    return ContinueBlock;
}

template <int width>
static InstTransResult doUCOMISrr(BasicBlock *&b, const MCOperand &op1, const MCOperand &op2)
{
    NASSERT(op1.isReg());
    NASSERT(op2.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = R_READ<width>(b, op2.getReg());

    Value *fp1_val = INT_AS_FP<width>(b, op1_val);
    Value *fp2_val = INT_AS_FP<width>(b, op2_val);

    return doUCOMISvv(b, fp1_val, fp2_val);

}

template <int width>
static InstTransResult doUCOMISrm(InstPtr ip, BasicBlock *&b, const MCOperand &op1, Value *memAddr)
{
    NASSERT(op1.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = M_READ<width>(ip, b, memAddr);

    Value *fp1_val = INT_AS_FP<width>(b, op1_val);
    Value *fp2_val = INT_AS_FP<width>(b, op2_val);

    return doUCOMISvv(b, fp1_val, fp2_val);
}

template <int elementwidth, Instruction::BinaryOps bin_op>
static InstTransResult doNewShift(BasicBlock *&b, 
        const MCOperand &dst, 
        Value *shift_count,
        Value *fallback = nullptr)
{
    NASSERT(dst.isReg());
    NASSERT(128 % elementwidth == 0);

    Value *max_count = CONST_V<64>(b, elementwidth-1);

    IntegerType *int_t = dyn_cast<IntegerType>(shift_count->getType());
    if (int_t->getBitWidth() > 64) {
        shift_count = new TruncInst( 
                shift_count, 
                Type::getIntNTy(b->getContext(), 64), 
                "",
                b);
    }
    // check if our shift count is over the 
    // allowable limit
    Value *countOverLimit = new ICmpInst(  *b, 
                                    CmpInst::ICMP_UGT, 
                                    shift_count, 
                                    max_count);

    // max the shift count at elementwidth
    // real_count = over limit ? max count : original count
    Value *real_count = SelectInst::Create(countOverLimit,
            max_count,
            shift_count,
            "",
            b);

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elementwidth, 128/elementwidth);

    // convert our base value to a vector
    Value *to_shift = R_READ<128>(b, dst.getReg());
    Value *vecValue = INT_AS_VECTOR<128, elementwidth>(b, to_shift); 

    // truncate shift count to element size since we
    // need to shove it in a vector
    int_t = dyn_cast<IntegerType>(real_count->getType());
    IntegerType *elem_int_t = dyn_cast<IntegerType>(elem_ty);
    Value *trunc_shift = nullptr;

    // size of shift count has to be the size of the vector elements
    if(elem_int_t->getBitWidth() < int_t->getBitWidth()) {
        trunc_shift = new TruncInst( 
                real_count, 
                elem_ty, 
                "",
                b);
    } else if (elem_int_t->getBitWidth() == int_t->getBitWidth()) {
        trunc_shift = real_count;
    } else {
        trunc_shift = new ZExtInst( 
                real_count, 
                elem_ty, 
                "",
                b);
    }

    Value *vecShiftPtr = new AllocaInst(vt, nullptr, "", b);
    Value *shiftVector = noAliasMCSemaScope(new LoadInst(vecShiftPtr, "", b));

    int elem_count = 128/elementwidth;

    // build a shift vector of elem_count
    // entries of trunc_shift
    for(int i = 0; i < elem_count; i++) {
        shiftVector = InsertElementInst::Create(
                shiftVector,
                trunc_shift, 
                CONST_V<32>(b, i), 
                "", 
                b );
    }

    // shift each element of the vector
    Value *shifted = BinaryOperator::Create(bin_op, vecValue, shiftVector, "", b);

    // convert value back to a 128bit int
    Value *back_to_int = CastInst::Create(
            Instruction::BitCast,
            shifted,
            Type::getIntNTy(b->getContext(), 128),
            "",
            b);

    // write back to register
    Value *final_to_write = back_to_int;

    // if this is an instruction that needs
    // a special case for shifts of 
    // count >= width, then check for the fallback
    // option
    if( fallback != nullptr ) {
        // yes,. this means all th work above was not
        // necessary. Ideally the optimizer will only
        // keep the fallback case. And this way
        // we don't need to generate multiple BBs
        final_to_write = SelectInst::Create(
                countOverLimit,
                fallback,
                back_to_int,
                "",
                b);
    }
            
    R_WRITE<128>(b, dst.getReg(), final_to_write);

    return ContinueBlock;
}

template <int width>
static InstTransResult doPSRArr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *shift_count = R_READ<128>(b, src.getReg());

    return doNewShift<width, Instruction::AShr>(b, dst, shift_count, nullptr);
}

template <int width>
static InstTransResult doPSRArm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    Value *shift_count = M_READ<128>(ip, b, memAddr);

    return doNewShift<width, Instruction::AShr>(b, dst, shift_count, nullptr);
}

template <int width>
static InstTransResult doPSRAri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isImm());

    Value *shift_count = CONST_V<128>(b, src.getImm());

    return doNewShift<width, Instruction::AShr>(b, dst, shift_count, nullptr);
}

template <int width>
static InstTransResult doPSLLrr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *shift_count = R_READ<128>(b, src.getReg());

    return doNewShift<width, Instruction::Shl>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width>
static InstTransResult doPSLLrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    Value *shift_count = M_READ<128>(ip, b, memAddr);

    return doNewShift<width, Instruction::Shl>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width>
static InstTransResult doPSRLrr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *shift_count = R_READ<128>(b, src.getReg());

    return doNewShift<width, Instruction::LShr>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width>
static InstTransResult doPSRLrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    Value *shift_count = M_READ<128>(ip, b, memAddr);

    return doNewShift<width, Instruction::LShr>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width>
static InstTransResult doPSRLri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isImm());

    Value *shift_count = CONST_V<128>(b, src.getImm());

    return doNewShift<width, Instruction::LShr>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width>
static InstTransResult doPSLLri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isImm());

    Value *shift_count = CONST_V<128>(b, src.getImm());

    return doNewShift<width, Instruction::Shl>(b, dst, shift_count, CONST_V<128>(b, 0));
}

template <int width, int elemwidth>
static Value* doDoubleShuffle(BasicBlock *&b, Value *input1, Value *input2, unsigned order)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, input1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, input2);

    Value *vecShuffle;
    if(32 == elemwidth) {
      // Based on order, take two doublewords from first vector of 4 double words, and 
      // two next two double words from second vector of 4 double words.
      Constant *shuffle_vec[4] = {
          CONST_V<32>(b, (order >> 0) & 3),
          CONST_V<32>(b, (order >> 2) & 3),
          CONST_V<32>(b, elem_count + ((order >> 4) & 3)),
          CONST_V<32>(b, elem_count + ((order >> 6) & 3)),
      };

      vecShuffle = ConstantVector::get(shuffle_vec);
    } else if(64 == elemwidth) {
      // Based on order, take one quadword from first vector of 2 quadwords, 
      // and next quadword from second vector of 2 quadwords
      Constant *shuffle_vec[2] = {
          CONST_V<32>(b, (order >> 0) & 1),
          CONST_V<32>(b, elem_count + ((order >> 1) & 1)),
      };

      vecShuffle = ConstantVector::get(shuffle_vec);
    }
    // do the shuffle
    Value *shuffled = new ShuffleVectorInst(
           vecInput1,
           vecInput2,
           vecShuffle,
           "",
           b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            shuffled,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intOutput;
}

template <int width, int elemwidth>
static Value* doShuffle(BasicBlock *&b, Value *input, unsigned order)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput = INT_AS_VECTOR<width,elemwidth>(b, input);

    Constant *shuffle_vec[4] = {
        CONST_V<32>(b, (order >> 0) & 3),
        CONST_V<32>(b, (order >> 2) & 3),
        CONST_V<32>(b, (order >> 4) & 3),
        CONST_V<32>(b, (order >> 6) & 3),
    };


    Value *vecShuffle = ConstantVector::get(shuffle_vec);


    // we are only shuffling one vector, so the
    // other one is undefined
    Value *vecUndef = UndefValue::get(vt);

    // do the shuffle
    Value *shuffled = new ShuffleVectorInst(
           vecInput,
           vecUndef,
           vecShuffle,
           "",
           b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            shuffled,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intOutput;
}

template <int width, int elemwidth>
static Value* doBlendVV(BasicBlock *&b, Value *input1, Value *input2, Value *order)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, input1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, input2);

    Value *vecOrder = INT_AS_VECTOR<width,elemwidth>(b, order);

    Value *resultAlloc = new AllocaInst(vt, nullptr, "", b);
    Value *vecResult = noAliasMCSemaScope(new LoadInst(resultAlloc, "", b));

    for(int i = 0; i < elem_count; i++) {
        // get input value
        Value *toTest = ExtractElementInst::Create(vecOrder, CONST_V<32>(b, i), "", b);

        // check if high bit is set
        Value *highBitSet = BinaryOperator::CreateAnd(
                toTest, 
                CONST_V<elemwidth>(b, 1 << (elemwidth-1)), 
                "", b);

        int mask = 0xF;
        switch(width) 
        {
            case 128:
                mask = 0xF;
                break;
            case 64:
                mask = 0x7;
                break;
            default:
                TASSERT(false, "UNSUPPORTED BIT WIDTH FOR BLEND");
        }


        Value *origPiece = ExtractElementInst::Create(vecInput1, CONST_V<32>(b, i), "", b);
        Value *newPiece = ExtractElementInst::Create(vecInput2, CONST_V<32>(b, i), "", b);

        // check if high bit was not set
        Value *isZero = new ICmpInst(*b, 
                                    CmpInst::ICMP_EQ, 
                                    highBitSet, 
                                    CONST_V<elemwidth>(b, 0));

        // pick either other byte position, or zero
        Value *whichValue = SelectInst::Create(
                isZero,  // if highBit is zero (aka not set), we keep old piece
                origPiece, // use dst version
                newPiece, // use src version (high bit is 1)
                "", b);

        vecResult = InsertElementInst::Create(
                vecResult,
                whichValue, 
                CONST_V<32>(b, i), 
                "", 
                b );
    }

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            vecResult,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intOutput;
}

template <int width, int elemwidth>
static Value* doShuffleRR(BasicBlock *&b, Value *input, Value *order)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput = INT_AS_VECTOR<width,elemwidth>(b, input);
    Value *vecOrder = INT_AS_VECTOR<width,elemwidth>(b, order);

    Value *resultAlloc = new AllocaInst(vt, nullptr, "", b);
    Value *vecResult = noAliasMCSemaScope(new LoadInst(resultAlloc, "", b));

    for(int i = 0; i < elem_count; i++) {
        // get input value
        Value *toTest = ExtractElementInst::Create(vecOrder, CONST_V<32>(b, i), "", b);

        // check if high bit is set
        Value *highBitSet = BinaryOperator::CreateAnd(
                toTest, 
                CONST_V<elemwidth>(b, 1 << (elemwidth-1)), 
                "", b);

        int mask = 0xF;
        switch(width) 
        {
            case 128:
                mask = 0xF;
                break;
            case 64:
                mask = 0x7;
                break;
            default:
                TASSERT(false, "UNSUPPORTED BIT WIDTH FOR PSHUFB");
        }

        // extract the low bits
        Value *lowBits = BinaryOperator::CreateAnd(
                toTest, 
                CONST_V<elemwidth>(b, mask),
                "", b);

        Value *origPiece = ExtractElementInst::Create(vecInput, lowBits, "", b);

        // check if high bit was not set
        Value *isZero = new ICmpInst(*b, 
                                    CmpInst::ICMP_EQ, 
                                    highBitSet, 
                                    CONST_V<elemwidth>(b, 0));

        // pick either other byte position, or zero
        Value *whichValue = SelectInst::Create(
                isZero,  // if highBit is zero (aka not set), we take a piece of the vector
                origPiece, // vector piece
                CONST_V<elemwidth>(b, 0), // if it is set, we take zero
                "", b);

        vecResult = InsertElementInst::Create(
                vecResult,
                whichValue, 
                CONST_V<32>(b, i), 
                "", 
                b );
    }

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            vecResult,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intOutput;
}

template <int width>
static InstTransResult doBLENDVBrr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *input1 = R_READ<width>(b, dst.getReg());
    Value *input2 = R_READ<width>(b, src.getReg());
    Value *order =  R_READ<width>(b, X86::XMM0);
    
    Value *blended = doBlendVV<width,8>(b, input1, input2, order);

    R_WRITE<width>(b, dst.getReg(), blended);
    return ContinueBlock;
}

template <int width>
static InstTransResult doBLENDVBrm(
        InstPtr ip, 
        BasicBlock *&b, 
        const MCOperand &dst, 
        Value *memAddr)
{
    NASSERT(dst.isReg());
    NASSERT(memAddr != nullptr);

    Value *input1 = R_READ<width>(b, dst.getReg());
    Value *input2 = M_READ<width>(ip, b, memAddr);
    Value *order =  R_READ<width>(b, X86::XMM0);

    Value *blended = doBlendVV<width,8>(b, input1, input2, order);
    R_WRITE<width>(b, dst.getReg(), blended);
    return ContinueBlock;
}

template <int width>
static InstTransResult doPSHUFBrr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *input = R_READ<width>(b, dst.getReg());
    Value *order = R_READ<width>(b, src.getReg());
    
    Value *shuffled = doShuffleRR<width,8>(b, input, order);

    R_WRITE<width>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

template <int width>
static InstTransResult doPSHUFBrm(
        InstPtr ip, 
        BasicBlock *&b, 
        const MCOperand &dst, 
        Value *memAddr)
{
    NASSERT(dst.isReg());
    NASSERT(memAddr != nullptr);

    Value *order = M_READ<width>(ip, b, memAddr);
    Value *input = R_READ<width>(b, dst.getReg());

    Value *shuffled = doShuffleRR<width,8>(b, input, order);
    R_WRITE<width>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static InstTransResult doPSHUFDri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *input = R_READ<128>(b, src.getReg());
    
    Value *shuffled = doShuffle<128,32>(b, input, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static InstTransResult doPSHUFDmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *mem_addr, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(order.isImm());


    Value *input = M_READ<128>(ip, b, mem_addr);
    
    Value *shuffled = doShuffle<128,32>(b, input, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

template <int width, int elementwidth>
static Value* doInsertion(BasicBlock *&b, Value *input, Value *what, unsigned position)
{
    Value *vec = INT_AS_VECTOR<width, elementwidth>(b, input);
    
    Value *newvec = InsertElementInst::Create(vec, what, CONST_V<32>(b, position), "", b);

    Value *newint = VECTOR_AS_INT<width>(b, newvec);
    
    return newint;
}

static InstTransResult doPINSRWrri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *vec = R_READ<128>(b, dst.getReg());
    Value *elem = R_READ<16>(b, src.getReg());
    
    Value *new_vec = doInsertion<128,16>(b, vec, elem, order.getImm());

    R_WRITE<128>(b, dst.getReg(), new_vec);
    return ContinueBlock;
}

static InstTransResult doPINSRWrmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr, const MCOperand &order)
{

    NASSERT(dst.isReg());
    NASSERT(order.isImm());

    Value *vec = R_READ<128>(b, dst.getReg());
    Value *elem = M_READ<16>(ip, b, memAddr);
    
    Value *new_vec = doInsertion<128,16>(b, vec, elem, order.getImm());

    R_WRITE<128>(b, dst.getReg(), new_vec);
    return ContinueBlock;
}

template <int width, int elementwidth>
static Value* doExtraction(BasicBlock *&b, Value *input, unsigned position)
{
    Value *vec = INT_AS_VECTOR<width, elementwidth>(b, input);
    
    Value *element = ExtractElementInst::Create(vec, CONST_V<32>(b, position), "", b);
    
    return element;
}

static InstTransResult doPEXTRWri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *vec = R_READ<128>(b, src.getReg());
    
    Value *item = doExtraction<128,16>(b, vec, order.getImm());

    // upper bits are set to zero
    Value *extItem  = new ZExtInst(
            item,
            Type::getInt32Ty(b->getContext()),
            "",
            b);

    R_WRITE<32>(b, dst.getReg(), extItem);
    return ContinueBlock;
}

static InstTransResult doPEXTRWmr(InstPtr ip, BasicBlock *&b, Value *memAddr, const MCOperand &src, const MCOperand &order)
{
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *vec = R_READ<128>(b, src.getReg());
    
    Value *item = doExtraction<128,16>(b, vec, order.getImm());

    M_WRITE<16>(ip, b, memAddr, item);
    return ContinueBlock;
}

enum UnpackType {UNPACK_LOW, UNPACK_HIGH};
template <int width, int elemwidth, UnpackType upt>
static Value* doUnpack(BasicBlock *&b, Value *v1, Value *v2)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, v1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, v2);

    std::vector<Constant*> shuffle_vec;

    int elem_start = 0;
    if(upt == UNPACK_HIGH) {
        elem_start = elem_count/2;
    }

    for(int i = 0; i < elem_count/2; i++) {
            shuffle_vec.push_back(CONST_V<32>(b, elem_start + i + elem_count));
            shuffle_vec.push_back(CONST_V<32>(b, elem_start + i));
    }
    Value *vecShuffle = ConstantVector::get(shuffle_vec);

    // do the shuffle
    Value *shuffled = new ShuffleVectorInst(
           vecInput1,
           vecInput2,
           vecShuffle,
           "",
           b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            shuffled,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    return intOutput;
}

template <int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKVV(
        BasicBlock *&b, 
        const MCOperand &dst, 
        Value *v1, Value *v2)
{
    
    NASSERT(dst.isReg());

    Value *shuffled = doUnpack<width, slice_width, upt>(b, v1, v2);

    R_WRITE<width>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

template <int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKrr(
        BasicBlock *&b, 
        const MCOperand &dst, 
        const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *srcVal = R_READ<width>(b, src.getReg());
    Value *dstVal = R_READ<width>(b, dst.getReg());

    return doPUNPCKVV<width, slice_width, upt>(b, dst, srcVal, dstVal);
}

template <int width, int slice_width, UnpackType upt>
static InstTransResult doPUNPCKrm(
        InstPtr ip, 
        BasicBlock *&b, 
        const MCOperand &dst, 
        Value *memAddr)
{
    NASSERT(dst.isReg());
    NASSERT(memAddr != nullptr);

    Value *srcVal = M_READ<width>(ip, b, memAddr);
    Value *dstVal = R_READ<width>(b, dst.getReg());

    return doPUNPCKVV<width, slice_width, upt>(b, dst, srcVal, dstVal);
}

template <int width, int elemwidth, CmpInst::Predicate cmp_op>
static llvm::Value* do_SATURATED_SUB(BasicBlock *&b, Value *v1, Value *v2)
{
    NASSERT(width % elemwidth == 0);
    constexpr int elem_count = width/elemwidth;
    Type *elem_ty;
    VectorType *vt;
    Type *int32ty = Type::getIntNTy(b->getContext(), 32);
    VectorType *vt_int32ty = VectorType::get(int32ty, elem_count);

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);
    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, v1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, v2);

    // result = v1 - v2
    Value *op_result = BinaryOperator::Create(
        Instruction::Sub,
        vecInput1,
        vecInput2,
        "",
        b);

    // if v1 is => v2, then we keep the original value (mask with 0xFF...)
    // else, if v1 < v2, make it saturate to 0x00 (mask with 0x00...)
    // The mask can be made as a sign extend of the (v1 => v2) vector op

    Value *comparison = CmpInst::Create(
            Instruction::ICmp,
            cmp_op,
            vecInput1,
            vecInput2,
            "",
            b);
    // values we should keep get sign extended to 0b11111...
    // values we want to set to zero get sign extended to 0b000000...
    Value *saturate_mask = new SExtInst(comparison, vt, "", b);

    // mask result with the saturation mask
    Value *saturated = BinaryOperator::Create(
        Instruction::And, 
        op_result,
        saturate_mask,
        "",
        b);

    Value *intOutput = CastInst::Create(
        Instruction::BitCast,
        saturated,
        Type::getIntNTy(b->getContext(), width),
        "",
        b);
    return intOutput;
}

template <int width, int elemwidth, CmpInst::Predicate cmp_op>
static InstTransResult do_SATURATED_SUB_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    Value *result = do_SATURATED_SUB<width, elemwidth, cmp_op>(block, opVal1, opVal2);
    R_WRITE<width>(block, o1.getReg(), result);
    return ContinueBlock;
}

template <int width, int elemwidth, CmpInst::Predicate cmp_op>
static InstTransResult do_SATURATED_SUB_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = M_READ<width>(ip, block, addr);

    Value *result = do_SATURATED_SUB<width, elemwidth, cmp_op>(block, opVal1, opVal2);
    R_WRITE<width>(block, o1.getReg(), result);
    return ContinueBlock;
}

template <int width, int elemwidth, CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE(const MCOperand &dst, BasicBlock *&b, Value *v1, Value *v2)
{
    NASSERT(width % elemwidth == 0);

    int elem_count = width/elemwidth;

    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elemwidth, elem_count);

    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, v1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, v2);

    Value *op_out = CmpInst::Create(
            Instruction::ICmp,
            cmp_op,
            vecInput1,
            vecInput2,
            "",
            b);

    // SExt to width since CmpInst returns
    // a vector of i1
    Value *sext_out = new SExtInst(op_out, vt, "", b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            sext_out,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, dst.getReg(), intOutput);
    return ContinueBlock;
}

template <int width, int elem_width, CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = M_READ<width>(ip, block, addr);

    return do_SSE_COMPARE<width, elem_width, cmp_op>(o1, block, opVal1, opVal2);
}

template <int width, int elem_width, CmpInst::Predicate cmp_op>
static InstTransResult do_SSE_COMPARE_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_COMPARE<width, elem_width, cmp_op>(o1, block, opVal1, opVal2);
}

template <int width, int elemwidth, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_OP(const MCOperand &dst, BasicBlock *&b, Value *v1, Value *v2)
{
    NASSERT(width % elemwidth == 0);
    Value *vecInput1 = INT_AS_VECTOR<width,elemwidth>(b, v1);
    Value *vecInput2 = INT_AS_VECTOR<width,elemwidth>(b, v2);

    Value *op_out = BinaryOperator::Create(
        bin_op,
        vecInput1,
        vecInput2,
        "",
        b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            op_out,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, dst.getReg(), intOutput);
    return ContinueBlock;
}


template <int width, int elemwidth, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_OP(const MCOperand &dst, BasicBlock *&b, Value *v1, Value *v2)
{
    NASSERT(width % elemwidth == 0);
    Value *vecInput1 = INT_AS_FPVECTOR<width,elemwidth>(b, v1);
    Value *vecInput2 = INT_AS_FPVECTOR<width,elemwidth>(b, v2);

    Value *op_out = BinaryOperator::Create(
        bin_op,
        vecInput1,
        vecInput2,
        "",
        b);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            op_out,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, dst.getReg(), intOutput);
    return ContinueBlock;
}

template <int width, int elem_width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = M_READ<width>(ip, block, addr);

    return do_SSE_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template <int width, int elem_width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_VECTOR_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template <int width, int elem_width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = M_READ<width>(ip, block, addr);

    return do_SSE_FP_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template <int width, int elem_width, Instruction::BinaryOps bin_op>
static InstTransResult do_SSE_FP_VECTOR_RR(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_FP_VECTOR_OP<width, elem_width, bin_op>(o1, block, opVal1, opVal2);
}

template <FCmpInst::Predicate binop>
static Value* doMAXMINvv(BasicBlock *&block, Value *op1, Value *op2)
{

    // TODO: handle the zero case 
    Value *is_gt = new FCmpInst(*block, binop, op1, op2);

    // if op1 > op2, use op1, else op2
    Value *which_op = SelectInst::Create(is_gt, op1, op2, "", block);

    return which_op;
}

template <int width, int elemwidth, FCmpInst::Predicate binop>
static InstTransResult doMAXMIN_FP_VECTOR_rr(BasicBlock *&b, const MCOperand &op1, const MCOperand &op2)
{
    NASSERT(op1.isReg());
    NASSERT(op2.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = R_READ<width>(b, op2.getReg());

    NASSERT(width % elemwidth == 0);
    Value *vecInput1 = INT_AS_FPVECTOR<width,elemwidth>(b, op1_val);
    Value *vecInput2 = INT_AS_FPVECTOR<width,elemwidth>(b, op2_val);

    Value *max = doMAXMINvv<binop>(b, vecInput1, vecInput2);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            max,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, op1.getReg(), intOutput);
    return ContinueBlock;
}

template <int width, int elemwidth, FCmpInst::Predicate binop>
static InstTransResult doMAXMIN_FP_VECTOR_rm(InstPtr ip, BasicBlock *&b, const MCOperand &op1, Value *memAddr)
{
    NASSERT(op1.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = M_READ<width>(ip, b, memAddr);
    
    NASSERT(width % elemwidth == 0);
    Value *vecInput1 = INT_AS_FPVECTOR<width,elemwidth>(b, op1_val);
    Value *vecInput2 = INT_AS_FPVECTOR<width,elemwidth>(b, op2_val);

    Value *max = doMAXMINvv<binop>(b, vecInput1, vecInput2);

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            max,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, op1.getReg(), intOutput);
    return ContinueBlock;
}

template <int width, FCmpInst::Predicate binop >
static InstTransResult doMAXMINrr(BasicBlock *&b, const MCOperand &op1, const MCOperand &op2)
{
    NASSERT(op1.isReg());
    NASSERT(op2.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = R_READ<width>(b, op2.getReg());

    Value *fp1_val = INT_AS_FP<width>(b, op1_val);
    Value *fp2_val = INT_AS_FP<width>(b, op2_val);

    Value *max = doMAXMINvv<binop>(b, fp1_val, fp2_val);
    R_WRITE<width>(b, op1.getReg(), FP_AS_INT<width>(b, max));
    return ContinueBlock;
}

template <int width, FCmpInst::Predicate binop >
static InstTransResult doMAXMINrm(InstPtr ip, BasicBlock *&b, const MCOperand &op1, Value *memAddr)
{
    NASSERT(op1.isReg());

    Value *op1_val = R_READ<width>(b, op1.getReg());
    Value *op2_val = M_READ<width>(ip, b, memAddr);

    Value *fp1_val = INT_AS_FP<width>(b, op1_val);
    Value *fp2_val = INT_AS_FP<width>(b, op2_val);

    Value *max = doMAXMINvv<binop>(b, fp1_val, fp2_val);
    R_WRITE<width>(b, op1.getReg(), FP_AS_INT<width>(b, max));
    return ContinueBlock;
}

template <int width>
static InstTransResult do_PANDNrr(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *notVal1 = BinaryOperator::CreateNot(opVal1, "", block);
    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_INT_VV<width, Instruction::And>(o1.getReg(), block, notVal1, opVal2);
}

template <int width>
static InstTransResult do_PANDNrm(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    Value *opVal1 = R_READ<width>(block, o1.getReg());
    Value *notVal1 = BinaryOperator::CreateNot(opVal1, "", block);
    Value *opVal2 = M_READ<width>(ip, block, addr);

    return do_SSE_INT_VV<width, Instruction::And>(o1.getReg(), block, notVal1, opVal2);
}

enum ExtendOp {
    SEXT,
    ZEXT
};

template <int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_OP(const MCOperand &dst, BasicBlock *&b, Value *v1)
{
    NASSERT(width % srcelem == 0);
    NASSERT(width % dstelem == 0);
    TASSERT(dstelem > srcelem, "Must use SSE extend to a bigger element size");

    int src_elem_count = width/srcelem;
    int dst_elem_count = width/dstelem;

    Type *src_elem_ty;
    Type *dst_elem_ty;
    VectorType *src_vt;
    VectorType *dst_vt;

    std::tie(src_vt, src_elem_ty) = getIntVectorTypes(b, srcelem, src_elem_count);
    std::tie(dst_vt, dst_elem_ty) = getIntVectorTypes(b, dstelem, dst_elem_count);

    // read input vector
    Value *vecInput1 = INT_AS_VECTOR<width,srcelem>(b, v1);

    Value *resultAlloc = new AllocaInst(dst_vt, nullptr, "", b);
    Value *vecResult = noAliasMCSemaScope(new LoadInst(resultAlloc, "", b));


    // we take lower dst_elem_count values
    for(int i = 0; i < dst_elem_count; i++)  
    {
        // read source element
        Value *item = ExtractElementInst::Create(vecInput1, CONST_V<32>(b, i), "", b);
        Value *newitem = nullptr;
        // op it to dst element type
        switch(op) {
            case SEXT:
                newitem = new SExtInst(item, dst_elem_ty, "", b);
                break;
            case ZEXT:
                newitem = new ZExtInst(item, dst_elem_ty, "", b);
                break;
            default:
                TASSERT(false, "Invalid operation for do_SSE_EXTEND_OP");
        }

        // store dst element
        vecResult = InsertElementInst::Create(
                vecResult,
                newitem, 
                CONST_V<32>(b, i), 
                "", 
                b );
        
    }

    // convert the output back to an integer
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            vecResult,
            Type::getIntNTy(b->getContext(), width),
            "",
            b);

    R_WRITE<width>(b, dst.getReg(), intOutput);
    return ContinueBlock;
}

template <int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_RM(InstPtr ip, BasicBlock *& block,
                                const MCOperand &o1,
                                Value *addr)
{
    NASSERT(o1.isReg());

    // memory operands are weird -- its the minimum
    // bytes needed to unpack to width / dstelem
    const int count = width / dstelem * srcelem;
    TASSERT(count < width, "Must SSE extend to greater size");
    llvm::dbgs() << "Reading: " << count << " bytes\n";
    Value *opVal1 = M_READ<count>(ip, block, addr);
    
    Value *zext = new ZExtInst(
            opVal1, 
            Type::getIntNTy(block->getContext(), width), 
            "", block);

    return do_SSE_EXTEND_OP<width, srcelem, dstelem, op>(o1, block, zext);
}

template <int width, int srcelem, int dstelem, ExtendOp op>
static InstTransResult do_SSE_EXTEND_RR(InstPtr ip, BasicBlock *& block, 
                                const MCOperand &o1,
                                const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value *opVal2 = R_READ<width>(block, o2.getReg());

    return do_SSE_EXTEND_OP<width, srcelem, dstelem, op>(o1, block, opVal2);
}

template <int width>
static InstTransResult doMOVHLPSrr(InstPtr ip, BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    NASSERT(dest.isReg());
    NASSERT(src.isReg());

    Value *r_dest = R_READ<width>(b, dest.getReg());
    Value *r_src = R_READ<width>(b, src.getReg());

    // capture top half of src
    Value *dest_keep = BinaryOperator::Create(
            Instruction::LShr, 
            r_dest, 
            CONST_V<width>(b, width/2),
            "", b);
    // put it back in top part
    dest_keep = BinaryOperator::Create(
            Instruction::Shl, 
            dest_keep, 
            CONST_V<width>(b, width/2),
            "", b);

    // get top of src
    Value *src_keep = BinaryOperator::Create(
            Instruction::LShr, 
            r_src, 
            CONST_V<width>(b, width/2),
            "", b);

    // or top half of src with the old
    // top half of dst, which is now the bottom
    Value *res = BinaryOperator::Create(
            Instruction::Or,
            src_keep,
            dest_keep,
            "", b);

    R_WRITE<width>(b, dest.getReg(), res);
}

template <int width>
static InstTransResult doMOVLHPSrr(InstPtr ip, BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    NASSERT(dest.isReg());
    NASSERT(src.isReg());

    Value *r_dest = R_READ<width>(b, dest.getReg());
    Value *r_src = R_READ<width>(b, src.getReg());

    // put low into high
    Value* dest_keep = BinaryOperator::Create(
            Instruction::Shl, 
            r_src, 
            CONST_V<width>(b, width/2),
            "", b);

    TASSERT( width >= 64 , "Can't truncate from smaller width");

    Value* bottom_part = new TruncInst( 
            r_dest, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);
    Value *zext = new llvm::ZExtInst(bottom_part, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);

    // or top half of src with the old
    // top half of dst, which is now the bottom
    Value *res = BinaryOperator::Create(
            Instruction::Or,
            zext,
            dest_keep,
            "", b);

    R_WRITE<width>(b, dest.getReg(), res);
}

static Value *doPMULUDQVV(BasicBlock *b, Value *dest, Value *src)
{

    // get top of src
    Value *vecSrc = INT_AS_VECTOR<128,32>(b, src);
    Value *vecDst = INT_AS_VECTOR<128,32>(b, dest);

    Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
    Value *src2 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 2), "", b);

    Value *src1_e = new llvm::ZExtInst(src1, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);
    Value *src2_e = new llvm::ZExtInst(src2, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);

    Value *dst1 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 0), "", b);
    Value *dst2 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 2), "", b);

    Value *dst1_e = new llvm::ZExtInst(dst1, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);
    Value *dst2_e = new llvm::ZExtInst(dst2, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);

    Value *res1 = BinaryOperator::Create(
            Instruction::Mul, 
            src1_e, 
            dst1_e,
            "", b);

    Value *res2 = BinaryOperator::Create(
            Instruction::Mul, 
            src2_e, 
            dst2_e,
            "", b);

    Value *res_shift = BinaryOperator::Create(
            Instruction::Shl,
            res2,
            CONST_V<128>(b, 64),
            "", b);

    Value *res_or = BinaryOperator::Create(
            Instruction::Or,
            res_shift,
            res1,
            "", b);


    return res_or;

}

static InstTransResult doPMULUDQrr(
        BasicBlock *&b, 
        const MCOperand &dst, 
        const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *srcVal = R_READ<128>(b, src.getReg());
    Value *dstVal = R_READ<128>(b, dst.getReg());

    Value *res = doPMULUDQVV(b, dstVal, srcVal);
    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static InstTransResult doPMULUDQrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    NASSERT(dst.isReg());

    Value *dstVal = R_READ<128>(b, dst.getReg());
    Value *srcVal = M_READ<128>(ip, b, memAddr);
    Value *res = doPMULUDQVV(b, dstVal, srcVal);
    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static InstTransResult doMOVHPDmr(InstPtr ip, BasicBlock *&b, Value *memAddr, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *dstVal = R_READ<128>(b, src.getReg());

    Value *sright = BinaryOperator::Create(
            Instruction::LShr,
            dstVal,
            CONST_V<128>(b, 64),
            "", b);

    Value *trunc_upper_64 = new TruncInst( 
            sright, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);

    M_WRITE<64>(ip, b, memAddr, trunc_upper_64);
    return ContinueBlock;
}

static InstTransResult doMOVHPDrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    NASSERT(dst.isReg());

    Value *dstVal = R_READ<128>(b, dst.getReg());
    Value *srcVal = M_READ<64>(ip, b, memAddr);

    // Extend the type of src to 128 bits
    Value *srcExt = new ZExtInst(srcVal,
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);

    //Left sheft 64 LSB to hihger quadword
    Value *srcLShift = BinaryOperator::Create(
            Instruction::Shl,
            srcExt,
            CONST_V<128>(b, 64),
            "", b);

    //Clean up the upper 64 bits of dest reg 
    Value *sleft = BinaryOperator::Create(
            Instruction::Shl,
            dstVal,
            CONST_V<128>(b, 64),
            "", b);
    Value *sright = BinaryOperator::Create(
            Instruction::LShr,
            sleft,
            CONST_V<128>(b, 64),
            "", b);

    Value *ored = BinaryOperator::Create(
            Instruction::Or,
            sright,
            srcLShift,
            "", b);
    
    R_WRITE<128>(b, dst.getReg(), ored);
    return ContinueBlock;
}

static InstTransResult doMOVLPDrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    NASSERT(dst.isReg());

    Value *dstVal = R_READ<128>(b, dst.getReg());
    Value *srcVal = M_READ<64>(ip, b, memAddr);

    Value *srcExt = new ZExtInst(srcVal,
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);
    
    Value *sright = BinaryOperator::Create(
            Instruction::LShr,
            dstVal,
            CONST_V<128>(b, 64),
            "", b);
    Value *sleft = BinaryOperator::Create(
            Instruction::Shl,
            sright,
            CONST_V<128>(b, 64),
            "", b);

    Value *ored = BinaryOperator::Create(
            Instruction::Or,
            sleft,
            srcExt,
            "", b);
    
    R_WRITE<128>(b, dst.getReg(), ored);
    return ContinueBlock;
}


Value *doCVTTPS2DQvv(BasicBlock *&b, Value *in) {
    // read in as FP vector
    //
    Value *fpv = INT_AS_FPVECTOR<128, 32>(b, in);
    //
    // truncate
    //
    //

    Type *elem_ty;
    VectorType *vt;
    std::tie(vt, elem_ty) = getIntVectorTypes(b, 32, 4);

    Value *as_ints = CastInst::Create(
            Instruction::FPToSI,
            fpv,
            vt, 
            "",
            b);
    
    // cast as int
    Value *intOutput = CastInst::Create(
            Instruction::BitCast,
            as_ints,
            Type::getIntNTy(b->getContext(), 128),
            "",
            b);
    // return
    return intOutput;
}

static InstTransResult doCVTTPS2DQrm(
        InstPtr ip, 
        BasicBlock *&b, 
        const MCOperand &dst, 
        Value *memAddr)
{
    NASSERT(dst.isReg());
    NASSERT(memAddr != nullptr);

    Value *memval = M_READ<128>(ip, b, memAddr);
    Value *out = doCVTTPS2DQvv(b, memval);
    R_WRITE<128>(b, dst.getReg(), out);

    return ContinueBlock;
}

static InstTransResult doCVTTPS2DQrr(
        BasicBlock *&b, 
        const MCOperand &dst, 
        const MCOperand &src)
    
{
    NASSERT(dst.isReg());

    Value *inval = R_READ<128>(b, src.getReg());
    Value *out = doCVTTPS2DQvv(b, inval);
    R_WRITE<128>(b, dst.getReg(), out);

    return ContinueBlock;
}

static InstTransResult doSHUFPDrri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *input1 = R_READ<128>(b, src.getReg());
    Value *input2 = R_READ<128>(b, dst.getReg());
    
    Value *shuffled = doDoubleShuffle<128,64>(b, input2, input1, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static InstTransResult doSHUFPDrmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *mem_addr, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(order.isImm());
    NASSERT(mem_addr != NULL);

    Value *input1 = M_READ<128>(ip, b, mem_addr);
    Value *input2 = R_READ<128>(b, dst.getReg());
    
    Value *shuffled = doDoubleShuffle<128,64>(b, input2, input1, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static InstTransResult doSHUFPSrri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *input1 = R_READ<128>(b, src.getReg());
    Value *input2 = R_READ<128>(b, dst.getReg());
    
    Value *shuffled = doDoubleShuffle<128,32>(b, input2, input1, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static InstTransResult doSHUFPSrmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *mem_addr, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(order.isImm());
    NASSERT(mem_addr != NULL);

    Value *input1 = M_READ<128>(ip, b, mem_addr);
    Value *input2 = R_READ<128>(b, dst.getReg());
    
    Value *shuffled = doDoubleShuffle<128,32>(b, input2, input1, order.getImm());

    R_WRITE<128>(b, dst.getReg(), shuffled);
    return ContinueBlock;
}

static Value* doPSHUFHWvv(BasicBlock *&b, Value *in, Value *dstVal, const MCOperand &order)
{
    Value *shuffled = doShuffle<64,16>(b, in, order.getImm());

    Value *shufExt = new ZExtInst(shuffled,
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);

    Value *shufAdjusted = BinaryOperator::Create(
            Instruction::Shl,
            shufExt,
            CONST_V<128>(b, 64),
            "", b);

    // Clear the bits [127:64] of dstVal
    Value *sleft = BinaryOperator::Create(
            Instruction::Shl,
            dstVal,
            CONST_V<128>(b, 64),
            "", b);
    Value *sright = BinaryOperator::Create(
            Instruction::LShr,
            sleft,
            CONST_V<128>(b, 64),
            "", b);

      
    Value *ored = BinaryOperator::Create(
            Instruction::Or,
            sright,
            shufAdjusted,
            "", b);

    return ored;
}


static InstTransResult doPSHUFHWri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *input1 = R_READ<128>(b, src.getReg());

    Value *rightShiftedHigher = BinaryOperator::Create(
                  Instruction::LShr,
                  input1,
                  CONST_V<128>(b, 64),
                  "", b);

    Value *i1_lower = new TruncInst( 
            rightShiftedHigher, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);


    Value *res = doPSHUFHWvv(b, i1_lower, input1, order);
    
    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static InstTransResult doPSHUFHWmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *mem_addr, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(order.isImm());
    NASSERT(mem_addr != NULL);

    Value *input1 = M_READ<128>(ip, b, mem_addr);

    Value *rightShiftedHigher = BinaryOperator::Create(
                  Instruction::LShr,
                  input1,
                  CONST_V<128>(b, 64),
                  "", b);

    Value *i1_lower = new TruncInst( 
            rightShiftedHigher, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);


    Value *res = doPSHUFHWvv(b, i1_lower, input1, order);

    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static Value* doPSHUFLWvv(BasicBlock *&b, Value *in, Value *dstVal, const MCOperand &order)
{
    Value *shuffled = doShuffle<64,16>(b, in, order.getImm());

    Value *sright = BinaryOperator::Create(
            Instruction::LShr,
            dstVal,
            CONST_V<128>(b, 64),
            "", b);
    Value *sleft = BinaryOperator::Create(
            Instruction::Shl,
            sright,
            CONST_V<128>(b, 64),
            "", b);

    Value *shufExt = new ZExtInst(shuffled,
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "",
                        b);
    Value *ored = BinaryOperator::Create(
            Instruction::Or,
            sleft,
            shufExt,
            "", b);

    return ored;
}

static InstTransResult doPSHUFLWri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    NASSERT(order.isImm());

    Value *input1 = R_READ<128>(b, src.getReg());
    Value *i1_lower = new TruncInst( 
            input1, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);

    Value *res = doPSHUFLWvv(b, i1_lower, input1, order);
    
    
    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static InstTransResult doPSHUFLWmi(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *mem_addr, const MCOperand &order)
{
    NASSERT(dst.isReg());
    NASSERT(order.isImm());
    NASSERT(mem_addr != NULL);

    Value *input1 = M_READ<128>(ip, b, mem_addr);

    Value *i1_lower = new TruncInst( 
            input1, 
            Type::getIntNTy(b->getContext(), 64), 
            "",
            b);

    Value *res = doPSHUFLWvv(b, i1_lower, input1, order);
    
    
    R_WRITE<128>(b, dst.getReg(), res);
    return ContinueBlock;
}

static Value *doUNPCKLPSvv(BasicBlock *b, Value *dest, Value *src)
{
    Value *vecSrc = INT_AS_VECTOR<128,32>(b, src);
    Value *vecDst = INT_AS_VECTOR<128,32>(b, dest);

    Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
    Value *src2 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 1), "", b);

    Value *dst1 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 0), "", b);
    Value *dst2 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 1), "", b);

    Value *res1 = InsertElementInst::Create(vecDst, dst1, CONST_V<32>(b, 0), "", b);
    Value *res2 = InsertElementInst::Create(res1, src1, CONST_V<32>(b, 1), "", b);
    Value *res3 = InsertElementInst::Create(res2, dst2, CONST_V<32>(b, 2), "", b);
    Value *res4 = InsertElementInst::Create(res3, src2, CONST_V<32>(b, 3), "", b);

    // convert the output back to an integer
    return VECTOR_AS_INT<128>(b, res4);
}

static Value *doUNPCKLPDvv(BasicBlock *b, Value *dest, Value *src)
{
    Value *vecSrc = INT_AS_VECTOR<128,64>(b, src);
    Value *vecDst = INT_AS_VECTOR<128,64>(b, dest);

    Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
    Value *dst1 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 0), "", b);

    Value *res1 = InsertElementInst::Create(vecDst, dst1, CONST_V<32>(b, 0), "", b);
    Value *res2 = InsertElementInst::Create(res1, src1, CONST_V<32>(b, 1), "", b);

    // convert the output back to an integer
    return VECTOR_AS_INT<128>(b, res2);
}

static InstTransResult doUNPCKLPSrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doUNPCKLPSvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}

static InstTransResult doUNPCKLPSrm(InstPtr ip, BasicBlock *b, const MCOperand &dest, Value *src)
{
    R_WRITE<128>(b, dest.getReg(),
               doUNPCKLPSvv(b, R_READ<128>(b, dest.getReg()),
                               M_READ<128>(ip, b, src)));
    return ContinueBlock;
}

static InstTransResult doUNPCKLPDrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doUNPCKLPDvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}

static InstTransResult doUNPCKLPDrm(InstPtr ip, BasicBlock *b, const MCOperand &dest, Value *src)
{
    R_WRITE<128>(b, dest.getReg(),
               doUNPCKLPDvv(b, R_READ<128>(b, dest.getReg()),
                               M_READ<128>(ip, b, src)));
    return ContinueBlock;
}

static Value *doUNPCKHPDvv(BasicBlock *b, Value *dest, Value *src)
{
    Value *vecSrc = INT_AS_VECTOR<128,64>(b, src);
    Value *vecDst = INT_AS_VECTOR<128,64>(b, dest);

    Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 1), "", b);
    Value *dst1 = ExtractElementInst::Create(vecDst, CONST_V<32>(b, 1), "", b);

    Value *res1 = InsertElementInst::Create(vecDst, dst1, CONST_V<32>(b, 0), "", b);
    Value *res2 = InsertElementInst::Create(res1, src1, CONST_V<32>(b, 1), "", b);

    // convert the output back to an integer
    return VECTOR_AS_INT<128>(b, res2);
}

static InstTransResult doUNPCKHPDrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doUNPCKHPDvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}

Value *doCVTPS2PDvv(BasicBlock *&b, Value *dest, Value *src) {
  Type *DoubleTy = Type::getDoubleTy(b->getContext());

  Value *vecSrc = INT_AS_FPVECTOR<128,32>(b, src);
  Value *vecDst = INT_AS_FPVECTOR<128,64>(b, dest);

  Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
  Value *src2 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 1), "", b);

  Value *src1_ext = CastInst::Create(Instruction::FPExt, src1, DoubleTy, "", b);
  Value *src2_ext = CastInst::Create(Instruction::FPExt, src2, DoubleTy, "", b);

  Value *res1 = InsertElementInst::Create(vecDst, src1_ext, CONST_V<32>(b, 0), "", b);
  Value *res2 = InsertElementInst::Create(res1, src2_ext, CONST_V<32>(b, 1), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res2);
}

Value *doCVTPD2PSvv(BasicBlock *&b, Value *dest, Value *src) {
  Type *FloatTy = Type::getFloatTy(b->getContext());

  Value *vecSrc = INT_AS_FPVECTOR<128,64>(b, src);
  Value *vecDst = INT_AS_FPVECTOR<128,32>(b, dest);

  Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
  Value *src2 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 1), "", b);

  Value *src1_trunc = new FPTruncInst(src1, FloatTy, "", b);
  Value *src2_trunc = new FPTruncInst(src2, FloatTy, "", b);

  Value *zero = CONST_V<32>(b, 0);
      
  Value *zero_as_fp = CastInst::Create(Instruction::BitCast, zero, FloatTy, "", b);

  Value *res1 = InsertElementInst::Create(vecDst, src1_trunc, CONST_V<32>(b, 0), "", b);
  Value *res2 = InsertElementInst::Create(res1, src2_trunc, CONST_V<32>(b, 1), "", b);
  Value *res3 = InsertElementInst::Create(res2, zero_as_fp, CONST_V<32>(b, 2), "", b);
  Value *res4 = InsertElementInst::Create(res3, zero_as_fp, CONST_V<32>(b, 3), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res4);
}


static InstTransResult doCVTPS2PDrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doCVTPS2PDvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}

Value *doCVTDQ2PSvv(BasicBlock *&b, Value *dest, Value *src) {
  Type *FloatTy = Type::getFloatTy(b->getContext());

  Value *vecSrc = INT_AS_VECTOR<128,32>(b, src);
  Value *vecDst = INT_AS_FPVECTOR<128,32>(b, dest);

  Value *src1 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 0), "", b);
  Value *src2 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 1), "", b);
  Value *src3 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 2), "", b);
  Value *src4 = ExtractElementInst::Create(vecSrc, CONST_V<32>(b, 3), "", b);

  Type *fpType = getFpTypeForWidth(b, 32);
    //TODO: Check rounding modes!
  Value *fp_value1 = CastInst::Create( Instruction::SIToFP, src1, fpType, "", b);
  Value *fp_value2 = CastInst::Create( Instruction::SIToFP, src2, fpType, "", b);
  Value *fp_value3 = CastInst::Create( Instruction::SIToFP, src3, fpType, "", b);
  Value *fp_value4 = CastInst::Create( Instruction::SIToFP, src4, fpType, "", b);

  Value *res1 = InsertElementInst::Create(vecDst, fp_value1, CONST_V<32>(b, 0), "", b);
  Value *res2 = InsertElementInst::Create(res1, fp_value2, CONST_V<32>(b, 1), "", b);
  Value *res3 = InsertElementInst::Create(res2, fp_value3, CONST_V<32>(b, 2), "", b);
  Value *res4 = InsertElementInst::Create(res3, fp_value4, CONST_V<32>(b, 3), "", b);

  // convert the output back to an integer
  return VECTOR_AS_INT<128>(b, res4);
}


static InstTransResult doCVTDQ2PSrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doCVTDQ2PSvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}


static InstTransResult doCVTPS2PDrm(InstPtr ip, BasicBlock *b, const MCOperand &dest, Value *src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doCVTPS2PDvv(b, R_READ<128>(b, dest.getReg()),
                                 M_READ<128>(ip, b, src)));
    return ContinueBlock;
}

static InstTransResult doCVTPD2PSrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doCVTPD2PSvv(b, R_READ<128>(b, dest.getReg()),
                                 R_READ<128>(b, src.getReg())));
    return ContinueBlock;
}

static InstTransResult doCVTPD2PSrm(InstPtr ip, BasicBlock *b, const MCOperand &dest, Value *src)
{
    R_WRITE<128>(b, dest.getReg(),
                 doCVTPD2PSvv(b, R_READ<128>(b, dest.getReg()),
                                 M_READ<128>(ip, b, src)));
    return ContinueBlock;
}

static InstTransResult doMOVDDUPrr(BasicBlock *b, const MCOperand &dest, const MCOperand &src)
{
    Value *s = R_READ<128>(b, src.getReg());

    Value* lower = new TruncInst( 
            s, 
            Type::getIntNTy(b->getContext(), 64), 
            "", b);
    Value *lower_ext = new llvm::ZExtInst(lower, 
                        llvm::Type::getIntNTy(b->getContext(), 128),
                        "", b);

    // duplicate it in upper half
    Value *top_half = BinaryOperator::Create(
            Instruction::Shl, 
            lower_ext, 
            CONST_V<128>(b, 64),
            "", b);

    // combine the halves
    Value *combined = BinaryOperator::CreateAnd(lower_ext, top_half, "", b);

    R_WRITE<128>(b, dest.getReg(), combined);

    return ContinueBlock;
}

GENERIC_TRANSLATION(MOVHLPSrr,
        (doMOVHLPSrr<128>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION(MOVLHPSrr,
        (doMOVLHPSrr<128>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION(PMOVSXBWrr,
        (do_SSE_EXTEND_RR<128,8,16,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXBWrm,
        (do_SSE_EXTEND_RM<128,8,16,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,16,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVSXBDrr,
        (do_SSE_EXTEND_RR<128,8,32,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXBDrm,
        (do_SSE_EXTEND_RM<128,8,32,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,32,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVSXBQrr,
        (do_SSE_EXTEND_RR<128,8,64,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXBQrm,
        (do_SSE_EXTEND_RM<128,8,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVSXWDrr,
        (do_SSE_EXTEND_RR<128,16,32,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXWDrm,
        (do_SSE_EXTEND_RM<128,16,32,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,16,32,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVSXWQrr,
        (do_SSE_EXTEND_RR<128,16,64,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXWQrm,
        (do_SSE_EXTEND_RM<128,16,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,16,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVSXDQrr,
        (do_SSE_EXTEND_RR<128,32,64,SEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVSXDQrm,
        (do_SSE_EXTEND_RM<128,32,64,SEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,32,64,SEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(PMOVZXBWrr,
        (do_SSE_EXTEND_RR<128,8,16,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXBWrm,
        (do_SSE_EXTEND_RM<128,8,16,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,16,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVZXBDrr,
        (do_SSE_EXTEND_RR<128,8,32,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXBDrm,
        (do_SSE_EXTEND_RM<128,8,32,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,32,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVZXBQrr,
        (do_SSE_EXTEND_RR<128,8,64,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXBQrm,
        (do_SSE_EXTEND_RM<128,8,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,8,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVZXWDrr,
        (do_SSE_EXTEND_RR<128,16,32,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXWDrm,
        (do_SSE_EXTEND_RM<128,16,32,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,16,32,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVZXWQrr,
        (do_SSE_EXTEND_RR<128,16,64,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXWQrm,
        (do_SSE_EXTEND_RM<128,16,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,16,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(PMOVZXDQrr,
        (do_SSE_EXTEND_RR<128,32,64,ZEXT>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(PMOVZXDQrm,
        (do_SSE_EXTEND_RM<128,32,64,ZEXT>(ip, block, OP(0), ADDR_NOREF(1))),
        (do_SSE_EXTEND_RM<128,32,64,ZEXT>(ip, block, OP(0), MEM_REFERENCE(1))) )


GENERIC_TRANSLATION(PANDNrr, 
        (do_PANDNrr<128>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PANDNrm, 
        (do_PANDNrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_PANDNrm<128>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PANDrr, 
        (do_SSE_INT_RR<128,Instruction::And>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PANDrm, 
        (do_SSE_INT_RM<128,Instruction::And>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_INT_RM<128,Instruction::And>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PORrr, 
        (do_SSE_INT_RR<128,Instruction::Or>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PORrm, 
        (do_SSE_INT_RM<128,Instruction::Or>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_INT_RM<128,Instruction::Or>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MMX_PORirr,
        (do_SSE_INT_RR<64,Instruction::Or>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MMX_PORirm,
        (do_SSE_INT_RM<64,Instruction::Or>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_INT_RM<64,Instruction::Or>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(XORPSrr, 
        (do_SSE_INT_RR<128,Instruction::Xor>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(XORPSrm, 
        (do_SSE_INT_RM<128,Instruction::Xor>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_INT_RM<128,Instruction::Xor>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(ADDSDrr, 
        (do_SSE_RR<64,Instruction::FAdd>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(ADDSDrm, 
        (do_SSE_RM<64,Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<64,Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(ADDSSrr, 
        (do_SSE_RR<32,Instruction::FAdd>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(ADDSSrm, 
        (do_SSE_RM<32,Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<32,Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(SUBSDrr, 
        (do_SSE_RR<64,Instruction::FSub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(SUBSDrm, 
        (do_SSE_RM<64,Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<64,Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(SUBSSrr, 
        (do_SSE_RR<32,Instruction::FSub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(SUBSSrm, 
        (do_SSE_RM<32,Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<32,Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(DIVSDrr,
        (do_SSE_RR<64,Instruction::FDiv>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(DIVSDrm, 
        (do_SSE_RM<64,Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<64,Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(DIVSSrr, 
        (do_SSE_RR<32,Instruction::FDiv>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(DIVSSrm, 
        (do_SSE_RM<32,Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<32,Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MULSDrr, 
        (do_SSE_RR<64,Instruction::FMul>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MULSDrm, 
        (do_SSE_RM<64,Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<64,Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MULSSrr, 
        (do_SSE_RR<32,Instruction::FMul>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MULSSrm, 
        (do_SSE_RM<32,Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_RM<32,Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))) )


GENERIC_TRANSLATION(MOVDI2PDIrr, 
        (MOVAndZextRR<32>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(MOVDI2PDIrm, 
        (MOVAndZextRM<32>(ip, block, OP(0), ADDR_NOREF(1))),
        (MOVAndZextRM<32>(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(MOVSS2DIrr, 
        (doRRMov<32>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION(UCOMISSrr, 
        (doUCOMISrr<32>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(UCOMISSrm, 
        (doUCOMISrm<32>(ip, block, OP(0), ADDR_NOREF(1))),
        (doUCOMISrm<32>(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(UCOMISDrr, 
        (doUCOMISrr<64>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(UCOMISDrm, 
        (doUCOMISrm<64>(ip, block, OP(0), ADDR_NOREF(1))),
        (doUCOMISrm<64>(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(PSRAWrr, 
        (doPSRArr<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRAWri, 
        (doPSRAri<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSRAWrm, 
        (doPSRArm<16>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSRArm<16>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSRADrr, 
        (doPSRArr<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRADri, 
        (doPSRAri<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSRADrm, 
        (doPSRArm<32>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSRArm<32>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSLLDrr, 
        (doPSLLrr<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLDri, 
        (doPSLLri<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSLLDrm, 
        (doPSLLrm<32>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSLLrm<32>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSRLWrr, 
        (doPSRLrr<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRLWri, 
        (doPSRLri<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSRLWrm, 
        (doPSRLrm<16>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSRLrm<16>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSRLDrr, 
        (doPSRLrr<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRLDri, 
        (doPSRLri<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSRLDrm, 
        (doPSRLrm<32>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSRLrm<32>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSRLQrr, 
        (doPSRLrr<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRLQri, 
        (doPSRLri<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSRLQrm, 
        (doPSRLrm<64>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSRLrm<64>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSLLWrr, 
        (doPSLLrr<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLWri, 
        (doPSLLri<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSLLWrm, 
        (doPSLLrm<16>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSLLrm<16>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSLLQrr, 
        (doPSLLrr<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLQri, 
        (doPSLLri<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSLLQrm, 
        (doPSLLrm<64>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSLLrm<64>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSLLDQri, 
        (doPSLLri<128>(block, OP(1), OP(2))) )

GENERIC_TRANSLATION(PSHUFDri,
        (doPSHUFDri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSHUFDmi,
        (doPSHUFDmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
        (doPSHUFDmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))) )

GENERIC_TRANSLATION(PSHUFBrr,
        (doPSHUFBrr<128>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSHUFBrm, 
        (doPSHUFBrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPSHUFBrm<128>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSHUFHWri,
        (doPSHUFHWri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSHUFHWmi, 
        (doPSHUFHWmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
        (doPSHUFHWmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))) )

GENERIC_TRANSLATION(PSHUFLWri,
        (doPSHUFLWri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSHUFLWmi, 
        (doPSHUFLWmi(ip, block, OP(0), ADDR_NOREF(1), OP(6))),
        (doPSHUFLWmi(ip, block, OP(0), MEM_REFERENCE(1), OP(6))) )

GENERIC_TRANSLATION(PINSRWrri,
        (doPINSRWrri(block, OP(1), OP(2), OP(3))) )
GENERIC_TRANSLATION_REF(PINSRWrmi,
        (doPINSRWrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
        (doPINSRWrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))) )
    
GENERIC_TRANSLATION(PEXTRWri,
        (doPEXTRWri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PEXTRWmr,
        (doPEXTRWmr(ip, block, ADDR_NOREF(0), OP(5), OP(6))),
        (doPEXTRWmr(ip, block, MEM_REFERENCE(0), OP(5), OP(6))) )

GENERIC_TRANSLATION(PUNPCKLBWrr, 
        (doPUNPCKrr<128,8,UNPACK_LOW>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKLBWrm, 
        (doPUNPCKrm<128,8,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,8,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKLWDrr, 
        (doPUNPCKrr<128,16,UNPACK_LOW>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKLWDrm, 
        (doPUNPCKrm<128,16,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,16,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKLDQrr, 
        (doPUNPCKrr<128,32,UNPACK_LOW>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKLDQrm, 
        (doPUNPCKrm<128,32,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,32,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKLQDQrr, 
        (doPUNPCKrr<128,64,UNPACK_LOW>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKLQDQrm, 
        (doPUNPCKrm<128,64,UNPACK_LOW>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,64,UNPACK_LOW>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKHBWrr, 
        (doPUNPCKrr<128,8,UNPACK_HIGH>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKHBWrm, 
        (doPUNPCKrm<128,8,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,8,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKHWDrr, 
        (doPUNPCKrr<128,16,UNPACK_HIGH>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKHWDrm, 
        (doPUNPCKrm<128,16,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,16,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKHDQrr, 
        (doPUNPCKrr<128,32,UNPACK_HIGH>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKHDQrm, 
        (doPUNPCKrm<128,32,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,32,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PUNPCKHQDQrr, 
        (doPUNPCKrr<128,64,UNPACK_HIGH>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PUNPCKHQDQrm, 
        (doPUNPCKrm<128,64,UNPACK_HIGH>(ip, block, OP(1), ADDR_NOREF(2))),
        (doPUNPCKrm<128,64,UNPACK_HIGH>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PCMPGTBrr,
        (do_SSE_COMPARE_RR<128,8,ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPGTBrm,
        (do_SSE_COMPARE_RM<128,8,ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,8,ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPGTWrr,
        (do_SSE_COMPARE_RR<128,16,ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPGTWrm,
        (do_SSE_COMPARE_RM<128,16,ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,16,ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPGTDrr,
        (do_SSE_COMPARE_RR<128,32,ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPGTDrm,
        (do_SSE_COMPARE_RM<128,32,ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,32,ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPGTQrr,
        (do_SSE_COMPARE_RR<128,64,ICmpInst::ICMP_SGT>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPGTQrm,
        (do_SSE_COMPARE_RM<128,64,ICmpInst::ICMP_SGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,64,ICmpInst::ICMP_SGT>(ip, block, OP(1), MEM_REFERENCE(2))) )


GENERIC_TRANSLATION(PCMPEQBrr,
        (do_SSE_COMPARE_RR<128,8,ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPEQBrm,
        (do_SSE_COMPARE_RM<128,8,ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,8,ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPEQWrr,
        (do_SSE_COMPARE_RR<128,16,ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPEQWrm,
        (do_SSE_COMPARE_RM<128,16,ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,16,ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPEQDrr,
        (do_SSE_COMPARE_RR<128,32,ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPEQDrm,
        (do_SSE_COMPARE_RM<128,32,ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,32,ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PCMPEQQrr,
        (do_SSE_COMPARE_RR<128,64,ICmpInst::ICMP_EQ>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PCMPEQQrm,
        (do_SSE_COMPARE_RM<128,64,ICmpInst::ICMP_EQ>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_COMPARE_RM<128,64,ICmpInst::ICMP_EQ>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PADDBrr, 
        (do_SSE_VECTOR_RR<128,8,Instruction::Add>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PADDBrm, 
        (do_SSE_VECTOR_RM<128,8,Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,8,Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PADDWrr, 
        (do_SSE_VECTOR_RR<128,16,Instruction::Add>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PADDWrm, 
        (do_SSE_VECTOR_RM<128,16,Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,16,Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PADDDrr, 
        (do_SSE_VECTOR_RR<128,32,Instruction::Add>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PADDDrm, 
        (do_SSE_VECTOR_RM<128,32,Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,32,Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PADDQrr, 
        (do_SSE_VECTOR_RR<128,64,Instruction::Add>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PADDQrm, 
        (do_SSE_VECTOR_RM<128,64,Instruction::Add>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,64,Instruction::Add>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(SUBPSrr,
        (do_SSE_FP_VECTOR_RR<128,32,Instruction::FSub>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(SUBPSrm,
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(SUBPDrr,
        (do_SSE_FP_VECTOR_RR<128,64,Instruction::FSub>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(SUBPDrm,
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FSub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FSub>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(ADDPSrr,
        (do_SSE_FP_VECTOR_RR<128,32,Instruction::FAdd>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(ADDPSrm,
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(ADDPDrr,
        (do_SSE_FP_VECTOR_RR<128,64,Instruction::FAdd>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(ADDPDrm,
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FAdd>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FAdd>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MULPSrr,
        (do_SSE_FP_VECTOR_RR<128,32,Instruction::FMul>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(MULPSrm,
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MULPDrr,
        (do_SSE_FP_VECTOR_RR<128,64,Instruction::FMul>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(MULPDrm,
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FMul>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FMul>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(DIVPSrr,
        (do_SSE_FP_VECTOR_RR<128,32,Instruction::FDiv>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(DIVPSrm,
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,32,Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(DIVPDrr,
        (do_SSE_FP_VECTOR_RR<128,64,Instruction::FDiv>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION_REF(DIVPDrm,
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FDiv>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_FP_VECTOR_RM<128,64,Instruction::FDiv>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PSUBUSBrr, 
        (do_SATURATED_SUB_RR<128,8,ICmpInst::ICMP_UGE>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSUBUSBrm, 
        (do_SATURATED_SUB_RM<128,8,ICmpInst::ICMP_UGE>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SATURATED_SUB_RM<128,8,ICmpInst::ICMP_UGE>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSUBUSWrr, 
        (do_SATURATED_SUB_RR<128,16,ICmpInst::ICMP_UGE>(ip, block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PSUBUSWrm, 
        (do_SATURATED_SUB_RM<128,16,ICmpInst::ICMP_UGE>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SATURATED_SUB_RM<128,16,ICmpInst::ICMP_UGE>(ip, block, OP(1), MEM_REFERENCE(2))))

GENERIC_TRANSLATION(PSUBBrr, 
        (do_SSE_VECTOR_RR<128,8,Instruction::Sub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSUBBrm, 
        (do_SSE_VECTOR_RM<128,8,Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,8,Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PSUBWrr, 
        (do_SSE_VECTOR_RR<128,16,Instruction::Sub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSUBWrm, 
        (do_SSE_VECTOR_RM<128,16,Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,16,Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PSUBDrr, 
        (do_SSE_VECTOR_RR<128,32,Instruction::Sub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSUBDrm, 
        (do_SSE_VECTOR_RM<128,32,Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,32,Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(PSUBQrr, 
        (do_SSE_VECTOR_RR<128,64,Instruction::Sub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PSUBQrm, 
        (do_SSE_VECTOR_RM<128,64,Instruction::Sub>(ip, block, OP(1), ADDR_NOREF(2))),
        (do_SSE_VECTOR_RM<128,64,Instruction::Sub>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MAXPSrr,
        (doMAXMIN_FP_VECTOR_rr<128, 32, FCmpInst::FCMP_UGT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MAXPSrm,
        (doMAXMIN_FP_VECTOR_rm<128, 32, FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMIN_FP_VECTOR_rm<128, 32, FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MAXPDrr,
        (doMAXMIN_FP_VECTOR_rr<128, 64, FCmpInst::FCMP_UGT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MAXPDrm,
        (doMAXMIN_FP_VECTOR_rm<128, 64, FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMIN_FP_VECTOR_rm<128, 64, FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MAXSSrr,
        (doMAXMINrr<32, FCmpInst::FCMP_UGT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MAXSSrm,
        (doMAXMINrm<32, FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMINrm<32, FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MAXSDrr,
        (doMAXMINrr<64, FCmpInst::FCMP_UGT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MAXSDrm,
        (doMAXMINrm<64, FCmpInst::FCMP_UGT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMINrm<64, FCmpInst::FCMP_UGT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MINPSrr,
        (doMAXMIN_FP_VECTOR_rr<128, 32, FCmpInst::FCMP_ULT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MINPSrm,
        (doMAXMIN_FP_VECTOR_rm<128, 32, FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMIN_FP_VECTOR_rm<128, 32, FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MINPDrr,
        (doMAXMIN_FP_VECTOR_rr<128, 64, FCmpInst::FCMP_ULT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MINPDrm,
        (doMAXMIN_FP_VECTOR_rm<128, 64, FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMIN_FP_VECTOR_rm<128, 64, FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MINSSrr,
        (doMAXMINrr<32, FCmpInst::FCMP_ULT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MINSSrm,
        (doMAXMINrm<32, FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMINrm<32, FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(MINSDrr,
        (doMAXMINrr<64, FCmpInst::FCMP_ULT>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(MINSDrm,
        (doMAXMINrm<64, FCmpInst::FCMP_ULT>(ip, block, OP(1), ADDR_NOREF(2))),
        (doMAXMINrm<64, FCmpInst::FCMP_ULT>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PBLENDVBrr0,
        (doBLENDVBrr<128>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(PBLENDVBrm0, 
        (doBLENDVBrm<128>(ip, block, OP(1), ADDR_NOREF(2))),
        (doBLENDVBrm<128>(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(PMULUDQrr, 
        (doPMULUDQrr(block, OP(1), OP(2))))
GENERIC_TRANSLATION_REF(PMULUDQrm, 
        (doPMULUDQrm(ip, block, OP(1), ADDR_NOREF(2))),
        (doPMULUDQrm(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(CVTTPS2DQrr, 
        (doCVTTPS2DQrr(block, OP(0), OP(1))))
GENERIC_TRANSLATION_REF(CVTTPS2DQrm, 
        (doCVTTPS2DQrm(ip, block, OP(0), ADDR_NOREF(1))),
        (doCVTTPS2DQrm(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION_REF(MOVHPDrm, 
        (doMOVHPDrm(ip, block, OP(1), ADDR_NOREF(2))),
        (doMOVHPDrm(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION_REF(MOVHPDmr,
        (doMOVHPDmr(ip, block, ADDR_NOREF(0), OP(5))),
        (doMOVHPDmr(ip, block, MEM_REFERENCE(0), OP(5))) )

GENERIC_TRANSLATION_REF(MOVLPDrm, 
        (doMOVLPDrm(ip, block, OP(1), ADDR_NOREF(2))),
        (doMOVLPDrm(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(SHUFPDrri,
        (doSHUFPDrri(block, OP(1), OP(2), OP(3))) )
GENERIC_TRANSLATION_REF(SHUFPDrmi,
        (doSHUFPDrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
        (doSHUFPDrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))) )

GENERIC_TRANSLATION(SHUFPSrri,
        (doSHUFPSrri(block, OP(1), OP(2), OP(3))) )
GENERIC_TRANSLATION_REF(SHUFPSrmi,
        (doSHUFPSrmi(ip, block, OP(1), ADDR_NOREF(2), OP(7))),
        (doSHUFPSrmi(ip, block, OP(1), MEM_REFERENCE(2), OP(7))) )

GENERIC_TRANSLATION(UNPCKLPSrr,
        (doUNPCKLPSrr(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(UNPCKLPSrm,
        (doUNPCKLPSrm(ip, block, OP(1), ADDR_NOREF(2))),
        (doUNPCKLPSrm(ip, block, OP(1), MEM_REFERENCE(2))) )
GENERIC_TRANSLATION(UNPCKLPDrr,
        (doUNPCKLPDrr(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_REF(UNPCKLPDrm,
        (doUNPCKLPDrm(ip, block, OP(1), ADDR_NOREF(2))),
        (doUNPCKLPDrm(ip, block, OP(1), MEM_REFERENCE(2))) )

GENERIC_TRANSLATION(UNPCKHPDrr,
        (doUNPCKHPDrr(block, OP(1), OP(2))) )

GENERIC_TRANSLATION(CVTDQ2PSrr,
        (doCVTDQ2PSrr(block, OP(0), OP(1))) )

GENERIC_TRANSLATION(CVTPS2PDrr,
        (doCVTPS2PDrr(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(CVTPS2PDrm,
        (doCVTPS2PDrm(ip, block, OP(0), ADDR_NOREF(1))),
        (doCVTPS2PDrm(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(CVTPD2PSrr,
        (doCVTPD2PSrr(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(CVTPD2PSrm,
        (doCVTPD2PSrm(ip, block, OP(0), ADDR_NOREF(1))),
        (doCVTPD2PSrm(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(MOV64toPQIrr, 
        (MOVAndZextRR<64>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(MOV64toSDrm, 
        (MOVAndZextRM<64>(ip, block, OP(0), ADDR_NOREF(1))),
        (MOVAndZextRM<64>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVQI2PQIrm,
        (MOVAndZextRM<64>(ip, block, OP(0), ADDR_NOREF(1))),
        (MOVAndZextRM<64>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(MOVDDUPrr,
        (doMOVDDUPrr(block, OP(0), OP(1))) )

void SSE_populateDispatchMap(DispatchMap &m) {
    m[X86::MOVSDrm] = (doMOVSrm<64>);
    m[X86::MOVSDmr] = (doMOVSmr<64>);

    m[X86::CVTSI2SDrr] = (translate_CVTSI2SDrr<32>);
    m[X86::CVTSI2SDrm] = (translate_CVTSI2SDrm<32>);
    m[X86::CVTSI2SD64rr] = (translate_CVTSI2SDrr<64>);
    m[X86::CVTSI2SD64rm] = (translate_CVTSI2SDrm<64>);


    m[X86::CVTSD2SSrm] = translate_CVTSD2SSrm;
    m[X86::CVTSD2SSrr] = translate_CVTSD2SSrr;
    m[X86::CVTSS2SDrm] = translate_CVTSS2SDrm;
    m[X86::CVTSS2SDrr] = translate_CVTSS2SDrr;
	m[X86::MOVSSrm] = (doMOVSrm<32>);
    m[X86::MOVSSmr] = (doMOVSmr<32>);
    m[X86::XORPSrr] = translate_XORPSrr;
    m[X86::XORPSrm] = translate_XORPSrm;
    // XORPD = XORPS = PXOR, for the purposes of translation
    // it just operates on different bitwidth and changes internal register type
    // which is not exposed to outside world but affects performance
    m[X86::XORPDrr] = translate_XORPSrr;
    m[X86::XORPDrm] = translate_XORPSrm;
    m[X86::PXORrr] = translate_XORPSrr;
    m[X86::PXORrm] = translate_XORPSrm;

    // these should be identical
    m[X86::ORPDrr] = translate_PORrr;
    m[X86::ORPDrm] = translate_PORrm;
    m[X86::ORPSrr] = translate_PORrr;
    m[X86::ORPSrm] = translate_PORrm;

    m[X86::CVTSI2SSrr] = translate_CVTSI2SSrr;
    m[X86::CVTSI2SSrm] = translate_CVTSI2SSrm;

    m[X86::CVTSI2SS64rr] = translate_CVTSI2SS64rr;
    m[X86::CVTSI2SS64rm] = translate_CVTSI2SS64rm;

    m[X86::CVTTSD2SIrm] = (doCVTT_to_SI_rm<64,32>);
    m[X86::CVTTSD2SIrr] = (doCVTT_to_SI_rr<64,32>);
    m[X86::CVTTSS2SIrm] = (doCVTT_to_SI_rm<32,32>);
    m[X86::CVTTSS2SIrr] = (doCVTT_to_SI_rr<32,32>);

    m[X86::CVTTSD2SI64rm] = (doCVTT_to_SI_rm<64,64>);
    m[X86::CVTTSD2SI64rr] = (doCVTT_to_SI_rr<64,64>);
    m[X86::CVTTSS2SI64rm] = (doCVTT_to_SI_rm<32,64>);
    m[X86::CVTTSS2SI64rr] = (doCVTT_to_SI_rr<32,64>);

    m[X86::ADDSDrr] = translate_ADDSDrr;
    m[X86::ADDSDrm] = translate_ADDSDrm;
    m[X86::ADDSSrr] = translate_ADDSSrr;
    m[X86::ADDSSrm] = translate_ADDSSrm;
    m[X86::SUBSDrr] = translate_SUBSDrr;
    m[X86::SUBSDrm] = translate_SUBSDrm;
    m[X86::SUBSSrr] = translate_SUBSSrr;
    m[X86::SUBSSrm] = translate_SUBSSrm;
    m[X86::DIVSDrr] = translate_DIVSDrr;
    m[X86::DIVSDrm] = translate_DIVSDrm;
    m[X86::DIVSSrr] = translate_DIVSSrr;
    m[X86::DIVSSrm] = translate_DIVSSrm;
    m[X86::MULSDrr] = translate_MULSDrr;
    m[X86::MULSDrm] = translate_MULSDrm;
    m[X86::MULSSrr] = translate_MULSSrr;
    m[X86::MULSSrm] = translate_MULSSrm;
    m[X86::PORrr] = translate_PORrr;
    m[X86::PORrm] = translate_PORrm;

    m[X86::MOVDQUrm] = (doMOVSrm<128>);
    m[X86::MOVDQUmr] = (doMOVSmr<128>);
    m[X86::MOVDQUrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVDQUrr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVDQArm] = (doMOVSrm<128>);
    m[X86::MOVDQAmr] = (doMOVSmr<128>);
    m[X86::MOVDQArr] = (doMOVSrr<128,0,1>);
    m[X86::MOVDQArr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVUPDrm] = (doMOVSrm<128>);
    m[X86::MOVUPDmr] = (doMOVSmr<128>);

    m[X86::MOVUPSrm] = (doMOVSrm<128>);
    m[X86::MOVUPSmr] = (doMOVSmr<128>);
    m[X86::MOVUPSrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVUPSrr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVAPSrm] = (doMOVSrm<128>);
    m[X86::MOVAPSmr] = (doMOVSmr<128>);
    m[X86::MOVAPSrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVAPSrr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVAPDrm] = (doMOVSrm<128>);
    m[X86::MOVAPDmr] = (doMOVSmr<128>);
    m[X86::MOVAPDrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVAPDrr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVSDrr] = (doMOVSrr<64,1,2>);
    m[X86::MOVSSrr] = (doMOVSrr<32,1,2>);

    m[X86::MOVDI2PDIrr] = translate_MOVDI2PDIrr;
    m[X86::MOVDI2PDIrm] = translate_MOVDI2PDIrm;

    m[X86::MOVPDI2DIrr] = (doMOVSrr<32,0,1>);
    m[X86::MOVPDI2DImr] = (doMOVSmr<32>);

    m[X86::MOVSS2DIrr] = translate_MOVSS2DIrr;
    m[X86::MOVSS2DImr] = (doMOVSmr<32>);

    m[X86::UCOMISSrr] = translate_UCOMISSrr;
    m[X86::UCOMISSrm] = translate_UCOMISSrm;
    m[X86::UCOMISDrr] = translate_UCOMISDrr;
    m[X86::UCOMISDrm] = translate_UCOMISDrm;

    m[X86::PSRAWrr] = translate_PSRAWrr;
    m[X86::PSRAWrm] = translate_PSRAWrm;
    m[X86::PSRAWri] = translate_PSRAWri;
    m[X86::PSRADrr] = translate_PSRADrr;
    m[X86::PSRADrm] = translate_PSRADrm;
    m[X86::PSRADri] = translate_PSRADri;

    m[X86::PSLLWrr] = translate_PSLLWrr;
    m[X86::PSLLWrm] = translate_PSLLWrm;
    m[X86::PSLLWri] = translate_PSLLWri;

    m[X86::PSLLDrr] = translate_PSLLDrr;
    m[X86::PSLLDrm] = translate_PSLLDrm;
    m[X86::PSLLDri] = translate_PSLLDri;

    m[X86::PSLLQrr] = translate_PSLLQrr;
    m[X86::PSLLQrm] = translate_PSLLQrm;
    m[X86::PSLLQri] = translate_PSLLQri;

    m[X86::PSLLDQri] = translate_PSLLDQri;

    m[X86::PSRLWrr] = translate_PSRLWrr;
    m[X86::PSRLWrm] = translate_PSRLWrm;
    m[X86::PSRLWri] = translate_PSRLWri;

    m[X86::PSRLDrr] = translate_PSRLDrr;
    m[X86::PSRLDrm] = translate_PSRLDrm;
    m[X86::PSRLDri] = translate_PSRLDri;

    m[X86::PSRLQrr] = translate_PSRLQrr;
    m[X86::PSRLQrm] = translate_PSRLQrm;
    m[X86::PSRLQri] = translate_PSRLQri;

    m[X86::PSHUFDri] = translate_PSHUFDri;
    m[X86::PSHUFDmi] = translate_PSHUFDmi;

    m[X86::PSHUFBrr] = translate_PSHUFBrr;
    m[X86::PSHUFBrm] = translate_PSHUFBrm;

    m[X86::PINSRWrri] = translate_PINSRWrri;
    m[X86::PINSRWrmi] = translate_PINSRWrmi;

    m[X86::PEXTRWri] = translate_PEXTRWri;
    m[X86::PEXTRWmr] = translate_PEXTRWmr;

    m[X86::PUNPCKLBWrr] = translate_PUNPCKLBWrr;
    m[X86::PUNPCKLBWrm] = translate_PUNPCKLBWrm;
    m[X86::PUNPCKLWDrr] = translate_PUNPCKLWDrr;
    m[X86::PUNPCKLWDrm] = translate_PUNPCKLWDrm;
    m[X86::PUNPCKLDQrr] = translate_PUNPCKLDQrr;
    m[X86::PUNPCKLDQrm] = translate_PUNPCKLDQrm;
    m[X86::PUNPCKLQDQrr] = translate_PUNPCKLQDQrr;
    m[X86::PUNPCKLQDQrm] = translate_PUNPCKLQDQrm;

    m[X86::PUNPCKHBWrr] = translate_PUNPCKHBWrr;
    m[X86::PUNPCKHBWrm] = translate_PUNPCKHBWrm;
    m[X86::PUNPCKHWDrr] = translate_PUNPCKHWDrr;
    m[X86::PUNPCKHWDrm] = translate_PUNPCKHWDrm;
    m[X86::PUNPCKHDQrr] = translate_PUNPCKHDQrr;
    m[X86::PUNPCKHDQrm] = translate_PUNPCKHDQrm;
    m[X86::PUNPCKHQDQrr] = translate_PUNPCKHQDQrr;
    m[X86::PUNPCKHQDQrm] = translate_PUNPCKHQDQrm;

    m[X86::PADDBrr] = translate_PADDBrr;
    m[X86::PADDBrm] = translate_PADDBrm;
    m[X86::PADDWrr] = translate_PADDWrr;
    m[X86::PADDWrm] = translate_PADDWrm;
    m[X86::PADDDrr] = translate_PADDDrr;
    m[X86::PADDDrm] = translate_PADDDrm;
    m[X86::PADDQrr] = translate_PADDQrr;
    m[X86::PADDQrm] = translate_PADDQrm;

    m[X86::PSUBUSBrr] = translate_PSUBUSBrr;
    m[X86::PSUBUSBrm] = translate_PSUBUSBrm;

    m[X86::PSUBUSWrr] = translate_PSUBUSWrr;
    m[X86::PSUBUSWrm] = translate_PSUBUSWrm;

    m[X86::PSUBBrr] = translate_PSUBBrr;
    m[X86::PSUBBrm] = translate_PSUBBrm;
    m[X86::PSUBWrr] = translate_PSUBWrr;
    m[X86::PSUBWrm] = translate_PSUBWrm;
    m[X86::PSUBDrr] = translate_PSUBDrr;
    m[X86::PSUBDrm] = translate_PSUBDrm;
    m[X86::PSUBQrr] = translate_PSUBQrr;
    m[X86::PSUBQrm] = translate_PSUBQrm;

    m[X86::MAXPSrr] = translate_MAXPSrr;
    m[X86::MAXPSrm] = translate_MAXPSrm;
    m[X86::MAXPDrr] = translate_MAXPDrr;
    m[X86::MAXPDrm] = translate_MAXPDrm;
    m[X86::MAXSSrr] = translate_MAXSSrr;
    m[X86::MAXSSrm] = translate_MAXSSrm;
    m[X86::MAXSDrr] = translate_MAXSDrr;
    m[X86::MAXSDrm] = translate_MAXSDrm;

    m[X86::MINPSrr] = translate_MINPSrr;
    m[X86::MINPSrm] = translate_MINPSrm;
    m[X86::MINPDrr] = translate_MINPDrr;
    m[X86::MINPDrm] = translate_MINPDrm;
    m[X86::MINSSrr] = translate_MINSSrr;
    m[X86::MINSSrm] = translate_MINSSrm;
    m[X86::MINSDrr] = translate_MINSDrr;
    m[X86::MINSDrm] = translate_MINSDrm;

    // all the same AND op
    m[X86::PANDrr] = translate_PANDrr;
    m[X86::PANDrm] = translate_PANDrm;
    m[X86::ANDPDrr] = translate_PANDrr;
    m[X86::ANDPDrm] = translate_PANDrm;
    m[X86::ANDPSrr] = translate_PANDrr;
    m[X86::ANDPSrm] = translate_PANDrm;

    // all the same NAND op
    m[X86::PANDNrr] = translate_PANDNrr;
    m[X86::PANDNrm] = translate_PANDNrm;
    m[X86::ANDNPDrr] = translate_PANDNrr;
    m[X86::ANDNPDrm] = translate_PANDNrm;
    m[X86::ANDNPSrr] = translate_PANDNrr;
    m[X86::ANDNPSrm] = translate_PANDNrm;

    // compares
    m[X86::PCMPGTBrr] = translate_PCMPGTBrr;
    m[X86::PCMPGTBrm] = translate_PCMPGTBrm;
    m[X86::PCMPGTWrr] = translate_PCMPGTWrr;
    m[X86::PCMPGTWrm] = translate_PCMPGTWrm;
    m[X86::PCMPGTDrr] = translate_PCMPGTDrr;
    m[X86::PCMPGTDrm] = translate_PCMPGTDrm;
    m[X86::PCMPGTQrr] = translate_PCMPGTQrr;
    m[X86::PCMPGTQrm] = translate_PCMPGTQrm;

    m[X86::PCMPEQBrr] = translate_PCMPEQBrr;
    m[X86::PCMPEQBrm] = translate_PCMPEQBrm;
    m[X86::PCMPEQWrr] = translate_PCMPEQWrr;
    m[X86::PCMPEQWrm] = translate_PCMPEQWrm;
    m[X86::PCMPEQDrr] = translate_PCMPEQDrr;
    m[X86::PCMPEQDrm] = translate_PCMPEQDrm;
    m[X86::PCMPEQQrr] = translate_PCMPEQQrr;
    m[X86::PCMPEQQrm] = translate_PCMPEQQrm;

    m[X86::PMOVSXBWrr] = translate_PMOVSXBWrr;
    m[X86::PMOVSXBWrm] = translate_PMOVSXBWrm;
    m[X86::PMOVSXBDrr] = translate_PMOVSXBDrr;
    m[X86::PMOVSXBDrm] = translate_PMOVSXBDrm;
    m[X86::PMOVSXBQrr] = translate_PMOVSXBQrr;
    m[X86::PMOVSXBQrm] = translate_PMOVSXBQrm;
    m[X86::PMOVSXWDrr] = translate_PMOVSXWDrr;
    m[X86::PMOVSXWDrm] = translate_PMOVSXWDrm;
    m[X86::PMOVSXWQrr] = translate_PMOVSXWQrr;
    m[X86::PMOVSXWQrm] = translate_PMOVSXWQrm;
    m[X86::PMOVSXDQrr] = translate_PMOVSXDQrr;
    m[X86::PMOVSXDQrm] = translate_PMOVSXDQrm;

    m[X86::PMOVZXBWrr] = translate_PMOVZXBWrr;
    m[X86::PMOVZXBWrm] = translate_PMOVZXBWrm;
    m[X86::PMOVZXBDrr] = translate_PMOVZXBDrr;
    m[X86::PMOVZXBDrm] = translate_PMOVZXBDrm;
    m[X86::PMOVZXBQrr] = translate_PMOVZXBQrr;
    m[X86::PMOVZXBQrm] = translate_PMOVZXBQrm;
    m[X86::PMOVZXWDrr] = translate_PMOVZXWDrr;
    m[X86::PMOVZXWDrm] = translate_PMOVZXWDrm;
    m[X86::PMOVZXWQrr] = translate_PMOVZXWQrr;
    m[X86::PMOVZXWQrm] = translate_PMOVZXWQrm;
    m[X86::PMOVZXDQrr] = translate_PMOVZXDQrr;
    m[X86::PMOVZXDQrm] = translate_PMOVZXDQrm;

    m[X86::PBLENDVBrr0] = translate_PBLENDVBrr0;
    m[X86::PBLENDVBrm0] = translate_PBLENDVBrm0;

    m[X86::MOVHLPSrr] = translate_MOVHLPSrr;
    m[X86::MOVLHPSrr] = translate_MOVLHPSrr;

    m[X86::PMULUDQrr] = translate_PMULUDQrr;
    m[X86::PMULUDQrm] = translate_PMULUDQrm;

    m[X86::CVTTPS2DQrr] = translate_CVTTPS2DQrr;
    m[X86::CVTTPS2DQrm] = translate_CVTTPS2DQrm;

    m[X86::MOVHPDrm] = translate_MOVHPDrm;
    m[X86::MOVHPDmr] = translate_MOVHPDmr;

    m[X86::MOVLPDrm] = translate_MOVLPDrm;
    m[X86::MOVLPDmr] = (doMOVSmr<64>);

    // we don't care if its moving two single precision floats
    // or a double precision float. 64 bits are 64 bits
    m[X86::MOVLPSrm] = translate_MOVLPDrm;
    m[X86::MOVLPSmr] = (doMOVSmr<64>);

    m[X86::SHUFPSrri] = translate_SHUFPSrri;
    m[X86::SHUFPSrmi] = translate_SHUFPSrmi;
    m[X86::SHUFPDrri] = translate_SHUFPDrri;
    m[X86::SHUFPDrmi] = translate_SHUFPDrmi;

    m[X86::PSHUFHWri] = translate_PSHUFHWri;
    m[X86::PSHUFHWmi] = translate_PSHUFHWmi;
    m[X86::PSHUFLWri] = translate_PSHUFLWri;
    m[X86::PSHUFLWmi] = translate_PSHUFLWmi;

    m[X86::UNPCKLPSrm] = translate_UNPCKLPSrm;
    m[X86::UNPCKLPSrr] = translate_UNPCKLPSrr;
    m[X86::UNPCKLPDrm] = translate_UNPCKLPDrm;
    m[X86::UNPCKLPDrr] = translate_UNPCKLPDrr;

    m[X86::UNPCKHPDrr] = translate_UNPCKHPDrr;

    m[X86::CVTPS2PDrm] = translate_CVTPS2PDrm;
    m[X86::CVTPS2PDrr] = translate_CVTPS2PDrr;

    m[X86::CVTDQ2PSrr] = translate_CVTDQ2PSrr;

    m[X86::CVTPD2PSrm] = translate_CVTPD2PSrm;
    m[X86::CVTPD2PSrr] = translate_CVTPD2PSrr;

    m[X86::MOV64toPQIrr] = translate_MOV64toPQIrr;
    m[X86::MOVPQIto64rr] = (doMOVSrr<64, 0, 1>);
    m[X86::MOV64toSDrm]  = translate_MOV64toSDrm;
    m[X86::MOVQI2PQIrm]  = translate_MOVQI2PQIrm;
    m[X86::MOVPQI2QImr]  = (doMOVSmr<64>);
    
    m[X86::MOVDDUPrr] = translate_MOVDDUPrr;

    m[X86::SUBPDrr] = translate_SUBPDrr;
    m[X86::SUBPDrm] = translate_SUBPDrm;

    m[X86::SUBPSrr] = translate_SUBPSrr;
    m[X86::SUBPSrm] = translate_SUBPSrm;

    m[X86::ADDPDrr] = translate_ADDPDrr;
    m[X86::ADDPDrm] = translate_ADDPDrm;

    m[X86::ADDPSrr] = translate_ADDPSrr;
    m[X86::ADDPSrm] = translate_ADDPSrm;

    m[X86::MULPDrr] = translate_MULPDrr;
    m[X86::MULPDrm] = translate_MULPDrm;

    m[X86::MULPSrr] = translate_MULPSrr;
    m[X86::MULPSrm] = translate_MULPSrm;

    m[X86::DIVPSrr] = translate_DIVPSrr;
    m[X86::DIVPSrm] = translate_DIVPSrm;

    m[X86::DIVPDrr] = translate_DIVPDrr;
    m[X86::DIVPDrm] = translate_DIVPDrm;
}
