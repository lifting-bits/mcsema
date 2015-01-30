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

    Value *zext = new llvm::ZExtInst(src, 
                        llvm::Type::getIntNTy(block->getContext(), 128),
                        "",
                        block);
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
        R_WRITE<width>(block, OP(0).getReg(), addrInt);
        return ContinueBlock;
    }
    else if( ip->is_data_offset() ) {
        ret = doRMMov<width>(ip, block, 
                GLOBAL( block, natM, inst, ip, 1 ),
                OP(0) );
    } else {
        ret = doRMMov<width>(ip, block, ADDR(1), OP(0));
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
    else if( ip->is_data_offset() ) {
        ret = doMRMov<width>(ip, block, GLOBAL( block, natM, inst, ip, 0), OP(5) );
    } else { 
        ret = doMRMov<width>(ip, block, ADDR(0), OP(5)) ; 
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
//
static InstTransResult translate_CVTSI2SDrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(src.isReg()); 
    NASSERT(dst.isReg()); 

    // read 32 bits from source
    Value *rval = R_READ<32>(block, src.getReg());

    return doCVTSI2SrV<64>(natM, block, ip, inst, rval, dst);
}

static InstTransResult translate_CVTSI2SDrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) 
{
    const MCOperand &dst = OP(0);
    NASSERT(dst.isReg()); 

    Value *src = ADDR(1);

    // read 32 bits from memory
    Value *mval = M_READ<32>(ip, block, src);

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

    Value *mem = ADDR(1);

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

	Value *mem = ADDR(1);

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
    Value *mem_addr = ADDR(1);

    NASSERT(dst.isReg()); 

    Value *src_val = M_READ<32>(ip, block, mem_addr);

    return doCVTSI2SrV<32>(natM, block, ip, inst, src_val, dst);

}


template <int width>
static InstTransResult doCVTTS2SIrV(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst, Value *src, const MCOperand &dst)
{
    Value *final_v = NULL;

    Value *to_int = CastInst::Create(
            Instruction::FPToSI,
            INT_AS_FP<width>(block, src),
            Type::getIntNTy(block->getContext(), 32),
            "",
            block);

    R_WRITE<32>(block, dst.getReg(), to_int);

    return ContinueBlock;

}

// convert w/ trunaction scalar double-precision fp value to signed integer
static InstTransResult translate_CVTTSD2SIrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    Value *mem_addr = ADDR(1);

    NASSERT(dst.isReg());
    
    Value *src_val = M_READ<64>(ip, block, mem_addr);
    
    return doCVTTS2SIrV<64>(natM, block, ip, inst, src_val, dst);

}

// convert w/ trunaction scalar double-precision fp value (xmm reg) to signed integer
static InstTransResult translate_CVTTSD2SIrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    
    Value *src_val = R_READ<64>(block, src.getReg());
    
    return doCVTTS2SIrV<64>(natM, block, ip, inst, src_val, dst);

}

// convert w/ truncation scalar single-precision fp value to dword integer
static InstTransResult translate_CVTTSS2SIrm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    Value *mem_addr = ADDR(1);

    NASSERT(dst.isReg());
    
    Value *src_val = M_READ<32>(ip, block, mem_addr);
    
    return doCVTTS2SIrV<32>(natM, block, ip, inst, src_val, dst);

}

// convert w/ truncation scalar single-precision fp value (xmm reg) to dword integer
static InstTransResult translate_CVTTSS2SIrr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {

    const MCOperand &dst = OP(0);
    const MCOperand &src = OP(1);

    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    
    Value *src_val = R_READ<32>(block, src.getReg());
    
    return doCVTTS2SIrV<32>(natM, block, ip, inst, src_val, dst);

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

    F_WRITE(block, "ZF", is_eq);            // ZF is 1 if either is QNaN or op1 == op2
    F_WRITE(block, "PF", is_qnan);          // PF is 1 if either op is a QNaN
    F_WRITE(block, "CF", is_lt);            // CF is 1 if either is QNaN or op1 < op2

    F_WRITE(block, "OF", CONST_V<1>(block, 0));
    F_WRITE(block, "SF", CONST_V<1>(block, 0));
    F_WRITE(block, "AF", CONST_V<1>(block, 0));


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
static InstTransResult doShiftOp(BasicBlock *&b, 
        const MCOperand &dst, 
        Value *shift_count, 
        Value *fallback)
{
    NASSERT(dst.isReg());
    NASSERT(128 % elementwidth == 0);


    Value *max_count = CONST_V<128>(b, elementwidth);
    Value *isOver = new ICmpInst(  *b, 
                                    CmpInst::ICMP_ULT, 
                                    shift_count, 
                                    max_count);


    Type *elem_ty;
    VectorType *vt;

    std::tie(vt, elem_ty) = getIntVectorTypes(b, elementwidth, 128/elementwidth);

    // convert our base value to a vector
    Value *to_shift = R_READ<128>(b, dst.getReg());
    Value *vecValue = INT_AS_VECTOR<128, elementwidth>(b, to_shift); 

    // limit shifts to 15 or 31 bits
    // otherwise the operator is undefined
    Value *bounded_shift = BinaryOperator::CreateAnd(
            shift_count, 
            CONST_V<128>(b, elementwidth-1), 
            "", b);

    Value *trunc_shift = new TruncInst( 
            bounded_shift, 
            elem_ty, 
            "",
            b);

    Value *vecShiftPtr = new AllocaInst(vt, nullptr, "", b);
    Value *vecShift = new LoadInst(vecShiftPtr, "", b);

    Value *which_to_put = SelectInst::Create(
                    isOver, 
                    trunc_shift,
                    fallback,
                    "",
                    b);

    int elem_count = 128/elementwidth;
    for(int i = 0; i < elem_count; i++) {
        InsertElementInst::Create(
                vecShift, 
                which_to_put, 
                CONST_V<32>(b, i), 
                "", 
                b );
    }

    // shift each vector 
    Value *shifted = BinaryOperator::Create(bin_op, vecValue, vecShift, "", b);

    // convert value back to a 128bit int
    Value *back_to_int = CastInst::Create(
            Instruction::BitCast,
            vecValue,
            Type::getIntNTy(b->getContext(), 128),
            "",
            b);

    // write back to register
    R_WRITE<128>(b, dst.getReg(), back_to_int);

    return ContinueBlock;
}

template <int width>
static InstTransResult doPSRArr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *shift_count = R_READ<128>(b, src.getReg());
    Value *fb_pre = CONST_V<width>(b, 0);
    Value *fallback = llvm::BinaryOperator::CreateNot(fb_pre, "", b);

    return doShiftOp<width, Instruction::AShr>(b, dst, shift_count, fallback);
}

template <int width>
static InstTransResult doPSRArm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    Value *shift_count = M_READ<128>(ip, b, memAddr);
    Value *fb_pre = CONST_V<width>(b, 0);
    Value *fallback = llvm::BinaryOperator::CreateNot(fb_pre, "", b);

    return doShiftOp<width, Instruction::AShr>(b, dst, shift_count, fallback);
}

template <int width>
static InstTransResult doPSRAri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isImm());

    Value *shift_count = CONST_V<128>(b, src.getImm());
    Value *fb_pre = CONST_V<width>(b, 0);
    Value *fallback = llvm::BinaryOperator::CreateNot(fb_pre, "", b);

    return doShiftOp<width, Instruction::AShr>(b, dst, shift_count, fallback);
}

template <int width>
static InstTransResult doPSLLrr(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isReg());

    Value *shift_count = R_READ<128>(b, src.getReg());

    return doShiftOp<width, Instruction::Shl>(b, dst, shift_count, CONST_V<width>(b, 0));
}

template <int width>
static InstTransResult doPSLLrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{
    Value *shift_count = M_READ<128>(ip, b, memAddr);

    return doShiftOp<width, Instruction::Shl>(b, dst, shift_count, CONST_V<width>(b, 0));
}

template <int width>
static InstTransResult doPSLLri(BasicBlock *&b, const MCOperand &dst, const MCOperand &src)
{
    NASSERT(src.isImm());

    Value *shift_count = CONST_V<128>(b, src.getImm());

    return doShiftOp<width, Instruction::Shl>(b, dst, shift_count, CONST_V<width>(b, 0));
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

GENERIC_TRANSLATION(PORrr, 
        (do_SSE_INT_RR<128,Instruction::Or>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PORrm, 
        (do_SSE_INT_RM<128,Instruction::Or>(ip, block, OP(1), ADDR(2))),
        (do_SSE_INT_RM<128,Instruction::Or>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(MMX_PORirr,
        (do_SSE_INT_RR<64,Instruction::Or>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(MMX_PORirm,
        (do_SSE_INT_RM<64,Instruction::Or>(ip, block, OP(1), ADDR(2))),
        (do_SSE_INT_RM<64,Instruction::Or>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(XORPSrr, 
        (do_SSE_INT_RR<128,Instruction::Xor>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(XORPSrm, 
        (do_SSE_INT_RM<128,Instruction::Xor>(ip, block, OP(1), ADDR(2))),
        (do_SSE_INT_RM<128,Instruction::Xor>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(ADDSDrr, 
        (do_SSE_RR<64,Instruction::FAdd>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(ADDSDrm, 
        (do_SSE_RM<64,Instruction::FAdd>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<64,Instruction::FAdd>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(ADDSSrr, 
        (do_SSE_RR<32,Instruction::FAdd>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(ADDSSrm, 
        (do_SSE_RM<32,Instruction::FAdd>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<32,Instruction::FAdd>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(SUBSDrr, 
        (do_SSE_RR<64,Instruction::FSub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(SUBSDrm, 
        (do_SSE_RM<64,Instruction::FSub>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<64,Instruction::FSub>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(SUBSSrr, 
        (do_SSE_RR<32,Instruction::FSub>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(SUBSSrm, 
        (do_SSE_RM<32,Instruction::FSub>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<32,Instruction::FSub>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(DIVSDrr, 
        (do_SSE_RR<64,Instruction::FDiv>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(DIVSDrm, 
        (do_SSE_RM<64,Instruction::FDiv>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<64,Instruction::FDiv>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(DIVSSrr, 
        (do_SSE_RR<32,Instruction::FDiv>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(DIVSSrm, 
        (do_SSE_RM<32,Instruction::FDiv>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<32,Instruction::FDiv>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(MULSDrr, 
        (do_SSE_RR<64,Instruction::FMul>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(MULSDrm, 
        (do_SSE_RM<64,Instruction::FMul>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<64,Instruction::FMul>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(MULSSrr, 
        (do_SSE_RR<32,Instruction::FMul>(ip, block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(MULSSrm, 
        (do_SSE_RM<32,Instruction::FMul>(ip, block, OP(1), ADDR(2))),
        (do_SSE_RM<32,Instruction::FMul>(ip, block, OP(1), STD_GLOBAL_OP(2))) )


GENERIC_TRANSLATION(MOVDI2PDIrr, 
        (MOVAndZextRR<32>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_MEM(MOVDI2PDIrm, 
        (MOVAndZextRM<32>(ip, block, OP(0), ADDR(1))),
        (MOVAndZextRM<32>(ip, block, OP(0), STD_GLOBAL_OP(1))) )

GENERIC_TRANSLATION(MOVSS2DIrr, 
        (doRRMov<32>(ip, block, OP(1), OP(2))) )

GENERIC_TRANSLATION(UCOMISSrr, 
        (doUCOMISrr<32>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_MEM(UCOMISSrm, 
        (doUCOMISrm<32>(ip, block, OP(0), ADDR(1))),
        (doUCOMISrm<32>(ip, block, OP(0), STD_GLOBAL_OP(1))) )

GENERIC_TRANSLATION(UCOMISDrr, 
        (doUCOMISrr<64>(block, OP(0), OP(1))) )
GENERIC_TRANSLATION_MEM(UCOMISDrm, 
        (doUCOMISrm<64>(ip, block, OP(0), ADDR(1))),
        (doUCOMISrm<64>(ip, block, OP(0), STD_GLOBAL_OP(1))) )

GENERIC_TRANSLATION(PSRAWrr, 
        (doPSRArr<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRAWri, 
        (doPSRAri<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSRAWrm, 
        (doPSRArm<16>(ip, block, OP(1), ADDR(2))),
        (doPSRArm<16>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(PSRADrr, 
        (doPSRArr<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSRADri, 
        (doPSRAri<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSRADrm, 
        (doPSRArm<32>(ip, block, OP(1), ADDR(2))),
        (doPSRArm<32>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(PSLLDrr, 
        (doPSLLrr<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLDri, 
        (doPSLLri<32>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSLLDrm, 
        (doPSLLrm<32>(ip, block, OP(1), ADDR(2))),
        (doPSLLrm<32>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(PSLLWrr, 
        (doPSLLrr<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLWri, 
        (doPSLLri<16>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSLLWrm, 
        (doPSLLrm<16>(ip, block, OP(1), ADDR(2))),
        (doPSLLrm<16>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(PSLLQrr, 
        (doPSLLrr<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION(PSLLQri, 
        (doPSLLri<64>(block, OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSLLQrm, 
        (doPSLLrm<64>(ip, block, OP(1), ADDR(2))),
        (doPSLLrm<64>(ip, block, OP(1), STD_GLOBAL_OP(2))) )

GENERIC_TRANSLATION(PSHUFDri,
        (doPSHUFDri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PSHUFDmi,
        (doPSHUFDmi(ip, block, OP(0), ADDR(1), OP(6))),
        (doPSHUFDmi(ip, block, OP(0), STD_GLOBAL_OP(1), OP(6))) )

GENERIC_TRANSLATION(PINSRWrri,
        (doPINSRWrri(block, OP(1), OP(2), OP(3))) )
GENERIC_TRANSLATION_MEM(PINSRWrmi,
        (doPINSRWrmi(ip, block, OP(1), ADDR(2), OP(7))),
        (doPINSRWrmi(ip, block, OP(1), STD_GLOBAL_OP(2), OP(7))) )
    
GENERIC_TRANSLATION(PEXTRWri,
        (doPEXTRWri(block, OP(0), OP(1), OP(2))) )
GENERIC_TRANSLATION_MEM(PEXTRWmr,
        (doPEXTRWmr(ip, block, ADDR(0), OP(5), OP(6))),
        (doPEXTRWmr(ip, block, STD_GLOBAL_OP(0), OP(5), OP(6))) )

void SSE_populateDispatchMap(DispatchMap &m) {
    m[X86::MOVSDrm] = (doMOVSrm<64>);
    m[X86::MOVSDmr] = (doMOVSmr<64>);
    m[X86::CVTSI2SDrr] = translate_CVTSI2SDrr;
    m[X86::CVTSI2SDrm] = translate_CVTSI2SDrm;
    m[X86::CVTSD2SSrm] = translate_CVTSD2SSrm;
    m[X86::CVTSD2SSrr] = translate_CVTSD2SSrr;
    m[X86::CVTSS2SDrm] = translate_CVTSS2SDrm;
    m[X86::CVTSS2SDrr] = translate_CVTSS2SDrr;
	m[X86::MOVSSrm] = (doMOVSrm<32>);
    m[X86::MOVSSmr] = (doMOVSmr<32>);
    m[X86::XORPSrr] = translate_XORPSrr;
    m[X86::XORPSrm] = translate_XORPSrm;
    // XORPD = XORPS, for the purposes of translation
    // it just operates on different bitwidth and changes internal register type
    // which is not exposed to outside world but affects performance
    m[X86::XORPDrr] = translate_XORPSrr;
    m[X86::XORPDrm] = translate_XORPSrm;

    m[X86::CVTSI2SSrr] = translate_CVTSI2SSrr;
    m[X86::CVTSI2SSrm] = translate_CVTSI2SSrm;

    m[X86::CVTTSD2SIrm] = translate_CVTTSD2SIrm;
    m[X86::CVTTSD2SIrr] = translate_CVTTSD2SIrr;
    m[X86::CVTTSS2SIrm] = translate_CVTTSS2SIrm;
    m[X86::CVTTSS2SIrr] = translate_CVTTSS2SIrr;

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

    m[X86::MOVUPSrm] = (doMOVSrm<128>);
    m[X86::MOVUPSmr] = (doMOVSmr<128>);
    m[X86::MOVUPSrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVUPSrr_REV] = (doMOVSrr<128,0,1>);

    m[X86::MOVAPSrm] = (doMOVSrm<128>);
    m[X86::MOVAPSmr] = (doMOVSmr<128>);
    m[X86::MOVAPSrr] = (doMOVSrr<128,0,1>);
    m[X86::MOVAPSrr_REV] = (doMOVSrr<128,0,1>);

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

    m[X86::PSHUFDri] = translate_PSHUFDri;
    m[X86::PSHUFDmi] = translate_PSHUFDmi;

    m[X86::PINSRWrri] = translate_PINSRWrri;
    m[X86::PINSRWrmi] = translate_PINSRWrmi;

    m[X86::PEXTRWri] = translate_PEXTRWri;
    m[X86::PEXTRWmr] = translate_PEXTRWmr;

}
