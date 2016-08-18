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
#include "x86Instrs_MOV.h"
#include "x86Instrs_flagops.h"
#include "x86Instrs_Misc.h"
#include "llvm/Support/Debug.h"
#include "ArchOps.h"

using namespace llvm;

static InstTransResult doNoop(BasicBlock *b) {
  //isn't this exciting
  return ContinueBlock;
}

static InstTransResult doHlt(BasicBlock *b) {
  //isn't this exciting
  llvm::dbgs() << "WARNING: Treating HLT as no-op, but HLT is normally privileged\n";
  return ContinueBlock;
}

static InstTransResult doInt3(BasicBlock *b) {
	Module	*M = b->getParent()->getParent();
	//emit an LLVM trap intrinsic
	//this should be changed to a debugtrap intrinsic eventually
	Function	*trapIntrin = Intrinsic::getDeclaration(M, Intrinsic::trap);

	CallInst::Create(trapIntrin, "", b);

    Value *unreachable = new UnreachableInst(b->getContext(), b);

	return ContinueBlock;
}

static InstTransResult doTrap(BasicBlock *b) {
	Module	*M = b->getParent()->getParent();
	Function	*trapIntrin = Intrinsic::getDeclaration(M, Intrinsic::trap);
	CallInst::Create(trapIntrin, "", b);
    Value *unreachable = new UnreachableInst(b->getContext(), b);
	return ContinueBlock;
}

static InstTransResult doCdq( BasicBlock   *b ) {
    // EDX <- SEXT(EAX)

    //read EAX
    Value   *EAX_v = R_READ<32>(b, X86::EAX);

    Value *sign_bit = CONST_V<32>(b, 1<<31);

    Value   *test_bit = 
        BinaryOperator::CreateAnd(EAX_v, sign_bit, "", b);


    Value   *is_zero = new ICmpInst(*b,
                                    CmpInst::ICMP_EQ,
                                    test_bit,
                                    CONST_V<32>(b, 0));
    Value *edx_val = SelectInst::Create(
            is_zero,
            CONST_V<32>(b, 0),
            CONST_V<32>(b, 0xFFFFFFFF),
            "", b);

    //write this value to EDX
    R_WRITE<32>(b, X86::EDX, edx_val);

    return ContinueBlock;
}


template <int width>
static InstTransResult doBswapR(InstPtr ip,   BasicBlock *&b,
                            const MCOperand &reg) 
{
    TASSERT(reg.isReg(), "");

    if(width != 32)
    {
        throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    Value   *tmp = R_READ<width>(b, reg.getReg());

    // Create the new bytes from the original value
    Value   *newByte1 = BinaryOperator::CreateShl(tmp, CONST_V<width>(b, 24), "", b);
    Value   *newByte2 = BinaryOperator::CreateShl(BinaryOperator::CreateAnd(tmp, CONST_V<width>(b, 0x0000FF00), "", b),
                                                    CONST_V<width>(b, 8),
                                                    "",
                                                    b);
    Value   *newByte3 = BinaryOperator::CreateLShr(BinaryOperator::CreateAnd(tmp, CONST_V<width>(b, 0x00FF0000), "", b),
                                                    CONST_V<width>(b, 8),
                                                    "",
                                                    b);
    Value   *newByte4 = BinaryOperator::CreateLShr(tmp, CONST_V<width>(b, 24), "", b);
    
    // Add the bytes together to make the resulting DWORD
    Value   *res = BinaryOperator::CreateAdd(newByte1, newByte2, "", b);
    res = BinaryOperator::CreateAdd(res, newByte3, "", b);
    res = BinaryOperator::CreateAdd(res, newByte4, "", b);

    R_WRITE<width>(b, reg.getReg(), res);

    return ContinueBlock;
}


static InstTransResult doLAHF(BasicBlock *b) {

    //we need to create an 8-bit value out of the status 
    //flags, shift and OR them, and then write them into AH

    Type    *t = Type::getInt8Ty(b->getContext());
    Value   *cf = new ZExtInst(F_READ(b, CF), t, "", b);
    Value   *af = new ZExtInst(F_READ(b, AF), t, "", b);
    Value   *pf = new ZExtInst(F_READ(b, PF), t, "", b);
    Value   *zf = new ZExtInst(F_READ(b, ZF), t, "", b);
    Value   *sf = new ZExtInst(F_READ(b, SF), t, "", b);

    //shift everything
    Value   *p_0 = cf;
    Value   *p_1 = 
        BinaryOperator::CreateShl(CONST_V<8>(b, 1), CONST_V<8>(b, 1), "", b);
    Value   *p_2 = 
        BinaryOperator::CreateShl(pf, CONST_V<8>(b, 2), "", b);
    Value   *p_3 =
        BinaryOperator::CreateShl(CONST_V<8>(b, 0), CONST_V<8>(b, 3), "", b);
    Value   *p_4 =
        BinaryOperator::CreateShl(af, CONST_V<8>(b, 4), "", b);
    Value   *p_5 =
        BinaryOperator::CreateShl(CONST_V<8>(b, 0), CONST_V<8>(b, 5), "", b);
    Value   *p_6 =
        BinaryOperator::CreateShl(zf, CONST_V<8>(b, 6), "", b);
    Value   *p_7 =
        BinaryOperator::CreateShl(sf, CONST_V<8>(b, 7), "", b);

    //OR everything
    Value   *res = 
        BinaryOperator::CreateOr(
            BinaryOperator::CreateOr(
                BinaryOperator::CreateOr(
                    BinaryOperator::CreateOr(p_0, p_1, "", b), 
                    p_2, "", b), 
                p_3, "", b), 
            BinaryOperator::CreateOr(
                BinaryOperator::CreateOr(
                    BinaryOperator::CreateOr(p_4, p_5, "", b), 
                    p_6, "", b), 
                p_7, "", b), 
            "", b);

    R_WRITE<8>(b, X86::AH, res);

    return ContinueBlock;
}

static InstTransResult doStd(BasicBlock *b) {

    F_SET(b, DF);

    return ContinueBlock;
}

static InstTransResult doCld(BasicBlock *b) {

    F_CLEAR(b, DF);

    return ContinueBlock;
}

static InstTransResult doStc(BasicBlock *b) {

    F_SET(b, CF);

    return ContinueBlock;
}

static InstTransResult doClc(BasicBlock *b) {

    F_CLEAR(b, CF);

    return ContinueBlock;
}

template<int width>
static InstTransResult doLeaV(BasicBlock *&b, 
                        const MCOperand &dst,
                        Value *addrInt)

{
    //write the address into the register
    R_WRITE<width>(b, dst.getReg(), addrInt);

    return ContinueBlock;
}

template<int width>
static InstTransResult doLea(InstPtr ip,   BasicBlock *&b, 
                        Value           *addr,
                        const MCOperand &dst)
{
    // LEA <r>, <expr>
    TASSERT(addr != NULL, "");
    TASSERT(dst.isReg(), "");

    //addr is an address, so, convert it to an integer value to write
    Type    *ty = Type::getIntNTy(b->getContext(), width);
    Value *addrInt = addr;
    if(addr->getType()->isPointerTy()) {
        addrInt = new PtrToIntInst(addr, ty, "", b);
    }

    return doLeaV<width>(b, dst, addrInt); 
}

static InstTransResult doRdtsc(BasicBlock *b) {
  /* write out a call to the RDTSC intrinsic */
	Module	*M = b->getParent()->getParent();
	//emit an LLVM trap intrinsic
	//this should be changed to a debugtrap intrinsic eventually
	Function	*rcc = Intrinsic::getDeclaration(M, Intrinsic::readcyclecounter);

	CallInst::Create(rcc, "", b);

  return ContinueBlock;
}

static InstTransResult doAAA(BasicBlock *b) {

    Function    *F = b->getParent();
    //trueBlock for when ((AL & 0x0F > 9) || (AF == 1)); falseblock otherwise
    BasicBlock  *trueBlock = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock  *falseBlock = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock  *endBlock = BasicBlock::Create(F->getContext(), "", F);

    Value   *al;
    Value   *af;

    al = R_READ<8>(b, X86::AL);
    af = F_READ(b, AF);

    // AL & 0x0F 
    Value   *andRes = BinaryOperator::CreateAnd(al, CONST_V<8>(b, 0x0F), "", b);

    // ((AL & 0x0F) > 9)? 
    Value   *testRes = new ICmpInst(*b,
                                    CmpInst::ICMP_UGT,
                                    andRes,
                                    CONST_V<8>(b, 9));

    Value   *orRes = BinaryOperator::CreateOr(testRes, af, "", b);

    BranchInst::Create(trueBlock, falseBlock, orRes, b);

    //True Block Statements
    Value   *alRes = BinaryOperator::CreateAdd(al, CONST_V<8>(trueBlock, 6), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AL, alRes);

    Value   *ahRes = BinaryOperator::CreateAdd(R_READ<8>(trueBlock, X86::AH), CONST_V<8>(trueBlock, 1), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AH, ahRes);

    F_SET(trueBlock, AF);
    F_SET(trueBlock, CF);

    alRes = BinaryOperator::CreateAnd(alRes, CONST_V<8>(trueBlock, 0x0F), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AL, alRes);

    BranchInst::Create(endBlock, trueBlock);

    //False Block Statements
    F_CLEAR(falseBlock, AF);
    F_CLEAR(falseBlock, CF);

    alRes = BinaryOperator::CreateAnd(al, CONST_V<8>(trueBlock, 0x0F), "", falseBlock);
    R_WRITE<8>(falseBlock, X86::AL, alRes);

    BranchInst::Create(endBlock, falseBlock);

    F_ZAP(endBlock, OF);
    F_ZAP(endBlock, SF);
    F_ZAP(endBlock, ZF);
    F_ZAP(endBlock, PF);

    //update our parents concept of what the current block is
    b = endBlock;

    return ContinueBlock;
}

static InstTransResult doAAS(BasicBlock *b) {

    Function    *F = b->getParent();
    //trueBlock for when ((AL & 0x0F > 9) || (AF == 1)); falseblock otherwise
    BasicBlock  *trueBlock = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock  *falseBlock = BasicBlock::Create(F->getContext(), "", F);
    BasicBlock  *endBlock = BasicBlock::Create(F->getContext(), "", F);

    Value   *al;
    Value   *af;

    al = R_READ<8>(b, X86::AL);
    af = F_READ(b, AF);

    // AL & 0x0F 
    Value   *andRes = BinaryOperator::CreateAnd(al, CONST_V<8>(b, 0x0F), "", b);

    // ((AL & 0x0F) > 9)? 
    Value   *testRes = new ICmpInst(*b,
                                    CmpInst::ICMP_UGT,
                                    andRes,
                                    CONST_V<8>(b, 9));

    Value   *orRes = BinaryOperator::CreateOr(testRes, af, "", b);

    BranchInst::Create(trueBlock, falseBlock, orRes, b);

    //True Block Statements
    Value   *alRes = BinaryOperator::CreateSub(al, CONST_V<8>(trueBlock, 6), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AL, alRes);

    Value   *ahRes = BinaryOperator::CreateSub(R_READ<8>(trueBlock, X86::AH), CONST_V<8>(trueBlock, 1), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AH, ahRes);

    F_SET(trueBlock, AF);
    F_SET(trueBlock, CF);

    alRes = BinaryOperator::CreateAnd(alRes, CONST_V<8>(trueBlock, 0x0F), "", trueBlock);
    R_WRITE<8>(trueBlock, X86::AL, alRes);

    BranchInst::Create(endBlock, trueBlock);

    //False Block Statements
    F_CLEAR(falseBlock, AF);
    F_CLEAR(falseBlock, CF);

    alRes = BinaryOperator::CreateAnd(al, CONST_V<8>(trueBlock, 0x0F), "", falseBlock);
    R_WRITE<8>(falseBlock, X86::AL, alRes);

    BranchInst::Create(endBlock, falseBlock);

    F_ZAP(endBlock, OF);
    F_ZAP(endBlock, SF);
    F_ZAP(endBlock, ZF);
    F_ZAP(endBlock, PF);

    //update our parents concept of what the current block is
    b = endBlock;

    return ContinueBlock;
}

static InstTransResult doAAM(BasicBlock *b) {

    Value   *al;

    al = R_READ<8>(b, X86::AL);

    Value   *res = BinaryOperator::Create(Instruction::SDiv, al, CONST_V<8>(b, 0x0A), "", b);
    Value   *mod = BinaryOperator::Create(Instruction::SRem, al, CONST_V<8>(b, 0x0A), "", b);

    R_WRITE<8>(b, X86::AL, mod);
    R_WRITE<8>(b, X86::AH, res);

    WriteSF<8>(b, mod);
    WriteZF<8>(b, mod);
    WritePF<8>(b, mod);
    F_ZAP(b, OF);
    F_ZAP(b, AF);
    F_ZAP(b, CF);

    return ContinueBlock;
}

static InstTransResult doAAD(BasicBlock *b) {

    Value   *al;
    Value   *ah;

    al = R_READ<8>(b, X86::AL);
    ah = R_READ<8>(b, X86::AH);

    Value   *tmp = BinaryOperator::Create(Instruction::Mul, ah, CONST_V<8>(b, 0x0A), "", b);
    tmp = BinaryOperator::CreateAdd(tmp, al, "", b);
    tmp = BinaryOperator::CreateAnd(tmp, CONST_V<8>(b, 0xFF), "", b);

    R_WRITE<8>(b, X86::AL, tmp);
    R_WRITE<8>(b, X86::AH, CONST_V<8>(b, 0x00));

    WriteSF<8>(b, tmp);
    WriteZF<8>(b, tmp);
    WritePF<8>(b, tmp);
    F_ZAP(b, OF);
    F_ZAP(b, AF);
    F_ZAP(b, CF);

    return ContinueBlock;
}

template <int width>
static InstTransResult doCwd(BasicBlock *b) {

    // read ax or eax
    Value *ax_val = R_READ<width>(b, X86::EAX);

    // sign extend to twice width
    Type    *dt = Type::getIntNTy(b->getContext(), width*2);
    Value   *tmp = new SExtInst(ax_val, dt, "", b);

    // rotate leftmost bits into rightmost
    Type    *t = Type::getIntNTy(b->getContext(), width);
    Value   *res_sh = BinaryOperator::Create(
                Instruction::LShr, 
                tmp, 
                CONST_V<width*2>(b, width), 
                "", 
                b);
    // original rightmost
    Value   *wrAX = new TruncInst(tmp, t, "", b);
    // original leftmost
    Value   *wrDX = new TruncInst(res_sh, t, "", b);
    switch(width) {
        case 16:
            R_WRITE<width>(b, X86::DX, wrDX);
            R_WRITE<width>(b, X86::AX, wrAX);
            break;
        case 32:
            R_WRITE<width>(b, X86::EDX, wrDX);
            R_WRITE<width>(b, X86::EAX, wrAX);
            break;
        case 64:
            R_WRITE<width>(b, X86::RDX, wrDX);
            R_WRITE<width>(b, X86::RAX, wrAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Not supported width");
    }

    return ContinueBlock;

}

static InstTransResult translate_SAHF(NativeModulePtr natM, BasicBlock *&block,
    InstPtr ip, MCInst &inst)
{
    Value *ah_val = R_READ<8>(block, X86::AH);
   
    SHR_SET_FLAG<8,1>(block, ah_val, CF, 0); 
    // bit 1 is reserved
    SHR_SET_FLAG<8,1>(block, ah_val, PF, 2); 
    // bit 3 is reserved
    SHR_SET_FLAG<8,1>(block, ah_val, AF, 4); 
    // bit 5 is reserved
    SHR_SET_FLAG<8,1>(block, ah_val, ZF, 6); 
    SHR_SET_FLAG<8,1>(block, ah_val, SF, 7); 

    return ContinueBlock;
}

template<int width>
static InstTransResult doBtrr(
        BasicBlock *&b, 
        const MCOperand &base,
        const MCOperand &index)
{

    TASSERT(base.isReg(), "operand must be register");
    TASSERT(index.isReg(), "operand must be register");

    Value *base_val  = R_READ<width>(b, base.getReg());
    Value *index_val = R_READ<width>(b, index.getReg());

    // modulo the index by register size
    Value *index_mod = BinaryOperator::CreateURem(
            index_val, 
            CONST_V<width>(b, width), 
            "", b);

   SHR_SET_FLAG_V<width,1>(b, base_val, CF, index_mod);

   return ContinueBlock;
}

template<int width>
static InstTransResult doBsrr(
        BasicBlock *&b, 
        const MCOperand &dst,
        const MCOperand &src)
{

    TASSERT(dst.isReg(), "operand must be register");
    TASSERT(src.isReg(), "operand must be register");

    Value *src_val = R_READ<width>(b, src.getReg());

    Type *s[1] = { Type::getIntNTy(b->getContext(), width) };
    Function *ctlzFn = Intrinsic::getDeclaration(b->getParent()->getParent(), Intrinsic::ctlz, s);

    TASSERT(ctlzFn != NULL, "Could not find ctlz intrinsic");

    vector<Value*>  ctlzArgs;
    ctlzArgs.push_back(src_val);
    ctlzArgs.push_back(CONST_V<1>(b, 0));
    Value *ctlz = CallInst::Create(ctlzFn, ctlzArgs, "", b);

    Value *index_of_first_1 = BinaryOperator::CreateSub(
                CONST_V<width>(b, width),
                ctlz,
                "", b);

    Value *is_zero = new ICmpInst(
            *b,
            CmpInst::ICMP_EQ,
            CONST_V<width>(b, 0),
            index_of_first_1);

    F_WRITE(b, ZF, is_zero);

    Value *fix_index = BinaryOperator::CreateSub(
                    index_of_first_1,
                    CONST_V<width>(b, 1),
                    "", b);

    // See if we write to register
    Value *save_index = SelectInst::Create(
            is_zero, // check if the source was zero
            src_val, // if it was, do not change contents
            fix_index,  // if it was not, set index
            "", b);

    R_WRITE<width>(b, dst.getReg(), save_index);

    return ContinueBlock;
}

template<int width>
static InstTransResult doBsfrm(InstPtr ip, BasicBlock *&b, const MCOperand &dst, Value *memAddr)
{

    TASSERT(dst.isReg(), "operand must be register");

    Value *src_val = M_READ<width>(ip, b, memAddr);

    Type *s[1] = { Type::getIntNTy(b->getContext(), width) };
    Function *cttzFn = Intrinsic::getDeclaration(b->getParent()->getParent(), Intrinsic::cttz, s);

    TASSERT(cttzFn != NULL, "Could not find cttz intrinsic");

    vector<Value*>  cttzArgs;
    cttzArgs.push_back(src_val);
    cttzArgs.push_back(CONST_V<1>(b, 0));
    Value *cttz = CallInst::Create(cttzFn, cttzArgs, "", b);


    Value *is_zero = new ICmpInst(
            *b,
            CmpInst::ICMP_EQ,
            CONST_V<width>(b, width),
            cttz);

    F_WRITE(b, ZF, is_zero);


    // See if we write to register
    Value *save_index = SelectInst::Create(
            is_zero, // check if the source was zero
            src_val, // if it was, do not change contents
            cttz,  // if it was not, set index
            "", b);

    R_WRITE<width>(b, dst.getReg(), save_index);

    return ContinueBlock;
}

template<int width>
static InstTransResult doBsfr(
        BasicBlock *&b, 
        const MCOperand &dst,
        const MCOperand &src)
{

    TASSERT(dst.isReg(), "operand must be register");
    TASSERT(src.isReg(), "operand must be register");

    Value *src_val = R_READ<width>(b, src.getReg());

    Type *s[1] = { Type::getIntNTy(b->getContext(), width) };
    Function *cttzFn = Intrinsic::getDeclaration(b->getParent()->getParent(), Intrinsic::cttz, s);

    TASSERT(cttzFn != NULL, "Could not find cttz intrinsic");

    vector<Value*>  cttzArgs;
    cttzArgs.push_back(src_val);
    cttzArgs.push_back(CONST_V<1>(b, 0));
    Value *cttz = CallInst::Create(cttzFn, cttzArgs, "", b);


    Value *is_zero = new ICmpInst(
            *b,
            CmpInst::ICMP_EQ,
            CONST_V<width>(b, width),
            cttz);

    F_WRITE(b, ZF, is_zero);


    // See if we write to register
    Value *save_index = SelectInst::Create(
            is_zero, // check if the source was zero
            src_val, // if it was, do not change contents
            cttz,  // if it was not, set index
            "", b);

    R_WRITE<width>(b, dst.getReg(), save_index);

    return ContinueBlock;
}


GENERIC_TRANSLATION(CDQ, doCdq(block))
GENERIC_TRANSLATION(INT3, doInt3(block))
GENERIC_TRANSLATION(TRAP, doTrap(block))
GENERIC_TRANSLATION(NOOP, doNoop(block))
GENERIC_TRANSLATION(HLT, doHlt(block))

GENERIC_TRANSLATION(BSWAP32r, doBswapR<32>(ip, block, OP(0)))

GENERIC_TRANSLATION(LAHF, doLAHF(block))
GENERIC_TRANSLATION(STD, doStd(block))
GENERIC_TRANSLATION(CLD, doCld(block))
GENERIC_TRANSLATION(STC, doStc(block))
GENERIC_TRANSLATION(CLC, doClc(block))

GENERIC_TRANSLATION_REF(LEA16r, 
	doLea<16>(ip, block, ADDR_NOREF(1), OP(0)),
	doLea<16>(ip, block, MEM_REFERENCE(1), OP(0))) 

template <int width>
static InstTransResult doLeaRef(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_code_ref() ) {
        Inst::CFGOpType optype;

        if(ip->has_mem_reference) {
            optype = Inst::MEMRef;
        } else if (ip->has_imm_reference) {
            optype = Inst::IMMRef;
        } else {
            throw TErr(__LINE__, __FILE__, "Have code ref but no reference");
        }

        Value *callback_fn = archMakeCallbackForLocalFunction(
                block->getParent()->getParent(), 
                ip->get_reference(optype));
        Value *addrInt = new PtrToIntInst(
            callback_fn, llvm::Type::getIntNTy(block->getContext(), width), "", block);
        ret = doLeaV<width>(block, OP(0), addrInt);
    } else if( ip->has_mem_reference ) {
        ret = doLea<width>(ip, block, MEM_REFERENCE(1), OP(0));
    }
    else if( ip->has_imm_reference ) {
        ret = doLea<width>(ip, block, IMM_AS_DATA_REF<width>(block, natM, ip), OP(0));
    } else { 
        ret = doLea<width>(ip, block, ADDR_NOREF(1), OP(0));
    }
    return ret;
}
static InstTransResult translate_LEA32r(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    return doLeaRef<32>(natM, block, ip, inst);
}

static InstTransResult translate_LEA64r(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    return doLeaRef<64>(natM, block, ip, inst);
}

static InstTransResult translate_LEA64_32r(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    return doLeaRef<32>(natM, block, ip, inst);
}

GENERIC_TRANSLATION(AAA, doAAA(block))
GENERIC_TRANSLATION(AAS, doAAS(block))
GENERIC_TRANSLATION(AAM8i8, doAAM(block))
GENERIC_TRANSLATION(AAD8i8, doAAD(block))
GENERIC_TRANSLATION(RDTSC, doRdtsc(block))
GENERIC_TRANSLATION(CWD, doCwd<16>(block))
GENERIC_TRANSLATION(CWDE, doCwd<32>(block))
GENERIC_TRANSLATION(CQO, doCwd<64>(block));

GENERIC_TRANSLATION(BT64rr, doBtrr<64>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT32rr, doBtrr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BT16rr, doBtrr<16>(block, OP(0), OP(1)))

GENERIC_TRANSLATION(BSR32rr, doBsrr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BSR16rr, doBsrr<16>(block, OP(0), OP(1)))
GENERIC_TRANSLATION(BSF32rr, doBsfr<32>(block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(BSF32rm,
        (doBsfrm<32>(ip, block, OP(0), ADDR_NOREF(1))),
        (doBsfrm<32>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION(BSF16rr, doBsfr<16>(block, OP(0), OP(1)))

void Misc_populateDispatchMap(DispatchMap &m) {
    m[X86::AAA] = translate_AAA;
    m[X86::AAS] = translate_AAS;
    m[X86::AAM8i8] = translate_AAM8i8;
    m[X86::AAD8i8] = translate_AAD8i8;
    m[X86::LEA16r] = translate_LEA16r;
    m[X86::LEA32r] = translate_LEA32r;
	m[X86::LEA64_32r] = translate_LEA64_32r;
	m[X86::LEA64r] = translate_LEA64r;
    m[X86::LAHF] = translate_LAHF;
    m[X86::STD] = translate_STD;
    m[X86::CLD] = translate_CLD;
    m[X86::STC] = translate_STC;
    m[X86::CLC] = translate_CLC;
    m[X86::BSWAP32r] = translate_BSWAP32r;
    m[X86::CDQ] = translate_CDQ;
    m[X86::INT3] = translate_INT3;
    m[X86::NOOP] = translate_NOOP;
    m[X86::NOOPW] = translate_NOOP;
    m[X86::NOOPL] = translate_NOOP;
    m[X86::HLT] = translate_HLT;
    m[X86::LOCK_PREFIX] = translate_NOOP;
    m[X86::REP_PREFIX] = translate_NOOP;
    m[X86::REPNE_PREFIX] = translate_NOOP;
    m[X86::PAUSE] = translate_NOOP;
    m[X86::RDTSC] = translate_RDTSC;
    m[X86::CWD] = translate_CWD;
    m[X86::CWDE] = translate_CWDE;
    m[X86::CQO] = translate_CQO;
    m[X86::CDQ] = translate_CDQ;
    m[X86::SAHF] = translate_SAHF;
    m[X86::BT64rr] = translate_BT64rr;
    m[X86::BT32rr] = translate_BT32rr;
    m[X86::BT16rr] = translate_BT16rr;
    m[X86::BSR32rr] = translate_BSR32rr;
    m[X86::BSR16rr] = translate_BSR16rr;
    m[X86::BSF32rr] = translate_BSF32rr;
    m[X86::BSF32rm] = translate_BSF32rm;
    m[X86::BSF16rr] = translate_BSF16rr;
    m[X86::TRAP] = translate_TRAP;
}
