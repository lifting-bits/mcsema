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
#include "x86Instrs_CMPTEST.h"
#include "x86Instrs_Exchanges.h"


#define NASSERT(cond) TASSERT(cond, "")

template <int width>
static InstTransResult doCmpxchgRR(InstPtr ip,    BasicBlock      *&b,
                            const MCOperand &dstReg,
                            const MCOperand &srcReg)
{
    NASSERT(dstReg.isReg());
    NASSERT(srcReg.isReg());


    Value   *acc;

    switch(width) {
        case 8:
            acc = R_READ<width>(b, X86::AL);
            break;
        case 16:
            acc = R_READ<width>(b, X86::AX);
            break;
        case 32:
            acc = R_READ<width>(b, X86::EAX);
            break;
        case 64:
            acc = R_READ<width>(b, X86::RAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    Value   *dstReg_v = R_READ<width>(b, dstReg.getReg());
    Value   *srcReg_v = R_READ<width>(b, srcReg.getReg());

    doCmpVV<width>(ip, b, acc, dstReg_v);

    Value   *Cmp = new ICmpInst(*b, CmpInst::ICMP_EQ, acc, dstReg_v);

    F_WRITE(b, ZF, Cmp);

    ///
    // ZF = Acc == DST
    // acc = select(ZF, acc, dst)
    // dst = select(ZF, src, dst)
    Value *new_acc = SelectInst::Create(Cmp, acc, dstReg_v, "", b);
    Value *new_dst = SelectInst::Create(Cmp, srcReg_v, dstReg_v, "", b);

    R_WRITE<width>(b, dstReg.getReg(), new_dst);

    switch(width) {
        case 8:
            R_WRITE<width>(b, X86::AL, new_acc);
            break;
        case 16:
            R_WRITE<width>(b, X86::AX, new_acc);
            break;
        case 32:
            R_WRITE<width>(b, X86::EAX, new_acc);
            break;
        case 64:
            R_WRITE<width>(b, X86::RAX, new_acc);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }


    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpxchgRM(InstPtr ip,    BasicBlock      *&b,
                            Value           *dstAddr,
                            const MCOperand &srcReg)
{
    NASSERT(dstAddr != NULL);
    NASSERT(srcReg.isReg());


    Value   *acc;

    switch(width) {
        case 8:
            acc = R_READ<width>(b, X86::AL);
            break;
        case 16:
            acc = R_READ<width>(b, X86::AX);
            break;
        case 32:
            acc = R_READ<width>(b, X86::EAX);
            break;
        case 64:
            acc = R_READ<width>(b, X86::RAX);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }

    //Value   *mem_v = M_READ<width>(ip, b, dstAddr);
    Value   *m_addr = NULL;

    unsigned addrspace = ip->get_addr_space();

    if( dstAddr->getType()->isPointerTy() == false ) {
		llvm::Type    *ptrTy =
            Type::getIntNPtrTy(b->getContext(), width, addrspace);
        m_addr = new llvm::IntToPtrInst(dstAddr, ptrTy, "", b);
	}
    else if( dstAddr->getType() != Type::getIntNPtrTy(
                b->getContext(), width, addrspace) )
    {
		//we need to bitcast the pointer value to a pointer type of the appropriate width
		m_addr = CastInst::CreatePointerCast(dstAddr,
                Type::getIntNPtrTy(b->getContext(), width, addrspace), "", b);
	} else {
        m_addr = dstAddr;
    }

    Value   *srcReg_v = R_READ<width>(b, srcReg.getReg());


    AtomicCmpXchgInst *cmpx = new AtomicCmpXchgInst(
            m_addr,
            acc,
            srcReg_v,
            llvm::SequentiallyConsistent,
            llvm::SequentiallyConsistent,
            llvm::CrossThread,
            b);
    cmpx->setVolatile(true);

    Value *cmpx_val = ExtractValueInst::Create(cmpx, 0, "cmpxchg_cmpx_val", b);
    Value *was_eq = ExtractValueInst::Create(cmpx, 1, "cmpxchg_was_eq", b);

    doCmpVV<width>(ip, b, acc, cmpx_val);


    F_WRITE(b, ZF, was_eq);

    Value *new_acc = SelectInst::Create(was_eq, acc, cmpx_val, "", b);

    switch(width) {
        case 8:
            R_WRITE<width>(b, X86::AL, new_acc);
            break;
        case 16:
            R_WRITE<width>(b, X86::AX, new_acc);
            break;
        case 32:
            R_WRITE<width>(b, X86::EAX, new_acc);
            break;
        case 64:
            R_WRITE<width>(b, X86::RAX, new_acc);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Width not supported");
    }


    return ContinueBlock;
}

template <int width>
static InstTransResult doXaddRM(InstPtr ip,    BasicBlock *&b,
                            const MCOperand &srcReg,
                            Value           *dstAddr)
{
    NASSERT(srcReg.isReg());
    NASSERT(dstAddr != NULL);

    Value   *reg_v = R_READ<width>(b, srcReg.getReg());
    Value   *mem_v = M_READ<width>(ip, b, dstAddr);

    Value   *res = BinaryOperator::CreateAdd(reg_v, mem_v, "", b);

    M_WRITE<width>(ip, b, dstAddr, res);
    R_WRITE<width>(b, srcReg.getReg(), mem_v);

    //write the flag updates
    //compute AF
    WriteAFAddSub<width>(b, res, mem_v, reg_v);
    //compute SF
    WriteSF<width>(b, res);
    //compute ZF
    WriteZF<width>(b, res);
    //compute OF
    WriteOFAdd<width>(b, res, mem_v, reg_v);
    //compute PF
    WritePF<width>(b, res);
    //compute CF*/
    WriteCFAdd<width>(b, res, mem_v);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXaddRR(InstPtr ip,    BasicBlock *&b,
                            const MCOperand &dstReg,
                            const MCOperand &srcReg)
{
    NASSERT(dstReg.isReg());
    NASSERT(srcReg.isReg());

    Value   *dstReg_v = R_READ<width>(b, dstReg.getReg());
    Value   *srcReg_v = R_READ<width>(b, srcReg.getReg());

    Value   *res = BinaryOperator::CreateAdd(dstReg_v, srcReg_v, "", b);

    R_WRITE<width>(b, dstReg.getReg(), res);
    R_WRITE<width>(b, srcReg.getReg(), dstReg_v);

    //write the flag updates
    //compute AF
    WriteAFAddSub<width>(b, res, dstReg_v, srcReg_v);
    //compute SF
    WriteSF<width>(b, res);
    //compute ZF
    WriteZF<width>(b, res);
    //compute OF
    WriteOFAdd<width>(b, res, dstReg_v, srcReg_v);
    //compute PF
    WritePF<width>(b, res);
    //compute CF*/
    WriteCFAdd<width>(b, res, dstReg_v);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXchgRR(InstPtr ip,    BasicBlock *&b,
                            const MCOperand &o1,
                            const MCOperand &o2)
{
    NASSERT(o1.isReg());
    NASSERT(o2.isReg());

    Value   *t1 = R_READ<width>(b, o1.getReg());
    Value   *t2 = R_READ<width>(b, o2.getReg());

    R_WRITE<width>(b, o2.getReg(), t1);
    R_WRITE<width>(b, o1.getReg(), t2);

    return ContinueBlock;
}

template <int width>
static InstTransResult doXchgRM(InstPtr ip,    BasicBlock *&b,
                            const MCOperand     &r,
                            Value               *mem)
{
    NASSERT(mem != NULL);
    NASSERT(r.isReg());

    Value   *t1 = R_READ<width>(b, r.getReg());
    Value   *t2 = M_READ<width>(ip, b, mem);

    R_WRITE<width>(b, r.getReg(), t2);
    M_WRITE<width>(ip, b, mem, t1);

    return ContinueBlock;
}

GENERIC_TRANSLATION_REF(CMPXCHG16rm,
	doCmpxchgRM<16>(ip, block, ADDR_NOREF(0), OP(5)),
	doCmpxchgRM<16>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(CMPXCHG16rr, doCmpxchgRR<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(CMPXCHG32rm,
	doCmpxchgRM<32>(ip, block, ADDR_NOREF(0), OP(5)),
	doCmpxchgRM<32>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(CMPXCHG64rm,
	doCmpxchgRM<64>(ip, block, ADDR_NOREF(0), OP(5)),
	doCmpxchgRM<64>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(CMPXCHG32rr, doCmpxchgRR<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMPXCHG64rr, doCmpxchgRR<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(CMPXCHG8rm,
	doCmpxchgRM<8>(ip, block, ADDR_NOREF(0), OP(5)),
	doCmpxchgRM<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(CMPXCHG8rr, doCmpxchgRR<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(XADD16rm,
	doXaddRM<16>(ip, block, OP(5), ADDR_NOREF(0)),
	doXaddRM<16>(ip, block, OP(5), MEM_REFERENCE(0)))
GENERIC_TRANSLATION(XADD16rr, doXaddRR<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(XADD32rm,
	doXaddRM<32>(ip, block, OP(5), ADDR_NOREF(0)),
	doXaddRM<32>(ip, block, OP(5), MEM_REFERENCE(0)))
GENERIC_TRANSLATION_REF(XADD64rm,
	 doXaddRM<64>(ip, block, OP(5), ADDR_NOREF(0)),
	 doXaddRM<64>(ip, block, OP(5), MEM_REFERENCE(0)))
GENERIC_TRANSLATION(XADD32rr, doXaddRR<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(XADD64rr, doXaddRR<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(XADD8rm,
	doXaddRM<8>(ip, block, OP(5), ADDR_NOREF(0)),
	doXaddRM<8>(ip, block, OP(5), MEM_REFERENCE(0)))
GENERIC_TRANSLATION(XADD8rr, doXaddRR<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(XCHG16ar, doXchgRR<16>(ip, block, MCOperand::CreateReg(X86::AL), OP(0)))
GENERIC_TRANSLATION_REF(XCHG16rm,
	doXchgRM<16>(ip,  block, OP(0), ADDR_NOREF(2)),
	doXchgRM<16>(ip,  block, OP(0), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XCHG16rr, doXchgRR<16>(ip, block, OP(1), OP(2)))
GENERIC_TRANSLATION(XCHG32ar, doXchgRR<32>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION(XCHG32ar64, doXchgRR<64>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION(XCHG64ar, doXchgRR<64>(ip, block, MCOperand::CreateReg(X86::RAX), OP(0)))
GENERIC_TRANSLATION_REF(XCHG32rm,
	doXchgRM<32>(ip,  block, OP(0), ADDR_NOREF(2)),
	doXchgRM<32>(ip,  block, OP(0), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XCHG32rr, doXchgRR<32>(ip, block, OP(1), OP(2)))
GENERIC_TRANSLATION(XCHG64rr, doXchgRR<64>(ip, block, OP(1), OP(2)))
GENERIC_TRANSLATION_REF(XCHG8rm,
	doXchgRM<8>(ip,   block, OP(0), ADDR_NOREF(2)),
	doXchgRM<8>(ip,   block, OP(0), MEM_REFERENCE(2)))
GENERIC_TRANSLATION(XCHG8rr, doXchgRR<8>(ip, block, OP(1), OP(2)))

void Exchanges_populateDispatchMap(DispatchMap &m) {

        m[X86::CMPXCHG16rm] = translate_CMPXCHG16rm;
        m[X86::CMPXCHG16rr] = translate_CMPXCHG16rr;
        m[X86::CMPXCHG32rm] = translate_CMPXCHG32rm;
        m[X86::CMPXCHG64rm] = translate_CMPXCHG64rm;
        m[X86::CMPXCHG32rr] = translate_CMPXCHG32rr;
        m[X86::CMPXCHG64rr] = translate_CMPXCHG64rr;
        m[X86::CMPXCHG8rm] = translate_CMPXCHG8rm;
        m[X86::CMPXCHG8rr] = translate_CMPXCHG8rr;
        m[X86::XADD16rm] = translate_XADD16rm;
        m[X86::XADD16rr] = translate_XADD16rr;
        m[X86::XADD32rm] = translate_XADD32rm;
        m[X86::XADD64rm] = translate_XADD64rm;
        m[X86::XADD32rr] = translate_XADD32rr;
        m[X86::XADD64rr] = translate_XADD64rr;
        m[X86::XADD8rm] = translate_XADD8rm;
        m[X86::XADD8rr] = translate_XADD8rr;
        m[X86::XCHG16ar] = translate_XCHG16ar;
        m[X86::XCHG16rm] = translate_XCHG16rm;
        m[X86::XCHG16rr] = translate_XCHG16rr;
        m[X86::XCHG32ar] = translate_XCHG32ar;
        m[X86::XCHG32ar64] = translate_XCHG32ar64;
        m[X86::XCHG64ar] = translate_XCHG64ar;
        m[X86::XCHG32rm] = translate_XCHG32rm;
        m[X86::XCHG64rr] = translate_XCHG64rr;
        m[X86::XCHG32rr] = translate_XCHG32rr;
        m[X86::XCHG8rm] = translate_XCHG8rm;
        m[X86::XCHG8rr] = translate_XCHG8rr;
}
