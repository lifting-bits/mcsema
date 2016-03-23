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
#include "llvm/Support/Debug.h"

#define NASSERT(cond) TASSERT(cond, "")
#define INSTR_DEBUG(ip) llvm::dbgs() << __FUNCTION__ << "\tRepresentation: " << ip->printInst() << "\n"

using namespace llvm;


template <int width>
static InstTransResult doCmpRR(InstPtr ip, BasicBlock *&b,
                        const MCOperand &lhs,
                        const MCOperand &rhs)
{
    NASSERT(lhs.isReg());
    NASSERT(rhs.isReg());

    Value   *lhs_v = R_READ<width>(b, lhs.getReg());
    Value   *rhs_v = R_READ<width>(b, rhs.getReg());

    doCmpVV<width>(ip, b, lhs_v, rhs_v);

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpRI(InstPtr ip, BasicBlock *&b,
                        const MCOperand &lhs,
                        const MCOperand &rhs)
{
    NASSERT(lhs.isReg());
    NASSERT(rhs.isImm());

    Value   *lhs_v = R_READ<width>(b, lhs.getReg());
    Value   *rhs_v = CONST_V<width>(b, rhs.getImm());

    doCmpVV<width>(ip, b, lhs_v, rhs_v);

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpRV(InstPtr ip, BasicBlock *&b,
                        const MCOperand &lhs,
                        llvm::Value *rhs)
{
    NASSERT(lhs.isReg());

    Value   *lhs_v = R_READ<width>(b, lhs.getReg());
    Value   *rhs_v = rhs;

    doCmpVV<width>(ip, b, lhs_v, rhs_v);

    return ContinueBlock;
}


template <int width>
static InstTransResult doCmpMR(InstPtr ip, BasicBlock *&b,
                        Value           *mem,
                        const MCOperand &reg)
{
    NASSERT(reg.isReg());
    NASSERT(mem!=NULL);

    //do a read from the register
    Value   *r = R_READ<width>(b, reg.getReg());

    //do a load from memory
    Value   *m = M_READ<width>(ip, b, mem);

    //do the compare
    doCmpVV<width>(ip, b, m, r);

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpRM(InstPtr ip, BasicBlock *&b,
                        const MCOperand &reg,
                        Value           *mem)
{
    NASSERT(reg.isReg());
    NASSERT(mem!=NULL);

    //do a read from the register
    Value   *r = R_READ<width>(b, reg.getReg());

    //do a load from memory
    Value   *m = M_READ<width>(ip, b, mem);

    //do the compare
    doCmpVV<width>(ip, b, r, m);

    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpMI(InstPtr ip, BasicBlock *&b,
                        Value           *r1,
                        const MCOperand &r2)
{
    NASSERT(r1 != NULL);
    NASSERT(r2.isImm());
    
    //read the value from memory
    Value   *fromMem = M_READ<width>(ip, b, r1);
    Value   *constPart = CONST_V<width>(b, r2.getImm());

    doCmpVV<width>(ip, b, fromMem, constPart);
  
    return ContinueBlock;
}

template <int width>
static InstTransResult doCmpMV(InstPtr ip, BasicBlock *&b,
                        Value           *r1,
                        Value           *rhs)
{
    NASSERT(r1 != NULL);
    NASSERT(rhs != NULL);
    
    //read the value from memory
    Value   *fromMem = M_READ<width>(ip, b, r1);

    doCmpVV<width>(ip, b, fromMem, rhs);
  
    return ContinueBlock;
}

template <int width>
static void doTestVV(InstPtr ip, BasicBlock *&b, Value *lhs, Value *rhs) {

	Value	*temp = BinaryOperator::CreateAnd(lhs, rhs, "", b);


	//test to see if temp is 0
	Value	*cmpRes = new ICmpInst(*b, CmpInst::ICMP_EQ, temp, CONST_V<width>(b, 0));
	NASSERT(cmpRes != NULL);

    F_WRITE(b, ZF, cmpRes);

	//set SF here
	Value	*msb = 
		new TruncInst(	BinaryOperator::CreateLShr(temp, CONST_V<width>(b, width-1),"",b), 
						Type::getInt1Ty(b->getContext()), "", b);
	F_WRITE(b, SF, msb);


    WritePF<width>(b, temp);

    Value   *pfVal = F_READ(b, PF);
    Value   *xV = 
        BinaryOperator::CreateXor(CONST_V<1>(b, 0), pfVal, "", b);
    Value   *aV = 
        BinaryOperator::CreateAnd(CONST_V<1>(b, 1), xV, "", b);
    F_WRITE(b, PF, aV);

	F_CLEAR(b, CF);
	F_CLEAR(b, OF);

	return;
}

template <int width>
static InstTransResult doTestMI(InstPtr ip,    BasicBlock      *&b,
                            Value           *lhs,
                            const MCOperand &rhs) 
{
    NASSERT(lhs != NULL);
    NASSERT(rhs.isImm());

    doTestVV<width>(ip, b,
                    M_READ<width>(ip, b, lhs),
                    CONST_V<width>(b, rhs.getImm()));

    return EndBlock;
}

template <int width>
static InstTransResult doTestMV(InstPtr ip,    BasicBlock      *&b,
                            Value           *lhs,
                            Value           *rhs)
{
    NASSERT(lhs != NULL);
    NASSERT(rhs != NULL);

    doTestVV<width>(ip, b,
                    M_READ<width>(ip, b, lhs),
                    rhs);

    return EndBlock;
}

template <int width>
static InstTransResult doTestRM(InstPtr ip,    BasicBlock      *&b,
                            const MCOperand &lhs,
                            Value           *rhs)
{
    NASSERT(rhs != NULL);
    NASSERT(lhs.isReg());

    doTestVV<width>(ip, b,
                    R_READ<width>(b, lhs.getReg()),
                    M_READ<width>(ip, b, rhs));

    return EndBlock;
}

template <int width>
static InstTransResult doTestRR(InstPtr ip, 	BasicBlock		*&b,
							const MCOperand	&lhs,
							const MCOperand &rhs)
{
	NASSERT(lhs.isReg());
	NASSERT(rhs.isReg());

	doTestVV<width>(ip, b, 
					R_READ<width>(b, lhs.getReg()),
					R_READ<width>(b, rhs.getReg()));	

	return EndBlock;
}

template <int width>
static InstTransResult doTestRI(InstPtr ip,    BasicBlock          *&b,
                            const MCOperand     &lhs,
                            const MCOperand     &rhs)
{
    NASSERT(lhs.isReg());
    NASSERT(rhs.isImm());

    doTestVV<width>(ip, b,
                    R_READ<width>(b, lhs.getReg()),
                    CONST_V<width>(b, rhs.getImm()));

    return EndBlock;
}

template <int width>
static InstTransResult doTestRV(InstPtr ip,    BasicBlock          *&b,
                            const MCOperand     &lhs,
                            llvm::Value     *rhs)
{
    NASSERT(lhs.isReg());

    doTestVV<width>(ip, b,
                    R_READ<width>(b, lhs.getReg()),
                    rhs);

    return EndBlock;
}

GENERIC_TRANSLATION(CMP8rr, doCmpRR<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP16rr, doCmpRR<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP16rr_REV, doCmpRR<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP16ri, doCmpRI<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP16ri8, doCmpRI<16>(ip, block, OP(0), OP(1)))

//GENERIC_TRANSLATION(CMP32i32, doCmpRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(CMP32i32,
    doCmpRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)),
    doCmpRV<32>(ip, block, MCOperand::CreateReg(X86::EAX), IMM_AS_DATA_REF(block, natM, ip)));

//GENERIC_TRANSLATION(CMP64i32, doCmpRI<64>(ip, block, MCOperand::CreateReg(X86::RAX), OP(0)))
GENERIC_TRANSLATION_REF(CMP64i32,
    doCmpRI<64>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)),
    doCmpRV<64>(ip, block, MCOperand::CreateReg(X86::EAX), IMM_AS_DATA_REF(block, natM, ip)));

GENERIC_TRANSLATION(CMP16i16, doCmpRI<16>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION(CMP32rr_REV, doCmpRR<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP32rr, doCmpRR<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP64rr, doCmpRR<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP32ri, doCmpRI<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP64ri, doCmpRI<64>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION(CMP8ri, doCmpRI<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(CMP8i8, doCmpRI<8>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION(CMP8rr_REV, doCmpRR<8>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION(CMP32ri8, doCmpRI<32>(ip, block, OP(0), OP(1)))

//GENERIC_TRANSLATION(CMP64ri32, doCmpRI<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(CMP64ri32,
    doCmpRI<64>(ip, block, OP(0), OP(1)),
    doCmpRV<64>(ip, block, OP(0), IMM_AS_DATA_REF(block, natM, ip)));

GENERIC_TRANSLATION(CMP64ri8, doCmpRI<64>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(CMP64mi8,
    doCmpMI<64>(ip,   block, ADDR_NOREF(0), OP(5)),
    doCmpMI<64>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_MI(CMP64mi32, 
	doCmpMI<64>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMI<64>(ip,   block, MEM_REFERENCE(0), OP(5)),
    doCmpMV<64>(ip,   block, ADDR_NOREF(0), IMM_AS_DATA_REF<64>(block, natM, ip)),
    doCmpMV<64>(ip,   block, MEM_REFERENCE(0), IMM_AS_DATA_REF<64>(block, natM, ip)))
GENERIC_TRANSLATION_REF(CMP32mi8,
	doCmpMI<32>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMI<32>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(CMP8mi, 
	doCmpMI<8>(ip,    block, ADDR_NOREF(0), OP(5)),
	doCmpMI<8>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(CMP16mi, 
	doCmpMI<16>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMI<16>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(CMP16mi8, 
	doCmpMI<16>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMI<16>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_MI(CMP32mi, 
	doCmpMI<32>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMI<32>(ip,   block, MEM_REFERENCE(0), OP(5)),
    doCmpMV<32>(ip,   block, ADDR_NOREF(0), IMM_AS_DATA_REF<32>(block, natM, ip)),
    doCmpMV<32>(ip,   block, MEM_REFERENCE(0), IMM_AS_DATA_REF<32>(block, natM, ip)))

GENERIC_TRANSLATION_REF(CMP8rm, 
	doCmpRM<8>(ip,    block, OP(0), ADDR_NOREF(1)),
	doCmpRM<8>(ip,    block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION_REF(CMP16rm, 
	doCmpRM<16>(ip,   block, OP(0), ADDR_NOREF(1)),
	doCmpRM<16>(ip,   block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION_REF(CMP32rm, 
	doCmpRM<32>(ip,   block, OP(0), ADDR_NOREF(1)),
	doCmpRM<32>(ip,   block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION_REF(CMP8mr, 
	doCmpMR<8>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMR<8>(ip,   block, MEM_REFERENCE(0), OP(5))) 
GENERIC_TRANSLATION_REF(CMP16mr, 
	doCmpMR<16>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMR<16>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(CMP32mr, 
	doCmpMR<32>(ip,   block, ADDR_NOREF(0), OP(5)),
	doCmpMR<32>(ip,   block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(CMP64rm,
  doCmpRM<64>(ip,   block, OP(0), ADDR_NOREF(1)),
  doCmpRM<64>(ip,   block, OP(0), MEM_REFERENCE(1)))

GENERIC_TRANSLATION_REF(CMP64mr,
  doCmpMR<64>(ip,   block, ADDR_NOREF(0), OP(5)),
  doCmpMR<64>(ip,   block, MEM_REFERENCE(0), OP(5)))


GENERIC_TRANSLATION(TEST32rr, doTestRR<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(TEST64rr, doTestRR<64>(ip, block, OP(0), OP(1)))
//there is a form of the encoding where the EAX operand is 
//implicit
//GENERIC_TRANSLATION(TEST64i32, doTestRI<64>(ip,  block, MCOperand::CreateReg(X86::RAX), OP(0)))
GENERIC_TRANSLATION_REF(TEST64i32,
    doTestRI<64>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)),
    doTestRV<64>(ip, block, MCOperand::CreateReg(X86::EAX), IMM_AS_DATA_REF(block, natM, ip)));

//GENERIC_TRANSLATION(TEST32i32, doTestRI<32>(ip,  block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(TEST32i32,
    doTestRI<32>(ip, block, MCOperand::CreateReg(X86::EAX), OP(0)),
    doTestRV<32>(ip, block, MCOperand::CreateReg(X86::EAX), IMM_AS_DATA_REF(block, natM, ip)));

//GENERIC_TRANSLATION(TEST64ri32, doTestRI<64>(ip,  block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(TEST64ri32,
    doTestRI<64>(ip, block, OP(0), OP(1)),
    doTestRV<64>(ip, block, OP(0), IMM_AS_DATA_REF(block, natM, ip)));

GENERIC_TRANSLATION(TEST32ri, doTestRI<32>(ip,  block, OP(0), OP(1)))
GENERIC_TRANSLATION(TEST16i16, doTestRI<16>(ip,  block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(TEST16mi, 
	doTestMI<16>(ip,  block, ADDR_NOREF(0), OP(5)),
	doTestMI<16>(ip,  block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(TEST16ri, doTestRI<16>(ip,  block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(TEST16rm, 
	doTestRM<16>(ip,  block, OP(0), ADDR_NOREF(1)),
	doTestRM<16>(ip,  block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION(TEST16rr, doTestRR<16>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION_MI(TEST32mi, 
	doTestMI<32>(ip, block, ADDR_NOREF(0), OP(5)),
	doTestMI<32>(ip, block, MEM_REFERENCE(0), OP(5)),
    doTestMV<32>(ip,  block, ADDR_NOREF(0), IMM_AS_DATA_REF<32>(block, natM, ip)),
    doTestMV<32>(ip,  block, MEM_REFERENCE(0), IMM_AS_DATA_REF<32>(block, natM, ip)))

GENERIC_TRANSLATION_REF(TEST64rm,
	doTestRM<64>(ip,  block, OP(0), ADDR_NOREF(1)),
	doTestRM<64>(ip,  block, OP(0), MEM_REFERENCE(1)))

GENERIC_TRANSLATION_REF(TEST32rm, 
	doTestRM<32>(ip,  block, OP(0), ADDR_NOREF(1)),
	doTestRM<32>(ip,  block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION(TEST8i8, doTestRI<8>(ip,   block, MCOperand::CreateReg(X86::EAX), OP(0)))
GENERIC_TRANSLATION_REF(TEST8mi, 
	doTestMI<8>(ip, block, ADDR_NOREF(0), OP(5)),
	doTestMI<8>(ip, block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION(TEST8ri, doTestRI<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(TEST8ri_NOREX, doTestRI<8>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION_REF(TEST8rm, 
	doTestRM<8>(ip, block, OP(0), ADDR_NOREF(1)),
	doTestRM<8>(ip, block, OP(0), MEM_REFERENCE(1)))
GENERIC_TRANSLATION(TEST8rr, doTestRR<8>(ip, block, OP(0), OP(1)))

void CMPTEST_populateDispatchMap(DispatchMap &m) {

    m[X86::CMP8rr] = translate_CMP8rr;
    m[X86::CMP8rr_REV] = translate_CMP8rr_REV;
    m[X86::CMP16rr] = translate_CMP16rr;
    m[X86::CMP16rr_REV] = translate_CMP16rr_REV;
    m[X86::CMP32rr_REV] = translate_CMP32rr_REV;
    m[X86::CMP32rr] = translate_CMP32rr;
    m[X86::CMP64rr] = translate_CMP64rr;

    m[X86::CMP8ri] = translate_CMP8ri;
    m[X86::CMP8i8] = translate_CMP8i8;
    m[X86::CMP16ri] = translate_CMP16ri;
    m[X86::CMP16ri8] = translate_CMP16ri8;
    m[X86::CMP16i16] = translate_CMP16i16;
    m[X86::CMP32i32] = translate_CMP32i32;
    m[X86::CMP32ri] = translate_CMP32ri;
    m[X86::CMP32ri8] = translate_CMP32ri8;
    m[X86::CMP64ri32] = translate_CMP64ri32;
    m[X86::CMP64ri8] = translate_CMP64ri8;
    m[X86::CMP64i32] = translate_CMP64i32;

    m[X86::CMP32mi8] = translate_CMP32mi8;
    m[X86::CMP8mi] = translate_CMP8mi;
    m[X86::CMP16mi] = translate_CMP16mi;
    m[X86::CMP32mi] = translate_CMP32mi;
    m[X86::CMP8rm] = translate_CMP8rm;
    m[X86::CMP16rm] = translate_CMP16rm;
    m[X86::CMP32rm] = translate_CMP32rm;
    m[X86::CMP8mr] = translate_CMP8mr;
    m[X86::CMP16mr] = translate_CMP16mr;
    m[X86::CMP32mr] = translate_CMP32mr;
    m[X86::CMP16mi8] = translate_CMP16mi8;

    m[X86::CMP64mi8] = translate_CMP64mi8;
    m[X86::CMP64mi32] = translate_CMP64mi32;
    m[X86::CMP64rm] = translate_CMP64rm;
    m[X86::CMP64mr] = translate_CMP64mr;

	m[X86::TEST64ri32] = translate_TEST64ri32;
	m[X86::TEST64i32] = translate_TEST64i32;
	m[X86::TEST64rm] = translate_TEST64rm;
	m[X86::TEST64rr] = translate_TEST64rr;
    m[X86::TEST32rr] = translate_TEST32rr;
    m[X86::TEST32i32] = translate_TEST32i32;
    m[X86::TEST32ri] = translate_TEST32ri;
    m[X86::TEST16i16] = translate_TEST16i16;
    m[X86::TEST16mi] = translate_TEST16mi;
    m[X86::TEST16ri] = translate_TEST16ri;
    m[X86::TEST16rm] = translate_TEST16rm;
    m[X86::TEST16rr] = translate_TEST16rr;
    m[X86::TEST32mi] = translate_TEST32mi;
    m[X86::TEST32rm] = translate_TEST32rm;
    m[X86::TEST8i8] = translate_TEST8i8;
    m[X86::TEST8mi] = translate_TEST8mi;
    m[X86::TEST8ri] = translate_TEST8ri;
    m[X86::TEST8ri_NOREX] = translate_TEST8ri_NOREX;
    m[X86::TEST8rm] = translate_TEST8rm;
    m[X86::TEST8rr] = translate_TEST8rr;
}
