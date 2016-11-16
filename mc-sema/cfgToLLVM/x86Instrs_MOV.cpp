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
#include "JumpTables.h"
#include "Externals.h"
#include "ArchOps.h"
#include "win64ArchOps.h"
#include "llvm/Support/Debug.h"

#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;

template <int width>
static Value* getSegmentValue(BasicBlock *&b, unsigned sreg) {

    Value *val = NULL;

    switch(sreg)
    {
        case X86::SS:
            val = CONST_V<width>(b, 0x23);
            break;
        case X86::CS:
            val = CONST_V<width>(b, 0x1B);
            break;
        case X86::DS:
            val = CONST_V<width>(b, 0x23);
            break;
        case X86::ES:
            val = CONST_V<width>(b, 0x23);
            break;
        case X86::FS:
            val = CONST_V<width>(b, 0x3B);
            break;
        case X86::GS:
            val = CONST_V<width>(b, 0x00);
            break;
        default:
            throw TErr(__LINE__, __FILE__, "Unknown Segment Register");
            break;
    }

    return val;

}

template <int width>
static InstTransResult doMSMov(InstPtr ip, BasicBlock *&b,
                        Value           *dstAddr,
                        const MCOperand &src)
{
    NASSERT(dstAddr != NULL);
    NASSERT(src.isReg());

    Value *seg_val = getSegmentValue<width>(b, src.getReg());

    M_WRITE<width>(ip, b, dstAddr, seg_val);

    return ContinueBlock;
}

template <int width>
static InstTransResult doSMMov(InstPtr ip, BasicBlock *&b,
                        Value           *dstAddr,
                        const MCOperand &src)
{
    NASSERT(dstAddr != NULL);
    NASSERT(src.isReg());

    Value *seg_val = getSegmentValue<width>(b, src.getReg());

	M_WRITE<width>(ip, b, dstAddr, seg_val);

    return ContinueBlock;
}

template <int width>
static InstTransResult doRSMov(InstPtr ip,   BasicBlock *&b,
                            const MCOperand &dst,
                            const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());

    Value *seg_val = getSegmentValue<width>(b, src.getReg());

	R_WRITE<width>(b, dst.getReg(), seg_val);

    return ContinueBlock;
}

template <int dstWidth>
static Value *doMovSXV(InstPtr ip, BasicBlock * b, Value *src) {
	// do an SX
	return new SExtInst(src, Type::getIntNTy(b->getContext(), dstWidth), "", b);
}

template <int width>
static InstTransResult doRIMovV(InstPtr ip,
                        BasicBlock *&b,
                        Value *src,
                        const MCOperand &dst)
{
    //MOV <r>, <imm>
    NASSERT(src != NULL);
    NASSERT(dst.isReg());

    //write the constant into the supplied register
	R_WRITE<width>(b, dst.getReg(), src);

    return ContinueBlock;
}

template <int width>
static InstTransResult doRIMov(InstPtr ip, BasicBlock *&b,
                        const MCOperand &src,
                        const MCOperand &dst)
{
    //MOV <r>, <imm>
    NASSERT(src.isImm());
    NASSERT(dst.isReg());

    //write the constant into the supplied register
	R_WRITE<width>(b, dst.getReg(), CONST_V<width>(b, src.getImm()));

    return ContinueBlock;
}

template <int width>
static InstTransResult doMIMovV(InstPtr ip, BasicBlock *&b,
                        Value           *dstAddr,
                        Value           *src)
{
    //MOV <m>, <imm>
    //store the constant in src into dstAddr

    M_WRITE<width>(ip, b, dstAddr, src);

    return ContinueBlock;
}

template <int width>
static InstTransResult doMIMov(InstPtr ip, BasicBlock *&b,
                        Value           *dstAddr,
                        const MCOperand &src)
{
    //MOV <m>, <imm>
    //store the constant in src into dstAddr
    NASSERT(dstAddr != NULL);
    NASSERT(src.isImm());

    return doMIMovV<width>(ip, b, dstAddr, CONST_V<width>(b, src.getImm()));
}

template <int dstWidth, int srcWidth>
static InstTransResult doMIMov(InstPtr ip, BasicBlock *&b,
                        Value           *dstAddr,
                        const MCOperand &src)
{
    //MOV <m>, <imm>
    //store the constant in src into dstAddr
    NASSERT(dstAddr != NULL);
    NASSERT(src.isImm());
	INSTR_DEBUG(ip);
    return doMIMovV<dstWidth>(ip, b, dstAddr, CONST_V<srcWidth>(b, src.getImm()));
}

template <int dstWidth, int srcWidth>
static InstTransResult doMovZXRR(InstPtr ip,   BasicBlock *&b,
                            const MCOperand &dst,
                            const MCOperand &src)
{
    NASSERT(dst.isReg());
    NASSERT(src.isReg());
    TASSERT(dstWidth > srcWidth, "Must ZExt to a greater bitwidth")

    //do a read from src of the appropriate width
    Value   *fromSrc = R_READ<srcWidth>(b, src.getReg());

    //extend
    Type    *toT = Type::getIntNTy(b->getContext(), dstWidth);
    Value   *xt = new ZExtInst(fromSrc, toT, "", b);

    //write into dst
	R_WRITE<dstWidth>(b, dst.getReg(), xt);

    return ContinueBlock;
}

template <int dstWidth, int srcWidth>
static InstTransResult doMovZXRM(InstPtr ip,   BasicBlock *&b,
                            const MCOperand &dst,
                            Value *src)
{
    NASSERT(dst.isReg());
	NASSERT(src != NULL);

    if( dstWidth == 32 &&
        srcWidth == 8 &&
        ip->has_jump_index_table())
    {
       doJumpIndexTableViaSwitch(b, ip);
       return ContinueBlock;
    }

    TASSERT(dstWidth > srcWidth, "Must ZExt to a greater bitwidth")
    //do a read from src of the appropriate width
    Value   *fromSrc = M_READ<srcWidth>(ip, b, src);

    //extend
    Type    *toT = Type::getIntNTy(b->getContext(), dstWidth);
    Value   *xt = new ZExtInst(fromSrc, toT, "", b);

    //write into dst
	R_WRITE<dstWidth>(b, dst.getReg(), xt);

    return ContinueBlock;
}

template<int dstWidth, int srcWidth>
static InstTransResult doMovSXRR(InstPtr ip, 	BasicBlock *&b,
							const MCOperand	&dst,
							const MCOperand &src)
{
	NASSERT(dst.isReg());
	NASSERT(src.isReg());

	Value *regOp;

	regOp = R_READ<srcWidth>(b, src.getReg());

	Value	*r = doMovSXV<dstWidth>(ip, b, regOp);

	R_WRITE<dstWidth>(b, dst.getReg(), r);

	return ContinueBlock;
}

template <int dstWidth, int srcWidth>
static InstTransResult doMovSXRM(InstPtr ip, 	BasicBlock *&b,
							const MCOperand	&dst,
							Value			*src)
{
	NASSERT(dst.isReg());
	NASSERT(src != NULL);

	Value	*r = doMovSXV<dstWidth>(ip, b, M_READ<srcWidth>(ip, b, src));

	R_WRITE<dstWidth>(b, dst.getReg(), r);

	return ContinueBlock;
}

template <int dstWidth, int srcWidth>
static InstTransResult doMovSMR(InstPtr ip, 	BasicBlock *&b,
							Value			*memAddr,
							const MCOperand	&dest)
{
	NASSERT(dest.isReg());
	NASSERT(memAddr != NULL);

  throw TErr(__LINE__, __FILE__, "NIY");

	return ContinueBlock;
}

GENERIC_TRANSLATION(MOV8rr, doRRMov<8>(ip, block, OP(0), OP(1)) )
GENERIC_TRANSLATION(MOV8rr_REV, doRRMov<8>(ip, block, OP(0), OP(1)) )
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

GENERIC_TRANSLATION_REF(MOV8mi,
	doMIMov<8>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMIMov<8>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV16mi,
	doMIMov<16>(ip,   block, ADDR_NOREF(0), OP(5)),
	doMIMov<16>(ip,   block, MEM_REFERENCE(0), OP(5)))

//GENERIC_TRANSLATION_32MI(MOV32mi,
//	doMIMov<32>(ip,   block, ADDR_NOREF(0), OP(5)),
//	doMIMov<32>(ip,   block, MEM_REFERENCE(0), OP(5)),
//    doMIMovV<32>(ip,  block, ADDR_NOREF(0), IMM_AS_DATA_REF(block, natM, ip))
//    )
//
static InstTransResult translate_MOV32mi(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_code_ref() ) {
        Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
        if( ip->has_mem_reference) {
            ret = doMIMovV<32>(ip, block, MEM_REFERENCE(0), addrInt);
        } else {
            ret = doMIMovV<32>(ip, block, ADDR_NOREF(0), addrInt);
        }
    }
    else
    {
        if( ip->has_mem_reference && ip->has_imm_reference) {
            Value *data_v = nullptr;
            if(shouldSubtractImageBase(M)) {
                // if we're here, then
                // * archGetImageBase is defined
                // * we are on win64

                data_v = IMM_AS_DATA_REF(block, natM, ip);
                data_v = doSubtractImageBase<32>(data_v, block);
            } else {
                data_v = IMM_AS_DATA_REF(block, natM, ip);
            }
            doMIMovV<32>(ip,  block, MEM_REFERENCE(0), data_v);
        } else if (ip->has_mem_reference) {
            doMIMov<32>(ip,   block, MEM_REFERENCE(0), OP(5));
        } else if (ip->has_imm_reference) {
            Value *data_v = nullptr;
            if(shouldSubtractImageBase(M)) {
                // if we're here, then
                // * archGetImageBase is defined
                // * we are on win64

                data_v = IMM_AS_DATA_REF(block, natM, ip);
                data_v = doSubtractImageBase<32>(data_v, block);
            } else {
                data_v = IMM_AS_DATA_REF(block, natM, ip);
            }

            doMIMovV<32>(ip,  block, ADDR_NOREF(0), data_v);
        } else {
            // no references
            doMIMov<32>(ip,   block, ADDR_NOREF(0), OP(5));
        }
    }
    ret = ContinueBlock;
    return ret;
}

static InstTransResult translate_MOV64mi32(NativeModulePtr natM, BasicBlock *&block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_code_ref() ) {
        Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
        if (ip->has_mem_reference) {
            ret = doMIMovV<64>(ip, block, MEM_REFERENCE(0), addrInt);
        } else {
            ret = doMIMovV<64>(ip, block, ADDR_NOREF(0), addrInt);
        }
    } else {
        if(ip->has_mem_reference && ip->has_imm_reference) {
            Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
            if(shouldSubtractImageBase(M)) {
                data_v = doSubtractImageBase<64>(data_v, block);
            }
            doMIMovV<64>(ip,  block, MEM_REFERENCE(0), data_v);

        } else if (ip->has_imm_reference) {
            Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
            if(shouldSubtractImageBase(M)) {
                data_v = doSubtractImageBase<64>(data_v, block);
            }
            doMIMovV<64>(ip,  block, ADDR_NOREF(0), data_v);
        } else if (ip->has_mem_reference) {
            doMIMov<64>(ip,   block, MEM_REFERENCE(0), OP(5));
        } else {
            ret = doMIMov<64>(ip,   block, ADDR_NOREF(0), OP(5));
        }

    }
    ret = ContinueBlock;
    return ret;
}

GENERIC_TRANSLATION_REF(MOV8mr,
	doMRMov<8>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMRMov<8>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOV16mr,
	doMRMov<16>(ip,   block, ADDR_NOREF(0), OP(5)),
	doMRMov<16>(ip,   block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOV8rm,
	doRMMov<8>(ip,   block, ADDR_NOREF(1), OP(0)),
	doRMMov<8>(ip,   block, MEM_REFERENCE(1), OP(0)))
GENERIC_TRANSLATION_REF(MOV16rm,
	doRMMov<16>(ip,   block, ADDR_NOREF(1), OP(0)),
	doRMMov<16>(ip,   block, MEM_REFERENCE(1), OP(0)))
GENERIC_TRANSLATION(MOVZX16rr8, (doMovZXRR<16,8>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION(MOVZX32rr8, (doMovZXRR<32,8>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION(MOVZX32rr16,( doMovZXRR<32,16>(ip, block, OP(0), OP(1))) )

GENERIC_TRANSLATION(MOV16rs, doRSMov<16>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV32rs, doRSMov<32>(ip, block, OP(0), OP(1)))
GENERIC_TRANSLATION(MOV64rs, doRSMov<64>(ip, block, OP(0), OP(1)))

GENERIC_TRANSLATION_REF(MOV64ms,
	doMSMov<64>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMSMov<64>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV64sm,
	    doSMMov<64>(ip,    block, ADDR_NOREF(0), OP(5)),
	    doSMMov<64>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV32ms,
    doMSMov<32>(ip,    block, ADDR_NOREF(0), OP(5)),
    doMSMov<32>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOV16ms,
	doMSMov<16>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMSMov<16>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOVZX16rm8,
	(doMovZXRM<16,8>(ip, block, OP(0), ADDR_NOREF(1))),
	(doMovZXRM<16,8>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVZX32rm8,
	(doMovZXRM<32,8>(ip, block, OP(0), ADDR_NOREF(1))),
	(doMovZXRM<32,8>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVZX32rm16,
	(doMovZXRM<32,16>(ip, block, OP(0), ADDR_NOREF(1))),
	(doMovZXRM<32,16>(ip, block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION(MOVSX16rr8, (doMovSXRR<16,8>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION(MOVSX32rr16,( doMovSXRR<32,16>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION(MOVSX32rr8, (doMovSXRR<32,8>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION(MOVSX64rr32, (doMovSXRR<64,32>(ip, block, OP(0), OP(1))) )
GENERIC_TRANSLATION_REF(MOVSX16rm8,
	(doMovSXRM<16,8>(ip, block, OP(0), ADDR_NOREF(1))),
	(doMovSXRM<16,8>(ip, block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVSX32rm8,
	(doMovSXRM<32,8>(ip, 	block, OP(0), ADDR_NOREF(1))),
	(doMovSXRM<32,8>(ip, 	block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVSX32rm16,
	(doMovSXRM<32,16>(ip, 	block, OP(0), ADDR_NOREF(1))),
	(doMovSXRM<32,16>(ip, 	block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION_REF(MOVSX64rm8,
    (doMovSXRM<64,8>(ip,   block, OP(0), ADDR_NOREF(1))),
	(doMovSXRM<64,8>(ip,   block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVSX64rm16,
	(doMovSXRM<64,16>(ip,   block, OP(0), ADDR_NOREF(1))),
	(doMovSXRM<64,16>(ip,   block, OP(0), MEM_REFERENCE(1))) )
GENERIC_TRANSLATION_REF(MOVSX64rm32,
    (doMovSXRM<64, 32>(ip,   block, OP(0), ADDR_NOREF(1))),
    (doMovSXRM<64, 32>(ip,   block, OP(0), MEM_REFERENCE(1))) )

GENERIC_TRANSLATION_REF(MOVBE16rm,
	doMRMovBE<16>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMRMovBE<16>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE32rm,
	doMRMovBE<32>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMRMovBE<32>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE64rm,
	doMRMovBE<64>(ip,    block, ADDR_NOREF(0), OP(5)),
	doMRMovBE<64>(ip,    block, MEM_REFERENCE(0), OP(5)))

GENERIC_TRANSLATION_REF(MOVBE16mr,
	doRMMovBE<16>(ip,    block, ADDR_NOREF(0), OP(5)),
	doRMMovBE<16>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE32mr,
	doRMMovBE<32>(ip,    block, ADDR_NOREF(0), OP(5)),
	doRMMovBE<32>(ip,    block, MEM_REFERENCE(0), OP(5)))
GENERIC_TRANSLATION_REF(MOVBE64mr,
	doRMMovBE<64>(ip,    block, ADDR_NOREF(0), OP(5)),
	doRMMovBE<64>(ip,    block, MEM_REFERENCE(0), OP(5)))

static InstTransResult translate_MOV32ri(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_code_ref() ) {
        Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
        ret = doRIMovV<32>(ip, block, addrInt, OP(0) );
    } else {
        if( ip->has_imm_reference) {
            Value *data_v = nullptr;
            if(shouldSubtractImageBase(M)) {
                // if we're here, then
                // * archGetImageBase is defined
                // * we are on win64

                data_v = IMM_AS_DATA_REF(block, natM, ip);
                data_v = doSubtractImageBase<32>(data_v, block);
            } else {
                data_v = IMM_AS_DATA_REF(block, natM, ip);
            }

            ret = doRIMovV<32>(ip, block, data_v, OP(0) );

        } else {
            ret = doRIMov<32>(ip, block, OP(1), OP(0)) ;
        }
    }
    return ret ;
}

static InstTransResult translate_MOV64ri(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_code_ref() ) {
        Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
        ret = doRIMovV<64>(ip, block, addrInt, OP(0) );
    }
    else if( ip->has_imm_reference ) {
        Value *data_v = IMM_AS_DATA_REF(block, natM, ip);
        if(shouldSubtractImageBase(M)) {
            // if we're here, then
            // * archGetImageBase is defined
            // * we are on win64
           
            data_v = doSubtractImageBase<64>(data_v, block);
        }

        ret = doRIMovV<64>(ip, block, data_v, OP(0) );
    } else {
        ret = doRIMov<64>(ip, block, OP(1), OP(0)) ;
    }
    return ret ;
}

template <int width>
int GET_XAX() {
  if (64 == width) {
    return X86::RAX;
  } else if (32 == width) {
    return X86::EAX;
  } else if (16 == width) {
    return X86::AX;
  } else if (8 == width) {
    return X86::AL;
  } else {
    throw TErr(__LINE__, __FILE__, "Unknown width!");
  }
}

//write to memory
template <int width>
static InstTransResult translate_MOVao (NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;

    Function *F = block->getParent();
    Module *M = F->getParent();

    // this is awful, but sometimes IDA detects the immediate
    // as a memory reference. However, this instruction can only
    // have an immediate, so this is safe
    if( ip->has_imm_reference || ip->has_mem_reference ) {
        ip->has_imm_reference = true;
        ip->set_reference(Inst::IMMRef, ip->get_reference(Inst::MEMRef));
    }

    if( ip->has_imm_reference ) {
        
        Value *data_v = nullptr;
        if(width == 32 && shouldSubtractImageBase(M)) {
            // if we're here, then
            // * archGetImageBase is defined
            // * we are on win64
           
            data_v = IMM_AS_DATA_REF(block, natM, ip);
            data_v = doSubtractImageBase<32>(data_v, block);
        } else {
            data_v = IMM_AS_DATA_REF(block, natM, ip);
        }
        ret = doMRMov<width>(ip, block, data_v,
                MCOperand::CreateReg(GET_XAX<width>()) );
    } else {
        Value *addrv = CONST_V<width>(block, OP(0).getImm());
        ret = doMRMov<width>(ip, block, addrv, MCOperand::CreateReg(GET_XAX<width>())) ;
    }
    return ret ;
}

//write to EAX
template <int width>
static InstTransResult translate_MOVoa (NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    unsigned eaxReg = GET_XAX<width>();

    // loading functions only available if its a 32-bit offset
    if( ip->has_external_ref() && width == 32) {
        Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
        TASSERT(addrInt != 0, "Could not get external data reference");
        doRMMov<width>(ip, block, addrInt, MCOperand::CreateReg(eaxReg));
        return ContinueBlock;
    }

    // this is awful, but sometimes IDA detects the immediate
    // as a memory reference. However, this instruction can only
    // have an immediate, so this is safe
    if( ip->has_imm_reference || ip->has_mem_reference ) {
        ip->has_imm_reference = true;
        ip->set_reference(Inst::IMMRef, ip->get_reference(Inst::MEMRef));
    }

    if( ip->has_code_ref() ) {
        Value *addrInt = IMM_AS_DATA_REF(block, natM, ip);
        ret = doRMMov<width>(ip, block, addrInt, MCOperand::CreateReg(eaxReg)) ;
    } else {
        if( ip->has_imm_reference ) {
            Value *data_v = nullptr;
            if(width == 32 && shouldSubtractImageBase(M)) {
                // if we're here, then
                // * archGetImageBase is defined
                // * we are on win64

                data_v = IMM_AS_DATA_REF(block, natM, ip);
                data_v = doSubtractImageBase<32>(data_v, block);
            } else {
                data_v = IMM_AS_DATA_REF(block, natM, ip);
            }
            ret = doRMMov<width>(ip, block,
                    data_v,
                    MCOperand::CreateReg(eaxReg) );
        } else {
            Value *addrv = CONST_V<width>(block, OP(0).getImm());
            ret = doRMMov<width>(ip, block, addrv, MCOperand::CreateReg(eaxReg)) ;
        }
    }
    return ret ;
}

static InstTransResult translate_MOV32rm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst)
{

    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
        ret = doRMMov<32>(ip, block, addrInt, OP(0) );
        TASSERT(addrInt != NULL, "Could not get address for external");
        return ContinueBlock;
    }
    else if( ip->has_mem_reference ) {

        Value *data_v = nullptr;
        if(shouldSubtractImageBase(M)) {
            // if we're here, then
            // * archGetImageBase is defined
            // * we are on win64

            data_v = MEM_AS_DATA_REF( block, natM, inst, ip, 1 );
            data_v = doSubtractImageBase<32>(data_v, block);
        } else {
            data_v = MEM_AS_DATA_REF( block, natM, inst, ip, 1 );
        }

        ret = doRMMov<32>(ip, block, data_v, OP(0) );
    } else {
		ret = doRMMov<32>(ip, block, ADDR_NOREF(1), OP(0));
    }
    return ret ;
}

static InstTransResult translate_MOV32mr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst)
{
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<32>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        return doMRMov<32>(ip, block, addrInt, OP(5) );
    }
    else if( ip->has_mem_reference ) {
        ret = doMRMov<32>(ip, block, MEM_AS_DATA_REF( block, natM, inst, ip, 0), OP(5) );
    } else {
        ret = doMRMov<32>(ip, block, ADDR_NOREF(0), OP(5)) ;
    }
    return ret ;
}


static InstTransResult translate_MOV64rm(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst)
{
    InstTransResult ret;
    Function *F = block->getParent();
    Module *M = F->getParent();

    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        doRMMov<64>(ip, block, addrInt, OP(0) );
        return ContinueBlock;
    }
    else if( ip->has_mem_reference ) {
        Value *data_v = nullptr;
        if(shouldSubtractImageBase(M)) {
            // if we're here, then
            // * archGetImageBase is defined
            // * we are on win64

            data_v = MEM_AS_DATA_REF( block, natM, inst, ip, 1 );
            data_v = doSubtractImageBase<64>(data_v, block);
        } else {
            data_v = MEM_AS_DATA_REF( block, natM, inst, ip, 1 );
        }
        ret = doRMMov<64>(ip, block, data_v, OP(0) );
    } else {
        ret = doRMMov<64>(ip, block, ADDR_NOREF(1), OP(0));
    }
    return ret ;
}

static InstTransResult translate_MOV64mr(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst)
{
    InstTransResult ret;
    Function *F = block->getParent();
    if( ip->has_external_ref()) {
        Value *addrInt = getValueForExternal<64>(F->getParent(), ip, block);
        TASSERT(addrInt != NULL, "Could not get address for external");
        return doMRMov<64>(ip, block, addrInt, OP(5) );
    }
    else if( ip->has_mem_reference ) {
        ret = doMRMov<64>(ip, block, MEM_AS_DATA_REF( block, natM, inst, ip, 0), OP(5) );
    } else {
        ret = doMRMov<64>(ip, block, ADDR_NOREF(0), OP(5)) ;
    }
    return ret ;
}

// sign extend %eax to %rax
static InstTransResult translate_CDQE(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst)
{
    InstTransResult ret = ContinueBlock;
    llvm::Value *eax = R_READ<32>(block, X86::EAX);
    llvm::Value	*rax = new llvm::SExtInst(eax,
    		llvm::Type::getInt64Ty(block->getContext()), "", block);
    R_WRITE<64>(block, X86::RAX, rax);
    return ret ;
}

void MOV_populateDispatchMap(DispatchMap &m) {
    m[X86::MOV8rr] = translate_MOV8rr;
    m[X86::MOV8rr_REV] = translate_MOV8rr_REV;
    m[X86::MOV16rr] = translate_MOV16rr;
    m[X86::MOV16rr_REV] = translate_MOV16rr_REV;
    m[X86::MOV32rr] = translate_MOV32rr;
    m[X86::MOV32rr_REV] = translate_MOV32rr_REV;
    m[X86::MOV64rr] = translate_MOV64rr;
    m[X86::MOV64rr_REV] = translate_MOV64rr_REV;

    m[X86::MOV8ri] = translate_MOV8ri;
    m[X86::MOV16ri] = translate_MOV16ri;
    m[X86::MOV32ao32] = translate_MOVao<32>;
    m[X86::MOV16ao16] = translate_MOVao<16>;
    m[X86::MOV8ao8] = translate_MOVao<8>;
    m[X86::MOV32o32a] = translate_MOVoa<32>;
    m[X86::MOV16o16a] = translate_MOVoa<16>;
    m[X86::MOV8o8a] = translate_MOVoa<8>;
    m[X86::MOV32ri] = translate_MOV32ri;
    m[X86::MOV64ri] = translate_MOV64ri;
    m[X86::MOV64ri32] = translate_MOV64ri;

    m[X86::MOV8mi] = translate_MOV8mi;
    m[X86::MOV16mi] = translate_MOV16mi;
    m[X86::MOV32mi] = translate_MOV32mi;
    m[X86::MOV64mi32] = translate_MOV64mi32;

    m[X86::MOV8mr] = translate_MOV8mr;
    m[X86::MOV16mr] = translate_MOV16mr;
    m[X86::MOV32mr] = translate_MOV32mr;
    m[X86::MOV64mr] = translate_MOV64mr;

    m[X86::MOV8rm] = translate_MOV8rm;
    m[X86::MOV16rm] = translate_MOV16rm;
    m[X86::MOV32rm] = translate_MOV32rm;
    m[X86::MOV64rm] = translate_MOV64rm;

    m[X86::MOVZX16rr8] = translate_MOVZX16rr8;
    m[X86::MOVZX32rr8] = translate_MOVZX32rr8;
    m[X86::MOVZX32rr16] = translate_MOVZX32rr16;

    m[X86::MOVZX16rm8] = translate_MOVZX16rm8;
    m[X86::MOVZX32rm8] = translate_MOVZX32rm8;
    m[X86::MOVZX32rm16] = translate_MOVZX32rm16;

    m[X86::MOVSX16rr8] = translate_MOVSX16rr8;
    m[X86::MOVSX32rr16] = translate_MOVSX32rr16;
    m[X86::MOVSX32rr8] = translate_MOVSX32rr8;
    m[X86::MOVSX64rr8] = translate_MOVSX32rr8;
    m[X86::MOVSX64rr16] = translate_MOVSX32rr8;
    m[X86::MOVSX64rr32] = translate_MOVSX64rr32;

    m[X86::MOVSX16rm8] = translate_MOVSX16rm8;
    m[X86::MOVSX32rm8] = translate_MOVSX32rm8;
    m[X86::MOVSX32rm16] = translate_MOVSX32rm16;
    m[X86::MOVSX64rm8] = translate_MOVSX64rm8;
    m[X86::MOVSX64rm16] = translate_MOVSX64rm16;
    m[X86::MOVSX64rm32] = translate_MOVSX64rm32;

    m[X86::MOV16rs] = translate_MOV16rs;
    m[X86::MOV32rs] = translate_MOV32rs;
    m[X86::MOV64rs] = translate_MOV64rs;

    m[X86::MOV16ms] = translate_MOV16ms;
    m[X86::MOV32ms] = translate_MOV32ms;
    m[X86::MOV64ms] = translate_MOV64ms;

    m[X86::MOV16sr] = translate_MOV32rs;
    m[X86::MOV32sr] = translate_MOV32rs;
    m[X86::MOV64sr] = translate_MOV32rs;

    //m[X86::MOV16sm] = translate_MOV16sm;
   // m[X86::MOV32sm] = translate_MOV32sm;
   // m[X86::MOV64sm] = translate_MOV64sm;

    m[X86::MOVBE16rm] = translate_MOVBE16rm;
    m[X86::MOVBE32rm] = translate_MOVBE32rm;
    m[X86::MOVBE64rm] = translate_MOVBE64rm;

    m[X86::MOVBE16mr] = translate_MOVBE16mr;
    m[X86::MOVBE32mr] = translate_MOVBE32mr;
    m[X86::MOVBE64mr] = translate_MOVBE64mr;

    m[X86::CDQE] = translate_CDQE;

}

