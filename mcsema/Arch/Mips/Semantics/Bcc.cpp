/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
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
#include <string>

#include <CFG/CFG.h>
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
#include "mcsema/Arch/Mips/Semantics/Bcc.h"

#include "mcsema/BC/Util.h"


#define NASSERT(cond) TASSERT(cond, "")

using namespace llvm;


static Value *CMPNE(BasicBlock *&b, Value *x, Value *y) {
    return new ICmpInst(*b, CmpInst::ICMP_NE, x, y);
}


static Value *CMPEQ(BasicBlock *&b, Value *x, Value *y) {
    return new ICmpInst(*b, CmpInst::ICMP_EQ, x, y);
}

Value *emitTestCodeMips(BasicBlock *&b, unsigned opCode, Value *r0, Value *r1) {
    Value       *emittedInsn = NULL;
    #define ONE CONST_V<1>(b, 1)
    #define ZERO CONST_V<1>(b, 0)

    switch(opCode) {
        case Mips::BNE:
            emittedInsn = CMPNE(b, r0, r1);
            break;

        case Mips::BEQ:
            emittedInsn = CMPEQ(b, r0, r1);
            break;

        default:
            throw TErr(__LINE__, __FILE__, "NIY");
            break;
    }

    #undef ONE
    #undef ZERO

    NASSERT(emittedInsn != NULL );

    return emittedInsn;
}

static InstTransResult translate_BNE(TranslationContext &ctx, 
				      llvm::BasicBlock *&block)
{
	InstTransResult ret;
	auto ip = ctx.natI;
  	auto &inst = ip->get_inst();

	std::cout << "translate_BNE -> " << std::hex << ip << ":-" << std::dec << inst.getNumOperands() << "\t-----" ;
	
        MCOperand op, op0, op1, op2;

        for(int i=0; i < inst.getNumOperands(); i++ )
        {

        op = inst.getOperand(i);
        if(op.isValid())
        {
                if(op.isReg())
                        std::cout << "isReg " << op.getReg() << "\t";
                if(op.isImm())
                        std::cout << "isImm " << op.getImm() << "\t";
                if(op.isFPImm())
                        std::cout << "isFPImm " << op.getFPImm() << "\t";
                if(op.isInst())
                        std::cout << "isFPImm " << op.getFPImm() << "\t";

        }

        }
        std::cout<<std::endl;

        Function *F = block->getParent();
	    BranchInst *bptr;

        op0 = inst.getOperand(0); //Reg
        op1 = inst.getOperand(1); //Reg
        op2 = inst.getOperand(2); //Imm

        if( op0.getReg() == op1.getReg())  //what is this condition?
        {
		std::cout<< "in if cond " << std::endl;
		 
		auto ifTrue = ctx.va_to_bb[ip->get_tr()];

                bptr = BranchInst::Create( ifTrue, block );
        }
        else
        {
                Value *r0 = R_READ<32>(block, op0.getReg());
                Value *r1 = R_READ<32>(block, op1.getReg());

		auto ifTrue = ctx.va_to_bb[ip->get_tr()];
		auto ifFalse = ctx.va_to_bb[ip->get_fa()];

                Value *cond = emitTestCodeMips(block, inst.getOpcode(), r0, r1 );

                bptr = BranchInst::Create( ifTrue, ifFalse, cond, block );
        }

        return EndBlock; 
}


static InstTransResult translate_BEQ(TranslationContext &ctx, 
                      llvm::BasicBlock *&block)
{
    InstTransResult ret;
    auto ip = ctx.natI;
    auto &inst  = ip->get_inst();

    std::cout << "translate_BEQ -> " << std::hex << ip << ":-" << std::dec << inst.getNumOperands() << "\t-----" ;
    
        MCOperand op, op0, op1, op2;

        for(int i=0; i < inst.getNumOperands(); i++ )
        {

        op = inst.getOperand(i);
        if(op.isValid())
        {
                if(op.isReg())
                        std::cout << "isReg " << op.getReg() << "\t";
                if(op.isImm())
                        std::cout << "isImm " << op.getImm() << "\t";
                if(op.isFPImm())
                        std::cout << "isFPImm " << op.getFPImm() << "\t";
                if(op.isInst())
                        std::cout << "isFPImm " << op.getFPImm() << "\t";

        }

        }
        std::cout<<std::endl;

        Function *F = block->getParent();

    op0 = inst.getOperand(0); //Reg
        op1 = inst.getOperand(1); //Reg
        op2 = inst.getOperand(2); //Imm

    if( op0.getReg() == op1.getReg())
    {
        auto ifTrue = ctx.va_to_bb[ip->get_tr()];

            //emit a branch 
            BranchInst::Create( ifTrue, block );
        }
    else
    {
            Value *r0 = R_READ<32>(block, op0.getReg());
            Value *r1 = R_READ<32>(block, op1.getReg());

        auto ifTrue = ctx.va_to_bb[ip->get_tr()];
        auto ifFalse = ctx.va_to_bb[ip->get_fa()];

        Value *cond = emitTestCodeMips(block, inst.getOpcode(), r0, r1 );

            BranchInst::Create( ifTrue, ifFalse, cond,  block );
    }

    return EndBlock;
}


void Bcc_populateDispatchMap(DispatchMap &m)
{

    m[Mips::BNE] = translate_BNE;
    m[Mips::BEQ] = translate_BEQ;
}
