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

#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include <llvm/MC/MCInst.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/Arch/X86/Util.h"
//#include "mcsema/Arch/X86/Semantics/flagops.h"
#include "mcsema/Arch/Mips/Semantics/JAL.h"

#include "mcsema/BC/Util.h"


using namespace llvm;
/*
static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target, bool sp_adjust = false) {
    Module      *M = b->getParent()->getParent();
    
    //write it into the location pointer to by ESP-4
    Value   *spOld = R_READ<32>(b, Mips::SP);

    //write the local values into the context register
    //for now, we will stop doing this because we are not calling a wrapper
    //that meaningfully understands the context structure
    //writeLocalsToContext(b, 32);

    //lookup the function in the module
    Function    *externFunction = M->getFunction(target);
    TASSERT(externFunction != NULL, "Coult not find external function: "+target);
    FunctionType    *externFunctionTy = externFunction->getFunctionType();
    Type            *rType = externFunction->getReturnType();
    int        paramCount = externFunctionTy->getNumParams();

    //now we need to do a series of reads off the stack, essentially
    //a series of POPs but without writing anything back to ESP
    Value   *baseSpVal=NULL;
    std::vector<Value *> arguments;

    // in fastcall, the first two params are passed via register
    // only need to adjust stack if there are more than two args

	std::cout<<"calling convention "<<externFunction->getCallingConv()<<std::endl;
	std::cout<<"param count "<<externFunctionTy->getNumParams()<<std::endl;
	//std::cout<<"ret type "<<)<<std::endl;
    if( externFunction->getCallingConv() == CallingConv::Fast) // previously it was fastcall
    {
        

        Function::ArgumentListType::iterator  it = externFunction->getArgumentList().begin();
        Function::ArgumentListType::iterator  end = externFunction->getArgumentList().end();
        AttrBuilder B;
        //B.addAttribute(Attributes::InReg);
        B.addAttribute(Attributes::None);

        if(paramCount && it != end) {
            Value *r_a0 = R_READ<32>(b, Mips::A0);
            arguments.push_back(r_a0);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a1 = R_READ<32>(b, Mips::A1);
            arguments.push_back(r_a1);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a2 = R_READ<32>(b, Mips::A2);
            arguments.push_back(r_a2);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a3 = R_READ<32>(b, Mips::A3);
            arguments.push_back(r_a3);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }
    }



    if( paramCount ) {
        baseSpVal = R_READ<32>(b, Mips::SP);
        if(sp_adjust) {
            baseSpVal = 
                BinaryOperator::CreateAdd(baseSpVal, CONST_V<32>(b, 4), "", b);
        }
    }

    for( int i = 0; i < paramCount; i++ ) {
        Value   *vFromStack = M_READ_0<32>(b, baseSpVal);

        arguments.push_back(vFromStack);

        if( i+1 != paramCount ) {
            baseSpVal = 
                BinaryOperator::CreateAdd(baseSpVal, CONST_V<32>(b, 4), "", b);
        }
    }

    CallInst    *callR = CallInst::Create(externFunction, arguments, "", b);
    //callR->setCallingConv(externFunction->getCallingConv());
    callR->setCallingConv(CallingConv::C);
    std::cout<<"extern returns or not: "<<externFunction->doesNotReturn()<<std::endl;

    if ( externFunction->doesNotReturn() ) {
        // noreturn functions just hit unreachable
        //std::cout << __FUNCTION__ << ": Adding Unreachable Instruction" << std::endl;
        std::cout << ": Adding Unreachable Instruction" << std::endl;
        callR->setDoesNotReturn();
        callR->setTailCall();
        Value *unreachable = new UnreachableInst(b->getContext(), b);
        return EndBlock;
    }
    
    //then, put the registers back into the locals
    //see above
    //writeContextToLocals(b, 32);
    
    
    // we returned from an extern: assume it cleared the direction flag
    // which is standard for MS calling conventions
    //
    //F_CLEAR(b, "DF");
   
    //if our convention says to keep the call result alive then do it
    //really, we could always keep the call result alive...
    if( rType == Type::getInt32Ty(M->getContext()) ) {
        R_WRITE<32>(b, Mips::RA, callR);
    }


    // stdcall and fastcall: callee changed ESP; adjust
    // REG_ESP accordingly
    if( externFunction->getCallingConv() == CallingConv::X86_StdCall ||
	//externFunction->getCallingConv() == CallingConv::X86_FastCall)
        externFunction->getCallingConv() == CallingConv::Fast)
    {
        Value *SP_adjust = CONST_V<32>(b, 4*paramCount);
        Value *spFix =
            BinaryOperator::CreateAdd(spOld, SP_adjust, "", b);

        R_WRITE<32>(b, Mips::SP, spFix);
    }

    return ContinueBlock;
}

static InstTransResult doCallPC(BasicBlock *&b, VA tgtAddr) {

        Module          *M = b->getParent()->getParent();
        Function        *ourF = b->getParent();
 
	std::string     fname = "sub_"+to_string<VA>(tgtAddr, std::hex);
    	Function        *F = M->getFunction(fname);

    	TASSERT( F != NULL, "Could not find function: " + fname );

	std::cout<<"JAL doCallPC sub: "<<fname<<std::endl;

//    	Value   *spOld = R_READ<32>(b, Mips::SP);
//   	Value   *fpOld = R_READ<32>(b, Mips::FP);
    	//Value   *spSub = BinaryOperator::CreateSub(spOld, CONST_V<32>(b, 4), "", b);
    
//	M_WRITE_0<32>(b, spSub, CONST_V<32>(b, 0xbadf00d0));
//    	R_WRITE<32>(b, Mips::SP, spSub);

        writeLocalsToContext(b, 32);

        TASSERT(ourF->arg_size() == 1, "");

    	std::vector<Value*> subArgs;

        subArgs.push_back(ourF->arg_begin());

        CallInst *c = CallInst::Create(F, subArgs, "", b);
        
	//std::cout << "calling conv = " << F->getCallingConv() << std::endl;
	//c->setCallingConv(F->getCallingConv());
	c->setCallingConv(CallingConv::C);

        writeContextToLocals(b, 32);

    	return ContinueBlock;
}
*/
static InstTransResult translate_JAL(TranslationContext &ctx, 
				      llvm::BasicBlock *&block)
{
	InstTransResult ret;
std::cout << "translate_JAL -> " << std::endl;
/*	std::cout << "translate_JAL -> " << std::hex << ip << ":-" << std::dec << inst.getNumOperands() << "\t-----" ;

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

	if( ip->has_ext_call_target() ) {
        	std::string  s = ip->get_ext_call_target()->getSymbolName();
		std::cout<< "JAL has external call target: "<< s << "\n";
        	ret = doCallPCExtern(block, s);
 
	} else if( ip->has_call_tgt() ) {
		std::cout<< "JAL has call tgt "<< "\n";
        	ret = doCallPC(block, ip->get_call_tgt(0));
    	}
 
    	else if( ip->is_data_offset() ) {
        	//doCallM<32>(block, ip, STD_GLOBAL_OP(0));
		std::cout<< "JAL is data off: "<< "\n";
        	ret = ContinueBlock;
 
    	} else {
        	//doCallM<32>(block, ip, ADDR(0));
		std::cout<< "JAL docallm: "<< "\n";
        	ret = ContinueBlock;
    	}			
*/
	return ret;
	//return EndBlock;
}

void JAL_populateDispatchMap(DispatchMap &m)
{

	m[Mips::JAL] = translate_JAL;
}
