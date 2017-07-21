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
#include "mcsema/Arch/Mips/Semantics/JALR.h"

#include "mcsema/BC/Util.h"

using namespace llvm;

template<int width>
static void writeDetachReturnAddr(llvm::BasicBlock *B) {
  auto xsp = 32 == width ? llvm::Mips::SP : llvm::Mips::SP;
  auto xip = 32 == width ? llvm::Mips::PC : llvm::Mips::PC;
  auto espOld = R_READ<width>(B, xsp);
  auto espSub = llvm::BinaryOperator::CreateSub(espOld,CONST_V<width>(B, width / 8),"", B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, 0xde7accccde7acccc));
  R_WRITE<width>(B, xsp, espSub);
}

static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target, NativeInst *ip, bool is_jump) {
    auto *M = b->getParent()->getParent();
    auto &C = M->getContext();
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

    auto exit_point = ArchAddExitPointDriver(externFunction);

    if( externFunction->getCallingConv() == CallingConv::Fast) // previously it was fastcall
    {
        std::cout << "calling convention is Fast" << std::endl; 

        Function::ArgumentListType::iterator  it = externFunction->arg_begin();
        Function::ArgumentListType::iterator  end = externFunction->arg_end();

	auto it_ep = exit_point->arg_begin();
	auto end_ep = exit_point->arg_end();

        AttrBuilder B;
        //B.addAttribute(Attributes::InReg); //Not working
        B.addAttribute(llvm::Attribute::None);

        if(paramCount && it != end) {
            Value *r_a0 = R_READ<32>(b, Mips::A0);
	    if(r_a0->getType()->isPointerTy() == true)
	    {
		std::cout<<"is pointer type true\n";
//		llvm::Type    *ptrTy = llvm::Type::getIntNPtrTy(b->getContext(), 32, ip->get_addr_space());
//		std::cout<<"is pointer type false2\n";
//        	Value *readLoc = new llvm::IntToPtrInst(r_a0, ptrTy, "", b);
//		std::cout<<"is pointer type false3\n";
//            	arguments.push_back(readLoc);
//		std::cout<<"is pointer type false4\n";
	    }else if(r_a0->getType()->isArrayTy() == true) {
		
		std::cout<<"is array type true\n";

//            	arguments.push_back(r_a0);
	    }else if(r_a0->getType()->isPtrOrPtrVectorTy() == true) {
		std::cout<<"is pointer type or ptr vector \n";
	    }else if(r_a0->getType()->isIntegerTy() == true) {
		std::cout<<"is integer type \n";
	}
		else {
		std::cout<<"is pointer type or ptr vector \n";
	}
            arguments.push_back(r_a0);
            --paramCount;
            it->addAttr(AttributeSet::get(it->getContext(), 1, B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a1 = R_READ<32>(b, Mips::A1);
	    if (r_a1->getType()->isIntegerTy() == true)
		std::cout<<"is integer type" << std::endl;
	    else
		std::cout<<"something else" << std::endl;

            arguments.push_back(r_a1);
            --paramCount;
            it->addAttr(AttributeSet::get(it->getContext(), 1, B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a2 = R_READ<32>(b, Mips::A2);
            arguments.push_back(r_a2);
            --paramCount;
            it->addAttr(AttributeSet::get(it->getContext(), 1, B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_a3 = R_READ<32>(b, Mips::A3);
            arguments.push_back(r_a3);
            --paramCount;
            it->addAttr(AttributeSet::get(it->getContext(), 1, B));
            ++it;
        }
    }


    if( paramCount ) {
	std::cout << "reading args from stack " << paramCount << std::endl;
        baseSpVal = R_READ<32>(b, Mips::SP);
        if(is_jump) {
            baseSpVal = BinaryOperator::CreateAdd(baseSpVal, CONST_V<32>(b, 4), "", b);
        }
    }

    for( int i = 0; i < paramCount; i++ ) {
	
	std::cout << "writing args from stack " << paramCount << std::endl;
        Value   *vFromStack = M_READ_0<32>(b, baseSpVal);

        arguments.push_back(vFromStack);

        if( i+1 != paramCount ) {
            baseSpVal = 
                BinaryOperator::CreateAdd(baseSpVal, CONST_V<32>(b, 4), "", b);
        }
    }

    if ( !is_jump) {
      writeDetachReturnAddr<32>(b);
    }

    auto callR = llvm::CallInst::Create(exit_point, arguments, "", b);
    //CallInst    *callR = CallInst::Create(externFunction, arguments, "", b);
    
    callR->setCallingConv(CallingConv::C);// 3 for O32: C works and Fast does not work
    std::cout<<"extern returns or not: "<<externFunction->doesNotReturn()<<std::endl;

    noAliasMCSemaScope(callR);

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
	std::cout<<"rType == Type::\n";
        R_WRITE<32>(b, Mips::V0, callR);  // This code decides the return of function
    }


    // stdcall and fastcall: callee changed ESP; adjust
    // REG_ESP accordingly
    if( externFunction->getCallingConv() == CallingConv::X86_StdCall ||
        externFunction->getCallingConv() == CallingConv::Fast)
        //externFunction->getCallingConv() == CallingConv::X86_FastCall)
    {
	std::cout << "control coming here stdcall or fastcall " << std::endl;
        Value *SP_adjust = CONST_V<32>(b, 4*paramCount);
        Value *spFix =
            BinaryOperator::CreateAdd(spOld, SP_adjust, "", b);

        R_WRITE<32>(b, Mips::SP, spFix);
    }

    return ContinueBlock;
}


static void doCallV(BasicBlock       *&block,
                    NativeInst ip,
                    Value *call_addr, bool is_jump)
{
  auto F = block->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();
  uint32_t bitWidth = ArchPointerSize(M);

  if (_X86_64_ == SystemArch(M)) {
    R_WRITE<64>(block, llvm::X86::RIP, call_addr);
    if ( !is_jump) {
      writeDetachReturnAddr<64>(block);
    }
  } else {
    R_WRITE<32>(block, llvm::Mips::PC, call_addr);
    if ( !is_jump) {
      writeDetachReturnAddr<32>(block);
    }
  }

  auto detach = M->getFunction("__mcsema_detach_call_value");
  auto call_detach = llvm::CallInst::Create(detach, "", block);
  call_detach->setCallingConv(llvm::CallingConv::C);
}

static InstTransResult translate_JALR(TranslationContext &ctx, 
				      llvm::BasicBlock *&block)
{
	InstTransResult ret;
	auto ip = ctx.natI;
    auto &inst = ip->get_inst();

	std::cout << "translate_JALR -> " << std::hex << ip << ":-" << std::dec << inst.getNumOperands() << "\t-----" ;

        MCOperand op, tgOp ;

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

        tgOp = inst.getOperand(0);
	TASSERT(inst.getNumOperands() == 2, "");

	//read the register
 	Value *rs = R_READ<32>(block, tgOp.getReg());

	if( ip->has_ext_call_target() ) {
        	std::string  s = ip->get_ext_call_target()->getSymbolName();
		std::cout<<"has external call target: "<<s<<std::endl;
        	ret = doCallPCExtern(block, s, ip, false);
	}
    	else if (ip->has_call_tgt() ) {
        	int64_t off = (int64_t) ip->get_call_tgt(0);
		std::cout<<"has call target: "<<off<<std::endl;
        	//ret = doCallPC(block, off);
    	}
    	/*else if (ip->is_data_offset() ) {
		std::cout<<"is data offset: "<<std::endl;
		
		Value *call_addr = M_READ<32>(ip, block, STD_GLOBAL_OP(0));
		doCallV(block, ip, call_addr, false);
			
	}*/
	else {
		std::cout<<"in else "<<std::endl;
        	//int64_t off = (int64_t) OP(0).getImm();
        	//ret = doCallPC(block, ip->get_loc()+ip->get_len()+off);
    	}


  	return ContinueBlock;
}

void JALR_populateDispatchMap(DispatchMap &m)
{

	m[Mips::JALR] = translate_JALR;
}
