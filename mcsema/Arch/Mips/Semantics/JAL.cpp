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

static InstTransResult doCallPC(NativeInstPtr ip, BasicBlock *&b, VA tgtAddr, bool is_jump) {

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
template<int width>
  static void writeReturnAddr(llvm::BasicBlock *B, VA ret_addr) {
    auto xsp = 32 == width ? llvm::Mips::SP : llvm::Mips::SP;
    auto espOld = R_READ<width>(B, xsp);
    auto espSub = llvm::BinaryOperator::CreateSub(espOld,
                                                  CONST_V<width>(B, width / 8),
                                                  "", B);
    M_WRITE_0<width>(B, espSub, CONST_V<width>(B, ret_addr));
    R_WRITE<width>(B, xsp, espSub);
  }

template<int width>
  static llvm::CallInst *emitInternalCall(llvm::BasicBlock *&b, llvm::Module *M,
                                          const std::string &target_fn,
                                          VA ret_addr, bool is_jmp) {
    // we need the parent function to get the regstate argument
    auto ourF = b->getParent();
    TASSERT(ourF->arg_size() == 1, "");
  
    // figure out who we are calling
    auto targetF = M->getFunction(target_fn);
  
    TASSERT(targetF != nullptr, "Could not find target function: " + target_fn);
  
    // do we need to push a ret addr?
    if (!is_jmp) {
      writeReturnAddr<width>(b, ret_addr);
    }
  
    // emit: call target_fn(regstate);
    std::vector<llvm::Value *> subArgs;
    for (auto &arg : ourF->args()) {
      subArgs.push_back(&arg);
    }
    auto c = llvm::CallInst::Create(targetF, subArgs, "", b);
    ArchSetCallingConv(M, c);
  
    // return ptr to this callinst
    return c;
  }


template<int width>
  static InstTransResult doCallPC(NativeInstPtr ip, llvm::BasicBlock *&b,
                                  VA tgtAddr, bool is_jump) {
    auto M = b->getParent()->getParent();
  
    //We should be able to look it up in our module.
    std::cout << __FUNCTION__ << "target address : "
              << std::hex << tgtAddr << std::endl;
  
    std::stringstream ss;
    ss << "sub_" << std::hex << tgtAddr;
    std::string fname = ss.str();
  
    auto c = emitInternalCall<width>(
        b, M, fname, ip->get_loc() + ip->get_len() * 2, is_jump);
    auto F = c->getCalledFunction();
  
    if (ip->has_local_noreturn() || F->doesNotReturn()) {
      // noreturn functions just hit unreachable
      std::cout << __FUNCTION__
                << ": Adding Unreachable Instruction to local noreturn"
                << std::endl;
      c->setDoesNotReturn();
      c->setTailCall();
      auto unreachable = new llvm::UnreachableInst(b->getContext(), b);
      return EndBlock;
    }
    //and we can continue to run the old code
  
    return ContinueBlock;
  }

template<int width>
static void writeDetachReturnAddr(llvm::BasicBlock *B) {
  auto xsp = 32 == width ? llvm::Mips::SP : llvm::Mips::SP;
  auto xip = 32 == width ? llvm::Mips::PC : llvm::Mips::PC;
  auto espOld = R_READ<width>(B, xsp);
  auto espSub = llvm::BinaryOperator::CreateSub(espOld,CONST_V<width>(B, width / 8),"", B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, 0xde7accccde7acccc));
  R_WRITE<width>(B, xsp, espSub);
}

static void doCallV(BasicBlock *&block,
                    NativeInstPtr ip,
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


template<int width>
static void doCallM(llvm::BasicBlock *&block, NativeInstPtr ip,
       llvm::Value *mem_addr, bool is_jump) 
{
  auto call_addr = M_READ<width>(ip, block, mem_addr);
  return doCallV(block, ip, call_addr, is_jump);
}

static InstTransResult translate_JAL(TranslationContext &ctx, 
				      llvm::BasicBlock *&block)
{
   InstTransResult ret;
   auto ip = ctx.natI;
   auto &inst = ip->get_inst();
   //auto F = block->getParent();
   //auto M = F->getParent();
   auto natM = ctx.natM;


   std::cout << "translate_JAL -> " << std::hex << ip << ":-" << std::dec << inst.getNumOperands() << "\t-----" ;
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
        	//ret = doCallPCExtern(block, s);
	} 
  else if( ip->has_code_ref() ) 
  {
		std::cout<< "JAL has code ref \n";
    ret = doCallPC<32>(ip, block, ip->get_reference(NativeInst::MEMRef), false );
	}
 
 	else if( ip->has_mem_reference ) { // JAL should not go here?
   	std::cout<< "JAL has memory reference: "<< "\n";
   	//doCallM<32>(block, ip, MEM_REFERENCE(1), false);
		ret = ContinueBlock;
 	} else {
   	//doCallM<32>(block, ip, ADDR(0));
		std::cout<< "JAL docallm: "<< "\n";
   	ret = ContinueBlock;
 	}			

	return ret;
}

void JAL_populateDispatchMap(DispatchMap &m)
{

	m[Mips::JAL] = translate_JAL;
}
