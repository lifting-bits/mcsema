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
#include "x86Instrs_Branches.h"
#include <vector>
#include "Externals.h"
#include "../common/to_string.h"
#include "JumpTables.h"

using namespace llvm;

static InstTransResult doRet(BasicBlock    *b) {
    //do a read from the location pointed to by ESP
    Value       *rESP = R_READ<32>(b, X86::ESP);
    Value       *nESP =
        BinaryOperator::CreateAdd(rESP, CONST_V<32>(b, 4), "", b);

    //write back to ESP
    R_WRITE<32>(b, X86::ESP, nESP); 

    //spill all locals into the structure
    writeLocalsToContext(b, 32);

    ReturnInst::Create(b->getContext(), b);
    
    return EndCFG;
}

static InstTransResult doRetI(BasicBlock *&b, const MCOperand &o) {
    TASSERT(o.isImm(), "Operand not immediate");

    Value   *c = CONST_V<32>(b, o.getImm());
    Value   *rESP = R_READ<32>(b, X86::ESP);
    Value       *fromStack = M_READ_0<32>(b, rESP);
    TASSERT(fromStack != NULL, "Could not read value from stack");

    //add the immediate to ESP
    Value       *rESP_1 = 
        BinaryOperator::CreateAdd(rESP, c, "", b);

    //add pointer width to ESP
    Value       *nESP =
        BinaryOperator::CreateAdd(rESP_1, CONST_V<32>(b, 4), "", b);

    //write back to ESP
    R_WRITE<32>(b, X86::ESP, nESP); 

    //spill all locals into the structure
    writeLocalsToContext(b, 32);
    ReturnInst::Create(b->getContext(), b); 
    return EndCFG;
}



//emit a nonconditional branch 
static InstTransResult doNonCondBranch(BasicBlock *&b, BasicBlock *tgt) {
    TASSERT(tgt != NULL, "Branch to a NULL target");

    BranchInst::Create(tgt, b);

    return EndBlock;
}

//for the LOOP class of instructions, we'll assume that the
//target of the loop branch has already been defined as a block

static InstTransResult doLoop(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
    TASSERT(T != NULL, "True block is NULL");
    TASSERT(F != NULL, "False block is NULL");

    //retrieve ECX
    Value   *count = R_READ<32>(b, X86::ECX);
    //decrement ECX
    Value   *count_dec = 
        BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
    //write ECX back into the register
    R_WRITE<32>(b, X86::ECX, count_dec);

    //test and see if ECX is 0
    Value   *testRes = 
        new ICmpInst(*b, CmpInst::ICMP_NE, count_dec, CONST_V<32>(b, 0));

    //conditionally branch on this result
    BranchInst::Create(T, F, testRes, b);

    return EndBlock;
}

static InstTransResult doLoopE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
    TASSERT(T != NULL, "");
    TASSERT(F != NULL, "");
    
    //retrieve ECX
    Value   *count = R_READ<32>(b, X86::ECX);
    //decrement ECX
    Value   *count_dec = 
        BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
    //write ECX back into the register
    R_WRITE<32>(b, X86::ECX, count_dec);

    //test and see if ECX is 0
    Value   *testRes = 
        new ICmpInst(*b, CmpInst::ICMP_NE, count_dec, CONST_V<32>(b, 0));

    //also test and see if ZF is 1
    Value   *zf = F_READ(b, "ZF");
    Value   *zfRes = 
        new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));
    
    Value   *andRes = 
        BinaryOperator::CreateAnd(zfRes, testRes, "", b);
    //conditionally branch on this result
    BranchInst::Create(T, F, andRes, b);

    return EndBlock;
}

static InstTransResult doLoopNE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
    TASSERT(T != NULL, "");
    TASSERT(F != NULL, "");
    
    //retrieve ECX
    Value   *count = R_READ<32>(b, X86::ECX);
    //decrement ECX
    Value   *count_dec = 
        BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
    //write ECX back into the register
    R_WRITE<32>(b, X86::ECX, count_dec);

    //test and see if ECX is 0
    Value   *testRes = 
        new ICmpInst(*b, CmpInst::ICMP_NE, count_dec, CONST_V<32>(b, 0));

    //test and see if ZF is 0
    Value   *zf = F_READ(b, "ZF");
    Value   *zfRes = 
        new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));
    
    Value   *andRes = 
        BinaryOperator::CreateAnd(zfRes, testRes, "", b);
    //conditionally branch on this result
    BranchInst::Create(T, F, andRes, b);

    return EndBlock;
}


static void doCallV(BasicBlock       *&block,
                    InstPtr ip,
                    Value *call_addr)
{

  Function *F = block->getParent();
  Module    *mod = F->getParent();
  Function  *doCallVal = mod->getFunction("do_call_value");

  TASSERT(doCallVal != NULL, "Could not insert do_call_value function");

  std::vector<Value *> args;

  // first argument of this function is a pointer to struct.regs
  TASSERT(F->arg_size() == 1, "Function must have at least one argument");
  args.push_back(F->arg_begin());
  args.push_back(call_addr);

  //sink context 
  writeLocalsToContext(block, 32);
  
  //insert the call
  CallInst::Create(doCallVal, args, "", block);

  //restore context
  writeContextToLocals(block, 32);
}

template <int width>
static void doCallM(BasicBlock       *&block,
                    InstPtr ip,
                    Value *mem_addr)
{
    Value *call_addr = M_READ<width>(ip, block, mem_addr);
    return doCallV(block, ip, call_addr);
}


static InstTransResult doCallPC(BasicBlock *&b, VA tgtAddr) {
	Module		*M = b->getParent()->getParent();
	Function	*ourF = b->getParent();
    //insert a call to the call function

	//this function will be a translated function that we emit, so we should
	//be able to look it up in our module.

    std::string			fname = "sub_"+to_string<VA>(tgtAddr, std::hex);
    Function        *F = M->getFunction(fname);

    TASSERT( F != NULL, "Could not find function: " + fname );

    Value   *espOld = R_READ<32>(b, X86::ESP);
    Value   *espSub = 
        BinaryOperator::CreateSub(espOld, CONST_V<32>(b, 4), "", b);
    M_WRITE_0<32>(b, espSub, CONST_V<32>(b, 0xbadf00d0));
    R_WRITE<32>(b, X86::ESP, espSub);

	//we need to wrap up our current context
	writeLocalsToContext(b, 32);

	//make the call, the only argument should be our parents arguments
	TASSERT(ourF->arg_size() == 1, "");

    std::vector<Value*>	subArgs;

	subArgs.push_back(ourF->arg_begin());


	CallInst *c = CallInst::Create(F, subArgs, "", b);
	c->setCallingConv(F->getCallingConv());

	//spill our context back
	writeContextToLocals(b, 32);

	//and we can continue to run the old code

    return ContinueBlock;
}


static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target, bool esp_adjust = false) {
    Module      *M = b->getParent()->getParent();
    
    //write it into the location pointer to by ESP-4
    Value   *espOld = R_READ<32>(b, X86::ESP);
    //Value   *espSub = 
    //    BinaryOperator::CreateSub(espOld, CONST_V<32>(b, 4), "", b);
    //M_WRITE_0<32>(b, espSub, CONST_V<32>(b, 0));
    //R_WRITE<32>(b, X86::ESP, espSub);

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
    Value   *baseEspVal=NULL;
    std::vector<Value *> arguments;

    // in fastcall, the first two params are passed via register
    // only need to adjust stack if there are more than two args

    if( externFunction->getCallingConv() == CallingConv::X86_FastCall)
    {
        

        Function::ArgumentListType::iterator  it =
                        externFunction->getArgumentList().begin();
        Function::ArgumentListType::iterator  end =
                        externFunction->getArgumentList().end();
        AttrBuilder B;
        B.addAttribute(Attributes::InReg);

        if(paramCount && it != end) {
            Value *r_ecx = R_READ<32>(b, X86::ECX);
            arguments.push_back(r_ecx);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }

        if(paramCount && it != end) {
            Value *r_edx = R_READ<32>(b, X86::EDX);
            arguments.push_back(r_edx);
            --paramCount;
            it->addAttr(Attributes::get(it->getContext(), B));
            ++it;
        }
    }



    if( paramCount ) {
        baseEspVal = R_READ<32>(b, X86::ESP);
        if(esp_adjust) {
            baseEspVal = 
                BinaryOperator::CreateAdd(baseEspVal, CONST_V<32>(b, 4), "", b);
        }
    }

    for( int i = 0; i < paramCount; i++ ) {
        Value   *vFromStack = M_READ_0<32>(b, baseEspVal);

        arguments.push_back(vFromStack);

        if( i+1 != paramCount ) {
            baseEspVal = 
                BinaryOperator::CreateAdd(baseEspVal, CONST_V<32>(b, 4), "", b);
        }
    }

    CallInst    *callR = CallInst::Create(externFunction, arguments, "", b);
    callR->setCallingConv(externFunction->getCallingConv());

    if ( externFunction->doesNotReturn() ) {
        // noreturn functions just hit unreachable
        std::cout << __FUNCTION__ << ": Adding Unreachable Instruction" << std::endl;
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
    F_CLEAR(b, "DF");
   
    //if our convention says to keep the call result alive then do it
    //really, we could always keep the call result alive...
    if( rType == Type::getInt32Ty(M->getContext()) ) {
        R_WRITE<32>(b, X86::EAX, callR);
    }


    // stdcall and fastcall: callee changed ESP; adjust
    // REG_ESP accordingly
    if( externFunction->getCallingConv() == CallingConv::X86_StdCall ||
        externFunction->getCallingConv() == CallingConv::X86_FastCall)
    {
        Value *ESP_adjust = CONST_V<32>(b, 4*paramCount);
        Value *espFix =
            BinaryOperator::CreateAdd(espOld, ESP_adjust, "", b);

        R_WRITE<32>(b, X86::ESP, espFix);
    }

    return ContinueBlock;
}


static InstTransResult translate_JMP32m(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;

    // translate JMP mem32 API calls
    // as a call <api>, ret;
    if( ip->has_ext_call_target() ) {
        std::string  s = ip->get_ext_call_target()->getSymbolName();
        ret = doCallPCExtern(block, s, true);
        if (ret != EndBlock) {
            return doRet(block);
        } else {
            // noreturn api calls don't need to fix stack
            return ret;
        }
    } else if (ip->has_jump_table() && ip->is_data_offset()) {
        // this is a jump table that got converted
        // into a table in the data section
        doJumpTableViaData(natM, block, ip, inst);
        // return a "ret", since the jmp is simulated
        // as a call/ret pair
        return doRet(block);

    } else if(ip->has_jump_table()) {
        // this is a conformant jump table
        // emit an llvm switch
        doJumpTableViaSwitch(natM, block, ip, inst);
        return EndBlock;

    } else {
        
        std::string msg("NIY: JMP32m only supported for external API calls and jump tables: ");
        
        msg += to_string<VA>(ip->get_loc(), std::hex);
        throw TErr(__LINE__, __FILE__, msg.c_str());
        return EndBlock;
    }

}

static InstTransResult translate_CALLpcrel32(NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {
    InstTransResult ret;

    if( ip->has_ext_call_target() ) {
        std::string  s = ip->get_ext_call_target()->getSymbolName();
        ret = doCallPCExtern(block, s);
    }
    else if (ip->has_call_tgt() ) {
        int64_t off = (int64_t) ip->get_call_tgt(0);
        ret = doCallPC(block, off);
    }
    else {
        int64_t off = (int64_t) OP(0).getImm();
        ret = doCallPC(block, ip->get_loc()+ip->get_len()+off);
    }

    return ret;
}

static InstTransResult translate_CALL32m(
    NativeModulePtr natM, 
    BasicBlock *& block, 
    InstPtr ip, 
    MCInst &inst) 
{

    InstTransResult ret;

    // is this an external call?
    if( ip->has_ext_call_target() ) {   
        std::string  s = ip->get_ext_call_target()->getSymbolName();
        ret = doCallPCExtern(block, s);
    // not external call, but some weird way of calling local function?
    } else if( ip->has_call_tgt() ) {
        ret = doCallPC(block, ip->get_call_tgt(0));
    }
    // is this referencing global data?
    else if( ip->is_data_offset() ) {
        doCallM<32>(block, ip, STD_GLOBAL_OP(0));
        ret = ContinueBlock;
    // is this a simple address computation?
    } else {
        doCallM<32>(block, ip, ADDR(0));
        ret = ContinueBlock;
    }       

    return ret;
}

static InstTransResult translate_CALL32r(NativeModulePtr  natM,
                                         BasicBlock       *&block,
                                         InstPtr          ip,
                                         MCInst           &inst)
{
  const MCOperand &tgtOp = inst.getOperand(0);
  //we are calling a register! this is VERY EXCITING
  //first, we need to know which register we are calling. read that
  //register, then make a call to the external procedure. 
  //the external procedure has a signature of
  // void do_call_value(Value *loc, struct regs *r); 
  
  //NIY("do_call_value needs inlined implementation, not finished yet");


  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  Value *fromReg = R_READ<32>(block, tgtOp.getReg());

  doCallV(block, ip, fromReg);

  return ContinueBlock;
}

static InstTransResult translate_JMP32r(NativeModulePtr  natM,
                                         BasicBlock       *&block,
                                         InstPtr          ip,
                                         MCInst           &inst)
{
  const MCOperand &tgtOp = inst.getOperand(0);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  Value *fromReg = R_READ<32>(block, tgtOp.getReg());

  // translate the JMP32r as a call/ret
  doCallV(block, ip, fromReg);

  return doRet(block);
}

#define BLOCKNAMES_TRANSLATION(NAME, THECALL) static InstTransResult translate_ ## NAME (NativeModulePtr natM, BasicBlock *& block, InstPtr ip, MCInst &inst) {\
    Function *F = block->getParent(); \
    std::string  trueStrName = "block_0x"+to_string<VA>(ip->get_tr(), std::hex); \
    std::string  falseStrName = "block_0x"+to_string<VA>(ip->get_fa(), std::hex); \
    BasicBlock          *ifTrue = bbFromStrName(trueStrName, F); \
    TASSERT(ifTrue != NULL, "Could not find true block:"+trueStrName); \
    BasicBlock          *ifFalse = bbFromStrName(falseStrName, F); \
    InstTransResult ret;\
    ret = THECALL ; \
    return ret ;\
} 

BLOCKNAMES_TRANSLATION(LOOP, doLoop(block, ifTrue, ifFalse))
BLOCKNAMES_TRANSLATION(LOOPE, doLoopE(block, ifTrue, ifFalse))
BLOCKNAMES_TRANSLATION(LOOPNE, doLoopNE(block, ifTrue, ifFalse))
GENERIC_TRANSLATION(RET, doRet(block))
GENERIC_TRANSLATION(RETI, doRetI(block, OP(0)))
BLOCKNAMES_TRANSLATION(JMP_4, doNonCondBranch(block, ifTrue))
BLOCKNAMES_TRANSLATION(JMP_1, doNonCondBranch(block, ifTrue))

void Branches_populateDispatchMap(DispatchMap &m) {
    m[X86::JMP32r] = translate_JMP32r;
    m[X86::JMP32m] = translate_JMP32m;
    m[X86::JMP_4] = translate_JMP_4;
    m[X86::JMP_1] = translate_JMP_1;
    m[X86::CALLpcrel32] = translate_CALLpcrel32;
    m[X86::CALL32m] = translate_CALL32m;
    m[X86::CALL32r] = translate_CALL32r;
    m[X86::LOOP] = translate_LOOP;
    m[X86::LOOPE] = translate_LOOPE;
    m[X86::LOOPNE] = translate_LOOPNE;
    m[X86::RET] = translate_RET;
    m[X86::RETI] = translate_RETI;
}
