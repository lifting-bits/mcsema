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
#include "../common/Defaults.h"
#include "JumpTables.h"
#include "llvm/Support/Debug.h"
#include "ArchOps.h"
#include "win64ArchOps.h"

using namespace llvm;

template <int width>
static InstTransResult doRet(BasicBlock *b) {
  //do a read from the location pointed to by ESP

  TASSERT(width == 32 || width == 64, "Invalid reg width for RET");
  Value *rESP = R_READ<width>(b, X86::ESP);
  Value *nESP = BinaryOperator::CreateAdd(rESP, CONST_V<width>(b, width/8), "", b);

  //write back to ESP
  R_WRITE<width>(b, X86::ESP, nESP);

  //spill all locals into the structure
  writeLocalsToContext(b, width, ABIRetStore);

  ReturnInst::Create(b->getContext(), b);

  return EndCFG;
}

template <int width>
static InstTransResult doRetI(BasicBlock *&b, const MCOperand &o) {
  TASSERT(width == 32 || width == 64, "Invalid reg width for RETI");
  TASSERT(o.isImm(), "Operand not immediate");

  Value *c = CONST_V<width>(b, o.getImm());
  Value *rESP = R_READ<width>(b, X86::ESP);
  Value *fromStack = M_READ_0<width>(b, rESP);
  TASSERT(fromStack != NULL, "Could not read value from stack");

  //add the immediate to ESP
  Value *rESP_1 = BinaryOperator::CreateAdd(rESP, c, "", b);

  //add pointer width to ESP
  Value *nESP = BinaryOperator::CreateAdd(rESP_1, CONST_V<width>(b, width/8), "", b);

  //write back to ESP
  R_WRITE<width>(b, X86::ESP, nESP);

  //spill all locals into the structure
  writeLocalsToContext(b, width, ABIRetStore);
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
namespace x86 {
static InstTransResult doLoop(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  TASSERT(T != NULL, "True block is NULL");
  TASSERT(F != NULL, "False block is NULL");

  //retrieve ECX
  Value *count = x86::R_READ<32>(b, X86::ECX);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
  //write ECX back into the register
  x86::R_WRITE<32>(b, X86::ECX, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst(*b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<32>(b, 0));

  //conditionally branch on this result
  BranchInst::Create(T, F, testRes, b);

  return EndBlock;
}
}

namespace x86_64 {
static InstTransResult doLoop(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  TASSERT(T != NULL, "True block is NULL");
  TASSERT(F != NULL, "False block is NULL");

  //retrieve RCX
  Value *count = R_READ<64>(b, X86::RCX);
  //decrement RCX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<64>(b, 1), "", b);
  //write RCX back into the register
  R_WRITE<64>(b, X86::RCX, count_dec);

  //test and see if RCX is 0
  Value *testRes = new ICmpInst(*b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<64>(b, 0));

  //conditionally branch on this result
  BranchInst::Create(T, F, testRes, b);

  return EndBlock;
}
}

static InstTransResult doLoop(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  llvm::Module *M = b->getParent()->getParent();

  if (getPointerSize(M) == Pointer32) {
    return x86::doLoop(b, T, F);
  } else {
    return x86_64::doLoop(b, T, F);
  }
}
static InstTransResult doLoopE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  Value *count = x86::R_READ<32>(b, X86::ECX);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
  //write ECX back into the register
  x86::R_WRITE<32>(b, X86::ECX, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst(*b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<32>(b, 0));

  //also test and see if ZF is 1
  Value *zf = F_READ(b, ZF);
  Value *zfRes = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));

  Value *andRes = BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

static InstTransResult doLoopNE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  Value *count = x86::R_READ<32>(b, X86::ECX);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<32>(b, 1), "", b);
  //write ECX back into the register
  x86::R_WRITE<32>(b, X86::ECX, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst(*b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<32>(b, 0));

  //test and see if ZF is 0
  Value *zf = F_READ(b, ZF);
  Value *zfRes = new ICmpInst(*b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));

  Value *andRes = BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

namespace x86 {
static void writeFakeReturnAddr(BasicBlock *block) {
  Value *espOld = x86::R_READ<32>(block, X86::ESP);
  Value *espSub = BinaryOperator::CreateSub(espOld, CONST_V<32>(block, 4), "",
                                            block);
  M_WRITE_0<32>(block, espSub, CONST_V<32>(block, 0xbadf00d0));
  x86::R_WRITE<32>(block, X86::ESP, espSub);
}
}

namespace x86_64 {
static void writeFakeReturnAddr(BasicBlock *block) {
  Value *espOld = R_READ<64>(block, X86::RSP);
  Value *espSub = BinaryOperator::CreateSub(espOld, CONST_V<64>(block, 8), "",
                                            block);
  M_WRITE_0<64>(block, espSub, CONST_V<64>(block, 0xbadf00d0badbeef0));
  R_WRITE<64>(block, X86::RSP, espSub);
}
}

static void doCallV(BasicBlock *&block, InstPtr ip, Value *call_addr) {

    Function *F = block->getParent();
    Module *mod = F->getParent();
    uint32_t bitWidth = getPointerSize(mod);
    Function *doCallVal = mod->getFunction("do_call_value");

    TASSERT(doCallVal != NULL, "Could not insert do_call_value function");

    std::vector<Value *> args;

    // first argument of this function is a pointer to struct.regs
    TASSERT(F->arg_size() == 1, "Function must have at least one argument");

    Instruction *voidPtr = CastInst::CreatePointerCast(
            F->arg_begin(), 
            getVoidPtrType(F->getContext()), 
            "", block);

    args.push_back(voidPtr);
    args.push_back(call_addr);

    //sink context
    writeLocalsToContext(block, bitWidth, ABICallStore);

    //insert the call
    CallInst::Create(doCallVal, args, "", block);

    //restore context
    writeContextToLocals(block, bitWidth, ABIRetSpill);
}

template<int width>
static void doCallM(BasicBlock *&block, InstPtr ip, Value *mem_addr) {
  Value *call_addr = M_READ<width>(ip, block, mem_addr);

  Module *M = block->getParent()->getParent();
  const std::string &triple = M->getTargetTriple();

  return doCallV(block, ip, call_addr);
}


template <int width>
static InstTransResult doCallPC(InstPtr ip, BasicBlock *&b, VA tgtAddr) {
  Module *M = b->getParent()->getParent();
  Function *ourF = b->getParent();

  //We should be able to look it up in our module.
  std::cout << __FUNCTION__ << "target address : "
            << to_string<VA>(tgtAddr, std::hex) << "\n";
  std::string fname = "sub_" + to_string<VA>(tgtAddr, std::hex);
  Function *F = M->getFunction(fname);

  TASSERT(F != NULL, "Could not find function: " + fname);


  if (width == 64) {
      x86_64::writeFakeReturnAddr(b);
  } else {
      x86::writeFakeReturnAddr(b);
  }

  //we need to wrap up our current context
  writeLocalsToContext(b, width, ABIRetStore);

  //make the call, the only argument should be our parents arguments
  TASSERT(ourF->arg_size() == 1, "");

  std::vector<Value*> subArgs;

  subArgs.push_back(ourF->arg_begin());

  CallInst *c = CallInst::Create(F, subArgs, "", b);
  archSetCallingConv(M, c);

  if (ip->has_local_noreturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__
              << ": Adding Unreachable Instruction to local noreturn"
              << std::endl;
    c->setDoesNotReturn();
    c->setTailCall();
    Value *unreachable = new UnreachableInst(b->getContext(), b);
    return EndBlock;
  }

  //spill our context back
  writeContextToLocals(b, width, ABIRetSpill);

  //and we can continue to run the old code

  return ContinueBlock;
}

namespace x86 {
static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target,
                                      bool esp_adjust = false) {
  Module *M = b->getParent()->getParent();

  //write it into the location pointer to by ESP-4
  Value *espOld = x86::R_READ<32>(b, X86::ESP);
  //Value   *espSub =
  //    BinaryOperator::CreateSub(espOld, CONST_V<32>(b, 4), "", b);
  //M_WRITE_0<32>(b, espSub, CONST_V<32>(b, 0));
  //R_WRITE<32>(b, X86::ESP, espSub);

  //write the local values into the context register
  //for now, we will stop doing this because we are not calling a wrapper
  //that meaningfully understands the context structure
  //writeLocalsToContext(b, 32);

  //lookup the function in the module
  Function *externFunction = M->getFunction(target);
  TASSERT(externFunction != NULL, "Could not find external function: " + target);
  FunctionType *externFunctionTy = externFunction->getFunctionType();
  Type *rType = externFunction->getReturnType();
  int paramCount = externFunctionTy->getNumParams();

  //now we need to do a series of reads off the stack, essentially
  //a series of POPs but without writing anything back to ESP
  Value *baseEspVal = NULL;
  std::vector<Value *> arguments;

  // in fastcall, the first two params are passed via register
  // only need to adjust stack if there are more than two args

  if (externFunction->getCallingConv() == CallingConv::X86_FastCall) {

    Function::ArgumentListType::iterator it = externFunction->getArgumentList()
        .begin();
    Function::ArgumentListType::iterator end = externFunction->getArgumentList()
        .end();
    AttrBuilder B;
    B.addAttribute(Attribute::InReg);

    if (paramCount && it != end) {
      Value *r_ecx = x86::R_READ<32>(b, X86::ECX);
      arguments.push_back(r_ecx);
      --paramCount;
      // set argument 1's attribute: make it in a register
      it->addAttr(AttributeSet::get(it->getContext(), 1, B));
      ++it;
    }

    if (paramCount && it != end) {
      Value *r_edx = x86::R_READ<32>(b, X86::EDX);
      arguments.push_back(r_edx);
      --paramCount;
      // set argument 2's attribute: make it in a register
      it->addAttr(AttributeSet::get(it->getContext(), 2, B));
      ++it;
    }
  }

  if (paramCount) {
    baseEspVal = x86::R_READ<32>(b, X86::ESP);
    if (esp_adjust) {
      baseEspVal = BinaryOperator::CreateAdd(baseEspVal, CONST_V<32>(b, 4), "",
                                             b);
    }
  }

  for (int i = 0; i < paramCount; i++) {
    Value *vFromStack = M_READ_0<32>(b, baseEspVal);

    arguments.push_back(vFromStack);

    if (i + 1 != paramCount) {
      baseEspVal = BinaryOperator::CreateAdd(baseEspVal, CONST_V<32>(b, 4), "",
                                             b);
    }
  }

  CallInst *callR = CallInst::Create(externFunction, arguments, "", b);
  callR->setCallingConv(externFunction->getCallingConv());

  noAliasMCSemaScope(callR);

  if (externFunction->doesNotReturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__ << ": Adding Unreachable Instruction"
              << std::endl;
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
  F_CLEAR(b, DF);

  //if our convention says to keep the call result alive then do it
  //really, we could always keep the call result alive...
  if (rType == Type::getInt32Ty(M->getContext())) {
    x86::R_WRITE<32>(b, X86::EAX, callR);
  }

  // stdcall and fastcall: callee changed ESP; adjust
  // REG_ESP accordingly
  if (externFunction->getCallingConv() == CallingConv::X86_StdCall
      || externFunction->getCallingConv() == CallingConv::X86_FastCall) {
    Value *ESP_adjust = CONST_V<32>(b, 4 * paramCount);
    Value *espFix = BinaryOperator::CreateAdd(espOld, ESP_adjust, "", b);

    x86::R_WRITE<32>(b, X86::ESP, espFix);
  }

  return ContinueBlock;
}
}

namespace x86_64 {

static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target,
                                      bool esp_adjust = false) {
  Module *M = b->getParent()->getParent();

  Value *rspOld = x86_64::R_READ<64>(b, X86::RSP);

  //lookup the function in the module
  Function *externFunction = M->getFunction(target);
  TASSERT(externFunction != NULL, "Could not find external function: " + target);
  FunctionType *externFunctionTy = externFunction->getFunctionType();
  Type *rType = externFunction->getReturnType();
  int paramCount = externFunctionTy->getNumParams();
  //std::string 	funcSign = externFunction->getSignature();

  std::cout << __FUNCTION__ << " paramCount  : " << paramCount << " : "
            << target << "\n";
  std::cout << externFunctionTy->getNumParams() << " : "
            << to_string<VA>((VA) externFunctionTy->getParamType(0), std::hex)
            << "\n";
  std::cout.flush();

  //now we need to do a series of reads off the stack, essentially
  //a series of POPs but without writing anything back to ESP
  Value *baseRspVal = NULL;
  std::vector<Value *> arguments;

  // on x86_64 platform all calls will be x86_64_SysV
  Function::ArgumentListType::iterator it = externFunction->getArgumentList()
      .begin();
  Function::ArgumentListType::iterator end = externFunction->getArgumentList()
      .end();
  AttrBuilder B;
  B.addAttribute(Attribute::InReg);

  if (getSystemOS(M) == llvm::Triple::Win32) {
    if (paramCount && it != end) {
      Type *T = it->getType();
      Value *arg1;
      if (T->isDoubleTy()) {
        int k = x86_64::getRegisterOffset(XMM0);
        Value *arg1FieldGEPV[] = { CONST_V<64>(b, 0), CONST_V<32>(b, k) };

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg1FieldGEPV, "XMM0_val", b);
        Instruction *GEP_double = CastInst::CreatePointerCast(
            GEP_128, PointerType::get(Type::getDoubleTy(M->getContext()), 0),
            "conv0", b);
        arg1 = new LoadInst(GEP_double, "", b);

      } else {
        printf("Argument is RCX\n"), fflush(stdout);
        arg1 = x86_64::R_READ<64>(b, X86::RCX);
      }

      arguments.push_back(arg1);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 1, B));
      ++it;
    }

    if (paramCount && it != end) {
      Type *T = it->getType();
      Value *arg2;
      if (T->isDoubleTy()) {
        int k = x86_64::getRegisterOffset(XMM1);
        Value *arg2FieldGEPV[] = { CONST_V<64>(b, 0), CONST_V<32>(b, k) };

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg2FieldGEPV, "XMM1_val", b);
        Instruction *GEP_double = CastInst::CreatePointerCast(
            GEP_128, PointerType::get(Type::getDoubleTy(M->getContext()), 0),
            "conv1", b);
        arg2 = new LoadInst(GEP_double, "", b);
      } else
        arg2 = x86_64::R_READ<64>(b, X86::RDX);

      arguments.push_back(arg2);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 2, B));
      ++it;
    }

    if (paramCount && it != end) {
      Type *T = it->getType();
      Value *arg3;
      if (T->isDoubleTy()) {
        int k = x86_64::getRegisterOffset(XMM2);
        Value *arg3FieldGEPV[] = { CONST_V<64>(b, 0), CONST_V<32>(b, k) };

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg3FieldGEPV, "XMM2_val", b);
        Instruction *GEP_double = CastInst::CreatePointerCast(
            GEP_128, PointerType::get(Type::getDoubleTy(M->getContext()), 0),
            "conv2", b);
        arg3 = new LoadInst(GEP_double, "", b);
      }

      else
        arg3 = x86_64::R_READ<64>(b, X86::R8);

      arguments.push_back(arg3);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 3, B));
      ++it;
    }

    if (paramCount && it != end) {
      Type *T = it->getType();
      Value *arg4;
      if (T->isDoubleTy()) {
        int k = x86_64::getRegisterOffset(XMM3);
        Value *arg4FieldGEPV[] = { CONST_V<64>(b, 0), CONST_V<32>(b, k) };

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg4FieldGEPV, "XMM3_val", b);
        Instruction *GEP_double = CastInst::CreatePointerCast(
            GEP_128, PointerType::get(Type::getDoubleTy(M->getContext()), 0),
            "conv3", b);
        arg4 = new LoadInst(GEP_double, "", b);
      } else
        arg4 = x86_64::R_READ<64>(b, X86::R9);

      arguments.push_back(arg4);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 4, B));
      ++it;
    }
  } else {
    if (paramCount && it != end) {
      // fix it by updating the value type
      Value *reg_rdi = x86_64::R_READ<64>(b, X86::RDI);
      arguments.push_back(reg_rdi);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 1, B));
      ++it;

    }

    if (paramCount && it != end) {
      Value *reg_rsi = x86_64::R_READ<64>(b, X86::RSI);
      arguments.push_back(reg_rsi);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 2, B));
      ++it;
    }

    if (paramCount && it != end) {
      Value *reg_rdx = x86_64::R_READ<64>(b, X86::RDX);
      arguments.push_back(reg_rdx);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 3, B));
      ++it;
    }

    if (paramCount && it != end) {
      Value *reg_rcx = x86_64::R_READ<64>(b, X86::RCX);
      arguments.push_back(reg_rcx);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 4, B));
      ++it;
    }

    if (paramCount && it != end) {
      Value *reg_r8 = x86_64::R_READ<64>(b, X86::R8);
      arguments.push_back(reg_r8);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 5, B));
      ++it;
    }

    if (paramCount && it != end) {
      Value *reg_r9 = x86_64::R_READ<64>(b, X86::R9);
      arguments.push_back(reg_r9);
      --paramCount;
      it->addAttr(AttributeSet::get(it->getContext(), 6, B));
      ++it;
    }
  }

  if (paramCount) {
    // rest of the arguments are passed over stack
    // adjust the stack pointer if required
    baseRspVal = x86_64::R_READ<64>(b, X86::RSP);
    if (esp_adjust) {
      baseRspVal = BinaryOperator::CreateAdd(baseRspVal, CONST_V<64>(b, 8), "",
                                             b);
    }
  }

  for (int i = 0; i < paramCount; i++) {
    Value *vFromStack = M_READ_0<64>(b, baseRspVal);

    arguments.push_back(vFromStack);

    if (i + 1 != paramCount) {
      baseRspVal = BinaryOperator::CreateAdd(baseRspVal, CONST_V<64>(b, 8), "",
                                             b);
    }
  }

  CallInst *callR = CallInst::Create(externFunction, arguments, "", b);
  archSetCallingConv(M, callR);

  if (externFunction->doesNotReturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__ << ": Adding Unreachable Instruction"
              << std::endl;
    callR->setDoesNotReturn();
    callR->setTailCall();
    Value *unreachable = new UnreachableInst(b->getContext(), b);
    return EndBlock;
  }

  //if our convention says to keep the call result alive then do it
  //really, we could always keep the call result alive...
  if (rType == Type::getInt64Ty(M->getContext())) {
    x86_64::R_WRITE<64>(b, X86::RAX, callR);
  }

  return ContinueBlock;
}

}

template <int width>
static InstTransResult translate_JMPm(NativeModulePtr natM,
                                        BasicBlock *& block, InstPtr ip,
                                        MCInst &inst) {
  InstTransResult ret;

  // translate JMP mem64 API calls
  // as a call <api>, ret;

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();
    if (width == width) {
        ret = x86_64::doCallPCExtern(block, s, true);
    } else {
        ret = x86::doCallPCExtern(block, s, true);
    }
    if (ret != EndBlock) {
      return doRet<width>(block);
    } else {
      // noreturn api calls don't need to fix stack
      return ret;
    }
  } else if (ip->has_jump_table() && ip->has_mem_reference) {
    // this is a jump table that got converted
    // into a table in the data section
    doJumpTableViaData(natM, block, ip, inst, width);
    // return a "ret", since the jmp is simulated
    // as a call/ret pair
    return doRet<width>(block);

  } else if (ip->has_jump_table()) {
    // this is a conformant jump table
    // emit an llvm switch
    doJumpTableViaSwitch(natM, block, ip, inst, width);
    return EndBlock;

  } else if (ip->has_mem_reference) {
    doCallM<width>(block, ip, MEM_REFERENCE(0));
    // clear stack
    return doRet<width>(block);
  }
}

template <int width>
static InstTransResult translate_JMPr(NativeModulePtr natM,
                                        BasicBlock *&block, InstPtr ip,
                                        MCInst &inst) {
  const MCOperand &tgtOp = inst.getOperand(0);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  Value *fromReg = R_READ<width>(block, tgtOp.getReg());

  Module *M = block->getParent()->getParent();

  if (ip->has_jump_table()) {
    // this is a jump table that got converted
    // into a table in the data section
    llvm::dbgs() << __FUNCTION__ << ": jump table via register: "
                 << to_string<VA>(ip->get_loc(), std::hex) << "\n";

    BasicBlock *defaultb = nullptr;

    // Terrible HACK
    // Subtract image base since we assume win64 adds it for jump
    // tables. This may not always be true.
    Value *minus_base = nullptr;
    if(width == 64 && shouldSubtractImageBase(M)) {
        minus_base = doSubtractImageBaseInt(fromReg, block);
    } else {
        minus_base = fromReg;
    }
    // end terrible HACK
    doJumpTableViaSwitchReg(block, ip, minus_base, defaultb, width);
    TASSERT(defaultb != nullptr, "Default block has to exit");
    // fallback to doing do_call_value
    doCallV(defaultb, ip, fromReg);
    writeLocalsToContext(defaultb, width, ABIRetStore);
    ReturnInst::Create(defaultb->getContext(), defaultb);
    return EndCFG;

  } else {
    // translate the JMP64r as a call/ret
    llvm::dbgs() << __FUNCTION__ << ": regular jump via register: "
                 << to_string<VA>(ip->get_loc(), std::hex) << "\n";
    doCallV(block, ip, fromReg);
    writeLocalsToContext(block, width, ABIRetStore);
    ReturnInst::Create(block->getContext(), block);
    return EndCFG;
  }
}

template <int width>
static InstTransResult translate_CALLpcrel32(NativeModulePtr natM,
                                             BasicBlock *& block, InstPtr ip,
                                             MCInst &inst) {
  InstTransResult ret;

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();
    if (width == 64) {
        ret = x86_64::doCallPCExtern(block, s);
    } else {
        ret = x86::doCallPCExtern(block, s);
    }
  } else if (ip->has_code_ref()) {
    int64_t off = (int64_t) ip->get_reference(Inst::MEMRef);
    ret = doCallPC<width>(ip, block, off);
  } else {
    int64_t off = (int64_t) OP(0).getImm();
    ret = doCallPC<width>(ip, block, ip->get_loc() + ip->get_len() + off);
  }

  return ret;
}


template <int width>
static InstTransResult translate_CALLm(NativeModulePtr natM,
                                         BasicBlock *& block, InstPtr ip,
                                         MCInst &inst) {
  InstTransResult ret;

  // is this an external call?
  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();
    if(width == 64) {
        ret = x86_64::doCallPCExtern(block, s);
    } else {
        ret = x86::doCallPCExtern(block, s);
    }

    // not external call, but some weird way of calling local function?
  } else if (ip->has_code_ref()) {
    cout << __FUNCTION__ << ":" << __LINE__ << ": doing call" << std::endl;
    doCallPC<width>(ip, block, ip->get_reference(Inst::MEMRef));
  }
  // is this referencing global data?
  else if (ip->has_mem_reference) {
    doCallM<width>(block, ip, MEM_REFERENCE(0));
    ret = ContinueBlock;
    // is this a simple address computation?
  } else {
    doCallM<width>(block, ip, ADDR_NOREF(0));
    ret = ContinueBlock;
  }

  return ret;
}

template <int width>
static InstTransResult translate_CALLr(NativeModulePtr natM,
                                         BasicBlock *&block, InstPtr ip,
                                         MCInst &inst) {
  const MCOperand &tgtOp = inst.getOperand(0);
  //we are calling a register! this is VERY EXCITING
  //first, we need to know which register we are calling. read that
  //register, then make a call to the external procedure.
  //the external procedure has a signature of
  // void do_call_value(Value *loc, struct regs *r);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  Value *fromReg = R_READ<width>(block, tgtOp.getReg());

  Module *M = block->getParent()->getParent();
  const std::string &triple = M->getTargetTriple();

  doCallV(block, ip, fromReg);

  return ContinueBlock;
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
GENERIC_TRANSLATION(RET, doRet<32>(block))
GENERIC_TRANSLATION(RETQ, doRet<64>(block))
GENERIC_TRANSLATION(RETI, doRetI<32>(block, OP(0)))
GENERIC_TRANSLATION(RETIQ, doRetI<64>(block, OP(0)))
BLOCKNAMES_TRANSLATION(JMP_4, doNonCondBranch(block, ifTrue))
BLOCKNAMES_TRANSLATION(JMP_2, doNonCondBranch(block, ifTrue))
BLOCKNAMES_TRANSLATION(JMP_1, doNonCondBranch(block, ifTrue))

void Branches_populateDispatchMap(DispatchMap &m) {
  m[X86::JMP32r] = (translate_JMPr<32>);
  m[X86::JMP32m] = (translate_JMPm<32>);
  m[X86::JMP64r] = (translate_JMPr<64>);
  m[X86::JMP64m] = (translate_JMPm<64>);

  m[X86::JMP_4] = translate_JMP_4;
  m[X86::JMP_2] = translate_JMP_2;
  m[X86::JMP_1] = translate_JMP_1;

  m[X86::CALLpcrel32] = (translate_CALLpcrel32<32>);
  m[X86::CALL64pcrel32] = (translate_CALLpcrel32<64>);
  m[X86::CALL32m] = (translate_CALLm<32>);
  m[X86::CALL64m] = (translate_CALLm<64>);
  m[X86::CALL32r] = (translate_CALLr<32>);
  m[X86::CALL64r] = (translate_CALLr<64>);

  m[X86::LOOP] = translate_LOOP;
  m[X86::LOOPE] = translate_LOOPE;
  m[X86::LOOPNE] = translate_LOOPNE;
  m[X86::RETL] = translate_RET;
  m[X86::RETIL] = translate_RETI;
  m[X86::RETQ] = translate_RETQ;
  m[X86::RETIQ] = translate_RETIQ;
  m[X86::RETIW] = translate_RET;
}
