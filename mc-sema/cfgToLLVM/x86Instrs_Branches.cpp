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

template<int width>
static InstTransResult doLRet(BasicBlock *b) {
  //do a read from the location pointed to by ESP

  TASSERT(width == 32 || width == 64, "Invalid reg width for RET");
  auto xsp = 32 == width ? X86::ESP : X86::RSP;
  Value *rESP = R_READ<width>(b, xsp);
  Value *nESP = BinaryOperator::CreateAdd(rESP, CONST_V<width>(b, 2 * width / 8),
                                          "", b);

  auto xip = 32 == width ? X86::EIP : X86::RIP;
  Value *ra = M_READ_0<width>(b, rESP);
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  ReturnInst::Create(b->getContext(), b);

  return EndCFG;
}

template<int width>
static InstTransResult doRet(BasicBlock *b) {
  //do a read from the location pointed to by ESP

  TASSERT(width == 32 || width == 64, "Invalid reg width for RET");
  auto xsp = 32 == width ? X86::ESP : X86::RSP;
  Value *rESP = R_READ<width>(b, xsp);
  Value *nESP = BinaryOperator::CreateAdd(rESP, CONST_V<width>(b, width / 8),
                                          "", b);

  auto xip = 32 == width ? X86::EIP : X86::RIP;
  Value *ra = M_READ_0<width>(b, rESP);
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  ReturnInst::Create(b->getContext(), b);

  return EndCFG;
}

template<int width>
static InstTransResult doRetI(BasicBlock *&b, const MCOperand &o) {
  TASSERT(width == 32 || width == 64, "Invalid reg width for RETI");
  TASSERT(o.isImm(), "Operand not immediate");

  auto xsp = 32 == width ? X86::ESP : X86::RSP;
  Value *c = CONST_V<width>(b, o.getImm());
  Value *rESP = R_READ<width>(b, xsp);
  Value *ra = M_READ_0<width>(b, rESP);
  TASSERT(ra != NULL, "Could not read value from stack");

  auto xip = 32 == width ? X86::EIP : X86::RIP;
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);
  //add the immediate to ESP
  Value *rESP_1 = BinaryOperator::CreateAdd(rESP, c, "", b);

  //add pointer width to ESP
  Value *nESP = BinaryOperator::CreateAdd(rESP_1, CONST_V<width>(b, width / 8),
                                          "", b);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  //spill all locals into the structure
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
template<size_t width>
static InstTransResult doLoopIMPL(BasicBlock *&b, BasicBlock *T,
                                  BasicBlock *F) {
  TASSERT(T != NULL, "True block is NULL");
  TASSERT(F != NULL, "False block is NULL");

  //retrieve ECX
  auto xcx = 32 == width ? X86::ECX : X86::RCX;

  Value *count = R_READ<width>(b, xcx);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<width>(b, 1), "",
                                               b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst( *b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<width>(b, 0));

  //conditionally branch on this result
  BranchInst::Create(T, F, testRes, b);

  return EndBlock;
}

template<int width>
static InstTransResult doLoopEIMPL(BasicBlock *&b, BasicBlock *T,
                                   BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  auto xcx = 32 == width ? X86::ECX : X86::RCX;
  Value *count = R_READ<width>(b, xcx);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<width>(b, 1), "",
                                               b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst( *b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<width>(b, 0));

  //also test and see if ZF is 1
  Value *zf = F_READ(b, ZF);
  Value *zfRes = new ICmpInst( *b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 1));

  Value *andRes = BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

template<int width>
static InstTransResult doLoopNEIMPL(BasicBlock *&b, BasicBlock *T,
                                    BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  auto xcx = 32 == width ? X86::ECX : X86::RCX;
  Value *count = R_READ<width>(b, xcx);
  //decrement ECX
  Value *count_dec = BinaryOperator::CreateSub(count, CONST_V<width>(b, 1), "",
                                               b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  Value *testRes = new ICmpInst( *b, CmpInst::ICMP_NE, count_dec,
                                CONST_V<width>(b, 0));

  //test and see if ZF is 0
  Value *zf = F_READ(b, ZF);
  Value *zfRes = new ICmpInst( *b, CmpInst::ICMP_EQ, zf, CONST_V<1>(b, 0));

  Value *andRes = BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

static InstTransResult doLoop(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  llvm::Module *M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopIMPL<32>(b, T, F);
  } else {
    return doLoopIMPL<64>(b, T, F);
  }
}

static InstTransResult doLoopE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  llvm::Module *M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopEIMPL<32>(b, T, F);
  } else {
    return doLoopEIMPL<64>(b, T, F);
  }
}

static InstTransResult doLoopNE(BasicBlock *&b, BasicBlock *T, BasicBlock *F) {
  llvm::Module *M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopNEIMPL<32>(b, T, F);
  } else {
    return doLoopNEIMPL<64>(b, T, F);
  }
}

template<int width>
static void writeReturnAddr(BasicBlock *B) {
  auto xsp = 32 == width ? X86::ESP : X86::RSP;
  auto xip = 32 == width ? X86::EIP : X86::RIP;
  Value *espOld = R_READ<width>(B, xsp);
  Value *espSub = BinaryOperator::CreateSub(espOld,
                                            CONST_V<width>(B, width / 8), "",
                                            B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, 0xbadf00d0badbeef0));
  R_WRITE<width>(B, xsp, espSub);
}

template<int width>
static void writeDetachReturnAddr(BasicBlock *B) {
  auto xsp = 32 == width ? X86::ESP : X86::RSP;
  auto xip = 32 == width ? X86::EIP : X86::RIP;
  Value *espOld = R_READ<width>(B, xsp);
  Value *espSub = BinaryOperator::CreateSub(espOld,
                                            CONST_V<width>(B, width / 8), "",
                                            B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, 0xde7accccde7acccc));
  R_WRITE<width>(B, xsp, espSub);
}

static void doCallV(BasicBlock *&block, InstPtr ip, Value *call_addr, bool is_jump) {

  Function *F = block->getParent();
  Module *M = F->getParent();
  auto &C = M->getContext();
  uint32_t bitWidth = ArchPointerSize(M);

  if (_X86_64_ == SystemArch(M)) {
    R_WRITE<64>(block, X86::RIP, call_addr);
    if (!is_jump) {
      writeDetachReturnAddr<64>(block);
    }
  } else {
    R_WRITE<32>(block, X86::EIP, call_addr);
    if (!is_jump) {
      writeDetachReturnAddr<32>(block);
    }
  }

  auto detach = M->getFunction("__mcsema_detach_call_value");
  auto call_detach = CallInst::Create(detach, "", block);
  call_detach->setCallingConv(CallingConv::C);
}

template<int width>
static void doCallM(BasicBlock *&block, InstPtr ip, Value *mem_addr, bool is_jump) {
  Value *call_addr = M_READ<width>(ip, block, mem_addr);
  return doCallV(block, ip, call_addr, is_jump);
}


template<int width>
static llvm::CallInst* emitInternalCall(BasicBlock *&b, Module *M, const std::string &target_fn, bool is_jmp) {
  // we need the parent function to get the regstate argument
  Function *ourF = b->getParent();
  TASSERT(ourF->arg_size() == 1, "");

  // figure out who we are calling
  Function *targetF = M->getFunction(target_fn);
  
  TASSERT(targetF != nullptr, "Could not find target function: "+target_fn);

  // do we need to push a ret addr?
  if (!is_jmp) {
    writeReturnAddr<width>(b);
  }


  // emit: call target_fn(regstate);
  std::vector<Value*> subArgs;
  subArgs.push_back(ourF->arg_begin());
  CallInst *c = CallInst::Create(targetF, subArgs, "", b);
  ArchSetCallingConv(M, c);

  // return ptr to this callinst
  return c;
}

template<int width>
static InstTransResult doCallPC(InstPtr ip, BasicBlock *&b, VA tgtAddr, bool is_jump) {
  Module *M = b->getParent()->getParent();

  //We should be able to look it up in our module.
  std::cout << __FUNCTION__ << "target address : "
            << to_string<VA>(tgtAddr, std::hex) << "\n";
  std::string fname = "sub_" + to_string<VA>(tgtAddr, std::hex);

  CallInst *c = emitInternalCall<width>(b, M, fname, is_jump);
  Function *F = c->getCalledFunction();

  if (ip->has_local_noreturn() || F->doesNotReturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__
              << ": Adding Unreachable Instruction to local noreturn"
              << std::endl;
    c->setDoesNotReturn();
    c->setTailCall();
    Value *unreachable = new UnreachableInst(b->getContext(), b);
    return EndBlock;
  }
  //and we can continue to run the old code

  return ContinueBlock;
}

namespace x86 {
static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target, bool is_jump) {
  Module *M = b->getParent()->getParent();

  //write it into the location pointer to by ESP-4
  Value *espOld = x86::R_READ<32>(b, X86::ESP);

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
  //

  Function *exit_point = ArchAddExitPointDriver(externFunction);

  if (externFunction->getCallingConv() == CallingConv::X86_FastCall) {

    Function::ArgumentListType::iterator it = externFunction->getArgumentList()
        .begin();
    Function::ArgumentListType::iterator end = externFunction->getArgumentList()
        .end();

    Function::ArgumentListType::iterator it_ep = exit_point->getArgumentList()
        .begin();
    Function::ArgumentListType::iterator end_ep = exit_point->getArgumentList()
        .end();

    AttrBuilder B;
    B.addAttribute(Attribute::InReg);

    if (paramCount && it != end) {
      Value *r_ecx = x86::R_READ<32>(b, X86::ECX);
      arguments.push_back(r_ecx);
      --paramCount;
      // set argument 1's attribute: make it in a register
      it->addAttr(AttributeSet::get(it->getContext(), 1, B));
      it_ep->addAttr(AttributeSet::get(it_ep->getContext(), 1, B));
      ++it;
      ++it_ep;
    }

    if (paramCount && it != end) {
      Value *r_edx = x86::R_READ<32>(b, X86::EDX);
      arguments.push_back(r_edx);
      --paramCount;
      // set argument 2's attribute: make it in a register
      it->addAttr(AttributeSet::get(it->getContext(), 2, B));
      it_ep->addAttr(AttributeSet::get(it_ep->getContext(), 2, B));
      ++it;
      ++it_ep;
    }
  }

  if (paramCount) {
    baseEspVal = x86::R_READ<32>(b, X86::ESP);
    // if this is a JMP, there is already a fake return address
    // on the stack. Skip it to read stack arguments
    if(is_jump) {
        baseEspVal = BinaryOperator::CreateAdd(baseEspVal, CONST_V<32>(b, 4), "", b);
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

  if (!is_jump) {
    writeDetachReturnAddr<32>(b);
  }
  CallInst *callR = CallInst::Create(exit_point,
                                     arguments, "", b);
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

  // we returned from an extern: assume it cleared the direction flag
  // which is standard for MS calling conventions
  //
  F_CLEAR(b, DF);

  //if our convention says to keep the call result alive then do it
  //really, we could always keep the call result alive...
  if (rType == Type::getInt32Ty(M->getContext())) {
    x86::R_WRITE<32>(b, X86::EAX, callR);
  }

  return ContinueBlock;
}
}

namespace x86_64 {

static InstTransResult doCallPCExtern(BasicBlock *&b, std::string target, bool is_jump) {
  Module *M = b->getParent()->getParent();

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

  if (SystemOS(M) == llvm::Triple::Win32) {
    if (paramCount && it != end) {
      Type *T = it->getType();
      Value *arg1;
      if (T->isDoubleTy()) {
        int k = x86_64::getRegisterOffset(XMM0);
        Value *arg1FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg1FieldGEPV, "XMM0", b);
        Instruction *GEP_double = CastInst::CreatePointerCast(
            GEP_128, PointerType::get(Type::getDoubleTy(M->getContext()), 0),
            "conv0", b);
        arg1 = new LoadInst(GEP_double, "", b);

      } else {
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
        Value *arg2FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg2FieldGEPV, "XMM1", b);
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
        Value *arg3FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg3FieldGEPV, "XMM2", b);
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
        Value *arg4FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        Instruction *GEP_128 = GetElementPtrInst::CreateInBounds(
            b->getParent()->arg_begin(), arg4FieldGEPV, "XMM3", b);
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

    // The Windows amd64 calling convention requires
    // 32-bytes of stack reserved in each function call. At the call point,
    // the stack is already pre-reserved, so the arguments start 32 bytes up
    // of where we would expect
    if (SystemOS(M) == llvm::Triple::Win32) {
        baseRspVal = BinaryOperator::CreateAdd(baseRspVal, CONST_V<64>(b, 0x20), "", b);
    }

    // if this is a JMP, there is already a fake return address
    // on the stack. Skip it to read stack arguments
    if(is_jump) {
        baseRspVal = BinaryOperator::CreateAdd(baseRspVal, CONST_V<64>(b, 8), "", b);
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

  if (!is_jump) {
    writeDetachReturnAddr<64>(b);
  }

  CallInst *callR = CallInst::Create(ArchAddExitPointDriver(externFunction),
                                     arguments, "", b);
  ArchSetCallingConv(M, callR);

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

template<int width>
static InstTransResult translate_JMPm(NativeModulePtr natM, BasicBlock *& block,
                                      InstPtr ip, MCInst &inst) {
  InstTransResult ret;

  // translate JMP mem64 API calls
  // as a call <api>, ret;

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();

    // this is really an internal call; this calling convention
    // is reserved for functions that we are going to implement internally
    if(ip->get_ext_call_target()->getCallingConvention() == ExternalCodeRef::McsemaCall) {
        Module *M = block->getParent()->getParent();
        std::string target_fn = ArchNameMcsemaCall(s);
        emitInternalCall<width>(block, M, target_fn, true);
        return ContinueBlock;
    }

    if (64 == width) {
      ret = x86_64::doCallPCExtern(block, s, true);
    } else {
      ret = x86::doCallPCExtern(block, s, true);
    }
    if (ret != EndBlock) {
        //doRet<width>(block);
        llvm::ReturnInst::Create(block->getContext(), block);
        return EndBlock;
    } else {
        // the external was a call to donotreturn function
        return ret;
    }
  } else if (ip->has_ext_data_ref()) {
    Module *M = block->getParent()->getParent();

    std::string target = ip->get_ext_data_ref()->getSymbolName();
    llvm::Value *gvar = M->getGlobalVariable(target);

    TASSERT(gvar != NULL, "Could not find data ref: " + target);

    Value *addrInt = new llvm::PtrToIntInst(
        gvar, llvm::Type::getIntNTy(block->getContext(), width), "", block);

    doCallM<width>(block, ip, addrInt, true);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;

  } else if (ip->has_jump_table() && ip->has_mem_reference) {
    // this is a jump table that got converted
    // into a table in the data section
    doJumpTableViaData(natM, block, ip, inst, width);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;

  } else if (ip->has_jump_table()) {
    // this is a conformant jump table
    // emit an llvm switch
    doJumpTableViaSwitch(natM, block, ip, inst, width);
    return EndBlock;

  } else if (ip->has_mem_reference) {
    doCallM<width>(block, ip, MEM_REFERENCE(0), true);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;
  } else {
    // normal jump by memory (e.g. jmp [reg+offset] )
    doCallM<width>(block, ip, ADDR_NOREF(0), true);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;
  }
}

template<int width>
static InstTransResult translate_JMPr(NativeModulePtr natM, BasicBlock *&block,
                                      InstPtr ip, MCInst &inst) {
  const MCOperand &tgtOp = inst.getOperand(0);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  Value *fromReg = R_READ<width>(block, tgtOp.getReg());

  Module *M = block->getParent()->getParent();

  VA ot_addr = ip->offset_table;

  // does this inst have an offset table?
  if (ot_addr != -1) {
    auto ot_value = natM->offsetTables.find(ot_addr);
    TASSERT(
        ot_value != natM->offsetTables.end(),
        "Could not find offset table for addr:"
            + to_string<VA>(ot_addr, std::hex));
    if (ot_value != natM->offsetTables.end()) {
      llvm::dbgs() << __FUNCTION__ << ": We have an offset table for: "
                   << to_string<VA>(ip->get_loc(), std::hex) << " at: "
                   << to_string<VA>(ot_addr, std::hex) << "\n";

      VA data_section = 0;
      MCSOffsetTablePtr ot = ot_value->second;
      VA old_table_addr = ot->getStartAddr();
      Value *global_v = getGlobalFromOriginalAddr<width>(old_table_addr, natM,
                                                         0, block);
      TASSERT(
          global_v != nullptr,
          "Could not find global for addr:"
              + to_string<VA>(old_table_addr, std::hex));

      if (global_v != nullptr) {
        BasicBlock *defaultb = nullptr;
        doJumpOffsetTableViaSwitchReg(block, ip, fromReg, defaultb, global_v,
                                      ot);
        // add trap to default block
        Function *trapIntrin = Intrinsic::getDeclaration(M, Intrinsic::trap);
        CallInst::Create(trapIntrin, "", defaultb);
        Value *unreachable = new UnreachableInst(defaultb->getContext(),
                                                 defaultb);
        return EndCFG;
      }
    }
  }

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
    if (width == 64 && shouldSubtractImageBase(M)) {
      minus_base = doSubtractImageBaseInt(fromReg, block);
    } else {
      minus_base = fromReg;
    }
    // end terrible HACK
    doJumpTableViaSwitchReg(block, ip, minus_base, defaultb, width);
    TASSERT(defaultb != nullptr, "Default block has to exit");
    // fallback to doing do_call_value
    doCallV(defaultb, ip, fromReg, true);
    ReturnInst::Create(defaultb->getContext(), defaultb);
    return EndCFG;

  } else {
    // translate the JMP64r as a call/ret
    llvm::dbgs() << __FUNCTION__ << ": regular jump via register: "
                 << to_string<VA>(ip->get_loc(), std::hex) << "\n";
    doCallV(block, ip, fromReg, true);
    ReturnInst::Create(block->getContext(), block);
    return EndCFG;
  }
}

template<int width>
static InstTransResult translate_CALLpcrel32(NativeModulePtr natM,
                                             BasicBlock *& block, InstPtr ip,
                                             MCInst &inst) {
  InstTransResult ret;

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();
    if(ip->get_ext_call_target()->getCallingConvention() == ExternalCodeRef::McsemaCall) {
        Module *M = block->getParent()->getParent();
        std::string target_fn = ArchNameMcsemaCall(s);
        emitInternalCall<width>(block, M, target_fn, false);
        return ContinueBlock;
    } else {
      llvm::dbgs() << __FUNCTION__ << ": function is: " << s << ", cc is: "
                   << ip->get_ext_call_target()->getCallingConvention() << "\n";       
    }
    if (width == 64) {
      ret = x86_64::doCallPCExtern(block, s, false);
    } else {
      ret = x86::doCallPCExtern(block, s, false);
    }
  } else if (ip->has_code_ref()) {
    int64_t off = (int64_t) ip->get_reference(Inst::MEMRef);
    ret = doCallPC<width>(ip, block, off, false);
  } else {
    int64_t off = (int64_t) OP(0).getImm();
    ret = doCallPC<width>(ip, block, ip->get_loc() + ip->get_len() + off, false);
  }

  return ret;
}

template<int width>
static InstTransResult translate_CALLm(NativeModulePtr natM,
                                       BasicBlock *& block, InstPtr ip,
                                       MCInst &inst) {
  InstTransResult ret;

  // is this an external call?
  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();

    // this is really an internal call; this calling convention
    // is reserved for functions that we are going to implement internally
    if(ip->get_ext_call_target()->getCallingConvention() == ExternalCodeRef::McsemaCall) {
        Module *M = block->getParent()->getParent();
        std::string target_fn = ArchNameMcsemaCall(s);
        emitInternalCall<width>(block, M, target_fn, false);
        return ContinueBlock;
    }

    if (width == 64) {
      ret = x86_64::doCallPCExtern(block, s, false);
    } else {
      ret = x86::doCallPCExtern(block, s, false);
    }

    // not external call, but some weird way of calling local function?
  } else if (ip->has_code_ref()) {
    cout << __FUNCTION__ << ":" << __LINE__ << ": doing call" << std::endl;
    doCallPC<width>(ip, block, ip->get_reference(Inst::MEMRef), false);
  }
  // is this referencing global data?
  else if (ip->has_mem_reference) {
    doCallM<width>(block, ip, MEM_REFERENCE(0), false);
    ret = ContinueBlock;
    // is this a simple address computation?
  } else {
    doCallM<width>(block, ip, ADDR_NOREF(0), false);
    ret = ContinueBlock;
  }

  return ret;
}

template<int width>
static InstTransResult translate_CALLr(NativeModulePtr natM, BasicBlock *&block,
                                       InstPtr ip, MCInst &inst) {
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

  doCallV(block, ip, fromReg, false);

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
GENERIC_TRANSLATION(RETI, doRetI<32>(block, OP(0)))
GENERIC_TRANSLATION(RETIW, doRetI<16>(block, OP(0)))
GENERIC_TRANSLATION(RETQ, doRet<64>(block))
GENERIC_TRANSLATION(RETIQ, doRetI<64>(block, OP(0)))

GENERIC_TRANSLATION(LRET, doLRet<32>(block))


BLOCKNAMES_TRANSLATION(JMP_4, doNonCondBranch(block, ifTrue))
BLOCKNAMES_TRANSLATION(JMP_2, doNonCondBranch(block, ifTrue))
BLOCKNAMES_TRANSLATION(JMP_1, doNonCondBranch(block, ifTrue))

void Branches_populateDispatchMap(DispatchMap &m) {
  m[X86::JMP32r] = (translate_JMPr<32> );
  m[X86::JMP32m] = (translate_JMPm<32> );
  m[X86::JMP64r] = (translate_JMPr<64> );
  m[X86::JMP64m] = (translate_JMPm<64> );

  m[X86::JMP_4] = translate_JMP_4;
  m[X86::JMP_2] = translate_JMP_2;
  m[X86::JMP_1] = translate_JMP_1;

  m[X86::CALLpcrel32] = (translate_CALLpcrel32<32> );
  m[X86::CALL64pcrel32] = (translate_CALLpcrel32<64> );
  m[X86::CALL32m] = (translate_CALLm<32> );
  m[X86::CALL64m] = (translate_CALLm<64> );
  m[X86::CALL32r] = (translate_CALLr<32> );
  m[X86::CALL64r] = (translate_CALLr<64> );

  m[X86::LOOP] = translate_LOOP;
  m[X86::LOOPE] = translate_LOOPE;
  m[X86::LOOPNE] = translate_LOOPNE;
  m[X86::RETL] = translate_RET;
  m[X86::RETIL] = translate_RETI;
  m[X86::RETQ] = translate_RETQ;
  m[X86::RETIQ] = translate_RETIQ;
  m[X86::RETIW] = translate_RETIW;


  m[X86::LRETL] = translate_LRET;
}
