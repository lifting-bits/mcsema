/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or
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

#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include <llvm/MC/MCInst.h>

#include <llvm/Support/CodeGen.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Dispatch.h"
#include "mcsema/Arch/Register.h"

#include "mcsema/Arch/X86/Util.h"
#include "mcsema/Arch/X86/Semantics/Branches.h"

#include "mcsema/CFG/Externals.h"
#include "mcsema/BC/Util.h"
#include "mcsema/cfgToLLVM/JumpTables.h"

template<int width>
static InstTransResult doLRet(llvm::BasicBlock *b) {
  //do a read from the location pointed to by ESP

  TASSERT(width == 32 || width == 64, "Invalid reg width for RET");
  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto rESP = R_READ<width>(b, xsp);
  auto nESP = llvm::BinaryOperator::CreateAdd(rESP,
                                              CONST_V<width>(b, 2 * width / 8),
                                              "", b);

  auto xip = 32 == width ? llvm::X86::EIP : llvm::X86::RIP;
  auto ra = M_READ_0<width>(b, rESP);
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  llvm::ReturnInst::Create(b->getContext(), b);

  return EndCFG;
}

template<int width>
static InstTransResult doRet(llvm::BasicBlock *b) {
  //do a read from the location pointed to by ESP

  TASSERT(width == 32 || width == 64, "Invalid reg width for RET");
  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto rESP = R_READ<width>(b, xsp);
  auto nESP = llvm::BinaryOperator::CreateAdd(rESP,
                                              CONST_V<width>(b, width / 8), "",
                                              b);

  auto xip = 32 == width ? llvm::X86::EIP : llvm::X86::RIP;
  auto ra = M_READ_0<width>(b, rESP);
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  llvm::ReturnInst::Create(b->getContext(), b);

  return EndCFG;
}

template<int width>
static InstTransResult doRetI(llvm::BasicBlock *&b, const llvm::MCOperand &o) {
  TASSERT(width == 32 || width == 64, "Invalid reg width for RETI");
  TASSERT(o.isImm(), "Operand not immediate");

  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto c = CONST_V<width>(b, o.getImm());
  auto rESP = R_READ<width>(b, xsp);
  auto ra = M_READ_0<width>(b, rESP);
  TASSERT(ra != NULL, "Could not read value from stack");

  auto xip = 32 == width ? llvm::X86::EIP : llvm::X86::RIP;
  // set EIP -- this is used by the asm stubs that
  // connect translated code and native code
  R_WRITE<width>(b, xip, ra);
  //add the immediate to ESP
  auto rESP_1 = llvm::BinaryOperator::CreateAdd(rESP, c, "", b);

  //add pointer width to ESP
  auto nESP = llvm::BinaryOperator::CreateAdd(rESP_1,
                                              CONST_V<width>(b, width / 8), "",
                                              b);

  //write back to ESP
  R_WRITE<width>(b, xsp, nESP);

  //spill all locals into the structure
  llvm::ReturnInst::Create(b->getContext(), b);
  return EndCFG;
}

//emit a nonconditional branch
static InstTransResult doNonCondBranch(llvm::BasicBlock *&b,
                                       llvm::BasicBlock *tgt) {
  TASSERT(tgt != NULL, "Branch to a NULL target");

  llvm::BranchInst::Create(tgt, b);

  return EndBlock;
}

//for the LOOP class of instructions, we'll assume that the
//target of the loop branch has already been defined as a block
template<size_t width>
static InstTransResult doLoopIMPL(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                                  llvm::BasicBlock *F) {
  TASSERT(T != NULL, "True block is NULL");
  TASSERT(F != NULL, "False block is NULL");

  //retrieve ECX
  auto xcx = 32 == width ? llvm::X86::ECX : llvm::X86::RCX;

  auto count = R_READ<width>(b, xcx);
  //decrement ECX
  auto count_dec = llvm::BinaryOperator::CreateSub(count, CONST_V<width>(b, 1),
                                                   "", b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  auto testRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, count_dec,
                                    CONST_V<width>(b, 0));

  //conditionally branch on this result
  llvm::BranchInst::Create(T, F, testRes, b);

  return EndBlock;
}

template<int width>
static InstTransResult doLoopEIMPL(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                                   llvm::BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  auto xcx = 32 == width ? llvm::X86::ECX : llvm::X86::RCX;
  auto count = R_READ<width>(b, xcx);
  //decrement ECX
  auto count_dec = llvm::BinaryOperator::CreateSub(count, CONST_V<width>(b, 1),
                                                   "", b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  auto testRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, count_dec,
                                    CONST_V<width>(b, 0));

  //also test and see if ZF is 1
  auto zf = F_READ(b, llvm::X86::ZF);
  auto zfRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, zf,
                                  CONST_V<1>(b, 1));

  auto andRes = llvm::BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  llvm::BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

template<int width>
static InstTransResult doLoopNEIMPL(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                                    llvm::BasicBlock *F) {
  TASSERT(T != NULL, "");
  TASSERT(F != NULL, "");

  //retrieve ECX
  auto xcx = 32 == width ? llvm::X86::ECX : llvm::X86::RCX;
  auto count = R_READ<width>(b, xcx);
  //decrement ECX
  auto count_dec = llvm::BinaryOperator::CreateSub(count, CONST_V<width>(b, 1),
                                                   "", b);
  //write ECX back into the register
  R_WRITE<width>(b, xcx, count_dec);

  //test and see if ECX is 0
  auto testRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_NE, count_dec,
                                    CONST_V<width>(b, 0));

  //test and see if ZF is 0
  auto zf = F_READ(b, llvm::X86::ZF);
  auto zfRes = new llvm::ICmpInst( *b, llvm::CmpInst::ICMP_EQ, zf,
                                  CONST_V<1>(b, 0));

  auto andRes = llvm::BinaryOperator::CreateAnd(zfRes, testRes, "", b);
  //conditionally branch on this result
  llvm::BranchInst::Create(T, F, andRes, b);

  return EndBlock;
}

static InstTransResult doLoop(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                              llvm::BasicBlock *F) {
  auto M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopIMPL<32>(b, T, F);
  } else {
    return doLoopIMPL<64>(b, T, F);
  }
}

static InstTransResult doLoopE(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                               llvm::BasicBlock *F) {
  auto M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopEIMPL<32>(b, T, F);
  } else {
    return doLoopEIMPL<64>(b, T, F);
  }
}

static InstTransResult doLoopNE(llvm::BasicBlock *&b, llvm::BasicBlock *T,
                                llvm::BasicBlock *F) {
  auto M = b->getParent()->getParent();

  if (ArchPointerSize(M) == Pointer32) {
    return doLoopNEIMPL<32>(b, T, F);
  } else {
    return doLoopNEIMPL<64>(b, T, F);
  }
}

template<int width>
static void writeReturnAddr(llvm::BasicBlock *B, VA ret_addr) {
  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto espOld = R_READ<width>(B, xsp);
  auto espSub = llvm::BinaryOperator::CreateSub(espOld,
                                                CONST_V<width>(B, width / 8),
                                                "", B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, ret_addr));
  R_WRITE<width>(B, xsp, espSub);
}

template<int width>
static void writeDetachReturnAddr(llvm::BasicBlock *B) {
  auto xsp = 32 == width ? llvm::X86::ESP : llvm::X86::RSP;
  auto xip = 32 == width ? llvm::X86::EIP : llvm::X86::RIP;
  auto espOld = R_READ<width>(B, xsp);
  auto espSub = llvm::BinaryOperator::CreateSub(espOld,
                                                CONST_V<width>(B, width / 8),
                                                "", B);
  M_WRITE_0<width>(B, espSub, CONST_V<width>(B, 0xde7accccde7acccc));
  R_WRITE<width>(B, xsp, espSub);
}

static void doCallV(llvm::BasicBlock *&block, NativeInstPtr ip,
                    llvm::Value *call_addr, bool is_jump) {

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
    R_WRITE<32>(block, llvm::X86::EIP, call_addr);
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
                    llvm::Value *mem_addr, bool is_jump) {
  auto call_addr = M_READ<width>(ip, block, mem_addr);
  return doCallV(block, ip, call_addr, is_jump);
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
      b, M, fname, ip->get_loc() + ip->get_len(), is_jump);
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

namespace x86 {
static InstTransResult doCallPCExtern(llvm::BasicBlock *&b, std::string target,
                                      bool is_jump) {
  auto M = b->getParent()->getParent();
  auto &C = M->getContext();

  //write it into the location pointer to by ESP-4
  auto espOld = x86::R_READ<32>(b, llvm::X86::ESP);

  //lookup the function in the module
  auto externFunction = M->getFunction(target);
  TASSERT(externFunction != nullptr,
          "Could not find external function: " + target);
  auto externFunctionTy = externFunction->getFunctionType();
  auto rType = externFunction->getReturnType();
  int paramCount = externFunctionTy->getNumParams();

  //now we need to do a series of reads off the stack, essentially
  //a series of POPs but without writing anything back to ESP
  llvm::Value *baseEspVal = nullptr;
  std::vector<llvm::Value *> arguments;

  // in fastcall, the first two params are passed via register
  // only need to adjust stack if there are more than two args
  //

  auto exit_point = ArchAddExitPointDriver(externFunction);

  if (externFunction->getCallingConv() == llvm::CallingConv::X86_FastCall) {

    auto it = externFunction->arg_begin();
    auto end = externFunction->arg_end();

    auto it_ep = exit_point->arg_begin();
    auto end_ep = exit_point->arg_end();

    llvm::AttrBuilder B;
    B.addAttribute(llvm::Attribute::InReg);

    if (paramCount && it != end) {
      auto r_ecx = x86::R_READ<32>(b, llvm::X86::ECX);
      arguments.push_back(r_ecx);
      --paramCount;
      // set argument 1's attribute: make it in a register
      it->addAttr(llvm::AttributeSet::get(C, 1, B));
      it_ep->addAttr(llvm::AttributeSet::get(C, 1, B));
      ++it;
      ++it_ep;
    }

    if (paramCount && it != end) {
      auto r_edx = x86::R_READ<32>(b, llvm::X86::EDX);
      arguments.push_back(r_edx);
      --paramCount;
      // set argument 2's attribute: make it in a register
      it->addAttr(llvm::AttributeSet::get(C, 2, B));
      it_ep->addAttr(llvm::AttributeSet::get(C, 2, B));
      ++it;
      ++it_ep;
    }
  }

  if (paramCount) {
    baseEspVal = x86::R_READ<32>(b, llvm::X86::ESP);
    // if this is a JMP, there is already a fake return address
    // on the stack. Skip it to read stack arguments
    if (is_jump) {
      baseEspVal = llvm::BinaryOperator::CreateAdd(baseEspVal,
                                                   CONST_V<32>(b, 4), "", b);
    }
  }

  for (int i = 0; i < paramCount; i++) {
    auto vFromStack = M_READ_0<32>(b, baseEspVal);

    arguments.push_back(vFromStack);

    if (i + 1 != paramCount) {
      baseEspVal = llvm::BinaryOperator::CreateAdd(baseEspVal,
                                                   CONST_V<32>(b, 4), "", b);
    }
  }

  if ( !is_jump) {
    writeDetachReturnAddr<32>(b);
  }
  auto callR = llvm::CallInst::Create(exit_point, arguments, "", b);
  callR->setCallingConv(externFunction->getCallingConv());

  noAliasMCSemaScope(callR);

  if (externFunction->doesNotReturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__ << ": Adding Unreachable Instruction"
              << std::endl;
    callR->setDoesNotReturn();
    callR->setTailCall();
    (void) new llvm::UnreachableInst(b->getContext(), b);
    return EndBlock;
  }

  // we returned from an extern: assume it cleared the direction flag
  // which is standard for MS calling conventions
  //
  F_CLEAR(b, llvm::X86::DF);

  //if our convention says to keep the call result alive then do it
  //really, we could always keep the call result alive...
  if (rType == llvm::Type::getInt32Ty(M->getContext())) {
    x86::R_WRITE<32>(b, llvm::X86::EAX, callR);
  }

  return ContinueBlock;
}
}

namespace x86_64 {

static InstTransResult doCallPCExtern(llvm::BasicBlock *&b, std::string target,
                                      bool is_jump) {
  auto F = b->getParent();
  auto M = F->getParent();
  auto &C = M->getContext();
  llvm::Argument *state_ptr = &*F->arg_begin();

  //lookup the function in the module
  auto externFunction = M->getFunction(target);
  TASSERT(externFunction != nullptr,
          "Could not find external function: " + target);
  auto externFunctionTy = externFunction->getFunctionType();
  auto rType = externFunction->getReturnType();
  int paramCount = externFunctionTy->getNumParams();
  //std::string 	funcSign = externFunction->getSignature();

  std::cout << __FUNCTION__ << " paramCount  : " << paramCount << " : "
            << target << std::endl;
  std::cout << externFunctionTy->getNumParams() << " : "
            << std::hex << ((VA) externFunctionTy->getParamType(0))
            << std::endl;
  std::cout.flush();

  //now we need to do a series of reads off the stack, essentially
  //a series of POPs but without writing anything back to ESP
  llvm::Value *baseRspVal = nullptr;
  std::vector<llvm::Value *> arguments;

  // on x86_64 platform all calls will be x86_64_SysV
  auto it = externFunction->arg_begin();
  auto end = externFunction->arg_end();
  llvm::AttrBuilder B;
  B.addAttribute(llvm::Attribute::InReg);

  if (SystemOS(M) == llvm::Triple::Win32) {
    if (paramCount && it != end) {
      auto T = it->getType();
      llvm::Value *arg1 = nullptr;
      if (T->isDoubleTy()) {
        int k = ArchRegisterOffset(llvm::X86::XMM0);
        llvm::Value *arg1FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        auto GEP_128 = llvm::GetElementPtrInst::CreateInBounds(
            state_ptr, arg1FieldGEPV, "XMM0", b);
        auto GEP_double = llvm::CastInst::CreatePointerCast(
            GEP_128,
            llvm::PointerType::get(llvm::Type::getDoubleTy(M->getContext()), 0),
            "conv0", b);
        arg1 = new llvm::LoadInst(GEP_double, "", b);

      } else {
        arg1 = x86_64::R_READ<64>(b, llvm::X86::RCX);
      }

      arguments.push_back(arg1);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 1, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto T = it->getType();
      llvm::Value *arg2 = nullptr;
      if (T->isDoubleTy()) {
        int k = ArchRegisterOffset(llvm::X86::XMM1);
        llvm::Value *arg2FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        auto GEP_128 = llvm::GetElementPtrInst::CreateInBounds(
            state_ptr, arg2FieldGEPV, "XMM1", b);
        auto GEP_double = llvm::CastInst::CreatePointerCast(
            GEP_128,
            llvm::PointerType::get(llvm::Type::getDoubleTy(M->getContext()), 0),
            "conv1", b);
        arg2 = new llvm::LoadInst(GEP_double, "", b);
      } else {
        arg2 = x86_64::R_READ<64>(b, llvm::X86::RDX);
      }
      arguments.push_back(arg2);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 2, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto T = it->getType();
      llvm::Value *arg3 = nullptr;
      if (T->isDoubleTy()) {
        int k = ArchRegisterOffset(llvm::X86::XMM2);
        llvm::Value *arg3FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        auto GEP_128 = llvm::GetElementPtrInst::CreateInBounds(
            state_ptr, arg3FieldGEPV, "XMM2", b);
        auto GEP_double = llvm::CastInst::CreatePointerCast(
            GEP_128,
            llvm::PointerType::get(llvm::Type::getDoubleTy(M->getContext()), 0),
            "conv2", b);
        arg3 = new llvm::LoadInst(GEP_double, "", b);
      } else {
        arg3 = x86_64::R_READ<64>(b, llvm::X86::R8);
      }
      arguments.push_back(arg3);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 3, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto T = it->getType();
      llvm::Value *arg4 = nullptr;
      if (T->isDoubleTy()) {
        int k = ArchRegisterOffset(llvm::X86::XMM3);
        llvm::Value *arg4FieldGEPV[] = {CONST_V<64>(b, 0), CONST_V<32>(b, k)};

        auto GEP_128 = llvm::GetElementPtrInst::CreateInBounds(
            state_ptr, arg4FieldGEPV, "XMM3", b);
        auto GEP_double = llvm::CastInst::CreatePointerCast(
            GEP_128,
            llvm::PointerType::get(llvm::Type::getDoubleTy(M->getContext()), 0),
            "conv3", b);
        arg4 = new llvm::LoadInst(GEP_double, "", b);
      } else {
        arg4 = x86_64::R_READ<64>(b, llvm::X86::R9);
      }
      arguments.push_back(arg4);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 4, B));
      ++it;
    }
  } else {
    if (paramCount && it != end) {
      // fix it by updating the value type
      auto reg_rdi = x86_64::R_READ<64>(b, llvm::X86::RDI);
      arguments.push_back(reg_rdi);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 1, B));
      ++it;

    }

    if (paramCount && it != end) {
      auto reg_rsi = x86_64::R_READ<64>(b, llvm::X86::RSI);
      arguments.push_back(reg_rsi);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 2, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto reg_rdx = x86_64::R_READ<64>(b, llvm::X86::RDX);
      arguments.push_back(reg_rdx);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 3, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto reg_rcx = x86_64::R_READ<64>(b, llvm::X86::RCX);
      arguments.push_back(reg_rcx);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 4, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto reg_r8 = x86_64::R_READ<64>(b, llvm::X86::R8);
      arguments.push_back(reg_r8);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 5, B));
      ++it;
    }

    if (paramCount && it != end) {
      auto reg_r9 = x86_64::R_READ<64>(b, llvm::X86::R9);
      arguments.push_back(reg_r9);
      --paramCount;
      it->addAttr(llvm::AttributeSet::get(C, 6, B));
      ++it;
    }
  }

  if (paramCount) {
    // rest of the arguments are passed over stack
    // adjust the stack pointer if required
    baseRspVal = x86_64::R_READ<64>(b, llvm::X86::RSP);

    // The Windows amd64 calling convention requires
    // 32-bytes of stack reserved in each function call. At the call point,
    // the stack is already pre-reserved, so the arguments start 32 bytes up
    // of where we would expect
    if (SystemOS(M) == llvm::Triple::Win32) {
      baseRspVal = llvm::BinaryOperator::CreateAdd(baseRspVal,
                                                   CONST_V<64>(b, 0x20), "", b);
    }

    // if this is a JMP, there is already a fake return address
    // on the stack. Skip it to read stack arguments
    if (is_jump) {
      baseRspVal = llvm::BinaryOperator::CreateAdd(baseRspVal,
                                                   CONST_V<64>(b, 8), "", b);
    }
  }

  for (int i = 0; i < paramCount; i++) {
    auto vFromStack = M_READ_0<64>(b, baseRspVal);

    arguments.push_back(vFromStack);

    if (i + 1 != paramCount) {
      baseRspVal = llvm::BinaryOperator::CreateAdd(baseRspVal,
                                                   CONST_V<64>(b, 8), "", b);
    }
  }

  if ( !is_jump) {
    writeDetachReturnAddr<64>(b);
  }

  auto callR = llvm::CallInst::Create(ArchAddExitPointDriver(externFunction),
                                      arguments, "", b);
  ArchSetCallingConv(M, callR);

  if (externFunction->doesNotReturn()) {
    // noreturn functions just hit unreachable
    std::cout << __FUNCTION__ << ": Adding Unreachable Instruction"
              << std::endl;
    callR->setDoesNotReturn();
    callR->setTailCall();
    (void) new llvm::UnreachableInst(b->getContext(), b);
    return EndBlock;
  }

  //if our convention says to keep the call result alive then do it
  //really, we could always keep the call result alive...
  if (rType == llvm::Type::getInt64Ty(M->getContext())) {
    x86_64::R_WRITE<64>(b, llvm::X86::RAX, callR);
  }

  return ContinueBlock;
}

}

template<int width>
static InstTransResult translate_JMPm(TranslationContext &ctx,
                                      llvm::BasicBlock *& block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  // translate JMP mem64 API calls
  // as a call <api>, ret;

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();

    // this is really an internal call; this calling convention
    // is reserved for functions that we are going to implement internally
    if (ip->get_ext_call_target()->getCallingConvention()
        == ExternalCodeRef::McsemaCall) {
      auto M = block->getParent()->getParent();
      std::string target_fn = ArchNameMcSemaCall(s);
      emitInternalCall<width>(
          block, M, target_fn, ip->get_loc() + ip->get_len(), true);
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
    auto M = block->getParent()->getParent();

    std::string target = ip->get_ext_data_ref()->getSymbolName();
    llvm::Value *gvar = M->getGlobalVariable(target);

    TASSERT(gvar != NULL, "Could not find data ref: " + target);

    auto addrInt = new llvm::PtrToIntInst(
        gvar, llvm::Type::getIntNTy(block->getContext(), width), "", block);

    doCallM<width>(block, ip, addrInt, true);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;

  } else if (ip->has_jump_table() && ip->has_mem_reference) {
    // this is a jump table that got converted
    // into a table in the data section
    doJumpTableViaData(ctx, block, width);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndBlock;

  } else if (ip->has_jump_table()) {
    // this is a conformant jump table
    // emit an llvm switch
    doJumpTableViaSwitch(ctx, block, width);
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
static InstTransResult translate_JMPr(TranslationContext &ctx,
                                      llvm::BasicBlock *&block) {
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const auto &tgtOp = inst.getOperand(0);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  auto fromReg = R_READ<width>(block, tgtOp.getReg());

  auto M = block->getParent()->getParent();

  VA ot_addr = ip->offset_table;

  // does this inst have an offset table?
  if (ot_addr != -1) {
    auto ot_value = ctx.natM->offset_tables.find(ot_addr);


    if (ot_value != ctx.natM->offset_tables.end()) {
      std::cerr
          << __FUNCTION__ << ": We have an offset table for: "
          << std::hex << ip->get_loc() << " at: "
          << std::hex << ot_addr << std::endl;

      VA data_section = 0;
      MCSOffsetTablePtr ot = ot_value->second;
      VA old_table_addr = ot->getStartAddr();
      auto global_v = getGlobalFromOriginalAddr<width>(old_table_addr, ctx.natM,
                                                       0, block);

      if (global_v) {
        llvm::BasicBlock *defaultb = nullptr;
        doJumpOffsetTableViaSwitchReg(ctx, block, fromReg, defaultb, global_v,
                                      ot);
        // add trap to default block
        auto trapIntrin = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trap);
        llvm::CallInst::Create(trapIntrin, "", defaultb);
        (void) new llvm::UnreachableInst(defaultb->getContext(), defaultb);
        return EndCFG;

      } else {
        std::cerr
            << "Could not find global for addr: "
            << std::hex << old_table_addr << std::endl;
        TASSERT(false, "");
      }
    } else {
      std::cerr
          << "Could not find offset table for addr: "
          << std::hex << ot_addr << std::endl;
      TASSERT(false, "");
    }
  }

  if (ip->has_jump_table()) {
    // this is a jump table that got converted
    // into a table in the data section
    std::cerr
        << __FUNCTION__ << ": jump table via register: "
        << std::hex << ip->get_loc() << std::endl;

    llvm::BasicBlock *defaultb = nullptr;

    // Terrible HACK
    // Subtract image base since we assume win64 adds it for jump
    // tables. This may not always be true.
    llvm::Value *minus_base = nullptr;
    if (width == 64 && shouldSubtractImageBase(M)) {
      minus_base = doSubtractImageBaseInt(fromReg, block);
    } else {
      minus_base = fromReg;
    }
    // end terrible HACK
    doJumpTableViaSwitchReg(ctx, block, minus_base, defaultb, width);
    TASSERT(defaultb != nullptr, "Default block has to exit");
    // fallback to doing do_call_value
    doCallV(defaultb, ip, fromReg, true);
    llvm::ReturnInst::Create(defaultb->getContext(), defaultb);
    return EndCFG;

  } else {
    // translate the JMP64r as a call/ret
    std::cerr
        << __FUNCTION__ << ": regular jump via register: "
        << std::hex << ip->get_loc() << std::endl;

    doCallV(block, ip, fromReg, true);
    llvm::ReturnInst::Create(block->getContext(), block);
    return EndCFG;
  }
}

template<int width>
static InstTransResult translate_CALLpcrel32(TranslationContext &ctx,
                                             llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();
    if (ip->get_ext_call_target()->getCallingConvention()
        == ExternalCodeRef::McsemaCall) {
      auto M = block->getParent()->getParent();
      std::string target_fn = ArchNameMcSemaCall(s);
      emitInternalCall<width>(
          block, M, target_fn, ip->get_loc() + ip->get_len(), false);
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
    VA off = ip->get_reference(NativeInst::MEMRef);
    ret = doCallPC<width>(ip, block, off, false);
  } else {
    VA off = OP(0).getImm();
    ret = doCallPC<width>(ip, block, ip->get_loc() + ip->get_len() + off,
                          false);
  }

  return ret;
}

template<int width>
static InstTransResult translate_CALLm(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  InstTransResult ret;
  auto natM = ctx.natM;
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();

  // is this an external call?
  if (ip->has_ext_call_target()) {
    std::string s = ip->get_ext_call_target()->getSymbolName();

    // this is really an internal call; this calling convention
    // is reserved for functions that we are going to implement internally
    if (ip->get_ext_call_target()->getCallingConvention()
        == ExternalCodeRef::McsemaCall) {
      auto M = block->getParent()->getParent();
      std::string target_fn = ArchNameMcSemaCall(s);
      emitInternalCall<width>(
          block, M, target_fn, ip->get_loc() + ip->get_len(), false);
      return ContinueBlock;
    }

    if (width == 64) {
      ret = x86_64::doCallPCExtern(block, s, false);
    } else {
      ret = x86::doCallPCExtern(block, s, false);
    }

    // not external call, but some weird way of calling local function?
  } else if (ip->has_code_ref()) {
    std::cout << __FUNCTION__ << ":" << __LINE__ << ": doing call" << std::endl;
    doCallPC<width>(ip, block, ip->get_reference(NativeInst::MEMRef), false);
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
static InstTransResult translate_CALLr(TranslationContext &ctx,
                                       llvm::BasicBlock *&block) {
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  const auto &tgtOp = inst.getOperand(0);
  //we are calling a register! this is VERY EXCITING
  //first, we need to know which register we are calling. read that
  //register, then make a call to the external procedure.
  //the external procedure has a signature of
  // void do_call_value(Value *loc, struct regs *r);

  TASSERT(inst.getNumOperands() == 1, "");
  TASSERT(tgtOp.isReg(), "");

  //read the register
  auto fromReg = R_READ<width>(block, tgtOp.getReg());
  doCallV(block, ip, fromReg, false);
  return ContinueBlock;
}

#define BLOCKNAMES_TRANSLATION(NAME, THECALL) static InstTransResult translate_ ## NAME (TranslationContext &ctx, llvm::BasicBlock *&block) {\
    auto F = block->getParent(); \
    auto ip = ctx.natI; \
    auto ifTrue = ctx.va_to_bb[ip->get_tr()]; \
    auto ifFalse = ctx.va_to_bb[ip->get_fa()]; \
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
  m[llvm::X86::JMP32r] = translate_JMPr<32>;
  m[llvm::X86::JMP32m] = translate_JMPm<32>;
  m[llvm::X86::JMP64r] = translate_JMPr<64>;
  m[llvm::X86::JMP64m] = translate_JMPm<64>;

  m[llvm::X86::JMP_4] = translate_JMP_4;
  m[llvm::X86::JMP_2] = translate_JMP_2;
  m[llvm::X86::JMP_1] = translate_JMP_1;

  m[llvm::X86::CALLpcrel32] = (translate_CALLpcrel32<32> );
  m[llvm::X86::CALL64pcrel32] = (translate_CALLpcrel32<64> );
  m[llvm::X86::CALL32m] = translate_CALLm<32>;
  m[llvm::X86::CALL64m] = translate_CALLm<64>;
  m[llvm::X86::CALL32r] = translate_CALLr<32>;
  m[llvm::X86::CALL64r] = translate_CALLr<64>;

  m[llvm::X86::LOOP] = translate_LOOP;
  m[llvm::X86::LOOPE] = translate_LOOPE;
  m[llvm::X86::LOOPNE] = translate_LOOPNE;
  m[llvm::X86::RETL] = translate_RET;
  m[llvm::X86::RETIL] = translate_RETI;
  m[llvm::X86::RETQ] = translate_RETQ;
  m[llvm::X86::RETIQ] = translate_RETIQ;
  m[llvm::X86::RETIW] = translate_RETIW;

  m[llvm::X86::LRETL] = translate_LRET;
}
