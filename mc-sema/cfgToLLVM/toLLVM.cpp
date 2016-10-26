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
#include "toLLVM.h"
#include "raiseX86.h"
#include "InstructionDispatch.h"
#include "ArchOps.h"
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/InstrTypes.h>
#include <cstdio>

using namespace llvm;
using namespace std;

StructType *g_RegStruct;
PointerType *g_PRegStruct;

FunctionType *getBaseFunctionType(Module *M) {
  vector<Type *> baseFunctionArgs;
  baseFunctionArgs.push_back(g_PRegStruct);
  FunctionType *funcTy = FunctionType::get(Type::getVoidTy(M->getContext()),
                                           baseFunctionArgs, false);
  TASSERT(funcTy != NULL, "");

  return funcTy;
}

Triple *getTargetTriple(const llvm::Target *T) {
  if (T->getName() == "x86")
    return new Triple("i386", "unknown", "unknown");
  else if (T->getName() == "x86-64")
    return new Triple("x86_64", "unknown", "unknown");
}

void initRegStateStruct(Module *M) {

  unsigned int regWidth = ArchPointerSize(M);

  //create the "reg" struct type
  auto &C = M->getContext();
  StructType *regs = StructType::create(C, "RegState");
  vector<Type *> regFields;

  Type *RegTy = IntegerType::getIntNTy(C, regWidth);
  Type *XMMTy = IntegerType::getIntNTy(C, 128);
  Type *FlagTy = IntegerType::getInt8Ty(C);

  //UPDATEREGS -- when we add something to 'regs', add it here
  //GPRs
  regFields.push_back(RegTy);  // RIP/EIP // 0
  regFields.push_back(RegTy);  // RAX/EAX // 1
  regFields.push_back(RegTy);  // RBX/EBX // 2
  regFields.push_back(RegTy);  // RCX/ECX // 3
  regFields.push_back(RegTy);  // RDX/EDX // 4
  regFields.push_back(RegTy);  // RSI/ESI // 5
  regFields.push_back(RegTy);  // RDI/EDI // 6
  regFields.push_back(RegTy);  // RSP/ESP // 7
  regFields.push_back(RegTy);  // RBP/EBP // 8

  //flags
  regFields.push_back(FlagTy);  // CF // 9
  regFields.push_back(FlagTy);  // PF // 10
  regFields.push_back(FlagTy);  // AF // 11
  regFields.push_back(FlagTy);  // ZF // 12
  regFields.push_back(FlagTy);  // SF // 13
  regFields.push_back(FlagTy);  // OF // 14
  regFields.push_back(FlagTy);  // DF // 15

  ArrayType *fpu_regs = ArrayType::get(Type::getX86_FP80Ty(C), 8);
  regFields.push_back(fpu_regs);  // 80 bytes 24

  // FPU Status Word
  regFields.push_back(FlagTy);  // FPU BUSY // 17
  regFields.push_back(FlagTy);  // Condition Code C3 // 18
  regFields.push_back(FlagTy);  // TOP OF STACK // 19
  regFields.push_back(FlagTy);  // Condition Code C2 // 20
  regFields.push_back(FlagTy);  // Condition Code C1 // 21
  regFields.push_back(FlagTy);  // Condition Code C0 // 22
  regFields.push_back(FlagTy);  // Error Summary Status // 23
  regFields.push_back(FlagTy);  // Stack Fault // 24
  regFields.push_back(FlagTy);  // Precision Flag // 25
  regFields.push_back(FlagTy);  // Underflow Flag // 26
  regFields.push_back(FlagTy);  // Overflow Flag // 27
  regFields.push_back(FlagTy);  // ZeroDivide Flag // 28
  regFields.push_back(FlagTy);  // Denormalized Operand Flag // 29
  regFields.push_back(FlagTy);  // Invalid Operation Flag // 30

  regFields.push_back(FlagTy);  // FPU Infinity Flag // 31
  regFields.push_back(FlagTy);  // FPU Rounding Control // 32
  regFields.push_back(FlagTy);  // FPU Precision Control // 33
  regFields.push_back(FlagTy);  // FPU Precision Mask // 34
  regFields.push_back(FlagTy);  // FPU Underflow Mask // 35
  regFields.push_back(FlagTy);  // FPU Overflow Mask // 36
  regFields.push_back(FlagTy);  // FPU Zero Divide Mask // 37
  regFields.push_back(FlagTy);  // FPU Denormal Operand Mask // 38
  regFields.push_back(FlagTy);  // FPU Invalid Operation Mask // 39

  // FPU tag word; 8 element array of 2-bit entries
  ArrayType *fpu_tag_word = ArrayType::get(FlagTy, 8);
  regFields.push_back(fpu_tag_word);  // 40

  // Last Instruction.
  regFields.push_back(Type::getInt16Ty(C));  // Segment // 41
  regFields.push_back(RegTy);  // Offset // 42

  // Last Data
  regFields.push_back(Type::getInt16Ty(C));  // Segment // 43
  regFields.push_back(RegTy);  // Offset // 44

  regFields.push_back(Type::getInt16Ty(C));  // FPU FOPCODE // 45

  // vector registers
  regFields.push_back(XMMTy);  // XMM0 46
  regFields.push_back(XMMTy);  // XMM1 47
  regFields.push_back(XMMTy);  // XMM2 48
  regFields.push_back(XMMTy);  // XMM3 49
  regFields.push_back(XMMTy);  // XMM4 50
  regFields.push_back(XMMTy);  // XMM5 51
  regFields.push_back(XMMTy);  // XMM6 52
  regFields.push_back(XMMTy);  // XMM7 53

  regFields.push_back(XMMTy);  // XMM8 54
  regFields.push_back(XMMTy);  // XMM9 55
  regFields.push_back(XMMTy);  // XMM10 56
  regFields.push_back(XMMTy);  // XMM11 57
  regFields.push_back(XMMTy);  // XMM12 58
  regFields.push_back(XMMTy);  // XMM13 59
  regFields.push_back(XMMTy);  // XMM14 60
  regFields.push_back(XMMTy);  // XMM15 61

  // non-register values in structRegs
  regFields.push_back(RegTy);  // 70: stack base (biggest value)
  regFields.push_back(RegTy);  // 71: stack limit (smallest value)

  if (64 == regWidth) {
    regFields.push_back(RegTy);  // R8  // 8
    regFields.push_back(RegTy);  // R9  // 9
    regFields.push_back(RegTy);  // R10 // 10
    regFields.push_back(RegTy);  // R11 // 11
    regFields.push_back(RegTy);  // R12 // 12
    regFields.push_back(RegTy);  // R13 // 13
    regFields.push_back(RegTy);  // R14 // 14
    regFields.push_back(RegTy);  // R15 // 15
  }

  PointerType *ptrToRegs = PointerType::get(regs, 0);
  regs->setBody(regFields, true);

  g_RegStruct = regs;
  g_PRegStruct = ptrToRegs;

  return;
}
