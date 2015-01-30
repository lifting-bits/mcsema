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
#include <llvm/IR/InlineAsm.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/InstrTypes.h>
#include <cstdio>

using namespace llvm;
using namespace std;

StructType  *g_RegStruct;
PointerType *g_PRegStruct;

GlobalVariable* g_StateBackup;


FunctionType    *getBaseFunctionType(Module *M) {
    vector<Type *>  baseFunctionArgs;
    baseFunctionArgs.push_back(g_PRegStruct);
    FunctionType    *funcTy = FunctionType::get(
                                        Type::getVoidTy(M->getContext()),
                                        baseFunctionArgs,
                                        false);
    TASSERT(funcTy != NULL, "");

    return funcTy;
}

void doGlobalInit(Module *M) {
    //create the "reg" struct type
    StructType  *regs = StructType::create(M->getContext(), "struct.regs");
    vector<Type *>  regFields;

    initInstructionDispatch();

    //UPDATEREGS -- when we add something to 'regs', add it here
    //GPRs 
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EAX // 0
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EBX // 1
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ECX // 2
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EDX // 3
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ESI // 4
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EDI // 5
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // ESP // 6
    regFields.push_back(IntegerType::get(M->getContext(), 32)); // EBP // 7
                                                                // 32 bytes

    //flags
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // CF // 8
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // PF // 9
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // AF // 10
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // ZF // 11
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // SF // 12
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // OF // 13
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // DF // 14
                                                                   // 28 bytes

    // FPU
    ArrayType  *fpu_regs = ArrayType::get(Type::getX86_FP80Ty(M->getContext()), 8);
    regFields.push_back(fpu_regs);                                 // 80 bytes // 15
    
    // FPU Status Word
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU BUSY // 16
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C3 // 17
    regFields.push_back(IntegerType::get(M->getContext(), 3)); // TOP OF STACK // 18
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C2 // 19
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C1 // 20
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C0 // 21
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Error Summary Status // 22
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Stack Fault // 23
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Precision Flag // 24 
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Underflow Flag // 25
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Overflow Flag // 26
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // ZeroDivide Flag // 27
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Denormalized Operand Flag // 28
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Invalid Operation Flag // 29
                                                                   // 56 bytes

    // 80 + 56 + 28 + 32 = 196 bytes

    
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Infinity Flag // 30
    regFields.push_back(IntegerType::get(M->getContext(), 2)); // FPU Rounding Control // 31
    regFields.push_back(IntegerType::get(M->getContext(), 2)); // FPU Precision Control // 32
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Precision Mask // 33
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Underflow Mask // 34
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Overflow Mask // 35
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Zero Divide Mask // 36
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Denormal Operand Mask // 37
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Invalid Operation Mask // 38

    // FPU tag word; 8 element array of 2-bit entries
    ArrayType  *fpu_tag_word = ArrayType::get(Type::getIntNTy(M->getContext(), 8), 8);
    regFields.push_back(fpu_tag_word);                                 // 80 bytes // 39

    regFields.push_back(IntegerType::getInt16Ty(M->getContext())); // Last Instruction Ptr Segment 40
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Instruction Ptr Offset 41
    regFields.push_back(IntegerType::getInt16Ty(M->getContext())); // Last Data Ptr Segment 42
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // Last Data Ptr Offset 43
    
    regFields.push_back(IntegerType::get(M->getContext(), 11)); // FPU FOPCODE 44

    // vector registers
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM0 45
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM1 46
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM2 47
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM3 48
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM4 49
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM5 50
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM6 51
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM7 52

    // non-register values in structRegs
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // 53: stack base (biggest value)
    regFields.push_back(IntegerType::getInt32Ty(M->getContext())); // 54: stack limit (smallest value)
    

    PointerType *ptrToRegs = PointerType::get(regs, 0);
    regs->setBody(regFields, true);

    vector<Type*> callValArgs;
    callValArgs.push_back(Type::getInt32Ty(M->getContext()));
    callValArgs.push_back(ptrToRegs);

    FunctionType  *callVal = FunctionType::get(
                                      Type::getVoidTy(M->getContext()),
                                      callValArgs,
                                      false);

    //GlobalVariable* g_StateBackup = 
    //    new GlobalVariable(*M, regs, false, GlobalValue::ExternalLinkage, 0, "state.backup");
    Type *int32ty = IntegerType::getInt32Ty(M->getContext());
    g_StateBackup = new GlobalVariable(*M, int32ty, 
                false, 
                GlobalValue::PrivateLinkage, 
                0, 
                "state.backup");
    g_StateBackup->setThreadLocalMode(GlobalVariable::GeneralDynamicTLSModel);


    Constant *zero = ConstantInt::get(int32ty, 0, false);
    g_StateBackup->setInitializer(zero);
    


    g_RegStruct = regs;
    g_PRegStruct = ptrToRegs;

    archAddCallValue(M);

    return;
}
