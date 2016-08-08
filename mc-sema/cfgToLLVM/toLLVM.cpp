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

Triple *getTargetTriple(const llvm::Target *T) {
    if(T->getName() == "x86")
        return new Triple("i386", "unknown", "unknown");
    else if(T->getName() == "x86-64")
        return new Triple("x86_64", "unknown", "unknown");
}

void doGlobalInit(Module *M) {

	unsigned int regWidth = getPointerSize(M);

    //create the "reg" struct type
    StructType  *regs = StructType::create(M->getContext(), "struct.regs");
    vector<Type *>  regFields;

    initInstructionDispatch();

    //UPDATEREGS -- when we add something to 'regs', add it here
    //GPRs
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RAX/EAX // 0
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RBX/EBX // 1
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RCX/ECX // 2
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RDX/EDX // 3
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RSI/ESI // 4
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RDI/EDI // 5
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RSP/ESP // 6
    regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RBP/EBP // 7

	if(getSystemArch(M) == _X86_64_){
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R8  // 8
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R9  // 9
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R10 // 10
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R11 // 11
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R12 // 12
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R13 // 13
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R14 // 14
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // R15 // 15

		// RIP for rip relative instructions
		regFields.push_back(IntegerType::get(M->getContext(), regWidth)); // RIP // 16
	}

    //flags
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // CF // 17
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // PF // 18
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // AF // 19
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // ZF // 20
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // SF // 21
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // OF // 22
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // DF // 23

    ArrayType  *fpu_regs = ArrayType::get(Type::getDoubleTy(M->getContext()), 8);
    regFields.push_back(fpu_regs);                            // 80 bytes 24


	// FPU Status Word
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU BUSY // 25
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C3 // 26
    regFields.push_back(IntegerType::get(M->getContext(), 3)); // TOP OF STACK // 27
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C2 // 28
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C1 // 29
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Condition Code C0 // 30
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Error Summary Status // 31
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Stack Fault // 32
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Precision Flag // 33
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Underflow Flag // 34
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Overflow Flag // 35
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // ZeroDivide Flag // 36
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Denormalized Operand Flag // 37
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // Invalid Operation Flag // 38


    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Infinity Flag // 39
    regFields.push_back(IntegerType::get(M->getContext(), 2)); // FPU Rounding Control // 40
    regFields.push_back(IntegerType::get(M->getContext(), 2)); // FPU Precision Control // 41
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Precision Mask // 42
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Underflow Mask // 43
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Overflow Mask // 44
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Zero Divide Mask // 45
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Denormal Operand Mask // 46
    regFields.push_back(IntegerType::getInt1Ty(M->getContext())); // FPU Invalid Operation Mask // 47

	// FPU tag word; 8 element array of 2-bit entries
    ArrayType  *fpu_tag_word = ArrayType::get(Type::getIntNTy(M->getContext(), 8), 8);
    regFields.push_back(fpu_tag_word);                                               // 48

    regFields.push_back(IntegerType::getInt16Ty(M->getContext())); // Last Instruction Ptr Segment 49
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), regWidth)); // Last Instruction Ptr Offset 50
    regFields.push_back(IntegerType::getInt16Ty(M->getContext())); // Last Data Ptr Segment 51
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), regWidth)); // Last Data Ptr Offset 52

    regFields.push_back(IntegerType::get(M->getContext(), 11)); // FPU FOPCODE 53


    // vector registers
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM0 54
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM1 55
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM2 56
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM3 57
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM4 58
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM5 59
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM6 60
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM7 61

	if(getSystemArch(M) == _X86_64_){
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM8 62
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM9 63
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM10 64
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM11 65
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM12 66
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM13 67
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM14 68
		regFields.push_back(IntegerType::getIntNTy(M->getContext(), 128)); // XMM15 69
	}

    // non-register values in structRegs
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), regWidth)); // 70: stack base (biggest value)
    regFields.push_back(IntegerType::getIntNTy(M->getContext(), regWidth)); // 71: stack limit (smallest value)


    PointerType *ptrToRegs = PointerType::get(regs, 0);
    regs->setBody(regFields, true);

    vector<Type*> callValArgs;
    callValArgs.push_back(Type::getIntNTy(M->getContext(), regWidth));
    callValArgs.push_back(ptrToRegs);

    FunctionType  *callVal = FunctionType::get(
                                      Type::getVoidTy(M->getContext()),
                                      callValArgs,
                                      false);

    //GlobalVariable* g_StateBackup =
    //    new GlobalVariable(*M, regs, false, GlobalValue::ExternalLinkage, 0, "state.backup");
    Type *intType = IntegerType::getIntNTy(M->getContext(), regWidth);
    g_StateBackup = new GlobalVariable(*M, intType,
                false,
                GlobalValue::PrivateLinkage,
                0,
                "state.backup");
    g_StateBackup->setThreadLocalMode(GlobalVariable::GeneralDynamicTLSModel);


    Constant *zero = ConstantInt::get(intType, 0, false);
    g_StateBackup->setInitializer(zero);



    g_RegStruct = regs;
    g_PRegStruct = ptrToRegs;

    archAddCallValue(M);

    return;
}
