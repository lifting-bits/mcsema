#ifndef ARCHOPS_H
#define ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/Triple.h"

#include <boost/cstdint.hpp>
typedef uint64_t VA;

llvm::Value* archAllocateStack(llvm::Module *M, llvm::Value *stackSize, llvm::BasicBlock *&driverBB);
llvm::Value* archGetStackSize(llvm::Module *M, llvm::BasicBlock *&driverBB);
llvm::Value* archFreeStack(llvm::Module *M, llvm::Value *stackAlloc, llvm::BasicBlock *&driverBB);
llvm::Module* archAddCallbacksToModule(llvm::Module *M);
llvm::Value *archMakeCallbackForLocalFunction(llvm::Module *M, VA local_target);
void archAddCallValue(llvm::Module *M);
void archSetCallingConv(llvm::Module *M, llvm::CallInst *ci);
void archSetCallingConv(llvm::Module *M, llvm::Function *F);
llvm::GlobalVariable *archGetImageBase(llvm::Module *M);
unsigned getSystemArch(llvm::Module *M);
llvm::Triple::OSType getSystemOS(llvm::Module *M);
unsigned getPointerSize(llvm::Module *M);

typedef enum _SystemArchType {
    _X86_,
    _X86_64_
} SystemArchType;

enum PointerSize {
    PointerAnySize =0,
    Pointer32 = 32,
    Pointer64 = 64
};


#endif
