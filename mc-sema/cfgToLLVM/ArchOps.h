#ifndef ARCHOPS_H
#define ARCHOPS_H

#include "llvm/Value.h"
#include "llvm/Module.h"
#include "llvm/BasicBlock.h"

llvm::Value* archAllocateStack(llvm::Module *M, llvm::Value *stackSize, llvm::BasicBlock *&driverBB);
llvm::Value* archGetStackSize(llvm::Module *M, llvm::BasicBlock *&driverBB);
llvm::Value* archFreeStack(llvm::Module *M, llvm::Value *stackAlloc, llvm::BasicBlock *&driverBB);
llvm::Module* archAddCallbacksToModule(llvm::Module *M);

#endif
