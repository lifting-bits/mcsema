#ifndef LINUXARCHOPS_H
#define LINUXARCHOPS_H

typedef uint64_t VA;

llvm::Value* linuxAllocateStack(llvm::Module *M, llvm::Value *stackSize, llvm::BasicBlock *&driverBB);
llvm::Value *linuxFreeStack(llvm::Module *M, llvm::Value *stackAlloc, llvm::BasicBlock *&driverBB);
llvm::Value *linuxMakeCallbackForLocalFunction(llvm::Module *M , VA local_target);
llvm::Value *linuxGetStackSize(llvm::Module *M, llvm::BasicBlock *&driverBB);
void linuxAddCallValue(llvm::Module *M);

#endif
