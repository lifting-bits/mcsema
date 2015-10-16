#ifndef OSXARCHOPS_H
#define OSXARCHOPS_H

typedef uint64_t VA;

llvm::Value* osxAllocateStack(llvm::Module *M, llvm::Value *stackSize, llvm::BasicBlock *&driverBB);
llvm::Value* osxFreeStack(llvm::Module *M, llvm::Value *stackAlloc, llvm::BasicBlock *&driverBB);
llvm::Value* osxMakeCallbackForLocalFunction(llvm::Module *M , VA local_target);
llvm::Value* osxGetStackSize(llvm::Module *M, llvm::BasicBlock *&driverBB);
void osxAddCallValue(llvm::Module *M);

#endif // OSXARCHOPS_H
