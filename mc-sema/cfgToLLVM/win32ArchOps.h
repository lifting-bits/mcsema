#ifndef WIN32ARCHOPS_H
#define WIN32ARCHOPS_H

#include "llvm/Value.h"
#include "llvm/Module.h"
#include "llvm/BasicBlock.h"

#include <boost/cstdint.hpp>
typedef boost::uint64_t VA;

llvm::Value *win32GetStackSize(llvm::Module *M, llvm::BasicBlock *&driverBB);
llvm::Value *win32AllocateStack(llvm::Module *M, llvm::Value *stackSize, llvm::BasicBlock *&driverBB);
llvm::Value *win32FreeStack(llvm::Value *stackAlloc, llvm::BasicBlock *&driverBB);
llvm::Value *win32MakeCallbackForLocalFunction(llvm::Module *M, VA local_target);
void win32AddCallValue(llvm::Module *mod);

#endif
