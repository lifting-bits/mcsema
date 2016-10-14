#ifndef WIN32ARCHOPS_H
#define WIN32ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"

typedef uint64_t VA;

inline static llvm::Function *win32MakeCallbackForLocalFunction(llvm::Module *M, VA local_target) { return nullptr; }

#endif
