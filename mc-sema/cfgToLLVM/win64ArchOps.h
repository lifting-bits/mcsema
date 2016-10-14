#ifndef WIN64_ARCHOPS_H
#define WIN64_ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/InstrTypes.h"
#include "ArchOps.h"

bool shouldSubtractImageBase(llvm::Module *M);

llvm::Value* doSubtractImageBaseInt(llvm::Value *original, llvm::BasicBlock *block);

#endif
