
#pragma once

#include <string>
#include <cstdint>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/CallingConv.h>

#include "mcsema/Arch/Arch.h"



namespace llvm {
class BasicBlock;
class CallInst;
class Function;
class Module;
class PointerType;
class StructType;
class Value;
}  // namespace llvm


void ArchInitAttachDetach(llvm::Module *M);

llvm::Function *ArchAddEntryPointDriver(
    llvm::Module *M, const std::string &name, VA entry);

llvm::Function *ArchAddExitPointDriver(llvm::Function *F);

llvm::Function *ArchAddCallbackDriver(llvm::Module *M, VA local_target);

void ArchSetCallingConv(llvm::Module *M, llvm::CallInst *ci);

void ArchSetCallingConv(llvm::Module *M, llvm::Function *F);

llvm::GlobalVariable *archGetImageBase(llvm::Module *M);

#define SystemOS(...) OSType()

SystemArchType SystemArch(llvm::Module *M);

std::string ArchNameMcSemaCall(const std::string &name);

llvm::Value *doSubtractImageBase(llvm::Value *original,
                                 llvm::BasicBlock *block, int width);

template <int width>
inline static llvm::Value *doSubtractImageBase(
    llvm::Value *original, llvm::BasicBlock *block) {
  return doSubtractImageBase(original, block, width);
}

bool shouldSubtractImageBase(llvm::Module *M);

llvm::Value *doSubtractImageBaseInt(llvm::Value *original,
                                    llvm::BasicBlock *block);
