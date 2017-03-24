/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MC_SEMA_ARCH_ARCH_H_
#define MC_SEMA_ARCH_ARCH_H_

#include <string>

#include <llvm/ADT/Triple.h>
#include <llvm/IR/CallingConv.h>

#include "remill/Arch/Instruction.h"

namespace llvm {

class BasicBlock;
class CallInst;
class Function;
class GlobalVariable;
class LLVMContext;
class Module;
class PointerType;
class StructType;
class Value;

}  // namespace llvm

typedef uint64_t VA;

enum SystemArchType {
  _X86_,
  _X86_64_
};

enum PointerSize {
  Pointer32 = 32,
  Pointer64 = 64
};

bool InitArch(llvm::LLVMContext *context,
              const std::string &os,
              const std::string &arch);

int ArchAddressSize(void);

const std::string &ArchTriple(void);
const std::string &ArchDataLayout(void);

// Return the default calling convention for code on this architecture.
llvm::CallingConv::ID ArchCallingConv(void);

// Return the LLVM arch type of the code we're lifting.
llvm::Triple::ArchType ArchType(void);

// Return the LLVM OS type of the code we're lifting.
llvm::Triple::OSType OSType(void);

// For compatibility.
#define ArchPointerSize(...) ArchAddressSize()
#define ArchGetCallingConv(...) ArchCallingConv()

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

#endif  // MC_SEMA_ARCH_ARCH_H_
