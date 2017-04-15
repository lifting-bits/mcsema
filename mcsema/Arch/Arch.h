/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MCSEMA_ARCH_ARCH_H_
#define MCSEMA_ARCH_ARCH_H_

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

namespace remill {
class Arch;
}  // namespace remill

namespace mcsema {
typedef uint64_t VA;

enum SystemArchType {
  _X86_,
  _X86_64_
};

enum PointerSize {
  Pointer32 = 32,
  Pointer64 = 64
};

extern const remill::Arch *gArch;

bool InitArch(const std::string &os,
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

void ArchInitAttachDetach(void);

llvm::Function *ArchAddEntryPointDriver(
    const std::string &name, llvm::Function *F);

llvm::Function *ArchAddExitPointDriver(llvm::Function *F);

llvm::Function *ArchAddCallbackDriver(llvm::Function *F);

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

}  // namespace mcsema

#endif  // MCSEMA_ARCH_ARCH_H_
