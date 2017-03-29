/*
Copyright (c) 2017, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the organization nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
