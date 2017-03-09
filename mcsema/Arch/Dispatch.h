/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MC_SEMA_ARCH_DISPATCH_H_
#define MC_SEMA_ARCH_DISPATCH_H_

#include <map>

#include "mcsema/Arch/Arch.h"

namespace llvm {
class BasicBlock;
class Function;
class MCInst;
class Module;
}  // namespace llvm

class NativeModule;
class NativeFunction;
class NativeBlock;
class NativeInst;

struct TranslationContext {
  NativeModule *natM;
  NativeFunction *natF;
  NativeBlock *natB;
  NativeInst *natI;
  llvm::Module *M;
  llvm::Function *F;
  std::map<VA, llvm::BasicBlock *> va_to_bb;
};

enum InstTransResult : int {
  ContinueBlock,
  EndBlock,
  EndCFG,
  TranslateErrorUnsupported,
  TranslateError
};

typedef InstTransResult (InstructionLifter)(
    TranslationContext &, llvm::BasicBlock *&);

class DispatchMap : public std::map<unsigned, InstructionLifter *> {};

InstructionLifter *ArchGetInstructionLifter(const llvm::MCInst &inst);

extern InstTransResult (*ArchLiftInstruction)(
    TranslationContext &, llvm::BasicBlock *&, InstructionLifter *);

#endif  // MC_SEMA_ARCH_DISPATCH_H_
