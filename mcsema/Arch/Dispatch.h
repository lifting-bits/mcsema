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

namespace remill {
class InstructionLifter;
}  // namespace remill

class NativeModule;
class NativeFunction;
class NativeBlock;
class NativeInst;

struct TranslationContext {
  remill::InstructionLifter *lifter;
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

#endif  // MC_SEMA_ARCH_DISPATCH_H_
