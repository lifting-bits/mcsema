/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#ifndef MC_SEMA_BC_UTIL_H_
#define MC_SEMA_BC_UTIL_H_

#include <cstdint>


namespace llvm {

class BasicBlock;
class ConstantInt;
class LLVMContext;
class Module;

}  // namespace llvm

extern llvm::LLVMContext *gContext;

// Create a new module for the current arch/os pair.
llvm::Module *CreateModule(llvm::LLVMContext *context);

// Return a constnat integer of width `width` and value `val`.
llvm::ConstantInt *CreateConstantInt(int width, uint64_t val);

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void);

template <int width>
inline static llvm::ConstantInt *CONST_V_INT(
    llvm::LLVMContext &, uint64_t val) {
  return CreateConstantInt(width, val);
}

template <int width>
inline static llvm::ConstantInt *CONST_V(llvm::BasicBlock *, uint64_t val) {
  return CreateConstantInt(width, val);
}

inline static llvm::ConstantInt *CONST_V(llvm::BasicBlock *, unsigned width,
                                         uint64_t val) {
  return CreateConstantInt(width, val);
}

#endif  // MC_SEMA_BC_UTIL_H_
