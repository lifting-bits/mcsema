/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

#include <llvm/IR/Constants.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Type.h>

#include "mcsema/Arch/Arch.h"
#include "mcsema/Arch/Register.h"
#include "mcsema/BC/Util.h"

llvm::LLVMContext *gContext = nullptr;

llvm::Module *CreateModule(llvm::LLVMContext *context) {
  if (!gContext) {
    gContext = context;
  }
  auto M = new llvm::Module("", *context);
  M->setTargetTriple(ArchTriple());
  M->setDataLayout(ArchDataLayout());
  return M;
}

// Return a constnat integer of width `width` and value `val`.
llvm::ConstantInt *ConstantInt(int width, uint64_t val) {
  auto bTy = llvm::Type::getIntNTy(*gContext, width);
  return llvm::ConstantInt::get(bTy, val);
}

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void) {
  static llvm::FunctionType *func_type = nullptr;
  if (!func_type) {
    auto state_type = ArchRegStateStructType();
    auto state_ptr_type = llvm::PointerType::get(state_type, 0);
    std::vector<llvm::Type *> arg_types;
    arg_types.push_back(state_ptr_type);
    func_type = llvm::FunctionType::get(llvm::Type::getVoidTy(*gContext),
                                        arg_types, false);
  }
  return func_type;
}
