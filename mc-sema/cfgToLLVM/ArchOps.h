#ifndef ARCHOPS_H
#define ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/Triple.h"

#include <boost/cstdint.hpp>

typedef uint64_t VA;

enum SystemArchType {
  _X86_,
  _X86_64_
};

enum PointerSize {
  Pointer32 = 32,
  Pointer64 = 64
};

void ArchInitAttachDetach(llvm::Module *M);

llvm::Function *ArchAddEntryPointDriver(
    llvm::Module *M, const std::string &name, VA entry);

llvm::Function *ArchAddExitPointDriver(llvm::Function *F);

llvm::Function *ArchAddCallbackDriver(llvm::Module *M, VA local_target);

llvm::CallingConv::ID ArchGetCallingConv(llvm::Module *M);

void ArchSetCallingConv(llvm::Module *M, llvm::CallInst *ci);

void ArchSetCallingConv(llvm::Module *M, llvm::Function *F);

llvm::GlobalVariable *archGetImageBase(llvm::Module *M);

llvm::Triple::OSType SystemOS(llvm::Module *M);

SystemArchType SystemArch(llvm::Module *M);

PointerSize ArchPointerSize(llvm::Module *M);

std::string ArchNameMcsemaCall(const std::string &name);


template <int width>
static llvm::Value* doSubtractImageBase(
    llvm::Value *original, llvm::BasicBlock *block) {

  llvm::Module *M = block->getParent()->getParent();
  auto &C = M->getContext();
  llvm::Value *ImageBase = archGetImageBase(M);

  llvm::Type *intWidthTy = llvm::Type::getIntNTy(C, width);
  llvm::Type *ptrWidthTy = llvm::PointerType::get(intWidthTy, 0);

  // TODO(artem): Why use `64` below??

  // convert original value pointer to int
  llvm::Value *original_int = new llvm::PtrToIntInst(
      original, llvm::Type::getIntNTy(C, 64), "", block);

  // convert image base pointer to int
  llvm::Value *ImageBase_int = new llvm::PtrToIntInst(
      ImageBase, llvm::Type::getIntNTy(C, 64), "", block);

  // do the subtraction
  llvm::Value *data_v = llvm::BinaryOperator::CreateSub(original_int,
                                                        ImageBase_int, "",
                                                        block);

  // convert back to a pointer
  llvm::Value *data_ptr = new llvm::IntToPtrInst(data_v, ptrWidthTy, "", block);

  return data_ptr;
}

bool shouldSubtractImageBase(llvm::Module *M);

llvm::Value* doSubtractImageBaseInt(llvm::Value *original,
    llvm::BasicBlock *block);

#endif
