#ifndef ARCHOPS_H
#define ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/Triple.h"

#include <boost/cstdint.hpp>
typedef uint64_t VA;

llvm::Function *addEntryPointDriver(llvm::Module *M, const std::string &name, VA entry);
llvm::Function *getExitPointDriver(llvm::Function *F);

llvm::Function *archMakeCallbackForLocalFunction(llvm::Module *M,
                                                 VA local_target);

void archSetCallingConv(llvm::Module *M, llvm::CallInst *ci);
void archSetCallingConv(llvm::Module *M, llvm::Function *F);

llvm::GlobalVariable *archGetImageBase(llvm::Module *M);
unsigned getSystemArch(llvm::Module *M);
llvm::Triple::OSType getSystemOS(llvm::Module *M);
unsigned getPointerSize(llvm::Module *M);

typedef enum _SystemArchType {
  _X86_,
  _X86_64_
} SystemArchType;

enum PointerSize {
  PointerAnySize = 0,
  Pointer32 = 32,
  Pointer64 = 64
};


template <int width>
static llvm::Value* doSubtractImageBase(
    llvm::Value *original, llvm::BasicBlock *block) {

    llvm::Module *M = block->getParent()->getParent();
    llvm::Value *ImageBase = archGetImageBase(M);

    llvm::Type *intWidthTy = llvm::Type::getIntNTy(
        block->getContext(), width);
    llvm::Type *ptrWidthTy = llvm::PointerType::get(intWidthTy, 0);

    // convert original value pointer to int
    llvm::Value *original_int = new llvm::PtrToIntInst(
        original,
        llvm::Type::getIntNTy(block->getContext(), 64),
        "", block);

    // convert image base pointer to int
    llvm::Value *ImageBase_int = new llvm::PtrToIntInst(
        ImageBase,
        llvm::Type::getIntNTy(block->getContext(), 64),
        "", block);

    // do the subtraction
    llvm::Value *data_v = llvm::BinaryOperator::CreateSub(
        original_int,
        ImageBase_int,
        "", block);

    // convert back to a pointer
    llvm::Value *data_ptr = new llvm::IntToPtrInst(data_v, ptrWidthTy, "", block);

    return data_ptr;
}

bool shouldSubtractImageBase(llvm::Module *M);
llvm::Value* doSubtractImageBaseInt(llvm::Value *original,
    llvm::BasicBlock *block);

#endif
