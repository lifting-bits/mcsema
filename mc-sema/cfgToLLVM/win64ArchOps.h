#ifndef WIN64_ARCHOPS_H
#define WIN64_ARCHOPS_H

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/ADT/Triple.h"
#include "llvm/IR/InstrTypes.h"
#include "ArchOps.h"

bool shouldSubtractImageBase(llvm::Module *M);

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

llvm::Value* doSubtractImageBaseInt(llvm::Value *original, llvm::BasicBlock *block);

#endif
