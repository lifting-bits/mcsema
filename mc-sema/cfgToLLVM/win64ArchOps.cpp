#include "win64ArchOps.h"
#include "ArchOps.h"
#include "llvm/Support/Debug.h"


using namespace llvm;

bool shouldSubtractImageBase(Module *M) {

    // we are on windows
    if(getSystemOS(M) != Triple::Win32) {
        //llvm::errs() << __FUNCTION__ << ": Not on Win32\n";
        return false;
    }

    // and we are on amd64
    if(getSystemArch(M) != _X86_64_) {
        //llvm::errs() << __FUNCTION__ << ": Not on amd64\n";
        return false;
    }

    // and the __ImageBase symbol is defined
    if(archGetImageBase(M) == nullptr) {
        llvm::errs() << __FUNCTION__ << ": No __ImageBase defined\n";
       return false; 
    }

    return true;

} 

llvm::Value* doSubtractImageBaseInt(llvm::Value *original, 
    llvm::BasicBlock *block) 
{
    llvm::Module *M = block->getParent()->getParent();
    llvm::Value *ImageBase = archGetImageBase(M);

    // convert image base pointer to int
    llvm::Value *ImageBase_int = new llvm::PtrToIntInst(
        ImageBase, 
        llvm::Type::getIntNTy(block->getContext(), 64), 
        "", block);

    // do the subtraction
    llvm::Value *data_v = BinaryOperator::CreateSub(
        original, 
        ImageBase_int, 
        "", block);

    return data_v;
}

