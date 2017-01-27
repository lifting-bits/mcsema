#include "Annotation.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"

#include <string>

const char * const kRealEIPAnnotation = "mcsema_real_eip";

void addAnnotation(llvm::Instruction *inst, VA addr) {
  auto C = llvm::ConstantInt::get(
      llvm::Type::getInt64Ty(llvm::getGlobalContext()), addr);
  auto n = llvm::MDNode::get(llvm::getGlobalContext(), C);
  inst->setMetadata(kRealEIPAnnotation, n);
}

bool getAnnotation(llvm::Instruction *inst, VA &its_eip) {
  if (auto metad = inst->getMetadata(kRealEIPAnnotation)) {
    if (auto val = metad->getOperand(0)) {
      if (auto ci = llvm::dyn_cast<llvm::ConstantInt>(val)) {
        its_eip = ci->getLimitedValue();
        return true;
      }
    }
  }
  return false;
}
