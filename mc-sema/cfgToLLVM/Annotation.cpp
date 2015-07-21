#include "Annotation.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/LLVMContext.h"

#include <string>

using namespace std;
using namespace llvm;

const char MCSEMA_ANNOT_STRING[] = "mcsema_real_eip";

void addAnnotation(llvm::Instruction *inst, VA addr) {

    Constant *C = ConstantInt::get(Type::getInt64Ty(llvm::getGlobalContext()), addr);
    MDNode *n = MDNode::get(llvm::getGlobalContext(), C);

    inst->setMetadata(MCSEMA_ANNOT_STRING, n);
}

bool getAnnotation(llvm::Instruction *inst, VA &its_eip) {
    MDNode *metad = inst->getMetadata(MCSEMA_ANNOT_STRING);
    if(metad == nullptr) {
        return false;
    }

    Value *val = metad->getOperand(0);
    if(val == nullptr) {
        return false;
    }

    if (ConstantInt *ci = dyn_cast<ConstantInt>(val)) {
        its_eip = ci->getLimitedValue();

        return true;
    }

    return false;
}
