/*
Copyright (c) 2013, Trail of Bits
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#include "toLLVM.h"
#include "raiseX86.h"
#include "X86.h"
#include "x86Instrs.h"
#include "x86Helpers.h"
#include "win32cb.h"
#include <set>
#include <map>
#include <iostream>

#include <llvm/Object/COFF.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringSwitch.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/PassManager.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "win32_Intrinsics.h"

using namespace llvm;
using namespace std;

typedef Value *(*ReplaceFunctionPt)(Module *M, Instruction *I, Pass *P);
map<string,ReplaceFunctionPt> specialMap;

//command line option to turn this pass on or not
static cl::opt<bool> NoSpecialInline(
  "no-special-inline", cl::NotHidden, cl::init(false),
  cl::desc("Disable inlining of special functions"));

//pass infrastructure
struct InlineSpecials : public FunctionPass {
  static char ID;
  InlineSpecials() : FunctionPass(ID) { }

  virtual bool runOnFunction(Function &F);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const { }
};

char InlineSpecials::ID = 0;
static RegisterPass<InlineSpecials>
A("inlinespecials", "Inline Specials");

bool InlineSpecials::runOnFunction(Function &F) {

    std::set<CallInst*> worklist;

  for(inst_iterator i = inst_begin(F), e = inst_end(F); i != e; ++i) {
    Instruction *I = &*i;

    if(CallInst *C = dyn_cast<CallInst>(I)) {
      //get the target of the call, if known
      Function  *invoked = C->getCalledFunction();
      
      if(invoked != NULL) {
        worklist.insert(C);
      }
    }
  }

  for(std::set<CallInst*>::iterator itr = worklist.begin();
          itr != worklist.end();
          itr++)
  {
      CallInst *C = *itr;
      Function  *invoked = C->getCalledFunction();
      string                                  invokedFuncName = invoked->getName();
      map<string,ReplaceFunctionPt>::iterator it = specialMap.find(invokedFuncName);

      if(it != specialMap.end()) {
          ReplaceFunctionPt func = it->second; 

          Value *newv = func(F.getParent(), C, this);

          C->replaceAllUsesWith(newv);
          C->eraseFromParent();
      }
  }
  
  return false;
}

//semantics of the RTL aullshr intrinsic stub
Value *replace_aullshr(Module *M, Instruction *I, Pass *P) {

  BasicBlock *topHalf = I->getParent();
  
  BasicBlock *bottomHalf = llvm::SplitBlock(topHalf, I, P);

  BasicBlock *newBlock = BasicBlock::Create(
          topHalf->getContext(), 
          "aullshr_MainBlock",
          topHalf->getParent());

  // remove old branch, and create a new branch to newBlock
  topHalf->getTerminator()->eraseFromParent();
  BranchInst::Create(newBlock, topHalf);


  // emit aullshr and link that block to bottomHalf
  Value *new_v = emit_aullshr(newBlock, bottomHalf);


  return new_v;
}

void inlineSpecials(const PassManagerBuilder &Builder, PassManagerBase &PM) {
  //check if we're running this pass or not
  if(NoSpecialInline == false) {
    //populate a global map of special functions
    specialMap.insert(pair<string,ReplaceFunctionPt>("__aullshr", replace_aullshr));

    //register the pass
    PM.add(new InlineSpecials());
  }

  return;
}

