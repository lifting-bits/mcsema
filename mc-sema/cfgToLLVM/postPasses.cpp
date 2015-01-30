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

#include <llvm/Object/COFF.h>
#include <llvm/IR/Constants.h>
#include <llvm/ADT/StringSwitch.h>
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/Bitcode/ReaderWriter.h"
#include "llvm/LinkAllPasses.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "postPassFuncs.h"

using namespace llvm;

// TRANSFORMATION: Bottom-Up Argument Pruning
//
//
struct BottomUpArgPrune : public ModulePass {
  static char ID;
  BottomUpArgPrune() : ModulePass(ID) { }

  virtual bool runOnModule(Module &M);
  virtual void getAnalysisUsage(AnalysisUsage &AU) const { }
};

char BottomUpArgPrune::ID = 0;
static RegisterPass<BottomUpArgPrune>
A("bottomupargprune", "Bottom Up Arg Prune");

static void getUsedRegistersFromLeaf(Function &F) {

  return;
}

//get the registers used from a function
static void getUsedRegisters(Function &F) {

  return;
}

bool BottomUpArgPrune::runOnModule(Module &M) {
  //we need to look at the call graph in M

  return false;
}

void bottomUpArgPrune(const PassManagerBuilder &Builder, PassManagerBase &PM) {
  PM.add(new BottomUpArgPrune());
  return;
}

// General registration function
//
//
void registerPostPasses(llvm::PassManagerBuilder &PMB) {
  PMB.addExtension(PassManagerBuilder::EP_OptimizerLast, bottomUpArgPrune);
  PMB.addExtension(PassManagerBuilder::EP_EarlyAsPossible, inlineSpecials);
  return;
}
