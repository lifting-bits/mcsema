/*
 * Copyright (c) 2017 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MCSEMA_BC_UTIL_H_
#define MCSEMA_BC_UTIL_H_

#include <cstdint>
#include <list>
#include <vector>

#include "mcsema/CFG/CFG.h"

namespace llvm {

class BasicBlock;
class ConstantInt;
class LLVMContext;
class Module;

}  // namespace llvm
namespace mcsema {

extern llvm::LLVMContext *gContext;
extern llvm::Module *gModule;

// Create a `mcsema_real_eip` annotation, and annotate every unannotated
// instruction with this new annotation.
void AnnotateInsts(llvm::Function *func, uint64_t pc);

// Return the type of a lifted function.
llvm::FunctionType *LiftedFunctionType(void);


enum StoreSpillType {
  AllRegs = (1 << 0),   // store/spill all regs
  ABICallStore = (1 << 1),   // store regs in preparation for CALL
  ABICallSpill = (1 << 2),   // spill regs at function prolog
  ABIRetStore = (1 << 3),   // Store regs in preparation for RET
  ABIRetSpill = (1 << 4)    // spill regs right after a RET
};

//llvm::Value *makeCallbackForLocalFunction(
//    llvm::Module *M, uint64_t local_target);

//
//#define OP(x) inst.getOperand(x)
//
//#define ADDR_NOREF(x) \
//    ArchPointerSize(block->getParent()->getParent()) == Pointer32 ? \
//    ADDR_NOREF_IMPL<32>(natM, block, x, ip, inst) :\
//    ADDR_NOREF_IMPL<64>(natM, block, x, ip, inst)
//
//#define CREATE_BLOCK(nm, b) \
//    auto block_ ## nm = llvm::BasicBlock::Create( \
//        (b)->getContext(), #nm, (b)->getParent())
//
//#define MEM_REFERENCE(which) MEM_AS_DATA_REF(block, natM, inst, ip, which)
//
//#define GENERIC_TRANSLATION_MI(NAME, NOREFS, MEMREF, IMMREF, TWOREFS) \
//    static InstTransResult translate_ ## NAME ( \
//        TranslationContext &ctx, llvm::BasicBlock *&block) { \
//      auto natM = ctx.natM; \
//      auto F = ctx.F; \
//      auto ip = ctx.natI; \
//      auto &inst = ip->get_inst(); \
//      if (ip->has_mem_reference && ip->has_imm_reference) { \
//          TWOREFS; \
//      } else if (ip->has_mem_reference ) { \
//          MEMREF; \
//      } else if (ip->has_imm_reference ) { \
//          IMMREF; \
//      } else { \
//          NOREFS; \
//      } \
//      return ContinueBlock;\
//    }
//
//
//#define GENERIC_TRANSLATION_REF(NAME, NOREFS, HASREF) \
//    static InstTransResult translate_ ## NAME ( \
//        TranslationContext &ctx, llvm::BasicBlock *&block) { \
//      auto natM = ctx.natM; \
//      auto F = ctx.F; \
//      auto ip = ctx.natI; \
//      auto &inst = ip->get_inst(); \
//      if (ip->has_mem_reference || ip->has_imm_reference || \
//         ip->has_external_ref()) { \
//          HASREF; \
//      } else {\
//          NOREFS; \
//      } \
//      return ContinueBlock; \
//    }
//
//#define GENERIC_TRANSLATION(NAME, NOREFS) \
//    static InstTransResult translate_ ## NAME ( \
//        TranslationContext &ctx, llvm::BasicBlock *&block) { \
//      InstTransResult ret;\
//      auto natM = ctx.natM; \
//      auto F = ctx.F; \
//      auto ip = ctx.natI; \
//      auto &inst = ip->get_inst(); \
//      ret = NOREFS; \
//      return ret; \
//    }
//
//// this template and macro simplify referencing semantics defined in external bitcode
//// the EXTERNAL_SEMANTICS macro will create a global string constant necessary to
//// instantiate this template. The constant gets shoved in the mcsema_const_strings namespace.
////
//// The template will call a function with the same prototype as the current translation semantics
//// The function itself is retreived by ArchGetOrCreateSemantics
//template <char const *fname>
//static InstTransResult EXTERNAL_BITCODE_HELPER(TranslationContext &ctx, llvm::BasicBlock *&block) {
//  auto F = ctx.F;
//  auto M = F->getParent();
//  auto externSemanticsF = ArchGetOrCreateSemantics(M, fname);
//  // we are calling a translation function, it gets the same args
//  // as our function
//  std::vector<llvm::Value *> subArgs;
//  for (auto &arg : F->args()) {
//    subArgs.push_back(&arg);
//  }
//  auto ci = llvm::CallInst::Create(externSemanticsF, subArgs, "", block);
//  ArchSetCallingConv(M, ci);
//  return ContinueBlock;
//}
//
//#define EXTERNAL_SEMANTICS(NAME) \
//  namespace mcsema_const_strings { char name_ ## NAME [] = #NAME; } \
//  static InstTransResult translate_ ## NAME (TranslationContext &ctx, llvm::BasicBlock *&block) { \
//      return EXTERNAL_BITCODE_HELPER<mcsema_const_strings::name_ ## NAME >(ctx, block); \
//  }

}  // namespace mcsema

#endif  // MCSEMA_BC_UTIL_H_
