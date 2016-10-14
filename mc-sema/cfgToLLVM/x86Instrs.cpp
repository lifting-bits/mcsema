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

#include "RegisterUsage.h"

#include "JumpTables.h"

#include "x86Helpers.h"
#include "x86Instrs_fpu.h"
#include "x86Instrs_MOV.h"
#include "InstructionDispatch.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/Debug.h"
#include "x86Instrs_flagops.h"
#include "../common/to_string.h"

using namespace std;
using namespace llvm;

Value* getGlobalRegAsPtr(BasicBlock *B, MCSemaRegs reg) {
  Function *F = B->getParent();
  Module *M = F->getParent();
  unsigned int regWidth = getPointerSize(M);

  Value *arg = F->arg_begin();

  int globalRegsOff =
      getSystemArch(M) == _X86_ ?
          x86::getRegisterOffset(reg) : x86_64::getRegisterOffset(reg);

  Value *globalGlobalGEPV[] = {CONST_V(B, regWidth, 0), CONST_V<32>(
      B, globalRegsOff), CONST_V(B, regWidth, 0)};

  // Get element pointer.
  Instruction *gGlobalPtr = aliasMCSemaScope(
      GetElementPtrInst::CreateInBounds(arg, globalGlobalGEPV, "", B));
  // Cast pointer to int8* for use with memcpy.
  Instruction *globalCastPtr = aliasMCSemaScope(
      CastInst::CreatePointerCast(gGlobalPtr,
                                  Type::getInt8PtrTy(B->getContext()), "", B));

  return globalCastPtr;
}

Value* getGlobalFPURegsAsPtr(BasicBlock *B) {
  return getGlobalRegAsPtr(B, ST0);
}

Value* getLocalRegAsPtr(BasicBlock *B, MCSemaRegs reg) {
  Function *F = B->getParent();
  Module *M = F->getParent();

  unsigned int regWidth = getPointerSize(M);

  Value *localReg =
      getSystemArch(M) == _X86_ ?
          x86::lookupLocal(F, reg) : x86_64::lookupLocal(F, reg);

  // Need to get pointer to array[0] via GEP.
  Value *localGEP[] = {CONST_V(B, regWidth, 0), CONST_V<32>(B, 0)};
  Instruction *localPtr = noAliasMCSemaScope(
      GetElementPtrInst::CreateInBounds(localReg, localGEP, "", B));

  // Cast pointer to an Int8* for use with memcpy.
  Instruction *localCastPtr = noAliasMCSemaScope(
      CastInst::CreatePointerCast(localPtr, Type::getInt8PtrTy(B->getContext()),
                                  "", B));

  return localCastPtr;
}

Value* getLocalFPURegsAsPtr(BasicBlock *B) {
  return getLocalRegAsPtr(B, ST0);
}

void lazyWriteFPULocalsToContext(BasicBlock *B, unsigned bits,
                                 StoreSpillType whichRegs) {
  Function *F = B->getParent();
  if (!tryLookupName(F, "USING_FPU")) {
    return;
  }

  // Look up the argument value to this function.
  TASSERT(F->arg_size() >= 1,
          "need at least one argument to write locals to context");
  Value *arg = F->arg_begin();

  // FPU registers are generally avoided on 64bit system
  // SOURCE: get pointer to FPU locals
  Value *localFPU = getLocalFPURegsAsPtr(B);
  // DEST: get pointer to FPU globals
  Value *globalFPU = getGlobalFPURegsAsPtr(B);

  DataLayout td(static_cast<Module*>(F->getParent()));
  uint32_t fpu_arr_size = (uint32_t) td.getTypeAllocSize(
      Type::getX86_FP80Ty(B->getContext())) * NUM_FPU_REGS;

  Instruction *mcp_fpu = aliasMCSemaScope(
      callMemcpy(B, globalFPU, localFPU, fpu_arr_size, 8, false));
  // SOURCE: get pointer to local tag word
  Value *localTag = getLocalRegAsPtr(B, FPU_TAG);
  // DEST: get pointer to FPU globals
  Value *globalTag = getGlobalRegAsPtr(B, FPU_TAG);
  // SIZE: 8 entries * sizeof(Int2Ty)
  // Volatile = FALSE
  uint32_t tags_arr_size = (uint32_t) td.getTypeAllocSize(
      Type::getIntNTy(B->getContext(), 2)) * NUM_FPU_REGS;

  Instruction *mcp = aliasMCSemaScope(
      callMemcpy(B, globalTag, localTag, tags_arr_size, 4, false));

  return;
}

namespace x86 {
}

using namespace x86;

// do any instruction preprocessing/conversion
// before moving on to translation.
// currently used to turn non-conforming jump talbles
// into data sections
//
static void preprocessInstruction(NativeModulePtr natM, BasicBlock *&block,
                                  InstPtr ip, MCInst &inst) {

  // only add data sections for non-conformant jump tables
  //
  // the conformant tables are handled in the instruction
  // translator via switch()
  if (ip->has_jump_table()) {
    if ( !isConformantJumpInst(ip)) {
      {
        llvm::dbgs() << "WARNING: jump table but non-conformant instruction:\n";
        llvm::dbgs() << to_string<VA>(ip->get_loc(), hex) << ": ";
        llvm::dbgs() << inst << "\n";

        VA tbl_va;
        MCSJumpTablePtr jmptbl = ip->get_jump_table();

        bool ok = addJumpTableDataSection(natM, block->getParent()->getParent(),
                                          tbl_va, *jmptbl);

        TASSERT(ok, "Could not add jump table data section!\n");

        uint32_t data_ref_va = static_cast<uint32_t>(tbl_va
            + 4 * jmptbl->getInitialEntry());

        ip->set_reference(Inst::MEMRef, data_ref_va);
        ip->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
      }

    }
  }
  // only add data references for unknown jump index table
  // reads
  else if (ip->has_jump_index_table() && inst.getOpcode() != X86::MOVZX32rm8) {

    VA idx_va;
    JumpIndexTablePtr idxtbl = ip->get_jump_index_table();

    bool ok = addJumpIndexTableDataSection(natM,
                                           block->getParent()->getParent(),
                                           idx_va, *idxtbl);

    TASSERT(ok, "Could not add jump index table data section!\n");

    uint32_t data_ref_va = static_cast<uint32_t>(idx_va
        + idxtbl->getInitialEntry());

    ip->set_reference(Inst::MEMRef, data_ref_va);
    ip->set_ref_type(Inst::MEMRef, Inst::CFGDataRef);
  }

}

// Take the supplied MCInst and turn it into a series of LLVM instructions.
// Insert those instructions into the supplied block.
// Here's the philosophy:
// LLVM MCInst opcodes encode X86 instructions by, roughly:
//
//    mnemonic[bitwidth]<operandlist>
//
//  So for example, there are many different encodings and bitwidths of the
//  "add" mnemonic. each combination has its own space in the opcodes enum
//
//  We're narrowing from the space of LLVM MCInst opcodes in a few steps:
//     1. First by width. we take each mnemonic and classify it by width.
//        there are templated functions for dealing with mnemonic / operand
//        pairs, parameterized around operand width
//     2. next by operand type. Within each parameterized wrapper, we
//        'unrwrap' by extracting each operand and producing input values
//        to the instructions
//     3. finally, in an inner step, we define the instruction semantics
//        entirely in terms of LLVM Value objects. This is where the 'meat'
//        of semantic modeling takes places.
//     The breakdown looks something like this:
//
//     X86::CMP8rr -> [1] -> doCmpRR<8> -> [2] doCmpVV<8> -> [3]
//
//     The innermost is where most of the intelligent decisions happen.
//
InstTransResult disInstrX86(InstPtr ip, BasicBlock *&block, NativeBlockPtr nb,
                            Function *F, NativeFunctionPtr natF,
                            NativeModulePtr natM) {
  MCInst inst = ip->get_inst();
  InstTransResult itr = ContinueBlock;
  string outS;
  raw_string_ostream strOut(outS);
  MCInstPrinter *IP = nb->get_printer();

  if (IP == NULL)
    throw TErr(__LINE__, __FILE__,
               "No instruction printer supplied with native block");

  // For conditional instructions, get the "true" and "false" targets.
  // This will also look up the target for nonconditional jumps.
  //string trueStrName = "block_0x" + to_string<VA>(ip->get_tr(), hex);
  //string falseStrName = "block_0x" + to_string<VA>(ip->get_fa(), hex);

  TranslationFuncPtr translationPtr;

  unsigned opcode = inst.getOpcode();
  if (translationDispatchMap.find(opcode) != translationDispatchMap.end()) {
    // Instruction translation defined.
    translationPtr = translationDispatchMap[opcode];
    preprocessInstruction(natM, block, ip, inst);
    itr = translationPtr(natM, block, ip, inst);
  } else {
    // Instruction translation not defined.
    errs() << "Unsupported!\n";
    // Print out the unhandled opcode.
    errs() << to_string<VA>(ip->get_loc(), hex) << " ";
    IP->printInst( &inst, strOut, "");
    errs() << strOut.str() << "\n";
    errs() << inst.getOpcode() << "\n";
    if (X86::REP_PREFIX != opcode && X86::REPNE_PREFIX != opcode) {
      itr = TranslateErrorUnsupported;
    } else {
      errs()
          << "Unsupported instruction is a rep/repne, trying to skip to next instr.\n";
    }
  }
  //D(cout << __FUNCTION__ << " : " << opcode << "\n";
  //cout.flush();)
  return itr;
}

#undef OP
