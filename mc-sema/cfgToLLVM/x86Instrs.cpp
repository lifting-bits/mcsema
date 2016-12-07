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
InstTransResult liftInstrImpl(InstPtr ip, BasicBlock *&block, NativeBlockPtr nb,
                            Function *F, NativeFunctionPtr natF,
                            NativeModulePtr natM) {
  MCInst inst = ip->get_inst();
  InstTransResult itr = ContinueBlock;
  string outS;
  raw_string_ostream strOut(outS);
  MCInstPrinter *IP = nb->get_printer();

  if (IP == NULL) {
    throw TErr(__LINE__, __FILE__,
               "No instruction printer supplied with native block");
  }

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
    if (TranslateError == itr || TranslateErrorUnsupported == itr) {
      errs() << "Error translating!";
      IP->printInst( &inst, errs(), to_string<VA>(ip->get_loc(), hex));
      errs() << "\n";
    }
  } else {
    // Instruction translation not defined.
    errs() << "Unsupported opcode " << opcode << " ("
      << IP->getOpcodeName(opcode) << "): ";
    IP->printInst( &inst, errs(), to_string<VA>(ip->get_loc(), hex));
    errs() << "\n";

    // In the case that we can't find the opcode, try building it out with
    // inline assembly calls in LLVM instead. If at any point we don't know
    // how to build the assembly, give up on trying to do so.
    const MCRegisterInfo *MRI = natM->getMCContext()->getRegisterInfo();
    const MCInstrInfo *MII = natM->getTarget()->createMCInstrInfo();

    // Build the inline asm and the constraint string.
    string inlineAsm = "", constraints = "";

    // Use the printer to build the ASM string. We'll need to substitute
    // $ for $$, though.
    {
      IP->printInst(&inst, strOut, "");
      for (char c : strOut.str()) {
        if (c == '$')
          inlineAsm += "$$";
        else
          inlineAsm += c;
      }
    }

    // Find all of the involved registers and build the LLVM
    unsigned argnum = 0;
    SmallVector<Value *, 3> operands;
    SmallVector<Type *, 3> resultTypes;
    for (unsigned i = 0; i < inst.getNumOperands(); i++) {
      MCOperand &op = inst.getOperand(i);
      if (op.isReg()) {
        if (argnum++ > 0) constraints += ",";
        if (i < MII->get(opcode).getNumDefs()) {
          constraints += "=";

          // Find the size of the register. Surprisingly, this is how you
          // have to do that.
          unsigned maxSize = 0;
          for (auto rc = MRI->regclass_begin();
              rc != MRI->regclass_end(); ++rc) {
            if (rc->contains(op.getReg())) {
              maxSize = std::max(maxSize, rc->getSize());
            }
          }

          if (maxSize > 8) {
            // LLVM can't handle register constraints of i128, so we
            // need to map this to <16 x i8>.
            resultTypes.push_back(VectorType::get(
              Type::getInt8Ty(block->getContext()), maxSize));
          } else if (maxSize > 0) {
            resultTypes.push_back(IntegerType::get(block->getContext(),
                  8 * maxSize));
          } else {
            errs() << "Can't find register size for " <<
              MRI->getName(op.getReg()) << '\n';
            goto failinlineasm;
          }
        } else {
          Value *readReg = nullptr;
          unsigned maxSize = 0;
          for (auto rc = MRI->regclass_begin();
              rc != MRI->regclass_end(); ++rc) {
            if (rc->contains(op.getReg()))
              maxSize = std::max(maxSize, rc->getSize());
          }
          switch (maxSize) {
            case 1: readReg = ::R_READ<8>(block, op.getReg()); break;
            case 2: readReg = ::R_READ<16>(block, op.getReg()); break;
            case 4: readReg = ::R_READ<32>(block, op.getReg()); break;
            case 8: readReg = ::R_READ<64>(block, op.getReg()); break;
            case 16: {
              readReg = ::R_READ<128>(block, op.getReg());
              // LLVM can't handle register constraints of i128, so we
              // need to map this to <16 x i8>.
              readReg = CastInst::Create(Instruction::BitCast, readReg,
                VectorType::get(Type::getInt8Ty(block->getContext()), 16),
                  "", block);
              break;
            }
            default:
              errs() << "Unknown register size " << maxSize << " for " <<
                MRI->getName(op.getReg()) << '\n';
              goto failinlineasm;
          }
          operands.push_back(readReg);
        }
        constraints += "{";
        constraints += MRI->getName(op.getReg());
        constraints += "}";
      }
    }

    // Build the call to inline asm at this point.
    {
      SmallVector<Type *, 3> argTypes;
      for (auto val : operands)
        argTypes.push_back(val->getType());
      Type *returnTy;
      if (resultTypes.empty())
        returnTy = Type::getVoidTy(block->getContext());
      else if (resultTypes.size() == 1)
        returnTy = resultTypes[0];
      else
        returnTy = StructType::get(block->getContext(), resultTypes);
      FunctionType *asmTy = FunctionType::get(returnTy, argTypes, false);
      InlineAsm *callee = InlineAsm::get(asmTy, inlineAsm, constraints, false);
      Value *resultPack =
        CallInst::Create(callee, operands, IP->getOpcodeName(opcode), block);
      for (unsigned i = 0; i < resultTypes.size(); i++) {
        Value *result = resultTypes.size() == 1 ? resultPack :
          ExtractValueInst::Create(resultPack, i, "", block);
        Type *ty = resultTypes[i];
        // Cast vector outputs to iXYZ for R_WRITE.
        if (ty->isVectorTy()) {
          ty = Type::getIntNTy(block->getContext(),
            ty->getVectorNumElements() * 8);
          result = CastInst::Create(Instruction::BitCast, result,
            ty, "", block);
        }
        unsigned regNo = inst.getOperand(i).getReg();
        switch (ty->getIntegerBitWidth()) {
        case 8: ::R_WRITE<8>(block, regNo, result); break;
        case 16: ::R_WRITE<16>(block, regNo, result); break;
        case 32: ::R_WRITE<32>(block, regNo, result); break;
        case 64: ::R_WRITE<64>(block, regNo, result); break;
        case 128: ::R_WRITE<128>(block, regNo, result); break;
        default:
          errs() << "Unknown register size " << resultTypes[i]->getIntegerBitWidth() << '\n';
          goto failinlineasm;
        }
      }
    }

    return itr;
failinlineasm:
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
