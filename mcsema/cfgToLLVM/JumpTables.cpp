/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this
 list of conditions and the following disclaimer in the documentation and/or
 other materials provided with the distribution.

 Neither the name of Trail of Bits nor the names of its
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

#include <vector>
#include <unordered_set>
#include <sstream>
#include <string>

#include <llvm/IR/Argument.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>

#include "mcsema/Arch/Dispatch.h"

#include "mcsema/Arch/X86/Util.h"  // TODO(pag): MEM_AS_DATA_REF

#include "mcsema/BC/Util.h"

#include "mcsema/CFG/CFG.h"

#include "mcsema/cfgToLLVM/JumpTables.h"
#include "mcsema/cfgToLLVM/TransExcn.h"

// convert a jump table to a data section of symbols
static DataSection *tableToDataSection(VA new_base, const MCSJumpTable &jt) {
  auto ds = new DataSection();
  const auto &entries = jt.getJumpTable();
  VA curAddr = new_base;

  for (auto va : entries) {
    std::stringstream ss;
    ss << "sub_" << std::hex << va;
    std::string sub_name = ss.str();
    DataSectionEntry dse(curAddr, sub_name);
    ds->addEntry(dse);
    curAddr += 4;
  }

  return ds;
}

// convert an index table to a data blob
static DataSection *tableToDataSection(VA new_base, const JumpIndexTable &jit) {
  auto ds = new DataSection();
  const auto &entries = jit.getJumpIndexTable();
  DataSectionEntry dse(new_base, entries);
  ds->addEntry(dse);
  return ds;
}

template<typename T>
static bool addTableDataSection(TranslationContext &ctx, VA &newVA,
                                const T &table) {
  auto natMod = ctx.natM;
  auto M = ctx.M;

  // ensure we make this the last data section
  newVA = 0;
  for (const auto &dt : natMod->getData()) {
    uint64_t extent = dt.getBase() + dt.getSize();
    if (newVA < extent) {
      newVA = extent;
    }
  }

  // skip a few
  newVA += 4;

  // create a new data section from the table
  DataSection *ds = tableToDataSection(newVA, table);

  // add to global data section list
  natMod->addDataSection( *ds);

  // create the GlobalVariable
  std::stringstream ss;
  ss << "data_" << std::hex << newVA;
  std::string bufferName = ss.str();
  auto st_opaque = llvm::StructType::create(M->getContext());
  auto gv = new llvm::GlobalVariable( *M, st_opaque, true,
                                     llvm::GlobalVariable::InternalLinkage,
                                     NULL,
                                     bufferName);

  std::vector<llvm::Type *> data_section_types;
  std::vector<llvm::Constant *> secContents;
  dataSectionToTypesContents(natMod->getData(), *ds, M, secContents,
                             data_section_types, false);

  st_opaque->setBody(data_section_types, true);
  auto cst = llvm::ConstantStruct::get(st_opaque, secContents);
  gv->setAlignment(4);
  gv->setInitializer(cst);

  return true;

}
bool addJumpTableDataSection(TranslationContext &ctx, VA &newVA,
                             const MCSJumpTable &table) {
  return addTableDataSection<MCSJumpTable>(ctx, newVA, table);
}

bool addJumpIndexTableDataSection(TranslationContext &ctx, VA &newVA,
                                  const JumpIndexTable &table) {
  return addTableDataSection<JumpIndexTable>(ctx, newVA, table);
}

void doJumpTableViaData(llvm::BasicBlock *&block, llvm::Value *fptr,
                        const int bitness) {
  llvm::Function *ourF = block->getParent();

  if ( !fptr->getType()->isPtrOrPtrVectorTy()) {
    auto FT = LiftedFunctionType();
    auto FptrTy = llvm::PointerType::get(FT, 0);
    fptr = new llvm::IntToPtrInst(fptr, FptrTy, "", block);
  }

  std::vector<llvm::Value *> subArgs;
  for (llvm::Argument &arg : ourF->args()) {
    subArgs.push_back( &arg);
  }

  llvm::CallInst::Create(fptr, subArgs, "", block);
}

void doJumpTableViaData(TranslationContext &ctx, llvm::BasicBlock *&block,
                        const int bitness) {
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto natM = ctx.natM;

  llvm::Value *addr = MEM_REFERENCE(0);
  //doJumpTableViaData(block, addr, bitness);

  llvm::errs() << __FUNCTION__ << ": Doing jump table via data\n";
  auto ourF = block->getParent();
  auto M = ourF->getParent();
  // get mem address

  auto FT = LiftedFunctionType();

  auto FptrTy = llvm::PointerType::get(FT, 0);
  auto Fptr2Ty = llvm::PointerType::get(FptrTy, 0);
  auto func_addr = llvm::CastInst::CreatePointerCast(addr, Fptr2Ty, "", block);

  // read in entry from table
  auto new_func = new llvm::LoadInst(func_addr, "", block);

  doJumpTableViaData(block, new_func, bitness);
}

template<int bitness>
static void doJumpTableViaSwitch(TranslationContext &ctx,
                                 llvm::BasicBlock *&block) {
  auto ip = ctx.natI;
  auto &inst = ip->get_inst();
  auto natM = ctx.natM;

  llvm::errs() << __FUNCTION__ << ": Doing jump table via switch\n";
  auto F = block->getParent();
  auto M = F->getParent();
  // we know this conforms to
  // jmp [reg*4+displacement]

  // sanity check
  const auto &scale = OP(1);
  const auto &index = OP(2);

  TASSERT(index.isReg(), "Conformant jump tables need index to be a register");
  TASSERT(scale.isImm() && scale.getImm() == (bitness / 8),
          "Conformant jump tables have scale == 4");

  MCSJumpTablePtr jmpptr = ip->get_jump_table();

  // to ensure no negative entries
  llvm::Value *adjustment = CONST_V<bitness>(block, jmpptr->getInitialEntry());
  llvm::Value *reg_val = R_READ<bitness>(block, index.getReg());
  llvm::Value *real_index = llvm::BinaryOperator::Create(llvm::Instruction::Add,
                                                         adjustment, reg_val,
                                                         "", block);

  // create a default block that just traps
  auto defaultBlock = llvm::BasicBlock::Create(block->getContext(), "",
                                               block->getParent(), 0);
  auto trapFn = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trap);

  llvm::CallInst::Create(trapFn, "", defaultBlock);
  llvm::ReturnInst::Create(defaultBlock->getContext(), defaultBlock);
  // end default block

  const auto &jmpblocks = jmpptr->getJumpTable();

  // create a switch inst
  auto theSwitch = llvm::SwitchInst::Create(real_index, defaultBlock,
                                            jmpblocks.size(), block);

  // populate switch
  int myindex = 0;
  for (auto jmp_block_va : jmpblocks) {
    auto toBlock = ctx.va_to_bb[jmp_block_va];
    TASSERT(toBlock != NULL, "Could not find block");
    theSwitch->addCase(CONST_V<bitness>(block, myindex), toBlock);
    ++myindex;
  }
}

void doJumpTableViaSwitch(TranslationContext &ctx, llvm::BasicBlock *&block,
                          int bitness) {
  switch (bitness) {
    case 32:
      doJumpTableViaSwitch<32>(ctx, block);
      break;
    case 64:
      doJumpTableViaSwitch<64>(ctx, block);
      break;
    default:
      TASSERT(false, "Invalid bitness!")
      ;
  }
}

template<int bitness>
static void doJumpTableViaSwitchReg(TranslationContext &ctx,
                                    llvm::BasicBlock *&block,
                                    llvm::Value *regVal,
                                    llvm::BasicBlock *&default_block) {

  llvm::errs() << __FUNCTION__ << ": Doing jump table via switch(reg)\n";

  auto F = block->getParent();
  auto M = F->getParent();
  auto ip = ctx.natI;
  auto jmpptr = ip->get_jump_table();

  // create a default block that just traps
  default_block = llvm::BasicBlock::Create(block->getContext(), "",
                                           block->getParent(), 0);
  // end default block

  const std::vector<VA> &jmpblocks = jmpptr->getJumpTable();
  std::unordered_set<VA> uniq_blocks(jmpblocks.begin(), jmpblocks.end());

  // create a switch inst
  auto theSwitch = llvm::SwitchInst::Create(regVal, default_block,
                                            uniq_blocks.size(), block);

  // populate switch
  for (auto blockVA : uniq_blocks) {
    auto toBlock = ctx.va_to_bb[blockVA];
    TASSERT(toBlock != NULL, "Could not find block!");
    auto thecase = CONST_V<bitness>(block, blockVA);
    theSwitch->addCase(thecase, toBlock);
  }
}

void doJumpOffsetTableViaSwitchReg(TranslationContext &ctx,
                                   llvm::BasicBlock *&block,
                                   llvm::Value *regVal,
                                   llvm::BasicBlock *&default_block,
                                   llvm::Value *data_location,
                                   MCSOffsetTablePtr ot_ptr) {
  auto ip = ctx.natI;
  llvm::errs() << __FUNCTION__ << ": Doing jump offset table via switch(reg)\n";
  auto F = block->getParent();

  // create a default block that just traps
  default_block = llvm::BasicBlock::Create(block->getContext(), "",
                                           block->getParent(), 0);
  // end default block

  const auto &offset_dest = ot_ptr->getConstTable();
  std::unordered_map<VA, VA> uniq_blocks;
  for (auto const &blockpair : offset_dest) {
    uniq_blocks[blockpair.first] = blockpair.second;
  }

  // switch on the offset, not the memory value
  llvm::Value *switch_val = llvm::BinaryOperator::CreateSub(regVal,
                                                            data_location, "",
                                                            block);
  switch_val = llvm::BinaryOperator::CreateAnd(switch_val,
                                               CONST_V<64>(block, 0xFFFFFFFF),
                                               "", block);
  // create a switch inst
  auto theSwitch = llvm::SwitchInst::Create(switch_val, default_block,
                                            uniq_blocks.size(), block);

  // populate switch
  for (const auto &entry : uniq_blocks) {
    auto toBlock = ctx.va_to_bb[entry.second];
    TASSERT(toBlock != NULL, "Could not find block!");
    auto thecase = CONST_V<64>(block, entry.first);
    theSwitch->addCase(thecase, toBlock);
  }
}

void doJumpTableViaSwitchReg(TranslationContext &ctx, llvm::BasicBlock *&block,
                             llvm::Value *regVal,
                             llvm::BasicBlock *&default_block,
                             const int bitness) {
  switch (bitness) {
    case 32:
      return doJumpTableViaSwitchReg<32>(ctx, block, regVal, default_block);
    case 64:
      return doJumpTableViaSwitchReg<64>(ctx, block, regVal, default_block);
    default:
      TASSERT(false, "Invalid bitness!")
      ;
  }
}

static llvm::BasicBlock *emitJumpIndexWrite(llvm::Function *F, uint8_t idx_val,
                                            unsigned dest_reg,
                                            llvm::BasicBlock *contBlock) {
  // create new block
  auto writeBlock = llvm::BasicBlock::Create(F->getContext(), "", F, 0);

  // write index to destination register
  R_WRITE<32>(writeBlock, dest_reg, CONST_V<32>(writeBlock, idx_val));

  // jump to continue block
  llvm::BranchInst::Create(contBlock, writeBlock);

  return writeBlock;
}

void doJumpIndexTableViaSwitch(llvm::BasicBlock *&block, NativeInstPtr ip) {
  auto F = block->getParent();
  auto M = F->getParent();
  // we know this conforms to
  // movzx reg32, [base+disp]

  // sanity check
  const auto &inst = ip->get_inst();
  const auto &dest = OP(0);
  const auto &base = OP(1);

  TASSERT(base.isReg(),
          "Conformant jump index tables need base to be a register");
  TASSERT(dest.isReg(),
          "Conformant jump index tables need to write to a register");

  JumpIndexTablePtr idxptr = ip->get_jump_index_table();

  // to ensure no negative entries
  llvm::Value *adjustment = CONST_V<32>(block, idxptr->getInitialEntry());
  llvm::Value *reg_val = R_READ<32>(block, base.getReg());
  llvm::Value *real_index = llvm::BinaryOperator::Create(llvm::Instruction::Add,
                                                         adjustment, reg_val,
                                                         "", block);

  auto continueBlock = llvm::BasicBlock::Create(block->getContext(), "", F, 0);

  // create a default block that just traps
  auto defaultBlock = llvm::BasicBlock::Create(block->getContext(), "", F, 0);
  auto trapFn = llvm::Intrinsic::getDeclaration(M, llvm::Intrinsic::trap);
  llvm::CallInst::Create(trapFn, "", defaultBlock);
  llvm::BranchInst::Create(continueBlock, defaultBlock);
  // end default block

  const auto &idxblocks = idxptr->getJumpIndexTable();

  // create a switch inst
  auto theSwitch = llvm::SwitchInst::Create(real_index, defaultBlock,
                                            idxblocks.size(), block);

  // populate switch
  int myindex = 0;
  for (auto index : idxblocks) {
    auto writeBl = emitJumpIndexWrite(F, index, dest.getReg(), continueBlock);
    theSwitch->addCase(CONST_V<32>(block, myindex), writeBl);
    ++myindex;
  }

  // new block to write to is continue block
  block = continueBlock;
}
