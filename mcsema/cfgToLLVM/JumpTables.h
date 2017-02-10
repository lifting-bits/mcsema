/*
 Copyright (c) 2014, Trail of Bits
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification,
 are permitted provided that the following conditions are met:

 Redistributions of source code must retain the above copyright notice, this
 list of conditions and the following disclaimer.

 Redistributions in binary form must reproduce the above copyright notice, this  list of conditions and the following disclaimer in the documentation and/or
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
#ifndef _JUMPTABLES_H
#define _JUMPTABLES_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#include <utility>

#include "mcsema/Arch/Arch.h"

struct TranslationContext;
class NativeInst;

template<class T>
class Table {
 public:
  Table(const std::vector<T> &table, int entry)
      : m_table(table),
        m_entry(entry) {}

  virtual int getInitialEntry(void) const {
    return this->m_entry;
  }

  virtual ~Table(void) {}

  virtual const std::vector<T> &getTable(void) const {
    return this->m_table;
  }

  virtual const std::vector<T> &getConstTable(void) const {
    return this->m_table;
  }

 protected:
  std::vector<T> m_table;
  int m_entry;

  virtual std::vector<T> &getTable(void) {
    return this->m_table;
  }
};

class MCSOffsetTable : public Table<std::pair<VA, VA>> {
 protected:
  VA m_start_addr;
 public:
  MCSOffsetTable(const std::vector<std::pair<VA, VA>> &table,
                 int entry, VA start)
      : Table<std::pair<VA, VA>>::Table(table, entry),
        m_start_addr(start) {}

  virtual ~MCSOffsetTable(void) {}

  virtual VA getStartAddr(void) const {
    return this->m_start_addr;
  }
};

class MCSJumpTable : public Table<VA> {
 protected:
  VA m_offset_from_data;

 public:

  MCSJumpTable(const std::vector<VA> &table, int entry, VA data_offset)
      : Table<VA>::Table(table, entry),
        m_offset_from_data(data_offset) {}

  virtual const std::vector<VA> &getJumpTable(void) const {
    return this->getTable();
  }

  virtual std::vector<VA> &getJumpTable(void) {
    return this->getTable();
  }

  virtual VA getOffsetFromData(void) const {
    return this->m_offset_from_data;
  }

  virtual ~MCSJumpTable(void) {}
};

class JumpIndexTable : public Table<uint8_t> {
 public:
  JumpIndexTable(const std::vector<uint8_t> &table, int entry)
      : Table<uint8_t>::Table(table, entry) {}

  virtual const std::vector<uint8_t> &getJumpIndexTable(void) const {
    return this->getTable();
  }

  virtual std::vector<uint8_t> &getJumpIndexTable(void) {
    return this->getTable();
  }

  virtual ~JumpIndexTable() {}
};

typedef MCSJumpTable *MCSJumpTablePtr;
typedef JumpIndexTable *JumpIndexTablePtr;

bool addJumpTableDataSection(TranslationContext &ctx, VA &newVA,
                             const MCSJumpTable &table);

bool addJumpIndexTableDataSection(TranslationContext &ctx,
                                  VA &newVA, const JumpIndexTable &table);

// check for the format:
// jmp [reg*4+<relocated offset>]
//
// TODO(pag): This is x86-specific; factor into an arch-specific place.
static bool isConformantJumpInst(NativeInst *jmpinst) {

  const auto &inst = jmpinst->get_inst();

  // these are now done via switch()
  if (inst.getOpcode() == llvm::X86::JMP32r ||
      inst.getOpcode() == llvm::X86::JMP64r) {
    return true;
  }

  if (inst.getNumOperands() < 4) {
    return false;
  }

  const auto &scale = inst.getOperand(1);
  const auto &index = inst.getOperand(2);
  const auto &disp = inst.getOperand(3);

  // scale: can be 4 (32-bit) or 8 (64-bit)
  // index must be a register
  return scale.isImm() && index.isReg() && disp.isImm() &&
         (scale.getImm() == 4 || scale.getImm() == 8);
}

void doJumpTableViaData(TranslationContext &ctx, llvm::BasicBlock *&block,
                        const int bitness);

void doJumpTableViaData(llvm::BasicBlock *&block, llvm::Value *val,
                        const int bitness);

void doJumpTableViaSwitch(TranslationContext &ctx, llvm::BasicBlock *&block,
                          const int bitness);

void doJumpTableViaSwitchReg(TranslationContext &ctx, llvm::BasicBlock *& block,
                             llvm::Value *regVal,
                             llvm::BasicBlock *&default_block,
                             const int bitness);

void doJumpIndexTableViaSwitch(llvm::BasicBlock *& block, NativeInst *ip);

void doJumpOffsetTableViaSwitchReg(TranslationContext &ctx, llvm::BasicBlock *&block,
                                   llvm::Value *regVal,
                                   llvm::BasicBlock *&default_block,
                                   llvm::Value *data_location,
                                   MCSOffsetTablePtr ot_ptr);

#endif
