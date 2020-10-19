/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <CFG.pb.h>
#include <CodeObject.h>
#include <Dereference.h>
#include <Expression.h>
#include <Instruction.h>
#include <Symtab.h>

#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "ExternalFunctionManager.h"
#include "MagicSection.h"
#include "OffsetTable.h"
#include "SectionManager.h"
#include "Util.h"

using SymbolMap = std::unordered_map<Dyninst::Address, std::string>;

struct SectionParser;

class CFGWriter {
 public:
  CFGWriter(mcsema::Module &m, Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::CodeObject &codeObj,
            ExternalFunctionManager &extFuncM);

  void Write();

 private:
  void WriteDataVariables(Dyninst::SymtabAPI::Region *region,
                          mcsema::Segment *segment,
                          SectionParser &section_parser);

  void WriteExternalVariables();
  void WriteGlobalVariables();
  void SweepStubs();
  void WriteInternalFunctions();

  void WriteFunctionBlocks(Dyninst::ParseAPI::Function *func,
                           mcsema::Function *cfg_internal_func);

  std::set<Dyninst::Address>
  WriteBlock(Dyninst::ParseAPI::Block *block, Dyninst::ParseAPI::Function *func,
             mcsema::Function *cfg_internal_func,
             std::set<Dyninst::ParseAPI::Block *> &written);

  void WriteInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                        Dyninst::Address addr, mcsema::Block *cfgBlock,
                        bool is_last = false);
  void HandleCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                             Dyninst::Address addr,
                             mcsema::Instruction *cfgInstruction,
                             bool is_last = false);
  void
  HandleNonCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                           Dyninst::Address addr,
                           mcsema::Instruction *cfgInstruction,
                           mcsema::Block *cfg_block, bool is_last = false);

  void WriteFunction(Dyninst::ParseAPI::Function *func,
                     mcsema::Function *cfg_internal_func);

  void WriteExternalFunctions();
  void WriteInternalData();
  void WriteRelocations(Dyninst::SymtabAPI::Region *, mcsema::Segment *);
  void WriteGOT(Dyninst::SymtabAPI::Region *, mcsema::Segment *);

  Dyninst::Address immediateNonCall(Dyninst::InstructionAPI::Immediate *imm,
                                    Dyninst::Address addr,
                                    mcsema::Instruction *cfgInstruction);
  Dyninst::Address dereferenceNonCall(Dyninst::InstructionAPI::Dereference *,
                                      Dyninst::Address, mcsema::Instruction *);

  bool HandleXref(mcsema::Instruction *, Dyninst::Address, bool force = true);

  void CheckDisplacement(Dyninst::InstructionAPI::Expression *,
                         mcsema::Instruction *);
  bool IsExternal(Dyninst::Address addr) const;
  void ComputeBBAttributes();


  mcsema::Module &module;

  /* Dyninst related objects */
  Dyninst::SymtabAPI::Symtab &symtab;
  Dyninst::ParseAPI::CodeObject &code_object;

  ExternalFunctionManager ext_funcs_m;
  SectionManager section_m;

  std::map<Dyninst::Address, CrossXref<mcsema::Segment>> code_xrefs_to_resolve;
  std::map<Dyninst::Address, CrossXref<mcsema::Instruction>>
      inst_xrefs_to_resolve;

  std::vector<OffsetTable> offset_tables;

  // magic_section is handle into ctx, needs to be initialized in this order
  DisassContext ctx;
  MagicSection &magic_section;
  int ptr_byte_size = 8;
};
