/*
 * Copyright (c) 2018 Trail of Bits, Inc.
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

#pragma once

#include "SectionManager.h"
#include "ExternalFunctionManager.h"
#include "MagicSection.h"
#include "Util.h"
#include "OffsetTable.h"

#include <CFG.pb.h>
#include <CodeObject.h>
#include <Expression.h>
#include <Symtab.h>
#include <Instruction.h>
#include <Dereference.h>

#include <unordered_set>
#include <unordered_map>
#include <sstream>

using SymbolMap = std::unordered_map<Dyninst::Address, std::string>;

struct SectionParser;

class CFGWriter {
public:
  CFGWriter(mcsema::Module &m,
            Dyninst::SymtabAPI::Symtab &symtab,
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
  void WriteLocalVariables();

  void WriteFunctionBlocks(Dyninst::ParseAPI::Function *func,
                           mcsema::Function *cfg_internal_func);

  std::set<Dyninst::Address> WriteBlock(
      Dyninst::ParseAPI::Block *block,
      Dyninst::ParseAPI::Function *func,
      mcsema::Function *cfg_internal_func,
      std::set<Dyninst::ParseAPI::Block *> &written);

  void WriteInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                        Dyninst::Address addr, mcsema::Block *cfgBlock,
                        bool is_last=false);
  void HandleCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                             Dyninst::Address addr,
                             mcsema::Instruction *cfgInstruction,
                             bool is_last=false);
  void
  HandleNonCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                           Dyninst::Address addr,
                           mcsema::Instruction *cfgInstruction,
                           mcsema::Block *cfg_block,
                           bool is_last=false);

  void WriteFunction(Dyninst::ParseAPI::Function *func,
                     mcsema::Function *cfg_internal_func);

  void WriteExternalFunctions();
  void WriteInternalData();
  void WriteRelocations(Dyninst::SymtabAPI::Region*, mcsema::Segment *);
  void WriteGOT(Dyninst::SymtabAPI::Region*, mcsema::Segment *);

  Dyninst::Address immediateNonCall(Dyninst::InstructionAPI::Immediate *imm,
                                    Dyninst::Address addr,
                                    mcsema::Instruction *cfgInstruction);
  Dyninst::Address dereferenceNonCall(Dyninst::InstructionAPI::Dereference *,
                                      Dyninst::Address,
                                      mcsema::Instruction *);

  bool HandleXref(mcsema::Instruction *, Dyninst::Address, bool force=true);

  bool IsNoReturn(const std::string& str);
  void GetNoReturns();

  void CheckDisplacement(Dyninst::InstructionAPI::Expression *,
                         mcsema::Instruction *);
  bool IsExternal(Dyninst::Address addr) const;

  mcsema::Module &module;

  /* Dyninst related objects */
  Dyninst::SymtabAPI::Symtab &symtab;
  Dyninst::ParseAPI::CodeObject &code_object;

  ExternalFunctionManager ext_funcs_m;
  SectionManager section_m;

  std::unordered_set<std::string> no_ret_funcs;

  std::map<Dyninst::Address, CrossXref<mcsema::Segment>> code_xrefs_to_resolve;
  std::map<Dyninst::Address, CrossXref<mcsema::Instruction>> inst_xrefs_to_resolve;

  std::vector<OffsetTable> offset_tables;

  // magic_section is handle into ctx, needs to be initialized in this order
  DisassContext ctx;
  MagicSection &magic_section;
  int ptr_byte_size = 8;
};
