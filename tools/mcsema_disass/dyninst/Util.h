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
#include <Symtab.h>
#include <dyntypes.h>

#include <algorithm>
#include <memory>
#include <string>
#include <type_traits>

#include "MagicSection.h"
#include "SectionManager.h"

struct DisassContext;

template <typename T>
auto *GetLastXref(T *cfg) {
  CHECK(cfg->xrefs_size() >= 1)
      << "Cannot retrieve last xref when there is none";
  return cfg->mutable_xrefs(cfg->xrefs_size() - 1);
}

mcsema::CodeReference *AddCodeXref(mcsema::Instruction *instruction,
                                   mcsema::CodeReference_OperandType opTy,
                                   Dyninst::Address addr);

template <typename CFGUnit = mcsema::Segment>
struct CrossXref {
  Dyninst::Address ea = 0;
  Dyninst::Address target_ea = 0;
  CFGUnit *segment = nullptr;
  std::string target_name = {};

  bool operator==(const CrossXref<CFGUnit> &other) {
    return ea == other.ea && target_ea == other.target_ea;
  }

  bool operator!=(const CrossXref<CFGUnit> &other) {
    return *this != other;
  }

  mcsema::DataReference *WriteDataXref(uint64_t width = 8) const {
    LOG(INFO) << "\tFound xref targeting " << std::hex << target_ea;
    auto cfg_xref = segment->add_xrefs();
    cfg_xref->set_ea(ea);
    cfg_xref->set_width(width);
    cfg_xref->set_target_ea(target_ea);

    // TODO(lukas): This will almost certainly cause problems once
    cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    return cfg_xref;
  }
};

// We want to remember a lot of things, to make lookup easier later on
// It could be avoided since all info can be reached from mcsema::Module
// but it would be much slower and more ugly
struct DisassContext {
  template <typename T>
  using SymbolMap = std::map<Dyninst::Address, T>;

  // TODO(lukas): I want heterogeneous container :'{!
  //              FishXref would be nice and there could be
  //              a function Contain<typename T>(Address) instead
  //              of manual lookup
  SymbolMap<mcsema::Function *> func_map;
  SymbolMap<mcsema::GlobalVariable *> global_vars;
  SymbolMap<mcsema::ExternalVariable *> external_vars;
  SymbolMap<mcsema::Variable *> segment_vars;
  SymbolMap<mcsema::ExternalFunction *> external_funcs;
  SymbolMap<mcsema::DataReference *> data_xrefs;

  std::vector<Dyninst::Address> segment_eas;
  MagicSection magic_section;

  // Writes and stores xref.ea into known data_xrefs
  mcsema::DataReference *WriteAndAccount(CrossXref<mcsema::Segment> xref,
                                         bool is_code = false,
                                         uint64_t width = 8) {
    width = std::min(width, 8ul);
    auto cfg_xref = xref.WriteDataXref(width);
    data_xrefs.insert({xref.ea, cfg_xref});
    return cfg_xref;
  }

  template <typename Container>
  bool FishForXref(const Container &facts, CrossXref<mcsema::Segment> &xref,
                   bool is_code = false, uint64_t width = 8) {
    auto fact = facts.find(xref.target_ea);
    if (fact != facts.end()) {
      xref.target_name = fact->second->name();
      WriteAndAccount(xref, is_code, width);
      LOG(INFO) << "\tResolved 0x" << std::hex << xref.ea << " -> 0x"
                << xref.target_ea;
      return true;
    }
    return false;
  }

  bool HandleDataXref(CrossXref<mcsema::Segment> xref) {
    if (FishForXref(global_vars, xref) ||
        FishForXref(external_funcs, xref, true) ||
        FishForXref(external_vars, xref) || FishForXref(segment_vars, xref) ||
        FishForXref(func_map, xref, true)) {

      if (xref.segment->xrefs_size()) {
        data_xrefs.insert({static_cast<Dyninst::Address>(xref.ea),
                           GetLastXref(xref.segment)});
      }
      return true;
    }
    return false;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::Function *fact) {
    AddCodeXref(xref.segment, mcsema::CodeReference::ControlFlowOperand,
                fact->ea());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::GlobalVariable *fact) {
    AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand, fact->ea());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::ExternalFunction *fact) {

    // Mapping to magic_section
    AddCodeXref(xref.segment, mcsema::CodeReference::ControlFlowOperand,
                magic_section.GetAllocated(xref.target_ea));
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::Variable *fact) {
    AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand, fact->ea());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::ExternalVariable *fact) {
    Dyninst::Address addr = magic_section.GetAllocated(xref.target_ea);
    if (!addr) {
      addr = fact->ea();
    }
    AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand, addr);
    return true;
  }


  bool WriteFact(const CrossXref<mcsema::Instruction> &xref,
                 mcsema::DataReference *fact) {
    AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand, fact->ea());
    return true;
  }

  template <typename Container>
  bool FishForXref(const Container &facts,
                   const CrossXref<mcsema::Instruction> &xref) {

    auto fact = facts.find(xref.target_ea);
    if (fact == facts.end()) {
      return false;
    }

    return WriteFact(xref, fact->second);
  }

  // If force=true function writes the xref even if target_ea
  // cannot be resolved in something reasonable
  bool HandleCodeXref(const CrossXref<mcsema::Instruction> &xref,
                      SectionManager &section_m, bool force = false) {
    if (FishForXref(global_vars, xref) || FishForXref(external_funcs, xref) ||
        FishForXref(external_vars, xref) || FishForXref(segment_vars, xref) ||
        FishForXref(data_xrefs, xref) || FishForXref(func_map, xref)) {
      return true;
    }

    // If one string is a proper substring, there can be reference to middle
    // of a variable
    // E.g printf("%s: %s\n", "partial string test", "string test");
    // .rodata will contain only partial string test and proper offset
    // will be used when "string test" is needed
    if (section_m.IsInRegions({".data", ".rodata", ".bss"}, xref.target_ea)) {
      AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand,
                  xref.target_ea);
      return true;
    }

    // Beginning of .jcr in framme_dummy for example
    for (auto a : segment_eas) {
      if (a == xref.target_ea) {
        AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand,
                    xref.target_ea);
        return true;
      }
    }

    if (force) {
      LOG(INFO) << "Could not regonize xref anywhere target_ea 0x" << std::hex
                << xref.target_ea << " forcing it";
      AddCodeXref(xref.segment, mcsema::CodeReference::MemoryOperand,
                  xref.target_ea);
      return true;
    }
    return false;
  }

  mcsema::Function *getInternalFunction(Dyninst::Address ea) {
    auto internal_func = func_map.find(ea);
    if (internal_func == func_map.end()) {
      return nullptr;
    }
    return internal_func->second;
  }
};
