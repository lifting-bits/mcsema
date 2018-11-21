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

#include <algorithm>
#include <string>
#include <memory>

#include <CFG.pb.h>

#include <Symtab.h>
#include <dyntypes.h>
#include <type_traits>

#include "MagicSection.h"
#include "SectionManager.h"

struct DisassContext;

extern std::unique_ptr<DisassContext> gDisassContext;


mcsema::CodeReference *AddCodeXref(
    mcsema::Instruction * instruction,
    mcsema::CodeReference::TargetType tarTy,
    mcsema::CodeReference_OperandType opTy,
    mcsema::CodeReference_Location location,
    Dyninst::Address addr,
    const std::string &name="");

template<typename CFGUnit=mcsema::Segment *>
struct CrossXref {
  Dyninst::Address ea = 0;
  Dyninst::Address target_ea = 0;
  CFGUnit segment = nullptr;
  std::string target_name = {};

  bool operator==(const CrossXref<CFGUnit> &other) {
    return ea == other.ea && target_ea == other.target_ea;
  }

  bool operator!=(const CrossXref<CFGUnit> &other) {
    return *this != other;
  }

  mcsema::DataReference *WriteDataXref(
      bool is_code=false,
      uint64_t width=8) const {
    LOG(INFO) << "\tFound xref targeting " << std::hex << target_ea;
    auto cfg_xref = segment->add_xrefs();
    cfg_xref->set_ea(ea);
    cfg_xref->set_width(width);
    cfg_xref->set_target_ea(target_ea);
    cfg_xref->set_target_name(target_name);
    cfg_xref->set_target_is_code(is_code);
    // TODO(lukas): This will almost certainly cause problems once
    cfg_xref->set_target_fixup_kind(mcsema::DataReference::Absolute);
    return cfg_xref;
  }
};

// We want to remember a lot of things, to make lookup easier later on
// It could be avoided since all info can be reached from mcsema::Module
// but it would be much slower and more ugly
struct DisassContext {
  template<typename T>
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
  mcsema::DataReference *WriteAndAccount(CrossXref<mcsema::Segment *> xref,
                                         bool is_code=false,
                                         uint64_t width=8) {
    width = std::min(width, 8ul);
    auto cfg_xref = xref.WriteDataXref(is_code, width);
    data_xrefs.insert({xref.ea, cfg_xref});
    return cfg_xref;
  }

  template<typename Container>
  bool FishForXref(const Container &facts,
                   CrossXref<mcsema::Segment *> &xref,
                   bool is_code=false,
                   uint64_t width=8) {
    auto fact = facts.find(xref.target_ea);
    if (fact != facts.end()) {
      xref.target_name = fact->second->name();
      WriteAndAccount(xref,is_code, width);
      LOG(INFO) << "\tResolved 0x" << std::hex << xref.ea
                << " -> 0x" << xref.target_ea;
      return true;
    }
    return false;
  }

  bool HandleDataXref(CrossXref<mcsema::Segment *> xref) {
    if (FishForXref(global_vars, xref) ||
        FishForXref(external_funcs, xref, true) ||
        FishForXref(external_vars, xref) ||
        FishForXref(segment_vars, xref) ||
        FishForXref(func_map, xref, true)) {

      if (xref.segment->xrefs_size()) {
      auto cfg_xref =
          xref.segment->mutable_xrefs(xref.segment->xrefs_size() - 1);
      data_xrefs.insert({static_cast<Dyninst::Address>(xref.ea), cfg_xref});
      }
      return true;
    }
    return false;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::Function *fact) {
    LOG(INFO) << "\tResolved as internal function";
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::ControlFlowOperand,
                mcsema::CodeReference::Internal,
                fact->ea(),
                fact->name());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::GlobalVariable *fact) {
    LOG(INFO) << "\tResolved as global variable";
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::MemoryOperand,
                mcsema::CodeReference::Internal,
                fact->ea(),
                fact->name());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::ExternalFunction *fact) {
    // Mapping to magic_section
    LOG(INFO) << "\tResolved as ext function";
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::ControlFlowOperand,
                mcsema::CodeReference::External,
                magic_section.GetAllocated(xref.target_ea),
                fact->name());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::Variable *fact) {
    LOG(INFO) << "\tResolved as segment variable";
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::MemoryOperand,
                mcsema::CodeReference::Internal,
                fact->ea(),
                fact->name());
    return true;
  }

  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::ExternalVariable *fact) {
    Dyninst::Address addr = magic_section.GetAllocated(xref.target_ea);
    LOG(INFO) << "\tResolved as external variable";
    if (!addr) {
      addr = fact->ea();
    }
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::MemoryOperand,
                mcsema::CodeReference::External,
                addr,
                fact->name());
    return true;
  }


  bool WriteFact(const CrossXref<mcsema::Instruction *> &xref,
                 mcsema::DataReference *fact) {
    LOG(INFO) << "\tResolved as data xref";
    AddCodeXref(xref.segment,
                mcsema::CodeReference::DataTarget,
                mcsema::CodeReference::MemoryOperand,
                mcsema::CodeReference::Internal,
                fact->ea());
    return true;
  }

  template<typename Container>
  bool FishForXref(const Container &facts,
                   const CrossXref<mcsema::Instruction *> &xref) {

    auto fact = facts.find(xref.target_ea);
    if (fact == facts.end()) {
      return false;
    }

    return WriteFact(xref, fact->second);
  }

  // If force=true function writes the xref even if target_ea
  // cannot be resolved in something reasonable
  bool HandleCodeXref(const CrossXref<mcsema::Instruction *> &xref,
                      bool force=false) {
    if (FishForXref(global_vars, xref) ||
        FishForXref(external_funcs, xref) ||
        FishForXref(external_vars, xref) ||
        FishForXref(segment_vars, xref) ||
        FishForXref(data_xrefs, xref) ||
        FishForXref(func_map, xref)) {
      return true;
    }

    // If one string is a proper substring, there can be reference to middle
    // of a variable
    // E.g printf("%s: %s\n", "partial string test", "string test");
    // .rodata will contain only partial string test and proper offset
    // will be used when "string test" is needed
    if (gSectionManager->IsInRegions({".data", ".rodata", ".bss"},
                                     xref.target_ea)) {
      LOG(INFO) << "\tIn .rodata or .data";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  xref.target_ea);
      return true;
    }

    // Beginning of .jcr in framme_dummy for example
    for (auto a : segment_eas) {
      if (a == xref.target_ea) {
        LOG(INFO) << "\tEa of segment";
        AddCodeXref(xref.segment,
                    mcsema::CodeReference::DataTarget,
                    mcsema::CodeReference::MemoryOperand,
                    mcsema::CodeReference::Internal,
                    xref.target_ea);
        return true;
      }
    }
    LOG(INFO) << "Could not regonize xref anywhere target_ea 0x"
            << std::hex << xref.target_ea;
    if (force) {
      LOG(INFO) << "\tForcing it";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  xref.target_ea);
      return true;
    }
    return false;
  }

  mcsema::Function *getInternalFunction(Dyninst::Address ea) {
    auto internal_func = func_map.find(ea);
    if (internal_func == func_map.end()) {
      LOG(INFO) << "There is no internal function in DisassContext with ea 0x"
                 << std::hex << ea;
      return nullptr;
    }
    return internal_func->second;
  }
};
