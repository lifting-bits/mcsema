#pragma once

#include <string>
#include <memory>

#include <CFG.pb.h>

#include <Symtab.h>
#include <dyntypes.h>

#include "MagicSection.h"

class DisassContext;

extern mcsema::Module gModule;
extern std::unique_ptr<DisassContext> gDisassContext;

template<typename CFGUnit=mcsema::Segment *>
struct ContextCrossXref {
  Dyninst::Address ea = 0;
  Dyninst::Address target_ea = 0;
  CFGUnit segment = nullptr;

  bool operator==(const ContextCrossXref<CFGUnit> &other) {
    return ea == other.ea && target_ea == other.target_ea;
  }

  bool operator!=(const ContextCrossXref<CFGUnit> &other) {
    return *this != other;
  }

  mcsema::DataReference *WriteDataXref(
      const std::string &name="",
      bool is_code=false,
      uint64_t width=8) {
    LOG(INFO) << "\tFound xref targeting " << std::hex << target_ea;
    auto cfg_xref = segment->add_xrefs();
    cfg_xref->set_ea(ea);
    cfg_xref->set_width(width);
    cfg_xref->set_target_ea(target_ea);
    cfg_xref->set_target_name(name);
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
  using SymbolMap = std::unordered_map<Dyninst::Address, T>;

  // TODO(lukas): I want heterogeneous container :'{!
  SymbolMap<mcsema::Function *> func_map;
  SymbolMap<mcsema::GlobalVariable *> global_vars;
  SymbolMap<mcsema::ExternalVariable *> external_vars;
  SymbolMap<mcsema::Variable *> segment_vars;
  SymbolMap<mcsema::ExternalFunction *> external_funcs;
  SymbolMap<mcsema::DataReference *> data_xrefs;

  MagicSection magic_section;

  template<typename Container, typename CFGUnit>
  bool FishForXref(const Container &facts,
                   ContextCrossXref<CFGUnit> &xref,
                   bool is_code=false,
                   uint64_t width=8) {
    auto fact = facts.find(xref.target_ea);
    if (fact != facts.end()) {
      xref.WriteDataXref(fact->second->name(), is_code, width);
      // TODO(lukas): Store into known xrefs
      return true;
    }
    return false;
  }

  bool HandleDataXref(ContextCrossXref<mcsema::Segment *> &xref) {
    if (FishForXref(global_vars, xref) ||
        FishForXref(external_vars, xref) ||
        FishForXref(segment_vars, xref) ||
        FishForXref(func_map, xref, true) ||
        FishForXref(external_funcs, xref, true)) {
        //FishForXref(data_xrefs, xref)) {
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

template<typename Ins>
auto AddCodeXref(Ins &instruction,
                 mcsema::CodeReference::TargetType tarTy,
                 mcsema::CodeReference_OperandType opTy,
                 mcsema::CodeReference_Location location,
                 Dyninst::Address addr,
                 const std::string &name="") {

    auto xref = instruction->add_xrefs();
    xref->set_target_type(tarTy);
    xref->set_operand_type(opTy);
    xref->set_location(location);
    xref->set_ea(addr);
    if (!name.empty())
        xref->set_name(name);
    return xref;
}
