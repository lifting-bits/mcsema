#pragma once

#include <string>
#include <memory>

#include <CFG.pb.h>

#include <Symtab.h>
#include <dyntypes.h>
#include <type_traits>

#include "MagicSection.h"

class DisassContext;

extern mcsema::Module gModule;
extern std::unique_ptr<DisassContext> gDisassContext;


template<class T, class... Rest>
inline constexpr bool is_any = (std::is_same<T, Rest>::value && ...);


mcsema::CodeReference *AddCodeXref(mcsema::Instruction * instruction,
                 mcsema::CodeReference::TargetType tarTy,
                 mcsema::CodeReference_OperandType opTy,
                 mcsema::CodeReference_Location location,
                 Dyninst::Address addr,
                 const std::string &name="");

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

  template<typename Container>
  bool FishForXref(const Container &facts,
                   ContextCrossXref<mcsema::Segment *> &xref,
                   bool is_code=false,
                   uint64_t width=8) {
    auto fact = facts.find(xref.target_ea);
    if (fact != facts.end()) {
      auto cfg_xref = xref.WriteDataXref(fact->second->name(), is_code, width);
      data_xrefs.insert({cfg_xref->ea(), cfg_xref});
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
      data_xrefs.insert({static_cast<Dyninst::Address>(xref.ea), xref.segment->mutable_xrefs(xref.segment->xrefs_size() - 1)});
      return true;
    }
    return false;
  }

  template<typename Base, typename Container>
  bool FishForXref(const Container &facts,
                   const ContextCrossXref<mcsema::Instruction *> &xref) {

    auto fact = facts.find(xref.target_ea);
    if (fact == facts.end()) {
      return false;
    }


    if constexpr (std::is_same<Base, mcsema::Function *>()) {
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::ControlFlowOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::ExternalFunction *>()) {
      // TODO(lukas) mapping to magic_section
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::ControlFlowOperand,
                  mcsema::CodeReference::External,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::GlobalVariable *>()) {
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::Variable *>()) {
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::ExternalVariable *>()) {
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::External,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::DataReference *>()) {
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea());
      return true;
    }
    return false;
  }

  bool HandleCodeXref(const ContextCrossXref<mcsema::Instruction *> &xref, bool force=true) {
    ContextCrossXref<mcsema::Instruction *> ext_func_cross_xref = {
      xref.ea, magic_section.GetAllocated(xref.target_ea), xref.segment
    };
    if (FishForXref<mcsema::GlobalVariable *>(global_vars, xref) ||
        FishForXref<mcsema::ExternalVariable *>(external_vars, xref) ||
        FishForXref<mcsema::Variable *>(segment_vars, xref) ||
        FishForXref<mcsema::Function *>(func_map, xref) ||
        FishForXref<mcsema::ExternalFunction *>(external_funcs, ext_func_cross_xref) ||
        FishForXref<mcsema::DataReference *>(data_xrefs, xref)) {
      return true;
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

