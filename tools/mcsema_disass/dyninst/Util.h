#pragma once

#include <string>
#include <memory>

#include <CFG.pb.h>

#include <Symtab.h>
#include <dyntypes.h>
#include <type_traits>

#include "MagicSection.h"
#include "SectionManager.h"

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
struct CrossXref {
  Dyninst::Address ea = 0;
  Dyninst::Address target_ea = 0;
  CFGUnit segment = nullptr;

  bool operator==(const CrossXref<CFGUnit> &other) {
    return ea == other.ea && target_ea == other.target_ea;
  }

  bool operator!=(const CrossXref<CFGUnit> &other) {
    return *this != other;
  }

  mcsema::DataReference *WriteDataXref(
      const std::string &name="",
      bool is_code=false,
      uint64_t width=8) const {
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
  using SymbolMap = std::map<Dyninst::Address, T>;

  // TODO(lukas): I want heterogeneous container :'{!
  SymbolMap<mcsema::Function *> func_map;
  SymbolMap<mcsema::GlobalVariable *> global_vars;
  SymbolMap<mcsema::ExternalVariable *> external_vars;
  SymbolMap<mcsema::Variable *> segment_vars;
  SymbolMap<mcsema::ExternalFunction *> external_funcs;
  SymbolMap<mcsema::DataReference *> data_xrefs;

  std::vector<Dyninst::Address> segment_eas;
  MagicSection magic_section;

  template<typename Container>
  bool FishForXref(const Container &facts,
                   CrossXref<mcsema::Segment *> &xref,
                   bool is_code=false,
                   uint64_t width=8) {
    auto fact = facts.find(xref.target_ea);
    if (fact != facts.end()) {
      auto cfg_xref = xref.WriteDataXref(fact->second->name(), is_code, width);
      data_xrefs.insert({cfg_xref->ea(), cfg_xref});
      LOG(INFO) << "\tResolved 0x" << std::hex << xref.ea << " -> 0x" << xref.target_ea;
      return true;
    }
    return false;
  }

  bool HandleDataXref(CrossXref<mcsema::Segment *> &xref) {
    if (FishForXref(global_vars, xref) ||
        FishForXref(external_funcs, xref, true) ||
        FishForXref(external_vars, xref) ||
        FishForXref(segment_vars, xref) ||
        FishForXref(func_map, xref, true)) {

        //FishForXref(data_xrefs, xref)) {
      data_xrefs.insert({static_cast<Dyninst::Address>(xref.ea), xref.segment->mutable_xrefs(xref.segment->xrefs_size() - 1)});
      return true;
    }
    return false;
  }

  template<typename Base, typename Container>
  bool FishForXref(const Container &facts,
                   const CrossXref<mcsema::Instruction *> &xref) {

    auto fact = facts.find(xref.target_ea);
    if (fact == facts.end()) {
      return false;
    }


    if constexpr (std::is_same<Base, mcsema::Function *>()) {
      LOG(INFO) << "\tResolved as internal function";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::ControlFlowOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::ExternalFunction *>()) {
      // Mapping to magic_section
      LOG(INFO) << "\tResolved as ext function";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::ControlFlowOperand,
                  mcsema::CodeReference::External,
                  magic_section.GetAllocated(xref.target_ea),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::GlobalVariable *>()) {
      LOG(INFO) << "\tResolved as global variable";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::Variable *>()) {
      LOG(INFO) << "\tResolved as segment variable";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea(),
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::ExternalVariable *>()) {
      Dyninst::Address addr = magic_section.GetAllocated(xref.target_ea);
      LOG(INFO) << "\tResolved as external variable";
      if (!addr) {
        addr = fact->second->ea();
      }
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::External,
                  addr,
                  fact->second->name());
      return true;
    } else if constexpr (std::is_same<Base, mcsema::DataReference *>()) {
      LOG(INFO) << "\tResolved as data xref";
      AddCodeXref(xref.segment,
                  mcsema::CodeReference::DataTarget,
                  mcsema::CodeReference::MemoryOperand,
                  mcsema::CodeReference::Internal,
                  fact->second->ea());
      return true;
    }
    return false;
  }

  bool HandleCodeXref(const CrossXref<mcsema::Instruction *> &xref, bool force=true) {
    LOG(INFO) << "Trying to resolve 0x" << std::hex << xref.ea << " -> 0x"
              << xref.target_ea;
    if (FishForXref<mcsema::GlobalVariable *>(global_vars, xref) ||
        FishForXref<mcsema::ExternalFunction *>(external_funcs, xref) ||
        FishForXref<mcsema::ExternalVariable *>(external_vars, xref) ||
        FishForXref<mcsema::Variable *>(segment_vars, xref) ||
        FishForXref<mcsema::Function *>(func_map, xref) ||
        FishForXref<mcsema::DataReference *>(data_xrefs, xref)) {
      return true;
    }

    // If one string is a proper substring, there can be reference to middle
    // of a variable
    // E.g printf("%s: %s\n", "partial string test", "string test");
    // .rodata will contain only partial string test and proper offset
    // will be used when "string test" is needed
    if (gSectionManager->IsInRegions({".data", ".rodata", ".bss"}, xref.target_ea)) {
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

