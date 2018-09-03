#pragma once

#include "ExternalFunctionManager.h"
#include "SectionManager.h"
#include <CFG.pb.h>
#include <CodeObject.h>
#include <Expression.h>
#include <Symtab.h>
#include <Instruction.h>
#include <Dereference.h>

#include <unordered_set>
#include <unordered_map>
#include <sstream>

#include "MagicSection.h"
#include "Util.h"

using SymbolMap = std::unordered_map<Dyninst::Address, std::string>;

class CFGWriter {
public:
  CFGWriter(mcsema::Module &m, const std::string &module_name,
            Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::SymtabCodeSource &symCodeSrc,
            Dyninst::ParseAPI::CodeObject &codeObj,
            ExternalFunctionManager &extFuncMgr);

  void write();

  template<typename CFGUnit=mcsema::Segment>
  struct CrossXref {
    Dyninst::Address ea = 0;
    Dyninst::Address target_ea = 0;
    CFGUnit *segment = nullptr;

    bool operator==(const CrossXref &other) {
      return ea == other.ea && target_ea == other.target_ea;
    }

    bool operator!=(const CrossXref &other) {
      return *this != other;
    }
  };
private:
  /* Don't want to include all functions in binary */
  bool shouldSkipFunction(const std::string &name) const;

  void writeDataVariables(Dyninst::SymtabAPI::Region *region,
                          mcsema::Segment *segment);

  void writeExternalVariables();
  void writeGlobalVariables();
  void writeInternalFunctions();
  void writeBlock(Dyninst::ParseAPI::Block *block,
                  Dyninst::ParseAPI::Function *func,
                  mcsema::Function *cfgInternalFunc);
  void  writeInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                        Dyninst::Address addr, mcsema::Block *cfgBlock);
  void handleCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                             Dyninst::Address addr,
                             mcsema::Instruction *cfgInstruction);
  void
  handleNonCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                           Dyninst::Address addr,
                           mcsema::Instruction *cfgInstruction);

  bool handleDataXref(const CFGWriter::CrossXref<mcsema::Segment> &xref);
  bool handleDataXref(mcsema::Segment *segment,
                      Dyninst::Address ea,
                      Dyninst::Address target);
  void ResolveCrossXrefs();
  void tryParseVariables(Dyninst::SymtabAPI::Region *, mcsema::Segment *);

  void writeExternalFunctions();
  void writeInternalData();
  void writeRelocations(Dyninst::SymtabAPI::Region*, mcsema::Segment *);
  void writeGOT(Dyninst::SymtabAPI::Region*, mcsema::Segment *);

  Dyninst::Address immediateNonCall(Dyninst::InstructionAPI::Immediate *imm,
                        Dyninst::Address addr,
                        mcsema::Instruction *cfgInstruction);
  Dyninst::Address dereferenceNonCall(Dyninst::InstructionAPI::Dereference *,
                          Dyninst::Address,
                          mcsema::Instruction *);

  bool handleXref(mcsema::Instruction *, Dyninst::Address, bool force=true);

  std::string getXrefName(Dyninst::Address addr);
  void xrefsInSegment(Dyninst::SymtabAPI::Region *region,
                      mcsema::Segment *segment );
  bool isNoReturn( const std::string& str);
  void getNoReturns();

  void checkDisplacement(Dyninst::InstructionAPI::Expression *,
                         mcsema::Instruction *);
  bool isExternal(Dyninst::Address addr) const;
  std::string getExternalName(Dyninst::Address addr) const;

  /* Tries to work out RegisterAST if there's some reference */
  bool tryEval(Dyninst::InstructionAPI::Expression *expr,
               const Dyninst::Address ip,
               Dyninst::Address &result) const;

  // #iamverysmart
  /*bool SmarterTryEval(Dyninst::InstructionAPI::Expression *expr,
               const Dyninst::Address ip,
               Dyninst::Address &result,
               Dyninst::Address instruction_size=0) const;
               */
  /* Dyninst related objects */
  mcsema::Module &module;
  std::string module_name;

  Dyninst::SymtabAPI::Symtab &symtab;
  Dyninst::ParseAPI::CodeObject &code_object;
  Dyninst::ParseAPI::SymtabCodeSource &code_source;

  /* After -abi-libraries are fully embraced in master branch, this can go out */
  ExternalFunctionManager &ext_func_manager;
  SectionManager section_manager;

  std::set<std::string> skip_funcss;

  std::unordered_map<Dyninst::Address, std::string> func_map;
  std::unordered_map<Dyninst::Address, std::string> global_vars;
  std::unordered_map<Dyninst::Address, std::string> external_vars;
  std::unordered_map<Dyninst::Address, std::string> segment_vars;
  //std::unordered_map<Dyninst::Address, Dyninst::Address> real_to_imag;
  SymbolMap external_functions;

  //std::vector<Dyninst::SymtabAPI::relocationEntry> relocations;
  std::unordered_set<std::string> no_ret_funcs;
  Dyninst::Address entry_point;

  std::vector<CrossXref<mcsema::Segment>> cross_xrefs;
  std::unordered_set<Dyninst::Address> found_xref;
  std::map<Dyninst::Address, CrossXref<mcsema::Segment>> code_xrefs_to_resolve;
  std::map<Dyninst::Address, CrossXref<mcsema::Instruction>> inst_xrefs_to_resolve;

  MagicSection magic_section;
  int ptr_byte_size = 8;
};
