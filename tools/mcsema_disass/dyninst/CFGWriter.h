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


class CFGWriter {
public:
  CFGWriter(mcsema::Module &m, const std::string &module_name,
            Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::SymtabCodeSource &symCodeSrc,
            Dyninst::ParseAPI::CodeObject &codeObj,
            const ExternalFunctionManager &extFuncMgr,
            Dyninst::Address entry_addres);

  void write();
  using SymbolMap = std::unordered_map<Dyninst::Offset, std::string>;

  struct CrossXref {
    Dyninst::Address ea;
    Dyninst::Address target_ea;
    mcsema::Segment *segment;
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

  bool handleDataXref(mcsema::Segment *segment,
                      Dyninst::Address ea,
                      Dyninst::Address target);
  void ResolveCrossXrefs();
  void tryParseVariables(Dyninst::SymtabAPI::Region *, mcsema::Segment *);

  void writeExternalFunctions();
  void writeInternalData();
  void writeRelocations(Dyninst::SymtabAPI::Region*, mcsema::Segment *);

  void immediateNonCall(Dyninst::InstructionAPI::Immediate *imm,
                        Dyninst::Address addr,
                        mcsema::Instruction *cfgInstruction);
  void dereferenceNonCall(Dyninst::InstructionAPI::Dereference *,
                          Dyninst::Address,
                          mcsema::Instruction *);

  void handleXref(mcsema::Instruction *, Dyninst::Address);

  std::string getXrefName(Dyninst::Address addr);
  void xrefsInSegment(Dyninst::SymtabAPI::Region *region,
                      mcsema::Segment *segment );
  bool isNoReturn( const std::string& str);
  void getNoReturns();

  void checkDisplacement(Dyninst::InstructionAPI::Instruction *,
                         mcsema::Instruction *);
  bool isExternal(Dyninst::Address addr) const;
  const std::string &getExternalName(Dyninst::Address addr) const;

  /* Tries to work out RegisterAST if there's some reference */
  bool tryEval(Dyninst::InstructionAPI::Expression *expr,
               const Dyninst::Address ip,
               Dyninst::Address &result) const;


  /* Dyninst related objects */
  mcsema::Module &module;
  std::string module_name;

  Dyninst::SymtabAPI::Symtab &symtab;
  Dyninst::ParseAPI::CodeObject &code_object;
  Dyninst::ParseAPI::SymtabCodeSource &code_source;

  /* After -abi-libraries are fully embraced in master branch, this can go out */
  const ExternalFunctionManager &ext_func_manager;
  SectionManager section_manager;

  std::set<std::string> skip_funcss;

  std::unordered_map<Dyninst::Address, std::string> func_map;
  std::unordered_map<Dyninst::Address, std::string> global_vars;
  std::unordered_map<Dyninst::Address, std::string> external_vars;
  std::unordered_map<Dyninst::Address, std::string> segment_vars;

  std::vector<Dyninst::SymtabAPI::relocationEntry> relocations;
  std::unordered_set<std::string> no_ret_funcs;
  Dyninst::Address entry_point;

  std::vector<CrossXref> cross_xrefs;
  std::unordered_set<Dyninst::Address> found_xref;
};
