#pragma once

#include "ExternalFunctionManager.hpp"
#include "SectionManager.hpp"
#include <CFG.pb.h>
#include <CodeObject.h>
#include <Dereference.h>
#include <Expression.h>
#include <Instruction.h>
#include <Symtab.h>

#include <unordered_map>
#include <unordered_set>

class CFGWriter {
public:
  CFGWriter(mcsema::Module &m, const std::string &moduleName,
            Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::SymtabCodeSource &symCodeSrc,
            Dyninst::ParseAPI::CodeObject &codeObj,
            const ExternalFunctionManager &extFuncMgr);

  void write();

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
  void writeInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                        Dyninst::Address addr, mcsema::Block *cfgBlock);
  void handleCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                             Dyninst::Address addr,
                             mcsema::Instruction *cfgInstruction);
  void
  handleNonCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                           Dyninst::Address addr,
                           mcsema::Instruction *cfgInstruction);
  void writeExternalFunctions();
  void writeInternalData();
  void writeRelocations(Dyninst::SymtabAPI::Region *, mcsema::Segment *);

  void immediateNonCall(Dyninst::InstructionAPI::Immediate *imm,
                        Dyninst::Address addr,
                        mcsema::Instruction *cfgInstruction);
  void dereferenceNonCall(Dyninst::InstructionAPI::Dereference *,
                          Dyninst::Address, mcsema::Instruction *);

  std::string getXrefName(Dyninst::Address addr);
  void xrefsInSegment(Dyninst::SymtabAPI::Region *region,
                      mcsema::Segment *segment);
  bool isNoReturn(const std::string &str);
  void getNoReturns();

  void checkDisplacement(Dyninst::InstructionAPI::Instruction *,
                         mcsema::Instruction *);
  bool isExternal(Dyninst::Address addr) const;
  const std::string &getExternalName(Dyninst::Address addr) const;

  /* Tries to work out RegisterAST if there's some reference */
  bool tryEval(Dyninst::InstructionAPI::Expression *expr,
               const Dyninst::Address ip, Dyninst::Address &result) const;

  /* Dyninst related objects */
  mcsema::Module &m_module;
  std::string m_moduleName;
  Dyninst::SymtabAPI::Symtab &m_symtab;
  Dyninst::ParseAPI::CodeObject &m_codeObj;
  Dyninst::ParseAPI::SymtabCodeSource &m_codeSource;

  /* After -abi-libraries are fully embraced in master branch, this can go out
   */
  const ExternalFunctionManager &m_extFuncMgr;
  SectionManager m_sectionMgr;

  std::set<std::string> m_skipFuncs;

  std::unordered_map<Dyninst::Offset, std::string> m_funcMap;
  std::unordered_map<Dyninst::Address, Dyninst::SymtabAPI::Symbol *>
      m_globalVars;
  std::unordered_map<Dyninst::Address, Dyninst::SymtabAPI::Symbol *>
      m_externalVars;
  std::unordered_map<Dyninst::Address, Dyninst::SymtabAPI::Symbol *>
      m_segmentVars;

  std::vector<Dyninst::SymtabAPI::relocationEntry> m_relocations;
  std::unordered_set<std::string> m_noreturnFunctions;
};
