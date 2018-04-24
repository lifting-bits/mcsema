#pragma once

#include "ExternalFunctionManager.hpp"
#include "SectionManager.hpp"
#include <CFG.pb.h>
#include <CodeObject.h>
#include <Expression.h>
#include <Symtab.h>

#include <unordered_set>

class CFGWriter {
public:
  CFGWriter(mcsema::Module &m, const std::string &moduleName,
            Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::CodeObject &codeObj,
            const ExternalFunctionManager &extFuncMgr);

  // Causes the function called "name" to be skipped (see below)
  void skipFunction(const std::string &name);

  void write();

private:
  // Some internal functions (such as __libc_csu_init) tend to cause
  // problems when disassembling. When the lifted code gets
  // recompiled, the linker will add those functions again, anyways,
  // so we just skip them here. This function returns true iff the
  // function called "name" should be skipped.
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

  bool isExternal(Dyninst::Address addr) const;
  const std::string &getExternalName(Dyninst::Address addr) const;
  bool tryEval(Dyninst::InstructionAPI::Expression *expr,
               const Dyninst::Address ip, Dyninst::Address &result) const;

  mcsema::Module &m_module;
  std::string m_moduleName;
  Dyninst::SymtabAPI::Symtab &m_symtab;
  Dyninst::ParseAPI::CodeObject &m_codeObj;
  const ExternalFunctionManager &m_extFuncMgr;

  std::map<Dyninst::Offset, std::string> m_funcMap;
  std::set<std::string> m_skipFuncs;

  std::set<Dyninst::SymtabAPI::Symbol *> m_globalVars;
  std::unordered_set<Dyninst::SymtabAPI::Symbol *> m_externalVars;

  SectionManager m_sectionMgr;
  std::vector<Dyninst::SymtabAPI::relocationEntry> m_relocations;
};
