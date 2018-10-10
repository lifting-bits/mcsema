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
#include "OffsetTable.h"

using SymbolMap = std::unordered_map<Dyninst::Address, std::string>;

class CFGWriter {
public:
  CFGWriter(mcsema::Module &m,
            Dyninst::SymtabAPI::Symtab &symtab,
            Dyninst::ParseAPI::SymtabCodeSource &symCodeSrc,
            Dyninst::ParseAPI::CodeObject &codeObj);

  void Write();

private:
  void WriteDataVariables(Dyninst::SymtabAPI::Region *region,
                          mcsema::Segment *segment);

  void WriteExternalVariables();
  void WriteGlobalVariables();
  void WriteInternalFunctions();
  void WriteLocalVariables();
  void WriteBlock(Dyninst::ParseAPI::Block *block,
                  Dyninst::ParseAPI::Function *func,
                  mcsema::Function *cfgInternalFunc);
  void  WriteInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                         Dyninst::Address addr, mcsema::Block *cfgBlock);
  void HandleCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                             Dyninst::Address addr,
                             mcsema::Instruction *cfgInstruction);
  void
  HandleNonCallInstruction(Dyninst::InstructionAPI::Instruction *instruction,
                           Dyninst::Address addr,
                           mcsema::Instruction *cfgInstruction);

  void ResolveCrossXrefs();
  void TryParseVariables(Dyninst::SymtabAPI::Region *, mcsema::Segment *);

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

  void XrefsInSegment(Dyninst::SymtabAPI::Region *region,
                      mcsema::Segment *segment );
  bool IsNoReturn( const std::string& str);
  void GetNoReturns();

  void CheckDisplacement(Dyninst::InstructionAPI::Expression *,
                         mcsema::Instruction *);
  bool IsExternal(Dyninst::Address addr) const;

  mcsema::Module &module;

  /* Dyninst related objects */
  Dyninst::SymtabAPI::Symtab &symtab;
  Dyninst::ParseAPI::CodeObject &code_object;
  Dyninst::ParseAPI::SymtabCodeSource &code_source;

  std::unordered_set<std::string> no_ret_funcs;

  std::vector<CrossXref<mcsema::Segment *>> cross_xrefs;
  std::map<Dyninst::Address, CrossXref<mcsema::Segment *>> code_xrefs_to_resolve;
  std::map<Dyninst::Address, CrossXref<mcsema::Instruction *>> inst_xrefs_to_resolve;

  std::vector<OffsetTable> offset_tables;
  MagicSection &magic_section;
  int ptr_byte_size = 8;
};
