#pragma once

#include "Util.h"
#include "OffsetTable.h"

struct SectionManager;

namespace Dyninst {
  namespace SymtabAPI {
    struct Region;
  }
}

namespace mcsema {
  struct Segment;
}



struct SectionParser {
  using CrossXrefMap = std::map<Dyninst::Address, CrossXref<mcsema::Segment *>>;

  SectionParser(DisassContext *disass_context,
                SectionManager &section_manager) :
    disass_context(disass_context),
    section_manager(section_manager) {

    };

  // More detailed parse for .data, .rodata
  void ParseVariables(Dyninst::SymtabAPI::Region *region,
                         mcsema::Segment *segment);

  // Simple parse looking only for alligned xrefs
  void XrefsInSegment(Dyninst::SymtabAPI::Region *region,
                      mcsema::Segment *segment);

  // Try to resolve what can be resolved return rest
  CrossXrefMap ResolveCrossXrefs();

  std::vector<OffsetTable> GetOffsetTables() {
    return offset_tables;
  }


private:
  DisassContext *disass_context;
  SectionManager &section_manager;

  // For variable names
  int unnamed = 0;
  int counter = 0;

  std::vector<CrossXref<mcsema::Segment *>> cross_xrefs;
  CrossXrefMap unresolved_code_xrefs;
  std::vector<OffsetTable> offset_tables;
};
