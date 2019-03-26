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

#include "Util.h"
#include "OffsetTable.h"

struct SectionManager;

namespace Dyninst {
  namespace SymtabAPI {
    class Region;
  }
}

namespace mcsema {
  class Segment;
}



struct SectionParser {
  using CrossXrefMap = std::map<Dyninst::Address, CrossXref<mcsema::Segment>>;

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

  bool TryXref(uint64_t offset, Dyninst::SymtabAPI::Region *region,
               mcsema::Segment *cfg_segment);
  bool TryOffsetTable(uint64_t &offset,
                      Dyninst::SymtabAPI::Region *region);
  bool TryVar(uint64_t &offset,
              Dyninst::SymtabAPI::Region *region,
              mcsema::Segment *cfg_segment);

  // For variable names
  int unnamed = 0;
  int counter = 0;

  std::vector<CrossXref<mcsema::Segment>> cross_xrefs;
  CrossXrefMap unresolved_code_xrefs;
  std::vector<OffsetTable> offset_tables;
};
