/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "OffsetTable.h"
#include "Util.h"

struct SectionManager;

namespace Dyninst {
namespace SymtabAPI {
class Region;
}
}  // namespace Dyninst

namespace mcsema {
class Segment;
}


struct SectionParser {
  using CrossXrefMap = std::map<Dyninst::Address, CrossXref<mcsema::Segment>>;

  SectionParser(DisassContext *disass_context, SectionManager &section_manager)
      : disass_context(disass_context),
        section_manager(section_manager){

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
  bool TryOffsetTable(uint64_t &offset, Dyninst::SymtabAPI::Region *region);
  bool TryVar(uint64_t &offset, Dyninst::SymtabAPI::Region *region,
              mcsema::Segment *cfg_segment);

  // For variable names
  int unnamed = 0;
  int counter = 0;

  std::vector<CrossXref<mcsema::Segment>> cross_xrefs;
  CrossXrefMap unresolved_code_xrefs;
  std::vector<OffsetTable> offset_tables;
};
