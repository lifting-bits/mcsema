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

#include <dyntypes.h>

#include <map>
#include <set>

#include "Maybe.h"

namespace Dyninst {
namespace SymtabAPI {
class Region;
}
}  // namespace Dyninst

struct SectionManager;

// Holds information about possible jump tables
// For 64, and possibly 32, bit ELF
struct OffsetTable {
  static Maybe<OffsetTable>
  Parse(const SectionManager &section_m, Dyninst::Address start_ea,
        int32_t *reader, Dyninst::SymtabAPI::Region *region, size_t size);

  Dyninst::Address ea() const {
    return start_ea;
  }

  bool contains(Dyninst::Address addr) const;
  Maybe<Dyninst::Address> Match(const std::set<Dyninst::Address> &succ,
                                const std::set<Dyninst::Address> &xrefs) const;

  OffsetTable Recompute(Dyninst::Address new_start_ea) const;

  bool Match(const std::set<Dyninst::Address> &targets) const;

  // TODO: This only exists so that Maybe<OffsetTable> can be constructed
  OffsetTable() = default;

 private:
  OffsetTable(Dyninst::Address start_ea, Dyninst::SymtabAPI::Region *region,
              size_t size)
      : start_ea(start_ea),
        region(region),
        size(size) {}

  Maybe<Dyninst::Address>
  BlindMatch(const std::set<Dyninst::Address> &succ) const;

  Dyninst::Address start_ea;
  Dyninst::SymtabAPI::Region *region;
  size_t size;

  // For now I want them ordered {ea, in form start_ea - *ea - 1}
  std::map<Dyninst::Address, Dyninst::Address> entries;

  // Set of all values in entries
  std::set<Dyninst::Address> targets;
};
