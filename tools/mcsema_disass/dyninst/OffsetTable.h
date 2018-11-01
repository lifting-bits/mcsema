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

#include <dyntypes.h>
#include <set>
#include <map>

#include <experimental/optional>

namespace Dyninst {
  namespace SymtabAPI {
    class Region;
  }
}

// Holds information about possible jump tables
// For 64, and possibly 32, bit ELF
struct OffsetTable {
  static std::experimental::optional<OffsetTable> Parse(
      Dyninst::Address start_ea,
      int32_t *reader,
      Dyninst::SymtabAPI::Region *region,
      size_t size);

  Dyninst::Address ea() const {
    return start_ea;
  }

  bool contains(Dyninst::Address addr) const;
  std::experimental::optional<Dyninst::Address> Match(
      const std::set<Dyninst::Address> &succ,
      const std::set<Dyninst::Address> &xrefs) const;

  OffsetTable Recompute(Dyninst::Address new_start_ea) const;

  bool Match(const std::set<Dyninst::Address> &targets) const;
  //bool SubsetMatch(const std::set<Dyninst::Address> &targets) const;
private:
  OffsetTable(Dyninst::Address start_ea,
              Dyninst::SymtabAPI::Region *region,
              size_t size) : start_ea(start_ea), region(region), size(size) {}

  Dyninst::Address start_ea;
  Dyninst::SymtabAPI::Region *region;
  size_t size;

  // For now I want them ordered {ea, in form start_ea - *ea - 1}
  std::map<Dyninst::Address, Dyninst::Address> entries;
  // Set of all values in entries
  std::set<Dyninst::Address> targets;

};
