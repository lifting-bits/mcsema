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

#include <glog/logging.h>

#include <algorithm>

#include <Symtab.h>

#include "OffsetTable.h"
#include "SectionManager.h"

// Sometimes there are no good candidates -> try every possibility
Maybe<Dyninst::Address> OffsetTable::BlindMatch(
    const std::set<Dyninst::Address> &succ) const {

  auto it = start_ea;

  while (it != start_ea + size) {

    if (Recompute(it).Match(succ)) {
      return it;
    }
    // TODO: Entries are smaller (maybe move by 8?)
    it += 4;

  }

  return {};
}

bool OffsetTable::contains(Dyninst::Address addr) const {
  if (addr < start_ea) {
    return false;
  }
  if (addr > start_ea + size) {
    return false;
  }
  return true;
}

Maybe<Dyninst::Address> OffsetTable::Match(
    const std::set<Dyninst::Address> &succs,
    const std::set<Dyninst::Address> &xrefs) const {

  if (xrefs.empty()) {
    return BlindMatch(succs);
  }

  if (Match(succs)) {
    return start_ea;
  }

  for (auto xref_target : xrefs) {
    if (!contains(xref_target)) {
      continue;
    }
    if (Recompute(xref_target).Match(succs)) {
      return xref_target;
    }
  }
  return {};
}


OffsetTable OffsetTable::Recompute(Dyninst::Address new_start_ea) const {
  CHECK(new_start_ea % 4 == 0)
      << "New start of offset table must be properly allign!";
  auto diff = new_start_ea - start_ea;
  OffsetTable table(new_start_ea, region, size - diff);

  auto it = entries.find(new_start_ea);

  while (it != entries.end()) {

    Dyninst::Address recalculated_target = it->second + diff;

    table.entries.insert({it->first, recalculated_target});
    table.targets.insert(recalculated_target);
    ++it;
  }

  return table;
}

// Tries to match with taking into account that it can be in the middle
bool OffsetTable::Match(const std::set<Dyninst::Address> &succs) const {
  if (targets.empty()) {
    DLOG(WARNING) << "Trying to match offset table with no targets";
    return false;
  }

  // Does it contain every successor?
  for (const auto &s : succs) {
    if (!targets.count(s)) {
      return false;
    }
  }

  // For big contiguous tables there might be some need to check if the entries are
  // close enough, but for now this solution works
  auto entry = entries.begin();
  while (!succs.count(entry->second)) {
    ++entry;
    if (entry == entries.end()) {
      return false;
    }
  }

  return true;
}

// This is just a bunch of 64-bit ELF specific heuristics
Maybe<OffsetTable> OffsetTable::Parse(
    const SectionManager &section_m,
    Dyninst::Address start_ea,
    int32_t *reader,
    Dyninst::SymtabAPI::Region *region,
    size_t size) {

  // It has to be alligned
  if (start_ea % 4) {
    return {};
  }

  // Don't know yet if both ea and target_ea are needed
  // This is lazy (and terrible) solution to avoid duplicities
  OffsetTable table{start_ea, region, size};

  for (Dyninst::Address it_ea = start_ea; it_ea < start_ea + size;
      it_ea += 4, ++reader) {

    // Get what is that entry truly pointing to
    auto target_ea = table.start_ea - ~(*reader) - 1;

    if (section_m.IsCode(target_ea)) {
      table.targets.insert({target_ea});
      table.entries.insert({it_ea, target_ea});

    } else if (target_ea == start_ea) {
      table.start_ea += 4;

    } else {
      // It doesn't point into text, it is not a jump table
      return {};
    }
  }

  if (table.entries.size() < 3) {
    return {};
  }

  LOG(INFO) << "Parsed offset table starting at 0x" << std::hex << start_ea
            << " -> " << table.entries.size() * 4 + start_ea << " (contains "
            << std::dec << table.entries.size() << ")";

  return {std::move(table)};
}
