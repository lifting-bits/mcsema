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

#include "OffsetTable.h"

#include <Symtab.h>

#include <glog/logging.h>

#include <algorithm>

#include "SectionManager.h"

bool OffsetTable::contains(Dyninst::Address addr) const {
  if (addr < start_ea) {
    return false;
  }
  if (addr > start_ea + size) {
    return false;
  }
  return true;
}

std::experimental::optional<Dyninst::Address> OffsetTable::Match(
    const std::set<Dyninst::Address> &succs,
    const std::set<Dyninst::Address> &xrefs) const {

  if (xrefs.count(start_ea) && Match(succs)) {
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
  CHECK(!targets.empty()) << "Trying to match offset table with no targets";

  // Does it contain every successor?
  for (const auto &s : succs) {
    if (!targets.count(s)) {
      return false;
    }
  }

  // This offset table contains all targets, but now we need to check
  // they are really part of one table
  auto entry = entries.begin();
  while (!succs.count(entry->second)) {
    ++entry;
    if (entry == entries.end()) {
      return false;
    }
  }

  // We encountered first one, now we need to iterate all the known ones
  while (!(entry == entries.end()) && succs.count(entry->second)) {
    ++entry;
  }

  while (!(entry == entries.end()) && !succs.count(entry->second)) {
    ++entry;
  }

  return entry == entries.end();
}

// This is just a bunch of 64-bit ELF specific heuristics
std::experimental::optional<OffsetTable> OffsetTable::Parse(
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
    if (gSectionManager->IsInRegion(".text", target_ea)) {
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
    LOG(INFO) << "0x" << std::hex << start_ea
              << " contains only " << std::dec << table.entries.size()
              << " therefore is probably not offset table";
    return {};
  }

  LOG(INFO) << "Parse offset table starting at 0x" << std::hex << start_ea
            << " containing " << std::dec << table.entries.size();

  return {std::move(table)};
}
