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

#include "SectionParser.h"

SectionParser::CrossXrefMap SectionParser::ResolveCrossXrefs() {
  for (auto &xref : cross_xrefs) {
    auto g_var = disass_context->global_vars.find(xref.target_ea);
    if (g_var != disass_context->global_vars.end()) {
      LOG(ERROR)
          << "CrossXref is targeting global variable, was not resolved earlier!";
      continue;
    }

    if (!disass_context->HandleDataXref(xref)) {
      if (section_manager.IsInRegions({".data", ".rodata", ".bss"},
                                      xref.target_ea)) {
        disass_context->WriteAndAccount(xref);
      }
    }
    // If it's xref into .text it's highly possible it is
    // entrypoint of some function that was missed by speculative parse.
    // Let's try to parse it now

    if (section_manager.IsInRegion(".text", xref.target_ea)) {
      LOG(INFO) << std::hex << xref.target_ea << " is unresolved";
      unresolved_code_xrefs.insert({xref.target_ea, xref});
    }
  }
  return unresolved_code_xrefs;
}

bool SectionParser::TryXref(uint64_t offset, Dyninst::SymtabAPI::Region *region,
                            mcsema::Segment *cfg_segment) {

  // Allignment
  if (offset % 8) {
    return false;
  }

  auto *reader = reinterpret_cast<uint64_t *>(
      static_cast<uint8_t *>(region->getPtrToRawData()) + offset);
  Dyninst::Address target_ea = *reader;
  Dyninst::Address ea = region->getMemOffset() + offset;

  if (disass_context->HandleDataXref({ea, target_ea, cfg_segment})) {
    LOG(INFO) << "Fished up " << std::hex << region->getMemOffset() + offset
              << " => " << target_ea;
    return true;
  }

  if (section_manager.IsInRegion(region, target_ea)) {
    std::string name =
        region->getRegionName() + "_unnamed_" + std::to_string(++unnamed);
    disass_context->WriteAndAccount({ea, target_ea, cfg_segment, name});

    // TODO(lukas): If we once try lift variables again
    //Now add target as var because it was not before
    //auto cfg_var = cfg_segment->add_vars();
    //cfg_var->set_name(name);
    //cfg_var->set_ea(target_ea);
    //disass_context->segment_vars.insert({target_ea, cfg_var});
    return true;

  } else if (target_ea && section_manager.IsInBinary(target_ea)) {
    cross_xrefs.push_back({ea, target_ea, cfg_segment});
    return true;
  }
  return false;
}

bool SectionParser::TryOffsetTable(uint64_t &offset,
                                   Dyninst::SymtabAPI::Region *region) {

  // Allignment
  if (offset % 4) {
    return false;
  }
  Dyninst::Address ea = region->getMemOffset() + offset;
  auto *reader = reinterpret_cast<uint32_t *>(
      static_cast<uint8_t *>(region->getPtrToRawData()) + offset);
  auto entry_reader = reader;

  // While it is a valid offset
  // TODO(lukas): Last entry can actually be an xref
  auto size = 0U;
  while (section_manager.IsCode(ea - ~(*entry_reader)) &&
         size + offset < region->getMemSize()) {
    size += 4;
    ++entry_reader;
  }

  // Try to build the table from it, depending on number of entries should succeed.
  auto table = OffsetTable::Parse(
      section_manager, ea, reinterpret_cast<int32_t *>(reader), region, size);
  if (table) {
    offset_tables.push_back(std::move(table.value()));
    offset += size;
    return true;
  }
  return false;
}

bool SectionParser::TryVar(uint64_t &offset, Dyninst::SymtabAPI::Region *region,
                           mcsema::Segment *cfg_segment) {
  auto *byte_reader = reinterpret_cast<uint8_t *>(
      static_cast<uint8_t *>(region->getPtrToRawData()) + offset);

  auto entry = 4;
  while (!*byte_reader && offset < region->getMemSize() && entry) {
    ++offset;
    --entry;
  }
  if (!entry || offset >= region->getMemSize()) {
    return false;
  }

  auto size = 0U;
  while (*byte_reader && size + offset < region->getMemSize()) {
    ++byte_reader;
    ++size;
  }

  std::string name = region->getRegionName() + "_" + std::to_string(++counter);
  LOG(INFO) << "Found var " << name << " at 0x" << std::hex
            << region->getMemOffset() + offset << " of size " << std::dec
            << size;

  // TODO(lukas): Var related
  //auto var = cfg_segment->add_vars();
  //var->set_ea(region->getMemOffset() + offset);
  //var->set_name(name);
  //disass_context->segment_vars.insert({region->getMemOffset() +  offset, var});

  // Clean all 0s that may have been added due to mem allign
  while (!*byte_reader && size + offset < region->getMemSize() &&
         ((offset + size) % 8)) {
    ++byte_reader;
    ++size;
  }
  offset += size;
  return true;
}

void SectionParser::ParseVariables(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {

  auto end = region->getMemOffset() + region->getMemSize();

  LOG(INFO) << "Trying to parse region " << region->getRegionName()
            << " for xrefs & vars";
  LOG(INFO) << "Starts at 0x" << std::hex << region->getMemOffset()
            << " ends at 0x" << end;

  for (uint64_t offset = 0U; offset < region->getMemSize();) {
    CHECK(region->getMemOffset() + offset == region->getDiskOffset() + offset)
        << "Memory reader != Disk reader, investigate!";

    if (TryXref(offset, region, segment)) {
      offset += 8;
      continue;
    }

    if (TryOffsetTable(offset, region)) {
      continue;
    }

    //TryVar(offset, region, segment);
    ++offset;
    while (offset % 4) {
      ++offset;
    }
  }
}

void SectionParser::XrefsInSegment(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {

  // Both are using something smarter, as they may contain other
  // data as static strings

  auto offset = static_cast<std::uint64_t *>(region->getPtrToRawData());

  for (auto j = 0U; j < region->getDiskSize(); j += 8, offset++) {
    if (!disass_context->HandleDataXref(
            {region->getMemOffset() + j, *offset, segment})) {
      if (section_manager.IsInRegion(".text", *offset)) {
        LOG(INFO) << "\tXref is pointing into .text";
        unresolved_code_xrefs.insert(
            {*offset, {region->getMemOffset() + j, *offset, segment}});
      }
    }
  }
}
