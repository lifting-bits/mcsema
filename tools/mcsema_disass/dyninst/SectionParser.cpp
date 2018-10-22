#include "SectionParser.h"

SectionParser::CrossXrefMap SectionParser::ResolveCrossXrefs() {
  for (auto &xref : cross_xrefs) {
    auto g_var = disass_context->global_vars.find(xref.target_ea);
    if (g_var != disass_context->global_vars.end()) {
      LOG(ERROR)
          << "CrossXref is targeting global variable, was not resolved earlier!";
      continue;
    }

    if(!disass_context->HandleDataXref(xref)) {
      if (section_manager.IsInRegions({".data", ".rodata", ".bss"},
                                       xref.target_ea)) {
        LOG(INFO) << "It is pointing into data sections, assuming it is xref";
        disass_context->WriteAndAccount(xref);
      }
    }
    // If it's xref into .text it's highly possible it is
    // entrypoint of some function that was missed by speculative parse.
    // Let's try to parse it now

    if (section_manager.IsInRegion(".text", xref.target_ea)) {
      LOG(INFO) << "\tIs acturally targeting something in .text!";
      unresolved_code_xrefs.insert({xref.target_ea, xref});
    }
  }
  return unresolved_code_xrefs;
}

void SectionParser::ParseVariables(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {

  std::string base_name = region->getRegionName();
  auto offset = static_cast<uint8_t *>(region->getPtrToRawData());
  auto end = region->getMemOffset() + region->getMemSize();

  LOG(INFO) << "Trying to parse region " << region->getRegionName()
            << " for xrefs & vars";
  LOG(INFO) << "Starts at 0x" << std::hex << region->getMemOffset()
            << " ends at 0x" << end;

  for (auto j = 0U; j < region->getDiskSize(); j += 1, ++offset) {
    CHECK(region->getMemOffset() + j == region->getDiskOffset() + j)
        << "Memory offset != Disk offset, investigate!";

    if (*offset == 0) {
      continue;
    }

    // Read until next zero
    uint64_t size = j;
    while (*offset != 0) {
      ++j;
      ++offset;
      if (region->getMemOffset() + j == end) {
        LOG(INFO) << "Hit end of region";
        break;
      }
    }

    // Zero was found, but it may have been something like
    // 04 bc 00 00 so zero is still valid part of address
    uint64_t off = size % 4;
    auto diff = j - size;

    if (diff + off <= 4) {
      diff += off;
    }

    // Check if it is small enough to be a one reference and try to match it
    // against the rest of the binary to see if it truly is a reference
    if (diff <= 4 && diff  >= 3) {
      auto tmp_ptr = reinterpret_cast<uint64_t *>(static_cast<uint8_t *>(
            region->getPtrToRawData()) + size - off);
      Dyninst::Address target_ea = *tmp_ptr;
      Dyninst::Address ea = region->getMemOffset() + size - off;

      if (disass_context->HandleDataXref({ea, target_ea, segment})) {
        LOG(INFO) << "Fished up " << std::hex
                  << region->getMemOffset() + size << " " << *tmp_ptr;
        continue;
      }

      if (section_manager.IsInRegion(region, target_ea)) {
        std::string name = base_name + "_unnamed_" + std::to_string(++unnamed);
        disass_context->WriteAndAccount({ea, target_ea, segment, name});

        //Now add target as var because it was not before
        auto cfg_var = segment->add_vars();
        cfg_var->set_name(name);
        cfg_var->set_ea(target_ea);
        disass_context->segment_vars.insert({target_ea, cfg_var});
        continue;

      } else if (section_manager.IsInBinary(target_ea)) {
        LOG(INFO) << "Cross xref 0x" << std::hex
                  << ea << " -> 0x" << target_ea;
        cross_xrefs.push_back({ea, target_ea, segment});
        continue;
      }
    }

    // Now we know it is not a simple xref, but it still may be an OffsetTable
    // which is a jump table (for example from switch statement)

    Dyninst::Address ea = region->getMemOffset() + size;
    auto *ptr_to_value = reinterpret_cast<int32_t *>(
        static_cast<uint8_t *>(region->getPtrToRawData()) + size);

    auto alligment = (ea + j - size) % 4;
    auto table = OffsetTable::Parse(ea, ptr_to_value, region, j - size - alligment);
    if (table) {
      offset_tables.push_back(std::move(table.value()));
      j -= alligment;
      continue;
    }

    std::string name = base_name + "_" + std::to_string(counter);
    ++counter;
    LOG(INFO) << "\tAdding var " << name << " at 0x"
              << std::hex << region->getMemOffset() + size;
    auto var = segment->add_vars();
    var->set_ea(region->getMemOffset() + size);
    var->set_name(name);
    disass_context->segment_vars.insert({region->getMemOffset() + size, var});
  }
}

void SectionParser::XrefsInSegment(Dyninst::SymtabAPI::Region *region,
                                   mcsema::Segment *segment) {

  // Both are using something smarter, as they may contain other
  // data as static strings
  if (region->getRegionName() == ".data" ||
      region->getRegionName() == ".rodata") {
    return;
  }
  auto offset = static_cast<std::uint64_t*>(region->getPtrToRawData());

  for (auto j = 0U; j < region->getDiskSize(); j += 8, offset++) {
    if (!disass_context->HandleDataXref(
          {region->getMemOffset() + j, *offset, segment})) {
      LOG(INFO) << "\tDid not resolve it, try to search in .text";

      if (section_manager.IsInRegion(".text", *offset)) {
        LOG(INFO) << "\tXref is pointing into .text";
        unresolved_code_xrefs.insert(
            {*offset,{region->getMemOffset() + j, *offset, segment}});
      }
    }
  }
}
