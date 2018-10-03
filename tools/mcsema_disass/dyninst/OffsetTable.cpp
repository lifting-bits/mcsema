#include "OffsetTable.h"

#include <Symtab.h>

#include <glog/logging.h>

#include "SectionManager.h"

std::experimental::optional<OffsetTable> OffsetTable::Parse(
    Dyninst::Address start_ea,
    int32_t *reader,
    Dyninst::SymtabAPI::Region *region,
    size_t size) {

  OffsetTable table{start_ea, region, size};

  for (Dyninst::Address it_ea = start_ea; it_ea < start_ea + size;
      it_ea += 4, ++reader) {

    // Get what is that entry truly pointing to
    auto target_ea = start_ea - ~(*reader) - 1;
    if (gSectionManager->IsInRegion(".text", target_ea)) {
      table.entries.insert({it_ea, target_ea});
    } else {

      // It doesn't point into text, it is not a jump table
      return {};
    }
  }

  LOG(INFO) << "Parse offset table starting at 0x" << std::hex << start_ea
            << " containing " << std::dec << table.entries.size();
  return {std::move(table)};
}
