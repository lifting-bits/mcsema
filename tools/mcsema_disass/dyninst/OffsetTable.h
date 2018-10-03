#include <dyntypes.h>
#include <set>
#include <utility>

#include <experimental/optional>

namespace Dyninst::SymtabAPI {
  class Region;
}

// Holds information about possible jump tables
struct OffsetTable {
  static std::experimental::optional<OffsetTable> Parse(
      Dyninst::Address start_ea,
      int32_t *reader,
      Dyninst::SymtabAPI::Region *region,
      size_t size);

private:
  OffsetTable(Dyninst::Address start_ea,
              Dyninst::SymtabAPI::Region *region,
              size_t size) : start_ea(start_ea), region(region), size(size) {}

  Dyninst::Address start_ea;
  Dyninst::SymtabAPI::Region *region;
  size_t size;

  // For now I want them ordered {ea, in form start_ea - *ea - 1}
  std::set<std::pair<Dyninst::Address, Dyninst::Address>> entries;

};
