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
