#pragma once

#include <Symtab.h>
#include <set>

class SectionManager {
public:
  void AddRegion(Dyninst::SymtabAPI::Region *r);

  bool IsData(Dyninst::Address a) const;
  bool IsCode(Dyninst::Address a) const;

  std::set<Dyninst::SymtabAPI::Region *> GetDataRegions() const;
  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions() { return regions; }

private:
  std::set<Dyninst::SymtabAPI::Region *> regions;
};
