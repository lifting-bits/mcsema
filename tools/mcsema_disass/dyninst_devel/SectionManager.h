#pragma once

#include <Symtab.h>
#include <set>
#include <array>
#include <memory>

namespace mcsema {
  class Segment;
}

struct Section {
  Dyninst::SymtabAPI::Region *region;
  std::string name;
};

class SectionManager {
public:
  void AddRegion(Dyninst::SymtabAPI::Region *r);

  bool IsData(Dyninst::Address a);
  bool IsCode(Dyninst::Address a);

  bool IsInRegion(Dyninst::SymtabAPI::Region *r, Dyninst::Address a);
  bool IsInRegions(std::vector<std::string> sections, Dyninst::Address addr);
  bool IsInRegion(const std::string& region, Dyninst::Address addr);
  bool IsInBinary(Dyninst::Address addr);

  std::set<Dyninst::SymtabAPI::Region *> GetDataRegions();
  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions();

  Dyninst::SymtabAPI::Region *GetRegion(const std::string &name);

private:
  // There won't be big enough number of regions to justify
  // std::map
  std::vector<Section> regions;
};

extern std::unique_ptr<SectionManager> gSectionManager;
