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
  mcsema::Segment *cfg_segment = nullptr;
  bool should_write = true;
};

class SectionManager {
public:
  void AddRegion(Dyninst::SymtabAPI::Region *r);

  bool IsData(Dyninst::Address a);
  bool IsCode(Dyninst::Address a);

  bool IsInRegions(std::vector<std::string> sections, Dyninst::Address addr);

  std::set<Dyninst::SymtabAPI::Region *> GetDataRegions();
  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions();

  Dyninst::SymtabAPI::Region *getRegion(const std::string &name);

private:
  std::vector<Section> regions;
};

extern std::unique_ptr<SectionManager> gSection_manager;
