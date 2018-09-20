#include "SectionManager.h"
#include "Util.h"

#include <CFG.h>

#include <glog/logging.h>


using namespace Dyninst;
using namespace SymtabAPI;

namespace {
  bool IsInRegion(SymtabAPI::Region *r, Address a) {
    if (a < r->getMemOffset()) {
      return false;
    }
    if (a > (r->getMemOffset() + r->getMemSize())) {
      return false;
    }
    return true;
  }

  bool IsInRegions(const std::vector<SymtabAPI::Region *> &regions, Address a) {
    for (auto &r : regions) {
      if (IsInRegion(r, a)) {
        return true;
      }
    }
    return false;
  }
}



std::unique_ptr<SectionManager> gSection_manager(new SectionManager);

bool SectionManager::IsInRegions(std::vector<std::string> sections,
                                  Dyninst::Address addr) {
  for (auto s : regions) {
    for (auto& name : sections) {
      if (name == s.region->getRegionName()) {
        if (IsInRegion(s.region, addr)) {
          return true;
        }
      }
    }
  }
  return false;
}

std::set<Region *> SectionManager::GetAllRegions() {
  std::set<Region *> result;
  for (auto &a : regions) {
    result.insert(a.region);
  }
  return result;
}

Dyninst::SymtabAPI::Region *
SectionManager::getRegion(const std::string &name) {
  for (auto &r : regions) {
    if (r.name == name) {
      return r.region;
    }
  }
  LOG(FATAL) << "Could not fetch section with name " << name;
}

void SectionManager::AddRegion(Region *r) {
  for (auto &s : regions) {
    if (s.name == r->getRegionName()) {
      LOG(INFO) << "Trying to add duplicite section into manager "
                << r->getRegionName();
      return;
    }
  }
  static std::array<std::string, 1> no_write = {
    ".fini_array",
  };

  bool should_write = true;
  for (auto &a : no_write) {
    if (r->getRegionName() == a) {
      should_write = false;
    }
  }
  mcsema::Segment *cfg_segment =
    (should_write) ? gModule.add_segments() : nullptr;
  regions.push_back({r, r->getRegionName(), cfg_segment, should_write});
}

bool SectionManager::IsData(Address a) {
  const auto &dataRegions{GetDataRegions()};
  const Offset o = static_cast<const Offset>(a);

  for (auto &r : dataRegions) {
    if (r->isOffsetInRegion(o)) {
      return true;
    }
  }

  return false;
}

bool SectionManager::IsCode(Address a) {
  return !IsData(a);
}

std::set<Region *> SectionManager::GetDataRegions() {
  return GetAllRegions();
}
