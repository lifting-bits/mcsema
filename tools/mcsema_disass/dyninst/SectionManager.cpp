#include "SectionManager.h"
#include "Util.h"

#include <CFG.h>

#include <glog/logging.h>


using namespace Dyninst;
using namespace SymtabAPI;

std::unique_ptr<SectionManager> gSectionManager(new SectionManager);

bool SectionManager::IsInRegion(SymtabAPI::Region *r, Address a) {
  if (a < r->getMemOffset()) {
    return false;
  }
  if (a > (r->getMemOffset() + r->getMemSize())) {
    return false;
  }
  return true;
}

bool SectionManager::IsInRegion(const std::string &region_name, Address addr) {
  return IsInRegion(GetRegion(region_name), addr);
}

bool SectionManager::IsInRegions(std::vector<std::string> sections,
                                  Dyninst::Address addr) {
  for (auto &s : regions) {
    for (auto &name : sections) {
      if (name == s.name) {
        if (IsInRegion(s.region, addr)) {
          return true;
        }
      }
    }
  }
  return false;
}

bool SectionManager::IsInBinary(Dyninst::Address addr) {
  for (auto &s : regions) {
    if (IsInRegion(s.region, addr)) {
      return true;
    }
  }
  LOG(INFO) << std::hex << "0x" << addr << " is not contained in binary";
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
SectionManager::GetRegion(const std::string &name) {
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
  regions.push_back({r, r->getRegionName()});
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
