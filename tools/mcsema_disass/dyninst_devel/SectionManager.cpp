#include "SectionManager.h"

#include <glog/logging.h>

using namespace Dyninst;
using namespace SymtabAPI;

Dyninst::SymtabAPI::Region *
SectionManager::getRegion(const std::string &name) {
  for (auto r : regions) {
    if (r->getRegionName() == name) {
      return r;
    }
  }
  LOG(FATAL) << "Could not fetch section with name " << name;
}

void SectionManager::AddRegion(Region *r) {
  if (regions.find(r) == regions.end()) {
    LOG(INFO) << "Inserting section " << r->getRegionName();
    if (r->getRegionName() == ".rodata") {
      rodata = r;
    } else if (r->getRegionName() == ".text") {
      text = r;
    }
    regions.insert(r);
    for (auto &to_write_region : to_write_regions) {
      if (r->getRegionName() == to_write_region) {
        data_regions.insert(r);
      }
    }
  }
}

bool SectionManager::IsData(Address a) const {
  const auto &dataRegions{GetDataRegions()};
  const Offset o = static_cast<const Offset>(a);

  for (auto &r : dataRegions) {
    if (r->isOffsetInRegion(o)) {
      return true;
    }
  }

  return false;
}

bool SectionManager::IsCode(Address a) const {
  return !IsData(a);
}

std::set<Region *> SectionManager::GetDataRegions() const {
  return regions;
}
