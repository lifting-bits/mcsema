#include "SectionManager.h"

#include <glog/logging.h>

using namespace Dyninst;
using namespace SymtabAPI;

void SectionManager::AddRegion(Region *r) {
  if (regions.find(r) == regions.end()) {
    LOG(INFO) << "Inserting section " << r->getRegionName();
    if (r->getRegionName() == ".rodata") {
      rodata = r;
    }
    regions.insert(r);
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
