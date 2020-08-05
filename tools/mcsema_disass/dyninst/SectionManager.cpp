/*
 * Copyright (c) 2020 Trail of Bits, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "SectionManager.h"

#include <CFG.h>
#include <glog/logging.h>

#include "Util.h"

using namespace Dyninst;
using namespace SymtabAPI;

bool SectionManager::IsInRegion(const SymtabAPI::Region *r, Address a) const {
  if (!r) {
    return false;
  }
  if (a < r->getMemOffset()) {
    return false;
  }
  if (a > (r->getMemOffset() + r->getMemSize())) {
    return false;
  }
  return true;
}

bool SectionManager::IsInRegion(const std::string &region_name,
                                Address addr) const {
  return IsInRegion(GetRegion(region_name), addr);
}

bool SectionManager::IsInRegions(std::vector<std::string> sections,
                                 Dyninst::Address addr) const {
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

bool SectionManager::IsCode(Dyninst::Address addr) const {
  return IsInRegion(".text", addr);
}

bool SectionManager::IsInBinary(Dyninst::Address addr) const {
  for (auto &s : regions) {
    if (IsInRegion(s.region, addr)) {
      return true;
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


const Dyninst::SymtabAPI::Region *
SectionManager::GetRegion(const std::string &name) const {
  return GetRegion_impl<const Dyninst::SymtabAPI::Region *>(*this, name);
}

Dyninst::SymtabAPI::Region *SectionManager::GetRegion(const std::string &name) {
  return GetRegion_impl<Dyninst::SymtabAPI::Region *>(*this, name);
}

void SectionManager::AddRegion(Dyninst::SymtabAPI::Region *r) {
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
  regions.push_back({r, r->getRegionName(), nullptr});
}

std::vector<Dyninst::SymtabAPI::Symbol *>
SectionManager::GetExternalRelocs(Dyninst::SymtabAPI::Symbol::SymbolType type) {
  std::vector<Dyninst::SymtabAPI::Symbol *> vars;
  for (auto &region : regions) {
    for (auto &reloc : region.region->getRelocations()) {
      auto symbol = reloc.getDynSym();
      if (!symbol) {
        continue;
      }
      if (symbol->getType() == type) {
        LOG(INFO) << "Found relocation of " << symbol->getMangledName();
        vars.push_back(symbol);
      }
    }
  }
  return vars;
}
