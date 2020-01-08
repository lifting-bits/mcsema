/*
 * Copyright (c) 2018 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "SectionManager.h"
#include "Util.h"

#include <CFG.h>

#include <glog/logging.h>

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

bool SectionManager::IsInRegion(const std::string &region_name, Address addr) const {
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

Dyninst::SymtabAPI::Region *
SectionManager::GetRegion(const std::string &name) {
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
