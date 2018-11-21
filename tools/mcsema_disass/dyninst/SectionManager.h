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
  mcsema::Segment *cfg_segment;
};

struct SectionManager {
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

  std::vector<Dyninst::SymtabAPI::Symbol *> GetExternalRelocs(
      Dyninst::SymtabAPI::Symbol::SymbolType type);

  void SetCFG(Dyninst::SymtabAPI::Region *reg,
              mcsema::Segment *segment) {
    for (auto &r : regions) {
      if (r.region == reg) {
        r.cfg_segment = segment;
      }
    }
  }

  mcsema::Segment *GetCFG(Dyninst::SymtabAPI::Region *reg) {
    for (auto &r : regions) {
      if (r.region == reg) {
        return r.cfg_segment;
      }
    }
    return nullptr;
  }

  Section *GetSection(const std::string &name) {
    for (auto &r : regions) {
      if (r.name == name) {
        return &r;
      }
    }
    return nullptr;
  }

private:
  // There won't be big enough number of regions to justify
  // std::map
  std::vector<Section> regions;
};

extern std::unique_ptr<SectionManager> gSectionManager;
