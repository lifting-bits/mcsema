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

#include <array>
#include <memory>
#include <set>

#include <glog/logging.h>

namespace mcsema {
  class Segment;
}

struct Section {
  Dyninst::SymtabAPI::Region *region = nullptr;
  std::string name;
  mcsema::Segment *cfg_segment = nullptr;
};

struct SectionManager {
public:
  void AddRegion(Dyninst::SymtabAPI::Region *r);

  bool IsInRegion(const Dyninst::SymtabAPI::Region *r, Dyninst::Address a) const;
  bool IsInRegions(std::vector<std::string> sections, Dyninst::Address addr) const;
  bool IsInRegion(const std::string& region, Dyninst::Address addr) const;

  // Is it in .text?
  bool IsCode(Dyninst::Address addr) const;

  bool IsInBinary(Dyninst::Address addr) const;


  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions();

  Dyninst::SymtabAPI::Region *GetRegion(const std::string &name);
  const Dyninst::SymtabAPI::Region *GetRegion(const std::string &name) const;

  std::vector<Dyninst::SymtabAPI::Symbol *> GetExternalRelocs(
      Dyninst::SymtabAPI::Symbol::SymbolType type);

  void SetCFG(const Dyninst::SymtabAPI::Region *reg,
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

  template<typename Out, typename T>
  static Out GetRegion_impl(T &self, const std::string &name) {
    for (auto &r : self.regions) {
      if (r.name == name) {
        return r.region;
      }
    }
    LOG(INFO) << "Could not fetch section with name " << name;
    return nullptr;
  }

  std::vector<Section> regions;
};
