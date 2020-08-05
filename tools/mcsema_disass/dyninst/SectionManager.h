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

#pragma once

#include <Symtab.h>
#include <glog/logging.h>

#include <array>
#include <memory>
#include <set>

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

  bool IsInRegion(const Dyninst::SymtabAPI::Region *r,
                  Dyninst::Address a) const;
  bool IsInRegions(std::vector<std::string> sections,
                   Dyninst::Address addr) const;
  bool IsInRegion(const std::string &region, Dyninst::Address addr) const;

  // Is it in .text?
  bool IsCode(Dyninst::Address addr) const;

  bool IsInBinary(Dyninst::Address addr) const;


  std::set<Dyninst::SymtabAPI::Region *> GetAllRegions();

  Dyninst::SymtabAPI::Region *GetRegion(const std::string &name);
  const Dyninst::SymtabAPI::Region *GetRegion(const std::string &name) const;

  std::vector<Dyninst::SymtabAPI::Symbol *>
  GetExternalRelocs(Dyninst::SymtabAPI::Symbol::SymbolType type);

  void SetCFG(const Dyninst::SymtabAPI::Region *reg, mcsema::Segment *segment) {
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

  template <typename Out, typename T>
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
